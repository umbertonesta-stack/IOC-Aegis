# Manuale tecnico — IOC-Aegis

Documento rivolto a chi voglia comprendere l'architettura interna del progetto o estenderlo.

## Panoramica dell'architettura

IOC-Aegis e' organizzato in quattro responsabilita' nettamente separate:

```
CLI  ──►  Client  ──►  (Cache)  ──►  API esterna
              │
              ▼
            IOC  ──►  get_severity_score()
              │
              ▼
          Export (CSV)
```

- I **client** (`clients/`) sanno *come recuperare* il dato: HTTP, autenticazione, parsing
  della risposta. Nient'altro.
- Gli **IOC** (`parsers/`) sanno *cosa significa* il dato: ogni tipo di indicatore calcola
  il proprio punteggio di pericolosita'.
- La **cache** (`cache.py`) intercetta le richieste prima che raggiungano la rete.
- L'**export** (`export.py`) serializza i risultati in CSV.
- La **CLI** (`cli.py`) orchestra il tutto e gestisce l'interazione con l'utente.

Questa separazione ha una conseguenza pratica: gli IOC non dipendono dalla rete e possono
essere costruiti e testati offline, cosa su cui si appoggiano i test unitari.

## Struttura dei moduli

```
src/ioc_aegis/
├── __main__.py     entry point: python -m ioc_aegis
├── cli.py          menu interattivo, crea la cache e i client, orchestra le analisi
├── cache.py        cache locale su file JSON, con scadenza (TTL) e limite di voci
├── export.py       esportazione dei risultati di sessione in CSV
├── parsers/        gerarchia degli indicatori
│   ├── base.py     IOC (classe base astratta)
│   ├── ip.py       IpIOC
│   ├── url.py      UrlIOC
│   ├── fileioc.py  FileIOC
│   └── domain.py   DomainIOC
└── clients/        client HTTP verso le sorgenti
    ├── abuseipdb.py    AbuseIPDBClient
    ├── urlhaus.py      URLhausClient
    ├── virustotal.py   VirusTotalClient
    └── alienvault.py   AlienVaultClient
```

## La gerarchia di ereditarieta'

Il cuore del progetto e' la gerarchia degli IOC. La classe base astratta `IOC` definisce il
contratto comune; ogni sottoclasse rappresenta un tipo di indicatore e implementa a modo
proprio il calcolo del punteggio.

```
                    ┌─────────────────────────┐
                    │      IOC (astratta)     │
                    │  value, source,         │
                    │  detected_at, __str__   │
                    │  get_severity_score()*  │   * metodo astratto
                    └───────────┬─────────────┘
             ┌──────────┬───────┴───────┬──────────────┐
             ▼          ▼               ▼              ▼
        ┌────────┐ ┌─────────┐   ┌──────────┐   ┌───────────┐
        │ IpIOC  │ │ UrlIOC  │   │ FileIOC  │   │ DomainIOC │
        └────────┘ └─────────┘   └──────────┘   └───────────┘
```

La classe base valida che `value` e `source` non siano vuoti, imposta il timestamp
`detected_at` e fornisce una rappresentazione testuale (`__str__`). Dichiara astratto il
metodo `get_severity_score() -> int`: questo rende `IOC` non istanziabile direttamente e
obbliga ogni sottoclasse a fornire la propria implementazione.

### Il metodo polimorfico

`get_severity_score()` e' il punto in cui si manifesta il polimorfismo. Ogni sottoclasse lo
implementa in base alla natura della propria sorgente:

| Sottoclasse | Come calcola lo score |
|---|---|
| `IpIOC` | Usa direttamente la confidence 0-100 fornita da AbuseIPDB. |
| `UrlIOC` | Lo deriva dallo stato dell'URL su URLhaus (online 95, offline 65, ignoto 50, assente 0). |
| `FileIOC` | Lo calcola come percentuale di motori antivirus che segnalano l'hash su VirusTotal. |
| `DomainIOC` | Lo deriva a scaglioni dal numero di "pulse" (segnalazioni OTX), con una whitelist di domini legittimi. |

Un qualsiasi codice che debba valutare un insieme di indicatori puo' iterare su una lista di
`IOC` e chiamare `get_severity_score()` su ciascuno, senza conoscere il tipo concreto: e' il
metodo, non il chiamante, a sapere come calcolare il punteggio. Questa proprieta' e'
verificata dai test (`tests/test_engine.py`).

### Costruttori delle sottoclassi

- `IpIOC(value, source, abuse_score)` — valida che `abuse_score` sia tra 0 e 100.
- `UrlIOC(value, source, query_status, url_status="unknown", threat=None, tags=None)` —
  dispone anche di una factory `from_urlhaus(url, raw)` che costruisce l'oggetto a partire
  dalla risposta grezza di URLhaus.
- `FileIOC(value, source, malicious_votes, total_votes)` — valida che i voti siano coerenti
  (totale positivo, maligni non superiori al totale).
- `DomainIOC(value, source, pulse_count=0)` — mantiene una whitelist di domini legittimi.

## I client

Ogni client incapsula l'accesso a una sorgente e restituisce un IOC concreto oppure `None`
(in caso di assenza di dati o di errore), senza mai propagare eccezioni al chiamante: la CLI
riceve sempre un oggetto valido o `None`, e non deve gestire try/except.

| Client | Sorgente | Metodo HTTP | Restituisce |
|---|---|---|---|
| `AbuseIPDBClient` | AbuseIPDB | GET | `IpIOC` |
| `URLhausClient` | URLhaus | POST (form) | `UrlIOC` |
| `VirusTotalClient` | VirusTotal | GET | `FileIOC` |
| `AlienVaultClient` | AlienVault OTX | GET | `DomainIOC` |

Tutti i client consultano la cache prima di effettuare la chiamata di rete e vi memorizzano
la risposta (compresi gli esiti negativi). Le chiavi API sono lette da variabili d'ambiente,
mai scritte nel codice.

## La cache

`Cache` e' un archivio su file JSON (`cache/lookups.json`). Ogni voce ha un timestamp e una
scadenza (TTL di 6 ore); le voci scadute o eccedenti il limite massimo vengono rimosse.
Memorizza solo i campi necessari a ricostruire l'IOC, mai la risposta grezza integrale.
Un'unica istanza di `Cache` viene creata dalla CLI e condivisa fra tutti i client, cosi' che
la cronologia sia coerente e non ci siano scritture concorrenti sullo stesso file.

## Esportazione

`export.py` serializza in CSV i risultati raccolti nella sessione (fonte, target, indice di
pericolosita'), salvandoli in `reports/` con un nome basato sul timestamp.

## Come estendere il progetto

Aggiungere una nuova sorgente richiede due passi, senza modificare il codice esistente:

1. creare una nuova sottoclasse di `IOC` che implementi `get_severity_score()` secondo la
   logica della nuova sorgente;
2. creare un client che interroghi la sorgente e restituisca istanze di quella sottoclasse,
   appoggiandosi alla cache condivisa.

Il codice che valuta gli indicatori non va toccato: continuera' a funzionare grazie al
polimorfismo della gerarchia.

## Test

I test (`tests/`) coprono il calcolo dello score di tutte le sottoclassi, la validazione
degli input e il comportamento polimorfico della gerarchia. Si eseguono con:

```
PYTHONPATH=src python -m pytest -v
```