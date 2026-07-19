# IOC-Aegis

Aggregatore di threat intelligence da riga di comando. Dato un IP, un URL, un hash di file o
un dominio, interroga in tempo reale piu' sorgenti (AbuseIPDB, URLhaus, VirusTotal,
AlienVault OTX), assegna a ciascun indicatore uno score di pericolosita' 0-100 e classifica
la minaccia. Le risposte vengono memorizzate in una cache locale per ridurre le chiamate
alle API e permettere l'analisi anche offline. I risultati di una sessione possono essere
esportati in CSV per firewall o SIEM.

## Requisiti

- Python 3.11+
- Account gratuiti per ottenere le chiavi API:
  - [AbuseIPDB](https://www.abuseipdb.com/) — reputazione degli IP
  - [abuse.ch](https://auth.abuse.ch/) — Auth-Key per URLhaus
  - [VirusTotal](https://www.virustotal.com/) — verdetti antivirus sugli hash
  - [AlienVault OTX](https://otx.alienvault.com/) — segnalazioni sui domini

> Le chiavi sono opzionali una per una: se ne manca una, la sorgente corrispondente viene
> disattivata all'avvio ma le altre restano utilizzabili.

## Installazione da zero (PC pulito)

Tutti i comandi vanno eseguiti nella cartella del progetto, da terminale.

### 1. Crea e attiva l'ambiente virtuale

L'ambiente virtuale (`.venv`) isola le dipendenze del progetto dal Python di sistema.

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Dopo l'attivazione il prompt mostra `(.venv)`. Da questo momento `python` e `pip` puntano
all'ambiente isolato.

> **Windows:** l'attivazione e' `.venv\Scripts\activate`
>
> **Debian/Ubuntu/WSL:** se il comando `venv` fallisce, installa prima il pacchetto:
> `sudo apt install python3-venv`

### 2. Installa le dipendenze

```bash
python -m pip install -r requirements.txt
```

### 3. Configura le chiavi API

Le chiavi non sono versionate. Copia il file di esempio e inserisci le tue chiavi reali:

```bash
cp .env.example .env
```

Apri `.env` con un editor e compila le variabili disponibili:

```
ABUSEIPDB_API_KEY=la_tua_chiave_qui
URLHAUS_API_KEY=la_tua_chiave_qui
VIRUSTOTAL_API_KEY=la_tua_chiave_qui
ALIENVAULT_API_KEY=la_tua_chiave_qui
```

> Il file `.env` e' ignorato da git e non deve mai essere committato.

### 4. Avvia il programma

```bash
PYTHONPATH=src python -m ioc_aegis
```

Si apre un menu interattivo.

## Uso

Il menu principale offre:

1. **Analizza Singolo Elemento** — apre un sottomenu per scegliere il tipo di indicatore
   (IP, URL, Mail/Dominio, Hash file). Inserito l'indicatore, il programma interroga la
   sorgente corrispondente (o la cache, se il dato e' recente) e mostra fonte, target e
   indice di pericolosita'. Se si inserisce un'email, viene analizzato il dominio dopo la `@`.
2. **Esporta per Firewall e SIEM** — salva i risultati analizzati nella sessione corrente in
   un file CSV nella cartella `reports/`.
3. **Mostra Cronologia Investigazioni** — elenca le ultime ricerche effettuate, comprese
   quelle senza esito.
0. **Esci**

## Sessioni successive

L'ambiente virtuale non resta attivo tra una sessione e l'altra. A ogni nuovo terminale:

```bash
source .venv/bin/activate
```

Per uscirne: `deactivate`.

## Struttura del progetto

```
IOC-Aegis/
├── src/ioc_aegis/
│   ├── __main__.py       # entry point (python -m ioc_aegis)
│   ├── cli.py            # menu interattivo
│   ├── cache.py          # cache locale delle risposte (JSON, con TTL)
│   ├── export.py         # esportazione dei risultati in CSV
│   ├── parsers/          # gerarchia IOC: base + IpIOC, UrlIOC, FileIOC, DomainIOC
│   └── clients/          # client HTTP: AbuseIPDB, URLhaus, VirusTotal, AlienVault
├── tests/                # test pytest (gerarchia IOC e polimorfismo)
├── docs/                 # proposta, manuali, devlog, scelte
├── .env.example          # template delle variabili d'ambiente (versionato)
├── requirements.txt      # dipendenze esterne
└── README.md
```

## Test

```bash
PYTHONPATH=src python -m pytest -v
```

## Note

- Le dipendenze esterne sono in `requirements.txt`; i moduli della libreria standard
  (`csv`, `json`, `datetime`, `abc`) non vanno dichiarati.
- Le sorgenti gratuite hanno limiti di quota (AbuseIPDB: 1.000 controlli/giorno;
  VirusTotal: 4 richieste/minuto): la cache locale riduce le chiamate ripetute ed evita di
  esaurire i limiti durante l'uso.
- La cache viene salvata in `cache/` (esclusa dal versionamento) con una scadenza di 6 ore
  per voce.
- I report CSV vengono salvati in `reports/` (esclusa dal versionamento).