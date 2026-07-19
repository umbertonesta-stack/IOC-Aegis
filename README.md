# IOC-Aegis

Aggregatore di threat intelligence da riga di comando. Dato un IP, un URL o un hash di file,
interroga in tempo reale piu' sorgenti (AbuseIPDB, URLhaus, VirusTotal), assegna a ciascun
indicatore uno score di pericolosita' 0-100 e classifica la minaccia. Le risposte vengono
memorizzate in una cache locale per ridurre le chiamate alle API e permettere l'analisi
anche offline.

## Requisiti

- Python 3.11+
- Account gratuiti per ottenere le chiavi API:
  - [AbuseIPDB](https://www.abuseipdb.com/) — reputazione degli IP
  - [abuse.ch](https://auth.abuse.ch/) — Auth-Key per URLhaus
  - [VirusTotal](https://www.virustotal.com/) — verdetti antivirus sugli hash

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

Apri `.env` con un editor e compila le variabili:

```
ABUSEIPDB_API_KEY=la_tua_chiave_qui
URLHAUS_API_KEY=la_tua_chiave_qui
VIRUSTOTAL_API_KEY=la_tua_chiave_qui
```

> Il file `.env` e' ignorato da git e non deve mai essere committato.

### 4. Avvia il programma

```bash
PYTHONPATH=src python -m ioc_aegis
```

Si apre un menu interattivo da cui scegliere il tipo di analisi.

## Uso

All'avvio compare il menu principale. La voce **1. Analizza Singolo Elemento** apre un
sottomenu per scegliere il tipo di indicatore (IP, URL, hash file). Inserito l'indicatore,
il programma interroga la sorgente corrispondente (o la cache, se il dato e' recente) e
mostra fonte, target e indice di pericolosita'.

La voce **4. Mostra Cronologia Investigazioni** elenca le ultime ricerche effettuate,
comprese quelle senza esito.

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
│   ├── engine.py         # IngestionEngine: filtro per soglia di severita'
│   ├── parsers/          # gerarchia IOC: base + IpIOC, UrlIOC, FileIOC
│   └── clients/          # client HTTP: AbuseIPDB, URLhaus, VirusTotal
├── tests/                # test pytest
├── docs/                 # proposta, manuali, devlog, scelte
├── .env.example          # template delle variabili d'ambiente (versionato)
├── requirements.txt      # dipendenze esterne
└── README.md
```

## Note

- Le dipendenze esterne sono in `requirements.txt`; i moduli della libreria standard
  (`ipaddress`, `re`, `csv`, `json`, `abc`) non vanno dichiarati.
- Le sorgenti gratuite hanno limiti di quota (AbuseIPDB: 1.000 controlli/giorno;
  VirusTotal: 4 richieste/minuto): la cache locale riduce le chiamate ripetute ed evita di
  esaurire i limiti durante l'uso.
- La cache viene salvata in `cache/` (esclusa dal versionamento) con una scadenza di 6 ore
  per voce.