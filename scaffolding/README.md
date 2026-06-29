# IOC-Aegis

Aggregatore di threat intelligence da riga di comando. Dato un IP o un URL, interroga in
tempo reale più sorgenti (es. AbuseIPDB, URLhaus), aggrega i verdetti assegnando uno score
e classificando la minaccia, e su una lista di indicatori esporta quelli malevoli in
formati pronti per firewall o SIEM.

## Requisiti

- Python 3.11+
- Un account gratuito su [AbuseIPDB](https://www.abuseipdb.com/) per ottenere una API key

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

> Su Windows l'attivazione è: `.venv\Scripts\activate`

### 2. Installa le dipendenze

```bash
pip install -r requirements.txt
```

### 3. Configura la chiave API

Le chiavi non sono versionate. Copia il file di esempio e inserisci la tua chiave reale:

```bash
cp .env.example .env
```

Apri `.env` con un editor e sostituisci il placeholder con la tua chiave AbuseIPDB:

```
ABUSEIPDB_API_KEY=la_tua_chiave_qui
```

La chiave si ottiene da: account AbuseIPDB → scheda **API** → *Create Key*.

> Il file `.env` è ignorato da git e non deve mai essere committato.

## Uso rapido

```bash
# Controlla un singolo IP
python -m ioc_aegis check 8.8.8.8

# Analizza una lista ed esporta gli indicatori sopra una soglia di severità
python -m ioc_aegis scan indicatori.txt --min-severity 80 --export csv --out blocklist.csv
```

*(I comandi esatti sono indicativi e verranno completati durante lo sviluppo.)*

## Sessioni successive

L'ambiente virtuale non resta attivo tra una sessione e l'altra. A ogni nuovo terminale:

```bash
source .venv/bin/activate
```

Per uscirne: `deactivate`.

## Struttura del progetto

```
ioc-aegis/
├── src/ioc_aegis/      # codice sorgente
├── tests/              # test pytest (con fixture per la demo offline)
├── docs/               # proposta, manuali, devlog
├── .env.example        # template delle variabili d'ambiente (versionato)
├── requirements.txt    # dipendenze esterne
└── README.md
```

## Note

- Le dipendenze esterne sono in `requirements.txt`; i moduli della libreria standard
  (`ipaddress`, `re`, `csv`, `json`, `argparse`, `abc`) non vanno dichiarati.
- L'account gratuito AbuseIPDB ha un limite di 1.000 controlli al giorno: la cache locale
  riduce le chiamate ripetute.