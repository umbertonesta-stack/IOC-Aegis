# Stato implementazione — IOC-Aegis

> Riepilogo tecnico dello stato del codice dopo gli ultimi commit su `main`.
> Non sostituisce `docs/devlog.md` / `docs/scelte.md` (quelli restano da scrivere voi per la
> valutazione): è solo una fotografia di cosa c'è e cosa manca, utile per allinearsi col
> compagno di gruppo.

## Ultimi commit considerati

```
bf0027e corretto output virus total
d638609 Merge branch 'main' of https://github.com/umbertonesta-stack/IOC-Aegis
74932b0 corretto funzionamento urlhaus e inserita la key per API, inserito nella cli opzioni 1,2,4 del sottomenu
1bede5e aggiunto client API VirusTotal per FileIOC
60c969d  aggiunto client API per URLhaus
```

## Gerarchia IOC (`src/ioc_aegis/parsers/`)

- `base.py` → `IOC` (ABC): valida `value`/`source` non vuoti, imposta `detected_at`,
  dichiara `get_severity_score()` astratto.
- `ip.py` → `IpIOC(IOC)`: score = `abuse_score` diretto (0-100) da AbuseIPDB.
- `url.py` → `UrlIOC(IOC)`: score derivato da `query_status`/`url_status` di URLhaus
  (online=95, offline=65, sconosciuto=50, nessun match=0). Ha anche un factory
  `from_urlhaus()` che isola il parsing del JSON grezzo.
- `fileioc.py` → `FileIOC(IOC)`: score = percentuale di motori che segnalano il file
  malevolo su VirusTotal (`malicious_votes / total_votes`).

Tre sottoclassi concrete, ciascuna con `get_severity_score()` polimorfico: soddisfa il
requisito di ereditarietà/polimorfismo reale (non solo IP e URL, anche hash file).

## Client API (`src/ioc_aegis/clients/`)

- `abuseipdb.py` → `AbuseIPDBClient.check_ip()`: GET a `abuseipdb.com/api/v2/check`,
  richiede `ABUSEIPDB_API_KEY`, ritorna `IpIOC | None`. Gestisce `RequestException`,
  `KeyError`, `ValueError`.
- `urlhaus.py` → `URLhausClient.check_url()`: POST a `urlhaus-api.abuse.ch/v1/url/`,
  richiede `URLHAUS_API_KEY`, ritorna `UrlIOC | None`, distingue `no_results` da `ok`.
- `virustotal.py` → `VirusTotalClient.check_hash()`: GET a
  `virustotal.com/api/v3/files/{hash}`, richiede `VIRUSTOTAL_API_KEY`, gestisce il 404
  (hash mai visto) come caso a parte, ritorna `FileIOC | None`.
  **Nota**: il blocco `try/except` finale ha due `except ValueError` duplicati uno di
  seguito all'altro (righe finali del file) — il secondo è irraggiungibile, da ripulire.

## VirusTotal: cosa fa e come usarlo

VirusTotal aggrega i verdetti di decine di motori antivirus/antimalware su un file già
noto al servizio: dato l'hash di un file, risponde con quanti motori lo hanno segnalato
come malevolo su quanti totali lo hanno analizzato. `VirusTotalClient.check_hash()` usa
questo dato per calcolare lo score di `FileIOC` (percentuale di rilevazioni positive).

Come usarlo da CLI:

1. Serve una API key gratuita VirusTotal, da inserire in `.env` come
   `VIRUSTOTAL_API_KEY=la_tua_chiave` (senza API key l'opzione stampa un errore e
   non prova nemmeno la richiesta).
2. Avvia l'app, scegli `1. Analizza Singolo Elemento` dal menu principale.
3. Nel sottomenu scegli `4. Scansiona Hash File`.
4. Incolla l'hash del file da controllare (MD5, SHA-1 o SHA-256 — VirusTotal accetta
   tutti e tre come identificatore in `/files/{hash}`).
5. Risultato:
   - se l'hash non è mai stato visto da VirusTotal, l'app avvisa che è sconosciuto e non
     produce un `FileIOC` (nessun dato su cui basare uno score);
   - se l'hash è noto, l'app stampa fonte, hash e indice di pericolosità (percentuale di
     motori che lo segnalano malevolo sul totale che lo hanno analizzato).

Limite pratico da tenere presente: serve l'hash del file, non il file stesso — l'app non
carica file su VirusTotal, si limita a controllare se quell'hash è già in archivio.

## CLI (`src/ioc_aegis/cli.py`)

Menu principale a 5 voci + uscita, sottomenu "Analizza Singolo Elemento":

| Voce menu | Stato |
|---|---|
| 1 → Scansiona IP | collegata a `AbuseIPDBClient`, funzionante |
| 1 → Scansiona URL | collegata a `URLhausClient`, funzionante |
| 1 → Scansiona Mail/Dominio | **non implementato** (stampa placeholder) |
| 1 → Scansiona Hash File | collegata a `VirusTotalClient`, funzionante |
| 2. Esporta per Firewall/SIEM | **stub**: chiede la soglia ma non genera davvero alcun file |
| 3. Mostra Hash Malware noti | **stub**: solo stampa, nessuna sorgente dati dietro |
| 4. Mostra Cronologia Investigazioni | **stub**: stampa una riga fissa, nessuna persistenza |
| 5. Regex Log Scanner | **stub**: chiede il percorso file ma non applica regex reali |

Il risultato di un'analisi (opzione 1) viene solo stampato a video — la riga
`" -> Ricerca salvata in cronologia."` è un messaggio di interfaccia, non corrisponde a un
salvataggio effettivo su disco/DB.

## Test (`tests/`)

`tests/test_controlli.py` importa ancora `progetto.core.base` / `progetto.core.controlli`,
moduli che non esistono nel layout attuale (`src/ioc_aegis/...`): è rimasto il template
d'esempio del corso, non è stato adattato alla gerarchia `IOC` reale. Da riscrivere per
coprire `IpIOC`/`UrlIOC`/`FileIOC` e il polimorfismo di `get_severity_score()`, richiesto
esplicitamente dalla rubrica.

## Area `TEST_API/`

Cartella isolata di prove sulle API (AbuseIPDB, URLhaus, Google Safe Browsing) con propri
test, `.env` e report (`RELAZIONE.md`) — non collegata al pacchetto `ioc_aegis`, sembra un
sandbox di ricerca separato dal codice applicativo.

## Non ancora avviato: cronologia ricerche + DB locale

Riguardo al prossimo lavoro che hai citato (cronologia delle ultime ricerche + DB locale
da consultare prima di una richiesta HTTP, per evitare chiamate ripetute): **al momento
non esiste nessuna traccia di questo nel codice**. L'opzione 4 del menu è solo una stringa
statica, non c'è alcun file `history.log`, nessuna cache né livello di persistenza (SQLite
o simile) da cui leggere prima di interrogare AbuseIPDB/URLhaus/VirusTotal. È lavoro
completamente da progettare e implementare.
