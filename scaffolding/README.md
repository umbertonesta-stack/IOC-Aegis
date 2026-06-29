# <Nome del progetto>

> Sostituisci questo README con quello del tuo progetto. Le istruzioni qui sotto sono il
> minimo: cosa fa, come si installa, come si avvia, come si lanciano i test.

## Cosa fa

Tre-cinque righe a parole tue. Se non riesci a riassumerlo, non l'hai ancora capito.

## Membri del gruppo

- Nome Cognome — handle GitHub
- Nome Cognome — handle GitHub

Corso: Programmazione Python — Cybersecurity Specialist.

## Installazione

```bash
git clone <URL-del-vostro-repo>
cd <nome-cartella>
python -m venv .venv && source .venv/bin/activate   # consigliato
pip install -r requirements.txt
```

Richiede **Python 3.11+**.

## Come si usa

```bash
python -m progetto --help
```

(Sostituisci `progetto` con il nome reale del tuo pacchetto. Vedi `docs/manuale-utente.md`
per la guida completa.)

## Test

```bash
pytest
```

## Struttura del repository

```
.
├── src/progetto/      ← SORGENTE: il codice del programma
├── tests/             ← test pytest
├── docs/              ← METAINFORMAZIONI: documentazione, proposta, devlog, uso IA
├── requirements.txt
└── README.md
```

Approfondimenti in `docs/manuale-tecnico.md` (architettura) e `docs/architettura` (gerarchia
delle classi).
