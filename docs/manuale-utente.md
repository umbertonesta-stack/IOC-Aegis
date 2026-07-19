## Installazione

git clone <https://github.com/umbertonesta-stack/IOC-Aegis.git>
cd ioc_aegis
python3 -m venv .venv
source .venv/bin/activate  # Su Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env

Richiede Python 3.11+.

## Uso

py -m src.ioc_aegis
Nota per macOS/Linux: usa python -m src.ioc_aegis 

### Comandi e opzioni

Comandi e opzioni (Menu Interattivo)
Una volta avviato il programma, potrai navigare nel menu digitando il numero corrispondente:

1 - Analizza Singolo Elemento: Apre il sottomenu operativo. Ti verrà chiesto di scegliere il tipo di indicatore (IP, URL, Hash o Dominio) e di digitare il dato da scansionare.

2 - Esporta per Firewall e SIEM: Salva i risultati delle analisi fatte fino a quel momento. Genera in automatico un file all'interno della cartella reports/ (es. ioc_aegis_report_<data-ora>.csv).

3 - Mostra Cronologia: Stampa a schermo lo storico delle ricerche effettuate durante la sessione, comprese quelle che non hanno prodotto risultati (indicatori non trovati).

0 - Esci: Chiude il programma. Come misura di sicurezza, se ci sono risultati non ancora salvati, esegue un'esportazione automatica in CSV prima della chiusura.
### Esempi pratici
caso 1 
$ py -m src.ioc_aegis
[Menu Principale] Scegli un'opzione: 1
[Sottomenu] Tipo di indicatore (1=IP, 2=URL, 3=Mail/Dominio, 4=Hash): 1
Inserisci l'IP da scansionare: 185.220.101.5

Verdetto: Analisi completata.
    Fonte: AbuseIPDB
    Target: 185.220.101.5
    Indice di Pericolosita': 100%

caso 2
 $ py -m src.ioc_aegis
[Menu Principale] Scegli un'opzione: 1
[Sottomenu] Tipo di indicatore (1=IP, 2=URL, 3=Mail/Dominio, 4=Hash): 3
Inserisci la Mail o il Dominio da scansionare: phishing@dominio-infetto.com

[*] Email rilevata. Analizzo il dominio estratto: dominio-infetto.com

Verifica in corso per: dominio-infetto.com...
[-] Nessuna minaccia nota (Pulse) trovata su AlienVault per dominio-infetto.com.
## Errori comuni e cosa fare

Errore "non configurato" mentre fai una ricerca:
Stai provando a cercare un elemento, ma ti sei dimenticato di inserire la chiave per il servizio che se ne occupa (ad esempio, manca la chiave di VirusTotal e stai cercando un file). Ti basta aprire il file .env, aggiungere la chiave mancante e riaprire il programma.

Cosa succede se scrivo male un dato?
Se sbagli a digitare (ad esempio metti delle lettere in un indirizzo IP, o scrivi un indirizzo web incompleto), il programma non si rompe. Ti avviserà semplicemente che il testo inserito non è valido e ti chiederà di scriverlo di nuovo in modo corretto.

Se manca la connessione a internet (la rete non risponde):
Il programma proverà a cercare la risposta nella sua memoria interna, dove salva in automatico le ricerche fatte nelle ultime 6 ore. Se il dato che cerchi non è lì dentro e sei senza internet, la ricerca si fermerà e un messaggio ti avviserà del problema di connessione.