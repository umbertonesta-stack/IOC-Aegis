# **Proposta di progetto**

## **Titolo**

IOC-Aegis — aggregatore di threat intelligence con esportazione per firewall/SIEM

## **Gruppo**

* Umberto Nesta  
* Ivan Viarengo

## **Cosa fa**

IOC-Aegis è uno strumento da riga di comando che, dato un IP o un URL, interroga in tempo reale più sorgenti di threat intelligence (es. AbuseIPDB e URLhaus), ne aggrega i verdetti e restituisce un giudizio unico, assegnando uno score e classificando la tipologia di minaccia. Su una lista di indicatori può esportare quelli realmente malevoli in formati pronti per essere consumati da un firewall o da un SIEM. L'utente decide la soglia di blocco tramite un flag (es. \--min-severity 80), scartando i punteggi bassi (probabili falsi positivi). La logica core è disaccoppiata dalla CLI, per poter aggiungere in futuro nuove sorgenti, nuovi formati o una GUI senza riscrivere il motore.

## **A chi serve / quale problema reale risolve**

Serve a chi gestisce una piccola rete o un host (amministratore, studente in laboratorio) e vuole verificare in fretta la reputazione di un IP o URL sospetto — visto in un log, in una mail, in una connessione anomala — senza consultare a mano cinque servizi diversi. L'esportazione chiude il ciclo "rilevo → blocco": trasforma l'analisi in un blocklist file caricabile in un firewall o ingeribile da uno stack ELK, invece di fermarsi alla sola consultazione.

## **Competenze del corso messe in gioco**

* **Richieste HTTP e JSON** — chiamate REST alle API di threat intel e parsing delle risposte.  
* **Networking e indirizzi IP** — validazione/normalizzazione con il modulo ipaddress.  
* **Regex** — riconoscimento IP vs URL ed estrazione di indicatori da testo grezzo.  
* **OOP ed ereditarietà** — gerarchia di parser polimorfici (vedi sotto).  
* **File JSON/CSV** — configurazione, cache locale e file di esportazione.  
* **CLI con argparse** \+ gestione delle eccezioni (timeout, rate limit, sorgenti irraggiungibili).

## **Gerarchia di ereditarietà prevista**

* **Classe base:** BaseParser — incapsula il comportamento comune di una sorgente di threat intel (sessione/IO, gestione errori, contratto unico per estrarre indicatori e produrre un verdetto con score).  
* **Sottoclassi:** AbuseIPParser (gestione API/JSON), URLHausParser (gestione file CSV), PhishingFeedParser (estrazione tramite regex da testo grezzo).  
* **Metodo polimorfico:** parse() \-\> list\[Verdetto\] — ogni sottoclasse lo ridefinisce in base al proprio formato; il motore IngestionEngine lo chiama senza conoscere la sottoclasse concreta, poi filtra i verdetti per soglia e li aggrega.  
* **Perché ereditarietà e non composizione/funzioni:** ogni parser *è* una sorgente di intel con lo stesso contratto ma estrazione diversa (JSON/CSV/regex); la relazione is-a è reale e il polimorfismo è sfruttato dal motore, quindi aggiungere una sorgente significa aggiungere una sottoclasse senza toccare il resto.

## **Piano di massima (fasi)**

1. Modello dati (Verdetto, score), BaseParser \+ AbuseIPParser, CLI minima per un IP.  
2. URLHausParser, IngestionEngine con aggregazione polimorfica e filtro \--min-severity.  
3. Esportatori (CSV/firewall), test pytest (incluso un test sul polimorfismo), documentazione e devlog.

A metà percorso conto di avere pronto: la validazione degli indicatori, una sorgente (AbuseIPDB) realmente interrogabile e la CLI che restituisce un verdetto con score su un singolo IP.

## **Estensione avanzata che vorrei tentare**

Esportatore in formato **STIX 2.1** (standard di interscambio threat intel) come gerarchia di esportatori polimorfica; in subordine, terza sorgente PhishingFeedParser, cache delle risposte con retry/backoff, o una GUI semplice sopra il core.