### Settimana 1 — [29 giugno - 5 luglio]
Questa settimana ci siamo concentrati sull'impostazione del progetto e sulla creazione della struttura di base per la nostra applicazione.

Cosa abbiamo fatto: Abbiamo effettuato il commit iniziale, organizzato le subdirectory e scritto il README.md con il setup per Windows e Linux. Abbiamo poi sviluppato la struttura e la logica del menu di navigazione della CLI.

Decisioni prese: Abbiamo stabilito di gestire le credenziali API fin dal primo giorno tramite variabili d'ambiente (creando un .env.example censurato da tracciare al posto del .env reale). Inoltre, abbiamo deciso di testare subito un flusso di lavoro su branch (come feature/prova-branch) per validare le Pull Request.

Cosa ci ha fatto perdere tempo: Abbiamo avuto grosse difficoltà iniziali a configurare il file .gitignore. Avevamo sbagliato la sintassi e abbiamo dovuto cancellarlo e ricrearlo da capo per assicurarci di non caricare file sensibili sul repository remoto.

Cosa abbiamo imparato: Dal punto di vista organizzativo, abbiamo imparato a gestire i branch su Git, affrontando e risolvendo i primi merge e i conflitti diretti sul branch main senza sovrascriverci il codice a vicenda.

Pianificazione: Per la prossima settimana prevediamo di definire la gerarchia OOP e iniziare a scrivere le classi base per l'analisi degli indicatori.

### Settimana 2 — [6 luglio - 12 luglio]

Il focus di questa settimana è stato l'implementazione del core logico e dell'ereditarietà richiesta dalle specifiche d'esame.

Cosa abbiamo fatto: Abbiamo creato la classe padre astratta IOC_base e le prime sottoclassi per IP e URL. Per gli URL abbiamo implementato una logica personalizzata per calcolare un punteggio. Abbiamo anche integrato i primi client API (AbuseIPDB e URLhaus).

Decisioni prese: Abbiamo deciso di riorganizzare pesantemente il progetto spostando i sorgenti in un package unificato (ioc_aegis), separando in modo netto i modelli di dati dai parser e dalla logica della CLI.

Cosa ci ha fatto perdere tempo: Abbiamo faticato parecchio a capire come incapsulare correttamente la logica delle richieste HTTP nella classe padre, cercando il modo giusto per non duplicare il codice di connessione in ogni classe figlia.

Cosa abbiamo imparato: Affrontando la struttura a oggetti, abbiamo compreso a fondo l'uso pratico del polimorfismo e l'importanza della funzione super() in Python per estendere i comportamenti senza sovrascriverli.

Pianificazione: Per la settimana prossima completeremo i client API mancanti e svilupperemo un sistema di caching per limitare le chiamate di rete.

### Settimana 3 — [13 luglio - 19 luglio]

L'ultima settimana è stata dedicata al completamento delle feature e all'ottimizzazione prima della consegna.

Cosa abbiamo fatto: Abbiamo aggiunto il client API di VirusTotal tramite la classe FileIOC e integrato AlienVault (domain.py). Abbiamo introdotto l'opzione per esportare i risultati in CSV e abbiamo creato i test unitari per validare la nostra gerarchia polimorfica.

Decisioni prese: Per evitare di esaurire il rate limit delle API gratuite, abbiamo progettato una cache locale basata su un file JSON unico che si aggiorna ad ogni chiamata e vale per tutti gli indicatori.

Cosa ci ha fatto perdere tempo: Due bug ci hanno bloccato a lungo. Le chiamate ad AlienVault andavano in timeout congelando il programma (risolto inserendo un timeout esplicito), e l'esportazione CSV duplicava i dati in memoria (sistemato svuotando la lista dopo ogni salvataggio).

Cosa abbiamo imparato: Abbiamo imparato a normalizzare risposte JSON disomogenee provenienti da fonti diverse e a gestire le eccezioni di rete in modo che non facessero crashare l'applicativo.

Pianificazione: Il codice è congelato per la consegna. Ci dedicheremo al ripasso della base di codice e alla preparazione dell'orale.

---

## Bilancio finale

Alla consegna, una entry di bilancio (30-50 righe). Spunti: di cosa siete più soddisfatti,
cosa avete capito di nuovo, cosa avete sottovalutato all'inizio, cosa rifareste diversamente,
se la divisione del lavoro è stata equa, cosa avreste aggiunto con un'altra settimana, e —
onestamente — che voto dareste al vostro progetto e perché.

---
Bilancio Finale del Progetto IOC-Aegis
Giunti alla fine di questo progetto, il nostro bilancio complessivo per il progetto IOC-Aegis è estremamente positivo. Guardando  il lavoro svolto in queste settimane, la cosa di cui siamo maggiormente soddisfatti è senza dubbio l'architettura polimorfica che siamo riusciti a costruire. Inizialmente avevamo paura che strutturare tutto su una classe padre IOC_base potesse complicare eccessivamente la codebase, ma una volta impostata correttamente l'ereditarietà per le varie tipologie (FileIOC, DomainIOC, ecc.), ci siamo resi conto di quanto il codice fosse diventato pulito, scalabile e facile da mantenere. Anche il sistema di caching unificato su file JSON è un traguardo che ci rende orgogliosi, perché ha risolto in modo elegante un problema reale e pratico: evitare di esaurire il rate limiting delle API gratuite.

Durante lo sviluppo abbiamo capito e imparato moltissime cose nuove, soprattutto riguardo alla gestione di dati provenienti dal mondo reale. Lavorare simultaneamente con le API di VirusTotal, AlienVault, URLhaus e AbuseIPDB ci ha insegnato che gli output JSON di fornitori diversi sono spesso disomogenei; normalizzarli per restituire all'utente un'interfaccia unificata e coerente è stata una grande sfida formativa. Abbiamo inoltre compreso a fondo le dinamiche di collaborazione su Git, arrivando a gestire in modo molto più fluido branch e pull request.

Non sono mancati gli ostacoli. All'inizio abbiamo decisamente sottovalutato la difficoltà di incapsulare le logiche di rete. Pensavamo bastasse scrivere una richiesta HTTP generica, ma gestire correttamente i timeout e le eccezioni (come nel caso dei blocchi causati da AlienVault) senza far crashare l'intera CLI ha richiesto molto più tempo del previsto. Se potessimo tornare indietro e rifare qualcosa diversamente, cambieremmo sicuramente l'approccio alla gestione dei dati in uscita. L'implementazione dell'esportazione in CSV ci ha infatti causato non pochi problemi di duplicazione dei record. Aver dovuto ristrutturare la logica di salvataggio in fase avanzata per ottenere un report pulito è stato un lavoro di refactoring che avremmo potuto evitare progettando fin da subito un formato standardizzato per il consolidamento dei risultati.

Per quanto riguarda l'organizzazione interna, riteniamo che la divisione del lavoro sia stata equa e bilanciata . Ivan si è fatto carico di gran parte dell'interfaccia CLI, dell'impostazione dei menu, della feature di esportazione CSV . Umberto si è concentrato molto sull'architettura, riorganizzando il package ioc_aegis, progettando il sistema di cache universale, risolvendo bug critici e adeguando i test di polimorfismo.
Ci siamo smezzati poi il lavoro sulle 4 API lavorando anche insieme in classe. Ci siamo tenuti in costante contatto per eventali problematiche, dubbi e avazamento lavori.

Se avessimo avuto a disposizione un'altra settimana di tempo, avremmo implementato uno scanner basato su espressioni regolari (Regex) per l'estrazione massiva e automatizzata degli indicatori da file di testo. Attualmente l'analisi degli IoC funziona, ma poter elaborare interi log testuali avrebbe reso lo strumento ancora più versatile. Inoltre, a supporto di questa funzionalità, avremmo introdotto l'asincronia (ad esempio tramite asyncio e aiohttp): interrogare le API per decine di IoC in modo puramente sequenziale risulta lento, e parallelizzare le chiamate avrebbe reso la CLI estremamente più rapida e professionale.

Infine, se dovessimo valutarci onestamente, crediamo che il nostro progetto meriti un voto tra il 26 e il 28. Riteniamo di aver rispettato in modo rigoroso e solido tutti i vincoli del laboratorio. L'uso dell'ereditarietà è centrale e motivato, il codice gestisce gli errori in modo strutturato, abbiamo una suite di test funzionante, un sistema di caching intelligente che aggira i limiti di rete, e una documentazione curata. Soprattutto, abbiamo costruito uno strumento di Threat Intelligence realmente funzionante.