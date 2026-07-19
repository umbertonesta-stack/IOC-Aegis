## Sintesi

L'IA (Gemini/Claude) è stata utilizzata come supporto mirato per il debugging di problemi specifici (gestione eccezioni di rete, anomalie sui file CSV) e per la consultazione rapida sulla sintassi di alcune librerie 

## Dettaglio per parte
Gestione API (AlienVault): Abbiamo chiesto all'IA "Come gestire in modo robusto i timeout e i blocchi temporanei in Python (libreria requests) senza interrompere lo script?". Abbiamo accettato l'idea di implementare un blocco try-except per le eccezioni di rete, ma abbiamo modificato il meccanismo di retry per riadattarlo al ciclo di esecuzione della nostra CLI. Questa scelta ci ha permesso di rendere il sistema resiliente e fault-tolerant, mantenendo però il controllo totale sul flusso specifico del nostro programma.

Esportazione CSV: Abbiamo consultato l'intelligenza artificiale per risolvere gli errori di duplicazione emersi durante l'utilizzo del modulo di scrittura dei dizionari su file. Abbiamo rifiutato il codice generico proposto, accogliendo solo il suggerimento teorico di appiattire e normalizzare le informazioni. Poiché l'assistente non conosceva la nostra architettura a oggetti, abbiamo elaborato da zero la logica di esportazione tramite una ristrutturazione manuale del codice, mirata specificamente alle nostre classi.

Test Unitari: Abbiamo chiesto "Come strutturare una suite di test per validare l'ereditarietà in una gerarchia di classi (polimorfismo)?". Abbiamo accettato la struttura architetturale generale del test, ma abbiamo rifiutato e modificato il contenuto dei test stessi, riscrivendoli interamente ex-novo. I test generati dall'IA risultavano infatti troppo astratti; a noi serviva un collaudo reale e mirato sul comportamento specifico delle nostre classi figlie (DomainIOC, FileIOC, ecc.).

## Cosa NON abbiamo delegato all'IA

L'idea di base, come è costruito il software e i contenuti del progetto sono tutta farina del nostro sacco. In particolare, NON abbiamo fatto fare all'IA:

La struttura del codice: L'idea di come usare la programmazione a oggetti e di organizzare le varie classi (padre e figlie) l'abbiamo decisa e progettata noi.

Le chiamate ad AlienVault: Le richieste di rete verso l'esterno le abbiamo scritte a mano. 

Il salvataggio dei file: Abbiamo scritto noi a mano, la logica necessaria per estrarre i dati dai nostri oggetti complessi e salvarli in modo pulito.

Le verifiche sul codice: Per assicurarci che il programma funzionasse davvero nelle varie casistiche reali, abbiamo pensato, progettato e scritto interamente da zero tutti i controlli di funzionamento.

L'organizzazione su Git: Come dividerci il lavoro sui branch, unire le modifiche e nascondere in sicurezza le chiavi nel file .env lo abbiamo gestito manualmente tra di noi.

Il diario di sviluppo: I problemi che abbiamo raccontato e le idee per il futuro (come usare le regex o rendere il codice asincrono) vengono esclusivamente da nostre idee.