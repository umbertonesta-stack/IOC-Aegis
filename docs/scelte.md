Perché l'ereditarietà (e non composizione/funzioni)
La modellazione degli indicatori di compromissione si basa su una gerarchia di classi in cui l'ereditarietà rappresenta una relazione is-a genuina: ogni tipo di indicatore (IP, URL, Hash, Dominio) è un IOC a tutti gli effetti. Tutti condividono il medesimo contratto pubblico (ad esempio, l'esposizione del metodo get_severity_score), ma lo implementano in base alla natura del dato.

Perché non un if/match sul tipo? L'uso di una singola classe con uno switch centralizzato avrebbe violato il Principio Aperto/Chiuso (Open/Closed Principle). Avrebbe accentrato una logica che appartiene intimamente a ciascun tipo di indicatore, costringendoci a modificare il motore centrale a ogni aggiunta di una nuova sorgente. Con l'ereditarietà, aggiungere una sorgente significa unicamente creare una nuova sottoclasse in modo isolato.

Perché non la composizione? La composizione esprime una relazione has-a (ha un), ma in questo dominio un indirizzo IP non "contiene" un indicatore, è l'indicatore. Inoltre, il modo in cui il punteggio di pericolosità viene calcolato dipende strettamente dalla struttura dati unica fornita da quella specifica API, non è un modulo di calcolo generico interscambiabile.

Dove si sfrutta concretamente il polimorfismo? Il polimorfismo vive nel calcolo dello score. Il sistema chiamante (come la CLI o il modulo di esportazione) invoca semplicemente ioc.get_severity_score() senza preoccuparsi dell'implementazione sottostante, che varia per ogni classe:

IpIOC (AbuseIPDB): Restituisce una confidence da 0 a 100, usata direttamente.

UrlIOC (URLhaus): Restituisce un dato binario; lo score è derivato logicamente (attivo = massimo, archiviato = medio, ignoto = nullo).

FileIOC (VirusTotal): Calcola una percentuale basata sul rapporto tra motori antivirus segnalanti e motori totali.

DomainIOC (OTX): Converte i "pulse" in scaglioni di pericolosità, applicando una whitelist per i falsi positivi.

## Altre scelte non ovvie
Struttura dati per la Cache (JSON invece di SQLite): Nonostante un database relazionale offra maggiore scalabilità, per i volumi di una sessione utente standard le prestazioni sono equivalenti. Abbiamo preferito un file di testo JSON perché è facilmente ispezionabile (tramite un semplice cat). Questo permette di dimostrare in modo trasparente che salviamo solo i dati strettamente necessari, scartando i payload grezzi delle API (che potrebbero contenere metadati sensibili o nomi di file caricati da altri utenti, come nel caso di VirusTotal).

Caching dei risultati negativi: Memorizziamo attivamente anche le ricerche che non restituiscono minacce. Per API con limiti di rate limit molto stringenti (es. VirusTotal gratuito consente 4 richieste al minuto), interrogare ripetutamente un indicatore ignoto sprecherebbe quote preziose. Utilizziamo un valore sentinella nella cache per distinguere un "mai cercato" da un "cercato ma pulito".

Separazione delle responsabilità (Client vs IOC): I client di rete fanno solo rete (HTTP request e restituzione JSON), mentre gli IOC fanno solo interpretazione. La regola d'oro del design è stata: import requests dentro una classe IOC indica un errore di progettazione. Questo garantisce la totale testabilità offline delle classi IOC.

Gestione degli errori non propagata: I client di rete gestiscono internamente i timeout o gli errori di connessione, restituendo un oggetto vuoto o None senza sollevare eccezioni verso l'alto. Di conseguenza, il ciclo principale della CLI non è inquinato da continui blocchi try/except per la rete, mantenendo l'esperienza utente fluida.

## Alternative scartate
TTL (Time-To-Live) differenziato per la cache: In fase di progettazione avevamo ipotizzato due TTL separati: uno più lungo per i positivi (minacce accertate) e uno molto breve per i negativi (che potrebbero diventare malevoli poco dopo). Per mantenere la complessità in linea con un progetto didattico, abbiamo scartato l'idea accettando il compromesso di un TTL unico fissato a 6 ore.