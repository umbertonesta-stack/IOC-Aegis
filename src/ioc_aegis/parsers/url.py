from .base import IOC


class UrlIOC(IOC):
    """Indicatore di tipo URL, valutato tramite la sorgente URLhaus (abuse.ch)."""

    def __init__(
        self,
        value: str,
        source: str,
        query_status: str,
        url_status: str = "unknown",
        threat: str | None = None,
        tags: list[str] | None = None,
    ):
        # Estende il costruttore del genitore: la validazione di value/source
        # resta in IOC, qui si aggiungono solo i campi specifici di URLhaus.
        super().__init__(value, source)

        # Esito della query: "ok" se l'URL e' presente nel database, altrimenti
        # "no_results".
        self.query_status = query_status.strip().lower()
        # Stato dell'URL segnalato: "online", "offline" oppure "unknown".
        self.url_status = url_status.strip().lower()
        # Categoria della minaccia (es. "malware_download"). Metadato, non
        # concorre al calcolo dello score.
        self.threat = threat
        # Famiglia di malware / campagna. Metadato, come sopra.
        self.tags = tags or []

    def get_severity_score(self) -> int:
        """Deriva uno score 0-100 dai dati qualitativi restituiti da URLhaus.

        A differenza di AbuseIPDB - che espone gia' una confidence numerica
        (abuseConfidenceScore, 0-100) usata direttamente da IpIOC - URLhaus
        adotta un modello binario: l'URL e' nel database oppure non lo e'.
        Lo score va quindi costruito, ed e' proprio questa differenza di
        strategia a giustificare un metodo polimorfico invece di una funzione
        unica condivisa.

        Criterio adottato: minaccia attiva > minaccia archiviata > stato ignoto.
        """
        # Nessun match nel database: nessuna evidenza per bloccare.
        # NB: non equivale a "URL pulito e verificato". URLhaus copre solo cio'
        # che e' stato segnalato, quindi l'assenza di prove non e' prova di
        # assenza.
        if self.query_status != "ok":
            return 0

        # Segnalato e ancora raggiungibile: la minaccia e' viva, priorita' massima.
        if self.url_status == "online":
            return 95

        # Segnalato ma non piu' raggiungibile: storicamente malevolo. Score piu'
        # basso ma non nullo, perche' resta utile per blocklist preventive
        # (il dominio potrebbe tornare attivo).
        if self.url_status == "offline":
            return 65

        # Segnalato, ma lo stato non e' noto: si applica prudenza, senza
        # arrivare alla soglia di blocco tipica (80).
        return 50

    @classmethod
    def from_urlhaus(cls, url: str, raw: dict) -> "UrlIOC":
        """Costruisce l'indicatore a partire dalla risposta grezza di URLhaus.

        Factory che isola la conoscenza del formato JSON della sorgente: la
        classe sa interpretare i dati, ma non e' lei ad andarli a prendere (le
        chiamate HTTP vivono nel client dedicato). Questo mantiene UrlIOC
        testabile offline.
        """
        return cls(
            value=url,
            source="URLhaus",
            query_status=raw.get("query_status", "no_results"),
            url_status=raw.get("url_status", "unknown"),
            threat=raw.get("threat"),
            tags=raw.get("tags") or [],
        )