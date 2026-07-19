from .base import IOC


class UrlIOC(IOC):

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

        self.query_status = query_status.strip().lower()
        # Stato dell'URL segnalato: "online", "offline" oppure "unknown".
        self.url_status = url_status.strip().lower()
        # Categoria della minaccia (es. "malware_download"). Metadato, non
        # concorre al calcolo dello score.
        self.threat = threat
        # Famiglia di malware / campagna. Metadato, come sopra.
        self.tags = tags or []

    def get_severity_score(self) -> int:

        if self.query_status != "ok":
            return 0

        if self.url_status == "online":
            return 95

        if self.url_status == "offline":
            return 65

        return 50

    @classmethod
    def from_urlhaus(cls, url: str, raw: dict) -> "UrlIOC":

        return cls(
            value=url,
            source="URLhaus",
            query_status=raw.get("query_status", "no_results"),
            url_status=raw.get("url_status", "unknown"),
            threat=raw.get("threat"),
            tags=raw.get("tags") or [],
        )