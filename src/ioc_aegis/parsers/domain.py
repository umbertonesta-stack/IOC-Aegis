from .base import IOC

class DomainIOC(IOC):
    # Domini legittimi spesso "abusati" e segnalati per errore: si azzera lo
    # score per evitare falsi positivi su servizi ad altissimo traffico.
    WHITELIST = frozenset({
        "gmail.com",
        "google.com",
        "microsoft.com",
        "windowsupdate.com",
        "apple.com",
        "amazon.com",
        "aws.amazon.com",
        "cloudflare.com",
        "github.com",
    })

    def __init__(self, value: str, source: str, pulse_count: int = 0):
        # Estende il costruttore della base: validazione di value/source e
        # detected_at arrivano da IOC, qui si aggiunge il dato specifico.
        super().__init__(value, source)
        self.pulse_count = pulse_count

    def get_severity_score(self) -> int:
        """Deriva uno score 0-100 dal numero di pulse OTX.

        I domini in whitelist sono considerati legittimi (score 0) a
        prescindere dalle segnalazioni. Per gli altri lo score cresce a
        scaglioni con il numero di pulse: piu' segnalazioni, piu' sospetto.
        """
        if self.value.lower() in self.WHITELIST:
            return 0
        if self.pulse_count <= 2:
            return 25
        if self.pulse_count <= 5:
            return 50
        if self.pulse_count <= 10:
            return 75
        return 100