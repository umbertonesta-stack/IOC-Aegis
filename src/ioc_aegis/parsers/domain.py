from .base import IOC

class DomainIOC(IOC):

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

        super().__init__(value, source)
        self.pulse_count = pulse_count

    def get_severity_score(self) -> int:

        if self.value.lower() in self.WHITELIST:
            return 0
        if self.pulse_count <= 2:
            return 25
        if self.pulse_count <= 5:
            return 50
        if self.pulse_count <= 10:
            return 75
        return 100