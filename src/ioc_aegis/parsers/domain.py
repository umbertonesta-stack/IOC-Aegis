class DomainIOC:
    def __init__(self, value: str, source: str, pulse_count: int = 0):
        self.value = value
        self.source = source
        self.pulse_count = pulse_count
        
        # Whitelist dei domini legittimi spesso "abusati" e segnalati per errore
        self.whitelist = [
            "gmail.com",
            "google.com",
            "microsoft.com",
            "windowsupdate.com",
            "apple.com",
            "amazon.com",
            "aws.amazon.com",
            "cloudflare.com",
            "github.com"
        ]

    def get_severity_score(self) -> int:
       
        if self.value.lower() in self.whitelist:
            return 0  
        if self.pulse_count <= 2:
            return 25
        elif self.pulse_count <= 5:
            return 50
        elif self.pulse_count <= 10:
            return 75
        else:
            return 100