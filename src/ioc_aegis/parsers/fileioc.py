from parsers.base import IOC

class FileIOC(IOC):
    def __init__(self, value: str, source: str, malicious_votes: int, total_votes: int):
        super().__init__(value, source)

        if malicious_votes <0 or total_votes<=0:
            raise ValueError("Errore: I voti non possono essere negativi e i voti totali devono essere > 0!")
        
        if malicious_votes > total_votes:
            raise ValueError(f"Errore logico: i voti malevoli ({malicious_votes}) non possono superare il totale ({total_votes})!")
        
        self.malicious_votes=malicious_votes
        self.total_votes=total_votes

    def get_severity_score(self) ->int:
        percentuale = (self.malicious_votes / self.total_votes) * 100 # ho n antivirus calcolo la percentuale di antivirus che hanno segnalato il file
        return int(percentuale)