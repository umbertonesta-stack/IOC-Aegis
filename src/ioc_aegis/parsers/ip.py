from base import IOC

class IpIOC(IOC):

    def __init__(self,value: str, source: str, abuse_score:int):
            super().__init__(value, source)
            if abuse_score<0 or  abuse_score>100:
                  raise ValueError(f"Errore: Il punteggio di abuso ({abuse_score}) deve essere compreso tra 0 e 100!")
            self.abuse_score=abuse_score

    def get_severity_score(self) -> int:
          return self.abuse_score