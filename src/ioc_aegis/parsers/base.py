from abc import ABC, abstractmethod
from datetime import datetime

class IOC(ABC):

    def __init__(self,value: str, source: str):
        pulito_value = value.strip()
        pulito_source = source.strip()
        
        if not pulito_value:
            raise ValueError("Errore: Il valore (value) non può essere vuoto!")
        if not pulito_source:
            raise ValueError("Errore: La fonte (source) non può essere vuota!")

        self.value = pulito_value
        self.source = pulito_source
        self.detected_at = datetime.now()
    @abstractmethod
    def get_severity_score(self) -> int:
        pass

    def __str__(self) -> str:
        return f"[{self.source}] {self.value} | Rilevato il: {self.detected_at.strftime('%Y-%m-%d %H:%M:%S')}"
    