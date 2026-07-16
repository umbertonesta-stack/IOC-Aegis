"""Client per l'API di AbuseIPDB: reputazione degli indirizzi IP."""

import os

import requests

from ..cache import Cache
from ..parsers.ip import IpIOC


class AbuseIPDBClient:
    """Interroga AbuseIPDB e restituisce un IpIOC, oppure None in caso di errore.

    Il client si occupa solo di recuperare il dato (HTTP, autenticazione,
    parsing del JSON): l'interpretazione - cioe' il calcolo dello score - resta
    in IpIOC. La cache viene consultata prima di ogni chiamata di rete.
    """

    SORGENTE = "AbuseIPDB"
    ENDPOINT = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, cache: Cache | None = None):
        self.api_key = os.environ.get("ABUSEIPDB_API_KEY")
        if not self.api_key:
            raise ValueError("Errore: ABUSEIPDB_API_KEY non configurata nel file .env!")

        self.headers = {"Accept": "application/json", "Key": self.api_key}
        # La cache va condivisa fra tutti i client: se non viene iniettata se ne
        # crea una, ma in cli.py va passata sempre la stessa istanza.
        self.cache = cache or Cache()

    def check_ip(self, ip_address: str) -> IpIOC | None:
        # 1. La cache viene prima della rete: risparmia quota (il tier gratuito
        #    concede 1.000 controlli al giorno) e permette di operare offline.
        salvato = self.cache.get(self.SORGENTE, ip_address)
        if salvato is not None:
            if self.cache.is_nessun_risultato(salvato):
                print("  (da cache) Nessun dato disponibile per questo IP.")
                return None
            print("  (da cache locale)")
            return IpIOC(ip_address, self.SORGENTE, abuse_score=salvato["abuse_score"])

        # 2. Nessuna voce valida in cache: si interroga l'API.
        params = {"ipAddress": ip_address, "maxAgeInDays": "90"}

        try:
            response = requests.get(
                self.ENDPOINT, headers=self.headers, params=params, timeout=10
            )
            response.raise_for_status()

            data = response.json().get("data", {})

            if not data:
                # Anche l'assenza di dati va memorizzata: ripetere la richiesta
                # consumerebbe quota senza aggiungere informazione.
                self.cache.set(self.SORGENTE, ip_address, Cache.NESSUN_RISULTATO)
                print("Nessun dato restituito da AbuseIPDB per questo IP.")
                return None

            abuse_score = data["abuseConfidenceScore"]

            # 3. Si memorizza solo il campo necessario a ricostruire l'IOC:
            #    countryCode, ISP e il resto della risposta non servono.
            self.cache.set(self.SORGENTE, ip_address, {"abuse_score": abuse_score})

            return IpIOC(data["ipAddress"], self.SORGENTE, abuse_score=abuse_score)

        except requests.exceptions.RequestException as e:
            print(f"Errore di rete nella chiamata ad AbuseIPDB: {e}")
            return None
        except KeyError as e:
            print(f"Formato di risposta inatteso da AbuseIPDB, campo mancante: {e}")
            return None
        except ValueError as e:
            print(f"Dato non valido ricevuto da AbuseIPDB: {e}")
            return None