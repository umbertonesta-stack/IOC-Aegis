"""Client per l'API di AbuseIPDB: reputazione degli indirizzi IP."""

import os

import requests

from ..cache import Cache
from ..parsers.ip import IpIOC


class AbuseIPDBClient:

    SORGENTE = "AbuseIPDB"
    ENDPOINT = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, cache: Cache | None = None):
        self.api_key = os.environ.get("ABUSEIPDB_API_KEY")
        if not self.api_key:
            raise ValueError("Errore: ABUSEIPDB_API_KEY non configurata nel file .env!")

        self.headers = {"Accept": "application/json", "Key": self.api_key}

        self.cache = cache or Cache()

    def check_ip(self, ip_address: str) -> IpIOC | None:

        salvato = self.cache.get(self.SORGENTE, ip_address)
        if salvato is not None:
            if self.cache.is_nessun_risultato(salvato):
                print("  (da cache) Nessun dato disponibile per questo IP.")
                return None
            print("  (da cache locale)")
            return IpIOC(ip_address, self.SORGENTE, abuse_score=salvato["abuse_score"])

        params = {"ipAddress": ip_address, "maxAgeInDays": "90"}

        try:
            response = requests.get(
                self.ENDPOINT, headers=self.headers, params=params, timeout=10
            )
            response.raise_for_status()

            data = response.json().get("data", {})

            if not data:

                self.cache.set(self.SORGENTE, ip_address, Cache.NESSUN_RISULTATO)
                print("Nessun dato restituito da AbuseIPDB per questo IP.")
                return None

            abuse_score = data["abuseConfidenceScore"]

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