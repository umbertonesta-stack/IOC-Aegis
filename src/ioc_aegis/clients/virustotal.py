"""Client per l'API di VirusTotal: verdetti antivirus su hash di file."""

import os

import requests

from ..cache import Cache
from ..parsers.fileioc import FileIOC


class VirusTotalClient:

    SORGENTE = "VirusTotal"
    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, cache: Cache | None = None):

        self.api_key = os.environ.get("VIRUSTOTAL_API_KEY")
        self.headers = {"x-apikey": self.api_key}
        self.cache = cache or Cache()

    def check_hash(self, file_hash: str) -> FileIOC | None:
        if not self.api_key:
            print("Errore: VIRUSTOTAL_API_KEY non configurata nel file .env!")
            return None

        salvato = self.cache.get(self.SORGENTE, file_hash)
        if salvato is not None:
            if self.cache.is_nessun_risultato(salvato):
                print("  (da cache) Hash sconosciuto a VirusTotal.")
                return None
            print("  (da cache locale)")
            return FileIOC(
                file_hash,
                self.SORGENTE,
                malicious_votes=salvato["malicious_votes"],
                total_votes=salvato["total_votes"],
            )

        try:
            response = requests.get(
                f"{self.BASE_URL}/files/{file_hash}", headers=self.headers, timeout=10
            )

            if response.status_code == 404:
                self.cache.set(self.SORGENTE, file_hash, Cache.NESSUN_RISULTATO)
                print("Hash mai visto da VirusTotal.")
                return None

            response.raise_for_status()

            attributes = response.json()["data"]["attributes"]
            stats = attributes["last_analysis_stats"]

            voti_maligni = stats["malicious"]

            voti_totali = sum(stats.values())

            self.cache.set(
                self.SORGENTE,
                file_hash,
                {"malicious_votes": voti_maligni, "total_votes": voti_totali},
            )

            return FileIOC(
                file_hash,
                self.SORGENTE,
                malicious_votes=voti_maligni,
                total_votes=voti_totali,
            )

        except requests.exceptions.RequestException as e:
            print(f"Errore di rete nella chiamata a VirusTotal: {e}")
            return None
        except KeyError as e:
            print(f"Formato di risposta inatteso da VirusTotal, campo mancante: {e}")
            return None
        except ValueError as e:
            print(f"Dato non valido ricevuto da VirusTotal: {e}")
            return None