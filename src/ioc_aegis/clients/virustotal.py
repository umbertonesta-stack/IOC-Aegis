"""Client per l'API di VirusTotal: verdetti antivirus su hash di file."""

import os

import requests

from ..cache import Cache
from ..parsers.fileioc import FileIOC


class VirusTotalClient:
    """Interroga VirusTotal per un hash e restituisce un FileIOC, oppure None.

    Il tier gratuito concede appena 4 richieste al minuto: la cache non e' qui
    un'ottimizzazione ma una necessita' operativa, altrimenti una demo con
    pochi hash esaurisce il limite.

    Nota: l'app non carica file su VirusTotal, si limita a verificare se un
    hash e' gia' in archivio.
    """

    SORGENTE = "VirusTotal"
    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, cache: Cache | None = None):
        # A differenza degli altri client, l'assenza della chiave non blocca
        # l'istanziazione: viene segnalata al momento dell'uso.
        self.api_key = os.environ.get("VIRUSTOTAL_API_KEY")
        self.headers = {"x-apikey": self.api_key}
        self.cache = cache or Cache()

    def check_hash(self, file_hash: str) -> FileIOC | None:
        if not self.api_key:
            print("Errore: VIRUSTOTAL_API_KEY non configurata nel file .env!")
            return None

        # 1. Prima la cache: con 4 richieste al minuto, ricontrollare un hash
        #    gia' noto (o gia' risultato sconosciuto) e' uno spreco che non
        #    possiamo permetterci.
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

        # 2. Interrogazione dell'API. L'hash va nel path: MD5, SHA-1 e SHA-256
        #    sono tutti accettati come identificatore.
        try:
            response = requests.get(
                f"{self.BASE_URL}/files/{file_hash}", headers=self.headers, timeout=10
            )

            # Il 404 va intercettato prima di raise_for_status: non e' un errore
            # ma un esito legittimo (hash mai analizzato).
            if response.status_code == 404:
                self.cache.set(self.SORGENTE, file_hash, Cache.NESSUN_RISULTATO)
                print("Hash mai visto da VirusTotal.")
                return None

            response.raise_for_status()

            attributes = response.json()["data"]["attributes"]
            stats = attributes["last_analysis_stats"]

            voti_maligni = stats["malicious"]
            # Tutti i motori che si sono espressi, non solo malicious+harmless:
            # include anche suspicious, undetected e timeout.
            voti_totali = sum(stats.values())

            # 3. Si memorizzano solo i due conteggi. Il resto di 'attributes'
            #    contiene nomi di file e informazioni su chi ha caricato il
            #    campione: dati che non ci servono e che non vogliamo su disco.
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