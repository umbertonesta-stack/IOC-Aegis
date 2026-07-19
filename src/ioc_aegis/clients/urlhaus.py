"""Client per l'API di URLhaus (abuse.ch): URL segnalati come malevoli."""

import os

import requests

from ..cache import Cache
from ..parsers.url import UrlIOC


class URLhausClient:

    SORGENTE = "URLhaus"
    ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/"

    def __init__(self, cache: Cache | None = None):
        self.api_key = os.environ.get("URLHAUS_API_KEY")
        if not self.api_key:
            raise ValueError("Errore: URLHAUS_API_KEY non configurata nel file .env!")

        self.headers = {"Auth-Key": self.api_key}
        self.cache = cache or Cache()

    def check_url(self, url_address: str) -> UrlIOC | None:
        # 1. Prima la cache.
        salvato = self.cache.get(self.SORGENTE, url_address)
        if salvato is not None:
            if self.cache.is_nessun_risultato(salvato):
                print("  (da cache) URL non presente nel database URLhaus.")
                return None
            print("  (da cache locale)")
            return UrlIOC.from_urlhaus(url_address, salvato)

        # 2. Interrogazione dell'API.
        try:
            response = requests.post(
                self.ENDPOINT,
                headers=self.headers,
                data={"url": url_address},
                timeout=10,
            )
            response.raise_for_status()

            data = response.json()
            query_status = data.get("query_status")

            if query_status == "no_results":
                self.cache.set(self.SORGENTE, url_address, Cache.NESSUN_RISULTATO)
                print("URL non presente nel database URLhaus (nessuna evidenza).")
                return None

            if query_status != "ok":

                print(f"Risposta anomala da URLhaus (query_status: {query_status}).")
                return None

            da_salvare = {
                "query_status": query_status,
                "url_status": data.get("url_status", "unknown"),
                "threat": data.get("threat"),
                "tags": data.get("tags") or [],
            }
            self.cache.set(self.SORGENTE, url_address, da_salvare)

            return UrlIOC.from_urlhaus(data.get("url", url_address), da_salvare)

        except requests.exceptions.RequestException as e:
            print(f"Errore di rete nella chiamata a URLhaus: {e}")
            return None
        except ValueError as e:
            print(f"Dato non valido ricevuto da URLhaus: {e}")
            return None