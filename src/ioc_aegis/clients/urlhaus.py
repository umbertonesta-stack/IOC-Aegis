import requests
import os
from parsers.url import UrlIOC

class URLhausClient:
    def __init__(self):
        self.api_key = os.getenv("URLHAUS_API_KEY")
        if not self.api_key:
             raise ValueError("Errore: la variabile URLHAUS_API_KEY non è impostata")
        self.base_url="https://urlhaus-api.abuse.ch/v1/url/"

        self.headers = {
            "Auth-Key": self.api_key
        }

    def check_url(self, url_address: str) -> UrlIOC | None:
        payload={
            "url":url_address
        }

        try:
            
            response = requests.post(
                url=self.base_url, 
                headers=self.headers,
                data=payload, 
                timeout=10
            )
            
            response.raise_for_status()
            data = response.json()

            if data.get("query_status") == "no_results":
                print(f"[-] Nessun risultato trovato su URLhaus per {url_address}. Probabilmente è sicuro.")
                return None
            
            elif data.get("query_status") == "ok":
                
                threat_type = data.get("threat", "sconosciuto")
                url_status = data.get("url_status", "sconosciuto")

                ioc = UrlIOC(
                    value=data.get("url", url_address),
                    source="URLhaus",
                    query_status=data.get("query_status", "ok"),
                    url_status=data.get("url_status", "unknown"), 
                    threat=threat_type,
                    tags=data.get("tags", [])
                )
                return ioc
            
            else:
                print(f"! Risposta anomala da URLhaus: {data.get('query_status')}")
                return None

        except requests.exceptions.RequestException as e:
            print(f"! Errore di connessione a URLhaus: {e}")
            return None
        except ValueError as e:
            print(f"! Dati non validi respinti dal modello per l'URL: {e}")
            return None