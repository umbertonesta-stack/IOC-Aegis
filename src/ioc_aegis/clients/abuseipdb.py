import os
from parsers.ip import IpIOC
import requests
class AbuseIPDBClient:
    
    def __init__(self):
        self.api_key=os.getenv("ABUSEIPDB_API_KEY")
        if not self.api_key:
            raise ValueError("Errore:la variabile ABUSEIPDB_API_KEY non è impostata")
        
        self.base_url="https://api.abuseipdb.com/api/v2/check"
        self.headers={
            "Accept": "application/json",
            "Key":self.api_key
        }

    def check_ip(self, ip_address: str) -> IpIOC | None:
        params={
            "ipaddress":ip_address,
            "maxAgeInDays":90
        }
        try:
            response=request.get(url=self.base_url,headers=self.headers,params=params,timeout=10)
            
            response.raise_for_status()
            data=response.json().get("data",{})
            
            if not data:
                    print(f"[!] Nessun dato restituito per l'IP {ip_address}")
                    return None

                # 6. Compiliamo il "fascicolo" passandogli i dati grezzi
            ioc = IpIOC(
                value=data["ipAddress"],
                source="AbuseIPDB",
                abuse_score=data["abuseConfidenceScore"]
            )
            return ioc
        
        except requests.exceptions.RequestException as e:
                # Cattura problemi di rete (niente internet, timeout, errori HTTP del server)
                print(f"! Errore di connessione ad AbuseIPDB: {e}")
                return None
        except KeyError as e:
            # Cattura errori se AbuseIPDB cambia il formato del JSON in futuro
            print(f"! Errore nel formato dei dati (chiave mancante): {e}")
            return None
        except ValueError as e:
            # Cattura gli errori "logici" generati dalla classe IpIOC (es. score negativo)
            print(f"! Dati non validi respinti dal modello per l'IP {ip_address}: {e}")
            return None