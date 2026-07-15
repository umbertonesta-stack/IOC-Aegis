from parsers.fileioc import FileIOC
import os
import requests

class VirusTotalClient:
    def __init__(self):
        self.api_key=os.getenv("VIRUSTOTAL_API_KEY")
        self.base_url="https://www.virustotal.com/api/v3"

        self.headers={
            "x-apikey": self.api_key
        }

    def check_hash(self, file_hash: str) -> FileIOC | None:
        if not self.api_key:
            print("! Errore critico: VIRUSTOTAL_API_KEY non trovata nel file .env!")
            return None
            
        # VirusTotal vuole l'hash direttamente nell'URL
        endpoint = f"{self.base_url}/files/{file_hash}"
        
        try:
    
            response = requests.get(
                url=endpoint, 
                headers=self.headers, 
                timeout=10
            )
            
            if response.status_code == 404:

                print(f"- Hash {file_hash} sconosciuto per VirusTotal (Mai visto prima).")

                return None
                
            response.raise_for_status()
            dati_grezzi = response.json()
            
            
            attributes = dati_grezzi.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            
            voti_maligni = stats.get("malicious", 0)
            voti_totali = sum(stats.values()) 
        
            ioc = FileIOC(
                value=file_hash,
                source="VirusTotal",
                malicious_votes=voti_maligni,
                total_votes=voti_totali
            )
            return ioc
            
        except requests.exceptions.RequestException as e:

            print(f"! Errore di connessione a VirusTotal: {e}")
            return None
        except ValueError as e:
            print(f"! I dati ricevuti da VirusTotal hanno fallito i test di sicurezza del modello: {e}")

            print(f"[!] Errore di connessione a VirusTotal: {e}")
            return None
        except ValueError as e:
            # Questo except cattura i `raise ValueError` che hai scritto tu nel fileioc.py!
            print(f"[!] I dati ricevuti da VirusTotal hanno fallito i test di sicurezza del modello: {e}")

            return None