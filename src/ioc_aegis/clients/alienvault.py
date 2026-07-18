import os
import requests
from dotenv import load_dotenv

from ..cache import Cache
from ..parsers.domain import DomainIOC

load_dotenv()

class AlienVaultClient:
   

    def __init__(self, cache: Cache):
        self.api_key = os.getenv("ALIENVAULT_API_KEY")
        self.cache = cache
        self.base_url = "https://otx.alienvault.com/api/v1/indicators"
        self.headers = {"X-OTX-API-KEY": self.api_key} if self.api_key else {}
        
        if not self.api_key:
            raise ValueError("Chiave ALIENVAULT_API_KEY mancante nel file .env")

    def check_domain(self, domain: str):
       
        # LETTURA DALLA CACHE 
        dati_cache = self.cache.get("alienvault", domain)
        
        if dati_cache is not None:
            if self.cache.is_nessun_risultato(dati_cache):
                print(f"[-] Nessun report dannoso in OTX per {domain} (letto da cache).")
                return None
            
            print(f"[+] Dati dominio '{domain}' recuperati dalla cache locale!")
            return DomainIOC(
                value=domain, 
                source="AlienVault OTX", 
                pulse_count=dati_cache.get("pulse_count", 0)
            )


        url = f"{self.base_url}/domain/{domain}/general"
        
        try:
            response = requests.get(url, headers=self.headers)
            
            if response.status_code == 200:
                data = response.json()
                pulse_info = data.get("pulse_info", {})
                pulse_count = pulse_info.get("count", 0)
                
                # Se il dominio esiste ma ha 0 minacce, salviamo "Nessun Risultato"
                if pulse_count == 0:
                    print(f"[-] Nessuna minaccia nota (Pulse) trovata su AlienVault per {domain}.")
                    self.cache.set("alienvault", domain, self.cache.NESSUN_RISULTATO)
                    return None
                
                # Se troviamo minacce, salviamo il conteggio nella cache
                self.cache.set("alienvault", domain, {"pulse_count": pulse_count})
                
                # e ritorniamo oggetto
                return DomainIOC(
                    value=domain, 
                    source="AlienVault OTX", 
                    pulse_count=pulse_count
                )
                
            elif response.status_code == 404:
                print(f"[-] Dominio '{domain}' sconosciuto per AlienVault.")
                self.cache.set("alienvault", domain, self.cache.NESSUN_RISULTATO)
                return None
                
            elif response.status_code == 401:
                print("[!] Errore API: 401 Non autorizzato. Controlla la chiave di AlienVault in .env.")
                return None
                
            else:
                print(f"[!] Errore inaspettato API AlienVault: {response.status_code}")
                return None
                
        except requests.exceptions.RequestException as e:
            print(f"[!] Errore di rete con AlienVault: {e}")
            return None