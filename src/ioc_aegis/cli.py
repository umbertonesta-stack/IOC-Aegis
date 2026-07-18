"""Interfaccia a riga di comando di IOC-Aegis."""

from datetime import datetime
from dotenv import load_dotenv

from .cache import Cache
from .clients.abuseipdb import AbuseIPDBClient
from .clients.urlhaus import URLhausClient
from .clients.virustotal import VirusTotalClient
from .clients.alienvault import AlienVaultClient

# Le chiavi API vengono lette dal file .env prima di istanziare i client.
load_dotenv()


def mostra_menu():
    print("\n=== IOC-AEGIS PANNELLO DI CONTROLLO ===")
    print("1. Analizza Singolo Elemento (Input)")
    print("2. Esporta per Firewall e SIEM")
    print("3. Mostra Hash File / Malware Noti")
    print("4. Mostra Cronologia Investigazioni")
    print("5. Scansiona File di Log (Regex Scanner)")
    print("0. Esci")


def sottomenu_analisi():
    print("\n--- SOTTOMENU: ANALISI INPUT ---")
    print("1. Scansiona IP")
    print("2. Scansiona URL")
    print("3. Scansiona Mail / Dominio")
    print("4. Scansiona Hash File")
    print("0. Torna al menu principale")
    return input("Seleziona il tipo di indicatore (0-4): ").strip()


def mostra_risultato(ioc):
    """Stampa il verdetto di un'analisi andata a buon fine."""
    print("\nVerdetto: Analisi completata.")
    print(f"    Fonte: {ioc.source}")
    print(f"    Target: {ioc.value}")
    print(f"    Indice di Pericolosita': {ioc.get_severity_score()}%")


def mostra_cronologia(cache: Cache):
    """Elenca le ultime ricerche effettuate, comprese quelle senza esito."""
    voci = cache.cronologia(limite=20)

    if not voci:
        print("\nNessuna ricerca in cronologia.")
        return

    print(f"\n--- CRONOLOGIA ({len(voci)} ricerche piu' recenti) ---")
    for voce in voci:
        quando = datetime.fromisoformat(voce["salvata_il"]).strftime("%d/%m/%Y %H:%M")
        if voce["senza_risultato"]:
            esito = "nessun risultato"
        else:
            esito = "dati disponibili"
        print(f"  [{quando}] {voce['indicatore']} ({voce['sorgente']}) - {esito}")


def gestisci_analisi(clients: dict, cache: Cache):
    """Ciclo del sottomenu di analisi di un singolo indicatore."""
    while True:
        sub_scelta = sottomenu_analisi()

        if sub_scelta == "0":
            break

        if sub_scelta not in ("1", "2", "3", "4"):
            print("! Opzione non valida. Riprova.")
            continue

        # --- CORREZIONE: Richiesta input inserita al posto giusto ---
        elemento = input("Incolla l'elemento da scansionare: ").strip()
        if not elemento:
            print("! Nessun elemento inserito.")
            continue
        # ------------------------------------------------------------

        if sub_scelta == "3" and "@" in elemento:
            dominio = elemento.split("@")[1]
            print(f"[*] Email rilevata. Analizzo il dominio estratto: {dominio}")
            elemento = dominio # Sostituiamo l'elemento col dominio pulito

        print(f"\nVerifica in corso per: {elemento}...")
            
        risultato = None
        
        # Instradamento sicuro ai vari client
        if sub_scelta == "1":
            if "ip" in clients:
                risultato = clients["ip"].check_ip(elemento)
            else:
                print("! Client AbuseIPDB non configurato.")
                
        elif sub_scelta == "2":
            if "url" in clients:
                risultato = clients["url"].check_url(elemento)
            else:
                print("! Client URLhaus non configurato.")
                
        elif sub_scelta == "3":
            if "domain" in clients:
                risultato = clients["domain"].check_domain(elemento)
            else:
                print("! Impossibile analizzare: AlienVault non e' configurato (manca API Key in .env).")
                
        elif sub_scelta == "4":
            if "hash" in clients:
                risultato = clients["hash"].check_hash(elemento)
            else:
                print("! Client VirusTotal non configurato.")

        if risultato is not None:
            mostra_risultato(risultato)
        # Se il risultato e' None il client ha gia' spiegato il motivo
        # (nessun dato, errore di rete, chiave mancante...).


def main():
    
    cache = Cache()

    # I client vengono creati una volta sola all'avvio, non a ogni ricerca.
    # Se una chiave API manca, il client corrispondente non viene istanziato ma
    # gli altri restano utilizzabili.
    clients = {}
    for nome, classe, metodo in (
        ("ip", AbuseIPDBClient, "AbuseIPDB"),
        ("url", URLhausClient, "URLhaus"),
        ("hash", VirusTotalClient, "VirusTotal"),
        ("domain", AlienVaultClient, "AlienVault OTX"),
    ):
        try:
            clients[nome] = classe(cache=cache)
        except ValueError as e:
            print(f"[avviso] {metodo} non disponibile: {e}")

    while True:
        mostra_menu()
        scelta = input("Seleziona un'opzione (0-5): ").strip()

        match scelta:
            case "1":
                gestisci_analisi(clients, cache)

            case "2":
                print("\nGenerazione regole di esportazione per la difesa attiva...")
                soglia = input("Inserisci soglia minima di score per il blocco (es. 80): ").strip()
                print(f"[non ancora implementato] Esportazione con soglia {soglia}.")

            case "3":
                print("\nRicerca per Hash File / Malware Noti ")
                
            case "4":
                mostra_cronologia(cache)

            case "5":
                print("\n--- REGEX LOG SCANNER ---")
                print("[non ancora implementato] Scansione di file di log.")

            case "0":
                print("\nChiusura di IOC-Aegis. Arrivederci!")
                break

            case _:
                print("! Opzione non valida. Riprova.")

if __name__ == "__main__":
    main()