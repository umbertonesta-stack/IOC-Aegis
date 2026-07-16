"""Interfaccia a riga di comando di IOC-Aegis."""

from datetime import datetime
from dotenv import load_dotenv

from .cache import Cache
from .clients.abuseipdb import AbuseIPDBClient
from .clients.urlhaus import URLhausClient
from .clients.virustotal import VirusTotalClient

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

        if sub_scelta == "3":
            print("\nAnalisi di mail e domini non ancora implementata.")
            continue

        elemento = input("Incolla l'elemento da scansionare: ").strip()
        if not elemento:
            print("! Nessun elemento inserito.")
            continue

        print(f"\nVerifica in corso per: {elemento}...")

        risultato = None
        if sub_scelta == "1":
            risultato = clients["ip"].check_ip(elemento)
        elif sub_scelta == "2":
            risultato = clients["url"].check_url(elemento)
        elif sub_scelta == "4":
            risultato = clients["hash"].check_hash(elemento)

        if risultato is not None:
            mostra_risultato(risultato)
        # Se il risultato e' None il client ha gia' spiegato il motivo
        # (nessun dato, errore di rete, chiave mancante...).


def main():
    # Una sola istanza di Cache, condivisa da tutti i client: istanze separate
    # che puntano allo stesso file si sovrascriverebbero a vicenda.
    cache = Cache()

    # I client vengono creati una volta sola all'avvio, non a ogni ricerca.
    # Se una chiave API manca, il client corrispondente non viene istanziato ma
    # gli altri restano utilizzabili.
    clients = {}
    for nome, classe, metodo in (
        ("ip", AbuseIPDBClient, "AbuseIPDB"),
        ("url", URLhausClient, "URLhaus"),
        ("hash", VirusTotalClient, "VirusTotal"),
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
                print("\n[non ancora implementato] Elenco degli hash malware noti.")

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