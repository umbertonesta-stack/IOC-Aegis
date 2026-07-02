
def mostra_menu():
    print("\n=== IOC-AEGIS PANELLO DI CONTROLLO ===")
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
def main():
    while True:
        mostra_menu()
        scelta = input("Seleziona un'opzione (0-5): ").strip()

        match scelta:

            case "1":
                while True:
                    sub_scelta = sottomenu_analisi()

                    if sub_scelta == "0":
                        break

                    if sub_scelta in ("1", "2", "3", "4"):
                        elemento = input("Incolla l'elemento da scansionare: ").strip()
                        print(f"\nContatto API e verifica in corso per: {elemento}...")
                        print("Verdetto: Analisi completata.")
                        print(" -> [LOG] Ricerca salvata in cronologia.")
                    else:
                        print("! Opzione non valida. Riprova.")

            case "2":
                print("\nGenerazione regole di esportazione per la difesa attiva...")
                soglia = input("Inserisci soglia minima di score per il blocco (es. 80): ").strip()
                print(f" File 'blacklist_firewall.txt' generato per gli IP con score >= {soglia}!")

            case "3":
                print("\nVisualizzazione dei Malware Hash noti in memoria (Threat Intelligence)...")

            case "4":
                print("\nCronologia delle ultime ricerche effettuate (history.log)...")

            case "5":
                print("\n--- REGEX LOG SCANNER ---")
                percorso_log = input("Inserisci il percorso del file di log (es. access.log): ").strip()
                print(f"Apertura di {percorso_log} e applicazione delle regex...")
                print("Estrazione completata!")

            case "0":
                print("\nChiusura di IOC-Aegis. Arrivederci!")
                break

            case _:
                print("! Opzione non valida. Riprova.")


if __name__ == "__main__":
    main()
