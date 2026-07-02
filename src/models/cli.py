
def mostra_menu():
    print("\n=== MENU ===")
    print("1. Avvia scansione e aggregazione feed")
    print("2. Mostra minacce critiche rilevate")
    print("3. Esporta indicatori malevoli")
    print("0. Esci")

def main():
    while True:
        mostra_menu()
        scelta = input("Seleziona un'opzione (0-3): ").strip()

        if scelta == "1":
            print("\nopzione 1")


        elif scelta == "2":
            print("\nopzione 2")


        elif scelta == "3":
             print("\nopzione 3")


        elif scelta == "0":
            print("\n Chiusura di IOC-Aegis. Arrivederci!")
            break  

        else:
            print("\n! Opzione non valida. Riprova.")

if __name__ == "__main__":
    main()