import csv
import os
from datetime import datetime

def export_to_csv(session_data):
    
    if not session_data:
        print("\n[!] Nessun dato da esportare in questa sessione.")
        return

    os.makedirs("reports", exist_ok=True)


    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"reports/ioc_aegis_report_{timestamp}.csv"

    headers = ["Fonte", "Target", "Pericolosita"]

    try:
        with open(filename, mode='w', newline='', encoding='utf-8') as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=headers)
            
            writer.writeheader()
            
            for row in session_data:
                writer.writerow(row)
                
        print(f"\n[+] Report esportato con successo in: {filename}")
        
    except Exception as e:
        print(f"\n[-] Errore durante l'esportazione del CSV: {e}")