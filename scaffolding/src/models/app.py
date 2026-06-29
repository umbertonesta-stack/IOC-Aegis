import os
import requests
from dotenv import load_dotenv

load_dotenv()
api_key = os.environ["ABUSEIPDB_API_KEY"]   # letta dal .env, mai nel codice

url = "https://api.abuseipdb.com/api/v2/check"
params = {"ipAddress": "118.25.6.39", "maxAgeInDays": "90"}
headers = {"Accept": "application/json", "Key": api_key}

resp = requests.get(url, headers=headers, params=params)
resp.raise_for_status()
data = resp.json()["data"]

print("IP:", data["ipAddress"])
print("Score:", data["abuseConfidenceScore"])   # 0–100, sarà la base del tuo scoring
print("Paese:", data.get("countryCode"))
print("ISP:", data.get("isp"))