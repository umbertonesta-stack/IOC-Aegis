import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


class Cache:

    TTL_ORE_PREDEFINITO = 6
    MAX_VOCI = 100

    # Valore memorizzato per i lookup che non hanno prodotto risultati (URL non
    # presente nel database, hash sconosciuto a VirusTotal). Serve a distinguere
    # "mai cercato" (get restituisce None) da "gia' cercato, nessun risultato".
    NESSUN_RISULTATO: dict[str, Any] = {"__nessun_risultato__": True}

    def __init__(
        self,
        percorso: str | Path = "cache/lookups.json",
        ttl_ore: int = TTL_ORE_PREDEFINITO,
    ):
        self.percorso = Path(percorso)
        self.ttl = timedelta(hours=ttl_ore)
        self._dati: dict[str, dict[str, Any]] = self._carica()

    # --- lettura/scrittura su disco ---

    def _carica(self) -> dict[str, dict[str, Any]]:

        if not self.percorso.exists():
            return {}
        try:
            with self.percorso.open(encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return {}

    def _salva(self) -> None:
        """Scrive la cache su disco applicando i permessi restrittivi."""
        self.percorso.parent.mkdir(parents=True, exist_ok=True)
        with self.percorso.open("w", encoding="utf-8") as f:
            json.dump(self._dati, f, indent=2, ensure_ascii=False)
        self._restringi_permessi()

    def _restringi_permessi(self) -> None:

        if os.name == "posix":
            os.chmod(self.percorso, 0o600)

    # --- interfaccia pubblica ---

    def _chiave(self, sorgente: str, indicatore: str) -> str:
        """Chiave univoca: lo stesso indicatore su sorgenti diverse e' voce diversa."""
        return f"{sorgente.lower()}:{indicatore.strip().lower()}"

    def get(self, sorgente: str, indicatore: str) -> dict[str, Any] | None:

        voce = self._dati.get(self._chiave(sorgente, indicatore))
        if voce is None:
            return None

        salvata_il = datetime.fromisoformat(voce["salvata_il"])
        if datetime.now(timezone.utc) - salvata_il > self.ttl:
            return None  # scaduta: si forza una nuova interrogazione

        return voce["dati"]

    def set(self, sorgente: str, indicatore: str, dati: dict[str, Any]) -> None:

        self._dati[self._chiave(sorgente, indicatore)] = {
            "salvata_il": datetime.now(timezone.utc).isoformat(),
            "dati": dati,
        }
        self._pota()
        self._salva()

    def is_nessun_risultato(self, dati: dict[str, Any]) -> bool:

        return dati == self.NESSUN_RISULTATO

    def _pota(self) -> None:

        adesso = datetime.now(timezone.utc)
        self._dati = {
            k: v for k, v in self._dati.items()
            if adesso - datetime.fromisoformat(v["salvata_il"]) <= self.ttl
        }

        if len(self._dati) > self.MAX_VOCI:
            # Conserva le piu' recenti, scarta le piu' vecchie.
            ordinate = sorted(
                self._dati.items(),
                key=lambda kv: kv[1]["salvata_il"],
                reverse=True,
            )
            self._dati = dict(ordinate[: self.MAX_VOCI])

    def cronologia(self, limite: int = 20) -> list[dict[str, Any]]:

        ordinate = sorted(
            self._dati.items(),
            key=lambda kv: kv[1]["salvata_il"],
            reverse=True,
        )
        return [
            {
                "sorgente": chiave.split(":", 1)[0],
                "indicatore": chiave.split(":", 1)[1],
                "salvata_il": voce["salvata_il"],
                "senza_risultato": self.is_nessun_risultato(voce["dati"]),
                "dati": voce["dati"],
            }
            for chiave, voce in ordinate[:limite]
        ]

    def svuota(self) -> int:
        """Cancella l'intera cache. Restituisce il numero di voci rimosse."""
        rimosse = len(self._dati)
        self._dati = {}
        if self.percorso.exists():
            self.percorso.unlink()
        return rimosse