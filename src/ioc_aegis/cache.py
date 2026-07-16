"""Cache locale delle risposte delle sorgenti di threat intelligence.

Motivazioni (vedi docs/scelte.md):

1. Risparmio di quota. I tier gratuiti sono limitati: AbuseIPDB concede 1.000
   controlli al giorno, VirusTotal appena 4 richieste al minuto. Senza cache,
   una demo con pochi indicatori esaurisce il limite.
2. Funzionamento offline. Un indicatore gia' interrogato resta consultabile
   anche se l'API e' irraggiungibile: la demo non dipende dalla rete.
3. Velocita'. Una lettura da disco e' immediata, una chiamata HTTP no.

Scelte implementative (vedi docs/scelte.md):

- Formato JSON invece di SQLite: con poche centinaia di voci le prestazioni
  sono equivalenti, ma il file resta ispezionabile con un semplice `cat` -
  un vantaggio concreto per dimostrare che non memorizziamo dati superflui.
- Vengono memorizzati anche i lookup senza risultato (URL non in database,
  hash sconosciuto): ricontrollarli consuma quota inutilmente, e con il
  limite di VirusTotal e' un costo che non possiamo permetterci.
- TTL unico di 6 ore per positivi e negativi. Avevamo valutato due TTL
  distinti (piu' lungo per i positivi, che invecchiano lentamente, e piu'
  corto per i negativi, che invecchiano in fretta perche' nuove segnalazioni
  arrivano di continuo). Abbiamo preferito un valore unico per semplicita',
  accettando una minore reattivita' sui negativi: in un progetto didattico
  la complessita' aggiuntiva non era giustificata.

Considerazioni di sicurezza (vedi docs/scelte.md):

Gli IOC in se' sono dati pubblici (IP e URL malevoli sono pubblicati da
AbuseIPDB e abuse.ch). Il rischio non e' la confidenzialita' del singolo dato,
ma il fatto che l'insieme delle ricerche riveli su cosa si sta indagando: e'
un problema di metadati. Le mitigazioni adottate:

- si salvano solo i campi necessari a ricostruire l'IOC, mai la risposta
  grezza integrale (che per VirusTotal include nomi di file e informazioni su
  chi ha caricato il campione) ne' le chiavi API;
- ogni voce ha una scadenza (TTL): i dati vecchi si eliminano da soli, il che
  limita sia lo storico conservato sia il rischio di verdetti obsoleti;
- il file ha permessi 0600 sui sistemi POSIX (vedi _restringi_permessi);
- la cronologia e' limitata a un numero fisso di voci, non cresce all'infinito;
- l'utente puo' svuotare la cache in qualsiasi momento;
- la cartella cache/ e' esclusa dal versionamento (.gitignore).
"""

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


class Cache:
    """Archivio locale su file JSON delle risposte gia' ottenute.

    Va istanziata UNA SOLA VOLTA e condivisa fra tutti i client: piu' istanze
    che puntano allo stesso file si sovrascriverebbero a vicenda, perche'
    ciascuna tiene in memoria la propria copia dei dati caricati all'avvio.
    """

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
        """Legge la cache da disco. Se il file manca o e' corrotto, riparte vuota.

        La cache e' un'ottimizzazione, non una dipendenza: un file illeggibile
        non deve impedire l'uso del programma. Nel peggiore dei casi si torna a
        interrogare le API.
        """
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
        """Limita l'accesso al file di cache al solo utente proprietario.

        Su sistemi POSIX (Linux, macOS) si usano i permessi Unix (0600). Su
        Windows il modello e' basato su ACL e richiederebbe la dipendenza
        pywin32: abbiamo scelto di non introdurla in un progetto didattico,
        accettando che il file erediti l'isolamento del profilo utente. La
        limitazione e' resa esplicita da questo controllo, invece di applicare
        un chmod che su Windows non avrebbe l'effetto atteso.
        """
        if os.name == "posix":
            os.chmod(self.percorso, 0o600)

    # --- interfaccia pubblica ---

    def _chiave(self, sorgente: str, indicatore: str) -> str:
        """Chiave univoca: lo stesso indicatore su sorgenti diverse e' voce diversa."""
        return f"{sorgente.lower()}:{indicatore.strip().lower()}"

    def get(self, sorgente: str, indicatore: str) -> dict[str, Any] | None:
        """Restituisce la voce se presente e non scaduta, altrimenti None.

        Attenzione: un valore uguale a NESSUN_RISULTATO significa "gia'
        cercato, la sorgente non aveva dati" - va distinto da None, che
        significa "mai cercato o voce scaduta". Usare is_nessun_risultato().
        """
        voce = self._dati.get(self._chiave(sorgente, indicatore))
        if voce is None:
            return None

        salvata_il = datetime.fromisoformat(voce["salvata_il"])
        if datetime.now(timezone.utc) - salvata_il > self.ttl:
            return None  # scaduta: si forza una nuova interrogazione

        return voce["dati"]

    def set(self, sorgente: str, indicatore: str, dati: dict[str, Any]) -> None:
        """Memorizza la risposta di una sorgente per un indicatore.

        Passare NESSUN_RISULTATO per registrare un lookup senza esito.
        """
        self._dati[self._chiave(sorgente, indicatore)] = {
            "salvata_il": datetime.now(timezone.utc).isoformat(),
            "dati": dati,
        }
        self._pota()
        self._salva()

    def is_nessun_risultato(self, dati: dict[str, Any]) -> bool:
        """True se la voce rappresenta un lookup andato a vuoto."""
        return dati == self.NESSUN_RISULTATO

    def _pota(self) -> None:
        """Rimuove le voci scadute e limita la cache a MAX_VOCI.

        Evita che l'archivio cresca indefinitamente: meno dati conservati,
        minore la superficie esposta.
        """
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
        """Ultime ricerche effettuate, dalla piu' recente.

        Include anche i lookup senza esito: sapere cosa e' gia' stato
        controllato senza risultato e' informazione utile quanto sapere cosa e'
        stato trovato. Il campo 'senza_risultato' permette alla CLI di
        formattare il messaggio senza esporre la sentinella interna.
        """
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