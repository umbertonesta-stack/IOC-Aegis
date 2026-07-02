"""Configurazione pytest: rende importabile il pacchetto in `src/`.

Aggiunge `src/` al percorso di import, così i test possono fare
`from progetto.core...` senza installare il pacchetto.
"""

import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(SRC))
