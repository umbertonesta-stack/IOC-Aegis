"""Test di esempio per la gerarchia di controllo.

⚠️  ESEMPIO DA SOSTITUIRE con i test del tuo progetto. Nota in particolare
    `test_polimorfismo`: un buon progetto ha almeno un test che sfrutta il
    polimorfismo della gerarchia (richiesto dalla rubrica, voce "Test unitari").
"""

from progetto.core.base import Controllo
from progetto.core.controlli import (
    ControlloLunghezzaMinima,
    ControlloNonVuoto,
    esegui_tutti,
)


def test_controllo_non_vuoto_fallisce_su_stringa_vuota():
    esito = ControlloNonVuoto().esegui("   ")
    assert esito.superato is False


def test_controllo_non_vuoto_passa_su_testo():
    esito = ControlloNonVuoto().esegui("ciao")
    assert esito.superato is True


def test_lunghezza_minima_rispetta_la_soglia():
    controllo = ControlloLunghezzaMinima(minimo=5)
    assert controllo.esegui("1234").superato is False
    assert controllo.esegui("12345").superato is True


def test_polimorfismo():
    """`esegui_tutti` lavora su `Controllo` senza conoscere le sottoclassi."""
    controlli: list[Controllo] = [ControlloNonVuoto(), ControlloLunghezzaMinima(3)]
    esiti = esegui_tutti(controlli, "ok!")
    assert [e.superato for e in esiti] == [True, True]
    # Ogni elemento è comunque un Controllo, qualunque sia la sua classe concreta.
    assert all(isinstance(c, Controllo) for c in controlli)
