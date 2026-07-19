import pytest

from ioc_aegis.parsers.base import IOC
from ioc_aegis.parsers.ip import IpIOC
from ioc_aegis.parsers.url import UrlIOC
from ioc_aegis.parsers.fileioc import FileIOC
from ioc_aegis.parsers.domain import DomainIOC


def filtra_per_soglia(indicatori: list[IOC], soglia: int) -> list[IOC]:

    return [ioc for ioc in indicatori if ioc.get_severity_score() >= soglia]


def _indicatori_misti() -> list[IOC]:

    return [
        IpIOC("185.220.101.5", "AbuseIPDB", abuse_score=99),                         # 99
        IpIOC("8.8.8.8", "AbuseIPDB", abuse_score=0),                                #  0
        UrlIOC("http://x.test", "URLhaus", query_status="ok", url_status="online"),  # 95
        UrlIOC("http://y.test", "URLhaus", query_status="no_results"),               #  0
        FileIOC("abc", "VirusTotal", malicious_votes=60, total_votes=80),            # 75
        DomainIOC("evil.test", "AlienVault OTX", pulse_count=20),                    # 100
    ]


def test_polimorfismo_filtra():

    malevoli = filtra_per_soglia(_indicatori_misti(), soglia=80)

    # Sopra 80: IP 99, URL 95, Domain 100 → 3 indicatori.
    assert len(malevoli) == 3
    # Ogni elemento resta un IOC, qualunque sia la sua classe concreta.
    assert all(isinstance(ioc, IOC) for ioc in malevoli)


def test_soglia_piu_bassa_include_di_piu():
    # Sopra 50: si aggiunge FileIOC (75) → 4 indicatori.
    malevoli = filtra_per_soglia(_indicatori_misti(), soglia=50)
    assert len(malevoli) == 4


def test_ogni_ioc_produce_uno_score_valido():

    for ioc in _indicatori_misti():
        score = ioc.get_severity_score()
        assert isinstance(score, int)
        assert 0 <= score <= 100
