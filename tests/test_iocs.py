"""Test unitari sulla gerarchia degli indicatori (IOC) e sul loro scoring.

Gli IOC sono oggetti puri: il calcolo dello score non dipende dalla rete, quindi
questi test girano offline e sono deterministici.
"""

import pytest

from ioc_aegis.parsers.base import IOC
from ioc_aegis.parsers.ip import IpIOC
from ioc_aegis.parsers.url import UrlIOC
from ioc_aegis.parsers.fileioc import FileIOC
from ioc_aegis.parsers.domain import DomainIOC


# --- Classe base: validazione comune ---

def test_ioc_e_astratta():
    """IOC non deve essere istanziabile direttamente (metodo astratto)."""
    with pytest.raises(TypeError):
        IOC("valore", "sorgente")


def test_valore_vuoto_solleva_errore():
    with pytest.raises(ValueError):
        IpIOC("   ", "AbuseIPDB", abuse_score=50)


def test_sorgente_vuota_solleva_errore():
    with pytest.raises(ValueError):
        IpIOC("8.8.8.8", "  ", abuse_score=50)


# --- IpIOC: score diretto da AbuseIPDB ---

def test_ip_score_diretto():
    assert IpIOC("8.8.8.8", "AbuseIPDB", abuse_score=99).get_severity_score() == 99
    assert IpIOC("8.8.8.8", "AbuseIPDB", abuse_score=0).get_severity_score() == 0


def test_ip_score_fuori_range_rifiutato():
    with pytest.raises(ValueError):
        IpIOC("8.8.8.8", "AbuseIPDB", abuse_score=101)
    with pytest.raises(ValueError):
        IpIOC("8.8.8.8", "AbuseIPDB", abuse_score=-1)


# --- UrlIOC: score derivato dallo stato ---

def test_url_online_score_alto():
    ioc = UrlIOC("http://x.test", "URLhaus", query_status="ok", url_status="online")
    assert ioc.get_severity_score() == 95


def test_url_offline_score_medio():
    ioc = UrlIOC("http://x.test", "URLhaus", query_status="ok", url_status="offline")
    assert ioc.get_severity_score() == 65


def test_url_stato_ignoto():
    ioc = UrlIOC("http://x.test", "URLhaus", query_status="ok", url_status="unknown")
    assert ioc.get_severity_score() == 50


def test_url_non_in_database_score_zero():
    ioc = UrlIOC("http://x.test", "URLhaus", query_status="no_results")
    assert ioc.get_severity_score() == 0


def test_url_from_urlhaus_factory():
    raw = {"query_status": "ok", "url_status": "online", "threat": "malware", "tags": ["x"]}
    ioc = UrlIOC.from_urlhaus("http://x.test", raw)
    assert ioc.get_severity_score() == 95
    assert ioc.threat == "malware"


# --- FileIOC: score come percentuale di rilevazioni ---

def test_file_percentuale_rilevazioni():
    # 60 motori su 80 lo segnalano → 75%
    ioc = FileIOC("abc123", "VirusTotal", malicious_votes=60, total_votes=80)
    assert ioc.get_severity_score() == 75


def test_file_nessuna_rilevazione():
    ioc = FileIOC("abc123", "VirusTotal", malicious_votes=0, total_votes=70)
    assert ioc.get_severity_score() == 0


def test_file_totale_non_positivo_rifiutato():
    with pytest.raises(ValueError):
        FileIOC("abc123", "VirusTotal", malicious_votes=0, total_votes=0)


def test_file_maligni_oltre_totale_rifiutato():
    with pytest.raises(ValueError):
        FileIOC("abc123", "VirusTotal", malicious_votes=10, total_votes=5)


# --- DomainIOC: score a scaglioni + whitelist ---

def test_domain_whitelist_azzera():
    ioc = DomainIOC("google.com", "AlienVault OTX", pulse_count=50)
    assert ioc.get_severity_score() == 0  # whitelist: pulse ignorati


def test_domain_scaglioni():
    fonte = "AlienVault OTX"
    assert DomainIOC("a.test", fonte, pulse_count=1).get_severity_score() == 25
    assert DomainIOC("a.test", fonte, pulse_count=4).get_severity_score() == 50
    assert DomainIOC("a.test", fonte, pulse_count=8).get_severity_score() == 75
    assert DomainIOC("a.test", fonte, pulse_count=20).get_severity_score() == 100
