"""Leak guard: every test fails if its logs or printed output contain the card, the test secret or a credential."""
import logging

import pytest

from helpers import CARD, SECRET

FORBIDDEN = (CARD, SECRET, "Bearer ", "Basic ")


def check_no_leak(text: str) -> None:
    for needle in FORBIDDEN:
        assert needle not in text, "leak guard: forbidden text found in logs or output"


@pytest.fixture(autouse=True)
def no_leaks(caplog, capsys):
    caplog.set_level(logging.DEBUG)
    yield
    out = capsys.readouterr()
    check_no_leak("\n".join(r.getMessage() for r in caplog.records) + out.out + out.err)


LOCAL_HOSTS = ("127.0.0.1", "::1", "localhost")


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    """No test reaches the network: only this machine's loopback address resolves."""
    import socket
    real = socket.getaddrinfo

    def getaddrinfo(host, *args, **kwargs):
        if host not in LOCAL_HOSTS:
            raise socket.gaierror(f"offline test: {host} not resolved")
        return real(host, *args, **kwargs)
    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
