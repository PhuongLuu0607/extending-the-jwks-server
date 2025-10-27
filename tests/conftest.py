import pytest
from threading import Thread
from http.server import HTTPServer
from app import main

@pytest.fixture(scope="session", autouse=True)
def _server():
    server = HTTPServer((main.hostName, main.serverPort), main.MyServer)
    t = Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield
    server.shutdown()
