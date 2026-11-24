"""End-to-end tests: real TLS handshakes against a real in-process gateway.

Run:  python -m unittest discover -s tests -v
Requires Python linked against OpenSSL >= 3.5 (ML-KEM); otherwise PQC tests skip.
"""
import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "edge"))
sys.path.insert(0, os.path.join(ROOT, "analysis"))
sys.path.insert(0, os.path.join(ROOT, "bench"))

HAS_PQC = ssl.OPENSSL_VERSION_INFO >= (3, 5)


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Echo(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):  # noqa: N802
        n = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(n)
        out = json.dumps({"bytes": len(body)}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *_):
        pass


class GatewayCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        subprocess.run(["sh", os.path.join(ROOT, "certs/gen_certs.sh"), cls.tmp],
                       check=True, capture_output=True)
        cls.ca = os.path.join(cls.tmp, "ca.crt")
        cls.backend = HTTPServer(("127.0.0.1", free_port()), Echo)
        threading.Thread(target=cls.backend.serve_forever, daemon=True).start()
        cls.gw = {}
        for prof in ("classical", "hybrid", "pqc"):
            port = free_port()
            env = dict(os.environ, GATEWAY_PROFILE=prof,
                       OPENSSL_CONF=os.path.join(ROOT, "gateway", "openssl-%s.cnf" % prof))
            proc = subprocess.Popen(
                [sys.executable, os.path.join(ROOT, "gateway/pqc_gateway.py"),
                 "--cert", os.path.join(cls.tmp, "server.crt"),
                 "--key", os.path.join(cls.tmp, "server.key"),
                 "--host", "127.0.0.1", "--stats-interval", "600",
                 "--map", "%d=127.0.0.1:%d" % (port, cls.backend.server_port)],
                env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            cls.gw[prof] = (port, proc)
        for port, _ in cls.gw.values():
            for _ in range(50):
                try:
                    socket.create_connection(("127.0.0.1", port), 0.2).close()
                    break
                except OSError:
                    time.sleep(0.1)

    @classmethod
    def tearDownClass(cls):
        for _, proc in cls.gw.values():
            proc.terminate()
            proc.wait(5)
        cls.backend.shutdown()

    def run_edge(self, profile, port, **kw):
        cmd = [sys.executable, os.path.join(ROOT, "edge/edge_node.py"), "--profile", profile,
               "--proto", "https", "--port", str(port), "--ca", self.ca, "--count", "2"]
        return subprocess.run(cmd, capture_output=True, text=True, timeout=30)

    def probe(self, profile, port):
        out = subprocess.run(
            [sys.executable, os.path.join(ROOT, "analysis/handshake_probe.py"),
             "--profile", profile, "--port", str(port), "--ca", self.ca],
            capture_output=True, text=True, timeout=30, check=True)
        return json.loads(out.stdout)

    def test_classical_roundtrip(self):
        r = self.run_edge("classical", self.gw["classical"][0])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout)["sent"], 2)

    @unittest.skipUnless(HAS_PQC, "needs OpenSSL >= 3.5")
    def test_hybrid_negotiates_x25519mlkem768(self):
        res = self.probe("hybrid", self.gw["hybrid"][0])
        self.assertEqual(res["server_hello"]["selected_group"][1], "X25519MLKEM768")
        self.assertEqual(res["client_hello"]["key_shares"][0][2], 1216)
        self.assertTrue(res["client_hello"]["key_share_pq"])

    @unittest.skipUnless(HAS_PQC, "needs OpenSSL >= 3.5")
    def test_pqc_only_negotiates_mlkem768(self):
        res = self.probe("pqc", self.gw["pqc"][0])
        self.assertEqual(res["server_hello"]["selected_group"][1], "MLKEM768")

    @unittest.skipUnless(HAS_PQC, "needs OpenSSL >= 3.5")
    def test_classical_client_rejected_by_pqc_gateway(self):
        r = self.run_edge("classical", self.gw["pqc"][0])
        self.assertNotEqual(r.returncode, 0)

    @unittest.skipUnless(HAS_PQC, "needs OpenSSL >= 3.5")
    def test_hybrid_gateway_still_serves_classical_clients(self):
        res = self.probe("classical", self.gw["hybrid"][0])
        self.assertEqual(res["server_hello"]["selected_group"][1], "x25519")

    @unittest.skipUnless(HAS_PQC, "needs OpenSSL >= 3.5")
    def test_pqc_handshake_is_bigger(self):
        c = self.probe("classical", self.gw["classical"][0])["total_bytes"]
        h = self.probe("hybrid", self.gw["hybrid"][0])["total_bytes"]
        self.assertGreater(h, c + 1500)


class StubBroker(threading.Thread):
    """Just enough MQTT 3.1.1 broker: CONNACK, PUBACK for QoS1, records topics."""

    def __init__(self):
        super().__init__(daemon=True)
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(4)
        self.port = self.sock.getsockname()[1]
        self.topics = []

    def _read(self, c, n):
        buf = b""
        while len(buf) < n:
            chunk = c.recv(n - len(buf))
            if not chunk:
                raise ConnectionError
            buf += chunk
        return buf

    def run(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            try:
                while True:
                    first = self._read(c, 1)[0]
                    mult, ln = 1, 0
                    while True:
                        b = self._read(c, 1)[0]
                        ln += (b & 0x7F) * mult
                        mult *= 128
                        if not b & 0x80:
                            break
                    body = self._read(c, ln)
                    kind = first >> 4
                    if kind == 1:
                        c.sendall(b"\x20\x02\x00\x00")
                    elif kind == 3:
                        tl = int.from_bytes(body[:2], "big")
                        self.topics.append(body[2:2 + tl].decode())
                        if (first >> 1) & 3 == 1:
                            c.sendall(b"\x40\x02" + body[2 + tl:4 + tl])
                    elif kind == 14:
                        break
            except (ConnectionError, OSError):
                pass
            finally:
                c.close()


class MqttThroughGateway(unittest.TestCase):
    def test_mqtt_qos1_over_tls_gateway(self):
        tmp = tempfile.mkdtemp()
        subprocess.run(["sh", os.path.join(ROOT, "certs/gen_certs.sh"), tmp],
                       check=True, capture_output=True)
        broker = StubBroker()
        broker.start()
        gport = free_port()
        gw = subprocess.Popen(
            [sys.executable, os.path.join(ROOT, "gateway/pqc_gateway.py"),
             "--cert", os.path.join(tmp, "server.crt"), "--key", os.path.join(tmp, "server.key"),
             "--host", "127.0.0.1", "--stats-interval", "600",
             "--map", "%d=127.0.0.1:%d" % (gport, broker.port)],
            env=dict(os.environ, GATEWAY_PROFILE="classical"),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for _ in range(50):
                try:
                    socket.create_connection(("127.0.0.1", gport), 0.2).close()
                    break
                except OSError:
                    time.sleep(0.1)
            r = subprocess.run(
                [sys.executable, os.path.join(ROOT, "edge/edge_node.py"), "--profile", "classical",
                 "--proto", "mqtt", "--port", str(gport), "--ca", os.path.join(tmp, "ca.crt"),
                 "--node-id", "n1", "--count", "3", "--qos", "1"],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(json.loads(r.stdout)["sent"], 3)
            self.assertEqual(broker.topics, ["sensors/n1/telemetry"] * 3)
        finally:
            gw.terminate()
            gw.wait(5)
            broker.sock.close()


class MqttCodec(unittest.TestCase):
    def test_remaining_length(self):
        from mqtt_min import dec_len, enc_len
        for n in (0, 127, 128, 16383, 16384, 2097151):
            buf = iter(enc_len(n))
            self.assertEqual(dec_len(lambda: next(buf)), n)

    def test_publish_packet(self):
        from mqtt_min import publish_packet
        p = publish_packet("a/b", b"hi", qos=0)
        self.assertEqual(p, b"\x30\x07\x00\x03a/bhi")


class PcapRoundTrip(unittest.TestCase):
    @unittest.skipUnless(HAS_PQC, "needs OpenSSL >= 3.5")
    def test_pcap_parser_on_synthetic_capture(self):
        from make_sample_pcap import build_pcap
        from pcap_clienthello import analyse
        from tls_parse import summarize_flow  # noqa: F401
        import ssl as _ssl
        # build a tiny capture from a throwaway in-process handshake is covered by
        # the gateway tests; here just make sure garbage input is handled.
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as fh:
            fh.write(build_pcap(b"\x16\x03\x01\x00\x04\x01\x00\x00\x00", b"", 8883))
            path = fh.name
        self.assertEqual(analyse(path), [])


if __name__ == "__main__":
    unittest.main()
