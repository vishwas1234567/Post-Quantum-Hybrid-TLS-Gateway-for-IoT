"""Minimal MQTT 3.1.1 client (CONNECT / PUBLISH / DISCONNECT) on a plain socket.

Deliberately dependency-free: an IoT-class node should not need paho just to
push telemetry, and it lets us run over Python's ssl module whose OpenSSL
build decides the TLS key exchange.
"""
import socket
import struct


def enc_len(n):
    """MQTT 'remaining length' variable-byte encoding."""
    out = bytearray()
    while True:
        byte = n % 128
        n //= 128
        if n:
            byte |= 0x80
        out.append(byte)
        if not n:
            return bytes(out)


def dec_len(read_byte):
    mult, value = 1, 0
    while True:
        b = read_byte()
        value += (b & 0x7F) * mult
        if not b & 0x80:
            return value
        mult *= 128


def enc_str(s):
    raw = s.encode() if isinstance(s, str) else s
    return struct.pack("!H", len(raw)) + raw


def connect_packet(client_id, keepalive=60):
    var = enc_str("MQTT") + bytes([4, 0x02]) + struct.pack("!H", keepalive)
    payload = enc_str(client_id)
    body = var + payload
    return bytes([0x10]) + enc_len(len(body)) + body


def publish_packet(topic, payload, qos=0, packet_id=1):
    if isinstance(payload, str):
        payload = payload.encode()
    body = enc_str(topic)
    if qos:
        body += struct.pack("!H", packet_id)
    body += payload
    return bytes([0x30 | (qos << 1)]) + enc_len(len(body)) + body


DISCONNECT = bytes([0xE0, 0x00])


class MQTTClient:
    def __init__(self, sock, client_id):
        self.sock = sock
        self.client_id = client_id
        self._pid = 0

    def _recv_exact(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("broker closed connection")
            buf += chunk
        return buf

    def _read_packet(self):
        first = self._recv_exact(1)[0]
        length = dec_len(lambda: self._recv_exact(1)[0])
        return first, self._recv_exact(length)

    def connect(self, keepalive=60):
        self.sock.sendall(connect_packet(self.client_id, keepalive))
        first, body = self._read_packet()
        if first != 0x20 or len(body) != 2 or body[1] != 0:
            raise ConnectionError("CONNACK refused: %r %r" % (first, body))

    def publish(self, topic, payload, qos=0):
        self._pid = self._pid % 65535 + 1
        self.sock.sendall(publish_packet(topic, payload, qos, self._pid))
        if qos == 1:
            first, body = self._read_packet()
            if first != 0x40:
                raise ConnectionError("expected PUBACK, got %r" % first)

    def close(self):
        try:
            self.sock.sendall(DISCONNECT)
        except OSError:
            pass
        self.sock.close()


def open_plain(host, port, timeout=10):
    return socket.create_connection((host, port), timeout=timeout)
