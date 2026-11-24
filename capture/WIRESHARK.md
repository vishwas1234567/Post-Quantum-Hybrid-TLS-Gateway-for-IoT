# Proving the handshake is quantum-safe in Wireshark

Capture on the interface that carries the gateway port (`any` or `lo` for
Docker published ports), or use `capture/capture.sh`.

## Display filters

| Goal | Filter |
|---|---|
| Only the gateway traffic | `tcp.port == 8884` (hybrid), `8883` classical, `8885` pure PQC |
| ClientHello | `tls.handshake.type == 1` |
| ServerHello | `tls.handshake.type == 2` |
| Client OFFERS the hybrid group | `tls.handshake.extensions_supported_group == 0x11ec` |
| Client SENDS a hybrid key share | `tls.handshake.extensions_key_share_group == 0x11ec` |
| Pure ML-KEM-768 offered | `tls.handshake.extensions_supported_group == 0x0201` |
| Server CHOSE the hybrid group | `tls.handshake.type == 2 && tls.handshake.extensions_key_share_group == 0x11ec` |
| Oversized (PQC) hellos | `tls.handshake.type == 1 && frame.len > 1000` |
| Did a client fall back to classical? | `tls.handshake.type == 2 && tls.handshake.extensions_key_share_group == 0x001d` |

Group codepoints: `0x001d` x25519, `0x11ec` X25519MLKEM768, `0x0201` MLKEM768.
Newer Wireshark builds print the group names; older ones show `Unknown (0x11ec)`.
The filters work either way.

## What to screenshot for the demo

1. ClientHello, expand **Extension: supported_groups** and **Extension: key_share**:
   the `X25519MLKEM768` entry has a **1216-byte** key exchange (32 B X25519 +
   1184 B ML-KEM-768 encapsulation key). A classical hello has a single 32-byte share.
2. ServerHello, **key_share**: the server's share is **1120 bytes** (32 B X25519 +
   1088 B ML-KEM ciphertext).
3. `Statistics -> Conversations` for the handshake byte totals, classical vs hybrid.
4. `tls` application data afterwards: MQTT is encrypted, so Wireshark shows only
   `Application Data` records (the broker side behind the gateway is plaintext
   on the private network, which is by design).

## Cross-check without Wireshark

    python analysis/pcap_clienthello.py capture/hybrid.pcap
