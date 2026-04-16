"""
Peer2Pear Relay Server

A minimal, untrusted relay that provides:
  - Anonymous envelope sending (POST /v1/send)
  - Authenticated WebSocket receive with push delivery (WS /v1/receive)
  - Presence (who's connected right now)
  - Store-and-forward mailbox for offline peers
  - Multi-hop forwarding to other relays (POST /v1/forward)

The relay never sees plaintext. It only reads the 'to' field (recipient
public key) from the envelope header to know where to route. Everything
else is opaque ciphertext.

Envelope wire format (first 33+ bytes):
  byte  0:       version (0x01)
  bytes 1-32:    recipient Ed25519 public key
  bytes 33+:     sealed ciphertext (ephemeral key + optional KEM ct + AEAD payload)
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import ipaddress
import logging
import os
import random
import secrets
import socket
import sqlite3
import time
from contextlib import contextmanager
from typing import Optional

import httpx
from fastapi import FastAPI, Header, HTTPException, Request, WebSocket, WebSocketDisconnect
from nacl.exceptions import BadSignatureError, CryptoError
from nacl.public import PrivateKey, PublicKey, Box
from nacl.signing import VerifyKey

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("relay")

app = FastAPI(title="Peer2Pear Relay")

# ── Config ────────────────────────────────────────────────────────────────────

MAX_ENVELOPE_BYTES = 256 * 1024                   # 262 144 B
MAX_QUEUE_ITEMS    = 5_000                         # per recipient
MAX_GLOBAL_ENVELOPES = 500_000                     # M5: total across all recipients
DEFAULT_TTL_MS     = 7 * 24 * 60 * 60 * 1_000     # 7 days
MAX_TTL_MS         = 7 * 24 * 60 * 60 * 1_000     # hard cap
REPLAY_WINDOW_MS   = 30 * 1_000                    # Fix #19: 30 s auth window (was 5 min; too long given in-memory nonce store)
CLEANUP_INTERVAL_S = 60 * 60                       # purge every hour
FORWARD_TIMEOUT_S  = 10                            # timeout for relay-to-relay forward

# DAITA: relay-side traffic analysis defense
COVER_TRAFFIC_MIN_SEC = 5   # min seconds between cover packets
COVER_TRAFFIC_MAX_SEC = 15  # max seconds between cover packets
DELIVERY_JITTER_MS    = 200 # max random delivery delay (ms)
DUMMY_VERSION         = 0x00 # version byte for dummy envelopes (client discards)

DB_PATH = os.environ.get("DB_PATH", "/tmp/peer2pear_relay.db")
# Parity fix: Go relay defaults to /data/... which lives on the persistent
# container volume.  Previously Python defaulted to /tmp/... which is
# ephemeral — the onion pubkey churned on every container restart,
# invalidating every client's cached relay_info.  Matching Go's path now.
RELAY_KEY_PATH = os.environ.get("RELAY_KEY_PATH", "/data/peer2pear_relay_x25519.key")

# Fix #7: onion routing — load or generate this relay's persistent X25519
# keypair.  The pubkey is advertised via /v1/relay_info so clients can build
# onion layers addressed to us.  The privkey peels one layer on /v1/forward-onion.
def _load_or_create_relay_key() -> PrivateKey:
    try:
        with open(RELAY_KEY_PATH, "rb") as f:
            raw = f.read()
        if len(raw) == 32:
            return PrivateKey(raw)
    except FileNotFoundError:
        pass
    key = PrivateKey.generate()
    try:
        os.makedirs(os.path.dirname(RELAY_KEY_PATH), exist_ok=True)
        with open(RELAY_KEY_PATH, "wb") as f:
            f.write(bytes(key))
        os.chmod(RELAY_KEY_PATH, 0o600)
    except OSError as e:
        log.warning("could not persist relay key: %s (using in-memory only)", e)
    return key

_relay_priv: PrivateKey  # initialised in startup event
_relay_pub_b64u: str     = ""

RATE_LIMIT_PER_MIN = 60   # max envelopes per IP per minute
RATE_LIMIT_WINDOW  = 60   # seconds

# Fix #10: per-recipient ingress cap — independent of source IP so an attacker
# rotating IPs can no longer flood a specific victim.  Recipient pubkey IS
# visible in the envelope header (or X-To for legacy), so this is enforceable
# without compromising sealed-sender anonymity.
RECIPIENT_RATE_LIMIT_PER_MIN = 300

# ── Sliding-window rate limiter (per-IP and per-recipient share the struct) ──

class _RateLimiter:
    def __init__(self) -> None:
        self._entries: dict[str, tuple[int, float]] = {}  # key → (count, reset_at)

    def allow(self, key: str, limit: int = RATE_LIMIT_PER_MIN) -> bool:
        now = time.time()
        entry = self._entries.get(key)
        if entry is None or now >= entry[1]:
            self._entries[key] = (1, now + RATE_LIMIT_WINDOW)
            return True
        count = entry[0] + 1
        self._entries[key] = (count, entry[1])
        return count <= limit

    def purge(self) -> None:
        now = time.time()
        self._entries = {k: e for k, e in self._entries.items() if now < e[1]}

_rate_limiter   = _RateLimiter()
_recip_limiter  = _RateLimiter()  # Fix #10: per-recipient ingress cap

# H3 fix: track seen auth nonces to prevent replay within the 5-min window
_seen_auth: dict[str, float] = {}  # "peer_id|ts" → expiry_time

def _check_auth_nonce(peer_id: str, ts: int) -> bool:
    """Returns True if nonce is fresh, False if replayed."""
    key = f"{peer_id}|{ts}"
    now = time.time()
    # Purge expired
    expired = [k for k, exp in _seen_auth.items() if now > exp]
    for k in expired:
        del _seen_auth[k]
    if key in _seen_auth:
        return False
    _seen_auth[key] = now + REPLAY_WINDOW_MS / 1000
    return True

TRUST_PROXY = os.environ.get("TRUST_PROXY", "") != ""

def _get_client_ip(request: Request) -> str:
    # H2 fix: only trust X-Forwarded-For when behind a known reverse proxy
    if TRUST_PROXY:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

def _hash_ip(ip: str) -> str:
    """Hash IP for rate limiting — never store raw IPs."""
    return hashlib.sha256(ip.encode()).hexdigest()[:32]


def _secure_shuffle(xs: list) -> None:
    """Fix #18: Fisher–Yates shuffle using secrets (CSPRNG) so delivery order
    on reconnect can't be correlated back to send order by a malicious relay
    observer who recorded enqueue timings."""
    for i in range(len(xs) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        xs[i], xs[j] = xs[j], xs[i]


# Fix #11: SSRF guard — parse host[:port], resolve DNS, reject any IP that
# lands in loopback / private / link-local / ULA / CGNAT / multicast /
# unspecified.  Returns None if safe, else a human-readable reason.
#
# Parity fix: match Go's net.SplitHostPort semantics exactly — the original
# `host.count(":") == 1` guard left unbracketed IPv6 literals (`::1:443`)
# as a full host string and diverged from the Go relay.
def _forward_host_reason(forward_to: str) -> Optional[str]:
    host = forward_to
    if host.startswith("["):
        close = host.find("]")
        if close <= 0:
            return "malformed IPv6 literal"
        host = host[1:close]
    else:
        # Two rules to match net.SplitHostPort:
        #   - Exactly one colon → split off port.
        #   - Zero or >=2 colons (unbracketed IPv6) → treat entire string
        #     as host (and let ipaddress / getaddrinfo validate).
        if host.count(":") == 1:
            host = host[:host.rfind(":")]
        else:
            # Try parsing as a bare IPv6 first — if it parses, use as-is.
            # Otherwise leave the string and let getaddrinfo reject it.
            try:
                ipaddress.ip_address(host)
            except ValueError:
                pass

    if not host:
        return "empty host"

    low = host.lower()
    if low in ("localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"):
        return "loopback name"

    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return "cannot resolve host"

    if not infos:
        return "no addresses resolved"

    for info in infos:
        sockaddr = info[4]
        try:
            ip = ipaddress.ip_address(sockaddr[0])
        except ValueError:
            return f"invalid address: {sockaddr[0]}"

        if (ip.is_loopback or ip.is_private or ip.is_link_local or
                ip.is_multicast or ip.is_unspecified or ip.is_reserved):
            return f"blocked address {ip}"
        # CGNAT 100.64.0.0/10 — not covered by is_private.
        if ip.version == 4:
            packed = ip.packed
            if packed[0] == 100 and (packed[1] & 0xC0) == 64:
                return "CGNAT range blocked"
    return None

def _generate_dummy_envelope() -> bytes:
    """DAITA: generate a random dummy envelope that the client discards (version 0x00)."""
    buckets = [2048, 16384, 262144]
    size = random.choice(buckets)
    buf = bytearray(secrets.token_bytes(size))
    buf[0] = DUMMY_VERSION
    return bytes(buf)

async def _cover_traffic_loop(ws: WebSocket, peer_id: str):
    """DAITA: send random dummy envelopes at unpredictable intervals."""
    try:
        while True:
            delay = random.uniform(COVER_TRAFFIC_MIN_SEC, COVER_TRAFFIC_MAX_SEC)
            await asyncio.sleep(delay)
            await ws.send_bytes(_generate_dummy_envelope())
    except Exception:
        pass  # connection closed — stop cover traffic

# ── In-memory presence ────────────────────────────────────────────────────────

# peer_id (base64url) → WebSocket connection
connected_peers: dict[str, WebSocket] = {}
# peer_id → set of peer_ids they want presence notifications for
presence_subscriptions: dict[str, set[str]] = {}

# ── SQLite helpers ────────────────────────────────────────────────────────────

def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn

@contextmanager
def db_conn():
    conn = get_db()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def init_db():
    with db_conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS envelopes (
                env_id       TEXT PRIMARY KEY,
                recipient_id TEXT NOT NULL,
                payload      BLOB NOT NULL,
                created_ms   INTEGER NOT NULL,
                expiry_ms    INTEGER NOT NULL
            );
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_env_recipient
            ON envelopes (recipient_id, created_ms);
        """)

init_db()

# ── Background cleanup ────────────────────────────────────────────────────────

async def background_purge():
    while True:
        await asyncio.sleep(CLEANUP_INTERVAL_S)
        try:
            with db_conn() as conn:
                before = conn.execute("SELECT COUNT(*) FROM envelopes;").fetchone()[0]
                conn.execute("DELETE FROM envelopes WHERE expiry_ms < ?;", (now_ms(),))
                after = conn.execute("SELECT COUNT(*) FROM envelopes;").fetchone()[0]
                removed = before - after
                if removed > 0:
                    log.info(f"purge: removed {removed} expired envelopes, {after} remaining")
            _rate_limiter.purge()
        except Exception as e:
            log.error(f"purge error: {e}")

@app.on_event("startup")
async def on_startup():
    asyncio.create_task(background_purge())

# ── Helpers ───────────────────────────────────────────────────────────────────

def now_ms() -> int:
    return int(time.time() * 1000)

def b64url_decode(s: str) -> bytes:
    pad = '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

def b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")

def verify_ed25519(id_pub_b64url: str, sig_b64url: str, message: str) -> None:
    try:
        pk = b64url_decode(id_pub_b64url)
        sig = b64url_decode(sig_b64url)
        VerifyKey(pk).verify(message.encode("utf-8"), sig)
    except (BadSignatureError, Exception):
        raise HTTPException(status_code=401, detail="signature invalid")

def purge_expired(conn: sqlite3.Connection):
    conn.execute("DELETE FROM envelopes WHERE expiry_ms < ?;", (now_ms(),))

def parse_recipient_from_envelope(data: bytes) -> str:
    """Extract recipient peer_id from envelope wire format.

    Envelope layout:
      byte  0:      version (must be 0x01)
      bytes 1-32:   recipient Ed25519 public key (32 bytes)
      bytes 33+:    sealed ciphertext
    """
    if len(data) < 33:
        raise HTTPException(400, "envelope too small (need at least 33 bytes)")
    version = data[0]
    if version != 0x01:
        raise HTTPException(400, f"unsupported envelope version: {version}")
    recipient_pub = data[1:33]
    return b64url_encode(recipient_pub)

# ── Presence helpers ──────────────────────────────────────────────────────────

async def notify_presence(peer_id: str, online: bool):
    """Push presence update to anyone subscribed to this peer_id."""
    msg = {"type": "presence", "peer_id": peer_id, "online": online}
    stale = []
    for subscriber_id, watched_peers in presence_subscriptions.items():
        if peer_id in watched_peers:
            ws = connected_peers.get(subscriber_id)
            if ws:
                try:
                    await ws.send_json(msg)
                except Exception:
                    stale.append(subscriber_id)
    for s in stale:
        connected_peers.pop(s, None)
        presence_subscriptions.pop(s, None)

# ══════════════════════════════════════════════════════════════════════════════
# NEW PROTOCOL — /v1/*
# ══════════════════════════════════════════════════════════════════════════════

# ── POST /v1/send — Anonymous envelope submission ─────────────────────────────
#
# No authentication. No sender identity. The relay reads only the recipient
# public key from the envelope header (bytes 1-32) and either:
#   - pushes it via WebSocket if the recipient is connected, or
#   - stores it in the mailbox for later delivery.
#
# Rate-limited by IP to prevent spam.

@app.post("/v1/send")
async def v1_send(request: Request):
    if not _rate_limiter.allow(_hash_ip(_get_client_ip(request))):
        raise HTTPException(429, "rate limit exceeded")
    body = await request.body()
    if len(body) > MAX_ENVELOPE_BYTES:
        raise HTTPException(413, f"envelope too large: {len(body)} > {MAX_ENVELOPE_BYTES}")

    to_id = parse_recipient_from_envelope(body)

    # Fix #10: per-recipient cap.
    if not _recip_limiter.allow(to_id, RECIPIENT_RATE_LIMIT_PER_MIN):
        raise HTTPException(429, "recipient rate limit exceeded")

    # Try direct WebSocket push
    ws = connected_peers.get(to_id)
    if ws:
        try:
            # DAITA: random delivery jitter to break timing correlation
            if DELIVERY_JITTER_MS > 0:
                await asyncio.sleep(random.uniform(0, DELIVERY_JITTER_MS / 1000))
            await ws.send_bytes(body)
            log.info(f"relayed: to={to_id[:8]}… size={len(body)}B")
            return {"delivered": True}
        except Exception:
            # WebSocket dead — remove and fall through to mailbox
            connected_peers.pop(to_id, None)
            presence_subscriptions.pop(to_id, None)

    # Recipient offline — store in mailbox
    env_id = f"{now_ms()}-{secrets.token_hex(8)}"
    exp = now_ms() + DEFAULT_TTL_MS

    with db_conn() as conn:
        purge_expired(conn)
        count = conn.execute(
            "SELECT COUNT(*) FROM envelopes WHERE recipient_id=?;",
            (to_id,),
        ).fetchone()[0]
        if count >= MAX_QUEUE_ITEMS:
            raise HTTPException(429, "mailbox full")
        # M5 fix: check global capacity to prevent disk exhaustion
        global_count = conn.execute("SELECT COUNT(*) FROM envelopes;").fetchone()[0]
        if global_count >= MAX_GLOBAL_ENVELOPES:
            raise HTTPException(429, "relay storage full")
        conn.execute(
            "INSERT OR IGNORE INTO envelopes (env_id, recipient_id, payload, created_ms, expiry_ms) "
            "VALUES (?, ?, ?, ?, ?);",
            (env_id, to_id, body, now_ms(), exp),
        )

    log.info(f"stored: to={to_id[:8]}… size={len(body)}B")
    return {"stored": True, "env_id": env_id}


# ── WS /v1/receive — Authenticated receive channel ───────────────────────────
#
# The client opens a persistent WebSocket and authenticates by signing a
# timestamp with their Ed25519 identity key. The relay then:
#   1. Delivers any stored mailbox envelopes immediately
#   2. Pushes new envelopes in real-time as they arrive via /v1/send
#   3. Responds to presence queries
#   4. Pushes presence updates for subscribed peers

@app.websocket("/v1/receive")
async def v1_receive(ws: WebSocket):
    # Fix #22: rate-limit ws auth attempts per IP.  The per-identity presence
    # sub cap (200) is bypassed by keypair rotation; capping auth attempts
    # bounds how fast an attacker can enumerate through many identities.
    client_ip = ws.client.host if ws.client else "unknown"
    if not _rate_limiter.allow(_hash_ip(client_ip)):
        await ws.close(code=4006, reason="rate limit exceeded")
        return

    await ws.accept()
    peer_id: Optional[str] = None

    try:
        # ── Step 1: Authenticate ─────────────────────────────────────────
        # First message must be JSON: { "peer_id": "...", "ts": 123, "sig": "..." }
        try:
            auth = await asyncio.wait_for(ws.receive_json(), timeout=10.0)
        except asyncio.TimeoutError:
            await ws.close(code=4001, reason="auth timeout")
            return

        peer_id = auth.get("peer_id", "")
        ts = auth.get("ts", 0)
        sig = auth.get("sig", "")

        if not peer_id or not sig:
            await ws.close(code=4002, reason="missing auth fields")
            return

        # Verify timestamp freshness
        n = now_ms()
        if abs(n - ts) > REPLAY_WINDOW_MS:
            await ws.close(code=4003, reason="timestamp outside window")
            return

        # Verify Ed25519 signature
        try:
            verify_ed25519(peer_id, sig, f"RELAY1|{peer_id}|{ts}")
        except HTTPException:
            await ws.close(code=4004, reason="auth failed")
            return

        # H3 fix: reject replayed auth messages
        if not _check_auth_nonce(peer_id, ts):
            await ws.close(code=4005, reason="auth replay")
            return

        # ── Step 2: Register presence ────────────────────────────────────
        old_ws = connected_peers.get(peer_id)
        if old_ws:
            try:
                await old_ws.close(code=4005, reason="replaced by new connection")
            except Exception:
                pass
        connected_peers[peer_id] = ws
        presence_subscriptions[peer_id] = set()
        log.info(f"connected: {peer_id[:8]}…")

        # DAITA: start cover traffic injection for this peer
        cover_task = asyncio.create_task(_cover_traffic_loop(ws, peer_id))

        # Notify subscribers that this peer came online
        await notify_presence(peer_id, online=True)

        # ── Step 3: Deliver stored envelopes ─────────────────────────────
        with db_conn() as conn:
            purge_expired(conn)
            rows = conn.execute(
                "SELECT env_id, payload FROM envelopes "
                "WHERE recipient_id=? ORDER BY created_ms ASC;",
                (peer_id,),
            ).fetchall()
            if rows:
                env_ids = [r["env_id"] for r in rows]
                # Fix #18: shuffle delivery order using secrets (CSPRNG) so the
                # relay operator can't correlate sender-enqueue-time with
                # recipient-fetch-time by matching ordinals.
                payloads = [bytes(r["payload"]) for r in rows]
                _secure_shuffle(payloads)
                for p in payloads:
                    await ws.send_bytes(p)
                placeholders = ",".join("?" * len(env_ids))
                conn.execute(
                    f"DELETE FROM envelopes WHERE env_id IN ({placeholders});",
                    env_ids,
                )
                log.info(f"delivered {len(rows)} stored envelope(s) to {peer_id[:8]}…")

        # Send auth success confirmation
        await ws.send_json({"type": "auth_ok", "peer_id": peer_id})

        # ── Step 4: Main receive loop ────────────────────────────────────
        # Handle presence queries and keepalives from the client.
        # Envelope delivery happens asynchronously via /v1/send pushing
        # to this WebSocket.
        while True:
            msg = await ws.receive_json()
            msg_type = msg.get("type", "")

            if msg_type == "presence_query":
                # Client asks: which of these peers are online?
                peer_ids = msg.get("peer_ids", [])
                results = {pid: (pid in connected_peers) for pid in peer_ids}
                await ws.send_json({"type": "presence_result", "peers": results})

            elif msg_type == "presence_subscribe":
                # Client wants push notifications when these peers come online/offline
                peer_ids = msg.get("peer_ids", [])[:200]  # H4 fix: cap at 200
                presence_subscriptions[peer_id] = set(peer_ids)
                # Send current state immediately
                results = {pid: (pid in connected_peers) for pid in peer_ids}
                await ws.send_json({"type": "presence_result", "peers": results})

            elif msg_type == "ping":
                await ws.send_json({"type": "pong"})

    except WebSocketDisconnect:
        pass
    except Exception as e:
        log.warning(f"ws error for {(peer_id or '?')[:8]}…: {e}")
    finally:
        if peer_id:
            cover_task.cancel()  # DAITA: stop cover traffic for this peer
            connected_peers.pop(peer_id, None)
            presence_subscriptions.pop(peer_id, None)
            log.info(f"disconnected: {peer_id[:8]}…")
            await notify_presence(peer_id, online=False)


# NOTE: /v1/peers endpoint removed — exposing connected peer IDs is a privacy leak.
# Presence is handled via authenticated WebSocket subscriptions in /v1/receive.


# ── POST /v1/forward — Multi-hop relay forwarding ─────────────────────────────
#
# Accepts an envelope and forwards it to another relay's /v1/send endpoint.
# Used for multi-hop routing: Alice → Relay B → Relay A (Bob's relay).
# Relay B calls /v1/forward on Relay A, which delivers to Bob.
#
# No authentication — anyone can ask a relay to forward. Rate-limited by IP.

@app.post("/v1/forward")
async def v1_forward(
    request: Request,
    x_forward_to: str = Header(..., alias="X-Forward-To"),
):
    if not _rate_limiter.allow(_hash_ip(_get_client_ip(request))):
        raise HTTPException(429, "rate limit exceeded")
    body = await request.body()
    if len(body) > MAX_ENVELOPE_BYTES:
        raise HTTPException(413, "envelope too large")
    if not x_forward_to:
        raise HTTPException(400, "missing X-Forward-To header")

    # Validate the target looks like a hostname (basic sanity)
    if "/" in x_forward_to or " " in x_forward_to:
        raise HTTPException(400, "invalid relay address")

    # Fix #11: SSRF hardening — the old prefix-match approach was fooled by
    # bracketed IPv6 (`[::1]:443` → split[":"][0] = "[") and never resolved
    # DNS (rebinding attacks).  Resolve and check every returned address.
    reason = _forward_host_reason(x_forward_to)
    if reason is not None:
        raise HTTPException(403, f"forwarding not allowed: {reason}")

    # Per-recipient cap on forwarded traffic too — parse the inner envelope.
    try:
        fwd_to_id = parse_recipient_from_envelope(body)
        if not _recip_limiter.allow(fwd_to_id, RECIPIENT_RATE_LIMIT_PER_MIN):
            raise HTTPException(429, "recipient rate limit exceeded")
    except HTTPException:
        raise
    except Exception:
        pass  # not a parseable envelope — let the downstream relay decide

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"https://{x_forward_to}/v1/send",
                content=body,
                headers={"Content-Type": "application/octet-stream"},
                timeout=FORWARD_TIMEOUT_S,
            )
        return {"forwarded": True, "relay": x_forward_to, "status": resp.status_code}
    except httpx.TimeoutException:
        raise HTTPException(504, f"forward to {x_forward_to} timed out")
    except httpx.ConnectError:
        raise HTTPException(502, f"cannot reach relay {x_forward_to}")


# Legacy /mbox/* and /rvz/* endpoints were removed.  The Qt client now uses
# /v1/send exclusively; peer discovery is replaced by WS presence + P2P ICE.


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/healthz")
def healthz():
    # Parity fix: `version` is the PROTOCOL version (identical across impls)
    # so clients can gate compatibility; `impl` distinguishes flavours.
    return {
        "ok": True,
        "version": "2.0.0",
        "impl": "python",
    }


# ── /v1/relay_info ───────────────────────────────────────────────────────────
# Fix #7: advertise this relay's X25519 pubkey so clients can build onion
# layers addressed to us.  Clients fetch this on connect and cache the result.

@app.get("/v1/relay_info")
def v1_relay_info():
    return {
        "x25519_pub": _relay_pub_b64u,
        "impl": "python",
    }


# ── /v1/forward-onion ────────────────────────────────────────────────────────
# Fix #7: real onion peel — decrypt ONE layer and forward the inner blob to
# the next hop.  Intermediate relays see only (ephPub, encrypted_next_hop_url)
# and never learn the final recipient pubkey.  Only the exit relay's /v1/send
# sees the recipient in the envelope header.
#
# Wire format (must match core/OnionWrap.cpp):
#   [version(1)=0x01][ephPub(32)][nonce(24)][Box ciphertext]
#   Box plaintext = [nextHopUrlLen(2 BE)][nextHopUrl][innerBlob]

@app.post("/v1/forward-onion")
async def v1_forward_onion(request: Request):
    if not _rate_limiter.allow(_hash_ip(_get_client_ip(request))):
        raise HTTPException(429, "rate limit exceeded")

    body = await request.body()
    # Minimum: version(1) + ephPub(32) + nonce(24) + Box tag(16) + at least 3
    # plaintext bytes (urlLen(2) + innerBlob(>=1)).
    if len(body) < 1 + 32 + 24 + 16 + 3:
        raise HTTPException(400, "onion envelope too small")
    if body[0] != 0x01:
        raise HTTPException(400, "unsupported onion version")

    eph_pub_raw = body[1:33]
    nonce       = body[33:57]
    ct          = body[57:]

    try:
        eph_pub = PublicKey(eph_pub_raw)
        box     = Box(_relay_priv, eph_pub)
        plain   = box.decrypt(ct, nonce)
    except (CryptoError, ValueError):
        # Fail-closed: drop silently with a generic 400 so the attacker
        # can't distinguish bad key vs bad ciphertext vs bad nonce.
        raise HTTPException(400, "onion decrypt failed")

    if len(plain) < 3:
        raise HTTPException(400, "onion plaintext too small")
    url_len = int.from_bytes(plain[:2], "big")
    if url_len == 0 or url_len > len(plain) - 2:
        raise HTTPException(400, "invalid next-hop url length")
    try:
        next_hop_url = plain[2:2 + url_len].decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(400, "invalid next-hop url encoding")
    inner_blob = plain[2 + url_len:]
    if not inner_blob:
        raise HTTPException(400, "empty inner blob")

    # SSRF guard — parse the URL and run the same reachability check as
    # /v1/forward so a peeled hop can't be redirected to internal infra.
    try:
        from urllib.parse import urlparse
        parsed = urlparse(next_hop_url)
    except Exception:
        raise HTTPException(400, "invalid next-hop url")
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise HTTPException(400, "invalid next-hop scheme")
    if parsed.path not in ("/v1/send", "/v1/forward-onion"):
        raise HTTPException(400, "invalid next-hop path")

    # Parity fix: pass `hostname` (not `netloc`) so userinfo like
    # `user:pass@host` can't sneak past the SSRF check — aligns with Go's
    # `url.URL.Host` which also excludes userinfo.
    ssrf_host = parsed.hostname
    if parsed.port:
        ssrf_host = f"{ssrf_host}:{parsed.port}"
    if not ssrf_host:
        raise HTTPException(400, "invalid next-hop host")
    ssrf_reason = _forward_host_reason(ssrf_host)
    if ssrf_reason is not None:
        raise HTTPException(403, f"forwarding not allowed: {ssrf_reason}")

    # Inner-blob size cap — an onion layer carrying a giant inner blob
    # (beyond what a normal envelope or onion layer would be) is suspicious.
    if len(inner_blob) > MAX_ENVELOPE_BYTES + 1024:
        raise HTTPException(413, "inner blob exceeds ceiling")

    # Forward as raw bytes to the next hop.
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                next_hop_url,
                content=inner_blob,
                headers={"Content-Type": "application/octet-stream"},
                timeout=FORWARD_TIMEOUT_S,
            )
        return {"forwarded": True, "status": resp.status_code}
    except httpx.TimeoutException:
        raise HTTPException(504, "next-hop timed out")
    except httpx.ConnectError:
        raise HTTPException(502, "cannot reach next hop")


# ── Startup: initialise relay keypair for onion routing ─────────────────────

@app.on_event("startup")
def _init_relay_key() -> None:
    global _relay_priv, _relay_pub_b64u
    _relay_priv = _load_or_create_relay_key()
    _relay_pub_b64u = base64.urlsafe_b64encode(
        bytes(_relay_priv.public_key)).decode().rstrip("=")
    log.info("onion routing enabled: x25519_pub=%s", _relay_pub_b64u[:12] + "…")


# ── Run ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8443))
    uvicorn.run(app, host="0.0.0.0", port=port)
