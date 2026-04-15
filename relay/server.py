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
import logging
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from typing import Optional

import httpx
from fastapi import FastAPI, Header, HTTPException, Request, Response, WebSocket, WebSocketDisconnect
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey
from pydantic import BaseModel, Field

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("relay")

app = FastAPI(title="Peer2Pear Relay")

# ── Config ────────────────────────────────────────────────────────────────────

MAX_ENVELOPE_BYTES = 256 * 1024                   # 262 144 B
MAX_QUEUE_ITEMS    = 5_000                         # per recipient
DEFAULT_TTL_MS     = 7 * 24 * 60 * 60 * 1_000     # 7 days
MAX_TTL_MS         = 7 * 24 * 60 * 60 * 1_000     # hard cap
REPLAY_WINDOW_MS   = 5 * 60 * 1_000               # 5 min auth window
CLEANUP_INTERVAL_S = 60 * 60                       # purge every hour
FORWARD_TIMEOUT_S  = 10                            # timeout for relay-to-relay forward

DB_PATH = os.environ.get("DB_PATH", "/tmp/peer2pear_relay.db")

RATE_LIMIT_PER_MIN = 60   # max envelopes per IP per minute
RATE_LIMIT_WINDOW  = 60   # seconds

# ── Per-IP rate limiter ──────────────────────────────────────────────────────

class _RateLimiter:
    def __init__(self) -> None:
        self._entries: dict[str, tuple[int, float]] = {}  # ip → (count, reset_at)

    def allow(self, ip: str) -> bool:
        now = time.time()
        entry = self._entries.get(ip)
        if entry is None or now >= entry[1]:
            self._entries[ip] = (1, now + RATE_LIMIT_WINDOW)
            return True
        count = entry[0] + 1
        self._entries[ip] = (count, entry[1])
        return count <= RATE_LIMIT_PER_MIN

    def purge(self) -> None:
        now = time.time()
        self._entries = {ip: e for ip, e in self._entries.items() if now < e[1]}

_rate_limiter = _RateLimiter()

def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

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
    if not _rate_limiter.allow(_get_client_ip(request)):
        raise HTTPException(429, "rate limit exceeded")
    body = await request.body()
    if len(body) > MAX_ENVELOPE_BYTES:
        raise HTTPException(413, f"envelope too large: {len(body)} > {MAX_ENVELOPE_BYTES}")

    to_id = parse_recipient_from_envelope(body)

    # Try direct WebSocket push
    ws = connected_peers.get(to_id)
    if ws:
        try:
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
                for r in rows:
                    await ws.send_bytes(bytes(r["payload"]))
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
                peer_ids = msg.get("peer_ids", [])
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
    if not _rate_limiter.allow(_get_client_ip(request)):
        raise HTTPException(429, "rate limit exceeded")
    body = await request.body()
    if len(body) > MAX_ENVELOPE_BYTES:
        raise HTTPException(413, "envelope too large")
    if not x_forward_to:
        raise HTTPException(400, "missing X-Forward-To header")

    # Validate the target looks like a hostname (basic sanity)
    if "/" in x_forward_to or " " in x_forward_to:
        raise HTTPException(400, "invalid relay address")

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


# ══════════════════════════════════════════════════════════════════════════════
# LEGACY ENDPOINTS — backward compatibility during client transition
# Remove these once all clients have migrated to /v1/* endpoints.
# ══════════════════════════════════════════════════════════════════════════════

def check_recipient_sig(to_id: str, ts: int, nonce: str,
                        sig: str, action: str, env_id: str = "") -> None:
    n = now_ms()
    if ts + REPLAY_WINDOW_MS < n or ts > n + REPLAY_WINDOW_MS:
        raise HTTPException(status_code=401, detail="timestamp outside window")
    verify_ed25519(to_id, sig, f"MBX1|{to_id}|{ts}|{nonce}|{action}|{env_id}")


# ── Legacy: Rendezvous ────────────────────────────────────────────────────────
# These will be removed. Presence is now handled by WS connections.

# In-memory rendezvous store (was SQLite, simplified for transition)
_rvz_store: dict[str, dict] = {}

class PublishReq(BaseModel):
    id:         str = Field(..., description="base64url Ed25519 public key")
    host:       str
    port:       int
    expires_ms: int = Field(600_000)
    sig:        str

class LookupReq(BaseModel):
    id: str

@app.post("/rvz/publish")
def rvz_publish(req: PublishReq):
    verify_ed25519(req.id, req.sig,
                   f"RVZ1|{req.id}|{req.host}|{req.port}|{req.expires_ms}")
    exp = now_ms() + min(req.expires_ms, 15 * 60 * 1_000)
    _rvz_store[req.id] = {"host": req.host, "port": req.port, "expiry_ms": exp}
    return {"ok": True, "expires_at_ms": exp}

@app.post("/rvz/lookup")
def rvz_lookup(req: LookupReq):
    entry = _rvz_store.get(req.id)
    if not entry or now_ms() > entry["expiry_ms"]:
        _rvz_store.pop(req.id, None)
        raise HTTPException(status_code=404, detail="not found")
    return {"host": entry["host"], "port": entry["port"],
            "expires_at_ms": entry["expiry_ms"]}


# ── Legacy: Mailbox enqueue ───────────────────────────────────────────────────
# Old clients send via this authenticated endpoint. New clients use /v1/send.

@app.post("/mbox/enqueue")
async def mbox_enqueue(
    request:  Request,
    x_to:     str           = Header(..., alias="X-To"),
    x_ttl_ms: Optional[int] = Header(None,  alias="X-TtlMs"),
    x_env_id: Optional[str] = Header(None,  alias="X-EnvId"),
):
    body = await request.body()
    if not body:
        raise HTTPException(status_code=400, detail="empty body")
    if len(body) > MAX_ENVELOPE_BYTES:
        raise HTTPException(status_code=413, detail="envelope too large")

    ttl    = DEFAULT_TTL_MS if x_ttl_ms is None else min(int(x_ttl_ms), MAX_TTL_MS)
    env_id = x_env_id or f"{now_ms()}-{secrets.token_hex(8)}"
    exp    = now_ms() + ttl

    # Try WebSocket push first (bridge old clients to new receive path)
    ws = connected_peers.get(x_to)
    if ws:
        try:
            await ws.send_bytes(body)
            log.info(f"legacy enqueue→ws push: to={x_to[:8]}… size={len(body)}B")
            return {"accepted": True, "env_id": env_id}
        except Exception:
            connected_peers.pop(x_to, None)

    with db_conn() as conn:
        purge_expired(conn)
        count = conn.execute(
            "SELECT COUNT(*) FROM envelopes WHERE recipient_id=?;", (x_to,)
        ).fetchone()[0]
        if count >= MAX_QUEUE_ITEMS:
            raise HTTPException(status_code=429, detail="mailbox full")
        conn.execute(
            "INSERT OR IGNORE INTO envelopes "
            "(env_id, recipient_id, payload, created_ms, expiry_ms) "
            "VALUES (?, ?, ?, ?, ?);",
            (env_id, x_to, body, now_ms(), exp),
        )

    log.info(f"legacy enqueue: to={x_to[:8]}… size={len(body)}B ttl={ttl // 1000}s")
    return {"accepted": True, "env_id": env_id}


# ── Legacy: Mailbox fetch ─────────────────────────────────────────────────────
# Old clients poll this. New clients receive via WebSocket push.

@app.get("/mbox/fetch")
def mbox_fetch(
    x_to:    str = Header(..., alias="X-To"),
    x_ts:    int = Header(..., alias="X-Ts"),
    x_nonce: str = Header(..., alias="X-Nonce"),
    x_sig:   str = Header(..., alias="X-Sig"),
):
    check_recipient_sig(x_to, int(x_ts), x_nonce, x_sig, "fetch")

    with db_conn() as conn:
        purge_expired(conn)
        row = conn.execute(
            "SELECT env_id, payload, created_ms, expiry_ms FROM envelopes "
            "WHERE recipient_id=? ORDER BY created_ms ASC LIMIT 1;",
            (x_to,),
        ).fetchone()

        if not row:
            return Response(status_code=204)

        conn.execute("DELETE FROM envelopes WHERE env_id=?;", (row["env_id"],))

    resp = Response(content=bytes(row["payload"]),
                    media_type="application/octet-stream")
    resp.headers["X-EnvId"]       = row["env_id"]
    resp.headers["X-CreatedAtMs"] = str(row["created_ms"])
    resp.headers["X-ExpiryAtMs"]  = str(row["expiry_ms"])
    return resp

@app.get("/mbox/fetch_all")
def mbox_fetch_all(
    x_to:    str = Header(..., alias="X-To"),
    x_ts:    int = Header(..., alias="X-Ts"),
    x_nonce: str = Header(..., alias="X-Nonce"),
    x_sig:   str = Header(..., alias="X-Sig"),
):
    check_recipient_sig(x_to, int(x_ts), x_nonce, x_sig, "fetch_all")

    with db_conn() as conn:
        purge_expired(conn)
        rows = conn.execute(
            "SELECT env_id, payload FROM envelopes "
            "WHERE recipient_id=? ORDER BY created_ms ASC;",
            (x_to,),
        ).fetchall()

        if not rows:
            return Response(status_code=204)

        env_ids      = [r["env_id"] for r in rows]
        placeholders = ",".join("?" * len(env_ids))
        conn.execute(
            f"DELETE FROM envelopes WHERE env_id IN ({placeholders});",
            env_ids,
        )

    log.info(f"legacy fetch_all: to={x_to[:8]}… delivered {len(rows)} envelope(s)")
    return [
        {"env_id": r["env_id"], "payload_b64": b64url_encode(bytes(r["payload"]))}
        for r in rows
    ]


class AckReq(BaseModel):
    env_id: str

@app.post("/mbox/ack")
def mbox_ack(
    req:     AckReq,
    x_to:    str = Header(..., alias="X-To"),
    x_ts:    int = Header(..., alias="X-Ts"),
    x_nonce: str = Header(..., alias="X-Nonce"),
    x_sig:   str = Header(..., alias="X-Sig"),
):
    check_recipient_sig(x_to, int(x_ts), x_nonce, x_sig, "ack", req.env_id)
    return {"ok": True}


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/healthz")
def healthz():
    return {
        "ok": True,
        "version": "2.0.0",
    }


# ── Run ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8443))
    uvicorn.run(app, host="0.0.0.0", port=port)
