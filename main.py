import asyncio
import json
import os
import hashlib
import secrets
import time
from datetime import datetime
from urllib.parse import quote
from collections import deque, defaultdict

from fastapi import FastAPI, Request, HTTPException, WebSocket, WebSocketDisconnect, Depends
from fastapi.responses import Response, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import httpx
import logging
import psutil

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("LUFFY-Gateway")

app = FastAPI(title="LUFFY PANEL", docs_url=None, redoc_url=None)

CONFIG = {
    "port": int(os.environ.get("PORT", 8000)),
    "secret": os.environ.get("SECRET_KEY", secrets.token_urlsafe(32)),
}

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

connections: dict = {}
connection_sockets: dict = {}
stats = {"total_bytes": 0, "total_requests": 0, "total_errors": 0, "start_time": time.time()}
error_logs: deque = deque(maxlen=50)
hourly_traffic: dict = defaultdict(int)
daily_traffic: dict = defaultdict(int)
http_client: httpx.AsyncClient | None = None

LINKS: dict = {}
LINKS_LOCK = asyncio.Lock()

SESSION_COOKIE = "luffy_session"
SESSION_TTL = 60 * 60 * 24 * 7
DATA_FILE = "luffy_data.json"

def hash_password(pw: str) -> str:
    return hashlib.sha256(f"{pw}{CONFIG['secret']}".encode()).hexdigest()

AUTH = {"password_hash": hash_password(os.environ.get("ADMIN_PASSWORD", "admin"))}
SESSIONS: dict = {}
SESSIONS_LOCK = asyncio.Lock()

def load_data():
    global LINKS, stats, hourly_traffic, daily_traffic
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, "r") as f:
                data = json.load(f)
                LINKS = data.get("links", {})
                saved_stats = data.get("stats", {})
                stats["total_bytes"] = saved_stats.get("total_bytes", 0)
                stats["total_requests"] = saved_stats.get("total_requests", 0)
                hourly_traffic = defaultdict(int, data.get("hourly_traffic", {}))
                daily_traffic = defaultdict(int, data.get("daily_traffic", {}))
                logger.info("LUFFY data loaded.")
        except Exception as e:
            logger.error(f"Error loading data: {e}")

async def save_data_loop():
    while True:
        await asyncio.sleep(60)
        async with LINKS_LOCK:
            data_to_save = {
                "links": LINKS,
                "stats": {"total_bytes": stats["total_bytes"], "total_requests": stats["total_requests"]},
                "hourly_traffic": dict(hourly_traffic),
                "daily_traffic": dict(daily_traffic),
            }
        try:
            await asyncio.to_thread(write_json, data_to_save)
        except Exception as e:
            logger.error(f"Error saving data: {e}")

def write_json(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

async def create_session() -> str:
    token = secrets.token_urlsafe(32)
    async with SESSIONS_LOCK:
        SESSIONS[token] = time.time() + SESSION_TTL
    return token

async def is_valid_session(token: str | None) -> bool:
    if not token:
        return False
    async with SESSIONS_LOCK:
        exp = SESSIONS.get(token)
        if exp is None or exp < time.time():
            SESSIONS.pop(token, None)
            return False
        return True

async def destroy_session(token: str | None):
    if token:
        async with SESSIONS_LOCK:
            SESSIONS.pop(token, None)

async def require_auth(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not await is_valid_session(token):
        raise HTTPException(status_code=401, detail="unauthorized")
    return token

async def keep_alive():
    while True:
        await asyncio.sleep(600)
        try:
            domain = get_domain()
            if domain and domain != "localhost":
                async with httpx.AsyncClient(timeout=10.0) as client:
                    await client.get(f"https://{domain}/health")
                logger.info("Keep-alive ping sent")
        except Exception:
            pass

@app.on_event("startup")
async def startup():
    global http_client
    load_data()
    limits = httpx.Limits(max_connections=500, max_keepalive_connections=100)
    timeout = httpx.Timeout(30.0, connect=10.0)
    http_client = httpx.AsyncClient(limits=limits, timeout=timeout, follow_redirects=True)
    logger.info(f"LUFFY PANEL started on port {CONFIG['port']}")
    asyncio.create_task(keep_alive())
    asyncio.create_task(save_data_loop())

@app.on_event("shutdown")
async def shutdown():
    if http_client:
        await http_client.aclose()
    data_to_save = {
        "links": LINKS,
        "stats": {"total_bytes": stats["total_bytes"], "total_requests": stats["total_requests"]},
        "hourly_traffic": dict(hourly_traffic),
        "daily_traffic": dict(daily_traffic),
    }
    write_json(data_to_save)

def get_domain() -> str:
    return os.environ.get("RENDER_EXTERNAL_URL", os.environ.get("RAILWAY_PUBLIC_DOMAIN", "localhost")).replace("https://", "").replace("http://", "")

def generate_uuid(seed: str | None = None) -> str:
    if seed is None:
        return str(secrets.token_hex(16))[:8] + "-" + secrets.token_hex(2) + "-" + secrets.token_hex(2) + "-" + secrets.token_hex(2) + "-" + secrets.token_hex(6)
    h = hashlib.sha256(f"{seed}{CONFIG['secret']}".encode()).hexdigest()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"

def generate_vless_link(uuid: str, remark: str = "LUFFY") -> str:
    domain = get_domain()
    path = f"/ws/{uuid}"
    params = {
        "encryption": "none",
        "security": "tls",
        "type": "ws",
        "host": domain,
        "path": path,
        "sni": domain,
        "fp": "chrome",
        "alpn": "http/1.1",
    }
    query = "&".join(f"{k}={quote(str(v))}" for k, v in params.items())
    return f"vless://{uuid}@{domain}:443?{query}#{quote(remark)}"

def uptime() -> str:
    secs = int(time.time() - stats["start_time"])
    h, m, s = secs // 3600, (secs % 3600) // 60, secs % 60
    return f"{h:02d}:{m:02d}:{s:02d}"

def parse_size_to_bytes(value: float, unit: str) -> int:
    unit = unit.upper()
    if unit == "GB": return int(value * 1024 * 1024 * 1024)
    if unit == "MB": return int(value * 1024 * 1024)
    if unit == "KB": return int(value * 1024)
    return int(value)

async def ensure_default_link():
    async with LINKS_LOCK:
        if not LINKS:
            uid = generate_uuid("default")
            LINKS[uid] = {"label": "Default", "limit_bytes": 0, "used_bytes": 0, "created_at": datetime.now().isoformat(), "active": True, "note": ""}

async def close_connections_for_link(uid: str):
    to_close = [cid for cid, info in connections.items() if info.get("uuid") == uid]
    for cid in to_close:
        ws = connection_sockets.get(cid)
        if ws:
            try:
                await ws.close(code=1000, reason="link deleted")
            except Exception:
                pass
        connections.pop(cid, None)
        connection_sockets.pop(cid, None)

@app.get("/")
async def root():
    return {"service": "LUFFY PANEL", "version": "3.0", "status": "active", "domain": get_domain()}

@app.get("/health")
async def health():
    return {"status": "ok", "connections": len(connections), "uptime": uptime()}

@app.post("/api/login")
async def api_login(request: Request):
    body = await request.json()
    password = str(body.get("password") or "")
    if hash_password(password) != AUTH["password_hash"]:
        raise HTTPException(status_code=401, detail="Invalid password")
    token = await create_session()
    resp = JSONResponse({"ok": True})
    resp.set_cookie(key=SESSION_COOKIE, value=token, max_age=SESSION_TTL, httponly=True, samesite="lax", path="/")
    return resp

@app.post("/api/logout")
async def api_logout(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    await destroy_session(token)
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp

@app.get("/api/me")
async def api_me(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    return {"authenticated": await is_valid_session(token)}

@app.post("/api/change-password")
async def api_change_password(request: Request, _=Depends(require_auth)):
    body = await request.json()
    current = str(body.get("current_password") or "")
    new = str(body.get("new_password") or "")
    if hash_password(current) != AUTH["password_hash"]:
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    if len(new) < 4:
        raise HTTPException(status_code=400, detail="Password must be at least 4 characters")
    AUTH["password_hash"] = hash_password(new)
    current_token = request.cookies.get(SESSION_COOKIE)
    async with SESSIONS_LOCK:
        SESSIONS.clear()
        if current_token:
            SESSIONS[current_token] = time.time() + SESSION_TTL
    return {"ok": True}

@app.get("/stats")
async def get_stats(_=Depends(require_auth)):
    active_links = sum(1 for l in LINKS.values() if l.get("active"))
    total_used = sum(l.get("used_bytes", 0) for l in LINKS.values())
    return {
        "active_connections": len(connections),
        "total_traffic_mb": round(stats["total_bytes"] / (1024 * 1024), 2),
        "total_requests": stats["total_requests"],
        "total_errors": stats["total_errors"],
        "uptime": uptime(),
        "timestamp": datetime.now().isoformat(),
        "recent_errors": list(error_logs)[-10:],
        "links_count": len(LINKS),
        "active_links": active_links,
        "domain": get_domain(),
        "cpu_percent": psutil.cpu_percent(interval=0.1),
        "memory_percent": psutil.virtual_memory().percent,
        "memory_used_mb": round(psutil.virtual_memory().used / (1024 * 1024), 1),
        "memory_total_mb": round(psutil.virtual_memory().total / (1024 * 1024), 1),
        "hourly_traffic": dict(hourly_traffic),
        "daily_traffic": dict(daily_traffic),
        "total_used_bytes": total_used,
        "connections": [
            {"id": cid, "uuid": info.get("uuid", ""), "bytes": info.get("bytes", 0), "connected_at": info.get("connected_at", "")}
            for cid, info in connections.items()
        ]
    }

@app.post("/api/links")
async def create_link(request: Request, _=Depends(require_auth)):
    body = await request.json()
    label = (body.get("label") or "New Link").strip()[:60]
    limit_value = float(body.get("limit_value") or 0)
    limit_unit = body.get("limit_unit") or "GB"
    limit_bytes = 0 if limit_value <= 0 else parse_size_to_bytes(limit_value, limit_unit)
    note = str(body.get("note") or "")[:200]
    uid = generate_uuid(label + secrets.token_hex(4))
    async with LINKS_LOCK:
        LINKS[uid] = {
            "label": label,
            "limit_bytes": limit_bytes,
            "used_bytes": 0,
            "created_at": datetime.now().isoformat(),
            "active": True,
            "note": note,
        }
    return {
        "uuid": uid,
        "label": label,
        "limit_bytes": limit_bytes,
        "used_bytes": 0,
        "active": True,
        "note": note,
        "created_at": LINKS[uid]["created_at"],
        "vless_link": generate_vless_link(uid, remark=f"LUFFY-{label}")
    }

@app.get("/api/links")
async def list_links(_=Depends(require_auth)):
    result = []
    async with LINKS_LOCK:
        for uid, data in LINKS.items():
            result.append({
                "uuid": uid,
                "label": data["label"],
                "limit_bytes": data["limit_bytes"],
                "used_bytes": data["used_bytes"],
                "active": data["active"],
                "note": data.get("note", ""),
                "created_at": data["created_at"],
                "vless_link": generate_vless_link(uid, remark=f"LUFFY-{data['label']}")
            })
    result.sort(key=lambda x: x["created_at"], reverse=True)
    return {"links": result}

@app.patch("/api/links/{uid}")
async def toggle_link(uid: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    async with LINKS_LOCK:
        if uid not in LINKS:
            raise HTTPException(status_code=404, detail="link not found")
        if "active" in body:
            LINKS[uid]["active"] = bool(body["active"])
        if "limit_value" in body:
            limit_value = float(body.get("limit_value") or 0)
            limit_unit = body.get("limit_unit") or "GB"
            LINKS[uid]["limit_bytes"] = 0 if limit_value <= 0 else parse_size_to_bytes(limit_value, limit_unit)
        if "reset_usage" in body and body["reset_usage"]:
            LINKS[uid]["used_bytes"] = 0
        if "label" in body:
            LINKS[uid]["label"] = str(body["label"])[:60]
        if "note" in body:
            LINKS[uid]["note"] = str(body["note"])[:200]
    return {"ok": True}

@app.delete("/api/links/{uid}")
async def delete_link(uid: str, _=Depends(require_auth)):
    async with LINKS_LOCK:
        LINKS.pop(uid, None)
    await close_connections_for_link(uid)
    return {"ok": True}

RELAY_BUF = 64 * 1024

async def parse_vless_header(first_chunk: bytes):
    if len(first_chunk) < 24:
        raise ValueError("chunk too small")
    pos = 0
    pos += 1; pos += 16
    addon_len = first_chunk[pos]; pos += 1; pos += addon_len
    command = first_chunk[pos]; pos += 1
    port = int.from_bytes(first_chunk[pos:pos + 2], "big"); pos += 2
    addr_type = first_chunk[pos]; pos += 1
    if addr_type == 1:
        addr_bytes = first_chunk[pos:pos + 4]; pos += 4
        address = ".".join(str(b) for b in addr_bytes)
    elif addr_type == 2:
        domain_len = first_chunk[pos]; pos += 1
        address = first_chunk[pos:pos + domain_len].decode("utf-8", errors="ignore"); pos += domain_len
    elif addr_type == 3:
        addr_bytes = first_chunk[pos:pos + 16]; pos += 16
        address = ":".join(f"{addr_bytes[i]:02x}{addr_bytes[i+1]:02x}" for i in range(0, 16, 2))
    else:
        raise ValueError(f"unknown address type: {addr_type}")
    return command, address, port, first_chunk[pos:]

async def check_quota(uid: str, extra_bytes: int) -> bool:
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if link is None: return False
        if not link["active"]: return False
        if link["limit_bytes"] == 0: return True
        return (link["used_bytes"] + extra_bytes) <= link["limit_bytes"]

async def add_usage(uid: str, n: int):
    async with LINKS_LOCK:
        if uid in LINKS:
            LINKS[uid]["used_bytes"] += n

async def ws_to_tcp(websocket: WebSocket, writer: asyncio.StreamWriter, conn_id: str, link_uid: str):
    try:
        while True:
            msg = await websocket.receive()
            if msg["type"] == "websocket.disconnect": break
            data = msg.get("bytes") or (msg.get("text") or "").encode()
            if not data: continue
            size = len(data)
            if not await check_quota(link_uid, size):
                await websocket.close(code=1008, reason="quota exceeded"); break
            stats["total_bytes"] += size; stats["total_requests"] += 1
            connections[conn_id]["bytes"] += size
            hour_key = datetime.now().strftime("%H:00")
            day_key = datetime.now().strftime("%Y-%m-%d")
            hourly_traffic[hour_key] += size
            daily_traffic[day_key] += size
            await add_usage(link_uid, size)
            writer.write(data); await writer.drain()
    except WebSocketDisconnect: pass
    finally:
        try: writer.write_eof()
        except: pass

async def tcp_to_ws(websocket: WebSocket, reader: asyncio.StreamReader, conn_id: str, link_uid: str):
    first = True
    try:
        while True:
            data = await reader.read(RELAY_BUF)
            if not data: break
            size = len(data)
            if not await check_quota(link_uid, size):
                await websocket.close(code=1008, reason="quota exceeded"); break
            stats["total_bytes"] += size
            connections[conn_id]["bytes"] += size
            hour_key = datetime.now().strftime("%H:00")
            day_key = datetime.now().strftime("%Y-%m-%d")
            hourly_traffic[hour_key] += size
            daily_traffic[day_key] += size
            await add_usage(link_uid, size)
            await websocket.send_bytes((b"\x00\x00" + data) if first else data)
            first = False
    except: pass

@app.websocket("/ws/{uuid}")
async def websocket_tunnel(websocket: WebSocket, uuid: str):
    await ensure_default_link()
    await websocket.accept()
    conn_id = secrets.token_urlsafe(8)
    connections[conn_id] = {"uuid": uuid, "connected_at": datetime.now().isoformat(), "bytes": 0}
    connection_sockets[conn_id] = websocket
    writer = None
    try:
        if not await check_quota(uuid, 0):
            await websocket.close(code=1008, reason="quota exceeded or link deleted"); return
        first_msg = await asyncio.wait_for(websocket.receive(), timeout=15.0)
        if first_msg["type"] == "websocket.disconnect": return
        first_chunk = first_msg.get("bytes") or (first_msg.get("text") or "").encode()
        if not first_chunk: return
        command, address, port, initial_payload = await parse_vless_header(first_chunk)
        size = len(first_chunk)
        stats["total_bytes"] += size; stats["total_requests"] += 1
        connections[conn_id]["bytes"] += size
        hour_key = datetime.now().strftime("%H:00")
        day_key = datetime.now().strftime("%Y-%m-%d")
        hourly_traffic[hour_key] += size
        daily_traffic[day_key] += size
        await add_usage(uuid, size)
        reader, writer = await asyncio.wait_for(asyncio.open_connection(address, port), timeout=10.0)
        if initial_payload:
            p_size = len(initial_payload)
            stats["total_bytes"] += p_size
            connections[conn_id]["bytes"] += p_size
            hourly_traffic[hour_key] += p_size
            daily_traffic[day_key] += p_size
            await add_usage(uuid, p_size)
            writer.write(initial_payload); await writer.drain()
        task_up = asyncio.create_task(ws_to_tcp(websocket, writer, conn_id, uuid))
        task_down = asyncio.create_task(tcp_to_ws(websocket, reader, conn_id, uuid))
        done, pending = await asyncio.wait({task_up, task_down}, return_when=asyncio.FIRST_COMPLETED)
        for t in pending: t.cancel()
    except WebSocketDisconnect: pass
    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"error": str(exc), "time": datetime.now().isoformat()})
    finally:
        if writer:
            try: writer.close()
            except: pass
        connections.pop(conn_id, None)
        connection_sockets.pop(conn_id, None)


LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>LUFFY — Sign In</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=Vazirmatn:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
<style>
*, *::before, *::after { margin: 0; padding: 0; box-sizing: border-box; }

:root {
  --c1: #6c63ff;
  --c2: #ff6584;
  --c3: #43e97b;
  --c4: #38f9d7;
  --glass: rgba(255,255,255,0.06);
  --glass-border: rgba(255,255,255,0.12);
  --glass-strong: rgba(255,255,255,0.10);
  --text: rgba(255,255,255,0.95);
  --text2: rgba(255,255,255,0.55);
  --text3: rgba(255,255,255,0.28);
  --error: #ff6b6b;
}

html, body {
  height: 100%;
  font-family: 'Inter', 'Vazirmatn', sans-serif;
  background: #080810;
  color: var(--text);
  overflow: hidden;
}

/* ── Animated Background ── */
.bg {
  position: fixed; inset: 0; z-index: 0;
  background: radial-gradient(ellipse at 20% 20%, rgba(108,99,255,0.25) 0%, transparent 50%),
              radial-gradient(ellipse at 80% 80%, rgba(255,101,132,0.2) 0%, transparent 50%),
              radial-gradient(ellipse at 50% 50%, rgba(67,233,123,0.08) 0%, transparent 60%),
              #080810;
}
.bg::before {
  content: '';
  position: absolute; inset: 0;
  background-image:
    radial-gradient(circle at 1px 1px, rgba(255,255,255,0.04) 1px, transparent 0);
  background-size: 40px 40px;
}

.orb {
  position: absolute;
  border-radius: 50%;
  filter: blur(60px);
  animation: float 8s ease-in-out infinite;
}
.orb1 { width:400px;height:400px;top:-100px;left:-100px;background:rgba(108,99,255,0.3);animation-delay:0s; }
.orb2 { width:300px;height:300px;bottom:-80px;right:-80px;background:rgba(255,101,132,0.25);animation-delay:-3s; }
.orb3 { width:250px;height:250px;top:50%;left:60%;background:rgba(67,233,123,0.15);animation-delay:-5s; }

@keyframes float {
  0%,100% { transform: translate(0,0) scale(1); }
  33% { transform: translate(30px,-20px) scale(1.05); }
  66% { transform: translate(-20px,30px) scale(0.95); }
}

/* ── Layout ── */
.wrap {
  position: relative; z-index: 1;
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 20px;
}

/* ── Card ── */
.card {
  width: 100%; max-width: 420px;
  background: rgba(255,255,255,0.055);
  backdrop-filter: blur(24px) saturate(180%);
  -webkit-backdrop-filter: blur(24px) saturate(180%);
  border: 1px solid rgba(255,255,255,0.12);
  border-radius: 28px;
  padding: 48px 40px 40px;
  box-shadow:
    0 0 0 1px rgba(255,255,255,0.04),
    0 32px 64px rgba(0,0,0,0.4),
    inset 0 1px 0 rgba(255,255,255,0.1);
  animation: cardIn .6s cubic-bezier(0.34,1.56,0.64,1) forwards;
}
@keyframes cardIn {
  from { opacity:0; transform:translateY(40px) scale(0.95); }
  to   { opacity:1; transform:translateY(0) scale(1); }
}

/* ── Logo ── */
.logo-wrap {
  text-align: center; margin-bottom: 36px;
}
.logo-ring {
  display: inline-flex;
  align-items: center; justify-content: center;
  width: 80px; height: 80px;
  border-radius: 24px;
  background: linear-gradient(135deg, #6c63ff, #ff6584);
  box-shadow: 0 8px 32px rgba(108,99,255,0.5), 0 0 0 1px rgba(255,255,255,0.1);
  margin-bottom: 20px;
  position: relative;
  animation: logoPulse 3s ease-in-out infinite;
}
@keyframes logoPulse {
  0%,100% { box-shadow: 0 8px 32px rgba(108,99,255,0.5), 0 0 0 1px rgba(255,255,255,0.1); }
  50% { box-shadow: 0 8px 48px rgba(108,99,255,0.7), 0 0 0 1px rgba(255,255,255,0.15), 0 0 80px rgba(108,99,255,0.2); }
}
.logo-ring svg { width:40px;height:40px; }
.logo-title {
  font-size: 28px; font-weight: 900;
  background: linear-gradient(135deg, #fff 0%, rgba(255,255,255,0.7) 100%);
  -webkit-background-clip: text; -webkit-text-fill-color: transparent;
  letter-spacing: -0.03em;
}
.logo-sub {
  font-size: 12px; color: var(--text3);
  font-weight: 600; letter-spacing: 0.15em;
  text-transform: uppercase; margin-top: 6px;
}

/* ── Form ── */
.field { margin-bottom: 18px; }
.field label {
  display: block;
  font-size: 11px; font-weight: 700;
  color: var(--text2);
  text-transform: uppercase; letter-spacing: 0.08em;
  margin-bottom: 8px;
}
.input-wrap { position: relative; }
.input-wrap svg {
  position: absolute; left: 14px; top: 50%;
  transform: translateY(-50%);
  color: var(--text3); pointer-events: none;
  transition: color .2s;
}
.field input {
  width: 100%;
  padding: 13px 14px 13px 42px;
  background: rgba(255,255,255,0.06);
  border: 1px solid rgba(255,255,255,0.1);
  border-radius: 14px;
  color: var(--text);
  font-size: 14px; font-family: inherit;
  outline: none;
  transition: all .25s;
}
.field input:focus {
  background: rgba(255,255,255,0.09);
  border-color: var(--c1);
  box-shadow: 0 0 0 3px rgba(108,99,255,0.2), 0 0 20px rgba(108,99,255,0.1);
}
.field input:focus + svg,
.field .input-wrap:focus-within svg { color: var(--c1); }
.field input::placeholder { color: var(--text3); }

/* eye toggle */
.eye-btn {
  position: absolute; right: 12px; top: 50%;
  transform: translateY(-50%);
  background: none; border: none; cursor: pointer;
  color: var(--text3); padding: 4px;
  display: flex; align-items: center; justify-content: center;
  transition: color .2s; z-index: 1;
}
.eye-btn:hover { color: var(--text2); }

/* ── Submit Button ── */
.btn-submit {
  width: 100%;
  padding: 14px;
  background: linear-gradient(135deg, #6c63ff, #ff6584);
  border: none; border-radius: 14px;
  color: #fff;
  font-size: 15px; font-weight: 700; font-family: inherit;
  cursor: pointer; letter-spacing: 0.02em;
  position: relative; overflow: hidden;
  transition: all .25s;
  box-shadow: 0 4px 24px rgba(108,99,255,0.4);
  margin-top: 8px;
}
.btn-submit::before {
  content: '';
  position: absolute; inset: 0;
  background: linear-gradient(135deg, rgba(255,255,255,0.15), transparent);
  opacity: 0; transition: opacity .25s;
}
.btn-submit:hover { transform: translateY(-2px); box-shadow: 0 8px 36px rgba(108,99,255,0.55); }
.btn-submit:hover::before { opacity: 1; }
.btn-submit:active { transform: translateY(0); }
.btn-submit.loading {
  pointer-events: none; opacity: 0.7;
}
.btn-submit .spinner {
  display: none;
  width: 18px; height: 18px;
  border: 2px solid rgba(255,255,255,0.3);
  border-top-color: #fff;
  border-radius: 50%;
  animation: spin .7s linear infinite;
  margin: 0 auto;
}
.btn-submit.loading .spinner { display: block; }
.btn-submit.loading .btn-text { display: none; }
@keyframes spin { to { transform: rotate(360deg); } }

/* ── Error ── */
.err {
  background: rgba(255,107,107,0.12);
  border: 1px solid rgba(255,107,107,0.3);
  border-radius: 10px;
  padding: 10px 14px;
  font-size: 13px; color: var(--error);
  text-align: center; font-weight: 500;
  margin-bottom: 16px;
  display: none;
  animation: shake .4s cubic-bezier(.36,.07,.19,.97);
}
.err.show { display: block; }
@keyframes shake {
  0%,100% { transform: translateX(0); }
  20%,60% { transform: translateX(-6px); }
  40%,80% { transform: translateX(6px); }
}

/* ── Lang/Theme toolbar ── */
.toolbar {
  position: fixed; top: 16px; right: 16px;
  display: flex; gap: 6px; z-index: 10;
}
.tb-btn {
  height: 34px; padding: 0 12px;
  background: rgba(255,255,255,0.06);
  backdrop-filter: blur(12px);
  border: 1px solid rgba(255,255,255,0.1);
  border-radius: 10px;
  color: var(--text2);
  font-size: 11px; font-weight: 700; font-family: inherit;
  letter-spacing: 0.05em;
  cursor: pointer; transition: all .2s;
}
.tb-btn:hover { border-color: var(--c1); color: var(--c1); }

/* ── Divider ── */
.divider {
  display: flex; align-items: center; gap: 12px;
  margin: 24px 0 0;
}
.divider::before,.divider::after {
  content:''; flex:1;
  height:1px; background:rgba(255,255,255,0.08);
}
.divider span { font-size:11px; color:var(--text3); font-weight:500; }

.footer-note {
  text-align: center; font-size: 11px; color: var(--text3);
  margin-top: 12px;
}
</style>
</head>
<body>

<div class="bg">
  <div class="orb orb1"></div>
  <div class="orb orb2"></div>
  <div class="orb orb3"></div>
</div>

<div class="toolbar">
  <button class="tb-btn" onclick="cycleLang()" id="lang-btn">EN</button>
  <button class="tb-btn" id="theme-btn" style="display:none">☀</button>
</div>

<div class="wrap">
  <div class="card">
    <div class="logo-wrap">
      <div class="logo-ring">
        <svg viewBox="0 0 56 56" fill="none">
          <path d="M16 13h8v22h16v8H16V13z" fill="white" opacity="0.95"/>
        </svg>
      </div>
      <div class="logo-title">LUFFY</div>
      <div class="logo-sub">Panel v3.0</div>
    </div>

    <div class="err" id="err-box"></div>

    <form id="form" autocomplete="off">
      <div class="field">
        <label data-en="Password" data-fa="رمز عبور">Password</label>
        <div class="input-wrap">
          <input type="password" id="pw" placeholder="Enter your password" autocomplete="current-password">
          <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="position:absolute;left:14px;top:50%;transform:translateY(-50%);pointer-events:none"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
          <button type="button" class="eye-btn" id="eye-btn" onclick="toggleEye()">
            <svg id="eye-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
          </button>
        </div>
      </div>

      <button type="submit" class="btn-submit" id="submit-btn">
        <span class="btn-text" data-en="Sign In" data-fa="ورود">Sign In</span>
        <div class="spinner"></div>
      </button>
    </form>

    <div class="divider"><span>VLESS WebSocket Gateway</span></div>
    <div class="footer-note">Secure · Encrypted · Private</div>
  </div>
</div>

<script>
let lang = localStorage.getItem('ll') || 'en';

function setLang(l) {
  lang = l;
  localStorage.setItem('ll', l);
  document.body.dir = l === 'fa' ? 'rtl' : 'ltr';
  document.querySelectorAll('[data-en]').forEach(el => {
    const v = el.getAttribute('data-' + l);
    if (v) el.textContent = v;
  });
  document.getElementById('lang-btn').textContent = l.toUpperCase();
}

function cycleLang() { setLang(lang === 'en' ? 'fa' : 'en'); }

function toggleEye() {
  const inp = document.getElementById('pw');
  const icon = document.getElementById('eye-icon');
  if (inp.type === 'password') {
    inp.type = 'text';
    icon.innerHTML = '<path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19m-6.72-1.07a3 3 0 11-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/>';
  } else {
    inp.type = 'password';
    icon.innerHTML = '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>';
  }
}

document.getElementById('form').addEventListener('submit', async e => {
  e.preventDefault();
  const err = document.getElementById('err-box');
  const btn = document.getElementById('submit-btn');
  err.classList.remove('show');
  btn.classList.add('loading');
  try {
    const r = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: document.getElementById('pw').value })
    });
    if (!r.ok) {
      const d = await r.json().catch(() => ({}));
      throw new Error(d.detail || 'Invalid password');
    }
    location.href = '/dashboard';
  } catch(e) {
    err.textContent = e.message;
    err.classList.add('show');
    btn.classList.remove('loading');
  }
});

setLang(lang);
</script>
</body>
</html>
"""

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>LUFFY — Dashboard</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=Vazirmatn:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.js"></script>
<style>
*,*::before,*::after{margin:0;padding:0;box-sizing:border-box}

:root {
  --c1: #6c63ff;
  --c2: #ff6584;
  --c3: #43e97b;
  --c4: #38f9d7;
  --cw: #fbbf24;
  --bg: #080810;
  --glass: rgba(255,255,255,0.055);
  --glass2: rgba(255,255,255,0.08);
  --glass3: rgba(255,255,255,0.11);
  --gb: rgba(255,255,255,0.10);
  --border: rgba(255,255,255,0.09);
  --border2: rgba(255,255,255,0.14);
  --text: rgba(255,255,255,0.95);
  --text2: rgba(255,255,255,0.55);
  --text3: rgba(255,255,255,0.28);
  --red: #ff6b6b;
  --green: #43e97b;
  --yellow: #fbbf24;
  --sidebar-w: 230px;
}

html,body{height:100%;font-family:'Inter','Vazirmatn',sans-serif;background:var(--bg);color:var(--text);overflow-x:hidden}
body[dir="rtl"]{direction:rtl;text-align:right}
::-webkit-scrollbar{width:4px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:rgba(255,255,255,0.1);border-radius:2px}

/* ── BG ── */
.bg-fixed{position:fixed;inset:0;z-index:0;pointer-events:none;overflow:hidden}
.bg-fixed::before{content:'';position:absolute;inset:0;background:radial-gradient(ellipse at 15% 15%,rgba(108,99,255,0.18) 0%,transparent 55%),radial-gradient(ellipse at 85% 85%,rgba(255,101,132,0.14) 0%,transparent 55%),#080810}
.bg-fixed::after{content:'';position:absolute;inset:0;background-image:radial-gradient(circle at 1px 1px,rgba(255,255,255,0.025) 1px,transparent 0);background-size:48px 48px}
.orb{position:absolute;border-radius:50%;filter:blur(80px);animation:floatOrb 10s ease-in-out infinite}
.orb1{width:600px;height:600px;top:-200px;left:-100px;background:rgba(108,99,255,0.18);animation-delay:0s}
.orb2{width:400px;height:400px;bottom:-150px;right:-100px;background:rgba(255,101,132,0.15);animation-delay:-4s}
@keyframes floatOrb{0%,100%{transform:translate(0,0)}50%{transform:translate(20px,-30px)}}

/* ── Sidebar ── */
.sidebar{
  position:fixed;left:0;top:0;bottom:0;width:var(--sidebar-w);
  background:rgba(10,10,20,0.7);
  backdrop-filter:blur(20px) saturate(180%);
  -webkit-backdrop-filter:blur(20px) saturate(180%);
  border-right:1px solid var(--border);
  display:flex;flex-direction:column;z-index:100;
  transition:transform .3s cubic-bezier(0.4,0,0.2,1);
}
.sb-brand{
  padding:20px 16px 16px;
  border-bottom:1px solid var(--border);
  display:flex;align-items:center;justify-content:space-between;
}
.sb-logo{
  display:flex;align-items:center;gap:10px;
}
.sb-logo-icon{
  width:36px;height:36px;border-radius:10px;
  background:linear-gradient(135deg,#6c63ff,#ff6584);
  display:flex;align-items:center;justify-content:center;
  box-shadow:0 4px 16px rgba(108,99,255,0.4);
  flex-shrink:0;
}
.sb-logo-icon svg{width:20px;height:20px}
.sb-title{font-size:17px;font-weight:900;letter-spacing:-0.02em}
.sb-ver{font-size:9px;font-weight:700;color:var(--text3);letter-spacing:0.1em;text-transform:uppercase;margin-top:1px}
.sb-actions{display:flex;gap:4px}
.sb-icon-btn{
  width:28px;height:28px;border-radius:8px;
  background:var(--glass);border:1px solid var(--border);
  color:var(--text3);cursor:pointer;
  display:flex;align-items:center;justify-content:center;
  transition:all .2s;
}
.sb-icon-btn:hover{background:var(--glass3);border-color:var(--c1);color:var(--c1)}

.sb-nav{flex:1;padding:10px 8px;overflow-y:auto}
.nav-section{
  font-size:9px;font-weight:700;color:var(--text3);
  text-transform:uppercase;letter-spacing:0.12em;
  padding:14px 10px 5px;
}
.nav-item{
  display:flex;align-items:center;gap:9px;
  padding:9px 10px;margin:1px 0;
  border-radius:10px;
  color:var(--text2);font-size:13px;font-weight:500;
  cursor:pointer;transition:all .2s;
  border:none;background:none;width:100%;text-align:left;
  position:relative;overflow:hidden;
}
body[dir="rtl"] .nav-item{text-align:right}
.nav-item::before{
  content:'';position:absolute;inset:0;
  background:linear-gradient(90deg,rgba(108,99,255,0.15),transparent);
  opacity:0;transition:opacity .2s;
  border-radius:10px;
}
.nav-item:hover{background:var(--glass2);color:var(--text)}
.nav-item.active{background:rgba(108,99,255,0.15);color:#fff;font-weight:600}
.nav-item.active::before{opacity:1}
.nav-item.active .nav-dot{background:var(--c1);box-shadow:0 0 8px rgba(108,99,255,0.7)}
.nav-dot{
  width:6px;height:6px;border-radius:50%;
  background:var(--text3);margin-left:auto;
  transition:all .2s;flex-shrink:0;
}
body[dir="rtl"] .nav-dot{margin-left:0;margin-right:auto}
.nav-badge{
  margin-left:auto;background:rgba(108,99,255,0.25);
  color:var(--c1);font-size:10px;padding:2px 7px;
  border-radius:6px;font-weight:700;
}
body[dir="rtl"] .nav-badge{margin-left:0;margin-right:auto}
.nav-icon{width:16px;height:16px;flex-shrink:0;opacity:0.7}
.nav-item.active .nav-icon{opacity:1}

.sb-footer{padding:10px 8px 14px;border-top:1px solid var(--border)}
.lang-row{display:flex;gap:4px;margin-bottom:8px}
.lang-btn{
  flex:1;padding:6px;border-radius:8px;
  background:var(--glass);border:1px solid var(--border);
  color:var(--text3);font-size:10px;font-weight:700;
  font-family:inherit;cursor:pointer;transition:all .2s;letter-spacing:0.05em;
}
.lang-btn.active{background:linear-gradient(135deg,#6c63ff,#ff6584);border-color:transparent;color:#fff}
.lang-btn:hover:not(.active){border-color:var(--c1);color:var(--c1)}
.logout-btn{
  width:100%;padding:8px;border-radius:9px;
  background:var(--glass);border:1px solid var(--border);
  color:var(--text3);font-family:inherit;font-size:12px;font-weight:600;
  cursor:pointer;transition:all .2s;
  display:flex;align-items:center;justify-content:center;gap:6px;
}
.logout-btn:hover{background:rgba(255,107,107,0.1);border-color:rgba(255,107,107,0.3);color:var(--red)}

/* online indicator */
.online-dot{
  width:7px;height:7px;border-radius:50%;
  background:var(--green);
  box-shadow:0 0 6px rgba(67,233,123,0.8);
  display:inline-block;
  animation:pulse-dot 2s ease-in-out infinite;
}
@keyframes pulse-dot{0%,100%{opacity:1}50%{opacity:0.4}}

/* ── Main ── */
.main{margin-left:var(--sidebar-w);padding:24px 26px 60px;min-height:100vh;position:relative;z-index:1}

/* ── Page ── */
.page{display:none}.page.active{display:block}
.ph{display:flex;align-items:center;justify-content:space-between;margin-bottom:22px;flex-wrap:wrap;gap:12px}
.ph-left .pt{font-size:20px;font-weight:800;letter-spacing:-0.02em}
.ph-left .ps{font-size:12px;color:var(--text3);margin-top:3px;font-weight:500}
.ph-right{display:flex;gap:8px;align-items:center}

/* ── Glass Card ── */
.gc{
  background:var(--glass);
  backdrop-filter:blur(12px);
  -webkit-backdrop-filter:blur(12px);
  border:1px solid var(--border);
  border-radius:18px;
  padding:20px;
  transition:all .25s;
  position:relative;overflow:hidden;
}
.gc::before{
  content:'';position:absolute;top:0;left:0;right:0;height:1px;
  background:linear-gradient(90deg,transparent,rgba(255,255,255,0.12),transparent);
}
.gc:hover{border-color:rgba(255,255,255,0.14);box-shadow:0 8px 32px rgba(0,0,0,0.3)}

/* ── Stat Cards ── */
.stats-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:14px}
.sc{
  background:var(--glass);
  backdrop-filter:blur(12px);
  border:1px solid var(--border);
  border-radius:16px;
  padding:18px 18px 16px;
  position:relative;overflow:hidden;
  transition:all .25s;
  cursor:default;
}
.sc::after{
  content:'';position:absolute;inset:0;
  background:linear-gradient(135deg,rgba(255,255,255,0.03),transparent);
  pointer-events:none;
}
.sc:hover{transform:translateY(-2px);box-shadow:0 12px 36px rgba(0,0,0,0.35)}
.sc-icon{
  width:36px;height:36px;border-radius:10px;
  display:flex;align-items:center;justify-content:center;
  margin-bottom:14px;
}
.sc-label{font-size:10px;font-weight:700;color:var(--text3);text-transform:uppercase;letter-spacing:0.08em;margin-bottom:6px}
.sc-val{font-size:26px;font-weight:800;letter-spacing:-0.03em;line-height:1}
.sc-unit{font-size:13px;font-weight:400;color:var(--text3)}
.sc-sub{font-size:11px;color:var(--text3);margin-top:5px;font-weight:500}

/* ── Chart wrapper ── */
.chart-wrap{height:190px;position:relative}

/* ── Tabs ── */
.tabs{display:flex;gap:4px;background:var(--glass);padding:4px;border-radius:12px;border:1px solid var(--border);margin-bottom:16px;width:fit-content}
.tab-btn{
  padding:6px 16px;border-radius:9px;font-family:inherit;
  font-size:12px;font-weight:600;
  border:none;background:none;color:var(--text3);cursor:pointer;transition:all .2s;
}
.tab-btn.active{background:linear-gradient(135deg,#6c63ff,#ff6584);color:#fff;box-shadow:0 2px 12px rgba(108,99,255,0.4)}
.tab-btn:hover:not(.active){background:var(--glass2);color:var(--text2)}

/* ── Inbound Table ── */
.tb-wrap{overflow-x:auto}
.tb{width:100%;border-collapse:collapse}
.tb th{
  text-align:left;font-size:10px;font-weight:700;color:var(--text3);
  padding:10px 14px;text-transform:uppercase;letter-spacing:0.08em;
  border-bottom:1px solid var(--border);
  background:rgba(255,255,255,0.02);
}
body[dir="rtl"] .tb th{text-align:right}
.tb td{padding:12px 14px;border-bottom:1px solid rgba(255,255,255,0.04);font-size:13px;vertical-align:middle}
.tb tr:last-child td{border-bottom:none}
.tb tbody tr{transition:background .15s}
.tb tbody tr:hover td{background:rgba(108,99,255,0.05)}

/* ── Tags ── */
.tag{display:inline-flex;align-items:center;padding:3px 9px;border-radius:6px;font-size:10px;font-weight:700;letter-spacing:0.04em;text-transform:uppercase}
.tag-vless{background:rgba(108,99,255,0.15);color:#a5a0ff;border:1px solid rgba(108,99,255,0.2)}
.tag-on{background:rgba(67,233,123,0.12);color:#5effa0;border:1px solid rgba(67,233,123,0.2)}
.tag-off{background:rgba(255,107,107,0.1);color:#ff8585;border:1px solid rgba(255,107,107,0.15)}

/* ── Usage Bar ── */
.ub{display:flex;align-items:center;gap:8px;min-width:160px}
.ub-text{font-size:11px;font-weight:600;color:var(--text);white-space:nowrap}
.ub-lim{font-size:11px;color:var(--text3);white-space:nowrap}
.ub-bar{flex:1;height:5px;background:rgba(255,255,255,0.08);border-radius:3px;min-width:40px;overflow:hidden}
.ub-fill{height:100%;border-radius:3px;transition:width .4s cubic-bezier(0.4,0,0.2,1)}

/* ── Toggle ── */
.tog{
  width:36px;height:20px;border-radius:10px;
  background:rgba(255,255,255,0.1);border:1px solid var(--border);
  position:relative;cursor:pointer;transition:all .25s;flex-shrink:0;
}
.tog::after{
  content:'';position:absolute;width:14px;height:14px;
  border-radius:50%;background:rgba(255,255,255,0.4);
  top:2px;left:2px;transition:all .25s;
}
.tog.on{background:rgba(67,233,123,0.25);border-color:rgba(67,233,123,0.4)}
.tog.on::after{left:18px;background:var(--green);box-shadow:0 0 8px rgba(67,233,123,0.6)}

/* ── Buttons ── */
.btn{
  font-family:inherit;font-size:12px;font-weight:600;
  border-radius:9px;padding:7px 14px;cursor:pointer;
  display:inline-flex;align-items:center;gap:5px;
  border:none;transition:all .2s;
}
.btn-primary{background:linear-gradient(135deg,#6c63ff,#ff6584);color:#fff;box-shadow:0 2px 12px rgba(108,99,255,0.3)}
.btn-primary:hover{filter:brightness(1.1);transform:translateY(-1px);box-shadow:0 4px 20px rgba(108,99,255,0.5)}
.btn-ghost{background:var(--glass);border:1px solid var(--border);color:var(--text2)}
.btn-ghost:hover{border-color:var(--c1);color:var(--c1);background:rgba(108,99,255,0.08)}
.btn-danger{background:rgba(255,107,107,0.1);border:1px solid rgba(255,107,107,0.2);color:var(--red)}
.btn-danger:hover{background:rgba(255,107,107,0.2)}
.btn-copy{background:rgba(108,99,255,0.1);border:1px solid rgba(108,99,255,0.2);color:#a5a0ff}
.btn-copy:hover{background:rgba(108,99,255,0.2);transform:translateY(-1px)}
.btn-qr{background:rgba(67,233,123,0.1);border:1px solid rgba(67,233,123,0.2);color:#5effa0}
.btn-qr:hover{background:rgba(67,233,123,0.2);transform:translateY(-1px)}
.btn-sm{padding:5px 10px;font-size:11px;border-radius:7px}
.btn-xs{padding:4px 8px;font-size:10px;border-radius:6px}

/* ── Action group in table ── */
.act-group{display:flex;gap:4px;align-items:center;flex-wrap:nowrap}

/* ── Toast ── */
#toast{
  position:fixed;bottom:24px;left:50%;
  transform:translateX(-50%) translateY(20px);
  background:rgba(20,20,35,0.95);
  backdrop-filter:blur(16px);
  border:1px solid var(--border);
  border-radius:12px;padding:10px 20px;
  font-size:13px;font-weight:500;
  opacity:0;transition:all .3s cubic-bezier(0.34,1.56,0.64,1);
  z-index:9999;display:flex;align-items:center;gap:8px;
  box-shadow:0 8px 32px rgba(0,0,0,0.4);
  pointer-events:none;
}
#toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
#toast.ok{border-color:rgba(67,233,123,0.3);color:var(--green)}
#toast.err{border-color:rgba(255,107,107,0.3);color:var(--red)}

/* ── Modal ── */
.moverlay{
  position:fixed;inset:0;
  background:rgba(0,0,0,0.7);
  backdrop-filter:blur(8px);
  z-index:200;display:none;
  align-items:center;justify-content:center;padding:20px;
}
.moverlay.open{display:flex}
.modal{
  background:rgba(14,14,28,0.95);
  backdrop-filter:blur(24px);
  border:1px solid var(--border2);
  border-radius:24px;
  padding:28px;width:100%;max-width:480px;
  position:relative;
  box-shadow:0 24px 60px rgba(0,0,0,0.5),0 0 0 1px rgba(255,255,255,0.04);
  animation:modalIn .35s cubic-bezier(0.34,1.56,0.64,1) forwards;
}
@keyframes modalIn{from{opacity:0;transform:scale(0.88) translateY(20px)}to{opacity:1;transform:scale(1) translateY(0)}}
.modal-close{
  position:absolute;top:14px;right:14px;
  width:28px;height:28px;border-radius:8px;
  background:var(--glass);border:1px solid var(--border);
  color:var(--text3);cursor:pointer;
  display:flex;align-items:center;justify-content:center;
  font-size:14px;transition:all .2s;
}
body[dir="rtl"] .modal-close{right:auto;left:14px}
.modal-close:hover{background:rgba(255,107,107,0.1);border-color:rgba(255,107,107,0.3);color:var(--red)}
.modal-title{font-size:17px;font-weight:800;margin-bottom:22px;letter-spacing:-0.02em}

/* ── Form elements ── */
.fg{display:flex;flex-direction:column;gap:6px;margin-bottom:14px}
.fl{font-size:10px;font-weight:700;color:var(--text2);text-transform:uppercase;letter-spacing:0.08em}
.fi,.fs{
  padding:10px 13px;border-radius:10px;
  background:rgba(255,255,255,0.05);border:1px solid var(--border);
  font-family:inherit;font-size:13px;outline:none;
  color:var(--text);transition:all .2s;
}
.fi:focus,.fs:focus{border-color:var(--c1);background:rgba(108,99,255,0.06);box-shadow:0 0 0 3px rgba(108,99,255,0.12)}
.fi::placeholder{color:var(--text3)}
.fs{cursor:pointer}
.fs option{background:#141428;color:var(--text)}
.form-row{display:flex;gap:10px;align-items:flex-end}
.form-row .fg{flex:1;margin-bottom:0}

/* ── Detail card ── */
.dc{padding:10px 13px;background:rgba(255,255,255,0.04);border:1px solid var(--border);border-radius:10px}
.dc-lbl{font-size:9px;font-weight:700;color:var(--text3);text-transform:uppercase;letter-spacing:0.08em;margin-bottom:4px}
.dc-val{font-size:12px;color:var(--text2);word-break:break-all;font-family:'JetBrains Mono',monospace;line-height:1.6}

/* ── QR ── */
.qr-box{
  text-align:center;padding:24px;
  background:rgba(255,255,255,0.03);
  border:1px solid var(--border);border-radius:16px;margin-top:16px;
  transition:all .3s;
}
.qr-box:hover{border-color:rgba(108,99,255,0.3);box-shadow:0 0 30px rgba(108,99,255,0.1)}
.qr-box img{max-width:200px;border-radius:10px;background:#fff;padding:8px}

/* ── System bars ── */
.sys-bar{height:6px;background:rgba(255,255,255,0.08);border-radius:3px;overflow:hidden;margin-top:10px}
.sys-fill{height:100%;border-radius:3px;transition:width .5s cubic-bezier(0.4,0,0.2,1)}

/* ── Status list ── */
.sl-item{display:flex;align-items:center;justify-content:space-between;padding:12px 0;border-bottom:1px solid rgba(255,255,255,0.05)}
.sl-item:last-child{border-bottom:none}
.sl-key{color:var(--text2);font-size:12px;display:flex;align-items:center;gap:8px}
.sl-val{color:var(--text);font-weight:600;font-size:13px}

/* ── Connections live list ── */
.conn-item{
  display:flex;align-items:center;justify-content:space-between;
  padding:10px 14px;border-radius:10px;
  background:rgba(255,255,255,0.03);border:1px solid var(--border);
  margin-bottom:6px;font-size:12px;
}
.conn-id{color:var(--text3);font-family:'JetBrains Mono',monospace;font-size:10px}
.conn-bytes{color:var(--c3);font-weight:600}

/* ── Search bar ── */
.search-wrap{position:relative;flex:1;min-width:180px}
.search-wrap svg{position:absolute;left:11px;top:50%;transform:translateY(-50%);color:var(--text3);pointer-events:none}
.search-inp{
  width:100%;padding:8px 12px 8px 34px;
  background:rgba(255,255,255,0.05);border:1px solid var(--border);
  border-radius:10px;color:var(--text);font-size:12px;
  font-family:inherit;outline:none;transition:all .2s;
}
.search-inp:focus{border-color:var(--c1);background:rgba(108,99,255,0.06)}
.search-inp::placeholder{color:var(--text3)}

/* ── Filter chips ── */
.chips{display:flex;gap:4px;background:rgba(255,255,255,0.04);padding:3px;border-radius:10px;border:1px solid var(--border)}
.chip{
  padding:5px 13px;border-radius:7px;font-size:11px;font-weight:600;
  color:var(--text3);cursor:pointer;border:none;background:none;
  transition:all .2s;font-family:inherit;
}
.chip.active{background:linear-gradient(135deg,#6c63ff,#ff6584);color:#fff}
.chip:hover:not(.active){background:var(--glass2);color:var(--text2)}

/* ── Empty state ── */
.empty{
  text-align:center;padding:48px 16px;color:var(--text3);
}
.empty-icon{font-size:40px;margin-bottom:12px;opacity:0.25}
.empty-msg{font-size:13px;font-weight:500}

/* ── Notification bell ── */
.notif-btn{
  position:relative;width:34px;height:34px;
  background:var(--glass);border:1px solid var(--border);
  border-radius:10px;cursor:pointer;
  display:flex;align-items:center;justify-content:center;
  color:var(--text3);transition:all .2s;
}
.notif-btn:hover{border-color:var(--c1);color:var(--c1)}
.notif-dot{
  position:absolute;top:6px;right:6px;
  width:6px;height:6px;border-radius:50%;
  background:var(--red);display:none;
  box-shadow:0 0 6px rgba(255,107,107,0.7);
}
.notif-dot.show{display:block}

/* ── Live badge ── */
.live-badge{
  display:inline-flex;align-items:center;gap:5px;
  background:rgba(67,233,123,0.1);border:1px solid rgba(67,233,123,0.2);
  border-radius:6px;padding:2px 8px;font-size:10px;font-weight:700;color:var(--green);
  letter-spacing:0.04em;
}

/* ── Progress ring ── */
.ring-wrap{display:flex;align-items:center;justify-content:center;position:relative}
.ring-wrap .ring-label{
  position:absolute;text-align:center;
}
.ring-label .rv{font-size:18px;font-weight:800;line-height:1}
.ring-label .rl{font-size:9px;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:0.06em}

/* ── Mobile ── */
.mob-header{
  display:none;position:fixed;top:0;left:0;right:0;
  height:48px;background:rgba(8,8,16,0.85);
  backdrop-filter:blur(20px);border-bottom:1px solid var(--border);
  z-index:90;align-items:center;justify-content:space-between;padding:0 16px;
}
.ham{width:34px;height:34px;border-radius:9px;background:var(--glass);border:1px solid var(--border);color:var(--text2);display:flex;align-items:center;justify-content:center;cursor:pointer;font-size:16px}
.sb-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,0.6);z-index:99}
.sb-overlay.open{display:block}

@media(max-width:900px){
  .stats-grid{grid-template-columns:repeat(2,1fr)}
  .g2{grid-template-columns:1fr}
}
@media(max-width:680px){
  .sidebar{transform:translateX(-100%);z-index:200}
  .sidebar.open{transform:translateX(0);box-shadow:4px 0 30px rgba(0,0,0,0.6)}
  .main{margin-left:0;padding-top:58px;padding-left:14px;padding-right:14px}
  .mob-header{display:flex}
  .stats-grid{grid-template-columns:1fr 1fr}
  .ph{flex-direction:column;align-items:flex-start}
}
@media(max-width:400px){
  .stats-grid{grid-template-columns:1fr}
}

.g2{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px}
.mb12{margin-bottom:12px}
.mb16{margin-bottom:16px}

/* ── Hover glow on stat cards ── */
.sc:nth-child(1):hover{box-shadow:0 12px 36px rgba(108,99,255,0.2)}
.sc:nth-child(2):hover{box-shadow:0 12px 36px rgba(67,233,123,0.15)}
.sc:nth-child(3):hover{box-shadow:0 12px 36px rgba(251,191,36,0.15)}
.sc:nth-child(4):hover{box-shadow:0 12px 36px rgba(255,101,132,0.15)}

/* ── sparkline mini chart ── */
.mini-spark{display:inline-block;vertical-align:middle}

/* password strength */
.pw-strength{height:3px;border-radius:2px;margin-top:6px;transition:all .3s;background:var(--border)}
.pw-strength.w{background:var(--red);width:25%}
.pw-strength.m{background:var(--yellow);width:60%}
.pw-strength.s{background:var(--green);width:100%}
</style>
</head>
<body>

<!-- Background -->
<div class="bg-fixed">
  <div class="orb orb1"></div>
  <div class="orb orb2"></div>
</div>

<!-- Toast -->
<div id="toast"></div>

<!-- Mobile Header -->
<div class="mob-header">
  <div style="font-weight:900;font-size:15px;background:linear-gradient(135deg,#6c63ff,#ff6584);-webkit-background-clip:text;-webkit-text-fill-color:transparent">LUFFY</div>
  <button class="ham" onclick="toggleSidebar()">&#9776;</button>
</div>
<div class="sb-overlay" id="sb-overlay" onclick="toggleSidebar()"></div>

<!-- Sidebar -->
<aside class="sidebar" id="sidebar">
  <div class="sb-brand">
    <div class="sb-logo">
      <div class="sb-logo-icon">
        <svg viewBox="0 0 40 40" fill="none"><path d="M10 8h7v18h13v7H10V8z" fill="white" opacity="0.95"/></svg>
      </div>
      <div>
        <div class="sb-title" style="background:linear-gradient(135deg,#a5a0ff,#ff9eb5);-webkit-background-clip:text;-webkit-text-fill-color:transparent">LUFFY</div>
        <div class="sb-ver">Panel v3.0</div>
      </div>
    </div>
    <div class="sb-actions">
      <button class="sb-icon-btn" onclick="toggleTheme()" id="theme-btn" title="Theme">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>
      </button>
    </div>
  </div>

  <nav class="sb-nav">
    <div class="nav-section">Main</div>
    <button class="nav-item active" data-page="dashboard">
      <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg>
      <span data-en="Dashboard" data-fa="داشبورد">Dashboard</span>
      <span class="online-dot" style="margin-left:auto"></span>
    </button>
    <button class="nav-item" data-page="inbounds">
      <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 00-3-3.87M16 3.13a4 4 0 010 7.75"/></svg>
      <span data-en="Inbounds" data-fa="اینباندها">Inbounds</span>
      <span class="nav-badge" id="links-badge">0</span>
    </button>
    <button class="nav-item" data-page="traffic">
      <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
      <span data-en="Traffic" data-fa="ترافیک">Traffic</span>
    </button>
    <button class="nav-item" data-page="connections">
      <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M12 1v4M12 19v4M4.22 4.22l2.83 2.83M16.95 16.95l2.83 2.83M1 12h4M19 12h4M4.22 19.78l2.83-2.83M16.95 7.05l2.83-2.83"/></svg>
      <span data-en="Connections" data-fa="اتصالات">Connections</span>
      <span class="nav-dot"></span>
    </button>
    <div class="nav-section">System</div>
    <button class="nav-item" data-page="security">
      <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
      <span data-en="Security" data-fa="امنیت">Security</span>
    </button>
  </nav>

  <div class="sb-footer">
    <div class="lang-row">
      <button class="lang-btn active" id="lb-en" onclick="setLang('en')">EN</button>
      <button class="lang-btn" id="lb-fa" onclick="setLang('fa')">FA</button>
    </div>
    <button class="logout-btn" onclick="doLogout()">
      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
      <span data-en="Logout" data-fa="خروج">Logout</span>
    </button>
  </div>
</aside>

<!-- Main Content -->
<main class="main">

  <!-- ─── DASHBOARD ─── -->
  <section class="page active" id="page-dashboard">
    <div class="ph">
      <div class="ph-left">
        <div class="pt" data-en="Overview" data-fa="نمای کلی">Overview</div>
        <div class="ps" id="last-upd">Refreshing every 10s</div>
      </div>
      <div class="ph-right">
        <span class="live-badge"><span class="online-dot" style="margin:0"></span> LIVE</span>
        <button class="btn btn-ghost btn-sm" onclick="quickCreate(0.5,'GB')">+ 0.5 GB</button>
        <button class="btn btn-primary btn-sm" onclick="quickCreate(1,'GB')">+ 1 GB</button>
      </div>
    </div>

    <div class="stats-grid mb12">
      <div class="sc">
        <div class="sc-icon" style="background:rgba(108,99,255,0.15)">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#a5a0ff" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
        </div>
        <div class="sc-label">Total Traffic</div>
        <div class="sc-val" id="s-traffic">--<span class="sc-unit"> MB</span></div>
        <div class="sc-sub" id="s-traffic-sub">All time</div>
      </div>
      <div class="sc">
        <div class="sc-icon" style="background:rgba(67,233,123,0.12)">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#5effa0" stroke-width="2"><path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 00-3-3.87M16 3.13a4 4 0 010 7.75"/></svg>
        </div>
        <div class="sc-label">Active Links</div>
        <div class="sc-val" id="s-links">--</div>
        <div class="sc-sub" id="s-links-sub">of -- total</div>
      </div>
      <div class="sc">
        <div class="sc-icon" style="background:rgba(251,191,36,0.12)">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#fbbf24" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
        </div>
        <div class="sc-label">Uptime</div>
        <div class="sc-val" id="s-uptime" style="font-size:18px">--</div>
        <div class="sc-sub">Since last restart</div>
      </div>
      <div class="sc">
        <div class="sc-icon" style="background:rgba(255,101,132,0.12)">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#ff9eb5" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M12 1v4M12 19v4M4.22 4.22l2.83 2.83M16.95 16.95l2.83 2.83M1 12h4M19 12h4M4.22 19.78l2.83-2.83M16.95 7.05l2.83-2.83"/></svg>
        </div>
        <div class="sc-label">Live Connections</div>
        <div class="sc-val" id="s-conns">--</div>
        <div class="sc-sub">Right now</div>
      </div>
    </div>

    <div class="g2 mb12">
      <div class="gc">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px">
          <div style="font-size:13px;font-weight:700">CPU Usage</div>
          <span id="s-cpu-val" style="font-size:20px;font-weight:800;color:#a5a0ff">--%</span>
        </div>
        <div class="sys-bar"><div class="sys-fill" id="s-cpu-bar" style="width:0%;background:linear-gradient(90deg,#6c63ff,#a5a0ff)"></div></div>
      </div>
      <div class="gc">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px">
          <div style="font-size:13px;font-weight:700">Memory</div>
          <span id="s-mem-val" style="font-size:20px;font-weight:800;color:#5effa0">--%</span>
        </div>
        <div class="sys-bar"><div class="sys-fill" id="s-mem-bar" style="width:0%;background:linear-gradient(90deg,#43e97b,#38f9d7)"></div></div>
        <div style="font-size:11px;color:var(--text3);margin-top:7px" id="s-mem-detail">-- / -- MB</div>
      </div>
    </div>

    <div class="gc mb12">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px">
        <div style="font-size:13px;font-weight:700">Hourly Traffic</div>
        <div class="tabs" style="margin-bottom:0">
          <button class="tab-btn active" onclick="switchChart('hourly',this)">Hourly</button>
          <button class="tab-btn" onclick="switchChart('daily',this)">Daily</button>
        </div>
      </div>
      <div class="chart-wrap"><canvas id="trafficChart"></canvas></div>
    </div>

    <div class="gc">
      <div style="font-size:13px;font-weight:700;margin-bottom:14px" data-en="Server Info" data-fa="اطلاعات سرور">Server Info</div>
      <div class="sl-item">
        <span class="sl-key">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>
          Domain
        </span>
        <span class="sl-val" id="s-domain" style="font-family:'JetBrains Mono',monospace;font-size:11px">--</span>
      </div>
      <div class="sl-item">
        <span class="sl-key">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15.3 15.3 0 010 20M12 2a15.3 15.3 0 000 20"/></svg>
          Total Requests
        </span>
        <span class="sl-val" id="s-reqs">--</span>
      </div>
      <div class="sl-item" style="border:none">
        <span class="sl-key">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/></svg>
          Total Errors
        </span>
        <span class="sl-val" id="s-errs" style="color:var(--red)">--</span>
      </div>
    </div>
  </section>

  <!-- ─── INBOUNDS ─── -->
  <section class="page" id="page-inbounds">
    <div class="ph">
      <div class="ph-left">
        <div class="pt" data-en="Inbounds" data-fa="اینباندها">Inbounds</div>
        <div class="ps">VLESS / WebSocket / TLS</div>
      </div>
      <button class="btn btn-primary" onclick="showAddModal()">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
        <span data-en="New Inbound" data-fa="اینباند جدید">New Inbound</span>
      </button>
    </div>

    <div style="display:flex;align-items:center;gap:8px;margin-bottom:14px;flex-wrap:wrap">
      <div class="search-wrap">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
        <input class="search-inp" id="srch" placeholder="Search by name or UUID..." oninput="filterLinks()">
      </div>
      <div class="chips">
        <button class="chip active" onclick="setFilter('all',this)" data-en="All" data-fa="همه">All</button>
        <button class="chip" onclick="setFilter('active',this)" data-en="Active" data-fa="فعال">Active</button>
        <button class="chip" onclick="setFilter('off',this)" data-en="Disabled" data-fa="غیرفعال">Disabled</button>
        <button class="chip" onclick="setFilter('limited',this)" data-en="Limited" data-fa="محدود">Limited</button>
      </div>
    </div>

    <div class="gc" style="padding:0;overflow:hidden">
      <div class="tb-wrap">
        <table class="tb">
          <thead><tr>
            <th>#</th>
            <th data-en="Name" data-fa="نام">Name</th>
            <th>Type</th>
            <th data-en="Traffic" data-fa="ترافیک">Traffic</th>
            <th data-en="Status" data-fa="وضعیت">Status</th>
            <th data-en="Actions" data-fa="عملیات">Actions</th>
          </tr></thead>
          <tbody id="links-tbody"></tbody>
        </table>
      </div>
      <div class="empty" id="links-empty" style="display:none">
        <div class="empty-icon">
          <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/><line x1="23" y1="11" x2="17" y2="11"/></svg>
        </div>
        <div class="empty-msg">No inbounds found</div>
      </div>
    </div>
  </section>

  <!-- ─── TRAFFIC ─── -->
  <section class="page" id="page-traffic">
    <div class="ph">
      <div class="ph-left">
        <div class="pt" data-en="Traffic Analytics" data-fa="آنالیز ترافیک">Traffic Analytics</div>
        <div class="ps">Detailed usage breakdown</div>
      </div>
    </div>
    <div class="g2 mb12">
      <div class="gc">
        <div style="font-size:13px;font-weight:700;margin-bottom:14px">Overview</div>
        <div class="sl-item"><span class="sl-key">Total Traffic</span><span class="sl-val" id="t-total">-- MB</span></div>
        <div class="sl-item"><span class="sl-key">Today</span><span class="sl-val" id="t-today">-- MB</span></div>
        <div class="sl-item"><span class="sl-key">Requests</span><span class="sl-val" id="t-reqs">--</span></div>
        <div class="sl-item" style="border:none"><span class="sl-key">Uptime</span><span class="sl-val" id="t-uptime">--</span></div>
      </div>
      <div class="gc">
        <div style="font-size:13px;font-weight:700;margin-bottom:14px">Top Users</div>
        <div id="top-users-list" style="display:flex;flex-direction:column;gap:8px"></div>
      </div>
    </div>
    <div class="gc">
      <div style="font-size:13px;font-weight:700;margin-bottom:14px">Daily Traffic (7 days)</div>
      <div class="chart-wrap"><canvas id="dailyChart"></canvas></div>
    </div>
  </section>

  <!-- ─── CONNECTIONS ─── -->
  <section class="page" id="page-connections">
    <div class="ph">
      <div class="ph-left">
        <div class="pt" data-en="Live Connections" data-fa="اتصالات زنده">Live Connections</div>
        <div class="ps" id="conn-count-sub">-- active tunnels</div>
      </div>
      <span class="live-badge"><span class="online-dot" style="margin:0"></span> LIVE</span>
    </div>
    <div class="gc" id="conn-list">
      <div class="empty">
        <div class="empty-icon">
          <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="10"/><path d="M8 12h8M12 8v8"/></svg>
        </div>
        <div class="empty-msg">No active connections</div>
      </div>
    </div>
  </section>

  <!-- ─── SECURITY ─── -->
  <section class="page" id="page-security">
    <div class="ph">
      <div class="ph-left">
        <div class="pt" data-en="Security" data-fa="امنیت">Security</div>
        <div class="ps">Password management</div>
      </div>
    </div>
    <div style="max-width:420px">
      <div class="gc mb12">
        <div style="font-size:13px;font-weight:700;margin-bottom:18px">Change Password</div>
        <div class="fg">
          <label class="fl" data-en="Current Password" data-fa="رمز فعلی">Current Password</label>
          <input class="fi" type="password" id="cur-pw" placeholder="Enter current password">
        </div>
        <div class="fg">
          <label class="fl" data-en="New Password" data-fa="رمز جدید">New Password</label>
          <input class="fi" type="password" id="new-pw" placeholder="Min 4 characters" oninput="checkPwStrength(this.value)">
          <div class="pw-strength" id="pw-str"></div>
        </div>
        <div class="fg" style="margin-bottom:0">
          <label class="fl" data-en="Confirm Password" data-fa="تکرار رمز">Confirm Password</label>
          <input class="fi" type="password" id="conf-pw" placeholder="Repeat new password">
        </div>
      </div>
      <button class="btn btn-primary" onclick="changePassword()" style="width:100%;justify-content:center;padding:12px">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
        <span data-en="Update Password" data-fa="به‌روزرسانی">Update Password</span>
      </button>
    </div>
  </section>
</main>

<!-- ─── Modals ─── -->

<!-- Add Modal -->
<div class="moverlay" id="add-modal" onclick="if(event.target===this)closeModal('add-modal')">
  <div class="modal">
    <button class="modal-close" onclick="closeModal('add-modal')">✕</button>
    <div class="modal-title">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:middle;margin-right:6px"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
      <span data-en="New Inbound" data-fa="اینباند جدید">New Inbound</span>
    </div>
    <div class="fg">
      <label class="fl" data-en="Name / Remark" data-fa="نام">Name / Remark</label>
      <input class="fi" id="new-lbl" placeholder="e.g. VIP User">
    </div>
    <div class="form-row">
      <div class="fg">
        <label class="fl" data-en="Traffic Limit" data-fa="محدودیت ترافیک">Traffic Limit</label>
        <input class="fi" id="new-lim" type="number" min="0" step="0.1" placeholder="0 = Unlimited">
      </div>
      <div class="fg" style="min-width:90px;max-width:100px">
        <label class="fl">Unit</label>
        <select class="fs" id="new-unit"><option value="GB">GB</option><option value="MB">MB</option></select>
      </div>
    </div>
    <div class="fg">
      <label class="fl" data-en="Note (optional)" data-fa="یادداشت">Note (optional)</label>
      <input class="fi" id="new-note" placeholder="e.g. Expires in 30 days">
    </div>
    <button class="btn btn-primary" onclick="createLink()" style="width:100%;justify-content:center;padding:11px;margin-top:6px">
      <span data-en="Create Inbound" data-fa="ایجاد">Create Inbound</span>
    </button>
  </div>
</div>

<!-- Detail Modal -->
<div class="moverlay" id="detail-modal" onclick="if(event.target===this)closeModal('detail-modal')">
  <div class="modal" style="max-width:520px">
    <button class="modal-close" onclick="closeModal('detail-modal')">✕</button>
    <div class="modal-title" id="dtl-title">Details</div>
    <div id="dtl-content"></div>
  </div>
</div>

<!-- QR Modal -->
<div class="moverlay" id="qr-modal" onclick="if(event.target===this)closeModal('qr-modal')">
  <div class="modal" style="max-width:360px">
    <button class="modal-close" onclick="closeModal('qr-modal')">✕</button>
    <div class="modal-title">QR Code</div>
    <div class="qr-box"><img id="qr-img" src="" alt="QR Code"></div>
    <div style="display:flex;gap:8px;margin-top:16px">
      <button class="btn btn-primary" style="flex:1;justify-content:center" onclick="dlQR()">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
        Download
      </button>
      <button class="btn btn-ghost" style="flex:1;justify-content:center" onclick="closeModal('qr-modal')">Close</button>
    </div>
  </div>
</div>

<script>
// ── State ──
let lang = localStorage.getItem('ll') || 'en';
let allLinks = [];
let currentFilter = 'all';
let statsData = {};
let chartMode = 'hourly';
let trafficChart = null;
let dailyChart = null;
const $ = s => document.querySelector(s);
const $$ = s => document.querySelectorAll(s);

// ── Sidebar nav ──
$$('.nav-item').forEach(el => el.addEventListener('click', () => {
  if(el.dataset.page) switchPage(el.dataset.page);
}));
function switchPage(id) {
  $$('.page').forEach(p => p.classList.remove('active'));
  $(`#page-${id}`)?.classList.add('active');
  $$('.nav-item').forEach(n => n.classList.toggle('active', n.dataset.page === id));
  $('#sidebar')?.classList.remove('open');
  $('#sb-overlay')?.classList.remove('open');
}
function toggleSidebar() {
  $('#sidebar').classList.toggle('open');
  $('#sb-overlay').classList.toggle('open');
}

// ── Lang ──
function setLang(l) {
  lang = l;
  localStorage.setItem('ll', l);
  document.body.dir = l === 'fa' ? 'rtl' : 'ltr';
  document.querySelectorAll('[data-en]').forEach(el => {
    const v = el.getAttribute('data-' + l);
    if (v) el.textContent = v;
  });
  $('#lb-en').classList.toggle('active', l === 'en');
  $('#lb-fa').classList.toggle('active', l === 'fa');
}

// ── Theme (future) ──
function toggleTheme() {}

// ── Toast ──
function toast(msg, type = 'ok') {
  const t = $('#toast');
  t.textContent = msg;
  t.className = 'show ' + type;
  clearTimeout(t._tid);
  t._tid = setTimeout(() => t.classList.remove('show'), 3200);
}

// ── Modal ──
function openModal(id) { $(`#${id}`).classList.add('open'); }
function closeModal(id) { $(`#${id}`).classList.remove('open'); }

// ── Logout ──
async function doLogout() {
  await fetch('/api/logout', { method: 'POST' });
  location.href = '/login';
}

// ── Format helpers ──
function fmtBytes(b) {
  if (b >= 1073741824) return (b / 1073741824).toFixed(2) + ' GB';
  if (b >= 1048576) return (b / 1048576).toFixed(2) + ' MB';
  if (b >= 1024) return (b / 1024).toFixed(1) + ' KB';
  return b + ' B';
}
function fmtLimit(b) {
  if (!b || b === 0) return '∞';
  if (b >= 1073741824) {
    const g = b / 1073741824;
    return (g % 1 === 0 ? g.toFixed(0) : g.toFixed(1)) + ' GB';
  }
  return (b / 1048576).toFixed(0) + ' MB';
}
function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ── Stats ──
async function loadStats() {
  try {
    const r = await fetch('/stats');
    if (!r.ok) return;
    statsData = await r.json();
    // Dashboard
    const mb = statsData.total_traffic_mb;
    const gb = (mb / 1024).toFixed(2);
    $('#s-traffic').innerHTML = mb > 1024 ? gb + '<span class="sc-unit"> GB</span>' : mb + '<span class="sc-unit"> MB</span>';
    $('#s-links').textContent = statsData.active_links ?? statsData.links_count;
    $('#s-links-sub').textContent = `of ${statsData.links_count} total`;
    $('#s-uptime').textContent = statsData.uptime;
    $('#s-conns').textContent = statsData.active_connections;
    $('#s-domain').textContent = statsData.domain;
    $('#s-reqs').textContent = (statsData.total_requests || 0).toLocaleString();
    $('#s-errs').textContent = (statsData.total_errors || 0).toLocaleString();
    $('#last-upd').textContent = 'Updated: ' + new Date().toLocaleTimeString();

    // CPU
    const cpu = statsData.cpu_percent || 0;
    const cpuColor = cpu > 80 ? 'linear-gradient(90deg,#ff6b6b,#ff9eb5)' : cpu > 50 ? 'linear-gradient(90deg,#fbbf24,#fcd34d)' : 'linear-gradient(90deg,#6c63ff,#a5a0ff)';
    $('#s-cpu-val').textContent = cpu.toFixed(1) + '%';
    $('#s-cpu-bar').style.width = cpu + '%';
    $('#s-cpu-bar').style.background = cpuColor;

    // Memory
    const mem = statsData.memory_percent || 0;
    const memColor = mem > 80 ? 'linear-gradient(90deg,#ff6b6b,#ff9eb5)' : mem > 50 ? 'linear-gradient(90deg,#fbbf24,#fcd34d)' : 'linear-gradient(90deg,#43e97b,#38f9d7)';
    $('#s-mem-val').textContent = mem.toFixed(1) + '%';
    $('#s-mem-bar').style.width = mem + '%';
    $('#s-mem-bar').style.background = memColor;
    if (statsData.memory_used_mb) $('#s-mem-detail').textContent = `${statsData.memory_used_mb} / ${statsData.memory_total_mb} MB`;

    $('#links-badge').textContent = statsData.links_count;

    // Traffic page
    const todayKey = new Date().toISOString().split('T')[0];
    const todayBytes = (statsData.daily_traffic || {})[todayKey] || 0;
    if ($('#t-total')) {
      $('#t-total').textContent = fmtBytes(statsData.total_bytes || (mb * 1024 * 1024));
      $('#t-today').textContent = fmtBytes(todayBytes);
      $('#t-reqs').textContent = (statsData.total_requests || 0).toLocaleString();
      $('#t-uptime').textContent = statsData.uptime;
    }

    // Connections page
    const conns = statsData.connections || [];
    $('#conn-count-sub').textContent = `${conns.length} active tunnel${conns.length !== 1 ? 's' : ''}`;
    const connList = $('#conn-list');
    if (conns.length === 0) {
      connList.innerHTML = `<div class="empty"><div class="empty-icon"><svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="10"/><path d="M8 12h8"/></svg></div><div class="empty-msg">No active connections</div></div>`;
    } else {
      connList.innerHTML = conns.map(c => `
        <div class="conn-item">
          <div>
            <div class="conn-id">${esc(c.id)}</div>
            <div style="font-size:11px;color:var(--text2);margin-top:2px">${esc(c.uuid.slice(0,16))}…</div>
          </div>
          <div style="text-align:right">
            <div class="conn-bytes">${fmtBytes(c.bytes)}</div>
            <div style="font-size:10px;color:var(--text3)">${esc(c.connected_at?.slice(11,19) || '')}</div>
          </div>
        </div>
      `).join('');
    }

    // Top users on traffic page
    const topList = $('#top-users-list');
    if (topList && allLinks.length) {
      const sorted = [...allLinks].sort((a,b) => b.used_bytes - a.used_bytes).slice(0,5);
      topList.innerHTML = sorted.map(l => {
        const pct = l.limit_bytes > 0 ? Math.min(100, (l.used_bytes / l.limit_bytes) * 100) : 0;
        const col = pct > 90 ? 'var(--red)' : pct > 70 ? 'var(--yellow)' : 'var(--c1)';
        return `<div style="display:flex;flex-direction:column;gap:4px">
          <div style="display:flex;justify-content:space-between;font-size:12px">
            <span style="font-weight:600">${esc(l.label)}</span>
            <span style="color:var(--text2)">${fmtBytes(l.used_bytes)}</span>
          </div>
          <div class="ub-bar"><div class="ub-fill" style="width:${pct}%;background:${col}"></div></div>
        </div>`;
      }).join('');
    }

    updateChart();
  } catch(e) {}
}

// ── Links ──
async function loadLinks() {
  try {
    const r = await fetch('/api/links');
    if (!r.ok) return;
    allLinks = (await r.json()).links || [];
    filterLinks();
  } catch(e) {}
}

let filterMode = 'all';
function setFilter(f, el) {
  filterMode = f;
  $$('.chip').forEach(c => c.classList.remove('active'));
  el.classList.add('active');
  filterLinks();
}
function filterLinks() {
  const q = ($('#srch')?.value || '').toLowerCase();
  let list = [...allLinks];
  if (filterMode === 'active') list = list.filter(l => l.active);
  if (filterMode === 'off') list = list.filter(l => !l.active);
  if (filterMode === 'limited') list = list.filter(l => l.limit_bytes > 0);
  if (q) list = list.filter(l => l.label.toLowerCase().includes(q) || l.uuid.toLowerCase().includes(q));
  renderLinks(list);
}

function renderLinks(links) {
  const tbody = $('#links-tbody');
  const empty = $('#links-empty');
  if (!links.length) {
    tbody.innerHTML = '';
    empty.style.display = 'block';
    return;
  }
  empty.style.display = 'none';
  let idx = links.length;
  tbody.innerHTML = links.map(l => {
    const u = l.used_bytes, lim = l.limit_bytes;
    const uF = fmtBytes(u), lF = fmtLimit(lim);
    const pct = lim > 0 ? Math.min(100, (u / lim) * 100) : 0;
    const col = pct > 90 ? 'var(--red)' : pct > 70 ? 'var(--yellow)' : '#6c63ff';
    const i = idx--;
    return `<tr>
      <td style="color:var(--text3);font-size:11px;font-family:'JetBrains Mono',monospace">${i}</td>
      <td>
        <div style="font-weight:600">${esc(l.label)}</div>
        ${l.note ? `<div style="font-size:10px;color:var(--text3);margin-top:2px">${esc(l.note)}</div>` : ''}
      </td>
      <td><span class="tag tag-vless">VLESS</span></td>
      <td>
        <div class="ub">
          <span class="ub-text">${uF}</span>
          <div class="ub-bar"><div class="ub-fill" style="width:${pct}%;background:${col}"></div></div>
          <span class="ub-lim">${lF}</span>
        </div>
      </td>
      <td><span class="tag ${l.active ? 'tag-on' : 'tag-off'}">${l.active ? 'ON' : 'OFF'}</span></td>
      <td>
        <div class="act-group">
          <div class="tog ${l.active ? 'on' : ''}" data-uid="${l.uuid}" onclick="toggleLink(this)" title="Toggle"></div>
          <button class="btn btn-ghost btn-xs" onclick="showDetail('${l.uuid}')" title="Details">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>
          </button>
          <button class="btn btn-copy btn-xs" onclick="copyText('${esc(l.vless_link)}')" title="Copy link">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>
          </button>
          <button class="btn btn-qr btn-xs" onclick="showQR('${esc(l.vless_link)}')" title="QR Code">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><path d="M14 14h.01M14 17h3v3M17 14h3"/></svg>
          </button>
          <button class="btn btn-danger btn-xs" onclick="deleteLink('${l.uuid}')" title="Delete">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v6M14 11v6M9 6V4h6v2"/></svg>
          </button>
        </div>
      </td>
    </tr>`;
  }).join('');
}

async function toggleLink(el) {
  const uid = el.dataset.uid;
  const link = allLinks.find(l => l.uuid === uid);
  if (!link) return;
  const newActive = !link.active;
  try {
    await fetch(`/api/links/${uid}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ active: newActive })
    });
    link.active = newActive;
    filterLinks();
    loadStats();
    toast(newActive ? 'Link enabled' : 'Link disabled');
  } catch(e) { toast('Error', 'err'); }
}

async function quickCreate(lim, unit) {
  const names = ['Ali','Sara','Reza','Nima','Mina','Arash','Yalda','Cyrus','Shirin','Dara','Tara','Kian'];
  const name = names[Math.floor(Math.random() * names.length)] + '-' + Math.floor(Math.random() * 100);
  try {
    const r = await fetch('/api/links', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ label: name, limit_value: lim, limit_unit: unit })
    });
    if (!r.ok) throw new Error();
    toast(`Created: ${name}`);
    await loadLinks();
    await loadStats();
  } catch(e) { toast('Error creating link', 'err'); }
}

function showAddModal() {
  $('#new-lbl').value = '';
  $('#new-lim').value = '';
  $('#new-note').value = '';
  openModal('add-modal');
}

async function createLink() {
  const label = ($('#new-lbl').value.trim() || 'New Link');
  const val = parseFloat($('#new-lim').value) || 0;
  const unit = $('#new-unit').value;
  const note = $('#new-note').value.trim();
  try {
    const r = await fetch('/api/links', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ label, limit_value: val, limit_unit: unit, note })
    });
    if (!r.ok) throw new Error();
    toast('Inbound created');
    closeModal('add-modal');
    await loadLinks();
    await loadStats();
  } catch(e) { toast('Error', 'err'); }
}

async function deleteLink(uid) {
  if (!confirm('Delete this inbound permanently?')) return;
  try {
    await fetch(`/api/links/${uid}`, { method: 'DELETE' });
    toast('Deleted');
    await loadLinks();
    await loadStats();
  } catch(e) { toast('Error', 'err'); }
}

function showDetail(uid) {
  const l = allLinks.find(x => x.uuid === uid);
  if (!l) return;
  const pct = l.limit_bytes > 0 ? Math.min(100, (l.used_bytes / l.limit_bytes) * 100) : 0;
  const col = pct > 90 ? 'var(--red)' : pct > 70 ? 'var(--yellow)' : 'var(--c1)';
  const created = l.created_at ? new Date(l.created_at).toLocaleString(lang === 'fa' ? 'fa-IR' : 'en-US') : '--';
  $('#dtl-title').textContent = l.label;
  $('#dtl-content').innerHTML = `
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:12px">
      <div class="dc"><div class="dc-lbl">Protocol</div><span class="tag tag-vless">VLESS</span></div>
      <div class="dc"><div class="dc-lbl">Status</div><span class="tag ${l.active ? 'tag-on' : 'tag-off'}">${l.active ? 'Active' : 'Disabled'}</span></div>
    </div>
    <div class="dc mb12"><div class="dc-lbl">UUID</div><div class="dc-val">${l.uuid}</div></div>
    <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px;margin-bottom:10px">
      <div class="dc"><div class="dc-lbl">Used</div><div class="dc-val" style="font-size:13px;color:var(--text)">${fmtBytes(l.used_bytes)}</div></div>
      <div class="dc"><div class="dc-lbl">Limit</div><div class="dc-val" style="font-size:13px;color:var(--text)">${fmtLimit(l.limit_bytes)}</div></div>
      <div class="dc"><div class="dc-lbl">Usage</div><div class="dc-val" style="font-size:13px;color:${col}">${pct.toFixed(1)}%</div></div>
    </div>
    <div class="ub-bar" style="height:6px;border-radius:3px;margin-bottom:12px;background:rgba(255,255,255,0.08)">
      <div class="ub-fill" style="width:${pct}%;background:${col}"></div>
    </div>
    ${l.note ? `<div class="dc mb12"><div class="dc-lbl">Note</div><div class="dc-val" style="font-family:inherit">${esc(l.note)}</div></div>` : ''}
    <div class="dc mb12"><div class="dc-lbl">Created</div><div class="dc-val" style="font-family:inherit;font-size:11px">${created}</div></div>
    <div class="dc mb12"><div class="dc-lbl">VLESS Link</div><div class="dc-val" style="font-size:10px;line-height:1.8">${esc(l.vless_link)}</div></div>
    <div style="display:flex;gap:6px;flex-wrap:wrap">
      <button class="btn btn-copy btn-sm" onclick="copyText('${esc(l.vless_link)}');closeModal('detail-modal')">Copy Link</button>
      <button class="btn btn-qr btn-sm" onclick="showQR('${esc(l.vless_link)}');closeModal('detail-modal')">QR Code</button>
      <button class="btn btn-ghost btn-sm" onclick="resetUsage('${l.uuid}');closeModal('detail-modal')">Reset Traffic</button>
      <button class="btn btn-danger btn-sm" onclick="deleteLink('${l.uuid}');closeModal('detail-modal')">Delete</button>
    </div>`;
  openModal('detail-modal');
}

async function resetUsage(uid) {
  try {
    await fetch(`/api/links/${uid}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ reset_usage: true })
    });
    toast('Traffic reset');
    await loadLinks();
  } catch(e) { toast('Error', 'err'); }
}

function copyText(txt) {
  navigator.clipboard.writeText(txt)
    .then(() => toast('Copied to clipboard ✓'))
    .catch(() => toast('Copy failed', 'err'));
}

function showQR(txt) {
  if (!txt) return;
  $('#qr-img').src = 'https://api.qrserver.com/v1/create-qr-code/?size=280x280&color=ffffff&bgcolor=111111&data=' + encodeURIComponent(txt);
  openModal('qr-modal');
}

function dlQR() {
  const img = $('#qr-img');
  if (!img.src) return;
  const a = document.createElement('a');
  a.href = img.src;
  a.download = 'luffy-qr.png';
  a.click();
}

// ── Password ──
function checkPwStrength(v) {
  const el = $('#pw-str');
  if (!v) { el.className = 'pw-strength'; return; }
  const strong = v.length >= 8 && /[A-Z]/.test(v) && /[0-9]/.test(v);
  const medium = v.length >= 6;
  el.className = 'pw-strength ' + (strong ? 's' : medium ? 'm' : 'w');
}

async function changePassword() {
  const cur = $('#cur-pw').value;
  const nw = $('#new-pw').value;
  const conf = $('#conf-pw').value;
  if (!cur || !nw) return toast('Fill all fields', 'err');
  if (nw !== conf) return toast('Passwords do not match', 'err');
  if (nw.length < 4) return toast('Min 4 characters', 'err');
  try {
    const r = await fetch('/api/change-password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ current_password: cur, new_password: nw })
    });
    if (!r.ok) {
      const d = await r.json().catch(() => ({}));
      throw new Error(d.detail || 'Error');
    }
    toast('Password updated ✓');
    $('#cur-pw').value = '';
    $('#new-pw').value = '';
    $('#conf-pw').value = '';
    $('#pw-str').className = 'pw-strength';
  } catch(e) { toast(e.message, 'err'); }
}

// ── Charts ──
function initCharts() {
  const baseOpts = {
    responsive: true, maintainAspectRatio: false,
    plugins: { legend: { display: false }, tooltip: {
      backgroundColor: 'rgba(14,14,28,0.95)',
      titleColor: 'rgba(255,255,255,0.7)',
      bodyColor: '#fff',
      borderColor: 'rgba(255,255,255,0.1)',
      borderWidth: 1, padding: 10, cornerRadius: 8,
    }},
    scales: {
      x: { grid: { display: false, drawBorder: false }, ticks: { color: 'rgba(255,255,255,0.28)', font: { size: 10, family: 'Inter' } } },
      y: { grid: { color: 'rgba(255,255,255,0.04)', drawBorder: false }, ticks: { color: 'rgba(255,255,255,0.28)', font: { size: 10 }, callback: v => fmtBytes(v) }, beginAtZero: true }
    }
  };

  const ctx1 = document.getElementById('trafficChart');
  if (ctx1) {
    trafficChart = new Chart(ctx1, {
      type: 'bar',
      data: { labels: [], datasets: [{
        label: 'Traffic', data: [],
        backgroundColor: 'rgba(108,99,255,0.4)',
        borderColor: '#6c63ff', borderWidth: 1.5,
        borderRadius: 5, borderSkipped: false,
        hoverBackgroundColor: 'rgba(108,99,255,0.65)',
      }]},
      options: { ...baseOpts }
    });
  }

  const ctx2 = document.getElementById('dailyChart');
  if (ctx2) {
    dailyChart = new Chart(ctx2, {
      type: 'line',
      data: { labels: [], datasets: [{
        label: 'Daily Traffic', data: [],
        borderColor: '#43e97b', borderWidth: 2,
        backgroundColor: 'rgba(67,233,123,0.08)',
        fill: true, tension: 0.4,
        pointBackgroundColor: '#43e97b',
        pointRadius: 4, pointHoverRadius: 6,
      }]},
      options: { ...baseOpts }
    });
  }
}

function switchChart(mode, el) {
  chartMode = mode;
  $$('.tab-btn').forEach(b => b.classList.remove('active'));
  el.classList.add('active');
  updateChart();
}

function updateChart() {
  if (!trafficChart) return;
  if (chartMode === 'hourly' && statsData.hourly_traffic) {
    const entries = Object.entries(statsData.hourly_traffic).sort((a,b) => a[0].localeCompare(b[0])).slice(-16);
    trafficChart.data.labels = entries.map(e => e[0]);
    trafficChart.data.datasets[0].data = entries.map(e => e[1]);
    trafficChart.update('none');
  } else if (chartMode === 'daily' && statsData.daily_traffic) {
    const entries = Object.entries(statsData.daily_traffic).sort((a,b) => a[0].localeCompare(b[0])).slice(-14);
    trafficChart.data.labels = entries.map(e => e[0].slice(5));
    trafficChart.data.datasets[0].data = entries.map(e => e[1]);
    trafficChart.update('none');
  }

  if (dailyChart && statsData.daily_traffic) {
    const entries = Object.entries(statsData.daily_traffic).sort((a,b) => a[0].localeCompare(b[0])).slice(-7);
    dailyChart.data.labels = entries.map(e => e[0].slice(5));
    dailyChart.data.datasets[0].data = entries.map(e => e[1]);
    dailyChart.update('none');
  }
}

// ── Init ──
setLang(lang);
initCharts();
loadStats();
loadLinks();
setInterval(loadStats, 10000);
setInterval(loadLinks, 30000);
</script>
</body>
</html>
"""

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if await is_valid_session(token):
        return RedirectResponse(url="/dashboard")
    return HTMLResponse(content=LOGIN_HTML)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not await is_valid_session(token):
        return RedirectResponse(url="/login")
    return HTMLResponse(content=DASHBOARD_HTML)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=CONFIG["port"])
