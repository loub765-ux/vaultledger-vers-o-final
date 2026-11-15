#!/usr/bin/env python3
"""
VaultLedger API Server
- SQLite database
- Users with password hashing
- Per-user transactions, goals, agenda
- Token-based auth
"""
import json
import sqlite3
import hashlib
import secrets
import os
import re
from datetime import datetime, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from pathlib import Path

# Paths
BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "vaultledger.db"
try:
    BASE_DIR.mkdir(parents=True, exist_ok=True)
except Exception:
    pass
# If server folder is not writable, use system temp (Windows/Mac/Linux)
def _resolve_db_path():
    import tempfile
    candidates = [
        BASE_DIR / "vaultledger.db",
        Path(tempfile.gettempdir()) / "vaultledger.db",
        Path.home() / "vaultledger.db",
    ]
    for cand in candidates:
        try:
            cand.parent.mkdir(parents=True, exist_ok=True)
            conn = __import__("sqlite3").connect(str(cand))
            conn.execute("SELECT 1")
            conn.close()
            return cand
        except Exception:
            continue
    return candidates[0]
DB_PATH = _resolve_db_path()
# All pages + js live in this same folder (pages/)
STATIC_DIRS = [
    BASE_DIR,  # pasta pages/
]
PORT = 5500

# ──────────────────────────── DB ────────────────────────────

def get_db():
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False, timeout=30)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=WAL")
    except Exception:
        pass
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = get_db()
    c = conn.cursor()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE COLLATE NOCASE,
        password_hash TEXT NOT NULL,
        settings TEXT DEFAULT '{}',
        created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        expires_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        date TEXT NOT NULL,
        type TEXT NOT NULL,
        category TEXT NOT NULL,
        description TEXT,
        value REAL NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS goals (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        description TEXT,
        target REAL NOT NULL,
        current REAL NOT NULL DEFAULT 0,
        category TEXT DEFAULT 'other',
        created_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS agenda (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        nome TEXT NOT NULL,
        valor REAL NOT NULL,
        data TEXT NOT NULL,
        tipo TEXT DEFAULT 'variavel',
        descricao TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    """)
    
    try:
        cols = [r[1] for r in c.execute("PRAGMA table_info(transactions)").fetchall()]
        if "tag" not in cols:
            c.execute("ALTER TABLE transactions ADD COLUMN tag TEXT DEFAULT ''")
    except Exception:
        pass

    conn.commit()
    conn.close()
    print(f"[DB] Ready at {DB_PATH}")


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 120000)
    return salt + ":" + h.hex()


def verify_password(password: str, stored: str) -> bool:
    try:
        salt, h = stored.split(":", 1)
        check = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 120000)
        return secrets.compare_digest(check.hex(), h)
    except Exception:
        return False


def create_session(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    expires = (datetime.utcnow() + timedelta(days=30)).isoformat()
    conn = get_db()
    conn.execute(
        "INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)",
        (token, user_id, expires),
    )
    conn.commit()
    conn.close()
    return token


def get_user_from_token(token: str):
    if not token:
        return None
    conn = get_db()
    row = conn.execute(
        """
        SELECT u.* FROM users u
        JOIN sessions s ON s.user_id = u.id
        WHERE s.token = ? AND s.expires_at > ?
        """,
        (token, datetime.utcnow().isoformat()),
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def user_public(u: dict) -> dict:
    return {
        "id": u["id"],
        "name": u["name"],
        "email": u["email"],
        "settings": json.loads(u["settings"] or "{}"),
        "created_at": u["created_at"],
    }


# ──────────────────────────── HTTP ────────────────────────────

CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
}

MIME = {
    ".html": "text/html; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".svg": "image/svg+xml",
    ".json": "application/json",
    ".ico": "image/x-icon",
}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print(f"[{self.address_string()}] {args[0]}")

    def _send(self, code=200, body=None, content_type="application/json"):
        data = b""
        if body is not None:
            if isinstance(body, (dict, list)):
                data = json.dumps(body, ensure_ascii=False).encode("utf-8")
            elif isinstance(body, str):
                data = body.encode("utf-8")
            else:
                data = body
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        for k, v in CORS_HEADERS.items():
            self.send_header(k, v)
        self.end_headers()
        if data:
            self.wfile.write(data)

    def _json_error(self, message, code=400):
        self._send(code, {"error": message})

    def _read_json(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return {}

    def _auth(self):
        auth = self.headers.get("Authorization") or ""
        token = ""
        if auth.lower().startswith("bearer "):
            token = auth[7:].strip()
        return get_user_from_token(token)

    def do_OPTIONS(self):
        self._send(204, b"")

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        # API routes
        if path.startswith("/api/"):
            return self.handle_api_get(path)

        # Static files
        return self.serve_static(path)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if path.startswith("/api/"):
            return self.handle_api_post(path)
        self._json_error("Not found", 404)

    def do_PUT(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if path.startswith("/api/"):
            return self.handle_api_put(path)
        self._json_error("Not found", 404)

    def do_PATCH(self):
        return self.do_PUT()

    def do_DELETE(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if path.startswith("/api/"):
            return self.handle_api_delete(path)
        self._json_error("Not found", 404)

    # ── Static ──

    def serve_static(self, path):
        if path == "/" or path == "":
            path = "/index.html"
        # security: no path traversal
        safe = os.path.normpath(path.lstrip("/").replace("\\", "/"))
        if safe.startswith("..") or safe.startswith("/") or ":" in safe:
            return self._json_error("Forbidden", 403)
        file_path = None
        for root in STATIC_DIRS:
            candidate = root / safe
            if candidate.is_file():
                file_path = candidate
                break
        if not file_path:
            tried = ", ".join(str(d / safe) for d in STATIC_DIRS)
            return self._send(404, f"Not found: {path}\nProcurou em: {tried}", "text/plain; charset=utf-8")
        ext = file_path.suffix.lower()
        ctype = MIME.get(ext, "application/octet-stream")
        data = file_path.read_bytes()
        self._send(200, data, ctype)

    # ── API GET ──

    def handle_api_get(self, path):
        if path == "/api/me":
            user = self._auth()
            if not user:
                return self._json_error("Não autenticado", 401)
            return self._send(200, user_public(user))

        if path == "/api/transactions":
            user = self._auth()
            if not user:
                return self._json_error("Não autenticado", 401)
            conn = get_db()
            rows = conn.execute(
                "SELECT * FROM transactions WHERE user_id = ? ORDER BY date DESC, id DESC",
                (user["id"],),
            ).fetchall()
            conn.close()
            return self._send(200, [dict(r) for r in rows])

        if path == "/api/goals":
            user = self._auth()
            if not user:
                return self._json_error("Não autenticado", 401)
            conn = get_db()
            rows = conn.execute(
                "SELECT * FROM goals WHERE user_id = ? ORDER BY id DESC",
                (user["id"],),
            ).fetchall()
            conn.close()
            return self._send(200, [dict(r) for r in rows])

        if path == "/api/agenda":
            user = self._auth()
            if not user:
                return self._json_error("Não autenticado", 401)
            conn = get_db()
            rows = conn.execute(
                "SELECT * FROM agenda WHERE user_id = ? ORDER BY data ASC",
                (user["id"],),
            ).fetchall()
            conn.close()
            return self._send(200, [dict(r) for r in rows])

        if path == "/api/settings":
            user = self._auth()
            if not user:
                return self._json_error("Não autenticado", 401)
            return self._send(200, json.loads(user["settings"] or "{}"))

        self._json_error("Not found", 404)

    # ── API POST ──

    def handle_api_post(self, path):
        body = self._read_json()

        if path == "/api/register":
            name = (body.get("name") or "").strip()
            email = (body.get("email") or "").strip().lower()
            password = body.get("password") or ""
            if not name or not email or not password:
                return self._json_error("Preencha nome, email e senha")
            if len(password) < 6:
                return self._json_error("Senha deve ter pelo menos 6 caracteres")
            if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
                return self._json_error("Email inválido")
            conn = get_db()
            exists = conn.execute(
                "SELECT id FROM users WHERE email = ?", (email,)
            ).fetchone()
            if exists:
                conn.close()
                return self._json_error("Email já cadastrado", 409)
            now = datetime.utcnow().isoformat()
            cur = conn.execute(
                "INSERT INTO users (name, email, password_hash, settings, created_at) VALUES (?, ?, ?, ?, ?)",
                (name, email, hash_password(password), "{}", now),
            )
            user_id = cur.lastrowid
            conn.commit()
            conn.close()
            token = create_session(user_id)
            conn = get_db()
            user = dict(conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone())
            conn.close()
            return self._send(201, {"token": token, "user": user_public(user)})

        if path == "/api/login":
            email = (body.get("email") or "").strip().lower()
            password = body.get("password") or ""
            conn = get_db()
            row = conn.execute(
                "SELECT * FROM users WHERE email = ?", (email,)
            ).fetchone()
            conn.close()
            if not row or not verify_password(password, row["password_hash"]):
                return self._json_error("Email ou senha incorretos", 401)
            user = dict(row)
            token = create_session(user["id"])
            return self._send(200, {"token": token, "user": user_public(user)})

        if path == "/api/logout":
            auth = self.headers.get("Authorization") or ""
            token = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
            if token:
                conn = get_db()
                conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
                conn.commit()
                conn.close()
            return self._send(200, {"ok": True})

        # Authenticated routes below
        user = self._auth()
        if not user:
            return self._json_error("Não autenticado", 401)

        if path == "/api/transactions":
            date = body.get("date") or datetime.utcnow().strftime("%Y-%m-%d")
            typ = body.get("type") or "Entrada"
            category = body.get("category") or "Débito"
            description = body.get("description") or ""
            try:
                value = float(body.get("value"))
            except (TypeError, ValueError):
                return self._json_error("Valor inválido")
            now = datetime.utcnow().isoformat()
            conn = get_db()
            cur = conn.execute(
                """INSERT INTO transactions (user_id, date, type, category, description, value, created_at, tag)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (user["id"], date, typ, category, description, value, now, body.get("tag") or ""),
            )
            tid = cur.lastrowid
            conn.commit()
            row = dict(conn.execute("SELECT * FROM transactions WHERE id = ?", (tid,)).fetchone())
            conn.close()
            return self._send(201, row)


        if path == "/api/transactions/apply-tags":
            rules = body.get("rules") or []
            overwrite = bool(body.get("overwrite"))
            if not isinstance(rules, list):
                return self._json_error("rules invalido")
            conn = get_db()
            try:
                rows = conn.execute(
                    "SELECT id, description, tag FROM transactions WHERE user_id = ?",
                    (user["id"],),
                ).fetchall()
            except Exception:
                rows = conn.execute(
                    "SELECT id, description FROM transactions WHERE user_id = ?",
                    (user["id"],),
                ).fetchall()
            updated = 0
            for row in rows:
                desc = (row["description"] or "").lower()
                try:
                    current = row["tag"] or ""
                except Exception:
                    current = ""
                if current and not overwrite:
                    continue
                new_tag = ""
                for rule in rules:
                    match = str(rule.get("match") or "").strip().lower()
                    tag = str(rule.get("tag") or "").strip()
                    if match and tag and match in desc:
                        new_tag = tag
                        break
                if new_tag and new_tag != current:
                    try:
                        conn.execute(
                            "UPDATE transactions SET tag = ? WHERE id = ? AND user_id = ?",
                            (new_tag, row["id"], user["id"]),
                        )
                        updated += 1
                    except Exception:
                        pass
            conn.commit()
            conn.close()
            return self._send(200, {"ok": True, "updated": updated})

        if path == "/api/goals":
            name = (body.get("name") or "").strip()
            if not name:
                return self._json_error("Nome obrigatório")
            try:
                target = float(body.get("target"))
            except (TypeError, ValueError):
                return self._json_error("Valor alvo inválido")
            description = body.get("description") or ""
            category = body.get("category") or "other"
            current = float(body.get("current") or 0)
            now = datetime.utcnow().isoformat()
            conn = get_db()
            cur = conn.execute(
                """INSERT INTO goals (user_id, name, description, target, current, category, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (user["id"], name, description, target, current, category, now),
            )
            gid = cur.lastrowid
            conn.commit()
            row = dict(conn.execute("SELECT * FROM goals WHERE id = ?", (gid,)).fetchone())
            conn.close()
            return self._send(201, row)

        if path == "/api/agenda":
            nome = (body.get("nome") or body.get("name") or "").strip()
            if not nome:
                return self._json_error("Nome obrigatório")
            try:
                valor = float(body.get("valor") if body.get("valor") is not None else body.get("value"))
            except (TypeError, ValueError):
                return self._json_error("Valor inválido")
            data = body.get("data") or body.get("date") or ""
            if not data:
                return self._json_error("Data obrigatória")
            tipo = body.get("tipo") or body.get("type") or "variavel"
            descricao = body.get("descricao") or body.get("description") or ""
            now = datetime.utcnow().isoformat()
            conn = get_db()
            cur = conn.execute(
                """INSERT INTO agenda (user_id, nome, valor, data, tipo, descricao, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (user["id"], nome, valor, data, tipo, descricao, now),
            )
            aid = cur.lastrowid
            conn.commit()
            row = dict(conn.execute("SELECT * FROM agenda WHERE id = ?", (aid,)).fetchone())
            conn.close()
            return self._send(201, row)

        self._json_error("Not found", 404)

    # ── API PUT ──

    def handle_api_put(self, path):
        user = self._auth()
        if not user:
            return self._json_error("Não autenticado", 401)
        body = self._read_json()

        m = re.match(r"^/api/transactions/(\d+)$", path)
        if m:
            tid = int(m.group(1))
            conn = get_db()
            row = conn.execute(
                "SELECT * FROM transactions WHERE id = ? AND user_id = ?",
                (tid, user["id"]),
            ).fetchone()
            if not row:
                conn.close()
                return self._json_error("Transação não encontrada", 404)
            date = body.get("date", row["date"])
            typ = body.get("type", row["type"])
            category = body.get("category", row["category"])
            description = body.get("description", row["description"]) if body.get("description") is not None else row["description"]
            try:
                value = float(body["value"]) if body.get("value") is not None else float(row["value"])
            except (TypeError, ValueError):
                conn.close()
                return self._json_error("Valor inválido")
            conn.execute(
                """UPDATE transactions SET date=?, type=?, category=?, description=?, value=?, tag=?
                   WHERE id=? AND user_id=?""",
                (date, typ, category, description, value, (body.get("tag") if body.get("tag") is not None else (row["tag"] if "tag" in row.keys() else "")), tid, user["id"]),
            )
            conn.commit()
            updated = dict(conn.execute("SELECT * FROM transactions WHERE id = ?", (tid,)).fetchone())
            conn.close()
            return self._send(200, updated)

        m = re.match(r"^/api/goals/(\d+)$", path)
        if m:
            gid = int(m.group(1))
            conn = get_db()
            row = conn.execute(
                "SELECT * FROM goals WHERE id = ? AND user_id = ?", (gid, user["id"])
            ).fetchone()
            if not row:
                conn.close()
                return self._json_error("Meta não encontrada", 404)
            name = body.get("name", row["name"])
            description = body.get("description", row["description"])
            target = float(body.get("target", row["target"]))
            current = float(body.get("current", row["current"]))
            category = body.get("category", row["category"])
            # add value helper
            if body.get("add_value") is not None:
                current = min(target, current + float(body["add_value"]))
            conn.execute(
                """UPDATE goals SET name=?, description=?, target=?, current=?, category=?
                   WHERE id=? AND user_id=?""",
                (name, description, target, current, category, gid, user["id"]),
            )
            conn.commit()
            updated = dict(conn.execute("SELECT * FROM goals WHERE id = ?", (gid,)).fetchone())
            conn.close()
            return self._send(200, updated)

        if path == "/api/settings":
            settings = body if isinstance(body, dict) else {}
            conn = get_db()
            conn.execute(
                "UPDATE users SET settings = ? WHERE id = ?",
                (json.dumps(settings, ensure_ascii=False), user["id"]),
            )
            conn.commit()
            conn.close()
            return self._send(200, settings)

        self._json_error("Not found", 404)

    # ── API DELETE ──

    def handle_api_delete(self, path):
        user = self._auth()
        if not user:
            return self._json_error("Não autenticado", 401)

        if path == "/api/transactions":
            conn = get_db()
            conn.execute("DELETE FROM transactions WHERE user_id = ?", (user["id"],))
            conn.commit()
            conn.close()
            return self._send(200, {"ok": True, "message": "Todas as transações excluídas"})

        m = re.match(r"^/api/transactions/(\d+)$", path)
        if m:
            tid = int(m.group(1))
            conn = get_db()
            conn.execute(
                "DELETE FROM transactions WHERE id = ? AND user_id = ?",
                (tid, user["id"]),
            )
            conn.commit()
            conn.close()
            return self._send(200, {"ok": True})

        m = re.match(r"^/api/goals/(\d+)$", path)
        if m:
            gid = int(m.group(1))
            conn = get_db()
            conn.execute(
                "DELETE FROM goals WHERE id = ? AND user_id = ?",
                (gid, user["id"]),
            )
            conn.commit()
            conn.close()
            return self._send(200, {"ok": True})

        m = re.match(r"^/api/agenda/(\d+)$", path)
        if m:
            aid = int(m.group(1))
            conn = get_db()
            conn.execute(
                "DELETE FROM agenda WHERE id = ? AND user_id = ?",
                (aid, user["id"]),
            )
            conn.commit()
            conn.close()
            return self._send(200, {"ok": True})

        if path == "/api/account" or path.rstrip("/") == "/api/account":
            # Apaga permanentemente usuário + todos os dados vinculados
            uid = int(user["id"])
            errors = []
            for table, sql in [
                ("transactions", "DELETE FROM transactions WHERE user_id = ?"),
                ("goals", "DELETE FROM goals WHERE user_id = ?"),
                ("agenda", "DELETE FROM agenda WHERE user_id = ?"),
                ("sessions", "DELETE FROM sessions WHERE user_id = ?"),
                ("users", "DELETE FROM users WHERE id = ?"),
            ]:
                try:
                    conn = get_db()
                    conn.execute("PRAGMA foreign_keys = OFF")
                    conn.execute(sql, (uid,))
                    conn.commit()
                    conn.close()
                except Exception as e:
                    errors.append(f"{table}: {e}")
                    try:
                        conn.close()
                    except Exception:
                        pass
            if errors and any("users:" in e for e in errors):
                return self._json_error("Erro ao excluir conta: " + "; ".join(errors), 500)
            return self._send(200, {
                "ok": True,
                "message": "Conta e dados excluídos permanentemente",
                "warnings": errors or None,
            })

        self._json_error("Not found", 404)


def main():
    init_db()
    server = HTTPServer(("0.0.0.0", PORT), Handler)
    print(f"VaultLedger server running on http://localhost:{PORT}")
    print(f"Open http://localhost:{PORT}/index.html")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.server_close()


if __name__ == "__main__":
    main()
