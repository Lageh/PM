import cgi
import hashlib
import json
import math
import os
import secrets
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib import error, parse, request

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
UPLOAD_DIR = BASE_DIR / "uploads"
DB_PATH = BASE_DIR / "project_manager.db"
HOST = "0.0.0.0"
PORT = int(os.getenv("PORT", "8000"))
LOCK = threading.Lock()

UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


def utc_now() -> str:
    return datetime.utcnow().isoformat()


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def tokenize(text: str) -> list[str]:
    normalized = "".join(ch.lower() if ch.isalnum() else " " for ch in text)
    return [tok for tok in normalized.split() if len(tok) > 2]


def vectorize(text: str) -> dict[str, float]:
    tokens = tokenize(text)
    if not tokens:
        return {}
    freq: dict[str, float] = {}
    for token in tokens:
        freq[token] = freq.get(token, 0.0) + 1.0
    norm = math.sqrt(sum(v * v for v in freq.values())) or 1.0
    return {k: v / norm for k, v in freq.items()}


def cosine_similarity(vec_a: dict[str, float], vec_b: dict[str, float]) -> float:
    if not vec_a or not vec_b:
        return 0.0
    shared = set(vec_a.keys()) & set(vec_b.keys())
    return sum(vec_a[token] * vec_b[token] for token in shared)


def create_multipart_body(fields: dict[str, str], files: dict[str, tuple[str, bytes, str]]) -> tuple[bytes, str]:
    boundary = f"----PMBoundary{uuid.uuid4().hex}"
    lines: list[bytes] = []

    for key, value in fields.items():
        lines.extend(
            [
                f"--{boundary}".encode("utf-8"),
                f'Content-Disposition: form-data; name="{key}"'.encode("utf-8"),
                b"",
                str(value).encode("utf-8"),
            ]
        )

    for key, (filename, content, content_type) in files.items():
        lines.extend(
            [
                f"--{boundary}".encode("utf-8"),
                f'Content-Disposition: form-data; name="{key}"; filename="{filename}"'.encode("utf-8"),
                f"Content-Type: {content_type}".encode("utf-8"),
                b"",
                content,
            ]
        )

    lines.append(f"--{boundary}--".encode("utf-8"))
    body = b"\r\n".join(lines) + b"\r\n"
    return body, boundary


def init_db() -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS artifacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                content_type TEXT,
                size_bytes INTEGER NOT NULL,
                notes TEXT,
                extracted_text TEXT,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS rag_chunks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                artifact_id INTEGER NOT NULL,
                chunk_index INTEGER NOT NULL,
                chunk_text TEXT NOT NULL,
                vector_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(artifact_id) REFERENCES artifacts(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS transcription_jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                artifact_id INTEGER NOT NULL,
                status TEXT NOT NULL,
                transcript TEXT,
                error_message TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(artifact_id) REFERENCES artifacts(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT NOT NULL,
                method TEXT,
                path TEXT,
                details TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
            """
        )

        existing_cols = {row[1] for row in conn.execute("PRAGMA table_info(artifacts)").fetchall()}
        if "extracted_text" not in existing_cols:
            conn.execute("ALTER TABLE artifacts ADD COLUMN extracted_text TEXT")

        default_user = conn.execute("SELECT id FROM users WHERE username = ?", ("admin",)).fetchone()
        if not default_user:
            default_password = os.getenv("PM_ADMIN_PASSWORD", "admin123")
            conn.execute(
                "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
                ("admin", hash_password(default_password), "admin", utc_now()),
            )


def log_audit(action: str, method: str | None = None, path: str | None = None, details: str | None = None, user_id: int | None = None) -> None:
    with LOCK:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                "INSERT INTO audit_logs (user_id, action, method, path, details, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (user_id, action, method, path, details, utc_now()),
            )


def create_session(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    expires_at = (datetime.utcnow() + timedelta(hours=24)).isoformat()
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO sessions (token, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)",
            (token, user_id, expires_at, utc_now()),
        )
    return token


def authenticate_token(token: str | None) -> dict | None:
    if not token:
        return None
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            """
            SELECT users.id, users.username, users.role, sessions.expires_at
            FROM sessions
            JOIN users ON users.id = sessions.user_id
            WHERE sessions.token = ?
            """,
            (token,),
        ).fetchone()
    if not row:
        return None

    expires = datetime.fromisoformat(row[3])
    if expires < datetime.utcnow():
        return None

    return {"id": row[0], "username": row[1], "role": row[2]}


def list_artifacts() -> list[dict]:
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute(
            "SELECT id, filename, content_type, size_bytes, notes, extracted_text, created_at FROM artifacts ORDER BY id DESC"
        ).fetchall()
    return [
        {
            "id": row[0],
            "filename": row[1],
            "content_type": row[2],
            "size_bytes": row[3],
            "notes": row[4],
            "extracted_text": row[5] or "",
            "created_at": row[6],
        }
        for row in rows
    ]


def extract_text(filename: str, content_type: str | None, content: bytes) -> str:
    text_like_extensions = {".txt", ".md", ".csv", ".log", ".json"}
    suffix = Path(filename).suffix.lower()
    looks_like_text = suffix in text_like_extensions or (content_type or "").startswith("text/")

    if not looks_like_text:
        return ""

    try:
        return content.decode("utf-8")
    except UnicodeDecodeError:
        try:
            return content.decode("latin-1")
        except UnicodeDecodeError:
            return ""


def chunk_text(text: str, chunk_size: int = 600) -> list[str]:
    if not text.strip():
        return []
    words = text.split()
    chunks: list[str] = []
    current: list[str] = []
    current_len = 0

    for word in words:
        current.append(word)
        current_len += len(word) + 1
        if current_len >= chunk_size:
            chunks.append(" ".join(current))
            current = []
            current_len = 0

    if current:
        chunks.append(" ".join(current))

    return chunks


def index_rag_chunks(artifact_id: int, text: str) -> None:
    chunks = chunk_text(text)
    with LOCK:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("DELETE FROM rag_chunks WHERE artifact_id = ?", (artifact_id,))
            for idx, chunk in enumerate(chunks):
                vec = vectorize(chunk)
                conn.execute(
                    "INSERT INTO rag_chunks (artifact_id, chunk_index, chunk_text, vector_json, created_at) VALUES (?, ?, ?, ?, ?)",
                    (artifact_id, idx, chunk, json.dumps(vec), utc_now()),
                )


def save_artifact(filename: str, content_type: str | None, content: bytes, notes: str | None) -> dict:
    safe_name = Path(filename).name
    file_path = UPLOAD_DIR / safe_name
    with open(file_path, "wb") as f:
        f.write(content)

    extracted_text = extract_text(safe_name, content_type, content)
    artifact = {
        "filename": safe_name,
        "content_type": content_type,
        "size_bytes": len(content),
        "notes": notes,
        "extracted_text": extracted_text,
        "created_at": utc_now(),
    }

    with LOCK:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.execute(
                "INSERT INTO artifacts (filename, content_type, size_bytes, notes, extracted_text, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    artifact["filename"],
                    artifact["content_type"],
                    artifact["size_bytes"],
                    artifact["notes"],
                    artifact["extracted_text"],
                    artifact["created_at"],
                ),
            )
            artifact_id = cursor.lastrowid

    if extracted_text.strip():
        index_rag_chunks(artifact_id, extracted_text)

    artifact["id"] = artifact_id
    return artifact


def transcribe_media(artifact_id: int, filename: str, content: bytes, content_type: str | None, api_key: str | None) -> dict:
    api_key_final = (api_key or "").strip() or os.getenv("OPENAI_API_KEY")
    if not api_key_final:
        return {"status": "error", "message": "OPENAI_API_KEY ausente para transcrição."}

    model = os.getenv("OPENAI_TRANSCRIPTION_MODEL", "whisper-1")
    base_url = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
    body, boundary = create_multipart_body(
        fields={"model": model, "language": "pt"},
        files={"file": (filename, content, content_type or "application/octet-stream")},
    )

    req = request.Request(
        url=f"{base_url}/audio/transcriptions",
        data=body,
        headers={
            "Authorization": f"Bearer {api_key_final}",
            "Content-Type": f"multipart/form-data; boundary={boundary}",
        },
        method="POST",
    )

    try:
        with request.urlopen(req, timeout=120) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        transcript = data.get("text", "")
        if not transcript.strip():
            return {"status": "error", "message": "Transcrição vazia retornada pela IA."}

        with LOCK:
            with sqlite3.connect(DB_PATH) as conn:
                conn.execute(
                    "UPDATE artifacts SET extracted_text = COALESCE(extracted_text, '') || ? WHERE id = ?",
                    (f"\n\n[Transcrição automática]\n{transcript}", artifact_id),
                )

        index_rag_chunks(artifact_id, transcript)
        return {"status": "completed", "transcript": transcript}
    except error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="ignore")
        return {"status": "error", "message": f"HTTP {exc.code}: {detail[:800]}"}
    except Exception as exc:  # noqa: BLE001
        return {"status": "error", "message": str(exc)}


def create_transcription_job(artifact_id: int, api_key: str | None) -> dict:
    with sqlite3.connect(DB_PATH) as conn:
        artifact = conn.execute(
            "SELECT filename, content_type FROM artifacts WHERE id = ?",
            (artifact_id,),
        ).fetchone()

    if not artifact:
        return {"status": "error", "message": "Artefato não encontrado."}

    file_path = UPLOAD_DIR / artifact[0]
    if not file_path.exists():
        return {"status": "error", "message": "Arquivo físico não encontrado."}

    created = utc_now()
    with LOCK:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.execute(
                "INSERT INTO transcription_jobs (artifact_id, status, transcript, error_message, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
                (artifact_id, "processing", None, None, created, created),
            )
            job_id = cursor.lastrowid

    result = transcribe_media(artifact_id, artifact[0], file_path.read_bytes(), artifact[1], api_key)

    with LOCK:
        with sqlite3.connect(DB_PATH) as conn:
            if result["status"] == "completed":
                conn.execute(
                    "UPDATE transcription_jobs SET status = ?, transcript = ?, updated_at = ? WHERE id = ?",
                    ("completed", result["transcript"], utc_now(), job_id),
                )
            else:
                conn.execute(
                    "UPDATE transcription_jobs SET status = ?, error_message = ?, updated_at = ? WHERE id = ?",
                    ("error", result["message"], utc_now(), job_id),
                )

    return {"job_id": job_id, **result}


def retrieve_rag_context(query: str, top_k: int = 5) -> list[dict]:
    query_vec = vectorize(query)
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute(
            "SELECT rag_chunks.id, artifacts.filename, rag_chunks.chunk_text, rag_chunks.vector_json FROM rag_chunks JOIN artifacts ON artifacts.id = rag_chunks.artifact_id"
        ).fetchall()

    scored: list[tuple[float, dict]] = []
    for row in rows:
        chunk_vec = json.loads(row[3] or "{}")
        score = cosine_similarity(query_vec, chunk_vec)
        if score > 0:
            scored.append(
                (
                    score,
                    {
                        "chunk_id": row[0],
                        "filename": row[1],
                        "chunk_text": row[2],
                    },
                )
            )

    scored.sort(key=lambda item: item[0], reverse=True)
    return [{**entry, "score": round(score, 4)} for score, entry in scored[:top_k]]


def build_context(question_or_objective: str = "") -> str:
    artifacts = list_artifacts()
    rag_hits = retrieve_rag_context(question_or_objective) if question_or_objective.strip() else []

    context = {
        "artifacts": [
            {
                "filename": a["filename"],
                "notes": a["notes"],
                "created_at": a["created_at"],
                "text_excerpt": a["extracted_text"][:1200],
            }
            for a in artifacts[:20]
        ],
        "rag_hits": rag_hits,
    }

    if not context["artifacts"]:
        return "Ainda não existem artefatos carregados."

    return json.dumps(context, ensure_ascii=False, indent=2)


def compute_dashboard_metrics() -> dict:
    with sqlite3.connect(DB_PATH) as conn:
        total_artifacts = conn.execute("SELECT COUNT(*) FROM artifacts").fetchone()[0]
        text_indexed = conn.execute("SELECT COUNT(*) FROM artifacts WHERE COALESCE(extracted_text, '') <> ''").fetchone()[0]
        transcriptions_done = conn.execute("SELECT COUNT(*) FROM transcription_jobs WHERE status = 'completed'").fetchone()[0]
        artifacts_7d = conn.execute(
            "SELECT COUNT(*) FROM artifacts WHERE datetime(created_at) >= datetime('now', '-7 day')"
        ).fetchone()[0]
        all_text_rows = conn.execute("SELECT COALESCE(extracted_text, ''), COALESCE(notes, '') FROM artifacts").fetchall()

    risk_terms = ["risco", "atraso", "bloqueio", "impedimento", "escalation", "dependência"]
    risk_mentions = 0
    for text, notes in all_text_rows:
        corpus = f"{text} {notes}".lower()
        risk_mentions += sum(corpus.count(term) for term in risk_terms)

    return {
        "total_artifacts": total_artifacts,
        "text_indexed_artifacts": text_indexed,
        "transcriptions_completed": transcriptions_done,
        "artifacts_last_7_days": artifacts_7d,
        "risk_mentions": risk_mentions,
    }


def list_audit_logs(limit: int = 100) -> list[dict]:
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute(
            """
            SELECT audit_logs.id, users.username, audit_logs.action, audit_logs.method, audit_logs.path, audit_logs.details, audit_logs.created_at
            FROM audit_logs
            LEFT JOIN users ON users.id = audit_logs.user_id
            ORDER BY audit_logs.id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    return [
        {
            "id": row[0],
            "username": row[1],
            "action": row[2],
            "method": row[3],
            "path": row[4],
            "details": row[5],
            "created_at": row[6],
        }
        for row in rows
    ]


def call_llm(system_prompt: str, user_prompt: str, api_key_override: str | None = None) -> str:
    api_key = (api_key_override or "").strip() or os.getenv("OPENAI_API_KEY")
    model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    base_url = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")

    if not api_key:
        return (
            "OPENAI_API_KEY não configurada. Informe a chave no campo da interface ou configure no ambiente.\n\n"
            f"Resumo local: {user_prompt[:500]}"
        )

    payload = json.dumps(
        {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.2,
        }
    ).encode("utf-8")

    req = request.Request(
        url=f"{base_url}/chat/completions",
        data=payload,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return data["choices"][0]["message"]["content"]
    except error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="ignore")
        return f"Erro no serviço de IA (HTTP {exc.code}): {detail[:800]}"
    except Exception as exc:  # noqa: BLE001
        return f"Falha ao chamar serviço de IA: {str(exc)}"


class PMHandler(BaseHTTPRequestHandler):
    def _send_json(self, payload: dict, code: int = 200) -> None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_file(self, path: Path, content_type: str) -> None:
        if not path.exists():
            self.send_error(HTTPStatus.NOT_FOUND, "Not found")
            return
        data = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _read_json_body(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8") if length > 0 else "{}"
        return json.loads(raw or "{}")

    def _get_auth_user(self) -> dict | None:
        auth_header = self.headers.get("Authorization", "")
        token = ""
        if auth_header.startswith("Bearer "):
            token = auth_header.replace("Bearer ", "", 1).strip()
        if not token:
            token = self.headers.get("X-PM-TOKEN", "").strip()
        return authenticate_token(token)

    def _require_auth(self) -> dict | None:
        user = self._get_auth_user()
        if not user:
            self._send_json({"detail": "Não autenticado"}, code=401)
            return None
        return user

    def do_GET(self):
        if self.path == "/":
            self._send_file(BASE_DIR / "templates" / "index.html", "text/html")
            return
        if self.path == "/static/app.js":
            self._send_file(STATIC_DIR / "app.js", "application/javascript")
            return
        if self.path == "/static/styles.css":
            self._send_file(STATIC_DIR / "styles.css", "text/css")
            return

        user = self._require_auth()
        if not user:
            return

        if self.path == "/api/artifacts":
            log_audit("list_artifacts", "GET", self.path, user_id=user["id"])
            self._send_json({"artifacts": list_artifacts()})
            return

        if self.path == "/api/dashboard":
            log_audit("dashboard", "GET", self.path, user_id=user["id"])
            self._send_json({"kpis": compute_dashboard_metrics()})
            return

        if self.path.startswith("/api/audit"):
            query = parse.urlparse(self.path).query
            params = parse.parse_qs(query)
            limit = int(params.get("limit", ["100"])[0])
            log_audit("view_audit", "GET", self.path, user_id=user["id"])
            self._send_json({"logs": list_audit_logs(limit=min(limit, 300))})
            return

        self.send_error(HTTPStatus.NOT_FOUND, "Not found")

    def do_POST(self):
        if self.path == "/api/auth/login":
            payload = self._read_json_body()
            username = str(payload.get("username", "")).strip()
            password = str(payload.get("password", ""))

            with sqlite3.connect(DB_PATH) as conn:
                row = conn.execute(
                    "SELECT id, username, role, password_hash FROM users WHERE username = ?",
                    (username,),
                ).fetchone()

            if not row or row[3] != hash_password(password):
                log_audit("login_failed", "POST", self.path, details=f"username={username}")
                self._send_json({"detail": "Credenciais inválidas"}, code=401)
                return

            token = create_session(row[0])
            log_audit("login_success", "POST", self.path, user_id=row[0])
            self._send_json({"token": token, "user": {"id": row[0], "username": row[1], "role": row[2]}})
            return

        user = self._require_auth()
        if not user:
            return

        if self.path == "/api/upload":
            form = cgi.FieldStorage(
                fp=self.rfile,
                headers=self.headers,
                environ={
                    "REQUEST_METHOD": "POST",
                    "CONTENT_TYPE": self.headers.get("Content-Type"),
                },
            )
            if "file" not in form:
                self._send_json({"detail": "Arquivo inválido"}, code=400)
                return

            file_item = form["file"]
            notes = form["notes"].value if "notes" in form else None
            artifact = save_artifact(
                filename=file_item.filename,
                content_type=file_item.type,
                content=file_item.file.read(),
                notes=notes,
            )

            log_audit("upload_artifact", "POST", self.path, details=f"artifact_id={artifact['id']}", user_id=user["id"])
            self._send_json({"message": "Arquivo enviado com sucesso", "artifact": artifact})
            return

        if self.path == "/api/transcribe":
            payload = self._read_json_body()
            artifact_id = int(payload.get("artifact_id", 0))
            api_key = payload.get("api_key")
            result = create_transcription_job(artifact_id, api_key)
            log_audit("transcribe", "POST", self.path, details=f"artifact_id={artifact_id};status={result.get('status')}", user_id=user["id"])
            self._send_json(result, code=200 if result.get("status") != "error" else 400)
            return

        if self.path == "/api/rag/search":
            payload = self._read_json_body()
            query = str(payload.get("query", ""))
            results = retrieve_rag_context(query)
            log_audit("rag_search", "POST", self.path, details=f"query={query[:120]}", user_id=user["id"])
            self._send_json({"results": results})
            return

        if self.path in {"/api/ask", "/api/insights", "/api/report"}:
            payload = self._read_json_body()
            api_key = payload.get("api_key")

            if self.path == "/api/ask":
                question = str(payload.get("question", ""))
                context = build_context(question)
                text = call_llm(
                    "Você é um PMO Assistant. Responda em português, com objetividade e recomendações acionáveis.",
                    (
                        "Com base no contexto abaixo, responda de forma estruturada com: resumo, riscos, ações e próximos passos.\n\n"
                        f"Contexto com RAG:\n{context}\n\nPergunta:\n{question}"
                    ),
                    api_key_override=api_key,
                )
                log_audit("ask", "POST", self.path, details=question[:200], user_id=user["id"])
                self._send_json({"answer": text})
                return

            if self.path == "/api/insights":
                objective = str(payload.get("objective", "Identificar riscos e gargalos."))
                context = build_context(objective)
                text = call_llm(
                    "Você é especialista em gestão de projetos. Entregue riscos, oportunidades, dependências, bloqueios e próximos passos.",
                    (
                        f"Objetivo: {objective}\n\n"
                        "Entregue seções: Riscos críticos, Bloqueios, Oportunidades, Plano de ação (7 dias), Perguntas em aberto.\n\n"
                        f"Contexto com RAG:\n{context}"
                    ),
                    api_key_override=api_key,
                )
                log_audit("insights", "POST", self.path, details=objective[:200], user_id=user["id"])
                self._send_json({"insights": text})
                return

            report_type = str(payload.get("report_type", "Status semanal"))
            context = build_context(report_type)
            text = call_llm(
                "Você produz relatório executivo para liderança com linguagem profissional e objetiva.",
                (
                    f"Tipo de relatório: {report_type}\n\n"
                    "Estruture com: Status geral, Principais entregas, Riscos/impactos, Cronograma, Decisões necessárias, Próximos passos.\n\n"
                    f"Contexto com RAG:\n{context}"
                ),
                api_key_override=api_key,
            )
            log_audit("report", "POST", self.path, details=report_type[:200], user_id=user["id"])
            self._send_json({"report": text})
            return

        self.send_error(HTTPStatus.NOT_FOUND, "Not found")


if __name__ == "__main__":
    init_db()
    server = ThreadingHTTPServer((HOST, PORT), PMHandler)
    print(f"Servidor rodando em http://{HOST}:{PORT}")
    server.serve_forever()
