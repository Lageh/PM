import cgi
import json
import os
import sqlite3
import threading
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib import error, request

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
UPLOAD_DIR = BASE_DIR / "uploads"
DB_PATH = BASE_DIR / "project_manager.db"
HOST = "0.0.0.0"
PORT = int(os.getenv("PORT", "8000"))
LOCK = threading.Lock()

UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


def init_db() -> None:
    with sqlite3.connect(DB_PATH) as conn:
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

        existing_cols = {row[1] for row in conn.execute("PRAGMA table_info(artifacts)").fetchall()}
        if "extracted_text" not in existing_cols:
            conn.execute("ALTER TABLE artifacts ADD COLUMN extracted_text TEXT")


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
        "created_at": datetime.utcnow().isoformat(),
    }

    with LOCK:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
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

    return artifact


def build_context() -> str:
    artifacts = list_artifacts()
    if not artifacts:
        return "Ainda não existem artefatos carregados."

    context_items: list[dict] = []
    for artifact in artifacts[:20]:
        context_items.append(
            {
                "filename": artifact["filename"],
                "notes": artifact["notes"],
                "created_at": artifact["created_at"],
                "text_excerpt": artifact["extracted_text"][:2500],
            }
        )

    return json.dumps(context_items, ensure_ascii=False, indent=2)


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
        if self.path == "/api/artifacts":
            self._send_json({"artifacts": list_artifacts()})
            return
        self.send_error(HTTPStatus.NOT_FOUND, "Not found")

    def do_POST(self):
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
            self._send_json({"message": "Arquivo enviado com sucesso", "artifact": artifact})
            return

        if self.path in {"/api/ask", "/api/insights", "/api/report"}:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
            api_key = payload.get("api_key")
            context = build_context()

            if self.path == "/api/ask":
                text = call_llm(
                    "Você é um PMO Assistant. Responda em português, com objetividade e recomendações acionáveis.",
                    (
                        "Com base no contexto abaixo, responda de forma estruturada com: resumo, riscos, ações e próximos passos.\n\n"
                        f"Contexto dos artefatos:\n{context}\n\nPergunta:\n{payload.get('question', '')}"
                    ),
                    api_key_override=api_key,
                )
                self._send_json({"answer": text})
                return

            if self.path == "/api/insights":
                text = call_llm(
                    "Você é especialista em gestão de projetos. Entregue riscos, oportunidades, dependências, bloqueios e próximos passos.",
                    (
                        f"Objetivo: {payload.get('objective', 'Identificar riscos e gargalos.')}\n\n"
                        "Entregue seções: Riscos críticos, Bloqueios, Oportunidades, Plano de ação (7 dias), Perguntas em aberto.\n\n"
                        f"Contexto:\n{context}"
                    ),
                    api_key_override=api_key,
                )
                self._send_json({"insights": text})
                return

            text = call_llm(
                "Você produz relatório executivo para liderança com linguagem profissional e objetiva.",
                (
                    f"Tipo de relatório: {payload.get('report_type', 'Status semanal')}\n\n"
                    "Estruture com: Status geral, Principais entregas, Riscos/impactos, Cronograma, Decisões necessárias, Próximos passos.\n\n"
                    f"Contexto:\n{context}"
                ),
                api_key_override=api_key,
            )
            self._send_json({"report": text})
            return

        self.send_error(HTTPStatus.NOT_FOUND, "Not found")


if __name__ == "__main__":
    init_db()
    server = ThreadingHTTPServer((HOST, PORT), PMHandler)
    print(f"Servidor rodando em http://{HOST}:{PORT}")
    server.serve_forever()
