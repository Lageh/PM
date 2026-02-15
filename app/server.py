import cgi
import json
import os
import tempfile
import threading
import time
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from secrets import token_hex
from urllib import error, request

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
DATA_DIR = Path(tempfile.gettempdir()) / "pm-insights-hub"
UPLOAD_DIR = DATA_DIR / "uploads"
METADATA_DIR = DATA_DIR / "metadata"
HOST = "0.0.0.0"
PORT = int(os.getenv("PORT", "8000"))
LOCK = threading.Lock()


def get_access_host() -> str:
    if HOST in {"0.0.0.0", "::"}:
        return "localhost"
    return HOST


def get_access_url() -> str:
    return f"http://{get_access_host()}:{PORT}"

def init_storage() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    METADATA_DIR.mkdir(parents=True, exist_ok=True)


def init_db() -> None:
    # Backward-compatible name used by app/main.py.
    init_storage()


def _read_metadata(path: Path) -> dict | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def list_artifacts() -> list[dict]:
    init_storage()
    artifacts: list[dict] = []
    for metadata_file in METADATA_DIR.glob("*.json"):
        artifact = _read_metadata(metadata_file)
        if artifact:
            artifacts.append(artifact)
    artifacts.sort(key=lambda item: item.get("created_at", ""), reverse=True)
    return artifacts


def save_artifact(filename: str, content_type: str, content: bytes, notes: str | None) -> dict:
    init_storage()
    safe_name = Path(filename or "uploaded_file").name
    artifact_id = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{token_hex(4)}"
    stored_name = f"{artifact_id}__{safe_name}"
    file_path = UPLOAD_DIR / stored_name

    artifact = {
        "id": artifact_id,
        "filename": safe_name,
        "stored_filename": stored_name,
        "content_type": content_type,
        "size_bytes": len(content),
        "notes": notes or "",
        "created_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
    }

    with LOCK:
        file_path.write_bytes(content)
        metadata_path = METADATA_DIR / f"{artifact_id}.json"
        metadata_path.write_text(
            json.dumps(artifact, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    return artifact


def build_context() -> str:
    artifacts = list_artifacts()
    if not artifacts:
        return "Ainda não existem artefatos carregados."
    return json.dumps(
        [
            {
                "filename": a["filename"],
                "size_bytes": a["size_bytes"],
                "notes": a["notes"],
                "created_at": a["created_at"],
            }
            for a in artifacts[:20]
        ],
        ensure_ascii=False,
        indent=2,
    )


def call_llm(system_prompt: str, user_prompt: str) -> str:
    api_key = os.getenv("OPENAI_API_KEY")
    model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    base_url = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")

    if not api_key:
        return (
            "OPENAI_API_KEY não configurada. Configure para receber respostas reais da IA.\n\n"
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

    max_attempts = 3
    for attempt in range(max_attempts):
        try:
            with request.urlopen(req, timeout=45) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            return data["choices"][0]["message"]["content"]
        except error.HTTPError as exc:
            if exc.code == 429 and attempt < max_attempts - 1:
                retry_after = exc.headers.get("Retry-After")
                wait_seconds = int(retry_after) if retry_after and retry_after.isdigit() else 2 ** attempt
                time.sleep(wait_seconds)
                continue
            if exc.code == 429:
                return (
                    "Limite de requisições/crédito atingido na API (HTTP 429). "
                    "Aguarde e tente novamente, ou revise o billing/limites do projeto OpenAI."
                )
            return (
                "Falha ao chamar a API de IA. Verifique OPENAI_API_KEY, modelo e conectividade.\n\n"
                f"Detalhe técnico: HTTP {exc.code}"
            )
        except Exception as exc:
            return (
                "Falha ao chamar a API de IA. Verifique OPENAI_API_KEY, modelo e conectividade.\n\n"
                f"Detalhe técnico: {exc}"
            )


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
            context = build_context()

            if self.path == "/api/ask":
                text = call_llm(
                    "Você é um PMO Assistant. Responda em português, objetivamente, com recomendações acionáveis.",
                    f"Contexto dos artefatos:\n{context}\n\nPergunta:\n{payload.get('question', '')}",
                )
                self._send_json({"answer": text})
                return

            if self.path == "/api/insights":
                text = call_llm(
                    "Você é especialista em gestão de projetos. Entregue riscos, oportunidades, dependências e próximos passos.",
                    f"Objetivo: {payload.get('objective', 'Identificar riscos e gargalos.')}\n\nContexto:\n{context}",
                )
                self._send_json({"insights": text})
                return

            text = call_llm(
                "Você produz relatório executivo de projetos para liderança.",
                f"Tipo de relatório: {payload.get('report_type', 'Status semanal')}\n\nContexto:\n{context}",
            )
            self._send_json({"report": text})
            return

        self.send_error(HTTPStatus.NOT_FOUND, "Not found")


if __name__ == "__main__":
    init_storage()
    server = ThreadingHTTPServer((HOST, PORT), PMHandler)
    print(f"Servidor rodando em {get_access_url()}")
    server.serve_forever()
