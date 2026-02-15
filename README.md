# PM Insights Hub

Aplicação web para gerentes de projeto centralizarem atividades (reuniões gravadas, documentos, atas, transcrições e textos), fazer perguntas em linguagem natural e gerar insights/relatórios com IA.

## O que foi implementado
- **Pipeline de transcrição automática para áudio/vídeo** via endpoint `POST /api/transcribe` usando API compatível com OpenAI (modelo padrão `whisper-1`).
- **RAG com vetorização local**: chunking + vetores TF normalizados + similaridade cosseno em `rag_chunks`, consultável via `POST /api/rag/search`.
- **Controle de acesso por usuário** com login (`POST /api/auth/login`) e sessões por token Bearer.
- **Trilha de auditoria** (`audit_logs`) para login, upload, consulta, transcrição, RAG, insights e relatórios.
- **Dashboard de KPIs** (`GET /api/dashboard`) com métricas de acervo, texto indexado, transcrições e menções de risco.

## Rodando localmente
```bash
python app/server.py
```

Abra: `http://localhost:8000`

## Primeiro acesso
- Usuário padrão: `admin`
- Senha padrão: `admin123`
- Para alterar a senha inicial:

```bash
export PM_ADMIN_PASSWORD="nova_senha_forte"
python app/server.py
```

## Integração com IA
Você pode informar a chave por:
1. Campo da interface (somente navegador/localStorage).
2. Variável de ambiente:

```bash
export OPENAI_API_KEY="sua_chave"
export OPENAI_MODEL="gpt-4o-mini"
export OPENAI_TRANSCRIPTION_MODEL="whisper-1"
export OPENAI_BASE_URL="https://api.openai.com/v1"
```

## Endpoints principais
- `POST /api/auth/login`
- `GET /api/artifacts`
- `POST /api/upload`
- `POST /api/transcribe`
- `POST /api/rag/search`
- `POST /api/ask`
- `POST /api/insights`
- `POST /api/report`
- `GET /api/dashboard`
- `GET /api/audit?limit=50`
