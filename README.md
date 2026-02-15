# PM Insights Hub

Aplicação web para gerentes de projeto centralizarem atividades (reuniões gravadas, documentos, atas, transcrições e textos), fazer perguntas em linguagem natural e gerar insights/relatórios com IA.

## Funcionalidades
- Upload de artefatos de projeto.
- Catálogo local dos arquivos com metadados (SQLite).
- Extração de texto para arquivos textuais (`.txt`, `.md`, `.csv`, `.json`, `text/*`) para enriquecer o contexto da IA.
- Perguntas em linguagem natural.
- Geração automática de insights.
- Geração de relatório executivo.
- Integração com API de IA compatível com OpenAI.

## Rodando localmente
```bash
python app/server.py
```

Abra: `http://localhost:8000`

## Integração com IA
Você pode informar a chave de duas maneiras:

1. **Pela interface web** (campo "OPENAI_API_KEY"), sem persistir no servidor.
2. **Por variável de ambiente**:

```bash
export OPENAI_API_KEY="sua_chave"
export OPENAI_MODEL="gpt-4o-mini"
export OPENAI_BASE_URL="https://api.openai.com/v1"
```

> Segurança: não versione chaves de API no código-fonte.

Sem `OPENAI_API_KEY`, a aplicação continua funcional com retorno de fallback local.

## Próximas evoluções recomendadas
- Pipeline de transcrição automática para áudio/vídeo.
- RAG com vetorização para análise semântica dos documentos.
- Controle de acesso por usuário e trilha de auditoria.
- Dashboard com KPIs de risco, prazo e capacidade.
