# PM Insights Hub

Aplicação web para gerentes de projeto centralizarem atividades (reuniões gravadas, documentos, atas, transcrições e textos), fazer perguntas em linguagem natural e gerar insights/relatórios com IA.

## Funcionalidades
- Upload de artefatos de projeto.
- Catálogo local dos arquivos com metadados em arquivos JSON no diretório temporário do sistema.
- Perguntas em linguagem natural.
- Geração automática de insights.
- Geração de relatório executivo.
- Integração com API de IA compatível com OpenAI.

## Rodando localmente
```bash
python app/server.py
```

Abra: `http://localhost:8000`

Dados locais são armazenados em: `<temp>/pm-insights-hub` (uploads + metadata).

## Integração com IA
Configure variáveis de ambiente:

```bash
export OPENAI_API_KEY="sua_chave"
export OPENAI_MODEL="gpt-4o-mini"
export OPENAI_BASE_URL="https://api.openai.com/v1"
```

Sem `OPENAI_API_KEY`, a aplicação continua funcional com retorno de fallback local.

## Próximas evoluções recomendadas
- Pipeline de transcrição automática para áudio/vídeo.
- RAG com vetorização para análise de conteúdo dos documentos.
- Controle de acesso por usuário e trilha de auditoria.
- Dashboard com KPIs de risco, prazo e capacidade.
