# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a **Google Drive MCP Server** — a single Python file (`main.py`) that exposes Google Drive, Sheets, and Apps Script tools over HTTP/SSE via the [Model Context Protocol (MCP)](https://modelcontextprotocol.io/). It runs as a Google Cloud Run service.

## Running Locally

```bash
pip install -r requirements.txt
export GOOGLE_APPLICATION_CREDENTIALS_JSON='{...service account JSON...}'
export MCP_SECRET=dev
python main.py
# Listens on $PORT (default 8080)
```

## Deployment

Push to `main` branch triggers Cloud Build automatically (`cloudbuild.yaml`):
- Builds Docker image → pushes to `gcr.io/$PROJECT_ID/google-drive-mcp-server:$COMMIT_SHA`
- Deploys to Cloud Run in `asia-southeast1`
- Secrets injected from Google Secret Manager: `google-drive-mcp-secret` → `MCP_SECRET`, `google-drive-creds-json` → `GOOGLE_APPLICATION_CREDENTIALS_JSON`

## Quality Tools

### Smoke test
```bash
./smoke-test.sh http://localhost:8080 $MCP_SECRET
```

### Lint and format (ruff)
```bash
ruff check .
ruff format .
```

### PR checks
`cloudbuild-pr.yaml` runs ruff + syntax check on every pull request. Merges are blocked until checks pass.

### Dependency pinning
Production builds use `requirements.lock` (pinned). Update after changing dependencies:
```bash
pip install -r requirements.txt
pip freeze > requirements.lock
```

## Key Architectural Notes

- **SSE reconnect patch** (`main.py:37-52`): Works around [python-sdk issue #423](https://github.com/modelcontextprotocol/python-sdk/issues/423) where reconnecting SSE clients send tool calls before the `initialize` handshake completes. The patch auto-promotes any new session to `Initialized` state on first request.
- **Endpoint protection**: All MCP routes are prefixed with `/{MCP_SECRET}/` so the path itself acts as a shared secret.
- Service account: `google-drive-mcp-sa@odoo-ocr-487104.iam.gserviceaccount.com`
- GCP project: `odoo-ocr-487104`
