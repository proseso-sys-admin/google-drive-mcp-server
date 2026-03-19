# Google Drive MCP Server

A Model Context Protocol (MCP) server exposing **Google Drive, Sheets, Apps Script, and Gmail** tools over HTTP/SSE, running on Google Cloud Run.

## How it works

Each team member authenticates once with their own Google account via OAuth 2.0. Claude passes their access token as a `Bearer` token on every request. The server validates it with Google and uses it directly to call the APIs — so every user sees only their own Drive, Sheets, and Gmail.

```
Team member uses Claude connector (first time)
  → Claude.ai triggers Google OAuth login
  → User signs in with their Google account
  → Claude stores their access token
  → Every subsequent tool call: Authorization: Bearer <token>
  → Server validates token → calls Google APIs as that user
```

## Tools

| Group | Count | Description |
|---|---|---|
| Drive | 3 | List files, read metadata, download content |
| Sheets | 50 | Full Sheets API — read, write, format, charts, pivot tables, filters, etc. |
| Apps Script | 4 | Get/update script content, create versions, deploy, run functions |
| Gmail | 64 | Messages, threads, drafts, labels, attachments, settings, filters, delegates |
| **Total** | **121** | |

## Setup

### 1. Google Cloud OAuth client

In [Google Cloud Console](https://console.cloud.google.com) → APIs & Services → Credentials:

1. Create an **OAuth 2.0 Client ID** (type: Web application)
2. Add the Claude.ai OAuth callback as an authorised redirect URI:
   ```
   https://claude.ai/api/oauth/callback
   ```
3. Note the **Client ID** and **Client Secret**

Enable these APIs in the project:
- Google Drive API
- Google Sheets API
- Apps Script API
- Gmail API

### 2. Configure the Claude team connector

In your Claude team settings, add a custom connector:

| Field | Value |
|---|---|
| Server URL | `https://google-drive-mcp-server-njiacix2yq-as.a.run.app/sse` |
| Authentication | OAuth 2.0 |
| Authorization URL | `https://accounts.google.com/o/oauth2/v2/auth` |
| Token URL | `https://oauth2.googleapis.com/token` |
| Client ID | *(from step 1)* |
| Client Secret | *(from step 1)* |
| Scopes | `https://www.googleapis.com/auth/drive https://www.googleapis.com/auth/spreadsheets https://www.googleapis.com/auth/script.projects https://www.googleapis.com/auth/script.processes https://mail.google.com/ email` |

### 3. Secret Manager

Only one secret is needed:

| Secret name | Value |
|---|---|
| `google-drive-creds-json` | Service account JSON key (retained for any server-level operations) |

## Deployment

Push to `main` triggers Cloud Build automatically (`cloudbuild.yaml`):

1. Builds Docker image → `gcr.io/odoo-ocr-487104/google-drive-mcp-server`
2. Deploys to Cloud Run in `asia-southeast1`
3. Injects `google-drive-creds-json` → `GOOGLE_APPLICATION_CREDENTIALS_JSON`

## Local development

Supply a valid Google OAuth access token for testing (get one via [OAuth Playground](https://developers.google.com/oauthplayground)):

```bash
cd google-drive-mcp-server
pip install -r requirements.txt
export GOOGLE_APPLICATION_CREDENTIALS_JSON='{...}'
python main.py
# Server on port 8080

# Test with curl:
curl -H "Authorization: Bearer ya29.xxx" http://localhost:8080/healthz
```

Connect your local MCP client to `http://localhost:8080/sse` with the Bearer token.

## Security notes

- **Per-user isolation**: each user's OAuth token is scoped to their own Google account — they cannot access anyone else's Drive or Gmail
- **Token validation**: every request is validated against Google's tokeninfo endpoint before any API call is made
- **No shared secret**: the OAuth flow handles authentication — there is no team-wide password to manage or rotate
- **File access**: because calls run as the authenticated user, any file the user owns or has been shared with is accessible — no need to share files with a service account email
- **Token expiry**: Google OAuth access tokens expire after ~1 hour; Claude handles token refresh automatically via the connector

## Architecture notes

- **`OAuthMiddleware`**: Starlette `BaseHTTPMiddleware` — extracts `Authorization: Bearer <token>`, validates with `https://oauth2.googleapis.com/tokeninfo`, stores the token in a `contextvars.ContextVar` for the request lifetime
- **`get_creds()`**: returns `google.oauth2.credentials.Credentials(token=access_token)` — works for Drive, Sheets, Script, and Gmail with no service account impersonation
- **SSE reconnect patch**: works around [python-sdk issue #423](https://github.com/modelcontextprotocol/python-sdk/issues/423)
