# Google Drive MCP Server

A Model Context Protocol (MCP) server for Google Drive, running on Cloud Run.

## Features

- List files
- Read file metadata
- Download file content (supports Google Docs export to text/csv)

## Configuration

The server requires the following environment variables (configured via Cloud Run secrets):

- `GOOGLE_APPLICATION_CREDENTIALS_JSON`: The content of your Service Account JSON key (for `google-drive-mcp-sa@odoo-ocr-487104.iam.gserviceaccount.com`).
- `MCP_SECRET`: A secret string to protect the endpoint (optional but recommended).

## Deployment

This project is set up for automatic deployment via Google Cloud Build.

1.  **Connect Repository**: Connect this GitHub repository to Cloud Build (2nd Gen).
2.  **Create Trigger**: Create a trigger to deploy on push to the `main` branch.
3.  **Secrets**: Ensure the secrets `google-drive-mcp-secret` and `google-drive-creds-json` exist in Google Secret Manager in the `asia-southeast1` region (or your target region).

## Local Development

```bash
# Install dependencies
pip install -r requirements.txt

# Run locally
export GOOGLE_APPLICATION_CREDENTIALS_JSON='{...}'
export MCP_SECRET=dev
python main.py
```
