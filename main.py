#!/usr/bin/env python3
"""
Google Drive MCP Server - Cloud Run HTTP edition.

Credentials are loaded from environment variables (set via Cloud Run secrets):
  GOOGLE_APPLICATION_CREDENTIALS_JSON - JSON string of the service account key
  MCP_SECRET                          - Secret path segment for basic endpoint protection

Run locally:
  MCP_SECRET=dev GOOGLE_APPLICATION_CREDENTIALS_JSON='{...}' python main.py
"""

import json
import os
import io
from typing import Any, Optional

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.server import TransportSecuritySettings
from starlette.requests import Request
from starlette.responses import PlainTextResponse

from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseDownload

# -- Config --------------------------------------------------------------------

MCP_SECRET = os.environ.get("MCP_SECRET", "")
SCOPES = ['https://www.googleapis.com/auth/drive.readonly']

def get_drive_service():
    """Authenticates and returns the Google Drive service."""
    creds_json = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS_JSON")
    
    if not creds_json:
        # Fallback to default credentials if no JSON provided (e.g. Workload Identity)
        # However, for Drive, explicit credentials are often needed unless using domain-wide delegation
        # This is a basic scaffold, assuming SA key or ADC.
        print("Warning: GOOGLE_APPLICATION_CREDENTIALS_JSON not set. Using default credentials.")
        return build('drive', 'v3')

    try:
        service_account_info = json.loads(creds_json)
        creds = service_account.Credentials.from_service_account_info(
            service_account_info, scopes=SCOPES)
        return build('drive', 'v3', credentials=creds)
    except Exception as e:
        raise ValueError(f"Failed to load credentials: {str(e)}")

# -- MCP Server ----------------------------------------------------------------

_port = int(os.environ.get("PORT", "8080"))
mcp = FastMCP(
    "google-drive",
    host="0.0.0.0",
    port=_port,
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=False
    ),
)

@mcp.tool()
def list_files(
    page_size: int = 10,
    query: str = "",
    order_by: str = "folder,name"
) -> dict:
    """
    List files in Google Drive.
    
    Args:
        page_size: Number of files to return (default 10).
        query: Drive API query string (e.g., "name contains 'report'" or "'root' in parents").
        order_by: Sort order (default "folder,name").
    """
    service = get_drive_service()
    
    # Basic query to filter out trashed files if no specific query provided
    q = "trashed = false"
    if query:
        q += f" and ({query})"
        
    results = service.files().list(
        pageSize=page_size, 
        fields="nextPageToken, files(id, name, mimeType, parents)",
        q=q,
        orderBy=order_by
    ).execute()
    
    return {
        "files": results.get('files', []),
        "nextPageToken": results.get('nextPageToken')
    }

@mcp.tool()
def read_file_metadata(file_id: str) -> dict:
    """Get metadata for a specific file."""
    service = get_drive_service()
    file = service.files().get(file_id=file_id, fields="*").execute()
    return file

@mcp.tool()
def download_file(file_id: str) -> str:
    """
    Download/Export a file's content. 
    Note: Only works for binary files or Docs that can be exported to plain text.
    Returns the content as a string.
    """
    service = get_drive_service()
    
    # First check mimeType to see if it's a Google Doc
    file_meta = service.files().get(file_id=file_id).execute()
    mime_type = file_meta.get('mimeType')
    
    if mime_type == 'application/vnd.google-apps.document':
        # Export Google Docs to plain text
        request = service.files().export_media(fileId=file_id, mimeType='text/plain')
    elif mime_type == 'application/vnd.google-apps.spreadsheet':
        # Export Sheets to CSV
        request = service.files().export_media(fileId=file_id, mimeType='text/csv')
    elif mime_type.startswith('application/vnd.google-apps.'):
        return f"File type {mime_type} export not yet supported in this scaffold."
    else:
        # Binary file
        request = service.files().get_media(fileId=file_id)
        
    fh = io.BytesIO()
    downloader = MediaIoBaseDownload(fh, request)
    done = False
    while done is False:
        status, done = downloader.next_chunk()
        
    fh.seek(0)
    try:
        return fh.read().decode('utf-8')
    except UnicodeDecodeError:
        return "<Binary Content - Cannot display as text>"

# -- Health check --------------------------------------------------------------

@mcp.custom_route("/healthz", methods=["GET"])
async def healthz(request: Request) -> PlainTextResponse:
    return PlainTextResponse("ok")

# -- Entry point ---------------------------------------------------------------

if __name__ == "__main__":
    mcp.run(transport="sse")
