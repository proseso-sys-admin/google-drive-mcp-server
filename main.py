#!/usr/bin/env python3
"""
Google Drive, Apps Script & Sheets MCP Server - Cloud Run HTTP edition.

Credentials are loaded from environment variables (set via Cloud Run secrets):
  GOOGLE_APPLICATION_CREDENTIALS_JSON - JSON string of the service account key
  MCP_SECRET                          - Secret path segment for basic endpoint protection

Run locally:
  MCP_SECRET=dev GOOGLE_APPLICATION_CREDENTIALS_JSON='{...}' python main.py
"""

import json
import os
import io
from typing import Any, Optional, Dict, List

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.server import TransportSecuritySettings
from starlette.requests import Request
from starlette.responses import PlainTextResponse

from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseDownload
from googleapiclient.errors import HttpError

# -- Config --------------------------------------------------------------------

MCP_SECRET = os.environ.get("MCP_SECRET", "")
SCOPES = [
    'https://www.googleapis.com/auth/drive',           # Full Drive access
    'https://www.googleapis.com/auth/script.projects', # Read/Write script projects
    'https://www.googleapis.com/auth/script.processes', # List processes
    'https://www.googleapis.com/auth/spreadsheets'     # Read/Write Google Sheets
]

def get_creds():
    creds_json = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS_JSON")
    if not creds_json:
        print("Warning: GOOGLE_APPLICATION_CREDENTIALS_JSON not set. Using default credentials.")
        return None
    try:
        service_account_info = json.loads(creds_json)
        return service_account.Credentials.from_service_account_info(
            service_account_info, scopes=SCOPES)
    except Exception as e:
        raise ValueError(f"Failed to load credentials: {str(e)}")

def get_drive_service():
    """Authenticates and returns the Google Drive service."""
    creds = get_creds()
    if not creds:
        return build('drive', 'v3')
    return build('drive', 'v3', credentials=creds)

def get_script_service():
    """Authenticates and returns the Google Apps Script service."""
    creds = get_creds()
    if not creds:
        return build('script', 'v1')
    return build('script', 'v1', credentials=creds)

def get_sheets_service():
    """Authenticates and returns the Google Sheets service."""
    creds = get_creds()
    if not creds:
        return build('sheets', 'v4')
    return build('sheets', 'v4', credentials=creds)

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

# -- Drive Tools ---------------------------------------------------------------

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
def read_file_metadata(fileId: str) -> dict:
    """Get metadata for a specific file."""
    service = get_drive_service()
    file = service.files().get(fileId=fileId, fields="*").execute()
    return file

@mcp.tool()
def download_file(fileId: str) -> str:
    """
    Download/Export a file's content. 
    Note: Only works for binary files or Docs that can be exported to plain text.
    Returns the content as a string.
    """
    service = get_drive_service()
    
    # First check mimeType to see if it's a Google Doc
    file_meta = service.files().get(fileId=fileId).execute()
    mime_type = file_meta.get('mimeType')
    
    if mime_type == 'application/vnd.google-apps.document':
        # Export Google Docs to plain text
        request = service.files().export_media(fileId=fileId, mimeType='text/plain')
    elif mime_type == 'application/vnd.google-apps.spreadsheet':
        # Export Sheets to CSV
        request = service.files().export_media(fileId=fileId, mimeType='text/csv')
    elif mime_type == 'application/vnd.google-apps.script':
        # JSON export for scripts
        request = service.files().export_media(fileId=fileId, mimeType='application/vnd.google-apps.script+json')
    elif mime_type.startswith('application/vnd.google-apps.'):
        return f"File type {mime_type} export not yet supported in this scaffold."
    else:
        # Binary file
        request = service.files().get_media(fileId=fileId)
        
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

# -- Apps Script Tools ---------------------------------------------------------

@mcp.tool()
def script_get_content(scriptId: str) -> dict:
    """
    Get the content (code files) of a Google Apps Script project.
    Returns a list of files with their source code.
    """
    service = get_script_service()
    try:
        content = service.projects().getContent(scriptId=scriptId).execute()
        return content
    except HttpError as e:
        return {"error": str(e)}

@mcp.tool()
def script_update_content(scriptId: str, files: List[Dict[str, Any]], merge: bool = True) -> dict:
    """
    Update the content (code files) of a Google Apps Script project.
    
    Args:
        scriptId: The ID of the script project.
        files: A list of file objects. Each object must have 'name', 'type', and 'source'.
               Type can be 'SERVER_JS', 'HTML', 'JSON'.
        merge: If True (default), merges with existing files (updating matches, adding new).
               If False, REPLACES ALL CONTENT with the provided files (dangerous).
               
    Example file object:
    {
      "name": "Code",
      "type": "SERVER_JS",
      "source": "function myFunction() { console.log('Hello'); }"
    }
    """
    service = get_script_service()
    try:
        final_files = []
        
        if merge:
            # Get existing content to merge
            current_content = service.projects().getContent(scriptId=scriptId).execute()
            current_files_map = {f['name']: f for f in current_content.get('files', [])}
            
            # Update with new files
            for f in files:
                current_files_map[f['name']] = f
                
            final_files = list(current_files_map.values())
        else:
            final_files = files

        request = {"files": final_files}
        result = service.projects().updateContent(scriptId=scriptId, body=request).execute()
        return result
    except HttpError as e:
        return {"error": str(e)}

@mcp.tool()
def script_run_function(scriptId: str, function_name: str, parameters: List[Any] = [], dev_mode: bool = False) -> dict:
    """
    Execute a function in a Google Apps Script project.
    
    IMPORTANT: 
    1. The script must be deployed as an "API Executable".
    2. The Service Account must have access to the script.
    
    Args:
        scriptId: The script ID.
        function_name: The name of the function to run.
        parameters: List of parameters to pass to the function.
        dev_mode: If true, runs the HEAD version (requires editor access). If false, runs the deployed version.
    """
    service = get_script_service()
    
    request = {
        "function": function_name,
        "parameters": parameters,
        "devMode": dev_mode
    }
    
    try:
        response = service.scripts().run(scriptId=scriptId, body=request).execute()
        return response
    except HttpError as e:
        return {"error": str(e)}

@mcp.tool()
def script_create_version(scriptId: str, description: str = "") -> dict:
    """Create a new immutable version of the script."""
    service = get_script_service()
    try:
        version = service.projects().versions().create(
            scriptId=scriptId, 
            body={"description": description}
        ).execute()
        return version
    except HttpError as e:
        return {"error": str(e)}

@mcp.tool()
def script_deploy(scriptId: str, version_number: int, description: str = "") -> dict:
    """Deploy a version of the script as an API executable."""
    service = get_script_service()
    try:
        deployment = service.projects().deployments().create(
            scriptId=scriptId,
            body={
                "versionNumber": version_number,
                "description": description,
                # Note: Only manifest-based deployments are fully supported via API now, 
                # but this endpoint creates a deployment resource.
            }
        ).execute()
        return deployment
    except HttpError as e:
        return {"error": str(e)}

# -- Google Sheets Tools -------------------------------------------------------

@mcp.tool()
def sheets_read_values(spreadsheetId: str, range: str) -> dict:
    """
    Read values from a specific range in a Google Sheet.
    Returns: {"values": [[row1_col1, row1_col2], ...]}
    """
    service = get_sheets_service()
    try:
        result = service.spreadsheets().values().get(
            spreadsheetId=spreadsheetId, range=range).execute()
        return {"values": result.get('values', [])}
    except HttpError as e:
        return {"error": str(e)}

@mcp.tool()
def sheets_update_values(spreadsheetId: str, range: str, values: List[List[Any]]) -> dict:
    """
    Update values in a specific range.
    Note: The input range is treated as the starting point.
    """
    service = get_sheets_service()
    body = {
        'values': values
    }
    try:
        result = service.spreadsheets().values().update(
            spreadsheetId=spreadsheetId, range=range,
            valueInputOption="USER_ENTERED", body=body).execute()
        return result
    except HttpError as e:
        return {"error": str(e)}

@mcp.tool()
def sheets_append_values(spreadsheetId: str, range: str, values: List[List[Any]]) -> dict:
    """
    Append values to a sheet (after the last content in the range).
    Useful for adding new rows like adjustments.
    """
    service = get_sheets_service()
    body = {
        'values': values
    }
    try:
        result = service.spreadsheets().values().append(
            spreadsheetId=spreadsheetId, range=range,
            valueInputOption="USER_ENTERED", body=body).execute()
        return result
    except HttpError as e:
        return {"error": str(e)}

@mcp.tool()
def sheets_get_info(spreadsheetId: str) -> dict:
    """Get information about the spreadsheet (sheets, properties)."""
    service = get_sheets_service()
    try:
        spreadsheet = service.spreadsheets().get(spreadsheetId=spreadsheetId).execute()
        return spreadsheet
    except HttpError as e:
        return {"error": str(e)}

# -- Health check --------------------------------------------------------------

@mcp.custom_route("/healthz", methods=["GET"])
async def healthz(request: Request) -> PlainTextResponse:
    return PlainTextResponse("ok")

# -- Entry point ---------------------------------------------------------------

if __name__ == "__main__":
    mcp.run(transport="sse")
