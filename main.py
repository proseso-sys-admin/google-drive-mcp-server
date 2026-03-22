#!/usr/bin/env python3
"""
Google Drive, Apps Script, Sheets & Gmail MCP Server - Cloud Run HTTP edition.

Authentication uses Google OAuth 2.0. The Claude team connector is configured
with Google as the OAuth provider; each team member authenticates once with
their own Google account, and Claude passes their access token as a Bearer
token on every request. The server validates the token with Google and uses
it directly to call Drive, Sheets, Script, and Gmail — no service account or
domain-wide delegation required.

Required environment variable (set via Cloud Run secret):
  GOOGLE_APPLICATION_CREDENTIALS_JSON - still used for any service-account-
                                        level operations (optional if all
                                        access is via user OAuth tokens)

OAuth scopes to request in the Google Cloud OAuth client:
  https://www.googleapis.com/auth/drive
  https://www.googleapis.com/auth/spreadsheets
  https://www.googleapis.com/auth/script.projects
  https://www.googleapis.com/auth/script.processes
  https://mail.google.com/
  email (to identify the user in logs)

Run locally (supply a valid Google OAuth access token for testing):
  GOOGLE_OAUTH_TOKEN='ya29.xxx' python main.py
  # Connect MCP client to: http://localhost:8080/sse
"""

import json
import os
import io
import base64
import hashlib
import hmac
import time
import asyncio
import logging
import contextvars
import urllib.request
import urllib.parse
import urllib.error
import email.mime.text
import email.mime.multipart
import email.mime.base
from typing import Any, Optional, Dict, List

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.server import TransportSecuritySettings
from mcp.server.session import ServerSession, InitializationState
from starlette.requests import Request
from starlette.responses import PlainTextResponse, JSONResponse, RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware

from google.oauth2.credentials import Credentials as UserCredentials
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseDownload
from googleapiclient.errors import HttpError

# -- Patch: auto-initialize SSE sessions on first request ----------------------
# Works around https://github.com/modelcontextprotocol/python-sdk/issues/423
# When SSE drops and the client reconnects, the server-side session is new and
# hasn't completed the initialize handshake yet. The client sends tool calls
# immediately, which fail with "Received request before initialization was
# complete".  This patch auto-promotes the session to Initialized.

_original_received_request = ServerSession._received_request

async def _patched_received_request(self, responder):
    if self._initialization_state != InitializationState.Initialized:
        import mcp.types as _types
        if not isinstance(responder.request.root, (_types.InitializeRequest, _types.PingRequest)):
            logging.warning("Auto-initializing MCP session on first request (SSE reconnect workaround)")
            self._initialization_state = InitializationState.Initialized
    return await _original_received_request(self, responder)

ServerSession._received_request = _patched_received_request

# -- Config --------------------------------------------------------------------

# Per-request Google OAuth access token — set by OAuthMiddleware, read by get_creds().
# ContextVar ensures concurrent requests from different users never bleed into each other.
_current_access_token: contextvars.ContextVar[str] = contextvars.ContextVar(
    'current_access_token', default=''
)

def get_creds() -> UserCredentials:
    """Return Google OAuth credentials for the current authenticated user."""
    token = _current_access_token.get()
    if not token:
        raise ValueError(
            "No authenticated user. Connect the Claude connector via Google OAuth."
        )
    return UserCredentials(token=token)

def get_drive_service():
    """Authenticates and returns the Google Drive service."""
    return build('drive', 'v3', credentials=get_creds())

def get_script_service():
    """Authenticates and returns the Google Apps Script service."""
    return build('script', 'v1', credentials=get_creds())

def get_sheets_service():
    """Authenticates and returns the Google Sheets service."""
    return build('sheets', 'v4', credentials=get_creds())

def get_gmail_service():
    """Authenticates and returns the Gmail API service."""
    return build('gmail', 'v1', credentials=get_creds())

# -- Auth middleware -----------------------------------------------------------

def _validate_google_token(token: str) -> str:
    """
    Validate a Google OAuth access token via the tokeninfo endpoint.
    Returns the user's email on success. Raises ValueError on failure.
    Runs synchronously — call via asyncio.to_thread in async contexts.
    """
    url = 'https://oauth2.googleapis.com/tokeninfo?' + urllib.parse.urlencode(
        {'access_token': token}
    )
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError:
        raise ValueError("Invalid or expired token")
    except Exception as e:
        raise ValueError(f"Token validation failed: {e}")

    email = data.get('email', '')
    if not email:
        raise ValueError(
            "Token is missing the 'email' scope — ensure the OAuth client "
            "requests the 'email' scope"
        )
    return email


# Paths that don't require a Bearer token (OAuth AS + discovery + health check)
_OAUTH_EXEMPT_PATHS = {'/healthz', '/authorize', '/oauth/callback', '/token', '/register'}


class OAuthMiddleware(BaseHTTPMiddleware):
    """
    Validate the Google OAuth Bearer token on every request, then store it
    in _current_access_token for the duration of the request.

    OAuth AS endpoints, /.well-known/ discovery, and /healthz bypass auth.
    Returns 401 JSON for missing, invalid, or expired tokens.
    """
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if path in _OAUTH_EXEMPT_PATHS or '/.well-known/' in path or path.endswith('/.well-known'):
            return await call_next(request)

        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            origin = _server_origin(request)
            return JSONResponse(
                {'error': 'Unauthorized: missing Bearer token'},
                status_code=401,
                headers={
                    'WWW-Authenticate': (
                        f'Bearer realm="Google Drive MCP",'
                        f' resource_metadata="{origin}/.well-known/oauth-protected-resource"'
                    )
                },
            )

        token = auth_header[len('Bearer '):]
        try:
            email = await asyncio.to_thread(_validate_google_token, token)
        except ValueError as e:
            return JSONResponse({'error': f'Unauthorized: {e}'}, status_code=401)

        logging.info(f"Authenticated request from {email}")
        ctx = _current_access_token.set(token)
        try:
            return await call_next(request)
        finally:
            _current_access_token.reset(ctx)


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
gmail_mcp = FastMCP(
    "gmail",
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

# -- Sheets: Spreadsheet Lifecycle ---------------------------------------------

@mcp.tool()
def sheets_create(title: str, sheet_names: List[str] = []) -> dict:
    """
    Create a new Google Spreadsheet.

    Args:
        title: The title of the new spreadsheet.
        sheet_names: Optional list of tab names to create (default creates one "Sheet1").
    """
    service = get_sheets_service()
    body: Dict[str, Any] = {"properties": {"title": title}}
    if sheet_names:
        body["sheets"] = [
            {"properties": {"title": name}} for name in sheet_names
        ]
    try:
        spreadsheet = service.spreadsheets().create(body=body).execute()
        return {
            "spreadsheetId": spreadsheet["spreadsheetId"],
            "spreadsheetUrl": spreadsheet["spreadsheetUrl"],
            "title": spreadsheet["properties"]["title"],
            "sheets": [
                {"sheetId": s["properties"]["sheetId"], "title": s["properties"]["title"]}
                for s in spreadsheet.get("sheets", [])
            ],
        }
    except HttpError as e:
        return {"error": str(e)}

@mcp.tool()
def sheets_copy_to(spreadsheetId: str, sheetId: int, destination_spreadsheet_id: str) -> dict:
    """
    Copy a sheet/tab from one spreadsheet to another.

    Args:
        spreadsheetId: Source spreadsheet ID.
        sheetId: The sheet (tab) ID to copy.
        destination_spreadsheet_id: The target spreadsheet ID.
    """
    service = get_sheets_service()
    try:
        result = service.spreadsheets().sheets().copyTo(
            spreadsheetId=spreadsheetId,
            sheetId=sheetId,
            body={"destinationSpreadsheetId": destination_spreadsheet_id},
        ).execute()
        return result
    except HttpError as e:
        return {"error": str(e)}

# -- Sheets: Tab / Sheet Management --------------------------------------------

@mcp.tool()
def sheets_add_sheet(spreadsheetId: str, title: str, rows: int = 1000, cols: int = 26) -> dict:
    """
    Add a new tab (sheet) to a spreadsheet.

    Args:
        spreadsheetId: The spreadsheet ID.
        title: Name of the new tab.
        rows: Number of rows (default 1000).
        cols: Number of columns (default 26).
    """
    service = get_sheets_service()
    try:
        result = service.spreadsheets().batchUpdate(
            spreadsheetId=spreadsheetId,
            body={"requests": [{"addSheet": {"properties": {
                "title": title,
                "gridProperties": {"rowCount": rows, "columnCount": cols},
            }}}]},
        ).execute()
        return result["replies"][0]["addSheet"]["properties"]
    except HttpError as e:
        return {"error": str(e)}

@mcp.tool()
def sheets_delete_sheet(spreadsheetId: str, sheetId: int) -> dict:
    """Delete a tab by its sheetId."""
    service = get_sheets_service()
    try:
        return service.spreadsheets().batchUpdate(
            spreadsheetId=spreadsheetId,
            body={"requests": [{"deleteSheet": {"sheetId": sheetId}}]},
        ).execute()
    except HttpError as e:
        return {"error": str(e)}

@mcp.tool()
def sheets_rename_sheet(spreadsheetId: str, sheetId: int, new_title: str) -> dict:
    """Rename a tab."""
    service = get_sheets_service()
    try:
        return service.spreadsheets().batchUpdate(
            spreadsheetId=spreadsheetId,
            body={"requests": [{"updateSheetProperties": {
                "properties": {"sheetId": sheetId, "title": new_title},
                "fields": "title",
            }}]},
        ).execute()
    except HttpError as e:
        return {"error": str(e)}

@mcp.tool()
def sheets_duplicate_sheet(
    spreadsheetId: str, sheetId: int, new_name: str = "", insert_index: int = 0
) -> dict:
    """
    Duplicate a tab within the same spreadsheet.

    Args:
        spreadsheetId: The spreadsheet ID.
        sheetId: The source tab's sheetId.
        new_name: Name for the copy (empty = auto).
        insert_index: Position index for the new tab.
    """
    service = get_sheets_service()
    req: Dict[str, Any] = {"sourceSheetId": sheetId, "insertSheetIndex": insert_index}
    if new_name:
        req["newSheetName"] = new_name
    try:
        result = service.spreadsheets().batchUpdate(
            spreadsheetId=spreadsheetId,
            body={"requests": [{"duplicateSheet": req}]},
        ).execute()
        return result["replies"][0]["duplicateSheet"]["properties"]
    except HttpError as e:
        return {"error": str(e)}

# -- Sheets: Formula Reading ---------------------------------------------------

@mcp.tool()
def sheets_read_formulas(spreadsheetId: str, range: str) -> dict:
    """
    Read raw formulas from a range (instead of computed values).
    Cells without formulas return their literal value.
    """
    service = get_sheets_service()
    try:
        result = service.spreadsheets().values().get(
            spreadsheetId=spreadsheetId,
            range=range,
            valueRenderOption="FORMULA",
        ).execute()
        return {"values": result.get("values", [])}
    except HttpError as e:
        return {"error": str(e)}

# -- Sheets: Data Operations ---------------------------------------------------

@mcp.tool()
def sheets_clear_values(spreadsheetId: str, range: str) -> dict:
    """Clear values in a range without deleting rows/columns or formatting."""
    service = get_sheets_service()
    try:
        return service.spreadsheets().values().clear(
            spreadsheetId=spreadsheetId, range=range, body={}
        ).execute()
    except HttpError as e:
        return {"error": str(e)}

@mcp.tool()
def sheets_find_replace(
    spreadsheetId: str,
    find: str,
    replacement: str,
    sheet_id: Optional[int] = None,
    all_sheets: bool = False,
    match_case: bool = False,
    match_entire_cell: bool = False,
    search_by_regex: bool = False,
    include_formulas: bool = False,
) -> dict:
    """
    Find and replace text across a sheet or all sheets.

    Args:
        spreadsheetId: The spreadsheet ID.
        find: Text to search for.
        replacement: Replacement text.
        sheet_id: Limit to this sheet (tab). Omit if using all_sheets.
        all_sheets: Search all sheets in the spreadsheet.
        match_case: Case-sensitive matching.
        match_entire_cell: Must match the full cell content.
        search_by_regex: Treat `find` as a Java-style regex.
        include_formulas: Also search inside formula text.
    """
    service = get_sheets_service()
    req: Dict[str, Any] = {
        "find": find,
        "replacement": replacement,
        "matchCase": match_case,
        "matchEntireCell": match_entire_cell,
        "searchByRegex": search_by_regex,
        "includeFormulas": include_formulas,
    }
    if all_sheets:
        req["allSheets"] = True
    elif sheet_id is not None:
        req["sheetId"] = sheet_id
    else:
        req["allSheets"] = True
    try:
        result = service.spreadsheets().batchUpdate(
            spreadsheetId=spreadsheetId,
            body={"requests": [{"findReplace": req}]},
        ).execute()
        return result["replies"][0].get("findReplace", {})
    except HttpError as e:
        return {"error": str(e)}

@mcp.tool()
def sheets_sort_range(
    spreadsheetId: str,
    sheetId: int,
    start_row: int,
    end_row: int,
    start_col: int,
    end_col: int,
    sort_specs: List[Dict[str, Any]],
) -> dict:
    """
    Sort a range by one or more columns.

    Args:
        spreadsheetId: The spreadsheet ID.
        sheetId: The tab's sheetId.
        start_row: 0-based start row index.
        end_row: 0-based end row index (exclusive).
        start_col: 0-based start column index.
        end_col: 0-based end column index (exclusive).
        sort_specs: List of sort specs, e.g. [{"dimensionIndex": 0, "sortOrder": "ASCENDING"}].
    """
    service = get_sheets_service()
    try:
        return service.spreadsheets().batchUpdate(
            spreadsheetId=spreadsheetId,
            body={"requests": [{"sortRange": {
                "range": {
                    "sheetId": sheetId,
                    "startRowIndex": start_row,
                    "endRowIndex": end_row,
                    "startColumnIndex": start_col,
                    "endColumnIndex": end_col,
                },
                "sortSpecs": sort_specs,
            }}]},
        ).execute()
    except HttpError as e:
        return {"error": str(e)}

@mcp.tool()
def sheets_delete_rows_columns(
    spreadsheetId: str, sheetId: int, dimension: str, start_index: int, end_index: int
) -> dict:
    """
    Delete rows or columns.

    Args:
        spreadsheetId: The spreadsheet ID.
        sheetId: The tab's sheetId.
        dimension: "ROWS" or "COLUMNS".
        start_index: 0-based start index.
        end_index: 0-based end index (exclusive).
    """
    service = get_sheets_service()
    try:
        return service.spreadsheets().batchUpdate(
            spreadsheetId=spreadsheetId,
            body={"requests": [{"deleteDimension": {"range": {
                "sheetId": sheetId,
                "dimension": dimension,
                "startIndex": start_index,
                "endIndex": end_index,
            }}}]},
        ).execute()
    except HttpError as e:
        return {"error": str(e)}

@mcp.tool()
def sheets_insert_rows_columns(
    spreadsheetId: str,
    sheetId: int,
    dimension: str,
    start_index: int,
    end_index: int,
    inherit_from_before: bool = True,
) -> dict:
    """
    Insert empty rows or columns.

    Args:
        spreadsheetId: The spreadsheet ID.
        sheetId: The tab's sheetId.
        dimension: "ROWS" or "COLUMNS".
        start_index: 0-based start index.
        end_index: 0-based end index (exclusive). Number inserted = end - start.
        inherit_from_before: Inherit formatting from the row/col before (True) or after (False).
    """
    service = get_sheets_service()
    try:
        return service.spreadsheets().batchUpdate(
            spreadsheetId=spreadsheetId,
            body={"requests": [{"insertDimension": {
                "range": {
                    "sheetId": sheetId,
                    "dimension": dimension,
                    "startIndex": start_index,
                    "endIndex": end_index,
                },
                "inheritFromBefore": inherit_from_before,
            }}]},
        ).execute()
    except HttpError as e:
        return {"error": str(e)}

# -- Sheets: Formatting --------------------------------------------------------

@mcp.tool()
def sheets_format_cells(
    spreadsheetId: str,
    sheetId: int,
    start_row: int,
    end_row: int,
    start_col: int,
    end_col: int,
    bold: Optional[bool] = None,
    italic: Optional[bool] = None,
    font_size: Optional[int] = None,
    font_family: Optional[str] = None,
    fg_color: Optional[Dict[str, float]] = None,
    bg_color: Optional[Dict[str, float]] = None,
    number_format_type: Optional[str] = None,
    number_format_pattern: Optional[str] = None,
    horizontal_alignment: Optional[str] = None,
    vertical_alignment: Optional[str] = None,
    wrap_strategy: Optional[str] = None,
) -> dict:
    """
    Apply formatting to a range.

    Args:
        spreadsheetId: The spreadsheet ID.
        sheetId: The tab's sheetId.
        start_row/end_row/start_col/end_col: 0-based range bounds (end exclusive).
        bold/italic: Text style booleans.
        font_size: Font size in pt.
        font_family: e.g. "Arial".
        fg_color: Text color as {"red": 0-1, "green": 0-1, "blue": 0-1}.
        bg_color: Background color in same format.
        number_format_type: e.g. "NUMBER", "CURRENCY", "PERCENT", "DATE", "TEXT".
        number_format_pattern: e.g. "#,##0.00".
        horizontal_alignment: "LEFT", "CENTER", "RIGHT".
        vertical_alignment: "TOP", "MIDDLE", "BOTTOM".
        wrap_strategy: "OVERFLOW_CELL", "CLIP", "WRAP".
    """
    service = get_sheets_service()
    cell: Dict[str, Any] = {"userEnteredFormat": {}}
    fmt = cell["userEnteredFormat"]
    fields = []

    text_format: Dict[str, Any] = {}
    if bold is not None:
        text_format["bold"] = bold
        fields.append("userEnteredFormat.textFormat.bold")
    if italic is not None:
        text_format["italic"] = italic
        fields.append("userEnteredFormat.textFormat.italic")
    if font_size is not None:
        text_format["fontSize"] = font_size
        fields.append("userEnteredFormat.textFormat.fontSize")
    if font_family is not None:
        text_format["fontFamily"] = font_family
        fields.append("userEnteredFormat.textFormat.fontFamily")
    if fg_color is not None:
        text_format["foregroundColorStyle"] = {"rgbColor": fg_color}
        fields.append("userEnteredFormat.textFormat.foregroundColorStyle")
    if text_format:
        fmt["textFormat"] = text_format

    if bg_color is not None:
        fmt["backgroundColorStyle"] = {"rgbColor": bg_color}
        fields.append("userEnteredFormat.backgroundColorStyle")

    if number_format_type is not None:
        nf: Dict[str, str] = {"type": number_format_type}
        if number_format_pattern:
            nf["pattern"] = number_format_pattern
        fmt["numberFormat"] = nf
        fields.append("userEnteredFormat.numberFormat")

    if horizontal_alignment is not None:
        fmt["horizontalAlignment"] = horizontal_alignment
        fields.append("userEnteredFormat.horizontalAlignment")
    if vertical_alignment is not None:
        fmt["verticalAlignment"] = vertical_alignment
        fields.append("userEnteredFormat.verticalAlignment")
    if wrap_strategy is not None:
        fmt["wrapStrategy"] = wrap_strategy
        fields.append("userEnteredFormat.wrapStrategy")

    if not fields:
        return {"error": "No formatting options specified."}

    try:
        return service.spreadsheets().batchUpdate(
            spreadsheetId=spreadsheetId,
            body={"requests": [{"repeatCell": {
                "range": {
                    "sheetId": sheetId,
                    "startRowIndex": start_row,
                    "endRowIndex": end_row,
                    "startColumnIndex": start_col,
                    "endColumnIndex": end_col,
                },
                "cell": cell,
                "fields": ",".join(fields),
            }}]},
        ).execute()
    except HttpError as e:
        return {"error": str(e)}

@mcp.tool()
def sheets_merge_cells(
    spreadsheetId: str,
    sheetId: int,
    start_row: int,
    end_row: int,
    start_col: int,
    end_col: int,
    merge_type: str = "MERGE_ALL",
) -> dict:
    """
    Merge cells in a range.

    Args:
        merge_type: "MERGE_ALL", "MERGE_COLUMNS", or "MERGE_ROWS".
    """
    service = get_sheets_service()
    try:
        return service.spreadsheets().batchUpdate(
            spreadsheetId=spreadsheetId,
            body={"requests": [{"mergeCells": {
                "range": {
                    "sheetId": sheetId,
                    "startRowIndex": start_row,
                    "endRowIndex": end_row,
                    "startColumnIndex": start_col,
                    "endColumnIndex": end_col,
                },
                "mergeType": merge_type,
            }}]},
        ).execute()
    except HttpError as e:
        return {"error": str(e)}

@mcp.tool()
def sheets_unmerge_cells(
    spreadsheetId: str, sheetId: int, start_row: int, end_row: int, start_col: int, end_col: int
) -> dict:
    """Unmerge previously merged cells in a range."""
    service = get_sheets_service()
    try:
        return service.spreadsheets().batchUpdate(
            spreadsheetId=spreadsheetId,
            body={"requests": [{"unmergeCells": {"range": {
                "sheetId": sheetId,
                "startRowIndex": start_row,
                "endRowIndex": end_row,
                "startColumnIndex": start_col,
                "endColumnIndex": end_col,
            }}}]},
        ).execute()
    except HttpError as e:
        return {"error": str(e)}

@mcp.tool()
def sheets_auto_resize(
    spreadsheetId: str, sheetId: int, dimension: str, start_index: int, end_index: int
) -> dict:
    """
    Auto-resize columns or rows to fit content.

    Args:
        dimension: "COLUMNS" or "ROWS".
        start_index/end_index: 0-based range (end exclusive).
    """
    service = get_sheets_service()
    try:
        return service.spreadsheets().batchUpdate(
            spreadsheetId=spreadsheetId,
            body={"requests": [{"autoResizeDimensions": {"dimensions": {
                "sheetId": sheetId,
                "dimension": dimension,
                "startIndex": start_index,
                "endIndex": end_index,
            }}}]},
        ).execute()
    except HttpError as e:
        return {"error": str(e)}

@mcp.tool()
def sheets_set_column_width(
    spreadsheetId: str, sheetId: int, start_index: int, end_index: int, pixel_size: int
) -> dict:
    """
    Set explicit pixel width for columns.

    Args:
        start_index/end_index: 0-based column range (end exclusive).
        pixel_size: Width in pixels.
    """
    service = get_sheets_service()
    try:
        return service.spreadsheets().batchUpdate(
            spreadsheetId=spreadsheetId,
            body={"requests": [{"updateDimensionProperties": {
                "range": {
                    "sheetId": sheetId,
                    "dimension": "COLUMNS",
                    "startIndex": start_index,
                    "endIndex": end_index,
                },
                "properties": {"pixelSize": pixel_size},
                "fields": "pixelSize",
            }}]},
        ).execute()
    except HttpError as e:
        return {"error": str(e)}

@mcp.tool()
def sheets_update_borders(
    spreadsheetId: str,
    sheetId: int,
    start_row: int,
    end_row: int,
    start_col: int,
    end_col: int,
    style: str = "SOLID",
    width: int = 1,
    color: Optional[Dict[str, float]] = None,
    sides: List[str] = ["top", "bottom", "left", "right"],
) -> dict:
    """
    Set borders on a range.

    Args:
        style: "SOLID", "SOLID_MEDIUM", "SOLID_THICK", "DASHED", "DOTTED", "DOUBLE", "NONE".
        width: Border width in pixels.
        color: e.g. {"red": 0, "green": 0, "blue": 0}. Defaults to black.
        sides: Which sides to set. Options: "top", "bottom", "left", "right", "innerHorizontal", "innerVertical".
    """
    service = get_sheets_service()
    border_color = color or {"red": 0, "green": 0, "blue": 0}
    border_def = {"style": style, "width": width, "colorStyle": {"rgbColor": border_color}}
    req: Dict[str, Any] = {
        "range": {
            "sheetId": sheetId,
            "startRowIndex": start_row,
            "endRowIndex": end_row,
            "startColumnIndex": start_col,
            "endColumnIndex": end_col,
        },
    }
    for side in sides:
        req[side] = border_def
    try:
        return service.spreadsheets().batchUpdate(
            spreadsheetId=spreadsheetId,
            body={"requests": [{"updateBorders": req}]},
        ).execute()
    except HttpError as e:
        return {"error": str(e)}

# -- Sheets: Validation & Protection -------------------------------------------

@mcp.tool()
def sheets_set_data_validation(
    spreadsheetId: str,
    sheetId: int,
    start_row: int,
    end_row: int,
    start_col: int,
    end_col: int,
    rule: Dict[str, Any],
) -> dict:
    """
    Set data validation on a range.

    Args:
        rule: A DataValidationRule object, e.g.:
            {"condition": {"type": "ONE_OF_LIST", "values": [{"userEnteredValue": "Yes"}, {"userEnteredValue": "No"}]}, "showCustomUi": true, "strict": true}
            Pass an empty dict or None to clear validation.
    """
    service = get_sheets_service()
    req: Dict[str, Any] = {
        "range": {
            "sheetId": sheetId,
            "startRowIndex": start_row,
            "endRowIndex": end_row,
            "startColumnIndex": start_col,
            "endColumnIndex": end_col,
        },
    }
    if rule:
        req["rule"] = rule
    try:
        return service.spreadsheets().batchUpdate(
            spreadsheetId=spreadsheetId,
            body={"requests": [{"setDataValidation": req}]},
        ).execute()
    except HttpError as e:
        return {"error": str(e)}

@mcp.tool()
def sheets_protect_range(
    spreadsheetId: str,
    sheetId: int,
    start_row: int,
    end_row: int,
    start_col: int,
    end_col: int,
    description: str = "",
    warning_only: bool = False,
) -> dict:
    """
    Protect a range from editing.

    Args:
        warning_only: If True, shows a warning but still allows edits.
    """
    service = get_sheets_service()
    try:
        result = service.spreadsheets().batchUpdate(
            spreadsheetId=spreadsheetId,
            body={"requests": [{"addProtectedRange": {"protectedRange": {
                "range": {
                    "sheetId": sheetId,
                    "startRowIndex": start_row,
                    "endRowIndex": end_row,
                    "startColumnIndex": start_col,
                    "endColumnIndex": end_col,
                },
                "description": description,
                "warningOnly": warning_only,
            }}}]},
        ).execute()
        return result["replies"][0].get("addProtectedRange", {})
    except HttpError as e:
        return {"error": str(e)}

# -- Sheets: Pivot Tables & Charts ---------------------------------------------

@mcp.tool()
def sheets_create_pivot_table(
    spreadsheetId: str,
    source_sheet_id: int,
    source_start_row: int,
    source_end_row: int,
    source_start_col: int,
    source_end_col: int,
    target_sheet_id: int,
    target_row: int,
    target_col: int,
    rows: List[Dict[str, Any]] = [],
    columns: List[Dict[str, Any]] = [],
    values: List[Dict[str, Any]] = [],
) -> dict:
    """
    Create a pivot table.

    Args:
        source_*: Define the data source range.
        target_sheet_id/target_row/target_col: Where to place the pivot table.
        rows: Pivot row groups, e.g. [{"sourceColumnOffset": 0, "sortOrder": "ASCENDING"}].
        columns: Pivot column groups, same format.
        values: Pivot values, e.g. [{"sourceColumnOffset": 2, "summarizeFunction": "SUM"}].
    """
    service = get_sheets_service()
    pivot_table: Dict[str, Any] = {
        "source": {
            "sheetId": source_sheet_id,
            "startRowIndex": source_start_row,
            "endRowIndex": source_end_row,
            "startColumnIndex": source_start_col,
            "endColumnIndex": source_end_col,
        },
        "rows": rows,
        "columns": columns,
        "values": values,
    }
    try:
        return service.spreadsheets().batchUpdate(
            spreadsheetId=spreadsheetId,
            body={"requests": [{"updateCells": {
                "rows": [{"values": [{"pivotTable": pivot_table}]}],
                "start": {"sheetId": target_sheet_id, "rowIndex": target_row, "columnIndex": target_col},
                "fields": "pivotTable",
            }}]},
        ).execute()
    except HttpError as e:
        return {"error": str(e)}

@mcp.tool()
def sheets_create_chart(
    spreadsheetId: str,
    sheetId: int,
    chart_type: str,
    start_row: int,
    end_row: int,
    start_col: int,
    end_col: int,
    title: str = "",
    anchor_row: int = 0,
    anchor_col: int = 0,
) -> dict:
    """
    Create an embedded chart.

    Args:
        chart_type: "BAR", "LINE", "PIE", "COLUMN", "AREA", "SCATTER", "COMBO", "STEPPED_AREA".
        start_row/end_row/start_col/end_col: Data source range (0-based, end exclusive).
        title: Chart title.
        anchor_row/anchor_col: Where to place the chart on the sheet.
    """
    service = get_sheets_service()
    source_range = {
        "sheetId": sheetId,
        "startRowIndex": start_row,
        "endRowIndex": end_row,
        "startColumnIndex": start_col,
        "endColumnIndex": end_col,
    }
    chart: Dict[str, Any] = {
        "spec": {
            "title": title,
            "basicChart": {
                "chartType": chart_type,
                "domains": [{"domain": {"sourceRange": {"sources": [source_range]}}}],
                "series": [{"series": {"sourceRange": {"sources": [source_range]}}}],
            },
        },
        "position": {"overlayPosition": {
            "anchorCell": {"sheetId": sheetId, "rowIndex": anchor_row, "columnIndex": anchor_col},
        }},
    }
    try:
        result = service.spreadsheets().batchUpdate(
            spreadsheetId=spreadsheetId,
            body={"requests": [{"addChart": {"chart": chart}}]},
        ).execute()
        return result["replies"][0].get("addChart", {})
    except HttpError as e:
        return {"error": str(e)}

# -- Sheets: Conditional Formatting --------------------------------------------

@mcp.tool()
def sheets_add_conditional_format(
    spreadsheetId: str,
    sheetId: int,
    start_row: int,
    end_row: int,
    start_col: int,
    end_col: int,
    rule: Dict[str, Any],
    index: int = 0,
) -> dict:
    """
    Add a conditional format rule.

    Args:
        rule: A ConditionalFormatRule body containing either "booleanRule" or "gradientRule".
            Example boolean rule:
            {"booleanRule": {"condition": {"type": "NUMBER_LESS", "values": [{"userEnteredValue": "0"}]},
             "format": {"textFormat": {"foregroundColorStyle": {"rgbColor": {"red": 1}}}}}}
        index: Position in the rule list (0 = highest priority).
    """
    service = get_sheets_service()
    rule["ranges"] = [{
        "sheetId": sheetId,
        "startRowIndex": start_row,
        "endRowIndex": end_row,
        "startColumnIndex": start_col,
        "endColumnIndex": end_col,
    }]
    try:
        return service.spreadsheets().batchUpdate(
            spreadsheetId=spreadsheetId,
            body={"requests": [{"addConditionalFormatRule": {"rule": rule, "index": index}}]},
        ).execute()
    except HttpError as e:
        return {"error": str(e)}

@mcp.tool()
def sheets_delete_conditional_format(spreadsheetId: str, sheetId: int, index: int) -> dict:
    """Delete a conditional format rule by its index on a sheet."""
    service = get_sheets_service()
    try:
        return service.spreadsheets().batchUpdate(
            spreadsheetId=spreadsheetId,
            body={"requests": [{"deleteConditionalFormatRule": {
                "sheetId": sheetId, "index": index,
            }}]},
        ).execute()
    except HttpError as e:
        return {"error": str(e)}

# -- Sheets: Named Ranges -----------------------------------------------------

@mcp.tool()
def sheets_add_named_range(
    spreadsheetId: str,
    name: str,
    sheetId: int,
    start_row: int,
    end_row: int,
    start_col: int,
    end_col: int,
) -> dict:
    """Create a named range for easier formula references."""
    service = get_sheets_service()
    try:
        result = service.spreadsheets().batchUpdate(
            spreadsheetId=spreadsheetId,
            body={"requests": [{"addNamedRange": {"namedRange": {
                "name": name,
                "range": {
                    "sheetId": sheetId,
                    "startRowIndex": start_row,
                    "endRowIndex": end_row,
                    "startColumnIndex": start_col,
                    "endColumnIndex": end_col,
                },
            }}}]},
        ).execute()
        return result["replies"][0].get("addNamedRange", {})
    except HttpError as e:
        return {"error": str(e)}

@mcp.tool()
def sheets_delete_named_range(spreadsheetId: str, named_range_id: str) -> dict:
    """Delete a named range by its ID."""
    service = get_sheets_service()
    try:
        return service.spreadsheets().batchUpdate(
            spreadsheetId=spreadsheetId,
            body={"requests": [{"deleteNamedRange": {"namedRangeId": named_range_id}}]},
        ).execute()
    except HttpError as e:
        return {"error": str(e)}

# -- Sheets: Filter Views ------------------------------------------------------

@mcp.tool()
def sheets_add_filter_view(
    spreadsheetId: str,
    sheetId: int,
    title: str,
    start_row: int,
    end_row: int,
    start_col: int,
    end_col: int,
    criteria: Dict[str, Any] = {},
) -> dict:
    """
    Create a saved filter view.

    Args:
        criteria: Filter criteria keyed by column index (as string), e.g.:
            {"0": {"hiddenValues": ["Draft"]}}
    """
    service = get_sheets_service()
    fv: Dict[str, Any] = {
        "title": title,
        "range": {
            "sheetId": sheetId,
            "startRowIndex": start_row,
            "endRowIndex": end_row,
            "startColumnIndex": start_col,
            "endColumnIndex": end_col,
        },
    }
    if criteria:
        fv["criteria"] = criteria
    try:
        result = service.spreadsheets().batchUpdate(
            spreadsheetId=spreadsheetId,
            body={"requests": [{"addFilterView": {"filter": fv}}]},
        ).execute()
        return result["replies"][0].get("addFilterView", {})
    except HttpError as e:
        return {"error": str(e)}

@mcp.tool()
def sheets_delete_filter_view(spreadsheetId: str, filter_view_id: int) -> dict:
    """Delete a filter view by its ID."""
    service = get_sheets_service()
    try:
        return service.spreadsheets().batchUpdate(
            spreadsheetId=spreadsheetId,
            body={"requests": [{"deleteFilterView": {"filterId": filter_view_id}}]},
        ).execute()
    except HttpError as e:
        return {"error": str(e)}

# -- Sheets: Cell Notes --------------------------------------------------------

@mcp.tool()
def sheets_set_note(
    spreadsheetId: str, sheetId: int, row: int, col: int, note: str
) -> dict:
    """
    Add, update, or clear a note on a single cell.
    Pass an empty string to clear the note.
    """
    service = get_sheets_service()
    try:
        return service.spreadsheets().batchUpdate(
            spreadsheetId=spreadsheetId,
            body={"requests": [{"updateCells": {
                "rows": [{"values": [{"note": note}]}],
                "start": {"sheetId": sheetId, "rowIndex": row, "columnIndex": col},
                "fields": "note",
            }}]},
        ).execute()
    except HttpError as e:
        return {"error": str(e)}

@mcp.tool()
def sheets_get_notes(spreadsheetId: str, range: str) -> dict:
    """
    Read notes from a range of cells.
    Returns a 2D array matching the range shape; cells without notes are empty strings.
    """
    service = get_sheets_service()
    try:
        result = service.spreadsheets().get(
            spreadsheetId=spreadsheetId,
            ranges=[range],
            fields="sheets.data.rowData.values.note",
        ).execute()
        notes = []
        for sheet in result.get("sheets", []):
            for grid_data in sheet.get("data", []):
                for row_data in grid_data.get("rowData", []):
                    row_notes = []
                    for cell in row_data.get("values", []):
                        row_notes.append(cell.get("note", ""))
                    notes.append(row_notes)
        return {"notes": notes}
    except HttpError as e:
        return {"error": str(e)}

# -- Sheets: Hide / Unhide ----------------------------------------------------

@mcp.tool()
def sheets_hide_rows_columns(
    spreadsheetId: str, sheetId: int, dimension: str, start_index: int, end_index: int
) -> dict:
    """
    Hide rows or columns.

    Args:
        dimension: "ROWS" or "COLUMNS".
        start_index/end_index: 0-based range (end exclusive).
    """
    service = get_sheets_service()
    try:
        return service.spreadsheets().batchUpdate(
            spreadsheetId=spreadsheetId,
            body={"requests": [{"updateDimensionProperties": {
                "range": {
                    "sheetId": sheetId,
                    "dimension": dimension,
                    "startIndex": start_index,
                    "endIndex": end_index,
                },
                "properties": {"hiddenByUser": True},
                "fields": "hiddenByUser",
            }}]},
        ).execute()
    except HttpError as e:
        return {"error": str(e)}

@mcp.tool()
def sheets_hide_sheet(spreadsheetId: str, sheetId: int) -> dict:
    """Hide a tab/sheet."""
    service = get_sheets_service()
    try:
        return service.spreadsheets().batchUpdate(
            spreadsheetId=spreadsheetId,
            body={"requests": [{"updateSheetProperties": {
                "properties": {"sheetId": sheetId, "hidden": True},
                "fields": "hidden",
            }}]},
        ).execute()
    except HttpError as e:
        return {"error": str(e)}

@mcp.tool()
def sheets_unhide_sheet(spreadsheetId: str, sheetId: int) -> dict:
    """Unhide a hidden tab/sheet."""
    service = get_sheets_service()
    try:
        return service.spreadsheets().batchUpdate(
            spreadsheetId=spreadsheetId,
            body={"requests": [{"updateSheetProperties": {
                "properties": {"sheetId": sheetId, "hidden": False},
                "fields": "hidden",
            }}]},
        ).execute()
    except HttpError as e:
        return {"error": str(e)}

# -- Sheets: Copy / Cut / Paste ------------------------------------------------

@mcp.tool()
def sheets_copy_paste(
    spreadsheetId: str,
    src_sheet_id: int,
    src_start_row: int,
    src_end_row: int,
    src_start_col: int,
    src_end_col: int,
    dst_sheet_id: int,
    dst_start_row: int,
    dst_end_row: int,
    dst_start_col: int,
    dst_end_col: int,
    paste_type: str = "PASTE_NORMAL",
    paste_orientation: str = "NORMAL",
) -> dict:
    """
    Copy a range to another location (preserves values, formatting, formulas).

    Args:
        paste_type: "PASTE_NORMAL", "PASTE_VALUES", "PASTE_FORMAT", "PASTE_NO_BORDERS",
                    "PASTE_FORMULA", "PASTE_DATA_VALIDATION", "PASTE_CONDITIONAL_FORMATTING".
        paste_orientation: "NORMAL" or "TRANSPOSE".
    """
    service = get_sheets_service()
    try:
        return service.spreadsheets().batchUpdate(
            spreadsheetId=spreadsheetId,
            body={"requests": [{"copyPaste": {
                "source": {
                    "sheetId": src_sheet_id,
                    "startRowIndex": src_start_row,
                    "endRowIndex": src_end_row,
                    "startColumnIndex": src_start_col,
                    "endColumnIndex": src_end_col,
                },
                "destination": {
                    "sheetId": dst_sheet_id,
                    "startRowIndex": dst_start_row,
                    "endRowIndex": dst_end_row,
                    "startColumnIndex": dst_start_col,
                    "endColumnIndex": dst_end_col,
                },
                "pasteType": paste_type,
                "pasteOrientation": paste_orientation,
            }}]},
        ).execute()
    except HttpError as e:
        return {"error": str(e)}

@mcp.tool()
def sheets_cut_paste(
    spreadsheetId: str,
    src_sheet_id: int,
    src_start_row: int,
    src_end_row: int,
    src_start_col: int,
    src_end_col: int,
    dst_sheet_id: int,
    dst_row: int,
    dst_col: int,
    paste_type: str = "PASTE_NORMAL",
) -> dict:
    """
    Move (cut) data from one range to another, clearing the source.

    Args:
        dst_row/dst_col: Top-left coordinate of the destination.
        paste_type: Same options as sheets_copy_paste.
    """
    service = get_sheets_service()
    try:
        return service.spreadsheets().batchUpdate(
            spreadsheetId=spreadsheetId,
            body={"requests": [{"cutPaste": {
                "source": {
                    "sheetId": src_sheet_id,
                    "startRowIndex": src_start_row,
                    "endRowIndex": src_end_row,
                    "startColumnIndex": src_start_col,
                    "endColumnIndex": src_end_col,
                },
                "destination": {"sheetId": dst_sheet_id, "rowIndex": dst_row, "columnIndex": dst_col},
                "pasteType": paste_type,
            }}]},
        ).execute()
    except HttpError as e:
        return {"error": str(e)}

@mcp.tool()
def sheets_paste_data(
    spreadsheetId: str,
    sheetId: int,
    row: int,
    col: int,
    data: str,
    delimiter: str = ",",
    is_html: bool = False,
    paste_type: str = "PASTE_NORMAL",
) -> dict:
    """
    Paste raw CSV or HTML data into a sheet.

    Args:
        data: The raw string data (CSV or HTML).
        delimiter: Delimiter for CSV data (ignored if is_html is True).
        is_html: If True, interpret data as HTML instead of delimited text.
        paste_type: How to paste the data.
    """
    service = get_sheets_service()
    req: Dict[str, Any] = {
        "coordinate": {"sheetId": sheetId, "rowIndex": row, "columnIndex": col},
        "data": data,
        "type": paste_type,
    }
    if is_html:
        req["html"] = True
    else:
        req["delimiter"] = delimiter
    try:
        return service.spreadsheets().batchUpdate(
            spreadsheetId=spreadsheetId,
            body={"requests": [{"pasteData": req}]},
        ).execute()
    except HttpError as e:
        return {"error": str(e)}

# -- Sheets: Banding (Alternating Colors) --------------------------------------

@mcp.tool()
def sheets_add_banding(
    spreadsheetId: str,
    sheetId: int,
    start_row: int,
    end_row: int,
    start_col: int,
    end_col: int,
    header_color: Optional[Dict[str, float]] = None,
    first_band_color: Optional[Dict[str, float]] = None,
    second_band_color: Optional[Dict[str, float]] = None,
) -> dict:
    """
    Apply alternating row colors (banding) to a range.

    Args:
        header_color/first_band_color/second_band_color:
            RGB dicts, e.g. {"red": 0.9, "green": 0.9, "blue": 0.9}.
    """
    service = get_sheets_service()
    banded: Dict[str, Any] = {
        "range": {
            "sheetId": sheetId,
            "startRowIndex": start_row,
            "endRowIndex": end_row,
            "startColumnIndex": start_col,
            "endColumnIndex": end_col,
        },
        "rowProperties": {},
    }
    if header_color:
        banded["rowProperties"]["headerColorStyle"] = {"rgbColor": header_color}
    if first_band_color:
        banded["rowProperties"]["firstBandColorStyle"] = {"rgbColor": first_band_color}
    if second_band_color:
        banded["rowProperties"]["secondBandColorStyle"] = {"rgbColor": second_band_color}
    try:
        result = service.spreadsheets().batchUpdate(
            spreadsheetId=spreadsheetId,
            body={"requests": [{"addBanding": {"bandedRange": banded}}]},
        ).execute()
        return result["replies"][0].get("addBanding", {})
    except HttpError as e:
        return {"error": str(e)}

@mcp.tool()
def sheets_delete_banding(spreadsheetId: str, banded_range_id: int) -> dict:
    """Remove banding by its banded range ID."""
    service = get_sheets_service()
    try:
        return service.spreadsheets().batchUpdate(
            spreadsheetId=spreadsheetId,
            body={"requests": [{"deleteBanding": {"bandedRangeId": banded_range_id}}]},
        ).execute()
    except HttpError as e:
        return {"error": str(e)}

# -- Sheets: Freeze ------------------------------------------------------------

@mcp.tool()
def sheets_freeze(
    spreadsheetId: str, sheetId: int, frozen_rows: int = 0, frozen_cols: int = 0
) -> dict:
    """
    Freeze rows and/or columns on a sheet. Set to 0 to unfreeze.

    Args:
        frozen_rows: Number of rows to freeze from the top.
        frozen_cols: Number of columns to freeze from the left.
    """
    service = get_sheets_service()
    try:
        return service.spreadsheets().batchUpdate(
            spreadsheetId=spreadsheetId,
            body={"requests": [{"updateSheetProperties": {
                "properties": {
                    "sheetId": sheetId,
                    "gridProperties": {
                        "frozenRowCount": frozen_rows,
                        "frozenColumnCount": frozen_cols,
                    },
                },
                "fields": "gridProperties.frozenRowCount,gridProperties.frozenColumnCount",
            }}]},
        ).execute()
    except HttpError as e:
        return {"error": str(e)}

# -- Sheets: AutoFill ----------------------------------------------------------

@mcp.tool()
def sheets_autofill(
    spreadsheetId: str,
    sheetId: int,
    start_row: int,
    end_row: int,
    start_col: int,
    end_col: int,
    use_alternate_series: bool = False,
) -> dict:
    """
    Smart-fill patterns based on existing data (like dragging the cell corner in the UI).
    The range must include the source cells that contain the pattern.
    """
    service = get_sheets_service()
    try:
        return service.spreadsheets().batchUpdate(
            spreadsheetId=spreadsheetId,
            body={"requests": [{"autoFill": {
                "range": {
                    "sheetId": sheetId,
                    "startRowIndex": start_row,
                    "endRowIndex": end_row,
                    "startColumnIndex": start_col,
                    "endColumnIndex": end_col,
                },
                "useAlternateSeries": use_alternate_series,
            }}]},
        ).execute()
    except HttpError as e:
        return {"error": str(e)}

# -- Sheets: Basic Filter ------------------------------------------------------

@mcp.tool()
def sheets_set_basic_filter(
    spreadsheetId: str,
    sheetId: int,
    start_row: int,
    end_row: int,
    start_col: int,
    end_col: int,
    criteria: Dict[str, Any] = {},
) -> dict:
    """
    Set the built-in auto-filter on a sheet (the toolbar filter icon).

    Args:
        criteria: Filter criteria keyed by column index (as string), e.g.:
            {"0": {"hiddenValues": ["Draft"]}}
    """
    service = get_sheets_service()
    bf: Dict[str, Any] = {
        "range": {
            "sheetId": sheetId,
            "startRowIndex": start_row,
            "endRowIndex": end_row,
            "startColumnIndex": start_col,
            "endColumnIndex": end_col,
        },
    }
    if criteria:
        bf["criteria"] = criteria
    try:
        return service.spreadsheets().batchUpdate(
            spreadsheetId=spreadsheetId,
            body={"requests": [{"setBasicFilter": {"filter": bf}}]},
        ).execute()
    except HttpError as e:
        return {"error": str(e)}

@mcp.tool()
def sheets_clear_basic_filter(spreadsheetId: str, sheetId: int) -> dict:
    """Remove the built-in filter from a sheet."""
    service = get_sheets_service()
    try:
        return service.spreadsheets().batchUpdate(
            spreadsheetId=spreadsheetId,
            body={"requests": [{"clearBasicFilter": {"sheetId": sheetId}}]},
        ).execute()
    except HttpError as e:
        return {"error": str(e)}

# -- Sheets: Move Rows/Columns ------------------------------------------------

@mcp.tool()
def sheets_move_rows_columns(
    spreadsheetId: str,
    sheetId: int,
    dimension: str,
    start_index: int,
    end_index: int,
    destination_index: int,
) -> dict:
    """
    Move rows or columns to a new position within the sheet.

    Args:
        dimension: "ROWS" or "COLUMNS".
        start_index/end_index: 0-based range of source rows/cols (end exclusive).
        destination_index: 0-based target position (based on coordinates before the move).
    """
    service = get_sheets_service()
    try:
        return service.spreadsheets().batchUpdate(
            spreadsheetId=spreadsheetId,
            body={"requests": [{"moveDimension": {
                "source": {
                    "sheetId": sheetId,
                    "dimension": dimension,
                    "startIndex": start_index,
                    "endIndex": end_index,
                },
                "destinationIndex": destination_index,
            }}]},
        ).execute()
    except HttpError as e:
        return {"error": str(e)}

# -- Sheets: Trim Whitespace ---------------------------------------------------

@mcp.tool()
def sheets_trim_whitespace(
    spreadsheetId: str, sheetId: int, start_row: int, end_row: int, start_col: int, end_col: int
) -> dict:
    """Strip leading/trailing whitespace from all cells in a range."""
    service = get_sheets_service()
    try:
        return service.spreadsheets().batchUpdate(
            spreadsheetId=spreadsheetId,
            body={"requests": [{"trimWhitespace": {"range": {
                "sheetId": sheetId,
                "startRowIndex": start_row,
                "endRowIndex": end_row,
                "startColumnIndex": start_col,
                "endColumnIndex": end_col,
            }}}]},
        ).execute()
    except HttpError as e:
        return {"error": str(e)}

# -- Sheets: Delete Duplicates -------------------------------------------------

@mcp.tool()
def sheets_delete_duplicates(
    spreadsheetId: str,
    sheetId: int,
    start_row: int,
    end_row: int,
    start_col: int,
    end_col: int,
    comparison_columns: List[int] = [],
) -> dict:
    """
    Remove duplicate rows based on specified columns.

    Args:
        comparison_columns: List of 0-based column indices to compare.
            Empty list = compare all columns.
    """
    service = get_sheets_service()
    req: Dict[str, Any] = {
        "range": {
            "sheetId": sheetId,
            "startRowIndex": start_row,
            "endRowIndex": end_row,
            "startColumnIndex": start_col,
            "endColumnIndex": end_col,
        },
    }
    if comparison_columns:
        req["comparisonColumns"] = [
            {"sheetId": sheetId, "dimension": "COLUMNS", "startIndex": c, "endIndex": c + 1}
            for c in comparison_columns
        ]
    try:
        return service.spreadsheets().batchUpdate(
            spreadsheetId=spreadsheetId,
            body={"requests": [{"deleteDuplicates": req}]},
        ).execute()
    except HttpError as e:
        return {"error": str(e)}

# -- Sheets: Text to Columns --------------------------------------------------

@mcp.tool()
def sheets_text_to_columns(
    spreadsheetId: str,
    sheetId: int,
    start_row: int,
    end_row: int,
    col: int,
    delimiter_type: str = "AUTODETECT",
    custom_delimiter: str = "",
) -> dict:
    """
    Split a column of delimited text into multiple columns.

    Args:
        col: 0-based column index (must be a single column).
        delimiter_type: "COMMA", "SEMICOLON", "PERIOD", "SPACE", "CUSTOM", "AUTODETECT".
        custom_delimiter: Only used when delimiter_type is "CUSTOM".
    """
    service = get_sheets_service()
    req: Dict[str, Any] = {
        "source": {
            "sheetId": sheetId,
            "startRowIndex": start_row,
            "endRowIndex": end_row,
            "startColumnIndex": col,
            "endColumnIndex": col + 1,
        },
        "delimiterType": delimiter_type,
    }
    if delimiter_type == "CUSTOM" and custom_delimiter:
        req["delimiter"] = custom_delimiter
    try:
        return service.spreadsheets().batchUpdate(
            spreadsheetId=spreadsheetId,
            body={"requests": [{"textToColumns": req}]},
        ).execute()
    except HttpError as e:
        return {"error": str(e)}

# -- Sheets: Randomize Range ---------------------------------------------------

@mcp.tool()
def sheets_randomize_range(
    spreadsheetId: str, sheetId: int, start_row: int, end_row: int, start_col: int, end_col: int
) -> dict:
    """Shuffle/randomize the order of rows in a range."""
    service = get_sheets_service()
    try:
        return service.spreadsheets().batchUpdate(
            spreadsheetId=spreadsheetId,
            body={"requests": [{"randomizeRange": {"range": {
                "sheetId": sheetId,
                "startRowIndex": start_row,
                "endRowIndex": end_row,
                "startColumnIndex": start_col,
                "endColumnIndex": end_col,
            }}}]},
        ).execute()
    except HttpError as e:
        return {"error": str(e)}

# -- Sheets: Slicers -----------------------------------------------------------

@mcp.tool()
def sheets_add_slicer(
    spreadsheetId: str,
    sheetId: int,
    data_range_sheet_id: int,
    data_start_row: int,
    data_end_row: int,
    data_start_col: int,
    data_end_col: int,
    filter_column_index: int,
    anchor_row: int = 0,
    anchor_col: int = 0,
    title: str = "",
) -> dict:
    """
    Add an interactive slicer control for dashboard-style filtering.

    Args:
        data_range_*: The data range the slicer filters.
        filter_column_index: 0-based column index the slicer filters on.
        anchor_row/anchor_col: Where to place the slicer.
    """
    service = get_sheets_service()
    slicer: Dict[str, Any] = {
        "spec": {
            "dataRange": {
                "sheetId": data_range_sheet_id,
                "startRowIndex": data_start_row,
                "endRowIndex": data_end_row,
                "startColumnIndex": data_start_col,
                "endColumnIndex": data_end_col,
            },
            "filterColumnIndex": filter_column_index,
        },
        "position": {"overlayPosition": {
            "anchorCell": {"sheetId": sheetId, "rowIndex": anchor_row, "columnIndex": anchor_col},
        }},
    }
    if title:
        slicer["spec"]["title"] = title
    try:
        result = service.spreadsheets().batchUpdate(
            spreadsheetId=spreadsheetId,
            body={"requests": [{"addSlicer": {"slicer": slicer}}]},
        ).execute()
        return result["replies"][0].get("addSlicer", {})
    except HttpError as e:
        return {"error": str(e)}

@mcp.tool()
def sheets_update_slicer(
    spreadsheetId: str, slicer_id: int, spec: Dict[str, Any]
) -> dict:
    """
    Update a slicer's specifications.

    Args:
        slicer_id: The slicer's ID.
        spec: New SlicerSpec object (partial updates via fields mask).
    """
    service = get_sheets_service()
    try:
        return service.spreadsheets().batchUpdate(
            spreadsheetId=spreadsheetId,
            body={"requests": [{"updateSlicerSpec": {
                "slicerId": slicer_id,
                "spec": spec,
                "fields": "*",
            }}]},
        ).execute()
    except HttpError as e:
        return {"error": str(e)}

# -- Sheets: Generic Batch Update (Passthrough) --------------------------------

@mcp.tool()
def sheets_batch_update(spreadsheetId: str, requests: List[Dict[str, Any]]) -> dict:
    """
    Execute raw batchUpdate requests against the Sheets API.
    This is the escape hatch for any operation not covered by the dedicated tools above.
    Accepts the same request format as the Sheets API docs.

    Args:
        spreadsheetId: The spreadsheet ID.
        requests: List of request objects, e.g.:
            [{"updateSpreadsheetProperties": {"properties": {"title": "New Title"}, "fields": "title"}}]
    """
    service = get_sheets_service()
    try:
        return service.spreadsheets().batchUpdate(
            spreadsheetId=spreadsheetId,
            body={"requests": requests},
        ).execute()
    except HttpError as e:
        return {"error": str(e)}

# -- Gmail: Private helpers ----------------------------------------------------

def _parse_message_headers(headers: list) -> dict:
    """Extract common headers from Gmail payload headers list into a flat dict."""
    keys = {
        'from': 'from', 'to': 'to', 'cc': 'cc', 'bcc': 'bcc',
        'subject': 'subject', 'date': 'date', 'reply-to': 'reply_to',
        'message-id': 'message_id', 'in-reply-to': 'in_reply_to',
        'references': 'references',
    }
    result = {}
    for h in headers:
        name_lower = h.get('name', '').lower()
        if name_lower in keys:
            result[keys[name_lower]] = h.get('value', '')
    return result


def _decode_message_body(payload: dict) -> dict:
    """Recursively decode MIME parts and return {plain, html}."""
    plain_parts = []
    html_parts = []

    def _walk(part):
        mime = part.get('mimeType', '')
        body = part.get('body', {})
        data = body.get('data', '')
        if data:
            decoded = base64.urlsafe_b64decode(data + '==').decode('utf-8', errors='replace')
            if mime == 'text/plain':
                plain_parts.append(decoded)
            elif mime == 'text/html':
                html_parts.append(decoded)
        for sub in part.get('parts', []):
            _walk(sub)

    _walk(payload)
    return {
        'plain': '\n'.join(plain_parts),
        'html': '\n'.join(html_parts),
    }


def _build_raw_message(
    to: str,
    subject: str,
    body: str,
    from_addr: str = 'me',
    cc: str = '',
    bcc: str = '',
    reply_to: str = '',
    body_html: str = '',
    in_reply_to: str = '',
    references: str = '',
) -> str:
    """Build an RFC 2822 message and return it base64url-encoded."""
    if body_html:
        msg = email.mime.multipart.MIMEMultipart('alternative')
        msg.attach(email.mime.text.MIMEText(body, 'plain', 'utf-8'))
        msg.attach(email.mime.text.MIMEText(body_html, 'html', 'utf-8'))
    else:
        msg = email.mime.text.MIMEText(body, 'plain', 'utf-8')

    msg['to'] = to
    msg['subject'] = subject
    if cc:
        msg['cc'] = cc
    if bcc:
        msg['bcc'] = bcc
    if reply_to:
        msg['reply-to'] = reply_to
    if in_reply_to:
        msg['In-Reply-To'] = in_reply_to
    if references:
        msg['References'] = references

    raw = base64.urlsafe_b64encode(msg.as_bytes()).decode('utf-8')
    return raw


# -- Gmail: Group A — Profile --------------------------------------------------

@gmail_mcp.tool()
def gmail_get_profile() -> dict:
    """
    Get the current user's Gmail profile.

    Returns email address, total messages, total threads, and the current historyId.
    """
    service = get_gmail_service()
    try:
        return service.users().getProfile(userId='me').execute()
    except HttpError as e:
        return {"error": str(e)}


# -- Gmail: Group B — Labels ---------------------------------------------------

@gmail_mcp.tool()
def gmail_list_labels() -> dict:
    """List all Gmail labels (both system labels and user-created labels)."""
    service = get_gmail_service()
    try:
        return service.users().labels().list(userId='me').execute()
    except HttpError as e:
        return {"error": str(e)}


@gmail_mcp.tool()
def gmail_get_label(labelId: str) -> dict:
    """
    Get details for a specific Gmail label.

    Args:
        labelId: The label ID (e.g. 'INBOX', 'SENT', or a user label ID like 'Label_123').
    """
    service = get_gmail_service()
    try:
        return service.users().labels().get(userId='me', id=labelId).execute()
    except HttpError as e:
        return {"error": str(e)}


@gmail_mcp.tool()
def gmail_create_label(
    name: str,
    label_list_visibility: str = 'labelShow',
    message_list_visibility: str = 'show',
    background_color: str = '',
    text_color: str = '',
) -> dict:
    """
    Create a new Gmail user label.

    Args:
        name: Display name for the label.
        label_list_visibility: 'labelShow', 'labelShowIfUnread', or 'labelHide'.
        message_list_visibility: 'show' or 'hide'.
        background_color: Optional hex background color (e.g. '#ffffff').
        text_color: Optional hex text color (e.g. '#000000').
    """
    service = get_gmail_service()
    body: Dict[str, Any] = {
        'name': name,
        'labelListVisibility': label_list_visibility,
        'messageListVisibility': message_list_visibility,
    }
    if background_color or text_color:
        body['color'] = {}
        if background_color:
            body['color']['backgroundColor'] = background_color
        if text_color:
            body['color']['textColor'] = text_color
    try:
        return service.users().labels().create(userId='me', body=body).execute()
    except HttpError as e:
        return {"error": str(e)}


@gmail_mcp.tool()
def gmail_update_label(
    labelId: str,
    name: str = '',
    label_list_visibility: str = '',
    message_list_visibility: str = '',
    background_color: str = '',
    text_color: str = '',
) -> dict:
    """
    Update an existing Gmail label (rename, recolor, or change visibility).

    Args:
        labelId: The label ID to update.
        name: New display name (omit to keep current).
        label_list_visibility: 'labelShow', 'labelShowIfUnread', or 'labelHide'.
        message_list_visibility: 'show' or 'hide'.
        background_color: Hex background color.
        text_color: Hex text color.
    """
    service = get_gmail_service()
    body: Dict[str, Any] = {'id': labelId}
    if name:
        body['name'] = name
    if label_list_visibility:
        body['labelListVisibility'] = label_list_visibility
    if message_list_visibility:
        body['messageListVisibility'] = message_list_visibility
    if background_color or text_color:
        body['color'] = {}
        if background_color:
            body['color']['backgroundColor'] = background_color
        if text_color:
            body['color']['textColor'] = text_color
    try:
        return service.users().labels().update(userId='me', id=labelId, body=body).execute()
    except HttpError as e:
        return {"error": str(e)}


@gmail_mcp.tool()
def gmail_delete_label(labelId: str) -> dict:
    """
    Permanently delete a user-created Gmail label.

    Args:
        labelId: The label ID to delete. System labels (INBOX, SENT, etc.) cannot be deleted.
    """
    service = get_gmail_service()
    try:
        service.users().labels().delete(userId='me', id=labelId).execute()
        return {"deleted": True, "labelId": labelId}
    except HttpError as e:
        return {"error": str(e)}


# -- Gmail: Group C — Messages -------------------------------------------------

@gmail_mcp.tool()
def gmail_list_messages(
    query: str = '',
    max_results: int = 10,
    page_token: str = '',
    label_ids: List[str] = [],
    include_spam_trash: bool = False,
) -> dict:
    """
    Search or list Gmail messages.

    Args:
        query: Gmail search query (e.g. 'is:unread from:boss@company.com').
        max_results: Maximum messages to return (default 10, max 500).
        page_token: Token for pagination (from a previous response).
        label_ids: Filter by label IDs (e.g. ['INBOX', 'UNREAD']).
        include_spam_trash: Include messages from SPAM and TRASH.
    """
    service = get_gmail_service()
    params: Dict[str, Any] = {
        'userId': 'me',
        'maxResults': max_results,
        'includeSpamTrash': include_spam_trash,
    }
    if query:
        params['q'] = query
    if page_token:
        params['pageToken'] = page_token
    if label_ids:
        params['labelIds'] = label_ids
    try:
        return service.users().messages().list(**params).execute()
    except HttpError as e:
        return {"error": str(e)}


@gmail_mcp.tool()
def gmail_get_message(messageId: str, format: str = 'full') -> dict:
    """
    Get a Gmail message with decoded headers and body.

    Args:
        messageId: The message ID.
        format: 'full' (default), 'metadata', 'minimal', or 'raw'.

    Returns a shaped dict with id, threadId, labelIds, snippet, headers, body, sizeEstimate, internalDate.
    """
    service = get_gmail_service()
    try:
        msg = service.users().messages().get(
            userId='me', id=messageId, format=format
        ).execute()
        payload = msg.get('payload', {})
        return {
            'id': msg.get('id'),
            'threadId': msg.get('threadId'),
            'labelIds': msg.get('labelIds', []),
            'snippet': msg.get('snippet', ''),
            'headers': _parse_message_headers(payload.get('headers', [])),
            'body': _decode_message_body(payload),
            'sizeEstimate': msg.get('sizeEstimate'),
            'internalDate': msg.get('internalDate'),
        }
    except HttpError as e:
        return {"error": str(e)}


@gmail_mcp.tool()
def gmail_send_message(
    to: str,
    subject: str,
    body: str,
    cc: str = '',
    bcc: str = '',
    reply_to: str = '',
    body_html: str = '',
) -> dict:
    """
    Send a new email via Gmail.

    Args:
        to: Recipient email address (or comma-separated list).
        subject: Email subject.
        body: Plain-text email body.
        cc: CC recipients (comma-separated).
        bcc: BCC recipients (comma-separated).
        reply_to: Reply-To address.
        body_html: HTML version of the body (creates multipart/alternative if provided).
    """
    service = get_gmail_service()
    raw = _build_raw_message(
        to=to, subject=subject, body=body,
        cc=cc, bcc=bcc, reply_to=reply_to, body_html=body_html,
    )
    try:
        return service.users().messages().send(
            userId='me', body={'raw': raw}
        ).execute()
    except HttpError as e:
        return {"error": str(e)}


@gmail_mcp.tool()
def gmail_reply_to_message(
    messageId: str,
    body: str,
    body_html: str = '',
    reply_all: bool = False,
) -> dict:
    """
    Reply to an existing Gmail message, automatically threading correctly.

    Args:
        messageId: The message ID to reply to.
        body: Plain-text reply body.
        body_html: HTML version of the reply body.
        reply_all: If True, reply to all recipients (CC included).
    """
    service = get_gmail_service()
    try:
        orig = service.users().messages().get(
            userId='me', id=messageId, format='full'
        ).execute()
        payload = orig.get('payload', {})
        headers = _parse_message_headers(payload.get('headers', []))
        thread_id = orig.get('threadId', '')
        to = headers.get('from', '')
        subject = headers.get('subject', '')
        if not subject.lower().startswith('re:'):
            subject = 'Re: ' + subject
        cc = ''
        if reply_all:
            cc_parts = [v for k, v in headers.items() if k in ('to', 'cc') and v]
            cc = ', '.join(cc_parts)
        raw = _build_raw_message(
            to=to, subject=subject, body=body, body_html=body_html, cc=cc,
            in_reply_to=headers.get('message_id', ''),
            references=' '.join(filter(None, [
                headers.get('references', ''), headers.get('message_id', '')
            ])),
        )
        return service.users().messages().send(
            userId='me', body={'raw': raw, 'threadId': thread_id}
        ).execute()
    except HttpError as e:
        return {"error": str(e)}


@gmail_mcp.tool()
def gmail_trash_message(messageId: str) -> dict:
    """
    Move a Gmail message to Trash (reversible).

    Args:
        messageId: The message ID to trash.
    """
    service = get_gmail_service()
    try:
        return service.users().messages().trash(userId='me', id=messageId).execute()
    except HttpError as e:
        return {"error": str(e)}


@gmail_mcp.tool()
def gmail_untrash_message(messageId: str) -> dict:
    """
    Restore a Gmail message from Trash.

    Args:
        messageId: The message ID to untrash.
    """
    service = get_gmail_service()
    try:
        return service.users().messages().untrash(userId='me', id=messageId).execute()
    except HttpError as e:
        return {"error": str(e)}


@gmail_mcp.tool()
def gmail_delete_message(messageId: str) -> dict:
    """
    Permanently delete a Gmail message (irreversible).

    Args:
        messageId: The message ID to permanently delete.
    """
    service = get_gmail_service()
    try:
        service.users().messages().delete(userId='me', id=messageId).execute()
        return {"deleted": True, "messageId": messageId}
    except HttpError as e:
        return {"error": str(e)}


@gmail_mcp.tool()
def gmail_modify_message_labels(
    messageId: str,
    add_label_ids: List[str] = [],
    remove_label_ids: List[str] = [],
) -> dict:
    """
    Add or remove labels on a Gmail message.

    Args:
        messageId: The message ID to modify.
        add_label_ids: Label IDs to add (e.g. ['STARRED']).
        remove_label_ids: Label IDs to remove (e.g. ['UNREAD']).
    """
    service = get_gmail_service()
    try:
        return service.users().messages().modify(
            userId='me', id=messageId,
            body={'addLabelIds': add_label_ids, 'removeLabelIds': remove_label_ids},
        ).execute()
    except HttpError as e:
        return {"error": str(e)}


@gmail_mcp.tool()
def gmail_mark_read(messageId: str) -> dict:
    """
    Mark a Gmail message as read (removes UNREAD label).

    Args:
        messageId: The message ID to mark as read.
    """
    return gmail_modify_message_labels(messageId, remove_label_ids=['UNREAD'])


@gmail_mcp.tool()
def gmail_mark_unread(messageId: str) -> dict:
    """
    Mark a Gmail message as unread (adds UNREAD label).

    Args:
        messageId: The message ID to mark as unread.
    """
    return gmail_modify_message_labels(messageId, add_label_ids=['UNREAD'])


# -- Gmail: Group D — Threads --------------------------------------------------

@gmail_mcp.tool()
def gmail_list_threads(
    query: str = '',
    max_results: int = 10,
    page_token: str = '',
    label_ids: List[str] = [],
    include_spam_trash: bool = False,
) -> dict:
    """
    Search or list Gmail threads.

    Args:
        query: Gmail search query (e.g. 'is:unread subject:invoice').
        max_results: Maximum threads to return (default 10, max 500).
        page_token: Token for pagination.
        label_ids: Filter by label IDs.
        include_spam_trash: Include threads from SPAM and TRASH.
    """
    service = get_gmail_service()
    params: Dict[str, Any] = {
        'userId': 'me',
        'maxResults': max_results,
        'includeSpamTrash': include_spam_trash,
    }
    if query:
        params['q'] = query
    if page_token:
        params['pageToken'] = page_token
    if label_ids:
        params['labelIds'] = label_ids
    try:
        return service.users().threads().list(**params).execute()
    except HttpError as e:
        return {"error": str(e)}


@gmail_mcp.tool()
def gmail_get_thread(threadId: str, format: str = 'full') -> dict:
    """
    Get all messages in a Gmail thread with decoded headers.

    Args:
        threadId: The thread ID.
        format: 'full' (default), 'metadata', or 'minimal'.
    """
    service = get_gmail_service()
    try:
        thread = service.users().threads().get(
            userId='me', id=threadId, format=format
        ).execute()
        messages = []
        for msg in thread.get('messages', []):
            payload = msg.get('payload', {})
            messages.append({
                'id': msg.get('id'),
                'labelIds': msg.get('labelIds', []),
                'snippet': msg.get('snippet', ''),
                'headers': _parse_message_headers(payload.get('headers', [])),
                'body': _decode_message_body(payload),
                'internalDate': msg.get('internalDate'),
            })
        return {
            'id': thread.get('id'),
            'snippet': thread.get('snippet', ''),
            'historyId': thread.get('historyId'),
            'messages': messages,
        }
    except HttpError as e:
        return {"error": str(e)}


@gmail_mcp.tool()
def gmail_modify_thread_labels(
    threadId: str,
    add_label_ids: List[str] = [],
    remove_label_ids: List[str] = [],
) -> dict:
    """
    Add or remove labels on all messages in a Gmail thread.

    Args:
        threadId: The thread ID.
        add_label_ids: Label IDs to add.
        remove_label_ids: Label IDs to remove.
    """
    service = get_gmail_service()
    try:
        return service.users().threads().modify(
            userId='me', id=threadId,
            body={'addLabelIds': add_label_ids, 'removeLabelIds': remove_label_ids},
        ).execute()
    except HttpError as e:
        return {"error": str(e)}


@gmail_mcp.tool()
def gmail_trash_thread(threadId: str) -> dict:
    """
    Move an entire Gmail thread to Trash (reversible).

    Args:
        threadId: The thread ID to trash.
    """
    service = get_gmail_service()
    try:
        return service.users().threads().trash(userId='me', id=threadId).execute()
    except HttpError as e:
        return {"error": str(e)}


@gmail_mcp.tool()
def gmail_untrash_thread(threadId: str) -> dict:
    """
    Restore an entire Gmail thread from Trash.

    Args:
        threadId: The thread ID to restore.
    """
    service = get_gmail_service()
    try:
        return service.users().threads().untrash(userId='me', id=threadId).execute()
    except HttpError as e:
        return {"error": str(e)}


@gmail_mcp.tool()
def gmail_delete_thread(threadId: str) -> dict:
    """
    Permanently delete an entire Gmail thread (irreversible).

    Args:
        threadId: The thread ID to permanently delete.
    """
    service = get_gmail_service()
    try:
        service.users().threads().delete(userId='me', id=threadId).execute()
        return {"deleted": True, "threadId": threadId}
    except HttpError as e:
        return {"error": str(e)}


# -- Gmail: Group E — Drafts ---------------------------------------------------

@gmail_mcp.tool()
def gmail_list_drafts(
    max_results: int = 10,
    page_token: str = '',
) -> dict:
    """
    List Gmail drafts.

    Args:
        max_results: Maximum drafts to return (default 10).
        page_token: Token for pagination.
    """
    service = get_gmail_service()
    params: Dict[str, Any] = {'userId': 'me', 'maxResults': max_results}
    if page_token:
        params['pageToken'] = page_token
    try:
        return service.users().drafts().list(**params).execute()
    except HttpError as e:
        return {"error": str(e)}


@gmail_mcp.tool()
def gmail_get_draft(draftId: str) -> dict:
    """
    Get a Gmail draft with decoded headers and body.

    Args:
        draftId: The draft ID.
    """
    service = get_gmail_service()
    try:
        draft = service.users().drafts().get(userId='me', id=draftId, format='full').execute()
        msg = draft.get('message', {})
        payload = msg.get('payload', {})
        return {
            'id': draft.get('id'),
            'message': {
                'id': msg.get('id'),
                'threadId': msg.get('threadId'),
                'labelIds': msg.get('labelIds', []),
                'snippet': msg.get('snippet', ''),
                'headers': _parse_message_headers(payload.get('headers', [])),
                'body': _decode_message_body(payload),
            },
        }
    except HttpError as e:
        return {"error": str(e)}


@gmail_mcp.tool()
def gmail_create_draft(
    to: str,
    subject: str,
    body: str,
    cc: str = '',
    bcc: str = '',
    body_html: str = '',
) -> dict:
    """
    Create a Gmail draft (does not send).

    Args:
        to: Recipient email address.
        subject: Email subject.
        body: Plain-text body.
        cc: CC recipients (comma-separated).
        bcc: BCC recipients (comma-separated).
        body_html: HTML body (creates multipart/alternative if provided).
    """
    service = get_gmail_service()
    raw = _build_raw_message(to=to, subject=subject, body=body, cc=cc, bcc=bcc, body_html=body_html)
    try:
        return service.users().drafts().create(
            userId='me', body={'message': {'raw': raw}}
        ).execute()
    except HttpError as e:
        return {"error": str(e)}


@gmail_mcp.tool()
def gmail_update_draft(
    draftId: str,
    to: str,
    subject: str,
    body: str,
    cc: str = '',
    bcc: str = '',
    body_html: str = '',
) -> dict:
    """
    Replace the content of an existing Gmail draft.

    Args:
        draftId: The draft ID to update.
        to: Recipient email address.
        subject: Email subject.
        body: Plain-text body.
        cc: CC recipients (comma-separated).
        bcc: BCC recipients (comma-separated).
        body_html: HTML body.
    """
    service = get_gmail_service()
    raw = _build_raw_message(to=to, subject=subject, body=body, cc=cc, bcc=bcc, body_html=body_html)
    try:
        return service.users().drafts().update(
            userId='me', id=draftId, body={'message': {'raw': raw}}
        ).execute()
    except HttpError as e:
        return {"error": str(e)}


@gmail_mcp.tool()
def gmail_send_draft(draftId: str) -> dict:
    """
    Send an existing Gmail draft.

    Args:
        draftId: The draft ID to send.
    """
    service = get_gmail_service()
    try:
        return service.users().drafts().send(
            userId='me', body={'id': draftId}
        ).execute()
    except HttpError as e:
        return {"error": str(e)}


@gmail_mcp.tool()
def gmail_delete_draft(draftId: str) -> dict:
    """
    Discard (permanently delete) a Gmail draft.

    Args:
        draftId: The draft ID to delete.
    """
    service = get_gmail_service()
    try:
        service.users().drafts().delete(userId='me', id=draftId).execute()
        return {"deleted": True, "draftId": draftId}
    except HttpError as e:
        return {"error": str(e)}


# -- Gmail: Group F — Attachments ----------------------------------------------

@gmail_mcp.tool()
def gmail_get_attachment(messageId: str, attachmentId: str) -> dict:
    """
    Retrieve a Gmail attachment as base64url-encoded data.

    The attachmentId can be found in the payload parts returned by gmail_get_message.

    Args:
        messageId: The message ID containing the attachment.
        attachmentId: The attachment ID from the message payload.
    """
    service = get_gmail_service()
    try:
        return service.users().messages().attachments().get(
            userId='me', messageId=messageId, id=attachmentId
        ).execute()
    except HttpError as e:
        return {"error": str(e)}


# -- Gmail: Group G — Batch operations & import --------------------------------

@gmail_mcp.tool()
def gmail_batch_delete_messages(message_ids: List[str]) -> dict:
    """
    Permanently delete multiple Gmail messages in one API call.

    Args:
        message_ids: List of message IDs to permanently delete.
    """
    service = get_gmail_service()
    try:
        service.users().messages().batchDelete(
            userId='me', body={'ids': message_ids}
        ).execute()
        return {"deleted": True, "count": len(message_ids)}
    except HttpError as e:
        return {"error": str(e)}


@gmail_mcp.tool()
def gmail_batch_modify_messages(
    message_ids: List[str],
    add_label_ids: List[str] = [],
    remove_label_ids: List[str] = [],
) -> dict:
    """
    Apply label changes to multiple Gmail messages in one API call.

    Args:
        message_ids: List of message IDs to modify.
        add_label_ids: Label IDs to add to all specified messages.
        remove_label_ids: Label IDs to remove from all specified messages.
    """
    service = get_gmail_service()
    try:
        service.users().messages().batchModify(
            userId='me',
            body={
                'ids': message_ids,
                'addLabelIds': add_label_ids,
                'removeLabelIds': remove_label_ids,
            },
        ).execute()
        return {"modified": True, "count": len(message_ids)}
    except HttpError as e:
        return {"error": str(e)}


@gmail_mcp.tool()
def gmail_insert_message(
    raw: str,
    label_ids: List[str] = [],
    internal_date_source: str = 'receivedTime',
    deleted: bool = False,
) -> dict:
    """
    Insert a message into a Gmail mailbox without sending it (e.g. for archiving external mail).

    Args:
        raw: Base64url-encoded RFC 2822 message string.
        label_ids: Labels to apply to the inserted message.
        internal_date_source: 'receivedTime' (default) or 'dateHeader'.
        deleted: If True, insert into TRASH immediately.
    """
    service = get_gmail_service()
    try:
        return service.users().messages().insert(
            userId='me',
            internalDateSource=internal_date_source,
            deleted=deleted,
            body={'raw': raw, 'labelIds': label_ids},
        ).execute()
    except HttpError as e:
        return {"error": str(e)}


@gmail_mcp.tool()
def gmail_import_message(
    raw: str,
    label_ids: List[str] = [],
    deleted: bool = False,
    never_mark_spam: bool = False,
    process_for_calendar: bool = True,
) -> dict:
    """
    Import a message into Gmail with standard email delivery processing (spam filtering, etc.).

    Args:
        raw: Base64url-encoded RFC 2822 message string.
        label_ids: Labels to apply.
        deleted: If True, mark as deleted immediately.
        never_mark_spam: If True, bypass spam filtering.
        process_for_calendar: If True, process calendar invites in the message.
    """
    service = get_gmail_service()
    try:
        return service.users().messages().import_(
            userId='me',
            neverMarkSpam=never_mark_spam,
            processForCalendar=process_for_calendar,
            deleted=deleted,
            body={'raw': raw, 'labelIds': label_ids},
        ).execute()
    except HttpError as e:
        return {"error": str(e)}


# -- Gmail: Group H — History --------------------------------------------------

@gmail_mcp.tool()
def gmail_list_history(
    start_history_id: str,
    max_results: int = 100,
    page_token: str = '',
    label_id: str = '',
    history_types: List[str] = [],
) -> dict:
    """
    Get mailbox changes since a given historyId (incremental sync).

    Args:
        start_history_id: The historyId to start from (from gmail_get_profile or a previous response).
        max_results: Maximum history records to return (default 100).
        page_token: Token for pagination.
        label_id: Only return history for messages with this label.
        history_types: Filter types: 'messageAdded', 'messageDeleted', 'labelAdded', 'labelRemoved'.
    """
    service = get_gmail_service()
    params: Dict[str, Any] = {
        'userId': 'me',
        'startHistoryId': start_history_id,
        'maxResults': max_results,
    }
    if page_token:
        params['pageToken'] = page_token
    if label_id:
        params['labelId'] = label_id
    if history_types:
        params['historyTypes'] = history_types
    try:
        return service.users().history().list(**params).execute()
    except HttpError as e:
        return {"error": str(e)}


# -- Gmail: Group I — Push notifications ---------------------------------------

@gmail_mcp.tool()
def gmail_watch(
    topic_name: str,
    label_ids: List[str] = [],
    label_filter_behavior: str = 'include',
) -> dict:
    """
    Start push notifications to a Google Cloud Pub/Sub topic.

    Returns historyId and expiration timestamp. Watches expire after ~7 days and must be renewed.

    Args:
        topic_name: Pub/Sub topic name (e.g. 'projects/my-project/topics/gmail-push').
        label_ids: Only notify for changes to messages with these labels. Empty means all labels.
        label_filter_behavior: 'include' (default) or 'exclude' the specified label_ids.
    """
    service = get_gmail_service()
    body: Dict[str, Any] = {
        'topicName': topic_name,
        'labelFilterBehavior': label_filter_behavior,
    }
    if label_ids:
        body['labelIds'] = label_ids
    try:
        return service.users().watch(userId='me', body=body).execute()
    except HttpError as e:
        return {"error": str(e)}


@gmail_mcp.tool()
def gmail_stop_watch() -> dict:
    """Stop receiving Gmail push notifications for the current user."""
    service = get_gmail_service()
    try:
        service.users().stop(userId='me').execute()
        return {"stopped": True}
    except HttpError as e:
        return {"error": str(e)}


# -- Gmail: Group J — Settings: Basic ------------------------------------------

@gmail_mcp.tool()
def gmail_get_auto_forwarding() -> dict:
    """Get the auto-forwarding configuration for the Gmail account."""
    service = get_gmail_service()
    try:
        return service.users().settings().getAutoForwarding(userId='me').execute()
    except HttpError as e:
        return {"error": str(e)}


@gmail_mcp.tool()
def gmail_update_auto_forwarding(
    enabled: bool,
    email_address: str = '',
    disposition: str = 'leaveInInbox',
) -> dict:
    """
    Enable or disable Gmail auto-forwarding.

    Args:
        enabled: True to enable auto-forwarding, False to disable.
        email_address: The verified address to forward to (required when enabled=True).
        disposition: What to do with forwarded messages: 'leaveInInbox', 'archive', 'trash', 'markRead'.
    """
    service = get_gmail_service()
    body: Dict[str, Any] = {'enabled': enabled, 'disposition': disposition}
    if email_address:
        body['emailAddress'] = email_address
    try:
        return service.users().settings().updateAutoForwarding(userId='me', body=body).execute()
    except HttpError as e:
        return {"error": str(e)}


@gmail_mcp.tool()
def gmail_get_imap() -> dict:
    """Get the IMAP settings for the Gmail account."""
    service = get_gmail_service()
    try:
        return service.users().settings().getImap(userId='me').execute()
    except HttpError as e:
        return {"error": str(e)}


@gmail_mcp.tool()
def gmail_update_imap(
    enabled: bool,
    auto_expunge: bool = True,
    expunge_behavior: str = 'archive',
    max_folder_size: int = 0,
) -> dict:
    """
    Configure IMAP access for the Gmail account.

    Args:
        enabled: True to enable IMAP.
        auto_expunge: Auto-expunge messages marked for deletion.
        expunge_behavior: 'archive', 'trash', or 'deleteForever'.
        max_folder_size: Maximum folder size in MB (0 = unlimited).
    """
    service = get_gmail_service()
    body: Dict[str, Any] = {
        'enabled': enabled,
        'autoExpunge': auto_expunge,
        'expungeBehavior': expunge_behavior,
        'maxFolderSize': max_folder_size,
    }
    try:
        return service.users().settings().updateImap(userId='me', body=body).execute()
    except HttpError as e:
        return {"error": str(e)}


@gmail_mcp.tool()
def gmail_get_language() -> dict:
    """Get the display language setting for the Gmail account."""
    service = get_gmail_service()
    try:
        return service.users().settings().getLanguage(userId='me').execute()
    except HttpError as e:
        return {"error": str(e)}


@gmail_mcp.tool()
def gmail_update_language(display_language: str) -> dict:
    """
    Set the display language for the Gmail account.

    Args:
        display_language: BCP 47 language tag (e.g. 'en' for English, 'tl' for Filipino).
    """
    service = get_gmail_service()
    try:
        return service.users().settings().updateLanguage(
            userId='me', body={'displayLanguage': display_language}
        ).execute()
    except HttpError as e:
        return {"error": str(e)}


@gmail_mcp.tool()
def gmail_get_pop() -> dict:
    """Get the POP settings for the Gmail account."""
    service = get_gmail_service()
    try:
        return service.users().settings().getPop(userId='me').execute()
    except HttpError as e:
        return {"error": str(e)}


@gmail_mcp.tool()
def gmail_update_pop(
    access_window: str = 'disabled',
    disposition: str = 'leaveInInbox',
) -> dict:
    """
    Configure POP access for the Gmail account.

    Args:
        access_window: 'disabled', 'fromNowOn', or 'allMail'.
        disposition: What to do with POP-accessed messages: 'leaveInInbox', 'archive', 'trash', 'markRead'.
    """
    service = get_gmail_service()
    try:
        return service.users().settings().updatePop(
            userId='me', body={'accessWindow': access_window, 'disposition': disposition}
        ).execute()
    except HttpError as e:
        return {"error": str(e)}


@gmail_mcp.tool()
def gmail_get_vacation() -> dict:
    """Get the vacation auto-responder settings for the Gmail account."""
    service = get_gmail_service()
    try:
        return service.users().settings().getVacation(userId='me').execute()
    except HttpError as e:
        return {"error": str(e)}


@gmail_mcp.tool()
def gmail_update_vacation(
    enable_auto_reply: bool,
    response_subject: str = '',
    response_body_plain_text: str = '',
    response_body_html: str = '',
    restrict_to_contacts: bool = False,
    restrict_to_domain: bool = False,
    start_time: int = 0,
    end_time: int = 0,
) -> dict:
    """
    Configure the Gmail vacation / out-of-office auto-responder.

    Args:
        enable_auto_reply: True to enable the auto-responder.
        response_subject: Subject line of the auto-reply.
        response_body_plain_text: Plain-text auto-reply body.
        response_body_html: HTML auto-reply body.
        restrict_to_contacts: Only reply to people in your contacts.
        restrict_to_domain: Only reply to people in your Google Workspace domain.
        start_time: Start time in milliseconds since epoch (0 = no start restriction).
        end_time: End time in milliseconds since epoch (0 = no end restriction).
    """
    service = get_gmail_service()
    body: Dict[str, Any] = {
        'enableAutoReply': enable_auto_reply,
        'restrictToContacts': restrict_to_contacts,
        'restrictToDomain': restrict_to_domain,
    }
    if response_subject:
        body['responseSubject'] = response_subject
    if response_body_plain_text:
        body['responseBodyPlainText'] = response_body_plain_text
    if response_body_html:
        body['responseBodyHtml'] = response_body_html
    if start_time:
        body['startTime'] = start_time
    if end_time:
        body['endTime'] = end_time
    try:
        return service.users().settings().updateVacation(userId='me', body=body).execute()
    except HttpError as e:
        return {"error": str(e)}


# -- Gmail: Group K — Settings: Filters ----------------------------------------

@gmail_mcp.tool()
def gmail_list_filters() -> dict:
    """List all Gmail message filters for the account."""
    service = get_gmail_service()
    try:
        return service.users().settings().filters().list(userId='me').execute()
    except HttpError as e:
        return {"error": str(e)}


@gmail_mcp.tool()
def gmail_get_filter(filterId: str) -> dict:
    """
    Get a specific Gmail message filter.

    Args:
        filterId: The filter ID.
    """
    service = get_gmail_service()
    try:
        return service.users().settings().filters().get(userId='me', id=filterId).execute()
    except HttpError as e:
        return {"error": str(e)}


@gmail_mcp.tool()
def gmail_create_filter(
    criteria: Dict[str, Any],
    action: Dict[str, Any],
) -> dict:
    """
    Create a Gmail message filter.

    Args:
        criteria: Filter criteria dict. Supported keys:
            from, to, subject, query, negatedQuery, hasAttachment (bool), size, sizeComparison.
            Example: {"from": "boss@company.com", "hasAttachment": true}
        action: Action dict. Supported keys:
            addLabelIds (list), removeLabelIds (list), forward (email string).
            Example: {"addLabelIds": ["STARRED"], "removeLabelIds": ["INBOX"]}
    """
    service = get_gmail_service()
    try:
        return service.users().settings().filters().create(
            userId='me', body={'criteria': criteria, 'action': action}
        ).execute()
    except HttpError as e:
        return {"error": str(e)}


@gmail_mcp.tool()
def gmail_delete_filter(filterId: str) -> dict:
    """
    Delete a Gmail message filter.

    Args:
        filterId: The filter ID to delete.
    """
    service = get_gmail_service()
    try:
        service.users().settings().filters().delete(userId='me', id=filterId).execute()
        return {"deleted": True, "filterId": filterId}
    except HttpError as e:
        return {"error": str(e)}


# -- Gmail: Group L — Settings: Forwarding addresses ---------------------------

@gmail_mcp.tool()
def gmail_list_forwarding_addresses() -> dict:
    """List all verified forwarding addresses for the Gmail account."""
    service = get_gmail_service()
    try:
        return service.users().settings().forwardingAddresses().list(userId='me').execute()
    except HttpError as e:
        return {"error": str(e)}


@gmail_mcp.tool()
def gmail_get_forwarding_address(forwardingEmail: str) -> dict:
    """
    Get a specific forwarding address and its verification status.

    Args:
        forwardingEmail: The forwarding email address to look up.
    """
    service = get_gmail_service()
    try:
        return service.users().settings().forwardingAddresses().get(
            userId='me', forwardingEmail=forwardingEmail
        ).execute()
    except HttpError as e:
        return {"error": str(e)}


@gmail_mcp.tool()
def gmail_create_forwarding_address(forwardingEmail: str) -> dict:
    """
    Add a new forwarding address (triggers a verification email to that address).

    Args:
        forwardingEmail: The email address to add as a forwarding destination.
    """
    service = get_gmail_service()
    try:
        return service.users().settings().forwardingAddresses().create(
            userId='me', body={'forwardingEmail': forwardingEmail}
        ).execute()
    except HttpError as e:
        return {"error": str(e)}


@gmail_mcp.tool()
def gmail_delete_forwarding_address(forwardingEmail: str) -> dict:
    """
    Remove a forwarding address from the Gmail account.

    Args:
        forwardingEmail: The forwarding email address to remove.
    """
    service = get_gmail_service()
    try:
        service.users().settings().forwardingAddresses().delete(
            userId='me', forwardingEmail=forwardingEmail
        ).execute()
        return {"deleted": True, "forwardingEmail": forwardingEmail}
    except HttpError as e:
        return {"error": str(e)}


# -- Gmail: Group M — Settings: Send-as aliases --------------------------------

@gmail_mcp.tool()
def gmail_list_send_as() -> dict:
    """List all send-as aliases for the Gmail account."""
    service = get_gmail_service()
    try:
        return service.users().settings().sendAs().list(userId='me').execute()
    except HttpError as e:
        return {"error": str(e)}


@gmail_mcp.tool()
def gmail_get_send_as(sendAsEmail: str) -> dict:
    """
    Get details of a specific send-as alias.

    Args:
        sendAsEmail: The send-as email address.
    """
    service = get_gmail_service()
    try:
        return service.users().settings().sendAs().get(
            userId='me', sendAsEmail=sendAsEmail
        ).execute()
    except HttpError as e:
        return {"error": str(e)}


@gmail_mcp.tool()
def gmail_create_send_as(
    sendAsEmail: str,
    displayName: str = '',
    reply_to_address: str = '',
    is_default: bool = False,
    treat_as_alias: bool = True,
) -> dict:
    """
    Create a new send-as alias for the Gmail account.

    Args:
        sendAsEmail: The email address to send as.
        displayName: Display name shown to recipients.
        reply_to_address: Reply-To address for this alias.
        is_default: Make this the default send-as address.
        treat_as_alias: Treat as alias (True) or external address (False).
    """
    service = get_gmail_service()
    body: Dict[str, Any] = {
        'sendAsEmail': sendAsEmail,
        'isDefault': is_default,
        'treatAsAlias': treat_as_alias,
    }
    if displayName:
        body['displayName'] = displayName
    if reply_to_address:
        body['replyToAddress'] = reply_to_address
    try:
        return service.users().settings().sendAs().create(userId='me', body=body).execute()
    except HttpError as e:
        return {"error": str(e)}


@gmail_mcp.tool()
def gmail_update_send_as(
    sendAsEmail: str,
    displayName: str = '',
    reply_to_address: str = '',
    is_default: bool = False,
    treat_as_alias: bool = True,
) -> dict:
    """
    Update an existing send-as alias.

    Args:
        sendAsEmail: The send-as email address to update.
        displayName: New display name.
        reply_to_address: New Reply-To address.
        is_default: Make this the default send-as address.
        treat_as_alias: Treat as alias (True) or external address (False).
    """
    service = get_gmail_service()
    body: Dict[str, Any] = {
        'sendAsEmail': sendAsEmail,
        'isDefault': is_default,
        'treatAsAlias': treat_as_alias,
    }
    if displayName:
        body['displayName'] = displayName
    if reply_to_address:
        body['replyToAddress'] = reply_to_address
    try:
        return service.users().settings().sendAs().update(
            userId='me', sendAsEmail=sendAsEmail, body=body
        ).execute()
    except HttpError as e:
        return {"error": str(e)}


@gmail_mcp.tool()
def gmail_delete_send_as(sendAsEmail: str) -> dict:
    """
    Remove a send-as alias from the Gmail account.

    Args:
        sendAsEmail: The send-as email address to remove.
    """
    service = get_gmail_service()
    try:
        service.users().settings().sendAs().delete(
            userId='me', sendAsEmail=sendAsEmail
        ).execute()
        return {"deleted": True, "sendAsEmail": sendAsEmail}
    except HttpError as e:
        return {"error": str(e)}


@gmail_mcp.tool()
def gmail_verify_send_as(sendAsEmail: str) -> dict:
    """
    Re-send the verification email for a send-as alias.

    Args:
        sendAsEmail: The send-as email address to verify.
    """
    service = get_gmail_service()
    try:
        service.users().settings().sendAs().verify(
            userId='me', sendAsEmail=sendAsEmail
        ).execute()
        return {"verificationSent": True, "sendAsEmail": sendAsEmail}
    except HttpError as e:
        return {"error": str(e)}


# -- Gmail: Group N — Settings: Delegates --------------------------------------

@gmail_mcp.tool()
def gmail_list_delegates() -> dict:
    """List all delegates (accounts that can access this Gmail mailbox)."""
    service = get_gmail_service()
    try:
        return service.users().settings().delegates().list(userId='me').execute()
    except HttpError as e:
        return {"error": str(e)}


@gmail_mcp.tool()
def gmail_get_delegate(delegateEmail: str) -> dict:
    """
    Get a delegate and their verification status.

    Args:
        delegateEmail: The delegate's email address.
    """
    service = get_gmail_service()
    try:
        return service.users().settings().delegates().get(
            userId='me', delegateEmail=delegateEmail
        ).execute()
    except HttpError as e:
        return {"error": str(e)}


@gmail_mcp.tool()
def gmail_create_delegate(delegateEmail: str) -> dict:
    """
    Add a delegate (triggers a verification email to the delegate).

    Args:
        delegateEmail: The email address of the account to grant delegate access.
    """
    service = get_gmail_service()
    try:
        return service.users().settings().delegates().create(
            userId='me', body={'delegateEmail': delegateEmail}
        ).execute()
    except HttpError as e:
        return {"error": str(e)}


@gmail_mcp.tool()
def gmail_delete_delegate(delegateEmail: str) -> dict:
    """
    Remove a delegate from the Gmail account.

    Args:
        delegateEmail: The delegate's email address to remove.
    """
    service = get_gmail_service()
    try:
        service.users().settings().delegates().delete(
            userId='me', delegateEmail=delegateEmail
        ).execute()
        return {"deleted": True, "delegateEmail": delegateEmail}
    except HttpError as e:
        return {"error": str(e)}


# -- Gmail ASGI dispatcher -----------------------------------------------------

class _GmailDispatcher:
    """
    Pure ASGI router: strips /gmail prefix and forwards to gmail_app.
    Everything else goes to drive_app unchanged.
    Avoids Starlette Mount's path-stripping bug with the root prefix.
    """
    def __init__(self, drive_app, gmail_app):
        self._drive = drive_app
        self._gmail = gmail_app

    async def __call__(self, scope, receive, send):
        if scope.get('type') in ('http', 'websocket'):
            path = scope.get('path', '')

            # RFC 9470: clients may append /.well-known/ to the resource URL path,
            # e.g. /sse/.well-known/oauth-protected-resource. Normalise these to the
            # root-level well-known path so drive_app's registered routes handle them.
            wk_idx = path.find('/.well-known/')
            if wk_idx > 0:
                scope = dict(scope)
                scope['path'] = path[wk_idx:]  # strip any path prefix before /.well-known/
                await self._drive(scope, receive, send)
                return

            if path == '/gmail' or path.startswith('/gmail/'):
                scope = dict(scope)
                scope['path'] = path[6:] or '/'
                scope['root_path'] = scope.get('root_path', '') + '/gmail'
                await self._gmail(scope, receive, send)
                return
        await self._drive(scope, receive, send)


# -- OAuth Authorization Server proxy -----------------------------------------
# Claude.ai's connector OAuth flow treats the MCP server as a full OAuth AS.
# These three endpoints proxy Google OAuth behind a PKCE-verified exchange.
# All state is passed as HMAC-signed tokens — no server-side storage needed.

_OAUTH_STATE_TTL = 600  # 10 min for user to complete the Google login page


def _server_origin(request: Request) -> str:
    """Return the server's public base URL, honouring X-Forwarded-Proto from Cloud Run's LB."""
    proto = request.headers.get('x-forwarded-proto', request.url.scheme)
    host = request.url.netloc
    return f"{proto}://{host}"


def _hmac_sign(data: str, secret: str) -> str:
    """HMAC-SHA256 sign a string; return base64url-encoded digest (no padding)."""
    sig = hmac.new(secret.encode(), data.encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(sig).rstrip(b'=').decode()


def _make_state_token(payload: dict, secret: str) -> str:
    """Encode a dict as a HMAC-signed, base64url token: <data>.<sig>"""
    data = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=').decode()
    sig = _hmac_sign(data, secret)
    return f"{data}.{sig}"


def _verify_state_token(token: str, secret: str) -> dict:
    """Decode and verify a state token. Raises ValueError if invalid or expired."""
    try:
        data, sig = token.rsplit('.', 1)
    except ValueError:
        raise ValueError("Malformed token")
    expected_sig = _hmac_sign(data, secret)
    if not hmac.compare_digest(sig, expected_sig):
        raise ValueError("Token signature mismatch")
    padded = data + '=' * (-len(data) % 4)
    payload = json.loads(base64.urlsafe_b64decode(padded))
    if payload.get('exp', 0) < time.time():
        raise ValueError("Token expired")
    return payload


@mcp.custom_route("/authorize", methods=["GET"])
async def oauth_authorize(request: Request) -> RedirectResponse:
    """
    OAuth AS /authorize endpoint.

    Claude.ai redirects the user's browser here with a code_challenge (PKCE).
    We relay the request to Google OAuth, embedding Claude.ai's parameters in
    a HMAC-signed state token so we can recover them in /oauth/callback without
    any server-side storage (required for stateless Cloud Run instances).
    """
    client_id = os.environ.get('OAUTH_CLIENT_ID', '')
    client_secret = os.environ.get('OAUTH_CLIENT_SECRET', '')
    if not client_id or not client_secret:
        return JSONResponse(
            {'error': 'server_error', 'error_description': 'OAuth client not configured'},
            status_code=500,
        )

    claude_state = request.query_params.get('state', '')
    claude_redirect_uri = request.query_params.get('redirect_uri', '')
    code_challenge = request.query_params.get('code_challenge', '')
    code_challenge_method = request.query_params.get('code_challenge_method', 'S256')

    import sys as _sys
    print(f"[/authorize] redirect_uri={claude_redirect_uri!r} state={claude_state!r}", file=_sys.stderr, flush=True)

    server_origin = _server_origin(request)
    callback_uri = f"{server_origin}/oauth/callback"

    state_payload = {
        'claude_state': claude_state,
        'claude_redirect_uri': claude_redirect_uri,
        'code_challenge': code_challenge,
        'code_challenge_method': code_challenge_method,
        'exp': int(time.time()) + _OAUTH_STATE_TTL,
    }
    state_token = _make_state_token(state_payload, client_secret)

    google_scopes = (
        'https://www.googleapis.com/auth/drive '
        'https://www.googleapis.com/auth/spreadsheets '
        'https://www.googleapis.com/auth/script.projects '
        'https://www.googleapis.com/auth/script.processes '
        'https://mail.google.com/ '
        'email'
    )
    params = urllib.parse.urlencode({
        'response_type': 'code',
        'client_id': client_id,
        'redirect_uri': callback_uri,
        'scope': google_scopes,
        'state': state_token,
        'access_type': 'offline',
        'prompt': 'consent',
    })
    return RedirectResponse(url=f"https://accounts.google.com/o/oauth2/v2/auth?{params}")


@mcp.custom_route("/oauth/callback", methods=["GET"])
async def oauth_callback(request: Request):
    """
    OAuth callback from Google.

    Unpacks the HMAC-signed state token to retrieve Claude.ai's parameters,
    then wraps the Google authorization code in a new signed token that carries
    the PKCE code_challenge. Redirects back to Claude.ai with our signed code.
    """
    client_secret = os.environ.get('OAUTH_CLIENT_SECRET', '')
    if not client_secret:
        return JSONResponse(
            {'error': 'server_error', 'error_description': 'OAuth client not configured'},
            status_code=500,
        )

    error = request.query_params.get('error', '')
    if error:
        return JSONResponse({'error': error}, status_code=400)

    google_code = request.query_params.get('code', '')
    state_token = request.query_params.get('state', '')
    if not google_code or not state_token:
        return JSONResponse(
            {'error': 'invalid_request', 'error_description': 'Missing code or state'},
            status_code=400,
        )

    try:
        state = _verify_state_token(state_token, client_secret)
    except ValueError as e:
        return JSONResponse({'error': 'invalid_request', 'error_description': str(e)}, status_code=400)

    # Embed the Google code + PKCE challenge in a signed token we pass to Claude.ai as "code"
    server_origin = _server_origin(request)
    callback_uri = f"{server_origin}/oauth/callback"
    code_payload = {
        'google_code': google_code,
        'code_challenge': state['code_challenge'],
        'code_challenge_method': state.get('code_challenge_method', 'S256'),
        'callback_uri': callback_uri,
        'exp': int(time.time()) + 300,  # 5 min to complete /token exchange
    }
    our_code = _make_state_token(code_payload, client_secret)

    redirect_params = urllib.parse.urlencode({
        'code': our_code,
        'state': state['claude_state'],
    })
    return RedirectResponse(url=f"{state['claude_redirect_uri']}?{redirect_params}")


@mcp.custom_route("/token", methods=["POST"])
async def oauth_token(request: Request) -> JSONResponse:
    """
    OAuth AS /token endpoint.

    Claude.ai POSTs the code + code_verifier here. We:
    1. Decode our signed code token to recover the Google code and code_challenge.
    2. Verify PKCE: SHA-256(code_verifier) == code_challenge.
    3. Exchange the Google authorization code for a Google access token.
    4. Return the Google token response so Claude.ai uses it as a Bearer token.
    """
    client_id = os.environ.get('OAUTH_CLIENT_ID', '')
    client_secret = os.environ.get('OAUTH_CLIENT_SECRET', '')
    if not client_id or not client_secret:
        return JSONResponse(
            {'error': 'server_error', 'error_description': 'OAuth client not configured'},
            status_code=500,
        )

    body_bytes = await request.body()
    content_type = request.headers.get('content-type', '')
    if 'application/x-www-form-urlencoded' in content_type:
        params = dict(urllib.parse.parse_qsl(body_bytes.decode()))
    else:
        try:
            params = json.loads(body_bytes) if body_bytes else {}
        except Exception:
            params = {}

    our_code = params.get('code', '')
    code_verifier = params.get('code_verifier', '')
    redirect_uri = params.get('redirect_uri', '')
    grant_type = params.get('grant_type', '')

    import sys as _sys
    print(f"[/token] grant_type={grant_type!r} code_prefix={our_code[:12]!r} has_dot={'.' in our_code} redirect_uri={redirect_uri!r}", file=_sys.stderr, flush=True)

    if grant_type != 'authorization_code':
        return JSONResponse({'error': 'unsupported_grant_type'}, status_code=400)
    if not our_code:
        return JSONResponse(
            {'error': 'invalid_request', 'error_description': 'Missing code'},
            status_code=400,
        )

    if '.' in our_code:
        # Our signed token path: PKCE-verified proxy flow via /authorize → /oauth/callback
        if not code_verifier:
            return JSONResponse(
                {'error': 'invalid_request', 'error_description': 'Missing code_verifier'},
                status_code=400,
            )
        try:
            code_data = _verify_state_token(our_code, client_secret)
        except ValueError as e:
            print(f"[/token] signed-token verify failed: {e}", file=_sys.stderr, flush=True)
            return JSONResponse({'error': 'invalid_grant', 'error_description': str(e)}, status_code=400)

        # Verify PKCE: SHA-256(code_verifier) must equal code_challenge
        code_challenge = code_data.get('code_challenge', '')
        method = code_data.get('code_challenge_method', 'S256')
        if method == 'S256':
            digest = hashlib.sha256(code_verifier.encode()).digest()
            computed = base64.urlsafe_b64encode(digest).rstrip(b'=').decode()
        else:
            computed = code_verifier  # plain method (not recommended but spec-compliant)

        if not hmac.compare_digest(computed, code_challenge):
            return JSONResponse(
                {'error': 'invalid_grant', 'error_description': 'PKCE verification failed'},
                status_code=400,
            )

        google_code = code_data['google_code']
        callback_uri = code_data['callback_uri']
    else:
        # Raw Google authorization code path: connector authorized via Google's own
        # OAuth endpoints (manual connector config) and sent the raw code here.
        # Skip PKCE — Google already authenticated the user.
        google_code = our_code
        callback_uri = redirect_uri
        if not callback_uri:
            return JSONResponse(
                {'error': 'invalid_request', 'error_description': 'Missing redirect_uri'},
                status_code=400,
            )

    # Exchange the Google authorization code for Google OAuth tokens
    token_body = urllib.parse.urlencode({
        'code': google_code,
        'client_id': client_id,
        'client_secret': client_secret,
        'redirect_uri': callback_uri,
        'grant_type': 'authorization_code',
    }).encode()

    try:
        req = urllib.request.Request(
            'https://oauth2.googleapis.com/token',
            data=token_body,
            method='POST',
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            token_response = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        error_body = e.read().decode()
        return JSONResponse(
            {'error': 'invalid_grant', 'error_description': error_body},
            status_code=400,
        )
    except Exception as e:
        return JSONResponse(
            {'error': 'server_error', 'error_description': str(e)},
            status_code=500,
        )

    return JSONResponse(token_response)


# -- MCP OAuth 2.0 Discovery (RFC 8414 / RFC 9470) -----------------------------
# Claude Desktop and MCP SDK clients auto-discover OAuth endpoints via these
# well-known URLs before attempting to open the browser for authentication.

def _as_metadata(request: Request) -> dict:
    """Build the Authorization Server metadata document."""
    origin = _server_origin(request)
    return {
        "issuer": origin,
        "authorization_endpoint": f"{origin}/authorize",
        "token_endpoint": f"{origin}/token",
        "registration_endpoint": f"{origin}/register",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_post"],
    }


@mcp.custom_route("/.well-known/oauth-authorization-server", methods=["GET"])
async def oauth_as_metadata(request: Request) -> JSONResponse:
    return JSONResponse(_as_metadata(request))


@mcp.custom_route("/.well-known/openid-configuration", methods=["GET"])
async def oauth_openid_config(request: Request) -> JSONResponse:
    return JSONResponse(_as_metadata(request))


def _protected_resource_response(request: Request) -> dict:
    origin = _server_origin(request)
    # RFC 9470: resource identifier is the protected resource URL.
    # We list both root and /sse so validators that check exact match pass
    # regardless of which connector URL the client used.
    return {
        "resource": origin,
        "authorization_servers": [origin],
        "bearer_methods_supported": ["header"],
        "scopes_supported": [
            "https://www.googleapis.com/auth/drive",
            "https://www.googleapis.com/auth/spreadsheets",
            "https://mail.google.com/",
            "email",
        ],
    }


@mcp.custom_route("/.well-known/oauth-protected-resource", methods=["GET"])
async def oauth_protected_resource(request: Request) -> JSONResponse:
    return JSONResponse(_protected_resource_response(request))


@mcp.custom_route("/.well-known/oauth-protected-resource/{path:path}", methods=["GET"])
async def oauth_protected_resource_path(request: Request) -> JSONResponse:
    return JSONResponse(_protected_resource_response(request))


@mcp.custom_route("/register", methods=["POST"])
async def oauth_register(request: Request) -> JSONResponse:
    """Dynamic client registration (RFC 7591) — returns a static client_id."""
    body_bytes = await request.body()
    body = json.loads(body_bytes) if body_bytes else {}
    return JSONResponse({
        "client_id": "mcp-client",
        "client_id_issued_at": int(time.time()),
        "redirect_uris": body.get("redirect_uris", []),
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
    }, status_code=201)


# -- Health check --------------------------------------------------------------

@mcp.custom_route("/healthz", methods=["GET"])
async def healthz(request: Request) -> PlainTextResponse:
    return PlainTextResponse("ok")

# -- Entry point ---------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    transport = os.environ.get("MCP_TRANSPORT", "sse")
    if transport == "sse":
        # Drive / Sheets / Script at /sse  (≤62 tools — fits client limit)
        # Gmail at /gmail/sse              (64 tools — separate connector)
        drive_app = mcp.sse_app()
        gmail_app = gmail_mcp.sse_app()
        app = OAuthMiddleware(_GmailDispatcher(drive_app, gmail_app))
        uvicorn.run(app, host="0.0.0.0", port=_port)
    else:
        mcp.run(transport=transport)
