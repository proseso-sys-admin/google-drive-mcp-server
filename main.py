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
import logging
from typing import Any, Optional, Dict, List

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.server import TransportSecuritySettings
from mcp.server.session import ServerSession, InitializationState
from starlette.requests import Request
from starlette.responses import PlainTextResponse

from google.oauth2 import service_account
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

# -- Health check --------------------------------------------------------------

@mcp.custom_route("/healthz", methods=["GET"])
async def healthz(request: Request) -> PlainTextResponse:
    return PlainTextResponse("ok")

# -- Entry point ---------------------------------------------------------------

if __name__ == "__main__":
    transport = os.environ.get("MCP_TRANSPORT", "sse")
    mcp.run(transport=transport)
