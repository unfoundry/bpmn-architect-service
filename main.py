"""
==============================================================================
BPMN ARCHITECT SERVICE - MAIN APPLICATION
==============================================================================
Headless, high-performance microservice providing:
- BPMN 2.0 XML and SVG validation & sanitization (XXE/XSS hardened)
- Dual-save persistence for high-availability static web hosting
- Cooperative soft-lock & collaborator presence tracking
- Kroki-like direct SVG image rendering (/api/diagram/{id}/svg)
- Multi-protocol authentication (Master Key, IIS X-Header, LDAP)
==============================================================================
"""

import time
import secrets
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import FastAPI, Depends, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles

import config
from components.models import (
    AuthUser,
    CreateDiagramRequest,
    UpdateMetadataRequest,
    SaveDiagramPayload,
    DiagramSummary,
    LockActionRequest,
    LockStatusResponse,
)
from components.auth import get_current_user, require_admin
from components.security import validate_bpmn_xml, validate_and_sanitize_svg
from components.storage import storage, sanitize_diagram_id
from components.lock_manager import lock_manager

# Service Startup Timestamp for live uptime tracking
SERVICE_START_TIME = datetime.now(timezone.utc)

# Setup Jinja2 template rendering for the status board
TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# Initialize FastAPI application
app = FastAPI(
    title="BPMN Architect Service",
    description="Headless API service for collaborative BPMN diagramming and static rendering",
    version="2.0.0",
)

# Static directory mount for service logos, favicons, and assets
STATIC_DIR = Path(__file__).resolve().parent / "static"
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# ------------------------------------------------------------------------------
# 1. CORS CONFIGURATION (Enables Decoupled Static UI)
# ------------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ------------------------------------------------------------------------------
# 2. STATUS BOARD & HEALTH DISCOVERY
# ------------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse, tags=["System"])
async def service_status_board(request: Request):
    """
    Renders the live operational status board for the BPMN Architect Service.
    """
    now = datetime.now(timezone.utc)
    uptime_delta = now - SERVICE_START_TIME
    uptime_seconds = int(uptime_delta.total_seconds())

    days = uptime_seconds // 86400
    rem = uptime_seconds % 86400
    hours = rem // 3600
    minutes = (rem % 3600) // 60
    seconds = rem % 60

    uptime_formatted = ""
    if days > 0:
        uptime_formatted += f"{days}d "
    if hours > 0 or days > 0:
        uptime_formatted += f"{hours}h "
    uptime_formatted += f"{minutes}m {seconds}s"

    all_diagrams = storage.list_diagrams(include_deleted=False)
    diagram_count = len(all_diagrams)

    # Calculate active locks
    active_locks = 0
    for d in all_diagrams:
        st = await lock_manager.get_status(d["id"])
        d["locked_by"] = st.get("locked_by")
        if st.get("is_locked"):
            active_locks += 1

    storage_str = str(config.STORAGE_PATH)
    storage_short = storage_str if len(storage_str) < 35 else "..." + storage_str[-32:]

    return templates.TemplateResponse(
        request=request,
        name="status.html",
        context={
            "request": request,
            "version": "2.0.0",
            "uptime_seconds": uptime_seconds,
            "uptime_formatted": uptime_formatted,
            "start_iso": SERVICE_START_TIME.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "diagram_count": diagram_count,
            "active_locks_count": active_locks,
            "storage_path": storage_str,
            "storage_path_short": storage_short,
            "max_payload_mb": config.MAX_PAYLOAD_SIZE_MB,
            "auth_method": config.AUTH_METHOD,
            "ui_base_url": config.UI_BASE_URL,
            "recent_diagrams": all_diagrams[:10],
        }
    )


@app.get("/health", tags=["System"])
def health_check():
    """
    Returns service health status, runtime configuration, and active auth method.
    """
    return {
        "status": "healthy",
        "service": "BPMN Architect Service",
        "version": "2.0.0",
        "auth_method": config.AUTH_METHOD,
        "max_payload_size_mb": config.MAX_PAYLOAD_SIZE_MB,
        "storage_directory": str(config.STORAGE_PATH),
    }


# ------------------------------------------------------------------------------
# 2B. ADMINISTRATIVE PORTAL & AUTHENTICATION
# ------------------------------------------------------------------------------

@app.get("/admin", response_class=HTMLResponse, tags=["Admin"])
async def admin_portal(request: Request):
    """
    Renders the Administrative Management Console.
    Provides session lock overrides, diagram deletion/recovery,
    and storage activity auditing under authenticated administrative governance.
    """
    method = config.AUTH_METHOD
    is_authenticated = False
    current_username = ""
    auth_err = ""

    # Strategy 1: Open / Dev Mode
    if method == "none":
        is_authenticated = True
        current_username = "dev-user (Dev Mode)"

    # Strategy 2: Master Key
    elif method == "master-key":
        provided_key = (
            request.headers.get("X-Master-Key")
            or request.cookies.get("bpmn_master_key")
            or request.query_params.get("key")
        )
        if provided_key:
            if secrets.compare_digest(provided_key.strip(), config.MASTER_KEY):
                is_authenticated = True
                current_username = request.cookies.get("bpmn_user") or "master-admin"
            else:
                auth_err = "Invalid Master Key credentials."

    # Strategy 3: IIS Windows Auth Header
    elif method == "iis-header":
        user_header = request.headers.get(config.IIS_HEADER_NAME)
        if user_header and user_header.strip():
            raw_user = user_header.strip()
            norm = raw_user.lower()
            short = norm.split("\\")[-1] if "\\" in norm else norm
            if any(norm == a or short == a for a in config.IIS_ADMIN_USERS):
                is_authenticated = True
                current_username = raw_user
            else:
                auth_err = f"User '{raw_user}' is authenticated via Windows Auth but not in the admin whitelist."
        else:
            auth_err = f"Missing Windows authentication header '{config.IIS_HEADER_NAME}'."

    # Strategy 4: Active Directory / LDAP Basic Auth
    elif method == "ldap":
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Basic "):
            import base64
            try:
                decoded = base64.b64decode(auth_header[6:]).decode("utf-8")
                u, p = decoded.split(":", 1)
                from components.auth import _verify_ldap_credentials
                auth_user = _verify_ldap_credentials(u, p)
                if auth_user and auth_user.is_admin:
                    is_authenticated = True
                    current_username = auth_user.username
                else:
                    auth_err = "User is not an authorized LDAP administrator."
            except Exception as ldap_exc:
                auth_err = f"LDAP verification failed: {ldap_exc}"

    # If unauthenticated, display the login panel
    if not is_authenticated:
        return templates.TemplateResponse(
            request=request,
            name="admin.html",
            context={
                "request": request,
                "is_authenticated": False,
                "auth_method": method,
                "auth_error": auth_err,
                "current_user": None,
                "diagrams": [],
                "storage_files": [],
                "storage_groups": [],
                "total_storage_files_count": 0,
                "storage_audit_limit": config.STORAGE_AUDIT_LIMIT,
                "storage_audit_max_days": config.STORAGE_AUDIT_MAX_DAYS,
                "active_count": 0,
                "deleted_count": 0,
                "lock_count": 0,
                "ui_base_url": config.UI_BASE_URL,
                "storage_path": str(config.STORAGE_PATH),
            }
        )

    # Gather full diagram inventory (including soft-deleted)
    all_diagrams = storage.list_diagrams(include_deleted=True)
    active_count = 0
    deleted_count = 0
    lock_count = 0

    for d in all_diagrams:
        # Query live lock status
        st = await lock_manager.get_status(d["id"])
        d["is_locked"] = st.get("is_locked", False)
        d["locked_by"] = st.get("locked_by")
        d["lock_expires_in_sec"] = st.get("expires_in_sec", 0)

        if d.get("is_deleted"):
            deleted_count += 1
        else:
            active_count += 1

        if d["is_locked"]:
            lock_count += 1

    # Gather physical storage file activity grouped by Diagram ID
    storage_groups_map = {}
    cutoff_timestamp = 0
    if config.STORAGE_AUDIT_MAX_DAYS > 0:
        cutoff_timestamp = time.time() - (config.STORAGE_AUDIT_MAX_DAYS * 86400)

    total_storage_files_count = 0
    if config.STORAGE_PATH.exists():
        all_files = [p for p in config.STORAGE_PATH.glob("*") if p.is_file()]
        total_storage_files_count = len(all_files)
        if cutoff_timestamp > 0:
            all_files = [p for p in all_files if p.stat().st_mtime >= cutoff_timestamp]

        # Sort files by newest timestamp descending
        all_files.sort(key=lambda x: x.stat().st_mtime, reverse=True)
        audit_files = all_files[:config.STORAGE_AUDIT_LIMIT]

        for p in audit_files:
            # Group stem by primary diagram ID
            stem = p.name.split(".")[0]
            ext = p.suffix.lower()
            st = p.stat()
            size_kb = round(st.st_size / 1024, 1)
            mtime = st.st_mtime
            mtime_iso = datetime.fromtimestamp(mtime, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

            if stem not in storage_groups_map:
                storage_groups_map[stem] = {
                    "id": stem,
                    "has_bpmn": False,
                    "bpmn_size_kb": None,
                    "has_svg": False,
                    "svg_size_kb": None,
                    "has_json": False,
                    "json_size_kb": None,
                    "other_files": [],
                    "total_size_kb": 0.0,
                    "latest_mtime": mtime,
                    "latest_mtime_iso": mtime_iso,
                    "file_count": 0,
                }

            grp = storage_groups_map[stem]
            grp["file_count"] += 1
            grp["total_size_kb"] = round(grp["total_size_kb"] + size_kb, 1)
            if mtime > grp["latest_mtime"]:
                grp["latest_mtime"] = mtime
                grp["latest_mtime_iso"] = mtime_iso

            if ext == ".bpmn":
                grp["has_bpmn"] = True
                grp["bpmn_size_kb"] = size_kb
            elif ext == ".svg":
                grp["has_svg"] = True
                grp["svg_size_kb"] = size_kb
            elif ext == ".json":
                grp["has_json"] = True
                grp["json_size_kb"] = size_kb
            else:
                grp["other_files"].append(f"{p.name} ({size_kb} KB)")

    storage_groups = sorted(storage_groups_map.values(), key=lambda g: g["latest_mtime"], reverse=True)

    return templates.TemplateResponse(
        request=request,
        name="admin.html",
        context={
            "request": request,
            "is_authenticated": True,
            "auth_method": method,
            "current_user": current_username,
            "diagrams": all_diagrams,
            "storage_groups": storage_groups,
            "total_storage_files_count": total_storage_files_count,
            "storage_audit_limit": config.STORAGE_AUDIT_LIMIT,
            "storage_audit_max_days": config.STORAGE_AUDIT_MAX_DAYS,
            "active_count": active_count,
            "deleted_count": deleted_count,
            "lock_count": lock_count,
            "ui_base_url": config.UI_BASE_URL,
            "storage_path": str(config.STORAGE_PATH),
        }
    )


@app.post("/api/admin/login", tags=["Admin"])
async def admin_login(payload: dict, response: Response):
    """
    Authenticates administrative session and sets browser cookie.
    """
    master_key = payload.get("master_key", "").strip()
    if config.AUTH_METHOD == "master-key":
        if not secrets.compare_digest(master_key, config.MASTER_KEY):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Master Key.")
        response.set_cookie(
            key="bpmn_master_key",
            value=master_key,
            path="/",
            max_age=86400,
            samesite="lax",
            httponly=False
        )
        return {"status": "success", "username": "master-admin"}
    return {"status": "success", "username": "dev-user"}


@app.post("/api/admin/logout", tags=["Admin"])
async def admin_logout(response: Response):
    """
    Clears administrative session cookie.
    """
    response.delete_cookie(key="bpmn_master_key", path="/")
    return {"status": "logged_out"}


# ------------------------------------------------------------------------------
# 3. DIAGRAM LIBRARY & RETRIEVAL
# ------------------------------------------------------------------------------

@app.get("/api/diagrams", response_model=List[DiagramSummary], tags=["Diagrams"])
async def list_diagrams(
    include_deleted: bool = False,
    current_user: AuthUser = Depends(get_current_user)
):
    """
    Returns a listing of diagrams stored on disk, merged with active lock status.
    """
    records = storage.list_diagrams(include_deleted=include_deleted)
    summaries = []

    for r in records:
        diagram_id = r["id"]
        lock_status = await lock_manager.get_status(diagram_id)

        summaries.append(
            DiagramSummary(
                id=r["id"],
                friendly_name=r.get("friendly_name", "Untitled Process"),
                project_name=r.get("project_name", ""),
                project_description=r.get("project_description", ""),
                author=r.get("author", "unknown"),
                last_edited_by=r.get("last_edited_by"),
                created_at=r.get("created_at", ""),
                updated_at=r.get("updated_at", ""),
                is_deleted=r.get("is_deleted", False),
                has_svg=r.get("has_svg", False),
                locked_by=lock_status.get("locked_by"),
                lock_expires_in_sec=lock_status.get("expires_in_sec"),
            )
        )

    return summaries


@app.post("/api/diagram/new", response_model=DiagramSummary, tags=["Diagrams"])
def create_diagram(
    payload: CreateDiagramRequest,
    current_user: AuthUser = Depends(get_current_user)
):
    """
    Registers and creates a new BPMN diagram on disk.
    If initial_xml is supplied, it is validated for authenticity before saving.
    """
    initial_xml = payload.initial_xml
    if initial_xml and initial_xml.strip():
        # Validate supplied initial XML
        is_valid, err_msg, _ = validate_bpmn_xml(initial_xml.encode("utf-8"))
        if not is_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid initial BPMN XML: {err_msg}"
            )

    meta = storage.create_diagram(
        friendly_name=payload.friendly_name,
        project_name=payload.project_name or "",
        project_description=payload.project_description or "",
        author=current_user.username,
        initial_xml=initial_xml
    )

    return DiagramSummary(
        id=meta["id"],
        friendly_name=meta["friendly_name"],
        project_name=meta["project_name"],
        project_description=meta["project_description"],
        author=meta["author"],
        last_edited_by=meta["last_edited_by"],
        created_at=meta["created_at"],
        updated_at=meta["updated_at"],
        is_deleted=meta["is_deleted"],
        has_svg=False,
        locked_by=None,
        lock_expires_in_sec=0
    )


@app.get("/api/diagram/{diagram_id}", response_model=DiagramSummary, tags=["Diagrams"])
async def get_diagram_metadata(
    diagram_id: str,
    current_user: AuthUser = Depends(get_current_user)
):
    """
    Retrieves metadata for a specific diagram along with its current lock state.
    """
    try:
        clean_id = sanitize_diagram_id(diagram_id)
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err))

    meta = storage.get_metadata(clean_id)
    if not meta or meta.get("is_deleted", False):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Diagram not found or deleted.")

    lock_status = await lock_manager.get_status(clean_id)
    svg_exists = storage.read_svg(clean_id) is not None

    return DiagramSummary(
        id=meta["id"],
        friendly_name=meta.get("friendly_name", "Untitled Process"),
        project_name=meta.get("project_name", ""),
        project_description=meta.get("project_description", ""),
        author=meta.get("author", "unknown"),
        last_edited_by=meta.get("last_edited_by"),
        created_at=meta.get("created_at", ""),
        updated_at=meta.get("updated_at", ""),
        is_deleted=meta.get("is_deleted", False),
        has_svg=svg_exists,
        locked_by=lock_status.get("locked_by"),
        lock_expires_in_sec=lock_status.get("expires_in_sec"),
    )


@app.get("/api/diagram/{diagram_id}/xml", tags=["Diagram Content"])
def get_diagram_xml(diagram_id: str):
    """
    Returns the raw BPMN 2.0 XML for a diagram.
    Open for read access to support intranet embedding and static viewer consumption.
    """
    try:
        clean_id = sanitize_diagram_id(diagram_id)
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err))

    xml_content = storage.read_bpmn(clean_id)
    if not xml_content:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="BPMN diagram XML not found on disk.")

    return Response(
        content=xml_content,
        media_type="application/xml; charset=utf-8",
        headers={"Cache-Control": "no-cache, must-revalidate"}
    )


@app.get("/api/diagram/{diagram_id}/svg", tags=["Diagram Content"])
def get_diagram_svg(diagram_id: str):
    """
    Kroki-like endpoint: Returns the pre-rendered, sanitized SVG image for a diagram.
    Can be used directly inside HTML <img> tags, Markdown documents, or wikis.
    """
    try:
        clean_id = sanitize_diagram_id(diagram_id)
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err))

    svg_content = storage.read_svg(clean_id)
    if not svg_content:
        # Fallback friendly placeholder SVG if not yet exported
        fallback_svg = (
            '<svg xmlns="http://www.w3.org/2000/svg" width="400" height="80" viewBox="0 0 400 80">'
            '<rect width="100%" height="100%" fill="#f8f9fa" stroke="#dee2e6" rx="6"/>'
            '<text x="50%" y="50%" dominant-baseline="middle" text-anchor="middle" '
            'fill="#6c757d" font-family="sans-serif" font-size="14">'
            'BPMN SVG Preview Pending (Open and Save in Editor)'
            '</text></svg>'
        )
        return Response(content=fallback_svg, media_type="image/svg+xml; charset=utf-8")

    return Response(
        content=svg_content,
        media_type="image/svg+xml; charset=utf-8",
        headers={"Cache-Control": "public, max-age=60"}
    )


# ------------------------------------------------------------------------------
# 4. DUAL-SAVE & METADATA MODIFICATIONS
# ------------------------------------------------------------------------------

@app.post("/api/diagram/{diagram_id}/save", tags=["Diagram Operations"])
async def save_diagram(
    diagram_id: str,
    payload: SaveDiagramPayload,
    current_user: AuthUser = Depends(get_current_user)
):
    """
    Dual-save endpoint: Atomically writes both the validated BPMN 2.0 XML
    and the pre-rendered, sanitized SVG image.
    Verifies that the user holds the active edit token.
    """
    try:
        clean_id = sanitize_diagram_id(diagram_id)
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err))

    meta = storage.get_metadata(clean_id)
    if not meta or meta.get("is_deleted", False):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Diagram not found or deleted.")

    # Step 1: Lock Verification
    lock_state = await lock_manager.get_status(clean_id)
    if lock_state["is_locked"] and lock_state["locked_by"] != current_user.username:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Cannot save: Diagram is currently locked by '{lock_state['locked_by']}'."
        )

    # Step 2: Validate BPMN XML (XXE, entity expansion & schema protection)
    xml_bytes = payload.bpmn_xml.encode("utf-8")
    is_valid_xml, xml_err, _ = validate_bpmn_xml(xml_bytes)
    if not is_valid_xml:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"BPMN XML rejected: {xml_err}")

    # Step 3: Sanitize SVG (XSS, script & event handler stripping)
    sanitized_svg = None
    if payload.svg_content and payload.svg_content.strip():
        svg_bytes = payload.svg_content.encode("utf-8")
        is_valid_svg, svg_err, cleaned_svg = validate_and_sanitize_svg(svg_bytes)
        if not is_valid_svg:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"SVG rejected: {svg_err}")
        sanitized_svg = cleaned_svg

    # Step 4: Atomic Persistence
    metadata_updates = {}
    if payload.friendly_name is not None:
        metadata_updates["friendly_name"] = payload.friendly_name
    if payload.project_name is not None:
        metadata_updates["project_name"] = payload.project_name
    if payload.project_description is not None:
        metadata_updates["project_description"] = payload.project_description

    updated_meta = storage.save_diagram(
        diagram_id=clean_id,
        bpmn_xml=payload.bpmn_xml,
        sanitized_svg=sanitized_svg,
        editor=current_user.username,
        metadata_updates=metadata_updates if metadata_updates else None
    )

    # Step 5: Extend active lock upon successful save
    await lock_manager.acquire_lock(clean_id, current_user.username)

    return {
        "status": "success",
        "message": "Diagram and SVG saved successfully.",
        "updated_at": updated_meta["updated_at"],
        "has_svg": sanitized_svg is not None
    }


@app.post("/api/diagram/{diagram_id}/metadata", tags=["Diagram Operations"])
def update_diagram_metadata(
    diagram_id: str,
    payload: UpdateMetadataRequest,
    current_user: AuthUser = Depends(get_current_user)
):
    """
    Updates descriptive metadata (process name, flow name, description).
    """
    try:
        clean_id = sanitize_diagram_id(diagram_id)
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err))

    updates = {}
    if payload.friendly_name is not None:
        updates["friendly_name"] = payload.friendly_name
    if payload.project_name is not None:
        updates["project_name"] = payload.project_name
    if payload.project_description is not None:
        updates["project_description"] = payload.project_description

    result = storage.update_metadata(clean_id, updates, editor=current_user.username)
    if not result:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Diagram not found.")

    return {"status": "success", "metadata": result}


@app.post("/api/diagram/{diagram_id}/delete", tags=["Diagram Operations"])
async def delete_diagram(
    diagram_id: str,
    current_user: AuthUser = Depends(get_current_user)
):
    """
    Marks a diagram as deleted and clears any active edit lock.
    """
    try:
        clean_id = sanitize_diagram_id(diagram_id)
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err))

    meta = storage.get_metadata(clean_id)
    if not meta:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Diagram not found.")

    # Only diagram author or admin can delete
    if meta.get("author") != current_user.username and not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the author or an administrator may delete this diagram."
        )

    storage.soft_delete(clean_id, editor=current_user.username)
    await lock_manager.release_lock(clean_id, current_user.username, force=True)

    return {"status": "deleted", "id": clean_id}


@app.post("/api/diagram/{diagram_id}/restore", tags=["Diagram Operations"])
async def restore_diagram(
    diagram_id: str,
    current_user: AuthUser = Depends(require_admin)
):
    """
    Administrative recovery: Restores a soft-deleted diagram back to active status.
    """
    try:
        clean_id = sanitize_diagram_id(diagram_id)
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err))

    meta = storage.get_metadata(clean_id)
    if not meta:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Diagram not found.")

    res = storage.update_metadata(clean_id, {"is_deleted": False}, editor=current_user.username)
    return {"status": "restored", "id": clean_id, "friendly_name": meta.get("friendly_name", clean_id)}


# ------------------------------------------------------------------------------
# 5. COOPERATIVE LOCK & PRESENCE COORDINATION
# ------------------------------------------------------------------------------

@app.post("/api/diagram/{diagram_id}/lock", response_model=LockStatusResponse, tags=["Lock & Presence"])
async def handle_lock_action(
    diagram_id: str,
    payload: LockActionRequest,
    current_user: AuthUser = Depends(get_current_user)
):
    """
    Coordinates cooperative soft-lock operations:
    - acquire: Take the edit token
    - heartbeat: Renew edit token and check for handoff requests
    - release: Voluntarily yield the edit token
    - request_handoff: Ask active editor to yield the token
    """
    try:
        clean_id = sanitize_diagram_id(diagram_id)
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err))

    action = payload.action

    if action == "acquire":
        res = await lock_manager.acquire_lock(clean_id, current_user.username)
    elif action == "heartbeat":
        res = await lock_manager.heartbeat(clean_id, current_user.username)
    elif action == "release":
        res = await lock_manager.release_lock(clean_id, current_user.username)
    elif action == "request_handoff":
        res = await lock_manager.request_handoff(clean_id, current_user.username)
    else:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unsupported lock action.")

    status_data = await lock_manager.get_status(clean_id)

    return LockStatusResponse(
        diagram_id=clean_id,
        is_locked=status_data["is_locked"],
        locked_by=status_data["locked_by"],
        expires_in_sec=status_data["expires_in_sec"],
        pending_handoff_to=status_data["pending_handoff_to"],
        active_viewers=status_data["active_viewers"],
        status_message=res.get("message", res.get("status", "")),
    )


@app.get("/api/diagram/{diagram_id}/lock/status", response_model=LockStatusResponse, tags=["Lock & Presence"])
async def get_lock_status(diagram_id: str):
    """
    Returns the current lock owner, seconds until expiry, and active viewers.
    """
    try:
        clean_id = sanitize_diagram_id(diagram_id)
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err))

    data = await lock_manager.get_status(clean_id)
    return LockStatusResponse(
        diagram_id=clean_id,
        is_locked=data["is_locked"],
        locked_by=data["locked_by"],
        expires_in_sec=data["expires_in_sec"],
        pending_handoff_to=data["pending_handoff_to"],
        active_viewers=data["active_viewers"],
        status_message="",
    )


@app.post("/api/diagram/{diagram_id}/presence", tags=["Lock & Presence"])
async def ping_presence(
    diagram_id: str,
    current_user: AuthUser = Depends(get_current_user)
):
    """
    Registers the user as an active viewer of the diagram.
    """
    try:
        clean_id = sanitize_diagram_id(diagram_id)
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err))

    res = await lock_manager.ping_presence(clean_id, current_user.username)
    return res


@app.post("/api/diagram/{diagram_id}/unlock", tags=["Lock & Presence"])
async def admin_force_unlock(
    diagram_id: str,
    current_user: AuthUser = Depends(require_admin)
):
    """
    Administrative override: Force releases any active edit token.
    """
    try:
        clean_id = sanitize_diagram_id(diagram_id)
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err))

    res = await lock_manager.release_lock(clean_id, current_user.username, force=True)
    return res


# ------------------------------------------------------------------------------
# 6. STANDALONE SERVER RUNNER
# ------------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    print(f"Starting BPMN Architect Service on {config.SERVICE_HOST}:{config.SERVICE_PORT}...")
    kwargs = {
        "app": "main:app",
        "host": config.SERVICE_HOST,
        "port": config.SERVICE_PORT,
        "reload": True,
    }
    if config.SERVICE_ROOT_PATH:
        kwargs["root_path"] = config.SERVICE_ROOT_PATH
    uvicorn.run(**kwargs)

