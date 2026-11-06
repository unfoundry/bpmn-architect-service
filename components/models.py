"""
==============================================================================
BPMN Architect Service - Pydantic Request & Response Data Models
==============================================================================
Defines strongly-typed schemas used for API inputs, outputs, error representations,
and session identity states.
==============================================================================
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


# ------------------------------------------------------------------------------
# 1. USER & AUTHENTICATION MODELS
# ------------------------------------------------------------------------------

class AuthUser(BaseModel):
    """
    Represents an authenticated user identity and their assigned authorization role.
    """
    username: str = Field(..., description="Unique username or domain account")
    role: str = Field(..., description="Assigned role: 'admin', 'editor', or 'viewer'")
    auth_method: str = Field(..., description="Method used to authenticate: 'master-key', 'iis-header', 'ldap', 'none'")

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"


# ------------------------------------------------------------------------------
# 2. DIAGRAM METADATA & OPERATIONS
# ------------------------------------------------------------------------------

class CreateDiagramRequest(BaseModel):
    """
    Payload required to register and generate a new BPMN process flow.
    """
    friendly_name: str = Field(..., min_length=1, max_length=120, description="User-friendly name of the flow")
    project_name: Optional[str] = Field("", max_length=120, description="Parent process or project name")
    project_description: Optional[str] = Field("", max_length=1000, description="Optional description of the process")
    initial_xml: Optional[str] = Field(None, description="Optional custom initial BPMN XML string")


class UpdateMetadataRequest(BaseModel):
    """
    Payload for updating diagram descriptive details without modifying XML.
    """
    friendly_name: Optional[str] = Field(None, min_length=1, max_length=120)
    project_name: Optional[str] = Field(None, max_length=120)
    project_description: Optional[str] = Field(None, max_length=1000)


class SaveDiagramPayload(BaseModel):
    """
    Dual-save payload submitted when saving an edited diagram:
    Carries both the BPMN 2.0 XML model and the pre-rendered SVG export.
    """
    bpmn_xml: str = Field(..., description="Full BPMN 2.0 XML representation")
    svg_content: Optional[str] = Field(None, description="Pre-rendered SVG export of the diagram")
    friendly_name: Optional[str] = Field(None, max_length=120)
    project_name: Optional[str] = Field(None, max_length=120)
    project_description: Optional[str] = Field(None, max_length=1000)


class DiagramSummary(BaseModel):
    """
    Summary view of a diagram returned in library listings and metadata lookups.
    """
    id: str
    friendly_name: str
    project_name: str
    project_description: str
    author: str
    last_edited_by: Optional[str] = None
    created_at: str
    updated_at: str
    is_deleted: bool = False
    has_svg: bool = False
    locked_by: Optional[str] = None
    lock_expires_in_sec: Optional[int] = None


# ------------------------------------------------------------------------------
# 3. COOPERATIVE LOCK & PRESENCE MODELS
# ------------------------------------------------------------------------------

class LockActionRequest(BaseModel):
    """
    Actions that can be requested on a diagram edit lock:
    - "acquire"        : Attempt to take the lock
    - "heartbeat"      : Renew / extend existing lock
    - "release"        : Voluntarily yield the lock
    - "request_handoff": Ask current lock holder to yield the token
    """
    action: str = Field(..., pattern="^(acquire|heartbeat|release|request_handoff)$")


class LockStatusResponse(BaseModel):
    """
    Current status of the diagram's lock and live viewer presence.
    """
    diagram_id: str
    is_locked: bool
    locked_by: Optional[str] = None
    expires_in_sec: int = 0
    pending_handoff_to: Optional[str] = None
    active_viewers: List[str] = Field(default_factory=list)
    status_message: str = ""

