"""
==============================================================================
BPMN Architect Service - Diagram Storage Engine
==============================================================================
Provides high-reliability, file-system-backed persistence for BPMN diagrams,
SVGs, and metadata.

Design Principles:
1. Static-Server Friendly:
   Diagrams are stored as `{id}.bpmn`, `{id}.svg`, and `{id}.json` in a single
   configurable folder. If IIS or Nginx hosts this directory statically, diagrams
   remain viewable and downloadable even if the Python service is completely down.
2. Atomic File Writes:
   Writes to temporary files before atomically replacing the destination file
   via `os.replace`. Prevents file corruption if an upload is interrupted.
3. Path Traversal Hardening:
   Strictly sanitizes `diagram_id` inputs to prevent directory traversal exploits.
==============================================================================
"""

import os
import json
import re
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple

import config


# Whitelist pattern for diagram IDs: alphanumeric, dashes, and underscores only
ID_PATTERN = re.compile(r"^[a-zA-Z0-9_\-]+$")


def sanitize_diagram_id(diagram_id: str) -> str:
    """
    Validates and sanitizes a diagram ID string.
    Raises ValueError if characters outside [a-zA-Z0-9_-] are present.
    """
    cleaned = diagram_id.strip()
    if not cleaned or not ID_PATTERN.match(cleaned) or ".." in cleaned:
        raise ValueError(f"Invalid diagram ID '{diagram_id}'. Only alphanumeric characters, dashes, and underscores are permitted.")
    return cleaned


def generate_unique_id(length: int = 12) -> str:
    """
    Generates a URL-safe, collision-resistant unique identifier for new diagrams.
    """
    token = secrets.token_urlsafe(length)[:length]
    # Replace urlsafe characters that might cause path ambiguity
    return token.replace("-", "A").replace("_", "B")


class StorageManager:
    """
    Handles all reading, writing, updating, and indexing of diagram files.
    """
    def __init__(self, storage_path: Path = config.STORAGE_PATH):
        self.storage_path = storage_path
        self.storage_path.mkdir(parents=True, exist_ok=True)

    def _get_paths(self, diagram_id: str) -> Tuple[Path, Path, Path]:
        """
        Returns (bpmn_path, svg_path, meta_path) for the given diagram ID.
        """
        clean_id = sanitize_diagram_id(diagram_id)
        bpmn_file = self.storage_path / f"{clean_id}.bpmn"
        svg_file = self.storage_path / f"{clean_id}.svg"
        meta_file = self.storage_path / f"{clean_id}.json"
        return bpmn_file, svg_file, meta_file

    def _atomic_write_text(self, destination: Path, content: str):
        """
        Writes text content to a temporary sibling file and renames it atomically.
        """
        temp_file = destination.with_suffix(destination.suffix + ".tmp")
        with open(temp_file, "w", encoding="utf-8") as f:
            f.write(content)
        os.replace(temp_file, destination)

    def create_diagram(
        self,
        friendly_name: str,
        project_name: str,
        project_description: str,
        author: str,
        initial_xml: Optional[str] = None,
        custom_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Initializes a brand-new diagram on disk with metadata and default BPMN XML.
        """
        diagram_id = sanitize_diagram_id(custom_id) if custom_id else generate_unique_id()
        bpmn_file, svg_file, meta_file = self._get_paths(diagram_id)

        now_iso = datetime.now(timezone.utc).isoformat()

        # Default minimal BPMN 2.0 XML definitions if none supplied
        if not initial_xml or not initial_xml.strip():
            initial_xml = (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<bpmn:definitions xmlns:bpmn="http://www.omg.org/spec/BPMN/20100524/MODEL" '
                'xmlns:bpmndi="http://www.omg.org/spec/BPMN/20100524/DI" '
                'xmlns:dc="http://www.omg.org/spec/DD/20100524/DC" '
                'id="Definitions_1" targetNamespace="http://bpmn.io/schema/bpmn">\n'
                f'  <bpmn:process id="Process_{diagram_id}" isExecutable="false">\n'
                f'    <bpmn:startEvent id="StartEvent_1" name="Start"/>\n'
                '  </bpmn:process>\n'
                f'  <bpmndi:BPMNDiagram id="BPMNDiagram_1">\n'
                f'    <bpmndi:BPMNPlane id="BPMNPlane_1" bpmnElement="Process_{diagram_id}">\n'
                '      <bpmndi:BPMNShape id="_BPMNShape_StartEvent_1" bpmnElement="StartEvent_1">\n'
                '        <dc:Bounds x="179" y="99" width="36" height="36"/>\n'
                '      </bpmndi:BPMNShape>\n'
                '    </bpmndi:BPMNPlane>\n'
                '  </bpmndi:BPMNDiagram>\n'
                '</bpmn:definitions>'
            )

        # Write .bpmn file
        self._atomic_write_text(bpmn_file, initial_xml)

        # Create metadata structure
        metadata = {
            "id": diagram_id,
            "friendly_name": friendly_name.strip(),
            "project_name": project_name.strip() if project_name else "",
            "project_description": project_description.strip() if project_description else "",
            "author": author,
            "last_edited_by": author,
            "created_at": now_iso,
            "updated_at": now_iso,
            "is_deleted": False,
        }

        # Write .json metadata file
        self._atomic_write_text(meta_file, json.dumps(metadata, indent=2))

        return metadata

    def get_metadata(self, diagram_id: str) -> Optional[Dict[str, Any]]:
        """
        Reads diagram metadata from disk.
        """
        _, _, meta_file = self._get_paths(diagram_id)
        if not meta_file.exists():
            return None

        try:
            with open(meta_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data
        except Exception as e:
            print(f"[Storage Warning] Could not read metadata for {diagram_id}: {e}")
            return None

    def update_metadata(self, diagram_id: str, updates: Dict[str, Any], editor: str) -> Optional[Dict[str, Any]]:
        """
        Updates metadata fields on disk.
        """
        meta = self.get_metadata(diagram_id)
        if not meta:
            return None

        # Apply permitted updates
        for field in ("friendly_name", "project_name", "project_description", "is_deleted"):
            if field in updates and updates[field] is not None:
                meta[field] = updates[field]

        meta["last_edited_by"] = editor
        meta["updated_at"] = datetime.now(timezone.utc).isoformat()

        _, _, meta_file = self._get_paths(diagram_id)
        self._atomic_write_text(meta_file, json.dumps(meta, indent=2))
        return meta

    def save_diagram(
        self,
        diagram_id: str,
        bpmn_xml: str,
        sanitized_svg: Optional[str],
        editor: str,
        metadata_updates: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Performs dual-save: atomically writes the BPMN XML and the pre-rendered SVG,
        and updates diagram metadata timestamps.
        """
        bpmn_file, svg_file, meta_file = self._get_paths(diagram_id)

        # 1. Write BPMN XML
        self._atomic_write_text(bpmn_file, bpmn_xml)

        # 2. Write SVG if provided
        if sanitized_svg and sanitized_svg.strip():
            self._atomic_write_text(svg_file, sanitized_svg)

        # 3. Update metadata
        meta = self.get_metadata(diagram_id)
        if not meta:
            # Generate fallback metadata if missing
            meta = {
                "id": diagram_id,
                "friendly_name": diagram_id,
                "project_name": "",
                "project_description": "",
                "author": editor,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }

        if metadata_updates:
            for k in ("friendly_name", "project_name", "project_description"):
                if k in metadata_updates and metadata_updates[k] is not None:
                    meta[k] = metadata_updates[k]

        meta["last_edited_by"] = editor
        meta["updated_at"] = datetime.now(timezone.utc).isoformat()

        self._atomic_write_text(meta_file, json.dumps(meta, indent=2))
        return meta

    def read_bpmn(self, diagram_id: str) -> Optional[str]:
        """
        Reads the BPMN XML content for a diagram.
        """
        bpmn_file, _, _ = self._get_paths(diagram_id)
        if not bpmn_file.exists():
            return None
        with open(bpmn_file, "r", encoding="utf-8") as f:
            return f.read()

    def read_svg(self, diagram_id: str) -> Optional[str]:
        """
        Reads the pre-rendered SVG for a diagram.
        """
        _, svg_file, _ = self._get_paths(diagram_id)
        if not svg_file.exists():
            return None
        with open(svg_file, "r", encoding="utf-8") as f:
            return f.read()

    def list_diagrams(self, include_deleted: bool = False) -> List[Dict[str, Any]]:
        """
        Lists all diagrams present in storage.
        """
        results = []
        if not self.storage_path.exists():
            return results

        # Iterate over all .json metadata files
        for meta_file in sorted(self.storage_path.glob("*.json"), key=os.path.getmtime, reverse=True):
            diagram_id = meta_file.stem
            try:
                with open(meta_file, "r", encoding="utf-8") as f:
                    meta = json.load(f)

                if not include_deleted and meta.get("is_deleted", False):
                    continue

                # Check if SVG exists
                svg_file = self.storage_path / f"{diagram_id}.svg"
                meta["has_svg"] = svg_file.exists()

                results.append(meta)
            except Exception as e:
                print(f"[Storage Warning] Skipped unreadable metadata {meta_file}: {e}")

        return results

    def soft_delete(self, diagram_id: str, editor: str) -> bool:
        """
        Flags a diagram as deleted without unlinking the underlying files from disk.
        """
        meta = self.get_metadata(diagram_id)
        if not meta:
            return False
        meta["is_deleted"] = True
        meta["last_edited_by"] = editor
        meta["updated_at"] = datetime.now(timezone.utc).isoformat()
        _, _, meta_file = self._get_paths(diagram_id)
        self._atomic_write_text(meta_file, json.dumps(meta, indent=2))
        return True


# Global storage manager singleton
storage = StorageManager()

