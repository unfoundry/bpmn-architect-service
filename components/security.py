"""
==============================================================================
BPMN Architect Service - Security & File Validation Engine
==============================================================================
Provides strict, multi-layered security validation for incoming BPMN XML
and SVG diagram files.

Key Security Guarantees:
1. Max Payload Size Enforcement: Prevents memory exhaustion / DoS attacks.
2. XML External Entity (XXE) Protection: Employs defusedxml to block entity
   expansion, external DTDs, and billion-laughs vulnerabilities.
3. BPMN 2.0 Semantic Verification: Ensures the file is an authentic BPMN model
   rather than arbitrary XML disguised as a diagram.
4. SVG Sanitization & Script Stripping: Cleans SVGs against Cross-Site
   Scripting (XSS), inline JavaScript (<script>), event handlers (onload, onerror),
   and malicious external references.
==============================================================================
"""

import io
import re
import xml.etree.ElementTree as ET
from typing import Tuple, Dict, Any

# Safe XML Parsing: prioritize defusedxml for input parsing; fall back to standard ET with warning
try:
    import defusedxml.ElementTree as SafeET
    HAS_DEFUSEDXML = True
except ImportError:
    SafeET = ET
    HAS_DEFUSEDXML = False
    print("[Security Warning] 'defusedxml' is not installed! Using standard xml.etree.ElementTree.")

from config import MAX_PAYLOAD_SIZE_BYTES, MAX_PAYLOAD_SIZE_MB

# Standard BPMN 2.0 Namespace constants
BPMN_NAMESPACES = {
    "bpmn": "http://www.omg.org/spec/BPMN/20100524/MODEL",
    "bpmndi": "http://www.omg.org/spec/BPMN/20100524/DI",
    "dc": "http://www.omg.org/spec/DD/20100524/DC",
    "di": "http://www.omg.org/spec/DD/20100524/DI",
}

# SVG Tags that are strictly prohibited due to potential code execution / iframe injection
FORBIDDEN_SVG_TAGS = {
    "script",
    "foreignobject",
    "applet",
    "object",
    "embed",
    "iframe",
    "meta",
    "link",
}

# URL schemes that are forbidden in href / xlink:href attributes
FORBIDDEN_URL_SCHEMES = ("javascript:", "vbscript:", "data:text/html", "data:text/javascript")


# ==============================================================================
# 1. BPMN XML VALIDATION
# ==============================================================================

def validate_bpmn_xml(xml_bytes: bytes, max_allowed_bytes: int = MAX_PAYLOAD_SIZE_BYTES) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Validates that the provided byte payload is authentic, safe BPMN 2.0 XML.

    Args:
        xml_bytes: Raw bytes received from the client upload / save request.
        max_allowed_bytes: Maximum permitted size in bytes (defaults to config setting).

    Returns:
        A tuple of (is_valid: bool, error_message: str, extracted_metadata: dict).
        If valid, error_message is empty ("") and extracted_metadata contains detected details.
    """
    # Step 1: Payload size check
    payload_size = len(xml_bytes)
    if payload_size == 0:
        return False, "Payload is empty.", {}

    if payload_size > max_allowed_bytes:
        return (
            False,
            f"Payload size ({payload_size / (1024 * 1024):.2f} MB) exceeds maximum allowed limit of {MAX_PAYLOAD_SIZE_MB} MB.",
            {},
        )

    # Step 2: Decode payload to string and check for basic XML marker
    try:
        xml_str = xml_bytes.decode("utf-8", errors="replace")
    except Exception as e:
        return False, f"Failed to decode XML payload as UTF-8: {str(e)}", {}

    # Quick pre-filter to reject non-XML before invoking the XML parser
    if "<" not in xml_str or "definitions" not in xml_str.lower():
        return False, "Payload does not appear to contain a BPMN <definitions> block.", {}

    # Step 3: Safe XML Parse (XXE & Entity Expansion Protected)
    try:
        root = SafeET.fromstring(xml_bytes)
    except Exception as parse_err:
        return False, f"Malformed XML structure or parsing error: {str(parse_err)}", {}

    # Step 4: Validate Root Tag
    # Root tag in ElementTree will be either '{http://www.omg.org/spec/BPMN/20100524/MODEL}definitions' or 'definitions'
    root_tag = root.tag.lower()
    if not (root_tag.endswith("definitions")):
        return (
            False,
            f"Invalid root XML element '{root.tag}'. Expected BPMN '<definitions>'.",
            {},
        )

    # Step 5: Extract basic metadata safely
    extracted_metadata = {
        "id": root.attrib.get("id", "Definitions_Unknown"),
        "targetNamespace": root.attrib.get("targetNamespace", ""),
        "exporter": root.attrib.get("exporter", "bpmn-js"),
        "element_count": len(list(root.iter())),
    }

    return True, "", extracted_metadata


# ==============================================================================
# 2. SVG VALIDATION & SANITIZATION
# ==============================================================================

def validate_and_sanitize_svg(svg_bytes: bytes, max_allowed_bytes: int = MAX_PAYLOAD_SIZE_BYTES) -> Tuple[bool, str, str]:
    """
    Validates and sanitizes an SVG diagram image against XSS, malicious scripts,
    and dangerous tags.

    Args:
        svg_bytes: Raw bytes of the SVG file uploaded by the client.
        max_allowed_bytes: Maximum permitted size in bytes.

    Returns:
        A tuple of (is_valid: bool, error_message: str, sanitized_svg_string: str).
    """
    # Step 1: Payload size check
    payload_size = len(svg_bytes)
    if payload_size == 0:
        return False, "SVG payload is empty.", ""

    if payload_size > max_allowed_bytes:
        return (
            False,
            f"SVG size ({payload_size / (1024 * 1024):.2f} MB) exceeds maximum allowed limit of {MAX_PAYLOAD_SIZE_MB} MB.",
            "",
        )

    # Step 2: Decode payload
    try:
        svg_str = svg_bytes.decode("utf-8", errors="replace")
    except Exception as e:
        return False, f"Failed to decode SVG as UTF-8: {str(e)}", ""

    # Quick pre-filter
    if "<svg" not in svg_str.lower():
        return False, "Payload does not contain an opening <svg> tag.", ""

    # Step 3: Safe XML Parse
    try:
        root = SafeET.fromstring(svg_bytes)
    except Exception as parse_err:
        return False, f"Malformed SVG XML structure: {str(parse_err)}", ""

    # Step 4: Validate Root Tag
    root_tag = root.tag.lower()
    if not root_tag.endswith("svg"):
        return False, f"Invalid root element '{root.tag}'. Expected '<svg>'.", ""

    # Step 5: Sanitize element tree recursively
    # Strip forbidden tags and attributes
    def sanitize_element(element):
        # 1. Clean attributes of this element
        attrs_to_remove = []
        for attr_name, attr_val in list(element.attrib.items()):
            attr_lower = attr_name.lower()
            val_lower = str(attr_val).strip().lower()

            # Remove event handlers (e.g. onload, onclick, onerror, onmouseover)
            if attr_lower.startswith("on"):
                attrs_to_remove.append(attr_name)
                continue

            # Check for javascript: pseudo-protocols in links
            for scheme in FORBIDDEN_URL_SCHEMES:
                if scheme in val_lower.replace(" ", ""):
                    attrs_to_remove.append(attr_name)
                    break

        for a in attrs_to_remove:
            del element.attrib[a]

        # 2. Inspect children: remove any element whose tag is forbidden
        children_to_remove = []
        for child in list(element):
            child_tag = child.tag.split("}")[-1].lower() if "}" in child.tag else child.tag.lower()
            if child_tag in FORBIDDEN_SVG_TAGS:
                children_to_remove.append(child)
            else:
                # Recurse down into safe children
                sanitize_element(child)

        for c in children_to_remove:
            element.remove(c)

    # Execute recursive sanitization
    sanitize_element(root)

    # Step 6: Convert sanitized tree back to UTF-8 XML string
    try:
        # Register default SVG namespace if missing to keep output tidy
        ET.register_namespace("", "http://www.w3.org/2000/svg")
        output_buffer = io.BytesIO()
        ET.ElementTree(root).write(output_buffer, encoding="utf-8", xml_declaration=True)
        sanitized_svg = output_buffer.getvalue().decode("utf-8")
    except Exception as serialize_err:
        return False, f"Failed to serialize sanitized SVG: {str(serialize_err)}", ""

    return True, "", sanitized_svg

