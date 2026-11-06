"""
==============================================================================
BPMN Architect Service - Configuration Loader
==============================================================================
Reads environment variables from the `.env` file or operating system environment.
Provides typed, validated configuration constants used across the application.
Includes automatic directory verification and path normalization.
==============================================================================
"""

import os
from pathlib import Path
from typing import List

# Attempt to load dotenv if available
try:
    from dotenv import load_dotenv
    # Resolve the .env path located in the same directory as this file
    env_path = Path(__file__).resolve().parent / ".env"
    if env_path.exists():
        load_dotenv(dotenv_path=env_path)
    else:
        # Fall back to default search
        load_dotenv()
except ImportError:
    # If python-dotenv is not yet installed, standard OS environment variables will be used
    pass

# Base directory of the service module
SERVICE_BASE_DIR = Path(__file__).resolve().parent

# ------------------------------------------------------------------------------
# 1. NETWORK & SERVICE BINDINGS
# ------------------------------------------------------------------------------
SERVICE_HOST: str = os.getenv("SERVICE_HOST", "0.0.0.0")
SERVICE_PORT: int = int(os.getenv("SERVICE_PORT", "8001"))
SERVICE_ROOT_PATH: str = os.getenv("SERVICE_ROOT_PATH", "").strip()

# Base URL of the static frontend application (used for admin and status links)
UI_BASE_URL: str = os.getenv("UI_BASE_URL", "http://127.0.0.1:8080").strip().rstrip("/")

# Parse comma-separated CORS origins into a list of strings
_cors_raw = os.getenv("CORS_ORIGINS", "*").strip()
CORS_ORIGINS: List[str] = [origin.strip() for origin in _cors_raw.split(",") if origin.strip()]

# ------------------------------------------------------------------------------
# 2. STORAGE & SIZE LIMITS
# ------------------------------------------------------------------------------
# Configurable storage directory path
_storage_dir_raw = os.getenv("STORAGE_DIR", "../diagram_storage").strip()
STORAGE_PATH: Path = (SERVICE_BASE_DIR / _storage_dir_raw).resolve()

# Ensure the storage directory exists on service startup
try:
    STORAGE_PATH.mkdir(parents=True, exist_ok=True)
except Exception as e:
    print(f"[Config Warning] Could not automatically create STORAGE_PATH: {STORAGE_PATH}. Error: {e}")

# Max payload size limit in megabytes
MAX_PAYLOAD_SIZE_MB: int = int(os.getenv("MAX_PAYLOAD_SIZE_MB", "5"))
MAX_PAYLOAD_SIZE_BYTES: int = MAX_PAYLOAD_SIZE_MB * 1024 * 1024

# Storage Audit & File Listing Controls (used by /admin console)
STORAGE_AUDIT_LIMIT: int = int(os.getenv("STORAGE_AUDIT_LIMIT", "100"))
STORAGE_AUDIT_MAX_DAYS: int = int(os.getenv("STORAGE_AUDIT_MAX_DAYS", "0"))

# ------------------------------------------------------------------------------
# 3. AUTHENTICATION & ACCESS CONTROL
# ------------------------------------------------------------------------------
# Accepted methods: "none", "master-key", "iis-header", "ldap"
AUTH_METHOD: str = os.getenv("AUTH_METHOD", "master-key").lower().strip()

# Master Key
MASTER_KEY: str = os.getenv("MASTER_KEY", "dev-master-key-12345").strip()

# IIS / Reverse Proxy Header
IIS_HEADER_NAME: str = os.getenv("IIS_HEADER_NAME", "X-Forwarded-User").strip()
_iis_admins_raw = os.getenv("IIS_ADMIN_USERS", "admin,CORP\\admin")
# Normalized list of admin usernames (case-insensitive comparison handled in auth.py)
IIS_ADMIN_USERS: List[str] = [u.strip().lower() for u in _iis_admins_raw.split(",") if u.strip()]

# LDAP / Active Directory Settings
LDAP_SERVER_URL: str = os.getenv("LDAP_SERVER_URL", "ldap://127.0.0.1:389").strip()
LDAP_BIND_DN: str = os.getenv("LDAP_BIND_DN", "").strip()
LDAP_BIND_PASSWORD: str = os.getenv("LDAP_BIND_PASSWORD", "").strip()
LDAP_BASE_DN: str = os.getenv("LDAP_BASE_DN", "").strip()
LDAP_USER_SEARCH_FILTER: str = os.getenv("LDAP_USER_SEARCH_FILTER", "(&(objectClass=user)(sAMAccountName={username}))").strip()
LDAP_ADMIN_GROUP_DN: str = os.getenv("LDAP_ADMIN_GROUP_DN", "").strip().lower()

# ------------------------------------------------------------------------------
# 4. COOPERATIVE LOCK & SESSION TIMINGS
# ------------------------------------------------------------------------------
LOCK_HEARTBEAT_SEC: int = int(os.getenv("LOCK_HEARTBEAT_SEC", "15"))
LOCK_EXPIRY_PAD_SEC: int = int(os.getenv("LOCK_EXPIRY_PAD_SEC", "15"))
IDLE_TIMEOUT_MIN: int = int(os.getenv("IDLE_TIMEOUT_MIN", "15"))

# Total lifetime of a lock window before expiring if no heartbeat arrives
TOTAL_LOCK_EXPIRY_SEC: int = LOCK_HEARTBEAT_SEC + LOCK_EXPIRY_PAD_SEC

