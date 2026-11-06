"""
==============================================================================
BPMN Architect Service - Authentication & Authorization Provider
==============================================================================
Provides enterprise authentication handling supporting four distinct strategies:

1. 'none'        : Open development mode with full administrative privileges.
2. 'master-key'  : Shared secret header (X-Master-Key or Bearer <token>).
                   Ideal for CI/CD, scripting, or simple secured deployments.
3. 'iis-header'  : Windows Authentication header injected by IIS ARR or reverse
                   proxies (e.g. X-Forwarded-User). Compares username against
                   the configured admin whitelist to grant admin privileges.
4. 'ldap'        : Authenticates via Active Directory / OpenLDAP using HTTP Basic
                   Auth credentials. Checks memberOf against LDAP_ADMIN_GROUP_DN
                   to grant admin privileges.
==============================================================================
"""

import secrets
from typing import Optional
from fastapi import Request, HTTPException, Security, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials

import config
from components.models import AuthUser

# HTTP Basic security scheme helper (auto_error=False to allow header inspection first)
basic_security = HTTPBasic(auto_error=False)

# Optional ldap3 import
try:
    from ldap3 import Server, Connection, ALL, SUBTREE
    HAS_LDAP3 = True
except ImportError:
    HAS_LDAP3 = False


def _verify_ldap_credentials(username: str, password: str) -> Optional[AuthUser]:
    """
    Validates user credentials against the configured LDAP / Active Directory server.
    Checks group membership to determine if the user is an admin.
    """
    if not HAS_LDAP3:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="LDAP authentication is enabled in configuration, but the 'ldap3' package is not installed."
        )

    if not config.LDAP_SERVER_URL or not config.LDAP_BASE_DN:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="LDAP_SERVER_URL or LDAP_BASE_DN is not configured in service environment."
        )

    try:
        server = Server(config.LDAP_SERVER_URL, get_info=ALL, connect_timeout=5)
        
        # Step 1: Bind with service account (if configured) or direct bind
        if config.LDAP_BIND_DN and config.LDAP_BIND_PASSWORD:
            service_conn = Connection(server, user=config.LDAP_BIND_DN, password=config.LDAP_BIND_PASSWORD, auto_bind=True)
            # Search for the user's distinguished name (DN) and memberOf groups
            search_filter = config.LDAP_USER_SEARCH_FILTER.replace("{username}", username)
            service_conn.search(
                search_base=config.LDAP_BASE_DN,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=["distinguishedName", "memberOf", "sAMAccountName", "mail"]
            )
            
            if not service_conn.entries:
                service_conn.unbind()
                return None  # User not found in directory
            
            user_entry = service_conn.entries[0]
            user_dn = str(user_entry.distinguishedName)
            member_of = [str(g).lower() for g in getattr(user_entry, "memberOf", [])]
            service_conn.unbind()
            
            # Step 2: Attempt user bind with user's DN and supplied password
            user_conn = Connection(server, user=user_dn, password=password)
            if not user_conn.bind():
                return None  # Invalid password
            user_conn.unbind()
            
            # Step 3: Determine admin role based on AD Group membership
            is_admin = False
            if config.LDAP_ADMIN_GROUP_DN:
                is_admin = any(config.LDAP_ADMIN_GROUP_DN in group_dn for group_dn in member_of)

            role = "admin" if is_admin else "editor"
            return AuthUser(username=username, role=role, auth_method="ldap")

        else:
            # Direct bind attempt using username and base DN
            user_conn = Connection(server, user=f"{username}@{config.LDAP_BASE_DN}", password=password)
            if not user_conn.bind():
                return None
            user_conn.unbind()
            return AuthUser(username=username, role="editor", auth_method="ldap")

    except Exception as ldap_err:
        print(f"[Auth LDAP Error] Failed during LDAP query: {ldap_err}")
        return None


async def get_current_user(
    request: Request,
    credentials: Optional[HTTPBasicCredentials] = Security(basic_security)
) -> AuthUser:
    """
    FastAPI dependency that extracts and validates user credentials according
    to the configured AUTH_METHOD setting.
    """
    method = config.AUTH_METHOD

    # --------------------------------------------------------------------------
    # 1. OPEN / DEV MODE
    # --------------------------------------------------------------------------
    if method == "none":
        # Allow optional X-Username override for testing multi-user flows in dev mode
        dev_username = request.headers.get("X-Username", "dev-user").strip() or "dev-user"
        return AuthUser(username=dev_username, role="admin", auth_method="none")

    # --------------------------------------------------------------------------
    # 2. MASTER KEY AUTHENTICATION
    # --------------------------------------------------------------------------
    elif method == "master-key":
        # Check X-Master-Key header first
        provided_key = request.headers.get("X-Master-Key")

        # Check Authorization Bearer header as secondary option
        if not provided_key:
            auth_header = request.headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                provided_key = auth_header[7:].strip()

        # Check cookie (for browser sessions in admin portal)
        if not provided_key:
            provided_key = request.cookies.get("bpmn_master_key")

        # Check query param (convenient for deep links)
        if not provided_key:
            provided_key = request.query_params.get("key")

        if not provided_key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required. Please provide a valid 'X-Master-Key' header, 'Bearer' token, or session cookie.",
                headers={"WWW-Authenticate": "Bearer"}
            )

        # Constant-time comparison to prevent timing attacks
        if not secrets.compare_digest(provided_key, config.MASTER_KEY):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid master key credentials."
            )

        # Allow user to identify as a specific named editor while authenticating via master key
        acting_user = request.headers.get("X-Username") or request.cookies.get("bpmn_user") or "master-admin"
        return AuthUser(username=acting_user.strip(), role="admin", auth_method="master-key")

    # --------------------------------------------------------------------------
    # 3. IIS / REVERSE PROXY IDENTITY HEADER
    # --------------------------------------------------------------------------
    elif method == "iis-header":
        user_header = request.headers.get(config.IIS_HEADER_NAME)
        if not user_header or not user_header.strip():
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Missing identity header '{config.IIS_HEADER_NAME}'. Ensure Windows Auth is enabled in IIS."
            )

        username = user_header.strip()
        normalized_username = username.lower()

        # Check against admin list (matches either full DOMAIN\\user or just user)
        is_admin = False
        user_short = normalized_username.split("\\")[-1] if "\\" in normalized_username else normalized_username
        for admin_entry in config.IIS_ADMIN_USERS:
            if normalized_username == admin_entry or user_short == admin_entry:
                is_admin = True
                break

        role = "admin" if is_admin else "editor"
        return AuthUser(username=username, role=role, auth_method="iis-header")

    # --------------------------------------------------------------------------
    # 4. LDAP / ACTIVE DIRECTORY BASIC AUTH
    # --------------------------------------------------------------------------
    elif method == "ldap":
        if not credentials:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="LDAP credentials required.",
                headers={"WWW-Authenticate": "Basic realm='BPMN Architect'"}
            )

        auth_user = _verify_ldap_credentials(credentials.username, credentials.password)
        if not auth_user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid LDAP username or password.",
                headers={"WWW-Authenticate": "Basic realm='BPMN Architect'"}
            )

        return auth_user

    else:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unsupported AUTH_METHOD '{method}' in service configuration."
        )


def require_admin(current_user: AuthUser = Security(get_current_user)) -> AuthUser:
    """
    FastAPI dependency guard enforcing that the active user possesses the 'admin' role.
    """
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrative privileges required for this action."
        )
    return current_user

