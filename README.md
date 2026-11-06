# BPMN Architect Service

> Headless, high-performance Python FastAPI microservice providing BPMN 2.0 validation, Kroki-style SVG rendering, dual-save persistence, cooperative soft-locking, and administrative governance.

Part of the **BPMN Architect Suite**:
- **[bpmn-architect-ui](https://github.com/unfoundry/bpmn-architect-ui)**: Client web application, process modeler, and embeddable viewer.
- **[bpmn-architect-service](https://github.com/unfoundry/bpmn-architect-service)**: Headless Python FastAPI microservice (this repository).
- **[bpmn-architect-docs](https://github.com/unfoundry/bpmn-architect-docs)**: Comprehensive VitePress documentation and deployment guides.

---

## Key Capabilities

1. **Dual-Save Persistence Engine**:
   - Atomically writes both the validated BPMN 2.0 XML (`{id}.bpmn`) and the pre-rendered SVG vector image (`{id}.svg`), plus descriptive metadata (`{id}.json`).
   - Uses temporary sibling writes and `os.replace` to prevent corrupted writes if network disconnects mid-save.
   - Decoupled disk layout: Allows Nginx or IIS to serve files statically even if the microservice process is stopped.
2. **Kroki-Like Direct SVG Renderer**:
   - `GET /api/diagram/{id}/svg` renders the cached, sanitized SVG directly.
   - Ideal for embedding into HTML `<img>` tags, Markdown documentation, wikis, and Jira tickets.
3. **Hardened Security Pipeline**:
   - **XXE Prevention**: BPMN XML payloads are parsed defensively via `defusedxml.ElementTree` to prevent XML entity expansion, external DTD fetching, and quadratic blowout attacks.
   - **SVG Sanitization**: Strips malicious `<script>` tags, event handlers (`onload`, `onerror`), and foreign namespaces while preserving presentation graphics.
   - **Payload Limit**: Enforces a strict 5MB upload ceiling configured via `MAX_PAYLOAD_SIZE_MB`.
4. **Cooperative Soft-Locking & Presence**:
   - Manages single-active-editor soft-locks with automated heartbeat renewals (`LOCK_HEARTBEAT_SEC=15`).
   - Supports handoff requests and voluntary yields to prevent hostage files without abrupt timeouts.
5. **Administrative Governance Console (`/admin`)**:
   - Dedicated governance portal protected by the configured authentication provider.
   - **Force Unlock**: Clear stuck collaborator edit locks.
   - **Soft-Delete & Recovery**: Safely archive and restore diagrams with SweetAlert2 confirmation dialogs.
   - **Storage Audit**: Inspect physical disk bundles grouped by Diagram ID with pagination, search, and configurable limit filters (`STORAGE_AUDIT_LIMIT`, `STORAGE_AUDIT_MAX_DAYS`).
6. **Multi-Strategy Authentication**:
   - `none`: Open development mode.
   - `master-key`: Shared secret validated via `X-Master-Key`, Bearer token, or session cookie.
   - `iis-header`: Windows Authentication via reverse proxy (`X-Forwarded-User` or `REMOTE_USER`) with admin whitelist matching.
   - `ldap`: Active Directory / OpenLDAP HTTP Basic Auth with group membership checks (`LDAP_ADMIN_GROUP_DN`).

---

## Directory Layout

```
bpmn-architect-service/
├── components/
│   ├── auth.py           # Multi-provider authentication & authorization guards
│   ├── lock_manager.py   # Async cooperative soft-lock broker & presence
│   ├── models.py         # Pydantic v2 validation models & request schemas
│   ├── security.py       # Hardened XXE & SVG XSS sanitization pipeline
│   └── storage.py        # File-system storage engine with atomic writes
├── static/
│   └── img/              # Service brand logos and icons (mounted at /static)
├── templates/
│   ├── base.html         # Base template with Lumen styling & navbar
│   ├── status.html       # Public operational status board (/)
│   └── admin.html        # Administrative governance console (/admin)
├── config.py             # Typed configuration loader from environment
├── main.py               # FastAPI application definition & endpoint handlers
├── requirements.txt      # Python dependencies
├── .env.example          # Environment template
├── .env                  # Local configuration (git-ignored)
└── .gitignore
```

---

## Quick Start

### 1. Requirements

- Python 3.10+ (tested on Python 3.12)
- Virtual environment recommended

### 2. Installation

```bash
# Create virtual environment
python3 -m venv .venv

# Activate virtual environment
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Environment Configuration

Copy `.env.example` to `.env` and adjust your settings:

```bash
cp .env.example .env
```

Key environment variables in `.env`:

```ini
SERVICE_HOST=0.0.0.0
SERVICE_PORT=8002
SERVICE_ROOT_PATH=
CORS_ORIGINS=*

STORAGE_DIR=../diagram_storage
MAX_PAYLOAD_SIZE_MB=5

# Audit controls for /admin console
STORAGE_AUDIT_LIMIT=100
STORAGE_AUDIT_MAX_DAYS=0

# Authentication method: "none", "master-key", "iis-header", "ldap"
AUTH_METHOD=master-key
MASTER_KEY=dev-master-key-12345

# URL where the frontend web app is hosted (used by admin and status portal links)
UI_BASE_URL=http://127.0.0.1:8080
```

### 4. Running the Service

```bash
# Using Python runner
python main.py

# Or via Uvicorn directly
uvicorn main:app --host 0.0.0.0 --port 8002 --reload
```

- Public Status Board: `http://localhost:8002/`
- Administrative Console: `http://localhost:8002/admin`
- Interactive OpenAPI Docs: `http://localhost:8002/docs`
- Health Check (JSON): `http://localhost:8002/health`

---

## Primary API Endpoints

| Method | Endpoint | Description | Auth Required |
| :--- | :--- | :--- | :--- |
| `GET` | `/health` | Returns service health and active configuration. | No |
| `GET` | `/` | Operational status board with live uptime tracking. | No |
| `GET` | `/admin` | Administrative console for locks & storage governance. | Admin |
| `GET` | `/api/diagrams` | List all active diagrams and current lock states. | User |
| `POST` | `/api/diagram/new` | Create a new diagram with optional starter XML. | User |
| `GET` | `/api/diagram/{id}` | Retrieve metadata and live lock info. | User |
| `GET` | `/api/diagram/{id}/xml`| Raw BPMN 2.0 XML for static viewing / embedding. | No |
| `GET` | `/api/diagram/{id}/svg`| Kroki-like rendered vector SVG preview. | No |
| `POST` | `/api/diagram/{id}/save`| Dual-save endpoint: persists XML and SVG atomically. | Editor |
| `POST` | `/api/diagram/{id}/lock`| Cooperative lock actions (acquire, heartbeat, release). | User |
| `POST` | `/api/diagram/{id}/delete`| Soft-deletes a diagram and releases active lock. | Author/Admin |
| `POST` | `/api/diagram/{id}/restore`| Restores a soft-deleted diagram to active status. | Admin |
| `POST` | `/api/diagram/{id}/unlock`| Force releases a stuck session lock. | Admin |

---

## License

Apache-2.0. Copyright &copy; 2026 BPMN Architect / Unfoundry.
