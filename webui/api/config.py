from pathlib import Path
import os
import json
import platform
import string
from typing import List


def _find_repo_root() -> Path:
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "dakshscra.py").exists():
            return parent
    return here.parents[1]


ROOT_DIR = _find_repo_root()
_DEFAULT_DB = f"sqlite:///{ROOT_DIR / 'runtime' / 'daksh.db'}"
DATABASE_URL = os.getenv("DATABASE_URL", _DEFAULT_DB)

# ── Authentication ────────────────────────────────────────────────────────
SESSION_COOKIE_NAME = "daksh_session"
ADMIN_USERNAME = os.getenv("DAKSH_ADMIN_USERNAME", "admin").strip() or "admin"
ADMIN_PASSWORD = os.getenv("DAKSH_ADMIN_PASSWORD", "").strip()
COOKIE_SECURE = os.getenv("DAKSH_COOKIE_SECURE", "false").strip().lower() == "true"
try:
    SESSION_TTL_HOURS = int(os.getenv("DAKSH_SESSION_TTL_HOURS", "168"))
except ValueError:
    SESSION_TTL_HOURS = 168


def get_cors_origins() -> List[str]:
    """Explicit allow-list for cross-origin requests with credentials.

    Production traffic is same-origin (nginx proxies /api/* alongside the
    built frontend on one origin) and needs no CORS entry at all. This is
    only for `npm run dev` (Vite dev server on its own port hitting a
    directly-running API), so the default only covers that.
    """
    raw = os.getenv("DAKSH_CORS_ORIGINS", "").strip()
    if raw:
        return [x.strip() for x in raw.split(",") if x.strip()]
    return ["http://localhost:5173"]


def host_locations() -> list:
    """Mount metadata supplied by the host launcher, never by the browser."""
    try:
        items = json.loads(os.getenv("DAKSH_HOST_PATHS", "[]"))
        return [x for x in items if isinstance(x, dict)
                and all(isinstance(x.get(k), str) for k in ("source", "path", "label"))]
    except (TypeError, ValueError):
        return []


def _default_browse_roots() -> List[str]:
    if os.getenv("DAKSH_CONTAINER") == "1" or Path("/.dockerenv").exists():
        # The OS inside the image is Linux even when the host is Windows/macOS.
        # Expose mounted host locations, not the image's /, /tmp or /home.
        locations = host_locations()
        roots = [x["path"] for x in locations]
        roots += ["/host/root", "/scan-targets"]
        for base in ("/host/drives", "/host/locations"):
            try:
                roots += [str(p) for p in sorted(Path(base).iterdir()) if p.is_dir()]
            except OSError:
                pass
        if not locations:
            for name in ("home", "Users", "Volumes", "mnt", "media", "srv", "opt"):
                roots.append(f"/host/root/{name}")
        roots.append(str(ROOT_DIR))
        return roots
    system = platform.system()
    if system == "Windows":
        return [f"{letter}:\\" for letter in string.ascii_uppercase] + [str(Path.home()), str(ROOT_DIR)]
    if system == "Darwin":
        return ["/", str(Path.home()), "/Users", "/Volumes", str(ROOT_DIR)]
    return ["/", str(Path.home()), "/home", "/mnt", "/media", "/srv", str(ROOT_DIR)]


def get_browse_roots() -> List[str]:
    raw = os.getenv("DAKSH_BROWSE_ROOTS", "").strip()
    candidates = [x.strip() for x in raw.split(",") if x.strip()] if raw else _default_browse_roots()
    roots: List[str] = []
    for candidate in candidates:
        try:
            p = Path(candidate).expanduser().resolve()
            if p.is_dir() and str(p) not in roots:
                roots.append(str(p))
        except (OSError, RuntimeError):
            continue
    # An explicit allow-list must never silently fall back to a broader root.
    return roots if roots or raw else [str(ROOT_DIR)]


def browse_shortcuts(roots: List[str]) -> list:
    labels = {str(Path(x["path"]).resolve()): x["label"] for x in host_locations()}
    defaults = {"/host/root": "Host filesystem", "/scan-targets": "Scan targets", str(ROOT_DIR): "Application folder"}
    return [{"path": p, "name": labels.get(p, defaults.get(p, p))} for p in roots]
