from pathlib import Path
import os
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


def _default_browse_roots() -> List[str]:
    """
    Return sensible default browse roots for the current OS.

    These are the paths shown in the Web UI directory browser when
    DAKSH_BROWSE_ROOTS is not set. The list is built at startup so only
    paths that actually exist on the current machine are included.

    To override, set DAKSH_BROWSE_ROOTS as a comma-separated list of
    absolute paths in your environment or .env file:
        DAKSH_BROWSE_ROOTS=/scan-targets,/host,/mnt
    """
    roots = [str(ROOT_DIR), "/scan-targets"]
    system = platform.system()

    if system == "Windows":
        # Add every drive letter that exists (C:\, D:\, etc.)
        for letter in string.ascii_uppercase:
            p = Path(f"{letter}:\\")
            if p.exists():
                roots.append(str(p))

    elif system == "Darwin":
        # macOS
        roots += ["/", "/Users", "/Volumes", "/tmp"]

    else:
        # Linux — covers native Linux, WSL, and Docker containers
        roots += ["/", "/home", "/srv", "/opt", "/tmp", "/mnt"]

        # WSL: include individual Windows drive mounts under /mnt
        # (single-letter directories such as /mnt/c, /mnt/d)
        mnt = Path("/mnt")
        if mnt.exists():
            try:
                for child in sorted(mnt.iterdir()):
                    if child.is_dir() and len(child.name) == 1 and child.name.isalpha():
                        roots.append(str(child))
            except PermissionError:
                pass

        # Docker container mount points and Docker Desktop host bridge
        roots += ["/host", "/host/c", "/host/d", "/host/source",
                  "/run/desktop/mnt/host", "/Volumes", "/Users"]

    return roots


def get_browse_roots() -> List[str]:
    raw = os.getenv("DAKSH_BROWSE_ROOTS", "").strip()
    if raw:
        candidates = [x.strip() for x in raw.split(",") if x.strip()]
    else:
        candidates = _default_browse_roots()

    roots: List[str] = []
    for c in candidates:
        try:
            p = Path(c).resolve()
            if p.exists() and p.is_dir():
                roots.append(str(p))
        except Exception:
            continue

    if not roots:
        roots = [str(ROOT_DIR)]
    return roots
