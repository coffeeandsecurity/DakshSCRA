import os
import platform
import subprocess
import sys
from pathlib import Path

def run(cmd, desc):
    print(f"[+] {desc}...")
    result = subprocess.run(cmd, shell=True)
    if result.returncode != 0:
        print(f"[!] Failed: {desc}")
        sys.exit(1)

venv_dir = Path("venv")
venv_python = venv_dir / "Scripts" / "python.exe" if platform.system() == "Windows" else venv_dir / "bin" / "python"

# Step 1: Create venv if it doesn't exist
if not venv_python.exists():
    run(f"{sys.executable} -m venv {venv_dir}", "Creating virtual environment")

# Step 2: Install requirements
run(f"{venv_python} -m pip install --upgrade pip", "Upgrading pip")
run(f"{venv_python} -m pip install -r requirements.txt", "Installing requirements.txt")

# Step 3: Install Playwright browser (Chromium)
run(f"{venv_python} -m playwright install chromium", "Installing Chromium")

# Step 4: Install Linux-only system deps
if platform.system() == "Linux":
    run(f"{venv_python} -m playwright install-deps", "Installing Linux system dependencies")

print("[✓] DakshSCRA environment setup complete.")
print(f"[→] Activate manually with:\n\n  source venv/bin/activate   # macOS/Linux\n  .\\venv\\Scripts\\activate   # Windows")
