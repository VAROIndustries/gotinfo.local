"""Build dist/gotinfo/gotinfo.exe (PyInstaller) then installer_output/*.exe (Inno Setup 6)."""
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent
ISCC = [Path(r"C:\Program Files (x86)\Inno Setup 6\ISCC.exe"), Path(r"C:\Program Files\Inno Setup 6\ISCC.exe")]

for d in ("build", "dist"):
    shutil.rmtree(ROOT / d, ignore_errors=True)
subprocess.run([sys.executable, "-m", "PyInstaller", "gotinfo.spec", "--noconfirm"], cwd=ROOT, check=True)
subprocess.run([str(ROOT / "dist" / "gotinfo" / "gotinfo.exe"), "--selftest"], check=True)
iscc = next((p for p in ISCC if p.exists()), None)
if not iscc:
    sys.exit("Inno Setup 6 not found; exe is in dist/gotinfo/")
subprocess.run([str(iscc), "installer.iss"], cwd=ROOT, check=True)
print("\nInstaller:", *(ROOT / "installer_output").glob("*.exe"))
