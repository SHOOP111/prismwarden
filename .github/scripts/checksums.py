"""Create checksums for runner-built distribution artifacts."""
import hashlib
from pathlib import Path
import sys

root = Path(sys.argv[1])
lines = []
for path in sorted(root.iterdir()):
    if path.is_file() and path.name != "SHA256SUMS":
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{digest}  {path.name}\n")
(root / "SHA256SUMS").write_text("".join(lines), encoding="utf-8")
