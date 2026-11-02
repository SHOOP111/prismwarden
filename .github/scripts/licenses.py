"""Bundle dependency metadata and available upstream license texts on CI runners."""
import json
from pathlib import Path
import shutil
import subprocess
import sys

output = Path(sys.argv[1])
metadata = json.loads(subprocess.check_output(
    ["cargo", "metadata", "--locked", "--format-version", "1"], text=True
))
packages = sorted(metadata["packages"], key=lambda item: (item["name"], item["version"]))
notices = [
    "# Third-party dependency notices\n\n",
    "This inventory includes normal, build, development, and platform-specific dependencies. "
    "Not every listed package is linked into this executable. Available upstream license "
    "texts are bundled alongside this index; review upstream terms before redistribution.\n\n",
]
inventory = []
for package in packages:
    if package["name"] == "prismwarden" and package["source"] is None:
        continue
    root = Path(package["manifest_path"]).parent.resolve()
    candidates = set()
    for pattern in ("LICENSE*", "LICENCE*", "COPYING*", "COPYRIGHT*", "NOTICE*", "UNLICENSE*"):
        candidates.update(root.glob(pattern))
    if package.get("license_file"):
        declared = Path(package["license_file"])
        candidates.add(declared if declared.is_absolute() else root / declared)
    copied = []
    destination = output / "third-party-licenses" / (package["name"] + "-" + package["version"])
    for path in sorted(candidates):
        resolved = path.resolve()
        if not resolved.is_relative_to(root):
            raise RuntimeError("dependency license path escapes package source")
        if not resolved.is_file():
            continue
        destination.mkdir(parents=True, exist_ok=True)
        target = destination / path.name
        shutil.copyfile(resolved, target)
        copied.append(target.relative_to(output).as_posix())
    record = {
        "name": package["name"], "version": package["version"],
        "license": package.get("license"), "repository": package.get("repository"),
        "license_files": copied,
    }
    inventory.append(record)
    notices.append(f"## {record['name']} {record['version']}\n\n")
    notices.append(f"Declared license: {record['license'] or 'unspecified'}\n\n")
    if copied:
        notices.extend(f"- [{path}]({path})\n" for path in copied)
    else:
        notices.append("No top-level license text found; consult the upstream repository.\n")
    notices.append("\n")
(output / "THIRD_PARTY_NOTICES.md").write_text("".join(notices), encoding="utf-8")
(output / "dependency-inventory.json").write_text(
    json.dumps(inventory, indent=2) + "\n", encoding="utf-8"
)
print(f"Bundled notices for {len(inventory)} dependencies")
