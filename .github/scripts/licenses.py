"""Bundle dependency metadata and available upstream license texts on CI runners."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess


def bundle(output: Path, metadata: dict) -> int:
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
            declared = declared if declared.is_absolute() else root / declared
            if not declared.is_file():
                raise ValueError("declared dependency license file is missing")
            candidates.add(declared)
        copied = []
        directory = package["name"] + "-" + package["version"]
        if directory in (".", "..") or any(character in directory for character in "/\\\r\n"):
            raise ValueError("invalid dependency inventory directory")
        destination = output / "third-party-licenses" / directory
        if not destination.resolve().is_relative_to(output.resolve()):
            raise ValueError("license destination escapes distribution")
        for path in sorted(candidates):
            resolved = path.resolve()
            if not resolved.is_relative_to(root):
                raise ValueError("dependency license path escapes package source")
            if not resolved.is_file():
                continue
            destination.mkdir(parents=True, exist_ok=True)
            target = destination / path.name
            if target.is_symlink():
                raise ValueError("license destination must not be a symlink")
            relative = target.relative_to(output).as_posix()
            if relative in copied:
                if target.read_bytes() != resolved.read_bytes():
                    raise ValueError("different dependency licenses have the same output name")
                continue
            shutil.copyfile(resolved, target)
            copied.append(relative)
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
    output.mkdir(parents=True, exist_ok=True)
    (output / "THIRD_PARTY_NOTICES.md").write_text("".join(notices), encoding="utf-8", newline="\n")
    (output / "dependency-inventory.json").write_text(
        json.dumps(inventory, indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    return len(inventory)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    metadata = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--locked", "--format-version", "1"], text=True
    ))
    print(f"Bundled notices for {bundle(args.directory, metadata)} dependencies")


if __name__ == "__main__":
    main()
