"""Create deterministic, streaming checksums for runner-built artifacts."""
import argparse
import hashlib
from pathlib import Path


def generate(root: Path) -> None:
    if root.is_symlink() or not root.is_dir():
        raise ValueError("distribution root must be a real directory")
    checksum_path = root / "SHA256SUMS"
    lines = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("distribution must not contain symlinks")
        if not path.is_file() or path == checksum_path:
            continue
        relative = path.relative_to(root).as_posix()
        if any(character in relative for character in "\r\n\\"):
            raise ValueError("distribution filename cannot be represented safely in SHA256SUMS")
        with path.open("rb") as source:
            digest = hashlib.file_digest(source, "sha256").hexdigest()
        lines.append(f"{digest}  {relative}\n")
    checksum_path.write_text("".join(lines), encoding="utf-8", newline="\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    generate(parser.parse_args().directory)


if __name__ == "__main__":
    main()
