"""CI-only unit coverage for distribution helpers; no Cargo invocation."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


checksums = load("checksums")
licenses = load("licenses")


class DistributionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.output = self.root / "distribution"
        self.output.mkdir()

    def package(self, name="example", license_file=None):
        source = self.root / name
        source.mkdir(exist_ok=True)
        (source / "Cargo.toml").write_text("", encoding="utf-8")
        return {
            "name": name, "version": "1.2.3", "source": "registry+synthetic",
            "manifest_path": str(source / "Cargo.toml"), "license": "MIT",
            "repository": None, "license_file": license_file,
        }

    def test_checksums_are_streamed_recursive_and_stable(self):
        (self.output / "binary").write_bytes(bytes(range(256)) * 4096)
        nested = self.output / "docs"
        nested.mkdir()
        (nested / "SHA256SUMS").write_bytes(b"also part of the distribution")
        with patch.object(Path, "read_bytes", side_effect=AssertionError("whole-file read")):
            checksums.generate(self.output)
        first = (self.output / "SHA256SUMS").read_bytes()
        checksums.generate(self.output)
        self.assertEqual(first, (self.output / "SHA256SUMS").read_bytes())
        lines = first.decode("utf-8").splitlines()
        self.assertEqual(len(lines), 2)
        for line in lines:
            digest, name = line.split("  ", 1)
            self.assertEqual(digest, hashlib.sha256((self.output / name).read_bytes()).hexdigest())
        self.assertNotIn(b"\r", first)

    @unittest.skipUnless(os.name == "posix", "Unix filenames and symlinks")
    def test_checksum_symlinks_and_ambiguous_names_are_rejected(self):
        target = self.root / "private"
        target.write_bytes(b"outside the package")
        link = self.output / "linked"
        link.symlink_to(target)
        with self.assertRaises(ValueError):
            checksums.generate(self.output)
        link.unlink()
        ambiguous = self.output / "new\nline"
        ambiguous.write_bytes(b"synthetic")
        with self.assertRaises(ValueError):
            checksums.generate(self.output)

    def test_inventory_is_sorted_and_omits_the_project(self):
        packages = [self.package("zeta"), self.package("alpha")]
        for package in packages:
            (Path(package["manifest_path"]).parent / "LICENSE-MIT").write_text("synthetic MIT", encoding="utf-8")
        project = dict(packages[0], name="prismwarden", source=None)
        self.assertEqual(licenses.bundle(self.output, {"packages": packages + [project]}), 2)
        inventory = json.loads((self.output / "dependency-inventory.json").read_text(encoding="utf-8"))
        self.assertEqual([item["name"] for item in inventory], ["alpha", "zeta"])
        for item in inventory:
            self.assertEqual(len(item["license_files"]), 1)
            self.assertTrue((self.output / item["license_files"][0]).is_file())
        checksums.generate(self.output)
        self.assertIn("dependency-inventory.json", (self.output / "SHA256SUMS").read_text(encoding="utf-8"))

    def test_nested_declared_license_is_bundled(self):
        package = self.package(license_file="legal/terms.txt")
        terms = Path(package["manifest_path"]).parent / "legal/terms.txt"
        terms.parent.mkdir()
        terms.write_text("synthetic terms", encoding="utf-8")
        licenses.bundle(self.output, {"packages": [package]})
        self.assertEqual((self.output / "third-party-licenses/example-1.2.3/terms.txt").read_text(encoding="utf-8"), "synthetic terms")

    def test_missing_declared_license_is_an_error(self):
        with self.assertRaises(ValueError):
            licenses.bundle(self.output, {"packages": [self.package(license_file="missing.txt")]})

    def test_declared_license_cannot_escape_package(self):
        (self.root / "private").write_bytes(b"outside package")
        with self.assertRaises(ValueError):
            licenses.bundle(self.output, {"packages": [self.package(license_file="../private")]})

    def test_ambiguous_license_basename_is_an_error(self):
        package = self.package(license_file="legal/LICENSE")
        source = Path(package["manifest_path"]).parent
        (source / "LICENSE").write_text("first terms", encoding="utf-8")
        (source / "legal").mkdir()
        (source / "legal/LICENSE").write_text("different terms", encoding="utf-8")
        with self.assertRaises(ValueError):
            licenses.bundle(self.output, {"packages": [package]})

    def test_inventory_directory_cannot_escape_distribution(self):
        package = self.package()
        package["name"] = "../escape"
        with self.assertRaises(ValueError):
            licenses.bundle(self.output, {"packages": [package]})


if __name__ == "__main__":
    unittest.main()
