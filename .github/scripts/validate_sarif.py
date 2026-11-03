"""CI-only SARIF conformance check; not part of the offline scanner."""
import json
from pathlib import Path
import subprocess
from urllib.request import urlopen

import jsonschema

SCHEMA = (
    "https://raw.githubusercontent.com/SchemaStore/schemastore/"
    "f0e072bb85076fcae82bebf058cf86520d4ea450/src/schemas/json/sarif-2.1.0.json"
)


def main() -> None:
    with urlopen(SCHEMA, timeout=30) as response:
        schema = json.load(response)
    validator = jsonschema.Draft7Validator(schema)
    validator.check_schema(schema)
    subprocess.run(["cargo", "build", "--locked"], check=True)
    executable = Path("target/debug/prismwarden").resolve()
    base = Path(".prismwarden/schema-fixtures")
    base.mkdir(parents=True, exist_ok=True)
    secret = "ghp_" + "Ab3d" * 9
    for case in ("empty", "findings", "incomplete", "truncated"):
        root = base / case
        root.mkdir(exist_ok=True)
        output = Path(f".prismwarden/schema-{case}.sarif")
        expected_results, expected_code = 0, 0
        extra = []
        if case != "empty":
            (root / "a # unicode-é.txt").write_text("λ " + secret + "\r\nλ " + secret, encoding="utf-8", newline="")
            expected_results, expected_code = 2, 1
        if case == "incomplete":
            (root / "binary").write_bytes(b"\0synthetic")
            expected_code = 3
        if case == "truncated":
            extra = ["--max-findings", "1"]
            expected_results, expected_code = 1, 3
        completed = subprocess.run(
            [str(executable), "scan", str(root), "--format", "sarif", "--output", str(output), *extra],
            check=False, capture_output=True,
        )
        assert completed.returncode == expected_code, completed.stderr.decode("utf-8", errors="replace")
        assert not completed.stdout
        contents = output.read_text(encoding="utf-8")
        document = json.loads(contents)
        validator.validate(document)
        run = document["runs"][0]
        assert len(run["results"]) == expected_results
        assert run["invocations"][0]["executionSuccessful"] == (expected_code != 3)
        assert secret not in contents
        assert str(root.resolve()) not in contents
        if expected_results:
            location = run["results"][0]["locations"][0]["physicalLocation"]
            assert location["artifactLocation"]["uri"] == "a%20%23%20unicode-%C3%A9.txt"
            assert location["region"] == {"startLine": 1, "startColumn": 3}
        if case == "incomplete":
            Path(".prismwarden/schema-report.sarif").write_text(contents, encoding="utf-8", newline="\n")
    print("SARIF schema: empty, findings, incomplete, truncated, coordinates, and redaction passed")


if __name__ == "__main__":
    main()
