"""CI-only SARIF conformance check; deliberately not part of the offline scanner."""
import json
from pathlib import Path
import subprocess
from urllib.request import urlopen

import jsonschema

SCHEMA = (
    "https://raw.githubusercontent.com/SchemaStore/schemastore/"
    "f0e072bb85076fcae82bebf058cf86520d4ea450/src/schemas/json/sarif-2.1.0.json"
)
root = Path(".prismwarden/schema-fixture")
root.mkdir(parents=True, exist_ok=True)
secret = "ghp_" + "Ab3d" * 9
(root / "a # unicode-é.txt").write_text("fixture: " + secret, encoding="utf-8")
output = Path(".prismwarden/schema-report.sarif")
subprocess.run(
    ["cargo", "run", "--locked", "--", "scan", str(root), "--format", "sarif",
     "--fail-on", "none", "--output", str(output)],
    check=True,
)
with urlopen(SCHEMA, timeout=30) as response:
    schema = json.load(response)
report = json.loads(output.read_text(encoding="utf-8"))
jsonschema.validate(report, schema)
assert len(report["runs"][0]["results"]) == 1
assert secret not in output.read_text(encoding="utf-8")
print("SARIF schema, synthetic finding, and evidence-redaction checks passed")
