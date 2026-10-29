#!/usr/bin/env python3
"""Check that every rule carries the metadata this ruleset promises.

`semgrep --validate` checks that a rule parses and that its patterns compile. It
does not check that the rule is documented. This script enforces the repository's
own contract: a stable id, a severity, at least one language, a message long
enough to explain a mechanism rather than name a category, and a full metadata
block with a correctly formatted CWE, references that are real URLs, and a
technology list.
"""

from __future__ import annotations

import pathlib
import re
import sys

import yaml

REQUIRED_METADATA = (
    "category",
    "cwe",
    "confidence",
    "impact",
    "likelihood",
    "subcategory",
    "references",
    "technology",
)
ENUMS = {
    "confidence": {"LOW", "MEDIUM", "HIGH"},
    "impact": {"LOW", "MEDIUM", "HIGH"},
    "likelihood": {"LOW", "MEDIUM", "HIGH"},
}
SEVERITIES = {"INFO", "WARNING", "ERROR"}
CWE_RE = re.compile(r"^CWE-\d+: .+")
ID_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
MIN_MESSAGE_WORDS = 40


def check_rule(rule: dict, path: pathlib.Path) -> list[str]:
    errors: list[str] = []
    rid = rule.get("id", "<missing id>")

    def bad(msg: str) -> None:
        errors.append(f"{path}: {rid}: {msg}")

    if not ID_RE.match(str(rid)):
        bad("id must be lower-kebab-case")
    if rule.get("severity") not in SEVERITIES:
        bad(f"severity must be one of {sorted(SEVERITIES)}")
    if not rule.get("languages"):
        bad("no languages declared")

    message = " ".join(str(rule.get("message", "")).split())
    if len(message.split()) < MIN_MESSAGE_WORDS:
        bad(
            f"message is {len(message.split())} words; "
            f"explain the mechanism and the fix in at least {MIN_MESSAGE_WORDS}"
        )

    metadata = rule.get("metadata") or {}
    for key in REQUIRED_METADATA:
        if key not in metadata:
            bad(f"metadata.{key} is missing")

    if metadata.get("category") != "security":
        bad("metadata.category must be 'security'")

    for key, allowed in ENUMS.items():
        value = metadata.get(key)
        if value is not None and value not in allowed:
            bad(f"metadata.{key} is {value!r}, expected one of {sorted(allowed)}")

    cwes = metadata.get("cwe") or []
    if not isinstance(cwes, list) or not cwes:
        bad("metadata.cwe must be a non-empty list")
    else:
        for cwe in cwes:
            if not CWE_RE.match(str(cwe)):
                bad(f"metadata.cwe entry {cwe!r} must read 'CWE-<id>: <title>'")

    references = metadata.get("references") or []
    if len(references) < 2:
        bad("metadata.references needs at least two entries")
    for ref in references:
        if not str(ref).startswith("https://"):
            bad(f"reference {ref!r} is not an https URL")

    if not metadata.get("technology"):
        bad("metadata.technology must list at least one technology")

    return errors


def main(argv: list[str]) -> int:
    root = pathlib.Path(argv[1] if len(argv) > 1 else "rules")
    paths = sorted(root.rglob("*.yaml")) + sorted(root.rglob("*.yml"))
    if not paths:
        print(f"no rule files found under {root}", file=sys.stderr)
        return 1

    errors: list[str] = []
    seen: dict[str, pathlib.Path] = {}
    count = 0

    for path in paths:
        document = yaml.safe_load(path.read_text())
        for rule in (document or {}).get("rules", []):
            count += 1
            rid = rule.get("id")
            if rid in seen:
                errors.append(f"{path}: duplicate rule id {rid!r}, first seen in {seen[rid]}")
            else:
                seen[rid] = path
            errors.extend(check_rule(rule, path))

    for error in errors:
        print(error, file=sys.stderr)

    if errors:
        print(f"\n{len(errors)} metadata problem(s) across {count} rule(s)", file=sys.stderr)
        return 1

    print(f"metadata lint: {count} rules in {len(paths)} files, no problems")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
