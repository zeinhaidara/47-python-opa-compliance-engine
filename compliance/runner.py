"""Run the Rego rules with `opa eval` and roll results up to controls."""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import yaml

PASS, FAIL, NOT_EVALUATED = "pass", "fail", "not evaluated"
QUERY = "data.compliance.report"


class OpaError(RuntimeError):
    """opa is missing, failed, or returned something we can't use."""


class MappingError(ValueError):
    pass


@dataclass(frozen=True)
class Result:
    rule: str
    resource: str
    status: str
    message: str


@dataclass
class Control:
    id: str
    framework: str
    title: str
    rules: list[str]
    results: list[Result] = field(default_factory=list)

    @property
    def status(self) -> str:
        if not self.results:
            return NOT_EVALUATED
        return FAIL if any(r.status == FAIL for r in self.results) else PASS


def find_opa(explicit: str | None) -> str:
    path = explicit or shutil.which("opa")
    if not path or not Path(path).is_file():
        raise OpaError(
            f"opa binary not found ({explicit or 'not on PATH'}); install opa or pass --opa"
        )
    return path


def check_input(path: Path) -> None:
    """Fail early on input the rules would silently ignore."""
    data = json.loads(path.read_text(encoding="utf-8"))
    resources = data.get("resources") if isinstance(data, dict) else None
    if not isinstance(resources, list) or not resources:
        raise ValueError(f"{path}: expected a non-empty 'resources' list")
    for i, r in enumerate(resources):
        if not isinstance(r, dict) or not {"id", "type", "config"} <= r.keys():
            raise ValueError(f"{path}: resources[{i}] needs id, type and config")


def evaluate(opa: str, policies: Path, resources: Path) -> tuple[set[str], list[Result]]:
    cmd = [
        opa,
        "eval",
        "--format",
        "json",
        "--data",
        str(policies),
        "--input",
        str(resources),
        QUERY,
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise OpaError(f"opa eval exited {proc.returncode}: {proc.stderr.strip()}")
    try:
        value = json.loads(proc.stdout)["result"][0]["expressions"][0]["value"]
        rules = set(value["rules"])
        results = [
            Result(r["rule"], r["resource"], r["status"], r["message"]) for r in value["results"]
        ]
    except (KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:
        # An undefined query gives {} with no "result": that's a policy bug, not a pass.
        raise OpaError(f"unexpected opa output for {QUERY}: {proc.stdout[:200]!r}") from exc
    return rules, results


def load_controls(path: Path, known_rules: set[str]) -> list[Control]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    controls = []
    seen = set()
    for c in raw["controls"]:
        unknown = set(c["rules"]) - known_rules
        if unknown:
            raise MappingError(f"control {c['id']} maps unknown rules {sorted(unknown)}")
        if c["id"] in seen:
            raise MappingError(f"control {c['id']} listed twice")
        seen.add(c["id"])
        controls.append(Control(c["id"], c["framework"], c["title"], list(c["rules"])))
    if not controls:
        raise MappingError("no controls in mapping")
    return controls


def attach(controls: list[Control], results: list[Result]) -> None:
    for control in controls:
        control.results = [r for r in results if r.rule in control.rules]


def unmapped_rules(controls: list[Control], known_rules: set[str]) -> list[str]:
    mapped = {r for c in controls for r in c.rules}
    return sorted(known_rules - mapped)
