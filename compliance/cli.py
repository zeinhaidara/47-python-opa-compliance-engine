"""python -m compliance --input resources.json [--output report.md] [--fail-on-fail]"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from compliance.report import to_markdown
from compliance.runner import (
    FAIL,
    attach,
    check_input,
    evaluate,
    find_opa,
    load_controls,
    unmapped_rules,
)

ROOT = Path(__file__).resolve().parent.parent


def parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Evaluate resources against mapped controls.")
    p.add_argument("--input", type=Path, required=True, help="resources JSON file")
    p.add_argument("--policies", type=Path, default=ROOT / "policies")
    p.add_argument("--controls", type=Path, default=ROOT / "controls.yaml")
    p.add_argument("--opa", help="path to the opa binary (default: opa on PATH)")
    p.add_argument("--output", type=Path, help="write Markdown here instead of stdout")
    p.add_argument("--fail-on-fail", action="store_true", help="exit 2 if any control fails")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    try:
        opa = find_opa(args.opa)
        check_input(args.input)
        rules, results = evaluate(opa, args.policies, args.input)
        controls = load_controls(args.controls, rules)
        attach(controls, results)
        count = len(json.loads(args.input.read_text(encoding="utf-8"))["resources"])
        text = to_markdown(controls, count, unmapped_rules(controls, rules))
    except Exception as exc:
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    if args.output:
        args.output.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    if args.fail_on_fail and any(c.status == FAIL for c in controls):
        return 2
    return 0
