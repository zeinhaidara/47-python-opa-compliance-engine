"""Markdown report per control."""

from __future__ import annotations

from compliance.runner import FAIL, NOT_EVALUATED, PASS, Control

DISCLAIMER = (
    "> This is an automated configuration check against an **illustrative** control "
    "mapping. It is not an audit, an attestation, or a SOC 2 / ISO 27001 certification."
)


def to_markdown(controls: list[Control], resource_count: int, unmapped: list[str]) -> str:
    counts = {s: sum(1 for c in controls if c.status == s) for s in (PASS, FAIL, NOT_EVALUATED)}
    lines = [
        "# Compliance check report",
        "",
        DISCLAIMER,
        "",
        f"Resources evaluated: {resource_count}. Controls: {len(controls)} "
        f"({counts[PASS]} pass, {counts[FAIL]} fail, {counts[NOT_EVALUATED]} not evaluated).",
        "",
        "| Control | Framework | Title | Status | Pass | Fail |",
        "|---|---|---|---|---:|---:|",
    ]
    for c in controls:
        passed = sum(1 for r in c.results if r.status == PASS)
        failed = sum(1 for r in c.results if r.status == FAIL)
        lines.append(
            f"| {c.id} | {c.framework} | {c.title} | **{c.status}** | {passed} | {failed} |"
        )

    failing = [(c, r) for c in controls for r in c.results if r.status == FAIL]
    lines += ["", "## Failures", ""]
    if failing:
        lines += ["| Control | Rule | Resource | Why |", "|---|---|---|---|"]
        for c, r in failing:
            lines.append(f"| {c.id} | {r.rule} | {r.resource} | {r.message} |")
    else:
        lines.append("None.")

    not_eval = [c.id for c in controls if c.status == NOT_EVALUATED]
    if not_eval:
        lines += [
            "",
            "## Not evaluated",
            "",
            "No resource in the input was in scope for these controls' rules: "
            + ", ".join(not_eval)
            + ".",
        ]
    if unmapped:
        lines += ["", f"Rules not mapped to any control: {', '.join(unmapped)}."]
    return "\n".join(lines) + "\n"
