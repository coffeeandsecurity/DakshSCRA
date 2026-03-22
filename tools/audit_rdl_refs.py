#!/usr/bin/env python3
from __future__ import annotations

import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PLATFORM_ROOT = ROOT / "rules" / "scanning" / "platform"
SCANNING_ROOT = ROOT / "rules" / "scanning"

# These are intentionally small, high-signal heuristics for mitigation rules.
SUSPICIOUS_MITIGATION_TOKENS = {
    "html.raw": "Raw HTML rendering is usually an XSS sink, not a mitigation.",
    "markupstring": "Raw markup wrappers are usually sinks, not mitigations.",
    "room.createquery": "Room.createQuery is not a stable mitigation signal for SQL injection.",
}


def unwrap_regex_token(text: str) -> str:
    raw = (text or "").strip()
    if len(raw) >= 2 and raw[0] == "/" and raw.count("/") >= 2:
        end = raw.rfind("/")
        raw = raw[1:end]
    return raw


def normalize_regex(text: str) -> str:
    normalized = unwrap_regex_token((text or "").strip())
    normalized = normalized.replace(r"\/", "/")
    normalized = normalized.replace(r"\]", "]")
    normalized = normalized.replace(r"\[", "[")
    return " ".join(normalized.split())


def extract_inline_flag(rdl_text: str) -> str:
    text = rdl_text or ""
    match = re.search(r"\[\s*FLAG\s*:", text, flags=re.IGNORECASE)
    if not match:
        return ""

    idx = match.end()
    buf = []
    escaped = False
    in_char_class = False

    while idx < len(text):
        ch = text[idx]
        if escaped:
            buf.append(ch)
            escaped = False
            idx += 1
            continue
        if ch == "\\":
            buf.append(ch)
            escaped = True
            idx += 1
            continue
        if ch == "[" and not in_char_class:
            in_char_class = True
            buf.append(ch)
            idx += 1
            continue
        if ch == "]":
            if in_char_class:
                in_char_class = False
                buf.append(ch)
                idx += 1
                continue
            break
        buf.append(ch)
        idx += 1

    return normalize_regex("".join(buf))


def extract_external_anchor(rdl_script: str) -> str:
    for raw_line in (rdl_script or "").splitlines():
        line = (raw_line or "").strip()
        if not line or line.startswith("#"):
            continue
        upper = line.upper()
        if upper.startswith("WHEN PRESENT "):
            return normalize_regex(line[len("WHEN PRESENT "):])
        if upper.startswith("WHEN CURRENT_FILE_MATCHES "):
            return normalize_regex(line[len("WHEN CURRENT_FILE_MATCHES "):])
    return ""


def collect_findings() -> list[str]:
    findings: list[str] = []
    logic_cache: dict[Path, str] = {}

    xml_files = []
    try:
        result = subprocess.run(
            ["rg", "--files", str(PLATFORM_ROOT), "-g", "*.xml"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        xml_files = [ROOT / line.strip() for line in result.stdout.splitlines() if line.strip()]
    except Exception:
        xml_files = sorted(PLATFORM_ROOT.rglob("*.xml"))

    for xml_path in xml_files:
        try:
            root = ET.parse(xml_path).getroot()
        except ET.ParseError as exc:
            findings.append(f"ERROR {xml_path}: XML parse failed: {exc}")
            continue

        for rule in root.iter("rule"):
            name = (rule.findtext("name") or "").strip() or "<unnamed>"
            regex_text = (rule.findtext("regex") or "").strip()
            rdl_text = (rule.findtext("rdl") or "").strip()
            rdl_ref = (rule.findtext("rdl_ref") or "").strip()
            label = f"{xml_path}:{name}"

            if not regex_text and not rdl_text and not rdl_ref:
                findings.append(f"ERROR {label}: missing regex, rdl, and rdl_ref")
                continue

            if not rdl_ref:
                continue

            logic_path = SCANNING_ROOT / rdl_ref
            if not logic_path.exists():
                findings.append(f"ERROR {label}: missing logic file {logic_path}")
                continue

            logic_text = logic_cache.get(logic_path)
            if logic_text is None:
                logic_text = logic_path.read_text(encoding="utf-8", errors="ignore")
                logic_cache[logic_path] = logic_text
            inline_flag = extract_inline_flag(rdl_text)
            external_anchor = extract_external_anchor(logic_text)

            if inline_flag and external_anchor and inline_flag != external_anchor:
                findings.append(
                    f"WARN  {label}: inline FLAG differs from external anchor\n"
                    f"      inline  = {inline_flag}\n"
                    f"      external= {external_anchor}"
                )

            lower_bundle = " ".join(
                [
                    name.lower(),
                    regex_text.lower(),
                    rdl_text.lower(),
                    logic_text.lower(),
                ]
            )
            if "mitigation" in name.lower():
                for token, message in SUSPICIOUS_MITIGATION_TOKENS.items():
                    if token in lower_bundle:
                        findings.append(f"WARN  {label}: suspicious mitigation token '{token}' - {message}")

    return findings


def main() -> int:
    findings = collect_findings()
    if findings:
        print("\n".join(findings))
        return 1
    print("RDL reference audit passed with no findings.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
