"""Evidence report builder.

Turns a deep-analysis result (PE or APK) into a structured, reviewable
evidence report: scored findings with concrete evidence lines, plus
Markdown and self-contained HTML renderings for export.

Static analysis only — every finding cites what was observed in the file,
never what the software did at runtime.
"""
from __future__ import annotations

import hashlib
import html
import json
import re
import uuid
from datetime import datetime, timezone

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_WEIGHT = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}

# Windows API functions that commonly show up in packers / injectors.
SUSPICIOUS_PE_IMPORTS = {
    "VirtualAllocEx": "remote memory allocation (injection primitive)",
    "WriteProcessMemory": "writing into another process (injection primitive)",
    "CreateRemoteThread": "starting code inside another process",
    "NtUnmapViewOfSection": "unmapping memory (process hollowing)",
    "ZwUnmapViewOfSection": "unmapping memory (process hollowing)",
    "SetWindowsHookExA": "keyboard/mouse hooking (keylogging risk)",
    "SetWindowsHookExW": "keyboard/mouse hooking (keylogging risk)",
    "InternetOpenA": "raw internet access (bypasses WinINet policy)",
    "InternetOpenW": "raw internet access (bypasses WinINet policy)",
    "URLDownloadToFileA": "downloading a file from the internet",
    "URLDownloadToFileW": "downloading a file from the internet",
    "WinExec": "legacy process execution",
    "ShellExecuteA": "program execution via shell",
    "ShellExecuteW": "program execution via shell",
    "CreateProcessA": "process creation",
    "CreateProcessW": "process creation",
    "IsDebuggerPresent": "anti-debugging check",
    "CheckRemoteDebuggerPresent": "anti-debugging check",
    "NtQueryInformationProcess": "anti-debugging / process inspection",
    "AdjustTokenPrivileges": "privilege escalation attempt",
}

# Android permissions grouped by risk for evidence reporting.
DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS": "reads text messages",
    "android.permission.RECEIVE_SMS": "intercepts incoming SMS",
    "android.permission.SEND_SMS": "sends text messages (premium-rate risk)",
    "android.permission.RECEIVE_MMS": "intercepts incoming MMS",
    "android.permission.READ_CONTACTS": "reads the address book",
    "android.permission.WRITE_CONTACTS": "modifies the address book",
    "android.permission.READ_CALL_LOG": "reads call history",
    "android.permission.WRITE_CALL_LOG": "modifies call history",
    "android.permission.PROCESS_OUTGOING_CALLS": "watches outgoing calls",
    "android.permission.CALL_PHONE": "places calls without user confirmation",
    "android.permission.RECORD_AUDIO": "records microphone audio",
    "android.permission.CAMERA": "uses the camera",
    "android.permission.ACCESS_FINE_LOCATION": "precise GPS location",
    "android.permission.ACCESS_COARSE_LOCATION": "approximate location",
    "android.permission.READ_PHONE_STATE": "reads phone identifiers",
    "android.permission.READ_EXTERNAL_STORAGE": "reads shared storage",
    "android.permission.WRITE_EXTERNAL_STORAGE": "writes shared storage",
    "android.permission.REQUEST_INSTALL_PACKAGES": "can launch APK installs",
    "android.permission.SYSTEM_ALERT_WINDOW": "draws over other apps (overlay attacks)",
    "android.permission.BIND_ACCESSIBILITY_SERVICE": "full UI observation/control via accessibility",
    "android.permission.RECEIVE_BOOT_COMPLETED": "starts automatically after reboot",
    "android.permission.QUERY_ALL_PACKAGES": "sees every installed app",
}

# Secrets patterns scanned in assets / manifest / raw ASCII strings.
SECRET_PATTERNS = [
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY"), "private key block"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key id"),
    (re.compile(r"\b(?:api[_-]?key|apikey|secret[_-]?key|auth[_-]?token)\s*[=:]\s*['\"][^'\"]{8,}['\"]", re.I), "hardcoded api key/token assignment"),
    (re.compile(r"\b(?:password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{4,}['\"]", re.I), "hardcoded password assignment"),
    (re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"), "GitHub personal access token"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "Slack token"),
]

RISK_LEVELS = [
    (60, "critical"),
    (35, "high"),
    (15, "medium"),
    (0, "low"),
]


def _finding(severity: str, category: str, title: str, evidence: list[str],
             recommendation: str = "") -> dict:
    return {
        "severity": severity,
        "category": category,
        "title": title,
        "evidence": evidence,
        "recommendation": recommendation,
    }


def _risk_score(findings: list[dict]) -> tuple[int, str]:
    score = sum(SEVERITY_WEIGHT.get(f["severity"], 0) for f in findings)
    score = min(score, 100)
    for threshold, level in RISK_LEVELS:
        if score >= threshold:
            return score, level
    return score, "low"


# --------------------------------------------------------------------------- PE


def _pe_findings(analysis: dict) -> list[dict]:
    pe = analysis.get("pe", {})
    findings: list[dict] = []

    if pe.get("packing_suspected"):
        findings.append(_finding(
            "high", "packing",
            "Packer / high-entropy indicators present",
            list(pe.get("packing_reasons", [])),
            "Unpack the binary (e.g. upx -d, DIE, detected packer tooling) before deeper triage.",
        ))

    rwx = [s["name"] for s in pe.get("sections", [])
           if "MEM_EXECUTE" in s.get("characteristics", []) and "MEM_WRITE" in s.get("characteristics", [])]
    if rwx:
        findings.append(_finding(
            "high", "memory",
            "Section(s) are simultaneously writable and executable",
            [f"RWX section: {name}" for name in rwx],
            "RWX memory is unusual for normal code; likely JIT, shellcode staging or a packer stub.",
        ))

    suspicious: list[str] = []
    for entry in pe.get("imports", []):
        for fn in entry.get("functions", []):
            if fn in SUSPICIOUS_PE_IMPORTS:
                suspicious.append(f"{entry['dll']}!{fn} — {SUSPICIOUS_PE_IMPORTS[fn]}")
    if suspicious:
        findings.append(_finding(
            "high" if len(suspicious) >= 3 else "medium", "imports",
            f"{len(suspicious)} security-relevant import(s) observed",
            suspicious,
            "Review each call site in a disassembler; confirm intended behaviour.",
        ))

    if not pe.get("authenticode_signed"):
        findings.append(_finding(
            "medium", "signing",
            "No Authenticode signature",
            [f"SECURITY data directory size = {pe.get('authenticode_size', 0)} (unsigned)"],
            "Unsigned binaries carry no publisher identity; verify origin before execution.",
        ))

    if pe.get("tls_directory"):
        findings.append(_finding(
            "medium", "execution",
            "TLS callback directory present",
            ["AddressOfEntryPoint is not the only code that runs — TLS callbacks execute first.",
             "Packers and malware commonly hide execution here."],
            "Inspect the TLS callback array in a disassembler.",
        ))

    overlay = pe.get("overlay_size", 0)
    if overlay and overlay > 4096:
        findings.append(_finding(
            "medium", "structure",
            f"Overlay data appended after the image ({overlay} bytes)",
            [f"File contains {overlay} bytes beyond the PE image (embedded payload?)" ],
            "Extract and scan the overlay separately (binwalk, foremost).",
        ))

    entry_section = pe.get("entry_point_section")
    if entry_section and entry_section.upper() not in (".TEXT", "CODE", ".RDATA"):
        findings.append(_finding(
            "low", "structure",
            f"Entry point lives in unusual section '{entry_section}'",
            [f"AddressOfEntryPoint → section {entry_section}"],
            "Unusual entry sections appear in packers and some compilers; verify.",
        ))

    for dbg in pe.get("debug", []):
        if dbg.get("pdb"):
            findings.append(_finding(
                "low", "information-disclosure",
                "Debug path embedded in binary",
                [f"PDB path: {dbg['pdb']}"] + ([f"Build timestamp: {dbg['timestamp']}"] if dbg.get("timestamp") else []),
                "Rebuild paths leak internal usernames/build layouts; strip debug info for release.",
            ))
            break

    if pe.get("is_dotnet"):
        findings.append(_finding(
            "info", "runtime",
            ".NET assembly",
            [f"CLR runtime version: {pe.get('clr_runtime_version') or 'unknown'}",
             "Managed metadata means easy decompilation (dnSpy/ilspycmd)."],
            "Decompile with dnSpy or ilspycmd for full source-level review.",
        ))

    unsigned_important = not pe.get("authenticode_signed") and not pe.get("is_dotnet")
    if unsigned_important and not any(f["category"] == "signing" for f in findings):
        pass  # covered above

    return findings


# --------------------------------------------------------------------------- APK

def _scan_secrets(label: str, text: str, findings: list[dict]) -> None:
    hits: list[str] = []
    for pattern, desc in SECRET_PATTERNS:
        for m in pattern.finditer(text):
            snippet = m.group(0)
            if len(snippet) > 70:
                snippet = snippet[:67] + "..."
            hits.append(f"{label}: {desc} → {snippet}")
    if hits:
        findings.append(_finding(
            "high", "secrets",
            f"Possible hardcoded secret(s) in {label}",
            hits[:10],
            "Rotate the exposed credentials and move them out of the client bundle.",
        ))


def _apk_findings(analysis: dict) -> list[dict]:
    apk = analysis.get("apk", {})
    findings: list[dict] = []

    dangerous = [p for p in apk.get("permissions", []) if p in DANGEROUS_PERMISSIONS]
    if dangerous:
        severity = "high" if len(dangerous) >= 3 else "medium"
        findings.append(_finding(
            severity, "permissions",
            f"{len(dangerous)} dangerous permission(s) requested",
            [f"{p} — {DANGEROUS_PERMISSIONS[p]}" for p in dangerous],
            "Confirm each permission is justified by the app's stated function.",
        ))

    if apk.get("debuggable") is True:
        findings.append(_finding(
            "high", "configuration",
            "Application is debuggable",
            ['android:debuggable="true" allows debugger attachment and runtime tampering.'],
            "Set android:debuggable=false for release builds.",
        ))

    if apk.get("allow_backup") is True:
        findings.append(_finding(
            "medium", "configuration",
            "Backup of app data is allowed",
            ['android:allowBackup="true" lets `adb backup` extract app data on older devices.'],
            "Set android:allowBackup=false unless backup is a required feature.",
        ))

    min_sdk = apk.get("min_sdk")
    if isinstance(min_sdk, int) and min_sdk and min_sdk < 23:
        findings.append(_finding(
            "low", "configuration",
            f"minSdkVersion {min_sdk} predates runtime permissions",
            [f"minSdkVersion={min_sdk}: install-time permission model, no runtime revocation UX."],
            "Raise minSdkVersion where product requirements allow.",
        ))

    native = apk.get("native_libs") or []
    if native:
        findings.append(_finding(
            "info", "native",
            f"{len(native)} native library entry(ies) present",
            [f"{e.get('name', e) if isinstance(e, dict) else e}" for e in native[:8]],
            "Native code needs separate reverse engineering (JNI boundary, IDA/Ghidra).",
        ))

    if apk.get("instrumentations"):
        findings.append(_finding(
            "high", "instrumentation",
            "Instrumentation runner declared",
            [f"Instrumentation: {i}" for i in apk["instrumentations"][:5]],
            "Instrumentation can intercept app lifecycle; confirm it belongs to a test framework.",
        ))

    if apk.get("signatures"):
        findings.append(_finding(
            "info", "signing",
            f"{len(apk['signatures'])} signature-related zip entr(ies)",
            [f"{e.get('name', e) if isinstance(e, dict) else e}" for e in apk["signatures"][:6]],
            "Verify the signer certificate fingerprint against the publisher's published key.",
        ))

    # Secret scan: manifest XML + text assets + dex strings if present.
    manifest_xml = apk.get("manifest_xml") or ""
    if manifest_xml:
        _scan_secrets("AndroidManifest.xml", manifest_xml, findings)

    for asset in apk.get("assets", []):
        name = asset.get("name", "") if isinstance(asset, dict) else str(asset)
        if name.lower().endswith((".js", ".json", ".html", ".xml", ".txt", ".cfg", ".ini", ".properties", ".yml", ".yaml")):
            body = asset.get("text") or asset.get("content") or ""
            if body:
                _scan_secrets(name, body, findings)

    return findings


# ---------------------------------------------------------------------- report


def build_report(filename: str, data: bytes, analysis: dict) -> dict:
    """Build an evidence report from a deep-analysis result."""
    if analysis.get("pe") is not None and "pe" in analysis:
        findings = _pe_findings(analysis)
        target_kind = "PE executable"
    elif "apk" in analysis:
        findings = _apk_findings(analysis)
        target_kind = "Android APK"
    else:
        findings = []
        target_kind = analysis.get("detected_format", "file")

    findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 9))
    for idx, f in enumerate(findings, start=1):
        f["id"] = f"F{idx:02d}"

    score, level = _risk_score(findings)
    counts: dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    subject = {
        "filename": analysis.get("filename", filename),
        "size_bytes": analysis.get("size_bytes", len(data)),
        "sha256": analysis.get("sha256") or hashlib.sha256(data).hexdigest(),
        "format": analysis.get("format", "unknown"),
        "kind": target_kind,
    }

    report = {
        "report_id": uuid.uuid4().hex[:12],
        "schema": "revstudio.evidence-report/1",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "subject": subject,
        "risk": {"score": score, "level": level, "counts": counts},
        "findings": findings,
        "summary": _summary_text(subject, score, level, counts, findings),
        "limitations": [
            "Static analysis only: the file was not executed.",
            "Findings are evidence from file structure and content, not proof of behaviour.",
            "Absence of findings is not evidence of safety.",
        ],
    }
    report["markdown"] = render_markdown(report)
    report["html"] = render_html(report)
    return report


def _summary_text(subject: dict, score: int, level: str, counts: dict, findings: list[dict]) -> str:
    top = ", ".join(f"{v} {k}" for k, v in counts.items() if v) or "no findings"
    return (
        f"{subject['filename']} ({subject['kind']}, {subject['size_bytes']} bytes) scored "
        f"{score}/100 ({level} risk) with {len(findings)} finding(s): {top}. "
        f"SHA-256 {subject['sha256']}."
    )


def render_markdown(report: dict) -> str:
    s = report["subject"]
    r = report["risk"]
    lines = [
        f"# Evidence Report — {s['filename']}",
        "",
        f"- **Report ID:** `{report['report_id']}`",
        f"- **Generated:** {report['generated_at']}",
        f"- **SHA-256:** `{s['sha256']}`",
        f"- **Format:** {s['format']} ({s['kind']})",
        f"- **Size:** {s['size_bytes']} bytes",
        f"- **Risk:** **{r['level'].upper()}** — {r['score']}/100",
        "",
        "## Findings summary",
        "",
        "| Severity | Count |",
        "|---|---|",
    ]
    for sev in SEVERITY_ORDER:
        if r["counts"].get(sev):
            lines.append(f"| {sev} | {r['counts'][sev]} |")
    if not any(r["counts"].values()):
        lines.append("| — | 0 |")
    lines += ["", "## Findings", ""]
    if not report["findings"]:
        lines.append("_No findings raised by the current rule set._")
    for f in report["findings"]:
        lines += [
            f"### {f['id']} · [{f['severity'].upper()}] {f['title']}",
            "",
            f"- Category: `{f['category']}`",
        ]
        for ev in f["evidence"]:
            lines.append(f"- Evidence: {ev}")
        if f.get("recommendation"):
            lines.append(f"- Recommendation: {f['recommendation']}")
        lines.append("")
    lines += ["## Limitations", ""]
    for lim in report["limitations"]:
        lines.append(f"- {lim}")
    lines.append("")
    return "\n".join(lines)


_SEV_CSS = {
    "critical": ("#3a0f14", "#ff8f8f", "#7a2a2a"),
    "high": ("#331a10", "#ffb59a", "#7a4326"),
    "medium": ("#33290f", "#ffd98f", "#7a6426"),
    "low": ("#12263a", "#9ecbff", "#2a527a"),
    "info": ("#12332a", "#9be7cd", "#2a7a5e"),
}


def render_html(report: dict) -> str:
    s = report["subject"]
    r = report["risk"]
    esc = html.escape

    sev_cards = []
    for sev in SEVERITY_ORDER:
        n = r["counts"].get(sev, 0)
        bg, fg, bd = _SEV_CSS[sev]
        sev_cards.append(
            f'<div class="card" style="background:{bg};border-color:{bd}">'
            f'<span style="color:{fg}">{n}</span><small>{sev}</small></div>'
        )

    finding_html = []
    for f in report["findings"]:
        bg, fg, bd = _SEV_CSS.get(f["severity"], _SEV_CSS["info"])
        ev = "".join(f"<li>{esc(e)}</li>" for e in f["evidence"])
        rec = (f'<p class="rec"><b>Recommendation:</b> {esc(f["recommendation"])}</p>'
               if f.get("recommendation") else "")
        finding_html.append(
            f'<article class="finding" style="border-left-color:{bd}">'
            f'<header><span class="sev" style="background:{bg};color:{fg};border-color:{bd}">'
            f'{esc(f["severity"].upper())}</span>'
            f'<span class="fid">{esc(f["id"])}</span>'
            f'<h3>{esc(f["title"])}</h3></header>'
            f'<p class="cat">category: <code>{esc(f["category"])}</code></p>'
            f'<ul class="ev">{ev}</ul>{rec}</article>'
        )
    if not finding_html:
        finding_html.append('<p class="empty">No findings raised by the current rule set.</p>')

    lim = "".join(f"<li>{esc(x)}</li>" for x in report["limitations"])
    risk_bg, risk_fg, risk_bd = _SEV_CSS.get(
        {"critical": "critical", "high": "high", "medium": "medium"}.get(r["level"], "low"),
        _SEV_CSS["low"],
    )

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Evidence Report — {esc(s['filename'])}</title>
<style>
  :root {{ color-scheme: dark; }}
  * {{ box-sizing: border-box; }}
  body {{ margin:0; background:#0a111d; color:#c9d6e8;
         font:14px/1.6 "Segoe UI",system-ui,sans-serif; padding:32px 18px; }}
  .wrap {{ max-width:880px; margin:0 auto; }}
  h1 {{ font-size:22px; margin:0 0 4px; color:#e9edf8; }}
  .meta {{ font:12px/1.8 "Cascadia Mono",Consolas,monospace; color:#71839c;
           border:1px solid #1c2b40; background:#0c1524; border-radius:10px;
           padding:14px 16px; margin:16px 0; overflow-wrap:anywhere; }}
  .meta b {{ color:#9fd4f3; font-weight:600; }}
  .risk {{ display:flex; gap:10px; align-items:center; flex-wrap:wrap; margin:14px 0; }}
  .risk .badge {{ border:1px solid {risk_bd}; background:{risk_bg}; color:{risk_fg};
                  padding:8px 14px; border-radius:8px; font-weight:700;
                  letter-spacing:1px; font-size:13px; }}
  .cards {{ display:flex; gap:8px; flex-wrap:wrap; }}
  .card {{ border:1px solid; border-radius:8px; padding:8px 14px; text-align:center; min-width:74px; }}
  .card span {{ font-size:20px; font-weight:700; display:block; }}
  .card small {{ font-size:10px; letter-spacing:1px; text-transform:uppercase; color:#71839c; }}
  h2 {{ font-size:15px; color:#8bd3ff; letter-spacing:.6px; margin:26px 0 10px;
        text-transform:uppercase; font-family:"Cascadia Mono",Consolas,monospace; }}
  .finding {{ border:1px solid #1c2b40; border-left:4px solid; background:#0c1524;
              border-radius:10px; padding:14px 16px; margin:10px 0; }}
  .finding header {{ display:flex; gap:10px; align-items:center; flex-wrap:wrap; }}
  .finding h3 {{ margin:0; font-size:14px; color:#e9edf8; flex:1; min-width:200px; }}
  .sev {{ font:10px "Cascadia Mono",monospace; border:1px solid; padding:3px 8px;
          border-radius:6px; letter-spacing:.8px; }}
  .fid {{ font:11px "Cascadia Mono",monospace; color:#44587a; }}
  .cat {{ font-size:11px; color:#71839c; margin:8px 0 4px; }}
  code {{ font:11px "Cascadia Mono",monospace; background:#091120; border:1px solid #1f3048;
          padding:2px 6px; border-radius:5px; color:#9fd4f3; }}
  .ev {{ margin:6px 0; padding-left:18px; font-size:12.5px; color:#c3cede; }}
  .ev li {{ margin:3px 0; }}
  .rec {{ font-size:12.5px; color:#9be7cd; margin:8px 0 0; }}
  .empty {{ color:#6f8099; font-style:italic; }}
  .lim {{ font-size:12.5px; color:#8291a9; background:#0c1524; border:1px solid #1c2b40;
          border-radius:10px; padding:14px 18px; }}
  footer {{ margin-top:26px; font-size:11px; color:#44587a; text-align:center; }}
</style></head><body><div class="wrap">
<h1>Evidence Report — {esc(s['filename'])}</h1>
<div class="meta">
  <b>Report ID</b> {esc(report['report_id'])} &nbsp;·&nbsp;
  <b>Generated</b> {esc(report['generated_at'])}<br>
  <b>SHA-256</b> {esc(s['sha256'])}<br>
  <b>Format</b> {esc(s['format'])} ({esc(s['kind'])}) &nbsp;·&nbsp;
  <b>Size</b> {s['size_bytes']} bytes
</div>
<div class="risk">
  <span class="badge">RISK {esc(r['level'].upper())} · {r['score']}/100</span>
  <div class="cards">{''.join(sev_cards)}</div>
</div>
<h2>Findings ({len(report['findings'])})</h2>
{''.join(finding_html)}
<h2>Limitations</h2>
<ul class="lim">{lim}</ul>
<footer>Generated by Reverse Engineering Studio — static analysis, evidence-based review.</footer>
</div></body></html>"""
