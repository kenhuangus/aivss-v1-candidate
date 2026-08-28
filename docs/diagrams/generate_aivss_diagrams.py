#!/usr/bin/env python3
"""AIVSS 1.0 figures — white background only, generous spacing (no text/shape overlap)."""

from pathlib import Path
import cairosvg

OUT = Path(__file__).resolve().parent
WHITE = "#ffffff"
RASTER_SCALE = 8.0

STYLE = """
<style>
  text { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif; }
  .title { font-size: 30px; font-weight: 700; fill: #0f172a; }
  .label { font-size: 26px; font-weight: 600; fill: #1e293b; }
  .small { font-size: 24px; fill: #475569; }
  .mono { font-family: Consolas, 'Courier New', monospace; font-size: 24px; fill: #1d4ed8; }
</style>
"""


def save(name: str, svg: str):
    path = OUT / f"{name}.svg"
    path.write_text(svg, encoding="utf-8")
    cairosvg.svg2png(url=str(path), write_to=str(OUT / f"{name}.png"), scale=RASTER_SCALE)
    print(f"  [+] {name}.png")


def fig_architecture():
    save("fig-architecture", f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1400 640" width="1400" height="640">
{STYLE}<rect width="1400" height="640" fill="{WHITE}"/>
<text x="40" y="48" class="title">AIVSS 1.0 — Three Layers</text>

<rect x="40" y="80" width="400" height="220" rx="14" fill="#eff6ff" stroke="#2563eb" stroke-width="2"/>
<text x="240" y="125" text-anchor="middle" class="title" fill="#1e3a8a">Layer 1 — Severity</text>
<text x="60" y="165" class="label">AIVSS = CVSS-BTE</text>
<text x="60" y="205" class="small">Honest CVSS v4.0 scoring</text>
<text x="60" y="255" class="mono">Output: AIVSS:7.8</text>

<rect x="500" y="80" width="400" height="220" rx="14" fill="#f0fdf4" stroke="#16a34a" stroke-width="2"/>
<text x="700" y="115" text-anchor="middle" class="title" fill="#14532d">Layer 2 — Agentic AI</text>
<text x="700" y="145" text-anchor="middle" class="title" fill="#14532d">Profile</text>
<text x="520" y="165" class="label">LC · CP · AP · SR · TD</text>
<text x="520" y="205" class="small">AI Effect Class A0 / A1 / A2</text>
<text x="520" y="255" class="mono">LC:D/CP:C/AP:L/SR:R</text>

<rect x="960" y="80" width="400" height="220" rx="14" fill="#fffbeb" stroke="#d97706" stroke-width="2"/>
<text x="1160" y="125" text-anchor="middle" class="title" fill="#92400e">Layer 3 — Timeline</text>
<text x="980" y="165" class="label">CISA BOD 26-04 + AI class</text>
<text x="980" y="205" class="small">When to remediate</text>
<text x="980" y="255" class="mono">3 / 14 / 60 days</text>

<line x1="440" y1="190" x2="500" y2="190" stroke="#64748b" stroke-width="3" marker-end="url(#a)"/>
<line x1="900" y1="190" x2="960" y2="190" stroke="#64748b" stroke-width="3" marker-end="url(#a)"/>

<rect x="40" y="340" width="1320" height="120" rx="14" fill="#fdf2f8" stroke="#db2777" stroke-width="2"/>
<text x="700" y="385" text-anchor="middle" class="title" fill="#9d174d">Taxonomy: OWASP Agentic AI Top 10 (ASI01–ASI10)</text>
<text x="700" y="425" text-anchor="middle" class="small">AIVSS is a scoring tool — OWASP ASI01–ASI10 is the canonical risk taxonomy (v1.0)</text>

<rect x="40" y="490" width="1320" height="100" rx="14" fill="#f8fafc" stroke="#94a3b8" stroke-width="2"/>
<text x="700" y="545" text-anchor="middle" class="label">Optional: Extended severity (Mode 2) · Internal priority (AIVSS-P)</text>

<defs><marker id="a" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto"><path d="M0,1 L10,5 L0,9 z" fill="#64748b"/></marker></defs>
</svg>""")


def fig_scoring_flow():
    save("fig-scoring-flow", f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1400 640" width="1400" height="640">
{STYLE}<rect width="1400" height="640" fill="{WHITE}"/>
<text x="40" y="48" class="title">Assessment Flow</text>

<rect x="40" y="90" width="170" height="110" rx="12" fill="#eff6ff" stroke="#2563eb" stroke-width="2"/>
<text x="125" y="135" text-anchor="middle" class="label">CVSS v4.0</text>
<text x="125" y="170" text-anchor="middle" class="label">vector</text>

<rect x="250" y="85" width="170" height="120" rx="12" fill="#eff6ff" stroke="#2563eb" stroke-width="2"/>
<text x="335" y="125" text-anchor="middle" class="label">Agentic AI</text>
<text x="335" y="155" text-anchor="middle" class="label">Profile</text>
<text x="335" y="185" text-anchor="middle" class="small">optional</text>

<rect x="460" y="80" width="190" height="130" rx="12" fill="#dbeafe" stroke="#1d4ed8" stroke-width="2"/>
<text x="555" y="125" text-anchor="middle" class="label">CVSS-BTE</text>
<text x="555" y="160" text-anchor="middle" class="mono">7.8</text>
<text x="555" y="195" text-anchor="middle" class="small">severity</text>

<rect x="690" y="80" width="190" height="130" rx="12" fill="#dcfce7" stroke="#16a34a" stroke-width="2"/>
<text x="785" y="125" text-anchor="middle" class="label">AI class</text>
<text x="785" y="160" text-anchor="middle" class="mono">A2</text>
<text x="785" y="195" text-anchor="middle" class="small">profile</text>

<rect x="920" y="75" width="200" height="140" rx="12" fill="#eff6ff" stroke="#1d4ed8" stroke-width="2"/>
<text x="1020" y="120" text-anchor="middle" class="label">AIVSS</text>
<text x="1020" y="155" text-anchor="middle" class="mono">7.8</text>
<text x="1020" y="190" text-anchor="middle" class="small">primary score</text>

<line x1="210" y1="145" x2="250" y2="145" stroke="#64748b" stroke-width="3" marker-end="url(#b)"/>
<line x1="420" y1="145" x2="460" y2="145" stroke="#64748b" stroke-width="3" marker-end="url(#b)"/>
<line x1="650" y1="145" x2="690" y2="145" stroke="#64748b" stroke-width="3" marker-end="url(#b)"/>
<line x1="880" y1="145" x2="920" y2="145" stroke="#64748b" stroke-width="3" marker-end="url(#b)"/>

<rect x="1160" y="230" width="200" height="120" rx="12" fill="#f5f3ff" stroke="#7c3aed" stroke-width="2" stroke-dasharray="8 4"/>
<text x="1260" y="275" text-anchor="middle" class="label">BTEA</text>
<text x="1260" y="310" text-anchor="middle" class="mono">9.0</text>
<text x="1260" y="340" text-anchor="middle" class="small">optional</text>
<line x1="785" y1="210" x2="785" y2="250" stroke="#64748b" stroke-width="3"/>
<line x1="785" y1="250" x2="1160" y2="250" stroke="#64748b" stroke-width="3"/>
<line x1="1160" y1="250" x2="1160" y2="230" stroke="#64748b" stroke-width="3" marker-end="url(#b)"/>

<rect x="40" y="380" width="1320" height="220" rx="14" fill="#fffbeb" stroke="#d97706" stroke-width="2"/>
<text x="700" y="430" text-anchor="middle" class="title" fill="#92400e">Remediation timeline (parallel track)</text>
<text x="60" y="475" class="small">Inputs: KEV · exposure · automatable · technical impact · AI class</text>
<text x="60" y="515" class="small">Evidence ladder: KEV → Vulnrichment → observed → PoC → none (EPSS: dated metadata only, Section 12.3.1)</text>
<text x="60" y="555" class="mono">Output: BOD 26-04 baseline + AIVSS recommendation</text>

<defs><marker id="b" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto"><path d="M0,1 L10,5 L0,9 z" fill="#64748b"/></marker></defs>
</svg>""")


def fig_ai_effect_class():
    save("fig-ai-effect-class", f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1300 560" width="1300" height="560">
{STYLE}<rect width="1300" height="560" fill="{WHITE}"/>
<text x="40" y="48" class="title">AI Effect Class (boolean rules — no arithmetic)</text>

<rect x="40" y="80" width="1220" height="120" rx="12" fill="#fef2f2" stroke="#dc2626" stroke-width="2"/>
<text x="60" y="125" class="title" fill="#991b1b">A2 — Substantial</text>
<text x="60" y="165" class="small">AP:L  OR  (LC Direct/Indirect AND CP Cross-session)  OR  (LC:D AND SR:R)</text>

<rect x="40" y="230" width="1220" height="120" rx="12" fill="#fffbeb" stroke="#d97706" stroke-width="2"/>
<text x="60" y="275" class="title" fill="#92400e">A1 — Present</text>
<text x="60" y="315" class="small">Not A2, but at least one AI metric above benign level</text>

<rect x="40" y="380" width="1220" height="120" rx="12" fill="#f0fdf4" stroke="#16a34a" stroke-width="2"/>
<text x="60" y="425" class="title" fill="#14532d">A0 — None</text>
<text x="60" y="465" class="small">All benign, or no Agentic AI Profile — AIVSS equals CVSS-BTE exactly</text>

<text x="650" y="530" text-anchor="middle" class="small">A2 may advance remediation timeline by one tier</text>
</svg>""")


def fig_bod_decision():
    save("fig-bod-decision", f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1300 580" width="1300" height="580">
{STYLE}<rect width="1300" height="580" fill="{WHITE}"/>
<text x="40" y="48" class="title">Remediation Decision Inputs</text>

<rect x="40" y="80" width="220" height="90" rx="10" fill="#eff6ff" stroke="#2563eb" stroke-width="2"/>
<text x="150" y="135" text-anchor="middle" class="label">KEV</text>
<rect x="280" y="80" width="220" height="90" rx="10" fill="#eff6ff" stroke="#2563eb" stroke-width="2"/>
<text x="390" y="135" text-anchor="middle" class="label">Exposure</text>
<rect x="520" y="80" width="220" height="90" rx="10" fill="#eff6ff" stroke="#2563eb" stroke-width="2"/>
<text x="630" y="135" text-anchor="middle" class="label">Automatable</text>
<rect x="760" y="80" width="220" height="90" rx="10" fill="#eff6ff" stroke="#2563eb" stroke-width="2"/>
<text x="870" y="135" text-anchor="middle" class="label">Impact</text>
<rect x="1000" y="80" width="260" height="90" rx="10" fill="#f0fdf4" stroke="#16a34a" stroke-width="2"/>
<text x="1130" y="135" text-anchor="middle" class="label">AI class</text>

<rect x="200" y="210" width="900" height="110" rx="12" fill="#eff6ff" stroke="#2563eb" stroke-width="2"/>
<text x="650" y="255" text-anchor="middle" class="label" fill="#1e3a8a">BOD 26-04 — 16-row lookup</text>
<text x="650" y="295" text-anchor="middle" class="small">All five inputs required — no shortcut formulas</text>

<rect x="80" y="360" width="260" height="80" rx="10" fill="#fef2f2" stroke="#dc2626"/>
<text x="210" y="410" text-anchor="middle" class="label">3 days</text>
<rect x="370" y="360" width="260" height="80" rx="10" fill="#fffbeb" stroke="#d97706"/>
<text x="500" y="410" text-anchor="middle" class="label">14 days</text>
<rect x="660" y="360" width="260" height="80" rx="10" fill="#eff6ff" stroke="#2563eb"/>
<text x="790" y="410" text-anchor="middle" class="label">60 days</text>
<rect x="950" y="360" width="260" height="80" rx="10" fill="#f8fafc" stroke="#94a3b8"/>
<text x="1080" y="410" text-anchor="middle" class="label">Defer</text>

<rect x="120" y="470" width="1060" height="80" rx="12" fill="#f5f3ff" stroke="#7c3aed" stroke-width="2"/>
<text x="650" y="520" text-anchor="middle" class="small">A2: advance one tier · always report BOD baseline alongside AIVSS recommendation</text>
</svg>""")


def fig_evidence_ladder():
    rows = [
        ("#fef2f2", "#dc2626", "1. CISA KEV listed"),
        ("#fffbeb", "#d97706", "2. Vulnrichment: active exploitation"),
        ("#f5f3ff", "#7c3aed", "3. Organization observed (unverified)"),
        ("#f8fafc", "#94a3b8", "4. Proof-of-concept exists"),
        ("#ffffff", "#cbd5e1", "5. No evidence"),
    ]
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1300 560" width="1300" height="560">\n{STYLE}<rect width="1300" height="560" fill="{WHITE}"/>']
    parts.append('<text x="40" y="48" class="title">Exploitation Evidence Ladder</text>')
    y = 80
    for fill, stroke, label in rows:
        parts.append(f'<rect x="40" y="{y}" width="1220" height="64" rx="10" fill="{fill}" stroke="{stroke}" stroke-width="2"/>')
        parts.append(f'<text x="60" y="{y + 42}" class="label">{label}</text>')
        y += 76
    parts.append('<rect x="40" y="470" width="1220" height="64" rx="10" fill="#eff6ff" stroke="#2563eb" stroke-width="2" stroke-dasharray="8 4"/>')
    parts.append('<text x="60" y="512" class="small">EPSS — recorded as dated metadata only (not a ladder rung); see Section 12.3.1</text>')
    parts.append("</svg>")
    save("fig-evidence-ladder", "\n".join(parts))


def fig_s2_promotion():
    save("fig-s2-promotion", f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1300 520" width="1300" height="520">
{STYLE}<rect width="1300" height="520" fill="{WHITE}"/>
<text x="40" y="48" class="title">Extended Severity — Mode 2 (optional)</text>

<rect x="40" y="80" width="380" height="150" rx="12" fill="#f0fdf4" stroke="#16a34a" stroke-width="2"/>
<text x="230" y="125" text-anchor="middle" class="title" fill="#14532d">A0</text>
<text x="230" y="165" text-anchor="middle" class="small">No change</text>
<text x="230" y="200" text-anchor="middle" class="mono">BTEA = AIVSS</text>

<rect x="460" y="80" width="380" height="150" rx="12" fill="#fffbeb" stroke="#d97706" stroke-width="2"/>
<text x="650" y="125" text-anchor="middle" class="title" fill="#92400e">A1</text>
<text x="650" y="165" text-anchor="middle" class="small">Promote SC/SI/SA class</text>
<text x="650" y="200" text-anchor="middle" class="mono">lookup table</text>

<rect x="880" y="80" width="380" height="150" rx="12" fill="#fef2f2" stroke="#dc2626" stroke-width="2"/>
<text x="1070" y="125" text-anchor="middle" class="title" fill="#991b1b">A2</text>
<text x="1070" y="165" text-anchor="middle" class="small">Also promote AV/PR/UI</text>
<text x="1070" y="200" text-anchor="middle" class="mono">lookup table</text>

<rect x="40" y="270" width="1220" height="210" rx="14" fill="#eff6ff" stroke="#2563eb" stroke-width="2"/>
<text x="650" y="320" text-anchor="middle" class="label" fill="#1e3a8a">Example: ASI06 memory poisoning</text>
<text x="650" y="365" text-anchor="middle" class="mono">AIVSS 7.8 → BTEA 9.0</text>
<text x="650" y="410" text-anchor="middle" class="small">Every value exists in FIRST cvss_lookup.js — no invented numbers</text>
<text x="650" y="450" text-anchor="middle" class="small">Provisional — not for contracts or compliance gates</text>
</svg>""")


def main():
    print("[*] Generating spaced white-background figures...")
    fig_architecture()
    fig_scoring_flow()
    fig_ai_effect_class()
    fig_bod_decision()
    fig_evidence_ladder()
    fig_s2_promotion()
    print("[OK] Done.")


if __name__ == "__main__":
    main()
