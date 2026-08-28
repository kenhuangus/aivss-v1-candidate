#!/usr/bin/env python3
"""Build AIVSS 1.0 Google Doc with large-font tables and figures."""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from doc_build import build, publish  # noqa: E402

MD = ROOT / "AIVSS-1.0-Google-Doc.md"
DOCX = ROOT / "AIVSS-1.0-Google-Doc.docx"
DIAGRAMS = ROOT / "diagrams"
QA = ROOT / "qa_pages"
GOOGLE_DOC_ID = "1SIO6yN1x4XXTnclLeEsFFHnqzRR-3SOvUJTHF7CGRpI"

DIAGRAM_MAP = {
    "6 Architecture Overview": ("fig-architecture.png", "Figure 1: AIVSS 1.0 system layers"),
    "8 End-to-End Assessment Flow": ("fig-scoring-flow.png", "Figure 2: Assessment flow"),
    "11 AI Effect Class": ("fig-ai-effect-class.png", "Figure 3: AI Effect Class rules"),
    "12 Remediation Timelines": ("fig-bod-decision.png", "Figure 4: Remediation decision inputs"),
    "12.3 Exploitation evidence ladder": ("fig-evidence-ladder.png", "Figure 5: Exploitation evidence ladder"),
    "13.2 Mode 2 — MacroVector extension": ("fig-s2-promotion.png", "Figure 6: Extended severity (Mode 2)"),
}


def main():
    subprocess.run([sys.executable, str(DIAGRAMS / "generate_aivss_diagrams.py")], check=True)
    # Clear stale table PNGs so numbering stays consistent.
    assets = ROOT / "assets" / "tables"
    if assets.exists():
        for p in assets.glob("table_infographic_*.png"):
            p.unlink()
    build(MD, DOCX, DIAGRAMS, DIAGRAM_MAP)
    ok = publish(GOOGLE_DOC_ID, DOCX, QA)
    if ok:
        print(f"\n[OK] Google Doc: https://docs.google.com/document/d/{GOOGLE_DOC_ID}/edit")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
