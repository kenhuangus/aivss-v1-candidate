#!/usr/bin/env python3
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))
from apply_doc_phase25 import insert_appendix_example, verify_account

if __name__ == "__main__":
    verify_account()
    insert_appendix_example()
