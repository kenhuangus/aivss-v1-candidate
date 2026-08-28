# AIVSS v1.0 Candidate

CVSS-compatible scoring for agentic AI vulnerabilities — specification, reference calculator, and Google Doc build pipeline.

## Repository layout

| Path | Description |
|------|-------------|
| [`docs/AIVSS-1.0-Google-Doc.md`](docs/AIVSS-1.0-Google-Doc.md) | Normative specification (source of truth) |
| [`tools/aivss-calc/`](tools/aivss-calc/) | Reference calculator CLI (`aivss-calc`) |
| [`schemas/aivss-report-v1.0.json`](schemas/aivss-report-v1.0.json) | Level 1–3 JSON report schema |

## Quick start

```bash
cd tools/aivss-calc
pip install -e ".[dev]"
pytest
aivss-calc assess examples/asi06-example.json
```

## Rebuild Google Doc

```bash
python docs/build_google_doc.py
```

Requires Google Drive API credentials configured for the doc upload step.

## Live document

https://docs.google.com/document/d/1SIO6yN1x4XXTnclLeEsFFHnqzRR-3SOvUJTHF7CGRpI/edit

## License

Open-source components per file headers and attributions in the specification (Appendix A).
