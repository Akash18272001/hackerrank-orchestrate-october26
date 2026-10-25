# Ghost Data Still Exists — Submission Code

## Run

From the repository root, with the challenge `dataset/` directory in place:

```powershell
python code/main.py
```

The program reads the participant-facing files under `dataset/`, audits all requests at each request's `audit_at` cutoff, writes root-level `output.csv`, and refreshes the evaluation and usage reports under `code/evaluation/`.

## Approach

This submission uses a deterministic, evidence-driven Python pipeline. It parses the supplied structured JSON, logs, SQL snapshots, text, and available PDF/image evidence; resolves identities against current and historical identifiers; applies the deletion rules and cutoff; creates ordered findings/remediation/verification steps; validates the output schema; and evaluates status/step quality against the provided public sample. It does not call an external LLM or API, so no API key is needed and model-token cost is zero.

Optional PDF/image extraction depends on local packages and OCR tools being installed. Missing optional extractors may reduce evidence coverage for those formats.

## Evaluation

See `evaluation/evaluation_report.md` and `evaluation/usage_report.md` for the latest full-dataset run, public-sample metrics, limitations, and token/cost accounting.
