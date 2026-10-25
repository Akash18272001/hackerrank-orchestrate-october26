# Evaluation report

## Full evaluation output

- Requests processed: 518
- COMPLETE: 177
- INCOMPLETE: 322
- NOT_APPLICABLE: 19
- Evidence manifest rows: 94
- Parsed evidence observations: 2976
- Structural validation errors: 0

## Public sample evaluation

- Sample requests: 32
- Status matches: 32/32
- Exact step-list matches: 14/32
- Expected steps: 193
- Exact semantic steps matched: 163
- Step field accuracy (position-aligned, six semantic fields): 945/1164 (81.2%)
- Sequence accuracy (phase/system/resource/operation/state in order): 14/32

Sample answers are used only for evaluation; they are not copied into the hidden output.

## Additional sanity cases

- PASS: non-deletion request
- PASS: exact identifier boundary (user_15 must not match user_150)
- PASS: evidence after audit_at is excluded

## First sample mismatches

- case_03: expected COMPLETE; generated COMPLETE; expected_steps=3 generated_steps=2
- case_04: expected COMPLETE; generated COMPLETE; expected_steps=2 generated_steps=1
- case_09: expected INCOMPLETE; generated INCOMPLETE; expected_steps=5 generated_steps=4
- case_17: expected INCOMPLETE; generated INCOMPLETE; expected_steps=5 generated_steps=6
- case_18: expected INCOMPLETE; generated INCOMPLETE; expected_steps=14 generated_steps=13
- case_20: expected INCOMPLETE; generated INCOMPLETE; expected_steps=8 generated_steps=7
- case_21: expected COMPLETE; generated COMPLETE; expected_steps=3 generated_steps=2
- case_22: expected INCOMPLETE; generated INCOMPLETE; expected_steps=8 generated_steps=6
- case_23: expected INCOMPLETE; generated INCOMPLETE; expected_steps=8 generated_steps=7
- case_24: expected INCOMPLETE; generated INCOMPLETE; expected_steps=7 generated_steps=6
- case_25: expected COMPLETE; generated COMPLETE; expected_steps=3 generated_steps=2
- case_26: expected COMPLETE; generated COMPLETE; expected_steps=6 generated_steps=5
- case_27: expected COMPLETE; generated COMPLETE; expected_steps=6 generated_steps=5
- case_28: expected COMPLETE; generated COMPLETE; expected_steps=6 generated_steps=5
- case_29: expected INCOMPLETE; generated INCOMPLETE; expected_steps=14 generated_steps=13
- case_30: expected INCOMPLETE; generated INCOMPLETE; expected_steps=14 generated_steps=13
- case_31: expected COMPLETE; generated COMPLETE; expected_steps=3 generated_steps=3
- case_32: expected INCOMPLETE; generated INCOMPLETE; expected_steps=5 generated_steps=5

## Structural validation errors

- None

## Failures found and improvements made

- Added parsing of JSON Lines observability logs and grouped records by trace ID so subject identifiers and resource readbacks can be associated within one trace.
- Resource-category classification now prioritizes explicit resource namespaces; connector names containing words such as analytics no longer override a data_flow resource ID.
- Contact-index lookups are classified as secondary identifiers requiring deletion, and explicit support PII-scan hits are treated as evidence of exposed identifiers.
- Remaining failures include resources whose identifiers were anonymized or absent from identity-bearing evidence, incomplete cross-file linkage, and resource IDs that cannot safely be inferred from a stable user ID.

## Limitations

- This is a deterministic evidence parser; no LLM/API calls are made.
- SQL snapshots are read with SQLite, JSON records are recursively parsed, logs/text are parsed line-by-line, PDFs use text extraction, and images use OCR when available.
- Resource absence is not inferred merely from no matching line; absence verification is emitted only when a cutoff-safe snapshot/readback supports it.
- Review the public sample comparison before submission; passing structural validation does not guarantee semantic accuracy.
