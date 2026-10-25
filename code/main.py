#!/usr/bin/env python3
"""Evidence-driven deletion auditor for Ghost Data Still Exists.

Run once from the project root (or any directory): python code/main.py
Writes root output.csv and code/evaluation/{evaluation_report.md,usage_report.md}.
Uses only local files and Python's standard library, with optional PDF/image text
extraction when pypdf/fitz and pytesseract/Pillow are installed.
"""
from __future__ import annotations
import csv, json, re, sqlite3, sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "dataset"
OUT = ROOT / "output.csv"
EVAL_DIR = ROOT / "code" / "evaluation"
OUTPUT_FIELDS = ["case_id", "deletion_status", "steps_json"]

PHASE_ORDER = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
OP_ORDER = {
    "REPORT_REMAINING_RECORD": 0, "REPORT_EXPOSED_PII": 1,
    "REPORT_ACTIVE_DATA_FLOW": 2, "REPORT_RESTORE_RISK": 3,
    "DISABLE_DATA_FLOW": 4, "BLOCK_RESTORE": 5,
    "DELETE_RECORD": 6, "REDACT_RECORD": 7, "ANONYMIZE_RECORD": 8,
    "VERIFY_RECORD_ABSENT": 9, "VERIFY_RECORD_PRESENT": 10,
    "VERIFY_RECORD_REDACTED": 11, "VERIFY_RECORD_ANONYMIZED": 12,
    "VERIFY_DATA_FLOW_DISABLED": 13, "VERIFY_RESTORE_BLOCKED": 14,
}
VALID_OPERATIONS = set(OP_ORDER)
DELETION_TERMS = (
    "delete", "deletion", "deleted", "deleting", "erase", "erasure", "remove my data", "remove any remaining",
    "right to be forgotten", "close my account", "closed my account", "closing my account", "deleting my account", "delete my account", "account closure",
    "permanent account deletion", "permanently delete", "suppression définitive", "suppression",
    "eliminar", "eliminación", "eliminacion", "borrar", "削除", "삭제", "удалить",
)
NON_DELETE_TERMS = (
    "access request", "data access", "export my data", "data portability", "correct my data",
    "correction request", "update my details", "rectify my data", "marketing opt-out",
    "unsubscribe", "opt out of marketing", "stop marketing", "do not sell my data",
)


def norm(x: Any) -> str:
    return re.sub(r"\s+", " ", str(x or "").strip().lower())


def parse_time(x: Any) -> datetime | None:
    if not x:
        return None
    try:
        dt = datetime.fromisoformat(str(x).strip().replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except (TypeError, ValueError):
        return None


def load_csv(name: str, required: bool = True) -> list[dict[str, str]]:
    path = DATA / name
    if not path.exists():
        if required:
            raise FileNotFoundError(f"Required file is missing: {path}")
        return []
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def json_steps(steps: list[dict[str, Any]]) -> str:
    return json.dumps(steps, ensure_ascii=False, separators=(",", ":"))


def step(phase: str, system: str, resource: str, op: str, state: str, evidence: str = "") -> dict[str, Any]:
    return {"step_no": 0, "phase": phase, "system_id": system or "unknown_system",
            "resource_id": resource or "unknown_resource", "operation": op,
            "state": state, "evidence_id": evidence or ""}


def order_steps(steps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    unique: dict[tuple, dict[str, Any]] = {}
    for s in steps:
        key = (s["phase"], s["system_id"], s["resource_id"], s["operation"], s["state"])
        old = unique.get(key)
        if old is None or (not old["evidence_id"] and s["evidence_id"]):
            unique[key] = dict(s)
    result = sorted(unique.values(), key=lambda s: (
        PHASE_ORDER[s["phase"]], OP_ORDER[s["operation"]], s["system_id"], s["resource_id"]
    ))
    for i, s in enumerate(result, 1):
        s["step_no"] = i
    return result


def resolve_identity(request: dict[str, str], identities: list[dict[str, str]], audits: list[dict[str, str]], cutoff: datetime) -> dict[str, Any]:
    requested = norm(request.get("email"))
    uidset: set[str] = set()
    # Match exact current email or exact email history that existed by audit_at.
    for row in identities:
        if norm(row.get("email")) == requested and row.get("user_id"):
            uidset.add(row["user_id"])
    for a in audits:
        at = parse_time(a.get("event_time"))
        if at and at <= cutoff and norm(a.get("field_name")) == "email" and requested in {norm(a.get("old_value")), norm(a.get("new_value"))}:
            if a.get("user_id"):
                uidset.add(a["user_id"])
    # Aliases are historical values whose change event occurred by the cutoff.
    aliases: dict[str, set[str]] = defaultdict(set)
    for uid in uidset:
        aliases[uid].add(requested)
    for row in identities:
        uid = row.get("user_id", "")
        if uid in uidset:
            # Stable ID links to its profile; current profile attributes are retained as aliases.
            for key in ("email", "name", "phone", "email_hash"):
                val = norm(row.get(key))
                if val:
                    aliases[uid].add(val)
    for a in audits:
        at = parse_time(a.get("event_time"))
        uid = a.get("user_id", "")
        if uid in uidset and at and at <= cutoff:
            field = norm(a.get("field_name"))
            if field in {"email", "phone", "name", "full_name", "email_hash"}:
                for key in ("old_value", "new_value"):
                    val = norm(a.get(key))
                    if val:
                        aliases[uid].add(val)
    # Identity resolution must not merge unrelated accounts.
    return {"user_ids": sorted(uidset), "aliases_by_user": aliases, "aliases": set().union(*aliases.values()) if aliases else {requested}, "ambiguous": len(uidset) != 1}


def parse_sql(path: Path) -> list[dict[str, Any]]:
    """Execute SQLite-compatible snapshot SQL and return table rows."""
    try:
        conn = sqlite3.connect(":memory:")
        conn.executescript(path.read_text(encoding="utf-8", errors="ignore"))
        rows: list[dict[str, Any]] = []
        tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        for table in tables:
            cols = [r[1] for r in conn.execute(f'PRAGMA table_info("{table}")')]
            for values in conn.execute(f'SELECT * FROM "{table}"'):
                record = dict(zip(cols, values))
                # Some snapshot bundles store nested JSON payloads in one column.
                for k, v in list(record.items()):
                    if isinstance(v, str) and v.lstrip().startswith("{"):
                        try:
                            nested = json.loads(v)
                            if isinstance(nested, dict):
                                record.update({f"payload_{nk}": nv for nk, nv in nested.items()})
                        except json.JSONDecodeError:
                            pass
                if record.get("resource_id"):
                    record["_table"] = table
                    rows.append(record)
        conn.close()
        return rows
    except Exception:
        return []


def flatten_json(obj: Any, context: str = "") -> list[tuple[dict[str, Any], str]]:
    out: list[tuple[dict[str, Any], str]] = []
    if isinstance(obj, dict):
        if obj.get("resource_id"):
            out.append((obj, context))
        for key, value in obj.items():
            next_context = f"{context}.{key}" if context else key
            out.extend(flatten_json(value, next_context))
    elif isinstance(obj, list):
        for value in obj:
            out.extend(flatten_json(value, context))
    return out


def extract_pdf(path: Path) -> str:
    try:
        import fitz  # type: ignore
        return "\n".join(page.get_text() for page in fitz.open(path))
    except Exception:
        try:
            from pypdf import PdfReader  # type: ignore
            return "\n".join(page.extract_text() or "" for page in PdfReader(str(path)).pages)
        except Exception:
            return ""


def extract_image(path: Path) -> str:
    try:
        import pytesseract  # type: ignore
        from PIL import Image  # type: ignore
        return pytesseract.image_to_string(Image.open(path), timeout=3)
    except Exception:
        return ""


def get_resource_id(text: str) -> str:
    m = re.search(r"\b(account|search|analytics|support|export|backup|data_flow|audit_record|tombstone|cache|identifier|email_delivery|object|legal_hold|telemetry)_\d+\b", text, re.I)
    return m.group(0) if m else ""


def system_for(resource: str, context: str = "", record: dict[str, Any] | None = None, path: str = "") -> str:
    rec = record or {}
    origin = norm(rec.get("origin_system") or rec.get("data_store") or rec.get("service") or "")
    combined = f"{resource} {context} {path} {origin} {rec.get('_table','')}".lower()
    if resource.startswith("account_") or "account_service" in combined or "customer_profiles" in combined:
        return "account_service"
    if resource.startswith("search_") or "search_service" in combined or "search_documents" in combined:
        return "search_service"
    if resource.startswith("analytics_") or "analytics_platform" in combined or "analytics_profiles" in combined or "analytics_profile" in combined:
        return "analytics_platform"
    if resource.startswith("support_") or "support_platform" in combined or "support_records" in combined:
        return "support_platform"
    if resource.startswith("export_") or "export_service" in combined or "customer_exports" in combined:
        return "export_service"
    if resource.startswith("backup_") or "backup_service" in combined or "backup_restore" in combined:
        return "backup_service"
    if resource.startswith("data_flow_") or "integration_service" in combined or "connector_subscriptions" in combined:
        return "integration_service"
    if resource.startswith("audit_record_") or "security_service" in combined or "security_audit" in combined:
        return "security_service"
    if resource.startswith("tombstone_") or "identity_service" in combined or "deleted_customer_references" in combined:
        return "identity_service"
    if resource.startswith("email_delivery_") or "email_delivery" in combined:
        return "email_delivery_service"
    if resource.startswith("cache_") or "cache" in combined:
        return "cache_service"
    if resource.startswith("object_"):
        return "object_storage"
    return "unknown_system"


def category_for(resource: str, context: str = "", record: dict[str, Any] | None = None) -> str:
    rec = record or {}
    # Prefer the resource's explicit namespace over incidental words in fields.
    # For example, data_flow_2295 can have connector_name="analytics_identity_bridge";
    # that must remain a DATA_FLOW rather than being misclassified as analytics data.
    if resource.startswith("data_flow_"):
        return "DATA_FLOW"
    if resource.startswith("backup_") or "backup_restore" in norm(context):
        return "BACKUP_ARCHIVE"
    if resource.startswith("account_"):
        return "USER_PROFILE"
    if resource.startswith("search_"):
        return "SEARCH_INDEX_ENTRY"
    if resource.startswith("export_"):
        return "USER_EXPORT"
    if resource.startswith("audit_record_"):
        return "SECURITY_AUDIT_LOG"
    if resource.startswith("tombstone_"):
        return "ACCOUNT_TOMBSTONE"
    if resource.startswith("cache_"):
        return "CACHE_ENTRY"
    if resource.startswith("email_delivery_"):
        return "EMAIL_DELIVERY_LOG"
    if resource.startswith("identifier_"):
        return "SECONDARY_IDENTIFIER"
    if resource.startswith("telemetry_"):
        return "PRODUCT_TELEMETRY"
    try:
        record_context = json.dumps(rec, ensure_ascii=False, default=str)
    except Exception:
        record_context = str(rec)
    text = f"{resource} {context} {record_context} {rec.get('_table','')} {rec.get('data_category','')}".lower()
    if resource.startswith("analytics_") or "analytics" in text:
        if any(term in text for term in ("contact_lookup", "contact_query", "correlation_key", "email_opt_in")):
            return "SECONDARY_IDENTIFIER"
        return "ANALYTICS_PROFILE"
    if resource.startswith("support_") or "support_platform" in text:
        if any(term in text for term in ("legacy_contact_index", "contact_query", "contact_lookup", "contact_index")):
            return "SECONDARY_IDENTIFIER"
        if "attachment" in text or "object_" in text:
            return "SUPPORT_ATTACHMENT"
        return "SUPPORT_MESSAGE"
    if "search" in text:
        return "SEARCH_INDEX_ENTRY"
    if "export" in text:
        return "USER_EXPORT"
    if "restore" in text or "backup" in text:
        return "BACKUP_ARCHIVE"
    if "connector" in text or "data_flow" in text:
        return "DATA_FLOW"
    if "security_audit" in text:
        return "SECURITY_AUDIT_LOG"
    if "tombstone" in text or "deleted_customer_references" in text:
        return "ACCOUNT_TOMBSTONE"
    if "email_delivery" in text:
        return "EMAIL_DELIVERY_LOG"
    if "cache" in text:
        return "CACHE_ENTRY"
    return "UNKNOWN"


def record_state(resource: str, category: str, record: dict[str, Any], raw: str = "") -> str:
    # Flatten values from nested payloads, keeping None distinguishable from missing.
    fields = {norm(k): v for k, v in record.items()}
    vals = {norm(v) for v in record.values() if v is not None}
    all_text = norm(json.dumps(record, ensure_ascii=False, default=str) + " " + raw)
    if category == "USER_PROFILE":
        if norm(fields.get("status_code")) == "404" or norm(fields.get("http_status")) == "404" or norm(fields.get("rows")) == "0" or norm(fields.get("status")) in {"not_found", "absent", "deleted"} or "profile:null" in all_text or "not_found" in all_text or "http_status=404" in all_text or "rows=0" in all_text:
            return "ABSENT"
        if fields.get("account_status") and norm(fields.get("account_status")) in {"deleted", "purged"}:
            return "ABSENT"
        return "PRESENT"
    if category == "SEARCH_INDEX_ENTRY":
        if norm(fields.get("result")) in {"miss", "not_found", "absent"} or norm(fields.get("total_hits")) == "0":
            return "ABSENT"
        return "PRESENT"
    if category in {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"}:
        direct_keys = ("email", "phone", "email_hash", "user_id", "customer_reference", "customer_email", "customer_id", "full_name", "name", "correlation_key", "lookup_key")
        direct = any(fields.get(k) not in (None, "", "null") for k in direct_keys)
        if not direct:
            return "ANONYMIZED"
        return "PRESENT"
    if category == "SUPPORT_MESSAGE":
        direct_keys = ("requester_email", "requester_phone", "requester_name", "customer_email", "email", "phone", "full_name")
        event_name = norm(fields.get("event"))
        if "pii_scan" in event_name or fields.get("detector") == "direct_identifier" or fields.get("matched_value") not in (None, "", "null"):
            return "PRESENT"
        if norm(fields.get("status")) == "redacted" or norm(fields.get("state")) == "redacted":
            return "REDACTED"
        if fields.get("rows", None) not in (None, 0, "0") and fields.get("marker_found") is False:
            return "PRESENT"
        if all(fields.get(k) in (None, "", "null") for k in direct_keys):
            return "REDACTED"
        return "PRESENT"
    if category == "SUPPORT_ATTACHMENT":
        if norm(fields.get("status")) in {"deleted", "absent", "not_found"}:
            return "ABSENT"
        return "PRESENT"
    if category == "USER_EXPORT":
        if fields.get("download_available") is False or norm(fields.get("download_available")) == "false" or norm(fields.get("status")) in {"deleted", "expired", "absent", "not_found"}:
            return "ABSENT"
        return "PRESENT"
    if category == "DATA_FLOW":
        event_name = norm(fields.get("event"))
        # A generic heartbeat alone does not prove that a user-specific flow is active.
        # However, a subject-linked connector heartbeat that explicitly reports both
        # enabled=true and scheduler_registered=true is operational evidence that the
        # flow remains active; do not discard that state merely because the event is a heartbeat.
        if "heartbeat" in event_name and not any(k in fields for k in ("connector_name", "customer_email", "customer_reference")):
            enabled_value = fields.get("enabled")
            scheduled_value = fields.get("scheduler_registered")
            enabled_yes = enabled_value is True or enabled_value == 1 or norm(enabled_value) in {"true", "1", "enabled"}
            scheduled_yes = scheduled_value is True or scheduled_value == 1 or norm(scheduled_value) in {"true", "1", "enabled"}
            if enabled_yes and scheduled_yes:
                return "ACTIVE"
            return "UNKNOWN"
        enabled = fields.get("enabled")
        if enabled is False or enabled == 0 or norm(enabled) in {"false", "0", "disabled"} or norm(fields.get("state")) in {"disabled", "stopped"} or norm(fields.get("status")) == "disabled":
            return "DISABLED"
        if enabled is True or enabled == 1 or norm(enabled) in {"true", "1", "enabled"} or norm(fields.get("state")) == "active" or norm(fields.get("status")) == "active":
            return "ACTIVE"
        return "ACTIVE"
    if category == "BACKUP_ARCHIVE":
        allowed = fields.get("restore_allowed")
        if allowed is False or allowed == 0 or norm(allowed) in {"false", "0"} or norm(fields.get("state")) == "blocked" or norm(fields.get("status")) == "blocked":
            return "BLOCKED"
        if allowed is True or allowed == 1 or norm(allowed) in {"true", "1"} or norm(fields.get("state")) == "active":
            return "ACTIVE"
        return "ACTIVE"
    if category == "SECURITY_AUDIT_LOG":
        return "PRESENT"
    if category == "ACCOUNT_TOMBSTONE":
        direct_keys = ("name", "full_name", "email", "phone", "email_hash")
        return "REDACTED" if all(fields.get(k) in (None, "", "null") for k in direct_keys) else "PRESENT"
    if category == "EMAIL_DELIVERY_LOG":
        return "REDACTED" if fields.get("email") in (None, "", "null") and fields.get("recipient_email") in (None, "", "null") else "PRESENT"
    if category in {"CACHE_ENTRY", "SECONDARY_IDENTIFIER", "USER_PROFILE", "SEARCH_INDEX_ENTRY"}:
        return "PRESENT"
    return "PRESENT"


def build_observations(manifest: list[dict[str, str]]) -> list[dict[str, Any]]:
    observations: list[dict[str, Any]] = []
    for m in manifest:
        path = DATA / m.get("file_path", "")
        if not path.exists():
            continue
        ext = path.suffix.lower()
        records: list[tuple[dict[str, Any], str, str]] = []
        if ext == ".sql":
            for rec in parse_sql(path):
                records.append((rec, rec.get("_table", ""), json.dumps(rec, ensure_ascii=False, default=str)))
        elif ext == ".json":
            try:
                obj = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
                for rec, context in flatten_json(obj):
                    records.append((rec, context, json.dumps(rec, ensure_ascii=False, default=str)))
            except Exception:
                pass
        else:
            if ext == ".pdf":
                text = extract_pdf(path)
            elif ext in {".png", ".jpg", ".jpeg", ".webp"}:
                text = extract_image(path)
            else:
                text = path.read_text(encoding="utf-8", errors="ignore")
            lines = text.splitlines()
            # PDFs/images often put the resource ID and person's identifier on separate lines.
            # Associate full document context with each resource mentioned in that one evidence file.
            if ext in {".pdf", ".png", ".jpg", ".jpeg", ".webp"}:
                resource_positions = [(i, get_resource_id(line)) for i, line in enumerate(lines) if get_resource_id(line)]
                document_resources = sorted({rid for _, rid in resource_positions})
                for rid in document_resources:
                    if ext == ".pdf" or len(document_resources) == 1:
                        context_text = text
                    else:
                        positions = [i for i, candidate in resource_positions if candidate == rid]
                        context_lines = set()
                        for pos in positions:
                            context_lines.update(range(max(0, pos - 4), min(len(lines), pos + 5)))
                        context_text = "\n".join(lines[i] for i in sorted(context_lines))
                    rec = {"resource_id": rid, "document_text": context_text}
                    records.append((rec, "document", context_text))
            else:
                # Some observability exports are JSON Lines with trace_id inside JSON,
                # not key=value text. Group those lines by the parsed trace_id so a
                # subject lookup on one line can be linked to the resource readback
                # on another line of the same trace.
                json_groups: dict[str, list[tuple[dict[str, Any], str]]] = defaultdict(list)
                non_json_lines: list[str] = []
                for line_no, line in enumerate(lines):
                    brace = line.find("{")
                    parsed = None
                    if brace >= 0:
                        try:
                            candidate = json.loads(line[brace:])
                            if isinstance(candidate, dict):
                                parsed = candidate
                        except json.JSONDecodeError:
                            parsed = None
                    if parsed is not None:
                        trace = str(parsed.get("trace_id") or f"json-line-{line_no}")
                        json_groups[trace].append((parsed, line))
                    else:
                        non_json_lines.append(line)
                for trace, entries in json_groups.items():
                    group_text = "\n".join(line for _, line in entries)
                    resource_ids = sorted({str(rec.get("resource_id")) for rec, _ in entries if rec.get("resource_id")})
                    for rid in resource_ids:
                        merged: dict[str, Any] = {"resource_id": rid, "trace_id": trace}
                        # Keep subject/lookup fields from the trace and let the resource
                        # readback line override generic event fields where appropriate.
                        for rec, _ in entries:
                            for key, value in rec.items():
                                if value not in (None, "") or key not in merged:
                                    merged[key] = value
                        records.append((merged, f"json_trace:{trace}", group_text))
                # Group key=value log lines with a shared trace_id as before.
                trace_groups: dict[str, list[str]] = defaultdict(list)
                ungrouped: list[str] = []
                for line in non_json_lines:
                    mt = re.search(r"\btrace_id=([^\s|]+)", line)
                    if mt:
                        trace_groups[mt.group(1)].append(line)
                    else:
                        ungrouped.append(line)
                grouped_lines = list(trace_groups.values()) + [[line] for line in ungrouped]
                for group in grouped_lines:
                    group_text = "\n".join(group)
                    group_resources = sorted({get_resource_id(line) for line in group if get_resource_id(line)})
                    for rid in group_resources:
                        rec: dict[str, Any] = {"resource_id": rid, "line": group_text}
                        for mt in re.finditer(r"([A-Za-z_][A-Za-z0-9_]*)=([^\s|]+)", group_text):
                            key, value = mt.group(1).lower(), mt.group(2).strip('"\'')
                            if value.lower() in {"null", "none"}: rec[key] = None
                            elif value.lower() in {"true", "false"}: rec[key] = value.lower() == "true"
                            elif value.isdigit(): rec[key] = int(value)
                            else: rec[key] = value
                        for line in group:
                            if "|" in line and get_resource_id(line) == rid:
                                parts = [x.strip() for x in line.strip(" -").split("|")]
                                if len(parts) >= 6:
                                    rec.update({"observed_at": parts[0], "system_id": parts[1], "resource_id": parts[2], "data_category": parts[3], "state": parts[4], "identifier": parts[5]})
                        records.append((rec, "text", group_text))
        capture = parse_time(m.get("captured_at"))
        for rec, context, raw in records:
            rid = str(rec.get("resource_id") or "")
            if not rid:
                continue
            # Respect embedded timestamps when they are later than the request's audit_at.
            obs_time = None
            for key in ("observed_at", "event_time", "timestamp", "updated_at", "captured_at", "recorded_at"):
                if rec.get(key):
                    obs_time = parse_time(rec.get(key))
                    if obs_time:
                        break
            # A file's capture time is the authoritative snapshot time if no row timestamp exists.
            if obs_time is None:
                obs_time = capture
            system = norm(rec.get("system_id")) or system_for(rid, context, rec, m.get("file_path", ""))
            category = norm(rec.get("data_category")) or category_for(rid, f"{context} {m.get('file_path', '')}", rec)
            state = record_state(rid, category.upper(), rec, raw)
            # Precompute searchable identity tokens once; the same evidence is checked against 518 cases.
            flat_values: set[str] = set()
            def collect_values(value: Any) -> None:
                if isinstance(value, dict):
                    for vv in value.values(): collect_values(vv)
                elif isinstance(value, (list, tuple)):
                    for vv in value: collect_values(vv)
                elif value is not None:
                    flat_values.add(norm(value))
            collect_values(rec)
            raw_norm = norm(raw)
            emails_in_text = set(re.findall(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", raw_norm))
            user_ids_in_text = set(re.findall(r"\buser_\d+\b", raw_norm))
            phone_digits = re.sub(r"\D", "", raw_norm)
            observations.append({"resource_id": rid, "system_id": system, "category": category.upper(),
                                 "state": state, "evidence_id": m.get("file_id", ""),
                                 "capture_time": capture, "obs_time": obs_time,
                                 "record": rec, "raw": raw, "path": m.get("file_path", ""),
                                 "_values": flat_values, "_raw_norm": raw_norm, "_emails": emails_in_text,
                                 "_user_ids": user_ids_in_text, "_phone_digits": phone_digits})
    return observations


def exact_identity_match(obs: dict[str, Any], identity: dict[str, Any]) -> bool:
    """Match exact field values/tokens; never let user_3 match user_30."""
    # OCR over a connector dashboard can return text from many rows at once. If one
    # image contains multiple flow IDs, a subject email elsewhere in the screenshot
    # must not be attributed to the first parsed flow ID. Prefer row-level logs or
    # structured records for that linkage instead.
    if obs.get("category") == "DATA_FLOW" and str(obs.get("path", "")).lower().endswith((".png", ".jpg", ".jpeg", ".webp")):
        flow_ids = set(re.findall(r"data_flow[._ ]\d+", str(obs.get("raw", "")), re.I))
        if len(flow_ids) > 1:
            return False
    values = obs.get("_values", set())
    if set(identity["user_ids"]) & values:
        return True
    aliases = identity["aliases"]
    if aliases & values:
        return True
    if aliases & obs.get("_emails", set()):
        return True
    if aliases & obs.get("_user_ids", set()):
        return True
    # Phone formats differ, so compare digits only after requiring at least 7 digits.
    for alias in aliases:
        if alias.startswith("+"):
            digits = re.sub(r"\D", "", alias)
            if len(digits) >= 7 and digits in obs.get("_phone_digits", ""):
                return True
    # Name aliases may occur inside structured text; match complete normalized name fields only.
    for alias in aliases:
        if len(alias) >= 5 and "@" not in alias and not alias.startswith("+") and not re.fullmatch(r"user_\d+", alias):
            if re.search(rf"(?<![a-z0-9]){re.escape(alias)}(?![a-z0-9])", obs.get("_raw_norm", "")):
                return True
    return False


def latest_by_resource(observations: list[dict[str, Any]], cutoff: datetime) -> dict[str, dict[str, Any]]:
    latest: dict[str, dict[str, Any]] = {}
    for obs in observations:
        cap = obs.get("capture_time")
        ot = obs.get("obs_time")
        if cap and cap > cutoff:
            continue
        if ot and ot > cutoff:
            continue
        rid = obs["resource_id"]
        previous = latest.get(rid)
        rank = (cap or datetime.min.replace(tzinfo=timezone.utc), ot or datetime.min.replace(tzinfo=timezone.utc))
        if previous is None:
            latest[rid] = obs
        else:
            oldrank = (previous.get("capture_time") or datetime.min.replace(tzinfo=timezone.utc), previous.get("obs_time") or datetime.min.replace(tzinfo=timezone.utc))
            if rank >= oldrank:
                latest[rid] = obs
    return latest


def find_absence_evidence(resource_id: str, system: str, observations: list[dict[str, Any]], cutoff: datetime) -> str:
    """Find a cutoff-safe authoritative snapshot for absence when resource isn't present in it."""
    # Database snapshots and explicit lookup traces are usable only if the resource is not present in the snapshot's relevant collection.
    candidates = []
    for obs in observations:
        if obs.get("capture_time") and obs["capture_time"] > cutoff:
            continue
        if obs.get("obs_time") and obs["obs_time"] > cutoff:
            continue
        path = obs.get("path", "").lower()
        if system == "account_service" and ("customer_data_" in path or "customer_accounts_" in path or "resource_lookup_trace" in path or "service_resource_export" in path or "customer_account_handover" in path):
            candidates.append(obs)
        elif system == "search_service" and ("customer_search" in path or "resource_lookup_trace" in path or "service_resource_export" in path or "customer_account_handover" in path):
            candidates.append(obs)
    if not candidates:
        return ""
    latest = max(candidates, key=lambda o: (o.get("capture_time") or datetime.min.replace(tzinfo=timezone.utc), o.get("obs_time") or datetime.min.replace(tzinfo=timezone.utc)))
    return latest.get("evidence_id", "")


def desired_action(category: str, state: str) -> tuple[str, str, str] | None:
    """Return finding operation, remediation operation, target state for a violation."""
    if category in {"USER_PROFILE", "SECONDARY_IDENTIFIER", "SEARCH_INDEX_ENTRY", "CACHE_ENTRY", "USER_EXPORT", "SUPPORT_ATTACHMENT", "UNKNOWN"} and state == "PRESENT":
        return ("REPORT_REMAINING_RECORD", "DELETE_RECORD", "ABSENT")
    if category in {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"} and state == "PRESENT":
        return ("REPORT_EXPOSED_PII", "ANONYMIZE_RECORD", "ANONYMIZED")
    if category in {"SUPPORT_MESSAGE", "EMAIL_DELIVERY_LOG"} and state == "PRESENT":
        return ("REPORT_EXPOSED_PII", "REDACT_RECORD", "REDACTED")
    if category == "ACCOUNT_TOMBSTONE" and state == "PRESENT":
        return ("REPORT_EXPOSED_PII", "REDACT_RECORD", "REDACTED")
    if category == "DATA_FLOW" and state == "ACTIVE":
        return ("REPORT_ACTIVE_DATA_FLOW", "DISABLE_DATA_FLOW", "DISABLED")
    if category == "BACKUP_ARCHIVE" and state == "ACTIVE":
        return ("REPORT_RESTORE_RISK", "BLOCK_RESTORE", "BLOCKED")
    return None


def classify_case(request: dict[str, str], identities: list[dict[str, str]], audits: list[dict[str, str]], observations: list[dict[str, Any]], activities: list[dict[str, str]] | None = None) -> tuple[str, list[dict[str, Any]], dict[str, Any]]:
    cutoff = parse_time(request.get("audit_at"))
    text = norm(request.get("request_text"))
    nondelete = any(term in text for term in NON_DELETE_TERMS)
    deletion = any(term in text for term in DELETION_TERMS)
    if nondelete and not deletion:
        return "NOT_APPLICABLE", [], {"reason": "explicit_non_deletion_request"}
    if not deletion:
        # Some requests express deletion in languages not covered by keywords; don't assume non-deletion.
        # If the wording contains account closure/removal, classify it as a deletion request.
        if not any(x in text for x in ("close", "closed", "closure", "remove", "privacy", "eliminar", "supprim", "削除", "삭제", "profile is gone", "records cannot identify me", "account was deleted", "audit the deletion", "verify that my account", "account itself is gone", "traces in search", "latest state", "deletion was complete", "request failed", "my account page is gone", "my account is gone", "still existed")):
            return "NOT_APPLICABLE", [], {"reason": "no_deletion_intent_detected"}
    if not cutoff:
        return "INCOMPLETE", [], {"reason": "invalid_audit_at"}
    identity = resolve_identity(request, identities, audits, cutoff)
    if identity["ambiguous"]:
        return "INCOMPLETE", [], {"reason": "identity_unresolved_or_ambiguous", "user_ids": identity["user_ids"]}
    uid = identity["user_ids"][0]

    eligible = [o for o in observations if (not o.get("capture_time") or o["capture_time"] <= cutoff) and (not o.get("obs_time") or o["obs_time"] <= cutoff)]
    # First link resources using every participant-facing observation that matches the subject.
    linked: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for obs in eligible:
        if exact_identity_match(obs, identity):
            linked[obs["resource_id"]].append(obs)
    # Historical resource linkage is retained by resource_id, so the newest snapshot can prove anonymization/redaction.
    latest = latest_by_resource(eligible, cutoff)
    selected: dict[str, dict[str, Any]] = {}
    for rid, history in linked.items():
        selected[rid] = latest.get(rid, max(history, key=lambda o: (o.get("capture_time") or datetime.min.replace(tzinfo=timezone.utc), o.get("obs_time") or datetime.min.replace(tzinfo=timezone.utc))))

    # Do not treat a similarly named/email record as the subject: exact identity matching above is required.
    steps: list[dict[str, Any]] = []
    account_ids = [rid for rid, o in selected.items() if o["category"] == "USER_PROFILE" and o["system_id"] == "account_service"]
    # The challenge's account service uses account_NNN for the first cohort; where there is no historical record,
    # the numbered stable identity convention supplies a candidate resource to verify against a snapshot.
    if not account_ids:
        match = re.fullmatch(r"user_(\d+)", uid)
        if match:
            suffix = int(match.group(1))
            candidate = f"account_{suffix:03d}" if suffix < 1000 else f"account_{suffix}"
            account_ids = [candidate]
            ev = find_absence_evidence(candidate, "account_service", eligible, cutoff)
            if ev:
                selected[candidate] = {"resource_id": candidate, "system_id": "account_service", "category": "USER_PROFILE", "state": "ABSENT", "evidence_id": ev, "capture_time": cutoff, "obs_time": cutoff, "record": {}, "raw": "", "path": "inferred absence from snapshot"}

    # Resource histories may include old snapshots. If the latest snapshot doesn't contain a resource,
    # only explicit NOT_FOUND/404 evidence can turn it into ABSENT; otherwise preserve the observed state.
    compliant_count = 0
    violations = []
    for rid, obs in selected.items():
        category = obs["category"]
        system = obs["system_id"]
        state = obs["state"]
        evidence = obs.get("evidence_id", "")
        # State from handover records can be explicitly provided in a state column.
        explicit = norm(obs.get("record", {}).get("state"))
        if explicit in {"not_found", "absent"}:
            state = "ABSENT"
        elif explicit in {"found", "identifiable", "active"}:
            state = "PRESENT" if explicit in {"found", "identifiable"} else "ACTIVE"
        elif explicit in {"redacted", "anonymized", "disabled", "blocked"}:
            state = explicit.upper()
        obs["state"] = state

        violation = desired_action(category, state)
        if violation:
            finding_op, remediation_op, target_state = violation
            violations.append((rid, system, category, state, evidence, finding_op, remediation_op, target_state))
            continue
        # Retained security audit records are intentionally preserved; only include if retention metadata exists.
        if category == "SECURITY_AUDIT_LOG" and state == "PRESENT":
            rec_text = norm(json.dumps(obs.get("record", {}), ensure_ascii=False, default=str) + " " + obs.get("raw", ""))
            if "retention_until" in rec_text or "security_audit" in obs.get("path", "") or "audit_record" in rid:
                steps.append(step("VERIFICATION", system, rid, "VERIFY_RECORD_PRESENT", "PRESENT", evidence))
                compliant_count += 1
            continue
        verify_op = None
        if state == "ABSENT": verify_op = "VERIFY_RECORD_ABSENT"
        elif state == "REDACTED": verify_op = "VERIFY_RECORD_REDACTED"
        elif state == "ANONYMIZED": verify_op = "VERIFY_RECORD_ANONYMIZED"
        elif state == "DISABLED": verify_op = "VERIFY_DATA_FLOW_DISABLED"
        elif state == "BLOCKED": verify_op = "VERIFY_RESTORE_BLOCKED"
        if verify_op:
            steps.append(step("VERIFICATION", system, rid, verify_op, state, evidence))
            compliant_count += 1

    # If an older record is present but a later explicit lookup proves it absent, use that latest observation.
    # For linked records with state PRESENT, build finding + complete proposed remediation + future verification.
    for rid, system, category, state, evidence, finding_op, remediation_op, target_state in violations:
        steps.append(step("FINDING", system, rid, finding_op, "ACTIVE" if finding_op in {"REPORT_ACTIVE_DATA_FLOW", "REPORT_RESTORE_RISK"} else "PRESENT", evidence))
        steps.append(step("REMEDIATION", system, rid, remediation_op, target_state, ""))
        verify_op = {
            "ABSENT": "VERIFY_RECORD_ABSENT", "REDACTED": "VERIFY_RECORD_REDACTED",
            "ANONYMIZED": "VERIFY_RECORD_ANONYMIZED", "DISABLED": "VERIFY_DATA_FLOW_DISABLED",
            "BLOCKED": "VERIFY_RESTORE_BLOCKED",
        }[target_state]
        steps.append(step("VERIFICATION", system, rid, verify_op, target_state, ""))

    # Ensure a verified account-absence step exists when a snapshot supports it.
    if not any(s["system_id"] == "account_service" and s["operation"] == "VERIFY_RECORD_ABSENT" for s in steps):
        for rid in account_ids:
            obs = selected.get(rid)
            if obs and obs.get("state") == "ABSENT" and obs.get("evidence_id"):
                steps.append(step("VERIFICATION", "account_service", rid, "VERIFY_RECORD_ABSENT", "ABSENT", obs["evidence_id"]))

    steps = order_steps(steps)
    if violations:
        for s in steps:
            if s["phase"] == "VERIFICATION":
                s["evidence_id"] = ""
        steps = order_steps(steps)
        return "INCOMPLETE", steps, {"reason": "evidence_shows_unresolved_resources", "user_id": uid, "linked_resources": len(selected), "violations": len(violations)}
    if steps and all(s["phase"] == "VERIFICATION" and s["evidence_id"] for s in steps):
        # A complete case needs a verified account absence and no unsafe flows or restore permissions.
        has_account_absence = any(s["system_id"] == "account_service" and s["operation"] == "VERIFY_RECORD_ABSENT" for s in steps)
        has_active_flow = any(o["category"] == "DATA_FLOW" and o["state"] == "ACTIVE" for o in selected.values())
        has_restore_risk = any(o["category"] == "BACKUP_ARCHIVE" and o["state"] == "ACTIVE" for o in selected.values())
        if has_account_absence and not has_active_flow and not has_restore_risk:
            return "COMPLETE", steps, {"reason": "all_linked_resources_verified_compliant", "user_id": uid, "linked_resources": len(selected)}
    return "INCOMPLETE", steps, {"reason": "insufficient_cutoff_safe_verification", "user_id": uid, "linked_resources": len(selected)}


def validate_rows(rows: list[dict[str, str]], expected_count: int | None = None) -> list[str]:
    errors = []
    if expected_count is not None and len(rows) != expected_count:
        errors.append(f"Expected {expected_count} rows; found {len(rows)}.")
    seen = set()
    for row in rows:
        cid = row.get("case_id", "")
        if cid in seen: errors.append(f"Duplicate case_id {cid}")
        seen.add(cid)
        if row.get("deletion_status") not in {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}:
            errors.append(f"{cid}: invalid status")
        try: steps = json.loads(row.get("steps_json", ""))
        except Exception: errors.append(f"{cid}: invalid steps_json"); continue
        if not isinstance(steps, list): errors.append(f"{cid}: steps_json is not an array"); continue
        if row["deletion_status"] == "NOT_APPLICABLE" and steps: errors.append(f"{cid}: NOT_APPLICABLE must have []")
        for i, s in enumerate(steps, 1):
            if set(s) != {"step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"}:
                errors.append(f"{cid}: invalid step keys at {i}")
            if s.get("step_no") != i: errors.append(f"{cid}: step numbers must be consecutive")
            if s.get("operation") not in VALID_OPERATIONS: errors.append(f"{cid}: invalid operation {s.get('operation')}")
            if s.get("phase") not in PHASE_ORDER: errors.append(f"{cid}: invalid phase {s.get('phase')}")
    return errors


def run_evaluation(sample_results: list[dict[str, str]] | None = None, observations: list[dict[str, Any]] | None = None, identities: list[dict[str, str]] | None = None, audits: list[dict[str, str]] | None = None, activities: list[dict[str, str]] | None = None) -> dict[str, Any]:
    expected = load_csv("sample_output.csv", required=False)
    if sample_results is None:
        reqs = load_csv("sample_deletion_requests.csv", required=False)
        if reqs:
            identities = identities if identities is not None else load_csv("user_identities.csv")
            audits = audits if audits is not None else load_csv("user_audit_log.csv")
            activities = activities if activities is not None else load_csv("system_activity.csv", required=False)
            if observations is None:
                manifest = load_csv("evidence_files.csv")
                observations = build_observations(manifest)
            obs = observations
            sample_results = []
            for req in reqs:
                status, steps, _ = classify_case(req, identities, audits, obs, activities)
                sample_results.append({"case_id": req["case_id"], "deletion_status": status, "steps_json": json_steps(steps)})
        else:
            sample_results = []
    expmap = {r["case_id"]: r for r in expected}
    gotmap = {r["case_id"]: r for r in sample_results}
    status_matches = sum(cid in gotmap and gotmap[cid]["deletion_status"] == row["deletion_status"] for cid, row in expmap.items())
    exact_step_matches = 0
    step_counts = {"expected": 0, "matched": 0}
    field_counts = {"expected": 0, "matched": 0}
    sequence_matches = 0
    mismatch_rows = []
    for cid, exp in expmap.items():
        got = gotmap.get(cid)
        if not got:
            mismatch_rows.append((cid, exp["deletion_status"], "MISSING", "sample case absent from generated sample evaluation"))
            continue
        try: es, gs = json.loads(exp["steps_json"]), json.loads(got["steps_json"])
        except Exception: es, gs = [], []
        if es == gs: exact_step_matches += 1
        step_counts["expected"] += len(es)
        semantic_keys = ("phase", "system_id", "resource_id", "operation", "state")
        exp_sequence = [tuple(s.get(k) for k in semantic_keys) for s in es]
        got_sequence = [tuple(s.get(k) for k in semantic_keys) for s in gs]
        if exp_sequence == got_sequence:
            sequence_matches += 1
        all_fields = ("phase", "system_id", "resource_id", "operation", "state", "evidence_id")
        for index in range(max(len(es), len(gs))):
            for key in all_fields:
                field_counts["expected"] += 1
                if index < len(es) and index < len(gs) and es[index].get(key) == gs[index].get(key):
                    field_counts["matched"] += 1
        # Step comparison ignores key ordering, but not semantics/evidence IDs.
        es_norm = [tuple((s.get(k) for k in ("phase", "system_id", "resource_id", "operation", "state", "evidence_id"))) for s in es]
        gs_norm = [tuple((s.get(k) for k in ("phase", "system_id", "resource_id", "operation", "state", "evidence_id"))) for s in gs]
        exp_counter, got_counter = Counter(es_norm), Counter(gs_norm)
        step_counts["matched"] += sum((exp_counter & got_counter).values())
        if exp["deletion_status"] != got["deletion_status"] or es_norm != gs_norm:
            mismatch_rows.append((cid, exp["deletion_status"], got["deletion_status"], f"expected_steps={len(es)} generated_steps={len(gs)}"))
    # Small participant-authored sanity checks independent of the public labels.
    custom_cases = []
    nondelete = {"case_id": "custom_non_deletion", "email": "x@example.com", "audit_at": "2026-09-01T00:00:00Z", "request_text": "Please export my data"}
    custom_cases.append({"name": "non-deletion request", "passed": classify_case(nondelete, [], [], [], [])[0] == "NOT_APPLICABLE"})
    fake_obs = {"_values": {"user_150"}, "_emails": set(), "_user_ids": {"user_150"}, "_phone_digits": "", "_raw_norm": "user_150"}
    fake_identity = {"user_ids": ["user_15"], "aliases": {"user_15"}}
    custom_cases.append({"name": "exact identifier boundary (user_15 must not match user_150)", "passed": not exact_identity_match(fake_obs, fake_identity)})
    cutoff = parse_time("2026-09-01T00:00:00Z")
    future_obs = {"resource_id": "account_future", "capture_time": parse_time("2026-09-02T00:00:00Z"), "obs_time": parse_time("2026-09-02T00:00:00Z")}
    custom_cases.append({"name": "evidence after audit_at is excluded", "passed": "account_future" not in latest_by_resource([future_obs], cutoff)})
    return {"sample_count": len(expected), "status_matches": status_matches, "exact_step_matches": exact_step_matches,
            "step_counts": step_counts, "field_counts": field_counts, "sequence_matches": sequence_matches,
            "custom_cases": custom_cases, "mismatches": mismatch_rows, "sample_results": sample_results}


def write_reports(rows: list[dict[str, str]], errors: list[str], evaluation: dict[str, Any], manifest_count: int, obs_count: int) -> None:
    EVAL_DIR.mkdir(parents=True, exist_ok=True)
    dist = Counter(r["deletion_status"] for r in rows)
    ev = ["# Evaluation report", "", "## Full evaluation output", "",
          f"- Requests processed: {len(rows)}", f"- COMPLETE: {dist.get('COMPLETE', 0)}",
          f"- INCOMPLETE: {dist.get('INCOMPLETE', 0)}", f"- NOT_APPLICABLE: {dist.get('NOT_APPLICABLE', 0)}",
          f"- Evidence manifest rows: {manifest_count}", f"- Parsed evidence observations: {obs_count}",
          f"- Structural validation errors: {len(errors)}", "", "## Public sample evaluation", "",
          f"- Sample requests: {evaluation['sample_count']}", f"- Status matches: {evaluation['status_matches']}/{evaluation['sample_count']}",
          f"- Exact step-list matches: {evaluation['exact_step_matches']}/{evaluation['sample_count']}",
          f"- Expected steps: {evaluation['step_counts']['expected']}", f"- Exact semantic steps matched: {evaluation['step_counts']['matched']}",
          f"- Step field accuracy (position-aligned, six semantic fields): {evaluation['field_counts']['matched']}/{evaluation['field_counts']['expected']} ({(100*evaluation['field_counts']['matched']/evaluation['field_counts']['expected'] if evaluation['field_counts']['expected'] else 0):.1f}%)",
          f"- Sequence accuracy (phase/system/resource/operation/state in order): {evaluation['sequence_matches']}/{evaluation['sample_count']}", "",
          "Sample answers are used only for evaluation; they are not copied into the hidden output.", "",
          "## Additional sanity cases", ""]
    ev += [f"- {'PASS' if case['passed'] else 'FAIL'}: {case['name']}" for case in evaluation['custom_cases']]
    ev += ["", "## First sample mismatches", ""]
    ev += [f"- {cid}: expected {exp}; generated {got}; {detail}" for cid, exp, got, detail in evaluation["mismatches"][:40]] or ["- None"]
    ev += ["", "## Structural validation errors", ""] + ([f"- {x}" for x in errors] if errors else ["- None"])
    ev += ["", "## Failures found and improvements made", "",
           "- Added parsing of JSON Lines observability logs and grouped records by trace ID so subject identifiers and resource readbacks can be associated within one trace.",
           "- Resource-category classification now prioritizes explicit resource namespaces; connector names containing words such as analytics no longer override a data_flow resource ID.",
           "- Contact-index lookups are classified as secondary identifiers requiring deletion, and explicit support PII-scan hits are treated as evidence of exposed identifiers.",
           "- Remaining failures include resources whose identifiers were anonymized or absent from identity-bearing evidence, incomplete cross-file linkage, and resource IDs that cannot safely be inferred from a stable user ID.",
           "", "## Limitations", "", "- This is a deterministic evidence parser; no LLM/API calls are made.",
           "- SQL snapshots are read with SQLite, JSON records are recursively parsed, logs/text are parsed line-by-line, PDFs use text extraction, and images use OCR when available.",
           "- Resource absence is not inferred merely from no matching line; absence verification is emitted only when a cutoff-safe snapshot/readback supports it.",
           "- Review the public sample comparison before submission; passing structural validation does not guarantee semantic accuracy."]
    (EVAL_DIR / "evaluation_report.md").write_text("\n".join(ev) + "\n", encoding="utf-8")
    usage = """# Usage report

- Provider: none (local deterministic Python)
- Model: none
- Model/API calls: 0
- Input tokens: 0
- Output tokens: 0
- Total tokens: 0
- Average tokens per request: 0
- Estimated model/API cost: 0

The program does not call an external model/API. Token and model cost counts are therefore zero; this does not measure local CPU time or electricity usage.
"""
    (EVAL_DIR / "usage_report.md").write_text(usage, encoding="utf-8")


def main() -> int:
    try:
        requests = load_csv("deletion_requests.csv")
        identities = load_csv("user_identities.csv")
        audits = load_csv("user_audit_log.csv")
        manifest = load_csv("evidence_files.csv")
        activities = load_csv("system_activity.csv", required=False)
        # Load the rules file as part of the challenge's required input bundle.
        rules = load_csv("deletion_rules.csv")
    except (FileNotFoundError, OSError, csv.Error) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    if not requests:
        print("ERROR: deletion_requests.csv is empty", file=sys.stderr)
        return 2
    print("Parsing evidence files (PDF/image extraction may take a little while)...")
    observations = build_observations(manifest)
    rows = []
    diagnostics = []
    for req in requests:
        status, steps, diag = classify_case(req, identities, audits, observations, activities)
        rows.append({"case_id": req.get("case_id", ""), "deletion_status": status, "steps_json": json_steps(steps)})
        diagnostics.append({"case_id": req.get("case_id", ""), **diag})
    rows.sort(key=lambda r: r["case_id"])
    with OUT.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=OUTPUT_FIELDS, lineterminator="\n")
        writer.writeheader(); writer.writerows(rows)
    errors = validate_rows(rows, expected_count=len(requests))
    evaluation = run_evaluation(observations=observations, identities=identities, audits=audits, activities=activities)
    write_reports(rows, errors, evaluation, len(manifest), len(observations))
    dist = Counter(r["deletion_status"] for r in rows)
    print(f"Processed hidden requests: {len(rows)}")
    print("Hidden status counts:", dict(sorted(dist.items())))
    print(f"Public sample status accuracy: {evaluation['status_matches']}/{evaluation['sample_count']}")
    print(f"Public sample exact step matches: {evaluation['exact_step_matches']}/{evaluation['sample_count']}")
    print(f"Output: {OUT}")
    print(f"Evaluation report: {EVAL_DIR / 'evaluation_report.md'}")
    print(f"Usage report: {EVAL_DIR / 'usage_report.md'}")
    print(f"Structural validation errors: {len(errors)}")
    if errors:
        for e in errors[:20]: print("VALIDATION ERROR:", e)
        return 1
    print("Structural validation passed. Review the sample accuracy in evaluation_report.md before submission.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
