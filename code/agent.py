#!/usr/bin/env python3
"""Bounded tool-using AI investigator for Ghost Data Still Exists.

This is an optional LLM investigation layer. The deterministic main.py remains the
final policy/output validator. No changes are made to source data or output.csv.

Usage:
  set OPENAI_API_KEY=...              # PowerShell: $env:OPENAI_API_KEY="..."
  python code/agent.py --case case_33
  python code/agent.py --case case_33 --model gpt-4.1-mini

The agent can only inspect participant-facing data and is limited to a small number
of tool calls. It must respect each case's audit_at cutoff and must not invent IDs.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from collections import defaultdict
from pathlib import Path
from typing import Any

import main as core

ROOT = core.ROOT
DATA = core.DATA
DEFAULT_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:3b")
OPENAI_DEFAULT_MODEL = os.getenv("OPENAI_MODEL", "gpt-4.1-mini")
DEFAULT_OLLAMA_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
MAX_TOOL_CALLS = 8

INSTRUCTIONS = """You are an evidence-investigation agent for a deletion audit challenge.
Your task is to investigate one deletion request using only the tools provided.

Safety and correctness rules:
- Treat reported workflow statuses and activity results as claims, not proof.
- Respect audit_at: evidence captured or observed after the cutoff is not admissible.
- Use exact identity relationships; never infer an account/resource ID from a case or user number.
- Apply the supplied policy. Security audit logs and legal holds may require retention;
  backups may require restore blocking; tombstones may retain stable user IDs but not direct PII.
- Separate observed facts from hypotheses. Cite evidence IDs returned by tools.
- Do not claim a deletion is complete unless all relevant resources and recreation paths
  are covered by cutoff-safe evidence. If evidence is insufficient, say so explicitly.
- Do not propose executing destructive actions. Only recommend a plan for human review.
- Use tools before reaching conclusions. Search for both remaining copies and active
  data flows/restore risks; investigate historical identifiers when available.

Return a concise, structured investigation summary with: request_scope, resolved_identity,
confirmed_findings (each with evidence IDs), policy_assessment, remediation_plan,
verification_plan, unresolved_questions, and confidence (low/medium/high). Do not output
or modify the challenge CSV directly."""


def _read_csv(name: str) -> list[dict[str, str]]:
    return core.load_csv(name, required=False)


class InvestigationTools:
    def __init__(self) -> None:
        self.requests = _read_csv("deletion_requests.csv")
        self.identities = _read_csv("user_identities.csv")
        self.audits = _read_csv("user_audit_log.csv")
        self.activities = _read_csv("system_activity.csv")
        self.rules = _read_csv("deletion_rules.csv")
        self.manifest = _read_csv("evidence_files.csv")
        self._request_by_id = {r.get("case_id", ""): r for r in self.requests}
        self._manifest_by_id = {m.get("file_id", ""): m for m in self.manifest}
        self._observations: list[dict[str, Any]] | None = None
        self.calls = 0

    def observations(self) -> list[dict[str, Any]]:
        if self._observations is None:
            self._observations = core.build_observations(self.manifest)
        return self._observations

    def cutoff_request(self, case_id: str) -> tuple[dict[str, str], Any]:
        req = self._request_by_id.get(case_id)
        if not req:
            raise ValueError(f"Unknown case_id: {case_id}")
        cutoff = core.parse_time(req.get("audit_at"))
        if cutoff is None:
            raise ValueError(f"Case {case_id} has an invalid audit_at")
        return req, cutoff

    def context(self, case_id: str) -> dict[str, Any]:
        req, cutoff = self.cutoff_request(case_id)
        identity = core.resolve_identity(req, self.identities, self.audits, cutoff)
        return {
            "request": {k: req.get(k, "") for k in (
                "case_id", "email", "requested_at", "reported_status", "reported_at", "audit_at", "request_text"
            )},
            "identity_resolution": {
                "user_ids": identity.get("user_ids", []),
                "ambiguous": identity.get("ambiguous", True),
                "alias_count": len(identity.get("aliases", [])),
            },
            "cutoff_rule": "Exclude evidence with capture/observation timestamps after audit_at.",
        }

    def search_evidence(self, case_id: str, query: str, limit: int = 8) -> dict[str, Any]:
        req, cutoff = self.cutoff_request(case_id)
        identity = core.resolve_identity(req, self.identities, self.audits, cutoff)
        terms = [core.norm(t) for t in query.split() if len(core.norm(t)) >= 3]
        aliases = set(identity.get("aliases", set()))
        aliases |= set(identity.get("user_ids", []))
        found: list[tuple[int, dict[str, Any]]] = []
        for obs in self.observations():
            cap, obs_time = obs.get("capture_time"), obs.get("obs_time")
            if cap and cap > cutoff or obs_time and obs_time > cutoff:
                continue
            raw = str(obs.get("raw", ""))
            rec = json.dumps(obs.get("record", {}), ensure_ascii=False, default=str)
            haystack = core.norm(" ".join(str(obs.get(k, "")) for k in (
                "resource_id", "system_id", "category", "state", "path", "evidence_id"
            )) + " " + raw + " " + rec)
            # Identifier-like query terms must match as complete tokens. Plain substring
            # matching made user_18 accidentally match user_181, which is unsafe.
            score = 0
            for term in terms:
                identifier_like = ("@" in term or "_" in term or len(term) >= 32 or term.startswith("+"))
                if (re_exact(term, haystack) if identifier_like else term in haystack):
                    score += 1
            # Boost exact subject aliases only; never use substring matching for IDs/emails.
            if any(a and (core.norm(a) in {core.norm(obs.get("resource_id")), core.norm(obs.get("user_id"))} or
                          re_exact(core.norm(a), haystack)) for a in aliases):
                score += 5
            if score:
                found.append((score, obs))
        found.sort(key=lambda pair: (-pair[0], str(pair[1].get("evidence_id", "")), str(pair[1].get("resource_id", ""))))
        results = []
        for score, obs in found[:max(1, min(int(limit), 12))]:
            results.append({
                "relevance": score,
                "evidence_id": obs.get("evidence_id", ""),
                "captured_at": obs.get("capture_time").isoformat() if obs.get("capture_time") else None,
                "observed_at": obs.get("obs_time").isoformat() if obs.get("obs_time") else None,
                "system_id": obs.get("system_id", "unknown_system"),
                "resource_id": obs.get("resource_id", "unknown_resource"),
                "category": obs.get("category", "UNKNOWN"),
                "state": obs.get("state", "UNKNOWN"),
                "path": obs.get("path", ""),
                "record": trim_record(obs.get("record", {})),
                "excerpt": str(obs.get("raw", ""))[:700],
            })
        return {"case_id": case_id, "query": query, "cutoff": cutoff.isoformat(), "results": results}

    def search_activity(self, case_id: str, query: str, limit: int = 10) -> dict[str, Any]:
        req, cutoff = self.cutoff_request(case_id)
        identity = core.resolve_identity(req, self.identities, self.audits, cutoff)
        terms = [core.norm(t) for t in query.split() if len(core.norm(t)) >= 3]
        aliases = set(identity.get("aliases", set())) | set(identity.get("user_ids", []))
        found = []
        for a in self.activities:
            at = core.parse_time(a.get("event_time"))
            if at is None or at > cutoff:
                continue
            text = core.norm(" ".join(a.get(k, "") for k in a))
            score = 0
            for term in terms:
                identifier_like = ("@" in term or "_" in term or len(term) >= 32 or term.startswith("+"))
                if (re_exact(term, text) if identifier_like else term in text):
                    score += 1
            resource = core.norm(a.get("resource_id"))
            if any(alias and (alias == resource or re_exact(alias, text)) for alias in aliases):
                score += 5
            if score:
                found.append((score, at, a))
        found.sort(key=lambda x: (-x[0], x[1]), reverse=False)
        return {"case_id": case_id, "query": query, "cutoff": cutoff.isoformat(), "results": [
            {**a, "relevance": score} for score, _, a in found[:max(1, min(int(limit), 15))]
        ]}

    def identity_history(self, case_id: str) -> dict[str, Any]:
        req, cutoff = self.cutoff_request(case_id)
        resolved = core.resolve_identity(req, self.identities, self.audits, cutoff)
        ids = set(resolved.get("user_ids", []))
        audit_rows = []
        for row in self.audits:
            at = core.parse_time(row.get("event_time"))
            if row.get("user_id") in ids and at and at <= cutoff:
                audit_rows.append(row)
        current = [r for r in self.identities if r.get("user_id") in ids]
        return {"case_id": case_id, "user_ids": sorted(ids), "ambiguous": resolved.get("ambiguous", True),
                "current_identity_rows": current, "historical_changes": audit_rows[:100]}

    def get_policy(self, category: str) -> dict[str, Any]:
        rows = [r for r in self.rules if core.norm(r.get("data_category")) == core.norm(category)]
        return {"category": category, "rules": rows, "found": bool(rows)}

    def dispatch(self, name: str, args: dict[str, Any], case_id: str) -> dict[str, Any]:
        self.calls += 1
        if self.calls > MAX_TOOL_CALLS:
            raise RuntimeError("Tool-call budget exceeded")
        if name == "get_case_context":
            return self.context(case_id)
        if name == "search_evidence":
            return self.search_evidence(case_id, str(args.get("query", "")), int(args.get("limit", 8)))
        if name == "search_activity":
            return self.search_activity(case_id, str(args.get("query", "")), int(args.get("limit", 10)))
        if name == "get_identity_history":
            return self.identity_history(case_id)
        if name == "get_policy":
            return self.get_policy(str(args.get("category", "")))
        raise ValueError(f"Tool not allowed: {name}")


def re_exact(alias: str, text: str) -> bool:
    """Check identity strings as tokens, not arbitrary substrings."""
    if not alias:
        return False
    import re
    return bool(re.search(r"(?<![A-Za-z0-9@._+-])" + re.escape(alias) + r"(?![A-Za-z0-9@._+-])", text))


def trim_record(record: Any) -> Any:
    if not isinstance(record, dict):
        return str(record)[:900]
    out = {}
    for key, value in record.items():
        if str(key).startswith("_"):
            continue
        if isinstance(value, (str, int, float, bool)) or value is None:
            out[str(key)] = str(value)[:300] if isinstance(value, str) else value
        else:
            out[str(key)] = str(value)[:300]
    return out


def tool_schemas() -> list[dict[str, Any]]:
    return [
        {"type": "function", "name": "get_case_context", "description": "Get one request and cutoff-safe identity resolution summary.", "parameters": {"type": "object", "properties": {}, "additionalProperties": False}},
        {"type": "function", "name": "search_evidence", "description": "Search parsed evidence observations, excluding evidence after audit_at. Query with resource IDs, emails, user IDs, or concepts such as analytics, support, replica, restore, anonymized.", "parameters": {"type": "object", "properties": {"query": {"type": "string"}, "limit": {"type": "integer", "minimum": 1, "maximum": 12}}, "required": ["query"], "additionalProperties": False}},
        {"type": "function", "name": "search_activity", "description": "Search activity events at or before audit_at. Activity results are claims, not proof of resulting state.", "parameters": {"type": "object", "properties": {"query": {"type": "string"}, "limit": {"type": "integer", "minimum": 1, "maximum": 15}}, "required": ["query"], "additionalProperties": False}},
        {"type": "function", "name": "get_identity_history", "description": "Get exact resolved user IDs and historical identity changes by audit_at.", "parameters": {"type": "object", "properties": {}, "additionalProperties": False}},
        {"type": "function", "name": "get_policy", "description": "Retrieve the supplied deletion policy for a data category.", "parameters": {"type": "object", "properties": {"category": {"type": "string"}}, "required": ["category"], "additionalProperties": False}},
    ]


def call_responses_api(api_key: str, payload: dict[str, Any]) -> dict[str, Any]:
    req = urllib.request.Request(
        "https://api.openai.com/v1/responses",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=90) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")[:2000]
        raise RuntimeError(f"OpenAI API returned HTTP {exc.code}: {body}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Could not reach OpenAI API: {exc.reason}") from exc


def run_openai_agent(case_id: str, model: str, dry_run: bool = False) -> int:
    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    tools = InvestigationTools()
    # Validate the case locally before any model call.
    try:
        initial = tools.context(case_id)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    if dry_run:
        req = initial["request"]
        user_ids = initial["identity_resolution"].get("user_ids", [])
        search_query = " ".join([req.get("email", ""), *user_ids])
        evidence = tools.search_evidence(case_id, search_query, limit=5)
        activity = tools.search_activity(case_id, search_query, limit=5)
        print(json.dumps({"mode": "dry-run-no-model-calls", "context": initial,
                          "matching_evidence_count_returned": len(evidence["results"]),
                          "matching_activity_count_returned": len(activity["results"]),
                          "evidence_preview": evidence["results"][:2],
                          "activity_preview": activity["results"][:2]}, indent=2, ensure_ascii=False, default=str))
        return 0
    if not api_key:
        print("OPENAI_API_KEY is not set. Set it in this PowerShell session before running the AI agent.", file=sys.stderr)
        return 2
    user_input = [{"role": "user", "content": f"Investigate deletion request {case_id}. Start with get_case_context, then search evidence and activity based on the resolved identity and policy categories. Request context: {json.dumps(initial, ensure_ascii=False)}"}]
    payload: dict[str, Any] = {
        "model": model,
        "instructions": INSTRUCTIONS,
        "input": user_input,
        "tools": tool_schemas(),
        "tool_choice": "auto",
        "max_output_tokens": 2200,
    }
    total_input_tokens = 0
    total_output_tokens = 0
    response = call_responses_api(api_key, payload)
    rounds = 0
    while True:
        rounds += 1
        if rounds > MAX_TOOL_CALLS + 2:
            print("Agent stopped safely: maximum tool-call rounds reached.", file=sys.stderr)
            return 1
        usage = response.get("usage", {})
        total_input_tokens += int(usage.get("input_tokens", 0) or 0)
        total_output_tokens += int(usage.get("output_tokens", 0) or 0)
        calls = [item for item in response.get("output", []) if item.get("type") == "function_call"]
        if not calls:
            output_text = response.get("output_text")
            if not output_text:
                for item in response.get("output", []):
                    if item.get("type") == "message":
                        for content in item.get("content", []):
                            if content.get("type") == "output_text":
                                output_text = content.get("text", "")
            print(output_text or "Agent returned no text output.")
            print("\n--- RUN METADATA ---")
            print(json.dumps({"case_id": case_id, "model": model, "tool_calls": tools.calls,
                              "input_tokens": total_input_tokens, "output_tokens": total_output_tokens,
                              "total_tokens": total_input_tokens + total_output_tokens}, indent=2))
            return 0
        tool_outputs = []
        for call in calls:
            try:
                args = json.loads(call.get("arguments") or "{}")
                result = tools.dispatch(str(call.get("name", "")), args, case_id)
                rendered = json.dumps(result, ensure_ascii=False, default=str)
            except Exception as exc:
                rendered = json.dumps({"error": str(exc)})
            tool_outputs.append({"type": "function_call_output", "call_id": call.get("call_id", ""), "output": rendered})
        payload = {
            "model": model,
            "instructions": INSTRUCTIONS,
            "previous_response_id": response.get("id"),
            "input": tool_outputs,
            "tools": tool_schemas(),
            "tool_choice": "auto",
            "max_output_tokens": 2200,
        }
        response = call_responses_api(api_key, payload)



def build_initial_investigation_bundle(tools: InvestigationTools, case_id: str) -> dict[str, Any]:
    """Run a focused deterministic evidence sweep before asking the LLM to reason.

    Resolve identity, follow identity-linked activity to resource IDs, and retrieve
    evidence for both current and historical aliases. Keep unrelated global events out
    of the LLM context so a small local model can reason over relevant records.
    """
    req, cutoff = tools.cutoff_request(case_id)
    identity = core.resolve_identity(req, tools.identities, tools.audits, cutoff)
    user_ids = sorted(identity.get("user_ids", []))
    aliases = sorted(a for a in identity.get("aliases", set()) if a)
    # Search with atomic identifiers only. Splitting a full name such as "Ingrid Dahl"
    # into words makes common surnames match unrelated people.
    searchable_aliases = [a for a in aliases if "@" in a or len(a) >= 32 or (" " not in a and a not in user_ids)]
    context = tools.context(case_id)
    identity_history = tools.identity_history(case_id)
    identity_query = " ".join([req.get("email", ""), *user_ids, *searchable_aliases])

    def references_identity(item: dict[str, Any]) -> bool:
        searchable = core.norm(" ".join(str(v) for v in item.values()))
        return any(re_exact(core.norm(alias), searchable) for alias in aliases if alias) or \
               any(re_exact(core.norm(uid), searchable) for uid in user_ids)

    activity_by_key: dict[str, dict[str, Any]] = {}
    # Search identity aliases first; only retain records explicitly tied to the subject.
    for item in tools.search_activity(case_id, identity_query, limit=15)["results"]:
        if references_identity(item):
            activity_by_key.setdefault(str(item.get("activity_id", "")), item)

    linked_resource_ids: list[str] = []
    for item in activity_by_key.values():
        resource_id = str(item.get("resource_id", "")).strip()
        if resource_id:
            linked_resource_ids.append(resource_id)
    linked_resource_ids = list(dict.fromkeys(linked_resource_ids))[:12]

    evidence_by_key: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for query in [identity_query, *linked_resource_ids]:
        if not query.strip():
            continue
        for item in tools.search_evidence(case_id, query, limit=8)["results"]:
            key = (str(item.get("evidence_id", "")), str(item.get("resource_id", "")),
                   str(item.get("state", "")), str(item.get("excerpt", "")))
            evidence_by_key.setdefault(key, item)

    # Search the activity stream for exact resource IDs found in evidence AND every
    # identity-linked resource. This matters when a catalog links a resource to the
    # subject but no evidence snapshot currently mentions that resource (for example,
    # export_1842). Without this pass, the agent sees the link event but misses other
    # cutoff-safe lifecycle events for that resource.
    resource_ids_to_trace = list(linked_resource_ids)
    for item in evidence_by_key.values():
        resource_id = str(item.get("resource_id", "")).strip()
        if resource_id and resource_id not in resource_ids_to_trace:
            resource_ids_to_trace.append(resource_id)

    resource_activity: dict[str, list[dict[str, Any]]] = {}
    for resource_id in resource_ids_to_trace:
        matched_events = []
        for event in tools.search_activity(case_id, resource_id, limit=10)["results"]:
            event_text = core.norm(" ".join(str(v) for v in event.values()))
            if re_exact(core.norm(resource_id), event_text):
                activity_by_key.setdefault(str(event.get("activity_id", "")), event)
                matched_events.append(event)
        resource_activity[resource_id] = matched_events

    evidence = list(evidence_by_key.values())[:18]
    activity = list(activity_by_key.values())[:30]
    evidence_coverage = {}
    for resource_id in resource_ids_to_trace:
        resource_evidence = [item for item in evidence if core.norm(item.get("resource_id", "")) == core.norm(resource_id)]
        evidence_coverage[resource_id] = {
            "evidence_ids": list(dict.fromkeys(str(item.get("evidence_id", "")) for item in resource_evidence if item.get("evidence_id"))),
            "states_observed": list(dict.fromkeys(str(item.get("state", "UNKNOWN")) for item in resource_evidence)),
            "cutoff_safe_activity_ids": list(dict.fromkeys(str(item.get("activity_id", "")) for item in resource_activity.get(resource_id, []) if item.get("activity_id"))),
            "state_evidence_found": bool(resource_evidence),
            "note": "No matching evidence observation was found for this resource at or before audit_at." if not resource_evidence else "Evidence observations found; interpret their state and timestamps carefully.",
        }
    for item in evidence:
        item["excerpt"] = str(item.get("excerpt", ""))[:420]
    return {
        "case_context": context,
        "identity_history": {
            "user_ids": identity_history.get("user_ids", []),
            "ambiguous": identity_history.get("ambiguous", True),
            "current_identity_rows": identity_history.get("current_identity_rows", [])[:8],
            "historical_changes": identity_history.get("historical_changes", [])[:12],
        },
        "policy_rules": tools.rules,
        "identity_linked_resource_ids": linked_resource_ids,
        "evidence_results": evidence,
        "activity_results": activity,
        "resource_evidence_coverage": evidence_coverage,
        "cutoff": req.get("audit_at", ""),
        "evidence_result_count": len(evidence),
        "activity_result_count": len(activity),
        "instructions": "Treat reported statuses/activity as claims. Use only evidence at or before cutoff. Cite exact evidence_id/activity_id. An activity link identifies a resource to investigate; it is not proof that the resource was deleted or remains present. If a linked resource has no cutoff-safe state evidence, explicitly leave its state unresolved and do not claim the overall deletion is verified complete. A plan to delete is not proof of deletion. Do not claim no secondary identifiers, copies, data flows, or restore risks exist unless the returned evidence supports that negative claim.",
    }


def ollama_tool_schemas() -> list[dict[str, Any]]:
    """Convert the local function definitions to Ollama's /api/chat schema."""
    result = []
    for item in tool_schemas():
        result.append({"type": "function", "function": {
            "name": item["name"],
            "description": item["description"],
            "parameters": item["parameters"],
        }})
    return result


def call_ollama_chat(base_url: str, payload: dict[str, Any]) -> dict[str, Any]:
    url = base_url.rstrip("/") + "/api/chat"
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=180) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")[:2000]
        raise RuntimeError(f"Ollama returned HTTP {exc.code}: {body}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(
            f"Could not reach Ollama at {base_url}. Start Ollama and check `ollama list`. Details: {exc.reason}"
        ) from exc


def run_ollama_agent(case_id: str, model: str, dry_run: bool = False,
                     base_url: str = DEFAULT_OLLAMA_URL) -> int:
    tools = InvestigationTools()
    try:
        initial = tools.context(case_id)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    if dry_run:
        bundle = build_initial_investigation_bundle(tools, case_id)
        print(json.dumps({"mode": "dry-run-no-model-calls", "provider": "ollama", "context": initial,
                          "matching_evidence_count_returned": bundle["evidence_result_count"],
                          "matching_activity_count_returned": bundle["activity_result_count"],
                          "identity_linked_resource_ids": bundle["identity_linked_resource_ids"],
                          "resource_evidence_coverage": bundle["resource_evidence_coverage"],
                          "evidence_preview": bundle["evidence_results"][:5],
                          "activity_preview": bundle["activity_results"][:8]}, indent=2, ensure_ascii=False, default=str))
        return 0

    # Pre-fetch cutoff-safe context and evidence because compact local models may
    # otherwise call only get_case_context and then guess from the request text.
    bundle = build_initial_investigation_bundle(tools, case_id)
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": INSTRUCTIONS + "\nYou are running locally with Qwen. The user message includes a deterministic evidence bundle already retrieved through cutoff-aware tools. Analyze those records before concluding. Cite evidence IDs exactly as provided. If you need a missing detail, call a focused tool. Do not use generic next steps when a concrete resource is visible."},
        {"role": "user", "content": (
            f"Investigate deletion request {case_id}. First analyze this pre-fetched, cutoff-safe investigation bundle, "
            f"then use additional tools if necessary. Return strict JSON with keys: case_id, request_scope, resolved_identity, "
            f"findings (each with finding, evidence_ids, and significance), recommended_status, recommended_steps, "
            f"unresolved_questions, and confidence. Use recommended_status INCOMPLETE when material linked resources "
            f"have no cutoff-safe state evidence or deletion is not verified. Do not say the investigation is complete "
            f"while unresolved_questions remain. Never assert absence of copies/data flows/restore risks without evidence. "
            f"Evidence bundle: {json.dumps(bundle, ensure_ascii=False, default=str)}"
        )},
    ]
    # The Python orchestrator has already called the evidence tools deterministically.
    # For small local models, asking the LLM to repeatedly choose tools creates long,
    # expensive loops and can lead to unsupported conclusions. Use one bounded reasoning
    # call over the evidence bundle, then apply a conservative local safety gate.
    compact_bundle = {
        "case_context": bundle["case_context"],
        "identity_history": bundle["identity_history"],
        "identity_linked_resource_ids": bundle["identity_linked_resource_ids"],
        "resource_evidence_coverage": bundle["resource_evidence_coverage"],
        "evidence_results": bundle["evidence_results"][:12],
        "activity_results": bundle["activity_results"][:20],
        "policy_rules": bundle["policy_rules"],
        "cutoff": bundle["cutoff"],
        "instructions": bundle["instructions"],
    }
    prompt = (
        f"Investigate deletion request {case_id} using ONLY this deterministic evidence bundle. "
        "Return a JSON object with keys: case_id, request_scope, resolved_identity, findings, "
        "evidence_ids, recommended_status, recommended_steps, unresolved_questions, confidence. "
        "findings must be an array of objects with finding, evidence_ids, significance. "
        "Use only exact evidence_id/activity_id values from the bundle. An identity-link activity "
        "proves linkage only; it does NOT prove deletion or policy applicability. A plan is not proof "
        "of execution. Do not claim that copies, backups, data flows, secondary identifiers, or restore "
        "risks do not exist unless the evidence explicitly establishes that. If any identity-linked "
        "resource has no cutoff-safe state evidence, or the evidence shows it PRESENT without later "
        "cutoff-safe deletion proof, recommend INCOMPLETE and list the gap. Never claim verified "
        "completion when deletion is not directly evidenced. Respect audit_at exactly. "
        "Keep the answer concise; do not include markdown fences.\n\n"
        "EVIDENCE BUNDLE:\n" + json.dumps(compact_bundle, ensure_ascii=False, default=str)
    )
    response = call_ollama_chat(base_url, {
        "model": model,
        "messages": [
            {"role": "system", "content": INSTRUCTIONS + "\nYou are a careful audit investigator. Never invent evidence."},
            {"role": "user", "content": prompt},
        ],
        "format": "json",
        "stream": False,
        "options": {"temperature": 0.1, "num_ctx": 8192, "num_predict": 700},
    })
    total_prompt_tokens = int(response.get("prompt_eval_count", 0) or 0)
    total_completion_tokens = int(response.get("eval_count", 0) or 0)
    message = response.get("message") or {}
    content = str(message.get("content") or "").strip()
    if not content:
        print("Agent failed safely: Ollama returned an empty response.", file=sys.stderr)
        return 1

    # Validate and conservatively gate claims before displaying the recommendation.
    try:
        result = json.loads(content)
        if not isinstance(result, dict):
            raise ValueError("model response is not a JSON object")
    except (json.JSONDecodeError, ValueError) as exc:
        print(f"Agent failed safely: model response was not valid JSON ({exc}).", file=sys.stderr)
        print(content[:4000])
        return 1

    coverage = bundle.get("resource_evidence_coverage", {})
    unresolved_resources = []
    # Gate only resources explicitly linked to the resolved identity. A screenshot can
    # contain unrelated rows (for example, another customer's export) that should not
    # be treated as in-scope resources merely because OCR found them in the same image.
    for resource_id in bundle.get("identity_linked_resource_ids", []):
        info = coverage.get(resource_id, {})
        states = {str(state).upper() for state in info.get("states_observed", [])}
        has_deletion_state = any(any(marker in state for marker in ("DELETED", "PURGED", "ERASED", "REMOVED")) for state in states)
        has_present_state = any("PRESENT" in state or "READY" in state or "ACTIVE" in state for state in states)
        if not info.get("state_evidence_found") or has_present_state and not has_deletion_state:
            unresolved_resources.append(resource_id)

    if unresolved_resources and str(result.get("recommended_status", "")).upper() == "COMPLETE":
        result["recommended_status"] = "INCOMPLETE"
    if unresolved_resources:
        existing_questions = result.get("unresolved_questions", [])
        if not isinstance(existing_questions, list):
            existing_questions = [str(existing_questions)]
        for resource_id in unresolved_resources:
            question = f"No cutoff-safe deletion proof for identity-linked resource {resource_id}."
            if question not in existing_questions:
                existing_questions.append(question)
        result["unresolved_questions"] = existing_questions
        result["confidence"] = "low" if not result.get("confidence") else result["confidence"]

    # Attach deterministic coverage so reviewers can see why a status was gated.
    result["safety_validation"] = {
        "unresolved_resource_ids": unresolved_resources,
        "rule": "A linked resource without cutoff-safe state evidence, or with PRESENT/READY/ACTIVE state and no deletion-state evidence, cannot support a verified COMPLETE recommendation.",
    }
    print(json.dumps(result, indent=2, ensure_ascii=False))
    print("\n--- RUN METADATA ---")
    print(json.dumps({
        "provider": "ollama", "base_url": base_url, "case_id": case_id,
        "model": model, "agent_mode": "deterministic-tool-prefetch-plus-single-pass-LLM-review",
        "tool_calls": tools.calls,
        "preflight_evidence_records": bundle["evidence_result_count"],
        "preflight_activity_records": bundle["activity_result_count"],
        "prompt_tokens_reported_by_ollama": total_prompt_tokens,
        "completion_tokens_reported_by_ollama": total_completion_tokens,
        "total_tokens_reported_by_ollama": total_prompt_tokens + total_completion_tokens,
        "empty_response_recovery_attempted": False,
    }, indent=2))
    return 0


def run_agent(case_id: str, model: str | None = None, dry_run: bool = False,
              provider: str = "ollama", base_url: str = DEFAULT_OLLAMA_URL) -> int:
    if provider == "ollama":
        return run_ollama_agent(case_id, model or DEFAULT_MODEL, dry_run, base_url)
    if provider == "openai":
        openai_model = model or OPENAI_DEFAULT_MODEL
        return run_openai_agent(case_id, openai_model, dry_run)
    print(f"Unsupported provider: {provider}", file=sys.stderr)
    return 2


def main() -> int:
    parser = argparse.ArgumentParser(description="Investigate one deletion request using local Ollama or OpenAI.")
    parser.add_argument("--case", required=True, help="case ID, e.g. case_33")
    parser.add_argument("--provider", choices=("ollama", "openai"), default="ollama",
                        help="LLM provider (default: ollama; no API key needed for Ollama)")
    parser.add_argument("--model", default=None, help="Model name; defaults to qwen2.5:3b for Ollama")
    parser.add_argument("--base-url", default=DEFAULT_OLLAMA_URL, help="Ollama URL (default: http://localhost:11434)")
    parser.add_argument("--dry-run", action="store_true", help="Validate local tools without calling a model")
    args = parser.parse_args()
    try:
        return run_agent(args.case, args.model, args.dry_run, args.provider, args.base_url)
    except (RuntimeError, OSError, json.JSONDecodeError) as exc:
        print(f"Agent failed safely: {exc}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
