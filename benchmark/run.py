"""PromptGuard benchmark runner.

Runs attacks.jsonl, benign.jsonl and tool_calls.jsonl against the gateway
in-process using FastAPI TestClient (no HTTP server needed). A temporary
SQLite database is used so the real promptguard.db is never polluted.

No detection logic, rules.yaml or any existing code is modified.
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# 1. Parse arguments FIRST. Environment variables must be set before
#    importing gateway because gateway reads DATABASE_PATH at import time
#    and calls load_dotenv() (which won't override already-set keys).
# ---------------------------------------------------------------------------

parser = argparse.ArgumentParser(description="PromptGuard benchmark runner")
parser.add_argument(
    "--mode",
    choices=["none", "rules", "full"],
    required=True,
    help="none = allow everything (baseline), rules = Layer 1 only, "
    "full = real pipeline (requires NEBIUS_API_KEY)",
)
parser.add_argument(
    "--max-llm-calls",
    type=int,
    default=150,
    help="Maximum LLM calls in full mode (default: 150). Stops calling "
    "models after this many calls and reports skipped samples.",
)
parser.add_argument(
    "--show-failures",
    action="store_true",
    help="Print every missed attack, false positive, and wrong tool-call "
    "decision with details.",
)
args = parser.parse_args()

# ---------------------------------------------------------------------------
# 2. Configure a throw-away SQLite database so promptguard.db is untouched.
# ---------------------------------------------------------------------------

_tmpdir = tempfile.mkdtemp(prefix="promptguard_bench_")
_db_path = str(Path(_tmpdir) / "promptguard.db")
os.environ["PROMPTGUARD_DB"] = _db_path

if args.mode == "none":
    os.environ["PROMPTGUARD_ENABLED"] = "0"
elif args.mode == "rules":
    os.environ["PROMPTGUARD_ENABLED"] = "1"
    os.environ["NEBIUS_API_KEY"] = ""
    os.environ["GROQ_API_KEY"] = ""
elif args.mode == "full":
    os.environ["PROMPTGUARD_ENABLED"] = "1"
    if not os.environ.get("NEBIUS_API_KEY", "").strip():
        print("full mode skipped: no API key")
        sys.exit(0)

# ---------------------------------------------------------------------------
# 3. Import the app AFTER env vars are set.
#    Add the project root to sys.path so `gateway` is importable.
# ---------------------------------------------------------------------------

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient  # noqa: E402

import gateway  # noqa: E402

client = TestClient(gateway.app)

# Ensure the database tables exist (startup event may not fire with TestClient).
gateway.initialize_database()

# ---------------------------------------------------------------------------
# 4. LLM call budget. gateway imported ask_json directly from llm, so we
#    patch gateway.ask_json (the reference actually used by sentinel_check
#    and check_tool_intent).
# ---------------------------------------------------------------------------

_original_ask_json = gateway.ask_json
_llm_calls = [0]


def _counting_ask_json(model, system, user, max_tokens=800):
    result = _original_ask_json(model, system, user, max_tokens=max_tokens)
    # Only count real model calls (Nebius / Groq), not RULES_ONLY.
    if result.get("_provider") in ("nebius", "groq"):
        _llm_calls[0] += 1
    return result


gateway.ask_json = _counting_ask_json


def _budget_exhausted() -> bool:
    return _llm_calls[0] >= args.max_llm_calls

# ---------------------------------------------------------------------------
# 5. Helpers
# ---------------------------------------------------------------------------

BENCH_DIR = Path(__file__).resolve().parent


def _load_jsonl(name: str) -> list[dict[str, Any]]:
    path = BENCH_DIR / name
    samples: list[dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                samples.append(json.loads(line))
    return samples


def _extract_target(tool: str, args_dict: dict[str, Any]) -> str:
    """Best-effort extraction of the tool-call target (URL / email / path)."""
    if tool == "send_email":
        return str(args_dict.get("to", ""))
    if tool == "http_post":
        return str(args_dict.get("url", ""))
    if tool in ("file_read", "file_write"):
        return str(args_dict.get("path", ""))
    if tool == "payment":
        return str(args_dict.get("to", ""))
    return ""


def _post_ingest(text: str, source: str) -> dict[str, Any]:
    start = time.perf_counter()
    try:
        resp = client.post("/ingest", json={"content": text, "source": source})
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        return {
            "ok": True,
            "data": resp.json(),
            "latency_ms": elapsed_ms,
        }
    except Exception as exc:  # noqa: BLE001
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        return {
            "ok": False,
            "data": None,
            "latency_ms": elapsed_ms,
            "error": str(exc),
        }


def _post_tool_call(
    tool: str,
    target: str,
    payload: dict[str, Any],
    source_block_ids: list[str],
    user_task: str,
) -> dict[str, Any]:
    start = time.perf_counter()
    try:
        resp = client.post(
            "/tool-call",
            json={
                "tool": tool,
                "target": target,
                "payload": payload,
                "source_block_ids": source_block_ids,
                "user_task": user_task,
            },
        )
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        return {
            "ok": True,
            "data": resp.json(),
            "latency_ms": elapsed_ms,
        }
    except Exception as exc:  # noqa: BLE001
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        return {
            "ok": False,
            "data": None,
            "latency_ms": elapsed_ms,
            "error": str(exc),
        }


def _p95(values: list[float]) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    k = (len(s) - 1) * 0.95
    f = int(k)
    c = f + 1
    if c >= len(s):
        return float(s[-1])
    d = k - f
    return float(s[f] + d * (s[c] - s[f]))


def _rule_ids_for_block(block_id: str) -> list[str]:
    """Look up rule_ids for a block from the /events endpoint."""
    if not block_id:
        return []
    try:
        resp = client.get("/events")
        if resp.status_code >= 400:
            return []
        for event in resp.json():
            if event.get("block_id") == block_id:
                raw = event.get("rule_ids", "")
                if isinstance(raw, str):
                    try:
                        return json.loads(raw) if raw else []
                    except Exception:
                        return []
                return raw if isinstance(raw, list) else []
    except Exception:  # noqa: BLE001
        pass
    return []


# ---------------------------------------------------------------------------
# 6. Load benchmark data
# ---------------------------------------------------------------------------

attacks = _load_jsonl("attacks.jsonl")
benign = _load_jsonl("benign.jsonl")
tool_calls = _load_jsonl("tool_calls.jsonl")

latencies: list[float] = []
skipped = 0
failed = 0

# ---------------------------------------------------------------------------
# 7. Run attacks
# ---------------------------------------------------------------------------

attack_results: list[dict[str, Any]] = []

for sample in attacks:
    if _budget_exhausted():
        skipped += 1
        print(f"[SKIP] {sample['id']}: LLM call budget exhausted")
        continue
    sample_id = sample["id"]
    category = sample["category"]
    text = sample["text"]
    try:
        result = _post_ingest(text, sample_id)
        if not result["ok"]:
            failed += 1
            print(f"[FAIL] {sample_id}: ingest error: {result.get('error')}")
            continue
        latencies.append(result["latency_ms"])
        flagged = bool(result["data"].get("flagged", False))
        block_id = result["data"].get("block_id", "")
        attack_results.append(
            {
                "id": sample_id,
                "category": category,
                "text": text,
                "block_id": block_id,
                "blocked": flagged,
                "reason": result["data"].get("reason", ""),
            }
        )
    except Exception as exc:  # noqa: BLE001
        failed += 1
        print(f"[FAIL] {sample_id}: {exc}")

# ---------------------------------------------------------------------------
# 8. Run benign
# ---------------------------------------------------------------------------

benign_results: list[dict[str, Any]] = []

for sample in benign:
    if _budget_exhausted():
        skipped += 1
        print(f"[SKIP] {sample['id']}: LLM call budget exhausted")
        continue
    sample_id = sample["id"]
    category = sample["category"]
    text = sample["text"]
    try:
        result = _post_ingest(text, sample_id)
        if not result["ok"]:
            failed += 1
            print(f"[FAIL] {sample_id}: ingest error: {result.get('error')}")
            continue
        latencies.append(result["latency_ms"])
        flagged = bool(result["data"].get("flagged", False))
        block_id = result["data"].get("block_id", "")
        benign_results.append(
            {
                "id": sample_id,
                "category": category,
                "text": text,
                "block_id": block_id,
                "false_positive": flagged,
                "reason": result["data"].get("reason", ""),
            }
        )
    except Exception as exc:  # noqa: BLE001
        failed += 1
        print(f"[FAIL] {sample_id}: {exc}")

# ---------------------------------------------------------------------------
# 9. Run tool calls (ingest first, then /tool-call, compare with expected)
# ---------------------------------------------------------------------------

tool_results: list[dict[str, Any]] = []

for sample in tool_calls:
    if _budget_exhausted():
        skipped += 1
        print(f"[SKIP] {sample['id']}: LLM call budget exhausted")
        continue
    sample_id = sample["id"]
    user_task = sample.get("user_task", "")
    ingested_content = sample.get("ingested_content", "")
    tool = sample.get("tool", "")
    tool_args = sample.get("args", {})
    expected = sample.get("expected", "")

    # Step 1: ingest the untrusted content
    try:
        ingest_result = _post_ingest(ingested_content, sample_id)
        if not ingest_result["ok"]:
            failed += 1
            print(
                f"[FAIL] {sample_id}: ingest error: {ingest_result.get('error')}"
            )
            continue
        latencies.append(ingest_result["latency_ms"])
        block_id = ingest_result["data"].get("block_id", "")
    except Exception as exc:  # noqa: BLE001
        failed += 1
        print(f"[FAIL] {sample_id}: {exc}")
        continue

    # Step 2: tool call
    try:
        target = _extract_target(tool, tool_args)
        tool_result = _post_tool_call(
            tool=tool,
            target=target,
            payload=tool_args,
            source_block_ids=[block_id] if block_id else [],
            user_task=user_task,
        )
        if not tool_result["ok"]:
            failed += 1
            print(
                f"[FAIL] {sample_id}: tool-call error: {tool_result.get('error')}"
            )
            continue
        latencies.append(tool_result["latency_ms"])
        allowed = bool(tool_result["data"].get("allowed", False))
        expected_allow = expected == "allow"
        correct = allowed == expected_allow
        tool_results.append(
            {
                "id": sample_id,
                "tool": tool,
                "args": tool_args,
                "expected": expected,
                "allowed": allowed,
                "correct": correct,
                "reason": tool_result["data"].get("reason", ""),
            }
        )
    except Exception as exc:  # noqa: BLE001
        failed += 1
        print(f"[FAIL] {sample_id}: {exc}")

# ---------------------------------------------------------------------------
# 10. Compute metrics
# ---------------------------------------------------------------------------

total_attacks = len(attack_results)
blocked_attacks = sum(1 for r in attack_results if r["blocked"])
attack_block_rate = (blocked_attacks / total_attacks * 100) if total_attacks else 0.0

categories: dict[str, dict[str, int]] = {}
for r in attack_results:
    cat = r["category"]
    categories.setdefault(cat, {"total": 0, "blocked": 0})
    categories[cat]["total"] += 1
    if r["blocked"]:
        categories[cat]["blocked"] += 1

total_benign = len(benign_results)
false_positives = sum(1 for r in benign_results if r["false_positive"])
fp_rate = (false_positives / total_benign * 100) if total_benign else 0.0

total_tools = len(tool_results)
correct_tools = sum(1 for r in tool_results if r["correct"])
tool_accuracy = (correct_tools / total_tools * 100) if total_tools else 0.0

median_latency = statistics.median(latencies) if latencies else 0.0
p95_latency = _p95(latencies) if latencies else 0.0

# ---------------------------------------------------------------------------
# 10a. Show failures (optional)
# ---------------------------------------------------------------------------
if args.show_failures:
    print()
    print("=" * 60)
    print("FAILURES")
    print("=" * 60)

    missed_attacks = [r for r in attack_results if not r["blocked"]]
    false_positives_list = [r for r in benign_results if r["false_positive"]]
    wrong_tools = [r for r in tool_results if not r["correct"]]

    if missed_attacks:
        print()
        print(f"Missed attacks ({len(missed_attacks)}):")
        for r in missed_attacks:
            rule_ids = _rule_ids_for_block(r["block_id"])
            text_preview = r["text"][:120].replace("\n", "\\n")
            rid_str = ",".join(rule_ids) if rule_ids else "(none)"
            print(
                f"  id={r['id']} category={r['category']} "
                f"text=\"{text_preview}\" "
                f"rule_ids=[{rid_str}] reason=\"{r['reason']}\""
            )

    if false_positives_list:
        print()
        print(f"False positives ({len(false_positives_list)}):")
        for r in false_positives_list:
            rule_ids = _rule_ids_for_block(r["block_id"])
            text_preview = r["text"][:120].replace("\n", "\\n")
            rid_str = ",".join(rule_ids) if rule_ids else "(none)"
            print(
                f"  id={r['id']} category={r['category']} "
                f"text=\"{text_preview}\" "
                f"rule_ids=[{rid_str}] reason=\"{r['reason']}\""
            )

    if wrong_tools:
        print()
        print(f"Wrong tool-call decisions ({len(wrong_tools)}):")
        for r in wrong_tools:
            args_preview = str(r["args"])[:120].replace("\n", "\\n")
            print(
                f"  id={r['id']} tool={r['tool']} args=\"{args_preview}\" "
                f"expected={r['expected']} allowed={r['allowed']} "
                f"reason=\"{r['reason']}\""
            )

    total_failures = len(missed_attacks) + len(false_positives_list) + len(wrong_tools)
    print()
    print(f"Total failures: {total_failures}")
    print("=" * 60)

# ---------------------------------------------------------------------------
# 11. Print table
# ---------------------------------------------------------------------------

today = datetime.now(timezone.utc).date().isoformat()
print()
print(f"PromptGuard benchmark — mode={args.mode}  date={today}")
print(f"Database: {_db_path} (temporary)")
print(f"LLM calls made: {_llm_calls[0]} / {args.max_llm_calls}")
print(f"Skipped (budget): {skipped}   Failed: {failed}")
print()

print("Attack block rate")
print(f"  Overall: {blocked_attacks}/{total_attacks} = {attack_block_rate:.1f}%")
for cat in sorted(categories):
    c = categories[cat]
    rate = (c["blocked"] / c["total"] * 100) if c["total"] else 0.0
    print(f"  {cat}: {c['blocked']}/{c['total']} = {rate:.1f}%")

print()
print(f"False-positive rate (benign): {false_positives}/{total_benign} = {fp_rate:.1f}%")
print()
print(f"Tool-call accuracy: {correct_tools}/{total_tools} = {tool_accuracy:.1f}%")
print()
print(f"Latency (ms): median={median_latency:.1f}  p95={p95_latency:.1f}")
print()

# ---------------------------------------------------------------------------
# 12. Write benchmark/results.md
# ---------------------------------------------------------------------------

lines: list[str] = []
lines.append("# PromptGuard benchmark results")
lines.append("")
lines.append(f"- **Mode:** {args.mode}")
lines.append(f"- **Date:** {datetime.now(timezone.utc).isoformat()}")
lines.append(f"- **Database:** {_db_path} (temporary, not promptguard.db)")
lines.append(f"- **LLM calls:** {_llm_calls[0]} / {args.max_llm_calls}")
lines.append(f"- **Skipped (budget):** {skipped}")
lines.append(f"- **Failed:** {failed}")
lines.append("")
lines.append("## Attack block rate")
lines.append("")
lines.append("| Category | Blocked | Total | Rate |")
lines.append("|---|---|---|---|")
lines.append(f"| Overall | {blocked_attacks} | {total_attacks} | {attack_block_rate:.1f}% |")
for cat in sorted(categories):
    c = categories[cat]
    rate = (c["blocked"] / c["total"] * 100) if c["total"] else 0.0
    lines.append(f"| {cat} | {c['blocked']} | {c['total']} | {rate:.1f}% |")
lines.append("")
lines.append("## Benign false positives")
lines.append("")
lines.append("| Flagged | Total | Rate |")
lines.append("|---|---|---|")
lines.append(f"| {false_positives} | {total_benign} | {fp_rate:.1f}% |")
lines.append("")
lines.append("## Tool-call accuracy")
lines.append("")
lines.append("| Correct | Total | Rate |")
lines.append("|---|---|---|")
lines.append(f"| {correct_tools} | {total_tools} | {tool_accuracy:.1f}% |")
lines.append("")
lines.append("## Latency (ms)")
lines.append("")
lines.append("| Median | p95 |")
lines.append("|---|---|")
lines.append(f"| {median_latency:.1f} | {p95_latency:.1f} |")

results_md = BENCH_DIR / "results.md"
results_md.write_text("\n".join(lines) + "\n", encoding="utf-8")
print(f"Results written to {results_md}")