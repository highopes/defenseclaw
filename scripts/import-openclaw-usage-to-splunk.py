#!/usr/bin/env python3
"""Import local OpenClaw session usage into the bundled Splunk dashboard.

The local Splunk app's "Model Usage And Cost" page expects flattened HEC
events with sourcetype=otel:metric / otel:trace. OpenClaw already keeps per
assistant response usage in session JSONL files, so this bridge turns that
local session history into the narrow event-indexed contract the dashboard
queries.

This is intentionally a local bridge, not a general OTLP collector.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


DEFAULT_HEC_URL = "http://127.0.0.1:8088/services/collector/event"
DEFAULT_INDEX = "defenseclaw_local"
DEFAULT_SOURCE = "openclaw-session-import"
DEFAULT_STATE_FILE = "~/.defenseclaw/openclaw-usage-splunk-import-state.json"


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Convert local OpenClaw session usage JSONL into Splunk HEC "
            "otel:metric / otel:trace events for the DefenseClaw local app."
        )
    )
    parser.add_argument("--openclaw-home", default="~/.openclaw")
    parser.add_argument("--days", type=float, default=7.0, help="Only import responses newer than this many days.")
    parser.add_argument("--limit", type=int, default=500, help="Maximum assistant responses to import.")
    parser.add_argument("--hec-url", default=os.environ.get("DEFENSECLAW_HEC_URL", DEFAULT_HEC_URL))
    parser.add_argument(
        "--hec-token",
        default=os.environ.get("DEFENSECLAW_SPLUNK_HEC_TOKEN")
        or os.environ.get("DEFENSECLAW_HEC_TOKEN")
        or os.environ.get("SPLUNK_HEC_TOKEN"),
    )
    parser.add_argument("--env-file", default="~/.defenseclaw/.env")
    parser.add_argument("--index", default=os.environ.get("DEFENSECLAW_INDEX", DEFAULT_INDEX))
    parser.add_argument("--source", default=DEFAULT_SOURCE)
    parser.add_argument(
        "--state-file",
        default=os.environ.get("DEFENSECLAW_OPENCLAW_USAGE_IMPORT_STATE", DEFAULT_STATE_FILE),
        help="Local state file used to avoid re-importing the same OpenClaw responses.",
    )
    parser.add_argument("--batch-size", type=int, default=200)
    parser.add_argument("--dry-run", action="store_true", help="Print counts and sample events without posting.")
    parser.add_argument("--force", action="store_true", help="Ignore import state and resend matching responses.")
    parser.add_argument(
        "--include-zero-usage",
        action="store_true",
        help="Also import responses whose token and cost counters are all zero.",
    )
    parser.add_argument(
        "--no-zero-queue",
        action="store_true",
        help="Do not emit zero-valued queue wait/depth baseline metrics.",
    )
    args = parser.parse_args()

    load_env_file(Path(args.env_file).expanduser())
    if not args.hec_token:
        args.hec_token = (
            os.environ.get("DEFENSECLAW_SPLUNK_HEC_TOKEN")
            or os.environ.get("DEFENSECLAW_HEC_TOKEN")
            or os.environ.get("SPLUNK_HEC_TOKEN")
        )

    openclaw_home = Path(args.openclaw_home).expanduser()
    state_file = Path(args.state_file).expanduser()
    candidate_responses = collect_responses(
        openclaw_home,
        days=args.days,
        limit=args.limit,
        include_zero_usage=args.include_zero_usage,
    )
    imported_keys = set() if args.force else load_import_state(state_file)
    responses = [
        response
        for response in candidate_responses
        if args.force or import_key(response) not in imported_keys
    ]
    events = []
    for response in responses:
        events.extend(
            build_events(
                response,
                index=args.index,
                source=args.source,
                emit_zero_queue=not args.no_zero_queue,
            )
        )

    if args.dry_run:
        candidate_first_at, candidate_last_at = response_window(candidate_responses)
        import_first_at, import_last_at = response_window(responses)
        print(
            json.dumps(
                {
                    "candidate_responses": len(candidate_responses),
                    "candidate_first_at": candidate_first_at,
                    "candidate_last_at": candidate_last_at,
                    "responses_to_import": len(responses),
                    "import_first_at": import_first_at,
                    "import_last_at": import_last_at,
                    "already_imported": len(candidate_responses) - len(responses),
                    "hec_events": len(events),
                    "openclaw_home": str(openclaw_home),
                    "state_file": str(state_file),
                    "force": args.force,
                    "sample": events[:5],
                },
                indent=2,
                ensure_ascii=False,
            )
        )
        return 0

    if not args.hec_token:
        print(
            "error: missing HEC token; set DEFENSECLAW_SPLUNK_HEC_TOKEN or pass --hec-token",
            file=sys.stderr,
        )
        return 2
    if not events:
        print("No OpenClaw usage responses found to import.")
        return 0

    try:
        sent = post_hec_batches(args.hec_url, args.hec_token, events, args.batch_size)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    save_import_state(state_file, imported_keys | {import_key(response) for response in responses})
    skipped = len(candidate_responses) - len(responses)
    print(
        f"Imported {len(responses)} OpenClaw responses as {sent} Splunk HEC events "
        f"({skipped} already imported)."
    )
    return 0


def load_env_file(path: Path) -> None:
    if not path.exists():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def load_import_state(path: Path) -> set[str]:
    if not path.exists():
        return set()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set()
    if isinstance(data, dict) and isinstance(data.get("imported"), list):
        return {str(item) for item in data["imported"]}
    if isinstance(data, list):
        return {str(item) for item in data}
    return set()


def save_import_state(path: Path, imported_keys: set[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "updated_at": iso_time(time.time()),
        "imported": sorted(imported_keys),
    }
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp_path.replace(path)


def import_key(response: dict[str, Any]) -> str:
    return f"{response['session_id']}\t{response['run_id']}"


def response_window(responses: list[dict[str, Any]]) -> tuple[str | None, str | None]:
    if not responses:
        return None, None
    ordered = sorted(responses, key=lambda item: item["timestamp"])
    return iso_time(ordered[0]["timestamp"]), iso_time(ordered[-1]["timestamp"])


def collect_responses(
    openclaw_home: Path,
    *,
    days: float,
    limit: int,
    include_zero_usage: bool,
) -> list[dict[str, Any]]:
    sessions_dir = openclaw_home / "agents"
    session_keys = load_session_keys(sessions_dir)
    cutoff = time.time() - (days * 86400)
    responses: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    session_files = sorted(
        (
            path
            for path in sessions_dir.glob("*/sessions/*.jsonl")
            if ".checkpoint." not in path.name
            and ".trajectory" not in path.name
            and ".reset." not in path.name
            and ".deleted." not in path.name
            and ".archived." not in path.name
        ),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )

    for path in session_files:
        session_id = path.name.split(".jsonl", 1)[0]
        agent_name = path.parents[1].name if len(path.parents) > 1 else "main"
        session_key = session_keys.get(session_id) or f"agent:{agent_name}:unknown"
        last_user_time: float | None = None

        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except UnicodeDecodeError:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()

        for raw in lines:
            if not raw.strip():
                continue
            try:
                envelope = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if envelope.get("type") != "message":
                continue
            msg = envelope.get("message")
            if not isinstance(msg, dict):
                continue
            role = msg.get("role")
            ts = parse_time(envelope.get("timestamp")) or parse_time(msg.get("timestamp"))
            if role == "user" and ts is not None:
                last_user_time = ts
                continue
            if role != "assistant":
                continue
            if ts is None or ts < cutoff:
                continue
            usage = msg.get("usage")
            if not isinstance(usage, dict):
                continue
            total_tokens = intish(usage.get("totalTokens")) or (
                intish(usage.get("input")) + intish(usage.get("output"))
            )
            cost = usage.get("cost") if isinstance(usage.get("cost"), dict) else {}
            total_cost = floatish(cost.get("total")) if isinstance(cost, dict) else 0.0
            if not include_zero_usage and total_tokens <= 0 and total_cost <= 0:
                continue

            response_id = str(msg.get("responseId") or envelope.get("id") or f"{session_id}:{ts}")
            dedupe_key = (session_id, response_id)
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)

            duration_ms = 0
            if last_user_time is not None and ts >= last_user_time:
                duration_ms = int(round((ts - last_user_time) * 1000))

            responses.append(
                {
                    "timestamp": ts,
                    "session_id": session_id,
                    "session_key": session_key,
                    "run_id": response_id,
                    "provider": str(msg.get("provider") or "unknown"),
                    "model": str(msg.get("model") or "unknown"),
                    "api": str(msg.get("api") or "unknown"),
                    "status": str(msg.get("stopReason") or "unknown"),
                    "usage": usage,
                    "cost": cost if isinstance(cost, dict) else {},
                    "duration_ms": duration_ms,
                }
            )
            if len(responses) >= limit:
                return sorted(responses, key=lambda item: item["timestamp"])

    return sorted(responses, key=lambda item: item["timestamp"])


def load_session_keys(agents_dir: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for sessions_json in agents_dir.glob("*/sessions/sessions.json"):
        try:
            data = json.loads(sessions_json.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(data, dict):
            continue
        for key, value in data.items():
            if isinstance(value, dict) and isinstance(value.get("sessionId"), str):
                out[value["sessionId"]] = key
    return out


def build_events(
    response: dict[str, Any],
    *,
    index: str,
    source: str,
    emit_zero_queue: bool,
) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    usage = response["usage"]
    cost = response["cost"]
    base = {
        "timestamp": iso_time(response["timestamp"]),
        "provider": response["provider"],
        "model": response["model"],
        "run_id": response["run_id"],
        "session_id": response["session_id"],
        "session_key": response["session_key"],
        "channel": channel_from_session_key(response["session_key"]),
        "component": "openclaw-session-import",
        "status": response["status"],
        "api": response["api"],
    }

    token_fields = (
        ("input", "input"),
        ("output", "output"),
        ("cacheRead", "cache_read"),
        ("cacheWrite", "cache_write"),
    )
    for usage_key, token_type in token_fields:
        value = intish(usage.get(usage_key))
        if value <= 0:
            continue
        events.append(hec_event(index, source, "otel:metric", response["timestamp"], {
            **base,
            "metric_name": "openclaw.tokens",
            "metric_value": value,
            "unit": "{token}",
            "token_type": token_type,
        }))

    events.append(hec_event(index, source, "otel:metric", response["timestamp"], {
        **base,
        "metric_name": "openclaw.cost.usd",
        "metric_value": floatish(cost.get("total")),
        "unit": "USD",
    }))
    events.append(hec_event(index, source, "otel:metric", response["timestamp"], {
        **base,
        "metric_name": "openclaw.run.duration_ms",
        "metric_value": intish(response.get("duration_ms")),
        "unit": "ms",
    }))
    if emit_zero_queue:
        events.append(hec_event(index, source, "otel:metric", response["timestamp"], {
            **base,
            "metric_name": "openclaw.queue.wait_ms",
            "metric_value": 0,
            "unit": "ms",
        }))
        events.append(hec_event(index, source, "otel:metric", response["timestamp"], {
            **base,
            "metric_name": "openclaw.queue.depth",
            "metric_value": 0,
            "unit": "{item}",
        }))

    trace_id, span_id = trace_ids(response["session_id"], response["run_id"])
    events.append(hec_event(index, source, "otel:trace", response["timestamp"], {
        **base,
        "trace_id": trace_id,
        "span_id": span_id,
        "parent_span_id": "",
        "span_name": "openclaw.model.usage",
        "duration_ms": intish(response.get("duration_ms")),
    }))
    return events


def hec_event(index: str, source: str, sourcetype: str, timestamp: float, event: dict[str, Any]) -> dict[str, Any]:
    return {
        "time": timestamp,
        "index": index,
        "source": source,
        "sourcetype": sourcetype,
        "event": event,
    }


def post_hec_batches(hec_url: str, token: str, events: list[dict[str, Any]], batch_size: int) -> int:
    sent = 0
    for start in range(0, len(events), batch_size):
        batch = events[start:start + batch_size]
        body = "".join(json.dumps(event, separators=(",", ":")) + "\n" for event in batch).encode()
        req = urllib.request.Request(
            hec_url,
            data=body,
            method="POST",
            headers={
                "Authorization": f"Splunk {token}",
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                payload = resp.read().decode("utf-8", errors="replace")
                if resp.status < 200 or resp.status >= 300:
                    raise RuntimeError(f"HEC returned HTTP {resp.status}: {payload}")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"HEC returned HTTP {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"HEC request failed: {exc}") from exc
        sent += len(batch)
    return sent


def parse_time(value: Any) -> float | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        if value > 10_000_000_000:
            return float(value) / 1000.0
        return float(value)
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        return dt.datetime.fromisoformat(text).timestamp()
    except ValueError:
        return None


def iso_time(ts: float) -> str:
    return dt.datetime.fromtimestamp(ts, tz=dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def intish(value: Any) -> int:
    if value is None:
        return 0
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return 0


def floatish(value: Any) -> float:
    if value is None:
        return 0.0
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def channel_from_session_key(session_key: str) -> str:
    parts = session_key.split(":")
    if len(parts) >= 3 and parts[2]:
        return parts[2]
    return "local"


def trace_ids(session_id: str, run_id: str) -> tuple[str, str]:
    digest = hashlib.sha256(f"{session_id}:{run_id}".encode()).hexdigest()
    return digest[:32], digest[32:48]


if __name__ == "__main__":
    raise SystemExit(main())
