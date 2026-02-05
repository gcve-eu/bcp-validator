#!/usr/bin/env python3
"""
Validate GCVE BCP-07 KEV assertions (JSON or NDJSON) from a URL using an external JSON Schema.

Examples:
  python validate_kev_url.py --url https://example.org/kev.json
  python validate_kev_url.py --url https://example.org/kev.ndjson --ndjson
  python validate_kev_url.py --url https://example.org/feed --auto

  # Use the uploaded schema file path:
  python validate_kev_url.py --url https://example.org/kev.ndjson --ndjson \
    --schema /mnt/data/gcve-bcp-07.schema.json

Exit codes:
  0 = all valid
  1 = validation errors found
  2 = fetch/parse/runtime error
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict, Iterable, Iterator, List, Tuple

import requests
from jsonschema import Draft202012Validator


def load_schema(schema_path: str) -> Dict[str, Any]:
    try:
        with open(schema_path, "r", encoding="utf-8") as f:
            schema = json.load(f)
    except FileNotFoundError as e:
        raise ValueError(f"Schema file not found: {schema_path}") from e
    except json.JSONDecodeError as e:
        raise ValueError(f"Schema file is not valid JSON: {schema_path}: {e}") from e

    if not isinstance(schema, dict):
        raise ValueError("Schema must be a JSON object at top-level")

    return schema


def _guess_mode(url: str, content_type: str | None) -> str:
    u = url.lower()
    ct = (content_type or "").lower()
    if u.endswith(".ndjson") or "ndjson" in ct or "x-ndjson" in ct:
        return "ndjson"
    return "json"


def _iter_ndjson_lines(resp: requests.Response) -> Iterator[Tuple[int, Dict[str, Any]]]:
    """
    Yield (line_number, parsed_object) for NDJSON.
    Robust to responses where iter_lines yields bytes.
    """
    for line_no, raw in enumerate(resp.iter_lines(decode_unicode=False), start=1):
        if raw is None:
            continue

        # Normalize to text
        if isinstance(raw, bytes):
            enc = resp.encoding or "utf-8"
            s = raw.decode(enc, errors="replace")
        else:
            s = str(raw)

        s = s.lstrip("\ufeff").strip()  # handle BOM + whitespace

        if not s or s.startswith("#"):
            continue

        try:
            obj = json.loads(s)
        except json.JSONDecodeError as e:
            raise ValueError(f"NDJSON parse error on line {line_no}: {e}") from e

        if not isinstance(obj, dict):
            raise ValueError(f"NDJSON line {line_no} is not a JSON object")

        yield line_no, obj


def _load_json(resp: requests.Response) -> Any:
    try:
        return json.loads(resp.text)
    except json.JSONDecodeError as e:
        raise ValueError(f"JSON parse error: {e}") from e


def _format_path(error) -> str:
    if not error.path:
        return "$"
    return "$." + ".".join(str(p) for p in error.path)


def validate_objects(
    schema: Dict[str, Any],
    objs: Iterable[Tuple[str, Dict[str, Any]]],
    max_errors: int,
) -> Tuple[int, int]:
    """
    objs yields (label, object).
    Returns (valid_count, invalid_count). Prints errors to stderr.
    """
    validator = Draft202012Validator(schema)

    valid = 0
    invalid = 0
    shown = 0

    for label, obj in objs:
        errors = sorted(validator.iter_errors(obj), key=lambda e: (list(e.path), e.message))
        if not errors:
            valid += 1
            continue

        invalid += 1
        for err in errors:
            if shown >= max_errors:
                break
            shown += 1
            path = _format_path(err)
            print(f"[INVALID] {label}: {path}: {err.message}", file=sys.stderr)

        if shown >= max_errors:
            break

    return valid, invalid


def main() -> int:
    ap = argparse.ArgumentParser(description="Validate GCVE BCP-07 KEV assertions from a URL (JSON or NDJSON).")
    ap.add_argument("--url", required=True, help="HTTP/HTTPS URL to fetch.")
    ap.add_argument(
        "--schema",
        required=True,
        help="Path to JSON Schema (Draft 2020-12). Example: /mnt/data/gcve-bcp-07.schema.json",
    )

    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--auto", action="store_true", help="Auto-detect JSON vs NDJSON (default).")
    mode.add_argument("--json", dest="force_json", action="store_true", help="Force JSON mode.")
    mode.add_argument("--ndjson", action="store_true", help="Force NDJSON mode.")

    ap.add_argument("--timeout", type=float, default=30.0, help="HTTP timeout seconds (default: 30).")
    ap.add_argument("--max-errors", type=int, default=50, help="Stop after this many errors (default: 50).")
    ap.add_argument("--user-agent", default="gcve-bcp07-validator/1.1", help="User-Agent string.")
    args = ap.parse_args()

    try:
        schema = load_schema(args.schema)

        # Fail fast if the schema is itself invalid/incompatible
        Draft202012Validator.check_schema(schema)

        with requests.get(
            args.url,
            stream=True,
            timeout=args.timeout,
            headers={"User-Agent": args.user_agent},
        ) as resp:
            resp.raise_for_status()
            ct = resp.headers.get("Content-Type", "")

            if args.force_json:
                m = "json"
            elif args.ndjson:
                m = "ndjson"
            else:
                m = _guess_mode(args.url, ct)

            if m == "ndjson":
                def gen():
                    for line_no, obj in _iter_ndjson_lines(resp):
                        yield f"line {line_no}", obj

                valid, invalid = validate_objects(schema, gen(), args.max_errors)

            else:
                payload = _load_json(resp)

                if isinstance(payload, dict):
                    valid, invalid = validate_objects(schema, [("root", payload)], args.max_errors)
                elif isinstance(payload, list):
                    def gen_list():
                        for i, item in enumerate(payload):
                            if not isinstance(item, dict):
                                raise ValueError(f"JSON array item {i} is not an object")
                            yield f"item {i}", item

                    valid, invalid = validate_objects(schema, gen_list(), args.max_errors)
                else:
                    raise ValueError("Top-level JSON must be an object or an array of objects")

    except requests.RequestException as e:
        print(f"[ERROR] HTTP fetch failed: {e}", file=sys.stderr)
        return 2
    except ValueError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}", file=sys.stderr)
        return 2

    total = valid + invalid
    print(f"Validated {total} record(s): {valid} valid, {invalid} invalid.")
    return 0 if invalid == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())

