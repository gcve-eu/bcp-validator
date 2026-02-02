#!/usr/bin/env python3
"""
gcve_bcp05_validate.py

Validator for GCVE-BCP-05 focusing on the `x_gcve` extension object.

It can validate:
  - a single JSON file
  - a directory (recursively) of *.json files
  - an URL returning JSON (either a single record or an array of records)

Validation approach:
  * Traverse the JSON and validate every occurrence of a key named `x_gcve`
    (top-level, inside containers.cna, inside other x_ namespaces, etc.).
  * Apply JSON Schema validation to each `x_gcve` entry, then apply BCP-05
    semantic checks (recordType requirements, translation language field, etc.).

Exit codes:
  0 -> all inputs valid (no errors)
  1 -> at least one validation error
  2 -> runtime / usage error
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Tuple, Union

try:
    import requests
except Exception:
    requests = None  # type: ignore

try:
    from jsonschema import Draft202012Validator
except Exception:
    Draft202012Validator = None  # type: ignore

BCP05_SCHEMA_JSON_TEXT = "{\n  \"$schema\": \"https://json-schema.org/draft/2020-12/schema\",\n  \"$id\": \"https://gcve.eu/bcp/bcp-05/gcve-bcp-05.schema.json\",\n  \"title\": \"GCVE-BCP-05 extension validator (x_gcve)\",\n  \"description\": \"Validates the GCVE extension object(s) as described in GCVE-BCP-05. This schema intentionally does not fully validate the underlying CVE Record Format.\",\n  \"oneOf\": [\n    {\n      \"$ref\": \"#/$defs/CVERecord\"\n    },\n    {\n      \"type\": \"array\",\n      \"items\": {\n        \"$ref\": \"#/$defs/CVERecord\"\n      }\n    }\n  ],\n  \"$defs\": {\n    \"CVERecord\": {\n      \"type\": \"object\",\n      \"required\": [\n        \"dataType\",\n        \"dataVersion\",\n        \"cveMetadata\",\n        \"containers\"\n      ],\n      \"properties\": {\n        \"dataType\": {\n          \"type\": \"string\"\n        },\n        \"dataVersion\": {\n          \"type\": \"string\"\n        },\n        \"cveMetadata\": {\n          \"type\": \"object\"\n        },\n        \"containers\": {\n          \"type\": \"object\"\n        },\n        \"x_gcve\": {\n          \"type\": \"array\",\n          \"items\": {\n            \"$ref\": \"#/$defs/GCVEExtension\"\n          }\n        }\n      },\n      \"additionalProperties\": true\n    },\n    \"GCVEExtension\": {\n      \"type\": \"object\",\n      \"required\": [\n        \"vulnId\",\n        \"recordType\"\n      ],\n      \"properties\": {\n        \"vulnId\": {\n          \"type\": \"string\",\n          \"description\": \"GCVE identifier. Spec references GCVE-BCP-04; this regex is a permissive approximation accepting case-insensitive GCVE-<digits>-<year>-<serial>.\",\n          \"pattern\": \"^(?i:GCVE)-[0-9]+-[0-9]{4}-[0-9]{4,}$\"\n        },\n        \"recordType\": {\n          \"type\": \"string\",\n          \"description\": \"Semantic type of the record. Unknown values are permitted for forward compatibility.\",\n          \"minLength\": 1\n        },\n        \"relationships\": {\n          \"type\": \"array\",\n          \"items\": {\n            \"$ref\": \"#/$defs/Relationship\"\n          }\n        },\n        \"language\": {\n          \"type\": \"string\",\n          \"description\": \"Only used when recordType is translation.\"\n        }\n      },\n      \"patternProperties\": {\n        \"^x_\": {\n          \"type\": [\n            \"object\",\n            \"array\",\n            \"string\",\n            \"number\",\n            \"boolean\",\n            \"null\"\n          ]\n        }\n      },\n      \"additionalProperties\": true\n    },\n    \"Relationship\": {\n      \"type\": \"object\",\n      \"required\": [\n        \"destId\",\n        \"type\"\n      ],\n      \"properties\": {\n        \"destId\": {\n          \"type\": \"string\",\n          \"minLength\": 1\n        },\n        \"type\": {\n          \"type\": \"string\",\n          \"minLength\": 1\n        },\n        \"srcId\": {\n          \"type\": \"string\",\n          \"minLength\": 1\n        }\n      },\n      \"additionalProperties\": true\n    }\n  }\n}\n"
BCP05_SCHEMA: Dict[str, Any] = json.loads(BCP05_SCHEMA_JSON_TEXT)

# Recommended relationship verbs per BCP-05 (VXREF-derived defaults)
RECOMMENDED_REL_VERBS = {
    "possibly_related",
    "related",
    "not equal",
    "equal",
    "superset",
    "subset",
    "overlap",
    "opposes",
    "not_applicable",
}

# recordType values that MUST include relationships (per BCP-05)
MUST_HAVE_RELATIONSHIPS = {
    "update",
    "analysis",
    "metadata",
    "reference",
    "comment",
    "statement",
    "remediation",
    "deprecation",
    "detection",
    "translation",
}

def eprint(*args: Any) -> None:
    print(*args, file=sys.stderr)

def iter_json_files(path: Path) -> Iterable[Path]:
    if path.is_file():
        yield path
        return
    for p in path.rglob("*.json"):
        if p.is_file():
            yield p

def load_json_from_file(p: Path) -> Any:
    with p.open("r", encoding="utf-8") as f:
        return json.load(f)

def load_json_from_url(url: str, timeout: int = 30) -> Any:
    if requests is None:
        raise RuntimeError("requests is not installed (needed for --url).")
    r = requests.get(url, timeout=timeout, headers={"Accept": "application/json"})
    r.raise_for_status()
    return r.json()

def json_pointer(parts: List[Union[str, int]]) -> str:
    if not parts:
        return ""
    out = ""
    for p in parts:
        if isinstance(p, int):
            out += f"/{p}"
        else:
            out += "/" + p.replace("~", "~0").replace("/", "~1")
    return out

def compile_validators() -> Tuple[Any, Any]:
    if Draft202012Validator is None:
        raise RuntimeError("jsonschema is not installed. Install with: pip install jsonschema")
    # Validate individual extension objects using schema $defs
    ext_schema = {"$ref": "#/$defs/GCVEExtension", "$defs": BCP05_SCHEMA.get("$defs", {})}
    rel_schema = {"$ref": "#/$defs/Relationship", "$defs": BCP05_SCHEMA.get("$defs", {})}
    return Draft202012Validator(ext_schema), Draft202012Validator(rel_schema)

def find_x_gcve(doc: Any) -> Iterator[Tuple[List[Union[str, int]], Any]]:
    """Yield (pathParts, value) for every key named 'x_gcve' in the JSON."""
    def rec(node: Any, path: List[Union[str, int]]) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                if k == "x_gcve":
                    yield_items.append((path + [k], v))
                rec(v, path + [k])
        elif isinstance(node, list):
            for i, item in enumerate(node):
                rec(item, path + [i])
    yield_items: List[Tuple[List[Union[str, int]], Any]] = []
    rec(doc, [])
    for item in yield_items:
        yield item

def normalize_record_type(rt: Any) -> str:
    if isinstance(rt, str):
        return rt.strip().lower()
    return ""

def validate_x_gcve_array(xgcve: Any, base_path: List[Union[str, int]], ext_validator: Any, rel_validator: Any) -> Tuple[List[Tuple[str, str]], List[Tuple[str, str]]]:
    errors: List[Tuple[str, str]] = []
    warns: List[Tuple[str, str]] = []

    if not isinstance(xgcve, list):
        errors.append((json_pointer(base_path), "x_gcve must be an array"))
        return errors, warns

    for i, ext in enumerate(xgcve):
        p = base_path + [i]
        if not isinstance(ext, dict):
            errors.append((json_pointer(p), "x_gcve entry must be an object"))
            continue

        # JSON-Schema validation for the extension object
        for err in sorted(ext_validator.iter_errors(ext), key=lambda e: list(e.path)):
            errors.append((json_pointer(p + list(err.absolute_path)), err.message))

        rt = normalize_record_type(ext.get("recordType"))
        if not rt:
            errors.append((json_pointer(p + ["recordType"]), "recordType must be a non-empty string"))
            rt = "advisory"  # best effort for follow-on checks

        rel = ext.get("relationships", None)

        if rt in MUST_HAVE_RELATIONSHIPS:
            if rel is None:
                errors.append((json_pointer(p), f"recordType '{rt}' MUST include relationships"))
            elif not isinstance(rel, list) or len(rel) == 0:
                errors.append((json_pointer(p + ["relationships"]), f"recordType '{rt}' MUST include a non-empty relationships array"))

        if rel is not None:
            if not isinstance(rel, list):
                errors.append((json_pointer(p + ["relationships"]), "relationships must be an array"))
            else:
                for j, r in enumerate(rel):
                    rp = p + ["relationships", j]
                    if not isinstance(r, dict):
                        errors.append((json_pointer(rp), "relationship must be an object"))
                        continue
                    for err in sorted(rel_validator.iter_errors(r), key=lambda e: list(e.path)):
                        errors.append((json_pointer(rp + list(err.absolute_path)), err.message))
                    t = r.get("type")
                    if isinstance(t, str) and t not in RECOMMENDED_REL_VERBS:
                        warns.append((json_pointer(rp + ["type"]), f"relationship type '{t}' is not in the recommended VXREF-derived list (allowed, but check spelling/semantics)."))

        if rt == "translation":
            lang = ext.get("language")
            if not isinstance(lang, str) or not lang.strip():
                errors.append((json_pointer(p + ["language"]), "translation records MUST include a non-empty 'language' field"))

    return errors, warns

def validate_doc(doc: Any) -> Tuple[List[Tuple[str, str]], List[Tuple[str, str]]]:
    ext_validator, rel_validator = compile_validators()

    errors: List[Tuple[str, str]] = []
    warns: List[Tuple[str, str]] = []

    # Validate every x_gcve occurrence, wherever it lives.
    found_any = False
    for path, xgcve in find_x_gcve(doc):
        found_any = True
        e, w = validate_x_gcve_array(xgcve, path, ext_validator, rel_validator)
        errors.extend(e)
        warns.extend(w)

    # If x_gcve is missing entirely, that's not necessarily an error:
    # BCP-05 describes the format when present.
    return errors, warns

def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Validate GCVE-BCP-05 `x_gcve` extension objects in JSON documents.")
    ap.add_argument("paths", nargs="*", help="JSON file(s) or directory(ies) to validate")
    ap.add_argument("--url", help="URL returning JSON (a single record or an array of records)")
    ap.add_argument("--fail-on-warning", action="store_true", help="Return exit code 1 if warnings are present")
    ap.add_argument("--quiet", action="store_true", help="Only print errors (no OK lines)")
    args = ap.parse_args(argv)

    if not args.paths and not args.url:
        ap.print_help()
        return 2

    all_errors: List[Tuple[str, str, str]] = []
    all_warns: List[Tuple[str, str, str]] = []

    if args.url:
        try:
            doc = load_json_from_url(args.url)
            errors, warns = validate_doc(doc)
            for p, m in errors:
                all_errors.append((args.url, p, m))
            for p, m in warns:
                all_warns.append((args.url, p, m))
            if not errors and not args.quiet:
                print(f"OK: {args.url}")
        except Exception as e:
            all_errors.append((args.url, "", f"failed to fetch/parse: {e}"))

    for raw in args.paths:
        p = Path(raw)
        if not p.exists():
            all_errors.append((raw, "", "path does not exist"))
            continue
        for f in iter_json_files(p):
            try:
                doc = load_json_from_file(f)
                errors, warns = validate_doc(doc)
                for pp, m in errors:
                    all_errors.append((str(f), pp, m))
                for pp, m in warns:
                    all_warns.append((str(f), pp, m))
                if not errors and not args.quiet:
                    print(f"OK: {f}")
            except Exception as e:
                all_errors.append((str(f), "", f"failed to load/parse: {e}"))

    if all_errors:
        eprint("\nErrors:")
        for src, path, msg in all_errors:
            loc = f"{src}{path}" if path else src
            eprint(f" - {loc}: {msg}")

    if all_warns and not args.quiet:
        eprint("\nWarnings:")
        for src, path, msg in all_warns:
            loc = f"{src}{path}" if path else src
            eprint(f" - {loc}: {msg}")

    if all_errors:
        return 1
    if args.fail_on_warning and all_warns:
        return 1
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
