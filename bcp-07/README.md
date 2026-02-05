# GCVE BCP-07 KEV Validator

This repository provides a **command-line Python validator** for **GCVE BCP-07 Known Exploited Vulnerability (KEV) assertions**, supporting both:

- **JSON** (single object or array)
- **NDJSON** (newline-delimited JSON, one assertion per line)

The validator fetches data **directly from a URL** and validates each KEV assertion against the **GCVE BCP-07 JSON Schema** (Draft 2020-12).

## Scope and Purpose

This tool is designed to support:

- **GCVE Numbering Authorities (GNAs)** publishing KEV assertions
- **CSIRTs / CERTs** validating inbound KEV feeds
- **Feed aggregators** performing schema enforcement
- **CI/CD pipelines** validating published KEV artifacts before release

### What this tool does

- Validates **structure and data types**  
- Enforces **required and optional fields** defined by BCP-07  
- Supports **streaming NDJSON** (as produced by [vulnerability-lookup](https://vulnerability-lookup.org/))  
- Produces **deterministic exit codes** for automation  
- Handles **real-world HTTP quirks** (bytes vs text, BOMs, comments)

### What this tool does *not* do

- It does **not** validate semantic correctness (e.g. whether a CVE exists)  
- It does **not** verify URLs or references  
- It does **not** enforce business logic beyond the JSON Schema  
- It does **not** modify or normalize input data  

Schema validation only — by design.

## Supported Formats

### JSON

Accepted forms:

- A **single KEV assertion object**
- An **array of KEV assertion objects**

Example:

```json
{
  "vulnerability": { "vulnId": "CVE-2024-XXXX" },
  "status": { "exploited": true }
}
```

### NDJSON (Newline-Delimited JSON)

- One JSON object per line
- Empty lines are ignored
- Lines starting with `#` are treated as comments

Example:

```json
{"vulnerability":{"vulnId":"CVE-2024-0001"},"status":{"exploited":true}}
{"vulnerability":{"vulnId":"CVE-2024-0002"},"status":{"exploited":false}}
```

## Requirements

- Python **3.9+**
- Dependencies:

```bash
pip install requests jsonschema
```

## Usage

### Basic syntax

```bash
python validate_kev_url.py   --url <KEV_FEED_URL>   --schema <PATH_TO_SCHEMA>
```

## Exit Codes

| Code | Meaning |
|-----:|--------|
| `0` | All records valid |
| `1` | One or more records invalid |
| `2` | Fetch, parse, or runtime error |

---
