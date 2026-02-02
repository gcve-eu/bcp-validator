# GCVE-BCP-05 Validator

This repository provides a **JSON Schema** and a **Python command-line validator** for **GCVE Best Current Practice 05 (BCP-05)**.

The validator focuses on the **`x_gcve` extension object**, as defined in GCVE-BCP-05, and is designed to work with data produced by GCVE-BCP-03–compliant pull APIs (e.g. `/api/vulnerability/recent`).

## Scope and Design Goals

The validator is intentionally **BCP-05–focused**:

- It **does not fully validate CVE v5 records**
- It **does not enforce CNA- or vendor-specific policies**
- It **does validate structure and semantics of `x_gcve` objects**

### Key design principles

- **Location-agnostic**  
  Every occurrence of a key named `x_gcve` is validated, regardless of where it appears:
  - top-level records
  - `containers.cna.x_gcve`
  - `containers.adp[*].x_gcve`
  - nested `x_` namespaces

- **Forward-compatible**  
  Unknown `recordType` values or relationship types are allowed, with warnings where appropriate.

- **Spec-aligned**  
  Rules are derived directly from GCVE-BCP-05, with minimal interpretation.

## What Is Validated

### JSON Schema validation

A lightweight JSON Schema validates:

- `x_gcve` is an array
- each entry is an object
- required fields:
  - `vulnId`
  - `recordType`
- optional fields:
  - `relationships`
  - `language`
- relationship object structure:
  - `destId` (required)
  - `type` (required)
  - `srcId` (optional)

> ⚠️ The schema **does not** attempt to validate the surrounding CVE record.

### Semantic (BCP-05) checks

Additional semantic checks are applied on top of the schema:

#### Mandatory relationships by `recordType`

The following `recordType` values **MUST include a non-empty `relationships` array**:

- `update`
- `analysis`
- `metadata`
- `reference`
- `comment`
- `statement`
- `remediation`
- `deprecation`
- `detection`
- `translation`

#### Translation records

- `recordType: "translation"` **MUST** include a non-empty `language` field.

#### Relationship types (warnings)

Relationship `type` values are compared against the **recommended VXREF-derived list** from BCP-05:

- `possibly_related`
- `related`
- `not equal`
- `equal`
- `superset`
- `subset`
- `overlap`
- `opposes`
- `not_applicable`

Unknown values are **allowed**, but generate a **warning** to help catch typos or semantic drift.

## What Is *Not* Enforced

By design, the validator does **not**:

- enforce strict GCVE identifier formats beyond a permissive regex
- require that `x_gcve[*].vulnId` matches `cveMetadata.vulnId`
- require that a record contains `x_gcve` at all
- validate CNA policies, scoring systems, or CVSS data

These checks can be layered on top by downstream tooling if desired.

## Installation

### Python dependencies

```bash
pip install jsonschema requests
```

## Usage

### Validate a single JSON file

```bash
python3 gcve_bcp05_validate.py record.json
```

### Validate a directory (recursive)

```bash
python3 gcve_bcp05_validate.py ./records/
```

### Validate a GCVE pull API endpoint

```bash
python3 gcve_bcp05_validate.py --url "--url "https://vulnerability.circl.lu/api/vulnerability/?source=gna-1" 
```

The URL may return:
- a single JSON object, or
- an array of JSON objects

Both are supported.

### Fail on warnings

By default, warnings do **not** cause a non-zero exit code.

```bash
python3 gcve_bcp05_validate.py ./records --fail-on-warning
```

### Quiet mode

Only print errors (no `OK:` lines):

```bash
python3 gcve_bcp05_validate.py ./records --quiet
```
## Exit Codes

| Code | Meaning |
|-----:|--------|
| `0` | All inputs valid (no errors) |
| `1` | Validation errors found (or warnings with `--fail-on-warning`) |
| `2` | Runtime error or invalid usage |

## License

## License

The validators are licensed under [GNU General Public License version 3](https://www.gnu.org/licenses/gpl-3.0.html).
