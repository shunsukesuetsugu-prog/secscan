"""OpenAPI fuzzing scanner (Schemathesis).

Phase 2-O: ``secscan apifuzz --api-url <URL> --schema <path-or-url>``
runs Schemathesis property-based tests against a live API and
emits Findings for each failing check (5xx responses, schema
conformance violations, ignored auth, etc.). Covers the
business-logic / input-validation gap that DAST (Phase 2-D/J/K,
HTTP-layer ZAP probes) does not address.

Public surface:

- :class:`ApifuzzScanner` — Scanner subclass registered by the CLI.
- ``classify_schema`` / ``Schema`` union — pure input classifier.
- ``schemathesis.build_argv`` / ``schemathesis.build_chown_argv``
  / ``schemathesis.parse_ndjson_report`` — pure helpers, unit-
  tested without docker.
- ``validators.*`` — input validators (URL, schema, mode,
  auth-header).
"""

from __future__ import annotations

from ._pinned import (
    DEFAULT_HELPER_IMAGE,
    DEFAULT_PINNED_AT,
    DEFAULT_SCHEMATHESIS_IMAGE,
    DEFAULT_SCHEMATHESIS_IMAGE_DIGEST,
    DEFAULT_SCHEMATHESIS_IMAGE_REPOSITORY,
    SCHEMATHESIS_GID,
    SCHEMATHESIS_UID,
)
from .scanner import ApifuzzScanner, ApifuzzScannerSettings
from .schemathesis import (
    DEFAULT_MAX_EXAMPLES,
    NDJSON_REPORT_PATH,
    SchemathesisInvocation,
    SchemathesisReportParse,
    build_argv,
    build_chown_argv,
    classify_schemathesis_exit,
    parse_ndjson_report,
    severity_for_check,
)
from .validators import (
    MAX_REPORT_BYTES,
    MAX_SCHEMA_BYTES,
    ApifuzzInputError,
    Schema,
    SchemaFile,
    SchemaUrl,
    assert_schema_file_under_scan_root,
    classify_schema,
    validate_api_url,
    validate_auth_header,
    validate_intermediate_volume_name,
    validate_mode,
)

__all__ = [
    "DEFAULT_HELPER_IMAGE",
    "DEFAULT_MAX_EXAMPLES",
    "DEFAULT_PINNED_AT",
    "DEFAULT_SCHEMATHESIS_IMAGE",
    "DEFAULT_SCHEMATHESIS_IMAGE_DIGEST",
    "DEFAULT_SCHEMATHESIS_IMAGE_REPOSITORY",
    "MAX_REPORT_BYTES",
    "MAX_SCHEMA_BYTES",
    "NDJSON_REPORT_PATH",
    "SCHEMATHESIS_GID",
    "SCHEMATHESIS_UID",
    "ApifuzzInputError",
    "ApifuzzScanner",
    "ApifuzzScannerSettings",
    "Schema",
    "SchemaFile",
    "SchemaUrl",
    "SchemathesisInvocation",
    "SchemathesisReportParse",
    "assert_schema_file_under_scan_root",
    "build_argv",
    "build_chown_argv",
    "classify_schema",
    "classify_schemathesis_exit",
    "parse_ndjson_report",
    "severity_for_check",
    "validate_api_url",
    "validate_auth_header",
    "validate_intermediate_volume_name",
    "validate_mode",
]
