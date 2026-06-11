"""Shared fixtures for the Layer-1 Region API fuzzing harness.

The harness fuzzes the live ``/api/v2`` surface of a Region service that is
backed by the *simulated* provider (regions ``sim-public`` / ``sim-private``),
so no OpenStack is touched. Credentials and resource IDs are read from the
``test/.env`` file produced by ``make integration-fixtures`` (see README.md).
"""

from __future__ import annotations

import collections
import dataclasses
import os
import pathlib
import re
import secrets
import time

import pytest
import requests
from schemathesis.core.compat import BaseExceptionGroup
from schemathesis.core.failures import Failure

# Optional exact request accounting, enabled with FUZZ_REQUEST_STATS=1. Counts
# every HTTP response observed on the shared session (scaffold + fuzz traffic).
REQUEST_STATS = {
    "total": 0,
    "by_method": collections.Counter(),
    "by_status": collections.Counter(),
}


def _count_response(resp, *args, **kwargs):
    REQUEST_STATS["total"] += 1
    REQUEST_STATS["by_method"][resp.request.method] += 1
    REQUEST_STATS["by_status"][resp.status_code] += 1


def pytest_sessionfinish(session, exitstatus):
    if not os.environ.get("FUZZ_REQUEST_STATS"):
        return
    s = REQUEST_STATS
    print("\n=== FUZZ REQUEST STATS ===")
    print(f"total HTTP responses : {s['total']}")
    print(f"by method            : {dict(s['by_method'])}")
    print(f"by status            : {dict(sorted(s['by_status'].items()))}")


# --- Failure reporting -------------------------------------------------------
#
# Schemathesis raises a FailureGroup whose *message* is already the readable
# artifact (check title, response status + payload, reproduction cURL); the
# surrounding ExceptionGroup traceback through hypothesis internals is noise.
# The makereport wrapper swaps the report body for that message — so the
# FAILURES section and the JUnit XML carry the concise block — and records each
# failure for the end-of-run summary, the GitHub step summary, and GitHub error
# annotations. The swap has to happen twice: at makereport time, before the
# junitxml plugin consumes the report, and again at pytest_exception_interact,
# because Schemathesis' own pytest plugin rewrites longrepr back to a formatted
# traceback there (conftest hooks run after plugin hooks, so ours wins).

_TRACE_ID_RE = re.compile(r'"trace_id"\s*:\s*"([0-9a-f]+)"')

# What each failure class means the harness was asserting, keyed by the
# Schemathesis Failure subclass name. Without this, a bare "Server error [500]"
# in CI does not say what property the fuzzer was testing.
_CHECK_INTENTS = {
    "ServerError": "no generated input may cause an unhandled 5xx",
    "UndefinedStatusCode": "every returned status code must be documented in the operation's OpenAPI responses",
    "JsonSchemaError": "the response body must conform to the documented response schema",
    "MalformedJson": "a JSON response body must parse as JSON",
    "MissingContentType": "the response must carry a Content-Type header",
    "UndefinedContentType": "the response Content-Type must be documented in the spec",
    "MalformedMediaType": "the response media type must be well-formed",
    "MissingHeaders": "documented required response headers must be present",
}


@dataclasses.dataclass(frozen=True)
class _CheckFailure:
    title: str
    severity: str
    status: str
    intent: str


@dataclasses.dataclass(frozen=True)
class _OperationFailures:
    operation: str
    checks: tuple[_CheckFailure, ...]
    trace_ids: tuple[str, ...]
    curl: str
    details: str


_FUZZ_FAILURES: dict[str, _OperationFailures] = {}


def _iter_failures(exc: BaseException):
    if isinstance(exc, BaseExceptionGroup):
        for sub in exc.exceptions:
            yield from _iter_failures(sub)
    elif isinstance(exc, Failure):
        yield exc


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    if call.when != "call" or call.excinfo is None:
        return
    exc = call.excinfo.value
    failures = list(_iter_failures(exc))
    if not failures:
        return

    # str() on an exception group appends a " (N sub-exceptions)" suffix; the
    # raw message is the formatted Schemathesis failure block.
    details = (exc.message if isinstance(exc, BaseExceptionGroup) else str(exc)).strip()
    report.longrepr = details

    checks = tuple(
        _CheckFailure(
            title=f.title,
            severity=f.severity.name,
            status=str(getattr(f, "status_code", "")) or "-",
            intent=_CHECK_INTENTS.get(type(f).__name__, ""),
        )
        for f in failures
    )
    _FUZZ_FAILURES[item.nodeid] = _OperationFailures(
        operation=failures[0].operation,
        checks=checks,
        trace_ids=tuple(dict.fromkeys(_TRACE_ID_RE.findall(details))),
        curl=details.partition("Reproduce with:")[2].strip(),
        details=details,
    )


# trylast pins this after the Schemathesis plugin's hook (which rewrites
# longrepr to a formatted traceback) instead of relying on registration order.
@pytest.hookimpl(trylast=True)
def pytest_exception_interact(node, call, report):
    record = _FUZZ_FAILURES.get(node.nodeid)
    if record is not None:
        report.longrepr = record.details


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    if not _FUZZ_FAILURES:
        return
    records = list(_FUZZ_FAILURES.values())
    terminalreporter.section(f"API fuzz failure summary ({len(records)} operations)")
    for record in records:
        terminalreporter.write_line(record.operation)
        for c in record.checks:
            line = f"  {c.title} [{c.status}] {c.severity}"
            if c.intent:
                line += f" — asserts {c.intent}"
            terminalreporter.write_line(line)
        if record.trace_ids:
            terminalreporter.write_line(f"  trace_id: {', '.join(record.trace_ids)}")
        for line in record.curl.splitlines():
            terminalreporter.write_line(f"  {line.strip()}")
        terminalreporter.write_line("")
    _write_github_step_summary(records)
    _emit_github_annotations(records)


def _write_github_step_summary(records: list[_OperationFailures]) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    lines = [
        f"## API fuzz failures ({len(records)} operations)",
        "",
        "| Operation | Check | Asserts | Status | Severity | trace_id |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for record in records:
        trace_ids = ", ".join(record.trace_ids) or "-"
        for check in record.checks:
            lines.append(
                f"| `{record.operation}` | {check.title} | {check.intent or '-'} "
                f"| {check.status} | {check.severity} | {trace_ids} |"
            )
    lines.append("")
    for record in records:
        lines += [
            "<details>",
            f"<summary><code>{record.operation}</code></summary>",
            "",
            "~~~",
            record.details,
            "~~~",
            "",
            "</details>",
            "",
        ]
    with open(path, "a") as fh:
        fh.write("\n".join(lines))


def _gha_escape(value: str, *, in_property: bool = False) -> str:
    value = value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    if in_property:
        value = value.replace(":", "%3A").replace(",", "%2C")
    return value


# GitHub drops ::error annotations beyond 10 per step without any indication,
# so cap explicitly and spend the last slot saying what was cut.
_MAX_ANNOTATIONS = 10


def _emit_github_annotations(records: list[_OperationFailures]) -> None:
    if os.environ.get("GITHUB_ACTIONS") != "true":
        return
    overflow = len(records) - _MAX_ANNOTATIONS
    if overflow > 0:
        shown = records[: _MAX_ANNOTATIONS - 1]
        omitted = records[_MAX_ANNOTATIONS - 1 :]
    else:
        shown, omitted = records, []
    for record in shown:
        check_lines = []
        for c in record.checks:
            line = f"{c.title} [{c.status}]"
            if c.intent:
                line += f" — asserts {c.intent}"
            check_lines.append(line)
        message = "\n".join(check_lines)
        if record.trace_ids:
            message += f"\ntrace_id: {', '.join(record.trace_ids)}"
        if record.curl:
            message += f"\nReproduce with:\n{record.curl}"
        title = _gha_escape(f"API fuzz: {record.operation}", in_property=True)
        print(f"::error title={title}::{_gha_escape(message)}")
    if omitted:
        operations = ", ".join(r.operation for r in omitted)
        title = _gha_escape(f"API fuzz: {len(omitted)} more failing operations", in_property=True)
        message = _gha_escape(f"Not annotated (10-per-step limit), see the step summary: {operations}")
        print(f"::error title={title}::{message}")

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
DOTENV_PATH = REPO_ROOT / "test" / ".env"

# The simulated provider reconciles in seconds; this bound only guards against a
# wedged controller so the scaffold fails loudly rather than hanging CI.
PROVISION_TIMEOUT_SECONDS = 180
PROVISION_POLL_SECONDS = 3


def _load_dotenv(path: pathlib.Path) -> None:
    """Populate os.environ from a KEY=VALUE .env file without overriding values
    already present in the environment (the Makefile target exports them)."""
    if not path.is_file():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip())


@dataclasses.dataclass(frozen=True)
class RegionEnv:
    base_url: str
    ca_cert: str | None
    token: str
    org: str
    project: str
    region: str


@dataclasses.dataclass(frozen=True)
class ScaffoldContext:
    """Known-good parent references used to pin fuzzed requests so they route to
    real resources instead of bouncing off 404s before reaching handler logic."""

    org: str
    project: str
    region: str
    network_id: str | None
    security_group_id: str | None
    storage_class_id: str | None


def _require(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise pytest.UsageError(
            f"{name} is not set. Run `make integration-fixtures` to generate "
            f"test/.env, or source it before running the harness."
        )
    return value


@pytest.fixture(scope="session")
def region_env() -> RegionEnv:
    _load_dotenv(DOTENV_PATH)
    return RegionEnv(
        base_url=_require("REGION_BASE_URL").rstrip("/"),
        ca_cert=os.environ.get("REGION_CA_CERT") or None,
        token=_require("API_AUTH_TOKEN"),
        org=_require("TEST_ORG_ID"),
        project=_require("TEST_PROJECT_ID"),
        region=_require("TEST_REGION_ID"),
    )


@pytest.fixture(scope="session")
def region_session(region_env: RegionEnv) -> requests.Session:
    session = requests.Session()
    session.headers["Authorization"] = f"Bearer {region_env.token}"
    if region_env.ca_cert:
        session.verify = region_env.ca_cert
    if os.environ.get("FUZZ_REQUEST_STATS"):
        session.hooks["response"].append(_count_response)
    return session


def _post(session: requests.Session, base: str, path: str, body: dict) -> dict:
    resp = session.post(f"{base}{path}", json=body, timeout=60)
    resp.raise_for_status()
    return resp.json()


def _delete(session: requests.Session, base: str, path: str) -> None:
    try:
        session.delete(f"{base}{path}", timeout=60)
    except requests.RequestException:
        pass


def _wait_provisioned(session: requests.Session, base: str, path: str) -> None:
    deadline = time.monotonic() + PROVISION_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        resp = session.get(f"{base}{path}", timeout=60)
        if resp.ok:
            status = resp.json().get("metadata", {}).get("provisioningStatus")
            if status == "provisioned":
                return
        time.sleep(PROVISION_POLL_SECONDS)


@pytest.fixture(scope="session")
def scaffold(region_env: RegionEnv, region_session: requests.Session) -> ScaffoldContext:
    """Create the minimal real resource graph the fuzzer needs as routable
    parents: one network (security groups and load balancers reference its ID),
    one security group, and a storage class lookup. Torn down at session end."""
    base = region_env.base_url
    suffix = secrets.token_hex(3)
    cleanup: list[str] = []

    network = _post(
        region_session,
        base,
        "/api/v2/networks",
        {
            "metadata": {"name": f"fuzz-net-{suffix}"},
            "spec": {
                "organizationId": region_env.org,
                "projectId": region_env.project,
                "regionId": region_env.region,
                "prefix": "10.128.0.0/24",
                "dnsNameservers": [],
            },
        },
    )
    network_id = network.get("metadata", {}).get("id")
    if network_id:
        cleanup.append(f"/api/v2/networks/{network_id}")
        _wait_provisioned(region_session, base, f"/api/v2/networks/{network_id}")

    security_group_id = None
    if network_id:
        sg = _post(
            region_session,
            base,
            "/api/v2/securitygroups",
            {
                "metadata": {"name": f"fuzz-sg-{suffix}"},
                "spec": {"networkId": network_id, "rules": []},
            },
        )
        security_group_id = sg.get("metadata", {}).get("id")
        if security_group_id:
            cleanup.insert(0, f"/api/v2/securitygroups/{security_group_id}")

    storage_class_id = None
    resp = region_session.get(
        f"{base}/api/v2/filestorageclasses",
        params={"regionID": region_env.region},
        timeout=60,
    )
    if resp.ok:
        classes = resp.json()
        if isinstance(classes, list) and classes:
            storage_class_id = classes[0].get("metadata", {}).get("id") or classes[0].get("id")

    yield ScaffoldContext(
        org=region_env.org,
        project=region_env.project,
        region=region_env.region,
        network_id=network_id,
        security_group_id=security_group_id,
        storage_class_id=storage_class_id,
    )

    for path in cleanup:
        _delete(region_session, base, path)
