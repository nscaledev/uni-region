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
import secrets
import time

import pytest
import requests

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
