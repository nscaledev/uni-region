"""Layer-1 input-robustness fuzzing of the Region ``/api/v2`` API.

Targets the simulated-provider deployment. Each in-scope operation is driven
with Schemathesis-generated inputs (bodies, query params, headers) while parent
references are pinned to real resources, and every response is checked for the
absence of server errors plus OpenAPI conformance.

Scope:
  * IN  - non-hidden, oauth2 (bearer) ``/api/v2`` operations: networks,
          security groups, load balancers, ssh certificate authorities,
          region images (read), file storage and storage classes.
  * OUT - ``/api/v2/servers*`` (internal mTLS API, separate trust boundary) and
          the hidden ``/references/`` reference-management endpoints.
"""

from __future__ import annotations

import os
import pathlib

import schemathesis
from schemathesis import Config

from pinning import apply_overrides

SPEC_PATH = pathlib.Path(__file__).resolve().parents[2] / "pkg" / "openapi" / "server.spec.yaml"

MAX_EXAMPLES = int(os.environ.get("FUZZ_MAX_EXAMPLES", "50"))
SEED = int(os.environ.get("FUZZ_SEED", "0"))

config = Config.from_dict({"generation": {"max-examples": MAX_EXAMPLES}, "seed": SEED})

schema = (
    schemathesis.openapi.from_path(SPEC_PATH, config=config)
    .include(path_regex=r"^/api/v2/")
    .exclude(path_regex=r"/servers|/references/")
)


@schema.parametrize()
def test_region_v2_fuzz(case, region_env, region_session, scaffold):
    apply_overrides(case, scaffold)
    case.call_and_validate(
        base_url=region_env.base_url,
        session=region_session,
        headers={"Authorization": f"Bearer {region_env.token}"},
        verify=region_env.ca_cert,
    )
