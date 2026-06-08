"""Pin parent references on fuzzed cases to known-good values.

Without this, Schemathesis fills ``regionID``/``networkID``/body ``spec.*``
parent references with random values, so every request 404s before reaching
handler logic — we would be fuzzing the router, not the code under test. Here we
overwrite *only* the parent-reference fields (query params, path params, and the
parent-id keys inside the request body ``spec``) with real IDs, leaving every
other field free to be fuzzed.
"""

from __future__ import annotations

# Body ``spec`` keys that name a parent resource, mapped to the attribute on the
# scaffold context that holds the real ID. Only keys actually present in a
# generated body are overwritten, so this is safe across every v2 create/update
# schema regardless of which subset of parents it declares.
_SPEC_PARENT_KEYS = {
    "organizationId": "org",
    "projectId": "project",
    "regionId": "region",
    "networkId": "network_id",
    "storageClassId": "storage_class_id",
}

_QUERY_PINS = {
    "organizationID": "org",
    "projectID": "project",
    "regionID": "region",
    "networkID": "network_id",
}


def _value(ctx, attr):
    return getattr(ctx, attr, None)


def apply_overrides(case, ctx) -> None:
    method = case.method.upper()

    if isinstance(case.query, dict):
        for key, attr in _QUERY_PINS.items():
            if key in case.query and _value(ctx, attr) is not None:
                # Collection filters are declared as arrays in the spec.
                case.query[key] = [_value(ctx, attr)]

    if isinstance(case.path_parameters, dict):
        pp = case.path_parameters
        if "regionID" in pp:
            pp["regionID"] = ctx.region
        if "networkID" in pp and ctx.network_id is not None:
            pp["networkID"] = ctx.network_id
        # Pin the security group on read/update so they exercise real handler
        # logic; leave it fuzzed on DELETE so the scaffold survives the run.
        if "securityGroupID" in pp and method in ("GET", "PUT") and ctx.security_group_id is not None:
            pp["securityGroupID"] = ctx.security_group_id

    body = case.body
    if isinstance(body, dict) and isinstance(body.get("spec"), dict):
        spec = body["spec"]
        for key, attr in _SPEC_PARENT_KEYS.items():
            if key in spec and _value(ctx, attr) is not None:
                spec[key] = _value(ctx, attr)
