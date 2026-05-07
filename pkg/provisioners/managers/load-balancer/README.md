# Load Balancer

`pkg/provisioners/managers/load-balancer` is intentionally unusual.

Provision is currently a scaffolded no-op that yields, while deprovision still
has real work to do:

- release identity-side quota allocation on teardown

So this package is mostly an accounting-edge maintainer rather than a full
provider lifecycle driver today.

## Caveats

- This asymmetry is easy to miss: create/update semantics are currently driven
  elsewhere, but deprovision still carries cleanup obligations here.

## TODO

- Either implement the intended provider lifecycle here or retire the remaining
  teardown-only allocation cleanup path if the architecture moves elsewhere for
  good.
