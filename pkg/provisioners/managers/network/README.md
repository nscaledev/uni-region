# Network

`pkg/provisioners/managers/network` provisions cloud networks once the backing
identity/service-principal context is ready.

Distinctive behaviour:

- blocks on parent identity readiness before provider create/delete
- deletes identity-side quota allocation on deprovision for `v2` networks only
- carries explicit `v1` compatibility debt in that allocation cleanup path

This package is where the hidden service-principal edge behind `Network v2`
turns into provider-scoped network creation.

## TODO

- Remove the `v1` compatibility branch in deprovision once legacy networks no
  longer need to coexist with discrete `v2` allocation cleanup.
