# Volume Health

`pkg/monitor/health/volume` polls the provider-neutral `ObserveVolume`
contract and projects provider truth into Region `Volume` status.

The checker owns only observed state:

- `status.size`
- the domain-typed Volume phase carried by the generic `Active` condition
- the coarse `Healthy` condition

The Volume controller remains the sole owner of the `Available` provisioning
condition and all create/delete intent. Known non-error provider phases are
healthy without being collapsed into health reasons; `error` and confirmed
provider absence are degraded, while an unknown provider phase has unknown
health. Provider request failures preserve the last successful observation.

Every phase and health transition is logged with Volume, organization, and
region identifiers. Confirmed absence clears observed size. The checker never
imports Cinder types or performs provider mutations.
