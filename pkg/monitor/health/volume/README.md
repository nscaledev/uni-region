# Volume Health

`pkg/monitor/health/volume` polls the provider-neutral `ObserveVolume`
contract and projects provider truth into Region `Volume` status.

The checker owns only observed state:

- `status.size`
- the coarse `Healthy` condition

The Volume controller remains the sole owner of the `Available` provisioning
condition and all create/delete intent. Creating, available, attaching,
attached, detaching, and updating provider states are healthy. Provider error,
unexpected provider deletion, and confirmed provider absence are degraded. An
unknown provider state has unknown health. Provider request failures preserve
the last observed size and make current health unknown. Provider absence only
degrades health after the controller records `Available=True/Provisioned`.
Before provisioning completes, absence is expected and does not set health.

Every health transition is logged with its previous and new status, reason, and
message. Logs also include Volume, organization, and region identifiers.
Confirmed absence clears observed size. The checker never imports Cinder types
or performs provider mutations. It removes the obsolete Volume `Active`
condition when it updates status.

Provider resolution results, including failures, are cached by region for one
poll cycle. A provider initialization failure is attempted once per region, not
once per Volume.
