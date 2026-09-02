# Volume Health

`pkg/monitor/health/volume` asks the provider to update a deep copy of the
Region `Volume` with its current backing-resource state, then persists one
optimistic status patch.

The provider owns provider-state mapping, observed size, missing-volume
semantics, and health messages. The checker owns orchestration, patching, and
transition logging.

The Volume controller remains the sole owner of the `Available` provisioning
condition and all create/delete intent. Provider request or observation errors
are logged and skipped, preserving the last observed status. Provider absence
semantics are defined by the provider implementation.

Every health transition is emitted on the structured lifecycle stream.
The checker never imports provider SDK types.

Provider resolution results, including failures, are cached by region for one
poll cycle. A provider initialization failure is attempted once per region, not
once per Volume.
