# C6 — CFG Unknown producer

Status: implemented on branch `dev`

## Scope

The second C6 slice applies the same opt-in ledger seam to CFG and indirect-target
recovery. `recover_control_flow(...)` keeps its legacy `ControlFlowReport` contract;
`recover_control_flow_with_evidence(...)` runs the same producer with an explicit
canonical ledger and returns `StaticControlFlowEvidence`.

Backend failure and incomplete indirect-target facts are emitted at their creation
sites through the shared recovery emitter. The old Pydantic Unknown remains in the
report, so existing thread/memory consumers and verdict JSON are unchanged.

## Boundary and refusal behavior

- Only canonical `UnknownFact` nodes are written; no dynamic observation or
  diagnostic hint can enter the CFG ledger.
- The canonical kind and scope are supplied by the recovery producer, not inferred
  later from a free-form `details` dictionary.
- Candidate target details remain explanation context until target-set provenance is
  migrated to typed premises. A target candidate is never upgraded to a closed proof
  by this sidecar.
- The old path remains available so a failed canonical emission cannot silently alter
  the established report; the opt-in path fails closed instead.

## Tests and next gate

`tests/static/unit/test_controlflow_evidence.py` injects a backend failure and checks
that the legacy report is equivalent while the sidecar contains one `CfgBackendFailure`
Unknown and no observation/hint. Existing CFG integration tests continue to exercise
indirect-target behavior.

The next C6 slice is thread lifecycle/synchronization. It must use the same emitter
without importing either dynamic or diagnostics, and it must preserve the old report
before any certificate consumer is migrated.
