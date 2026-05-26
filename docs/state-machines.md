# State Machines

The executable transition specification is maintained in
[architecture/state-machines.md](architecture/state-machines.md) and enforced by
`StateTransitionGuard`.

`StateTransitionGuardTest.exhaustivelyChecksEveryAggregateTransitionTable` iterates the
cartesian transition tables for data, grant, package, proxy and key states. Illegal
transitions consistently fail with `INVALID_STATE_TRANSITION`; service lifecycle tests
verify that revoke/rotation actions emit audit records and invalidated packages cannot be
downloaded.
