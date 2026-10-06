| Command | Kind | Scope | Verdict | Meaning | Time (s) | As expected |
|---|---|---|---|---|---|---|
| Reach_DelegationChainDepth2 | run | main | SAT | reachable | 25.0 | yes |
| Reach_RevokedParentWithLiveChild | run | main | SAT | reachable | 15.8 | yes |
| Reach_RoleMismatchDelegation | run | main | SAT | reachable | 10.8 | yes |
| Rich_AllMechanismsInOneTrace | run | main | TIMEOUT | TIMEOUT | 1800 | — |
| Reach_DelegationChainDepth2_small | run | small | SAT | reachable | 12.0 | yes |
| Reach_ParentReissuedAfterLapse | run | small | SAT | reachable | 221.1 | yes |
| P1_TokenUniqueness | check | main | UNSAT | holds (no counterexample) | 32.7 | yes |
| P2_StoredState | check | main | SAT | counterexample | 63.1 | yes |
| P3_AuthCorrectness | check | main | UNSAT | holds (no counterexample) | 308.5 | yes |
| R_Revocation | check | main | UNSAT | holds (no counterexample) | 106.2 | yes |
| R1_RootTokensMatchPolicyRoles | check | main | TIMEOUT | TIMEOUT | 1800 | — |
| R2_DelegatedTokensMatchPolicyRoles | check | main | SAT | counterexample | 7.8 | yes |
| P2_AtDerivation | check | small | UNSAT | holds (no counterexample) | 373.8 | yes |
| P2_EvaluatedChain | check | small | UNSAT | holds (no counterexample) | 1145.1 | yes |
| R_ReissueOutcome | check | small | UNSAT | holds (no counterexample) | 9210.0 | yes |
| WalkExpiryRedundant | check | small | UNSAT | holds (no counterexample) | 5433.1 | yes |
| F2_OpsNeverGrowWithinGeneration | check | small | TIMEOUT | TIMEOUT | 1800 | — |
| A1_NonDelegationChangesOnlyByObjectOwner | check | small | UNSAT | holds (no counterexample) | 196.1 | yes |
| A2_DelegationOnlyByParentHolder | check | small | UNSAT | holds (no counterexample) | 177.5 | yes |
| A3_RevocationOnlyByObjectOwner | check | small | UNSAT | holds (no counterexample) | 66.5 | yes |
| A4_NoUnattributedChange | check | small | UNSAT | holds (no counterexample) | 193.3 | yes |
