| Command | Kind | Scope | Result | Solve time (s) | As expected | Source |
|---|---|---|---|---|---|---|
| Reach_DelegationChainDepth2 | run | main | reachable | 25 | yes | main |
| Reach_DelegationChainDepth2_small | run | small | reachable | 12 | yes | main |
| Reach_RevokedParentWithLiveChild | run | main | reachable | 16 | yes | main |
| Reach_ParentReissuedAfterLapse | run | small | reachable | 221 | yes | main |
| Reach_RoleMismatchDelegation | run | main | reachable | 11 | yes | main |
| Rich_AllMechanismsInOneTrace | run | main | reachable | 1355 | yes | rerun |
| P1_TokenUniqueness | check | main | holds | 33 | yes | main |
| P2_StoredState | check | main | counterexample | 63 | yes | main |
| P2_AtDerivation | check | small | holds | 374 | yes | main |
| P2_EvaluatedChain | check | small | holds | 1145 | yes | main |
| P3_AuthCorrectness | check | main | holds | 308 | yes | main |
| R_Revocation | check | main | holds | 106 | yes | main |
| R_ReissueOutcome | check | small | holds | 2140 | yes | timing |
| WalkExpiryRedundant | check | small | holds | 309 | yes | rerun |
| F2_OpsNeverGrowWithinGeneration | check | small | holds | 4420 | yes | timing |
| A1_NonDelegationChangesOnlyByObjectOwner | check | small | holds | 196 | yes | main |
| A2_DelegationOnlyByParentHolder | check | small | holds | 178 | yes | main |
| A3_RevocationOnlyByObjectOwner | check | small | holds | 66 | yes | main |
| A4_NoUnattributedChange | check | small | holds | 193 | yes | main |
| R1_RootTokensMatchPolicyRoles | check | small | holds | 64 | yes | rerun |
| R2_DelegatedTokensMatchPolicyRoles | check | main | counterexample | 8 | yes | main |
