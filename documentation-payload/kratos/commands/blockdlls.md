+++
title = "blockdlls"
chapter = false
weight = 23
+++

## Summary
Toggle the BlockDLLs mitigation policy for all subsequently spawned sacrifice processes.

When enabled, `PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON` is applied to every process created by `spawn`, `spawnas`, and `execute_assembly`. This prevents non-Microsoft signed DLLs (including EDR hooking DLLs) from loading into the sacrifice process.

## Arguments
| Name | Required | Description |
|------|----------|-------------|
| `Block` | Yes | Enable (`true`) or disable (`false`) BlockDLLs. Default: `true` |

## Usage
Select via modal popup in the Mythic UI.

## Notes
- State is session-level: persists until changed or agent restarts.
- No elevated privileges required to set the policy.
- PPID spoofing and BlockDLLs are compatible (both use `UpdateProcThreadAttribute` on the same `STARTUPINFOEX`).
- Not compatible with `CreateProcessWithLogonW` used by `spawnas` (PPID spoof also not applied there).
- Detectable: even without userland hooks, EDRs can observe `PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON` via kernel `PsSetCreateProcessNotifyRoutine` callbacks.
- ATT&CK: T1562.001 (Impair Defenses: Disable or Modify Tools)
