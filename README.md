# Token Binding Showcase (Managed Identity, mTLS PoP)

A single .NET 8 console app that acquires a Managed Identity token for **Azure Key Vault** -
a classic **bearer** token, plus a **token-bound (mTLS Proof-of-Possession)** token three ways.
The menu **loops** (stays open between calls) and prints the **full token** so you can copy it
and replay it from another VM.

| # | Path | Token |
| - | ---- | ----- |
| 1 | **Classic MSI (v1)** | Plain **bearer** token from a single raw call to local IMDS - the "before": simple, but stealable / replayable. |
| 2 | **MSAL .NET** | Bound **mtls_pop** token via `ManagedIdentityApplication` + `.WithMtlsProofOfPossession().WithAttestationSupport()`, then a manual mTLS Key Vault call. |
| 3 | **Microsoft Identity Web** | Bound, config-driven `IDownstreamApi` (`"ProtocolScheme": "MTLS_POP"`) - acquisition, binding cert, and mTLS call handled for you. |
| 4 | **Azure Key Vault SDK** | `ManagedIdentityCredential` passed to `SecretClient`; binding applied transparently on a supported host. |

## Download & run (prebuilt)

Grab **`TokenBindingShowcase.exe`** from the [Releases](../../releases) page, copy it onto your
Trusted Launch / Confidential VM, and run it - it's a **self-contained single file** (no .NET install needed):

```powershell
.\TokenBindingShowcase.exe        # interactive menu (loops until you choose 0)
.\TokenBindingShowcase.exe 5      # run the bound paths (MSAL + Identity Web + AKV SDK)
```

## Configure

Values are **pre-baked** (in `appsettings.json` and as defaults in `AppSettings.cs`) so the exe runs as-is:

| Setting | Value |
| ------- | ----- |
| `UserAssignedClientId` | `71d22d68-0415-4801-9a68-f3916c8968d0` |
| `AzureRegion` | `westcentralus` |
| `KeyVaultUrl` | `https://msidlabs.vault.azure.net/` |
| `SecretName` | `mytbsecret` |

These are **non-secret identifiers** (a managed-identity client id only yields tokens on the VM it's
assigned to). Override any of them by dropping an `appsettings.json` next to the exe, or via environment
variables, e.g. `TokenBinding__KeyVaultUrl=...`, `TokenBinding__UserAssignedClientId=...`
(leave empty for a system-assigned identity).

## Run

```powershell
dotnet run                 # interactive menu (loops; 0 to exit)
dotnet run -- 1            # Classic MSI - bearer token
dotnet run -- 2            # MSAL - bound mtls_pop
dotnet run -- 3            # Microsoft Identity Web
dotnet run -- 4            # Azure Key Vault SDK
dotnet run -- 5            # all bound paths (2-4)
```

## Where it actually works

The bound (KeyGuard-backed) Managed Identity flow needs a **Trusted Launch or
Confidential VM with VBS/KeyGuard**, the Managed Identity assigned, and
**Key Vault Secrets User** RBAC on the target vault. On a normal dev box the
acquisition will fail with a managed-identity error - that is expected; the code
paths are the point of this sample.

- A **403** from Key Vault is an **RBAC** result (assign the role), not a binding failure.
- A **401** indicates an auth / token-binding problem.

## Package notes

- MSAL (`Microsoft.Identity.Client` + `Microsoft.Identity.Client.KeyAttestation`)
  and Microsoft Identity Web are referenced from public NuGet and fully exercise
  the bound flow on a supported host.
- The **Azure Key Vault SDK** token-binding support is **preview**: the
  `DisableMtlsProofOfPossession` option and the bound behavior require the preview
  package feed (`Azure.Core 1.60.0-alpha...`). The public versions referenced here
  compile and run; pin the preview feed for true binding via the Azure SDK.
