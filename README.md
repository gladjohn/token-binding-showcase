# Token Binding Showcase (Managed Identity, mTLS PoP)

A single .NET 8 console app that acquires a **token-bound (mTLS Proof-of-Possession)**
Managed Identity token for **Azure Key Vault** three different ways:

| # | Path | How it binds |
| - | ---- | ------------ |
| 1 | **MSAL .NET** | `ManagedIdentityApplication` + `.WithMtlsProofOfPossession().WithAttestationSupport()`, then a manual mTLS Key Vault call with the binding certificate. |
| 2 | **Microsoft Identity Web** | Config-driven `IDownstreamApi` with `"ProtocolScheme": "MTLS_POP"` - acquisition, binding cert, and the mTLS call are handled for you. |
| 3 | **Azure Key Vault SDK** | `ManagedIdentityCredential` passed to `SecretClient`; binding is applied transparently on a supported host. |

## Download & run (prebuilt)

Grab **`TokenBindingShowcase.exe`** from the [Releases](../../releases) page, copy it onto your
Trusted Launch / Confidential VM, and run it - it's a **self-contained single file** (no .NET install needed):

```powershell
.\TokenBindingShowcase.exe        # interactive menu
.\TokenBindingShowcase.exe 4      # run all three paths
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
dotnet run                 # interactive menu
dotnet run -- 1            # MSAL
dotnet run -- 2            # Microsoft Identity Web
dotnet run -- 3            # Azure Key Vault SDK
dotnet run -- 4            # all three
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
