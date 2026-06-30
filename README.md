# Token Binding Showcase (Managed Identity, mTLS PoP)

A single .NET 8 console app that shows the **KeyGuard key** behind token binding (and why a software
key isn't enough), then acquires a Managed Identity token for **Azure Key Vault** - a classic
**bearer** token, plus a **token-bound (mTLS Proof-of-Possession)** token three ways. The menu
**loops** (stays open between calls) and prints the **full token** so you can copy it and replay it
from another VM. Option **9** is the attacker side - paste a stolen token and it calls Key Vault as a
bearer (a plain bearer is accepted; a bound token is rejected).

| # | Path | What it shows |
| - | ---- | ------------- |
| 1 | **KeyGuard key** | Creates a VBS-isolated CNG key (`DemoKeyGuardKey`), lists it, and proves the private key **cannot be exported**. |
| 2 | **Non-KeyGuard key** | Creates an ordinary software key (`DemoSoftwareKey`) and shows its private key **can** be exported - what KeyGuard prevents. |
| 3 | **Certs from both keys** | Mints a self-signed cert from each into `CurrentUser\My`; open `certmgr.msc` to compare (one non-exportable, one exportable). |
| 4 | **Classic MSI (v1)** | Plain **bearer** token from a single raw call to local IMDS - the "before": simple, but stealable / replayable. |
| 5 | **MSAL .NET** | Bound **mtls_pop** token via `ManagedIdentityApplication` + `.WithMtlsProofOfPossession().WithAttestationSupport()`, then a manual mTLS Key Vault call. |
| 6 | **Microsoft Identity Web** | Bound, config-driven `IDownstreamApi` (`"ProtocolScheme": "MTLS_POP"`) - acquisition, binding cert, and mTLS call handled for you. |
| 7 | **Azure Key Vault SDK** | `ManagedIdentityCredential` passed to `SecretClient`; binding applied transparently on a supported host. |

## Download & run (prebuilt)

Grab **`TokenBindingShowcase.exe`** from the [Releases](../../releases) page, copy it onto your
Trusted Launch / Confidential VM, and run it - it's a **self-contained single file** (no .NET install needed):

```powershell
.\TokenBindingShowcase.exe        # interactive menu (loops until you choose 0)
.\TokenBindingShowcase.exe 8      # run the bound paths (MSAL + Identity Web + AKV SDK)
```

## Configure

Values are **pre-baked** (in `appsettings.json` and as defaults in `AppSettings.cs`) so the exe runs as-is:

| Setting | Value |
| ------- | ----- |
| `UserAssignedClientId` | `71d22d68-0415-4801-9a68-f3916c8968d0` |
| `AzureRegion` | `westcentralus` |
| `KeyVaultUrl` | `https://tokenbindingdemo.vault.azure.net/` |
| `SecretName` | `tbsecret` |

These are **non-secret identifiers** (a managed-identity client id only yields tokens on the VM it's
assigned to). Override any of them by dropping an `appsettings.json` next to the exe, or via environment
variables, e.g. `TokenBinding__KeyVaultUrl=...`, `TokenBinding__UserAssignedClientId=...`
(leave empty for a system-assigned identity).

## Run

```powershell
dotnet run                 # interactive menu (loops; 0 to exit)
dotnet run -- 1            # KeyGuard key (create / list / export-fails)
dotnet run -- 2            # Non-KeyGuard key (create / list / export-succeeds)
dotnet run -- 3            # Certs from both keys -> CurrentUser\My
dotnet run -- 4            # Classic MSI - bearer token
dotnet run -- 5            # MSAL - bound mtls_pop
dotnet run -- 6            # Microsoft Identity Web
dotnet run -- 7            # Azure Key Vault SDK
dotnet run -- 8            # all bound paths (5-7)
dotnet run -- 9            # Replay a stolen token (attacker) - paste + call Key Vault
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
