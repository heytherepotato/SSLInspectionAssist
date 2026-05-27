# bcrypt proxy DLL — CA bundle patcher

A drop-in `bcrypt.dll` proxy that intercepts an application's Mozilla CA bundle
(embedded in the executable) and replaces the first certificate slot with your
own CA cert. This lets you MITM TLS traffic from apps that bundle their own
trust store instead of using the Windows certificate store.

All real `BCrypt*` calls are forwarded transparently to
`C:\Windows\System32\bcrypt.dll`.

---

## Files to deploy

Place these files in the **same folder as the target executable**:

```
<app folder>\
    bcrypt.dll          ← this proxy DLL
    ca-cert.pem         ← your CA cert in PEM format (see below)
    bcrypt_hook.cfg     ← optional; omit for first-run discovery mode
```

---

## Workflow

### Step 1 — Discovery run (no config file needed)

Drop `bcrypt.dll` and `ca-cert.pem` next to the app. Do **not** create
`bcrypt_hook.cfg` yet.

Run the app and trigger any outbound HTTPS connection, then close it.

A log file is written to `<app folder>\logs\ring_<date>_<pid>.log`.
Search it for a line like:

```
[bundle] DISCOVERY: myapp.exe -- marker at RVA 0x4F100B -- add BundleMarkerRVA=0x4F100B to bcrypt_hook.cfg
```

### Step 2 — Create the config file

Create `bcrypt_hook.cfg` next to the DLL using the RVA from the log:

```ini
# bcrypt_hook.cfg
BundleMarkerRVA=0x4F100B
```

### Step 3 — Patch run

Run the app again. The DLL will probe the known address directly (O(1), no
scan) and inject your cert within milliseconds of the first outbound connect.

Log line to confirm success:

```
[bundle] PATCHED: CA cert injected into Mozilla bundle
```

---

## Obtaining your CA cert (`ca-cert.pem`)

### Option A — mitmproxy

1. Install mitmproxy: https://mitmproxy.org  
2. Start it once to generate its CA:
   ```
   mitmproxy
   ```
3. The CA cert is generated at:
   ```
   %USERPROFILE%\.mitmproxy\mitmproxy-ca-cert.pem
   ```
4. Copy it:
   ```powershell
   Copy-Item "$env:USERPROFILE\.mitmproxy\mitmproxy-ca-cert.pem" ".\ca-cert.pem"
   ```

### Option B — Fiddler (Classic / Fiddler2)

Fiddler's root CA is stored in the Windows **Trusted Root Certification
Authorities** store under the friendly name **DO_NOT_TRUST_FiddlerRoot**.

#### Export with PowerShell (recommended)

```powershell
# Find the cert
$cert = Get-ChildItem Cert:\LocalMachine\Root |
        Where-Object { $_.Subject -like '*FiddlerRoot*' } |
        Select-Object -First 1

if (-not $cert) {
    # Try current user store
    $cert = Get-ChildItem Cert:\CurrentUser\Root |
            Where-Object { $_.Subject -like '*FiddlerRoot*' } |
            Select-Object -First 1
}

if (-not $cert) { Write-Error "FiddlerRoot cert not found. Open Fiddler and enable HTTPS decryption first."; exit 1 }

# Export as DER then convert to PEM
$derPath = [System.IO.Path]::GetTempFileName()
$cert.Export('Cert') | Set-Content $derPath -Encoding Byte

$derBytes = [System.IO.File]::ReadAllBytes($derPath)
$b64 = [System.Convert]::ToBase64String($derBytes)

# Wrap in PEM header/footer with 64-char lines
$lines = for ($i = 0; $i -lt $b64.Length; $i += 64) {
    $b64.Substring($i, [Math]::Min(64, $b64.Length - $i))
}
$pem = "-----BEGIN CERTIFICATE-----`n" +
       ($lines -join "`n") +
       "`n-----END CERTIFICATE-----`n"

Set-Content -Path ".\ca-cert.pem" -Value $pem -Encoding ASCII
Remove-Item $derPath

Write-Host "ca-cert.pem written ($($derBytes.Length) DER bytes)"
```

#### Export via certmgr (manual)

1. Run `certmgr.msc`
2. Navigate to **Trusted Root Certification Authorities → Certificates**
3. Find **DO_NOT_TRUST_FiddlerRoot**
4. Right-click → **All Tasks → Export**
5. Select **Base-64 encoded X.509 (.CER)** format
6. Save as `ca-cert.pem` (the `.cer` Base-64 format is valid PEM)

#### Trigger cert generation (if not yet present)

Open Fiddler → **Tools → Options → HTTPS** → check **Decrypt HTTPS traffic**
→ click **Actions → Trust Root Certificate** → restart Fiddler.
The cert will now appear in the certificate store.

---

## Config file reference

`bcrypt_hook.cfg` — plain text, `Key=Value`, one per line.
Lines starting with `#` or `;` are comments.

| Key | Value | Default |
|-----|-------|---------|
| `BundleMarkerRVA` | RVA (hex `0x...` or decimal) of the `## Certificate data from Mozilla` marker in the exe | `0` (discovery mode) |

Example:
```ini
; Obtained from discovery run on 2026-05-27
BundleMarkerRVA=0x4F100B
```

---

## Log file

Logs are written to `<app folder>\logs\ring_YYYYMMDD_HHMMSS_<pid>.log`.

Key log messages:

| Message | Meaning |
|---------|---------|
| `[config] bcrypt_hook.cfg not found -- running in discovery mode` | No config; will scan |
| `[config] BundleMarkerRVA=0x... (fast patch mode)` | Config loaded OK |
| `[bundle] DISCOVERY: ... marker at RVA 0x...` | Found marker; copy RVA to config |
| `[bundle] PATCHED: CA cert injected into Mozilla bundle` | Success |
| `[bundle] cert not found: ...\ca-cert.pem` | Missing cert file |
| `[bundle] cert size suspicious: N` | Cert file empty or > 4000 bytes |
| `[bundle] cert (N) too big for slot (M)` | Cert larger than first certificate slot |
| `[hook] connect hook installed` | ws2_32!connect hooked via MinHook |

---

## Troubleshooting

**No log file created**  
The `logs\` subdirectory is created next to `bcrypt.dll`. Ensure the process
has write access to that directory.

**`[bundle] Mozilla marker not found`**  
The app may compress or encrypt its resources, or the bundle may be in a
separate data file rather than embedded in the main exe.

**`[bundle] cert too big for slot`**  
The slot size equals the gap between the first and second `BEGIN CERTIFICATE`
lines. Try a CA cert with a shorter base64 body, or use a 2048-bit RSA CA
instead of 4096-bit.

**App crashes on startup**  
The app may verify the integrity of its embedded bundle before the hook fires.
Try setting `BundleMarkerRVA` to trigger the fast (1 ms poll) path so the
patch lands before verification.

**Fiddler cert not in store**  
Run Fiddler at least once with HTTPS decryption enabled. If the PowerShell
script finds nothing, check both `Cert:\LocalMachine\Root` and
`Cert:\CurrentUser\Root`.
