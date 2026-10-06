Add-Type @"
using System;
using System.Runtime.InteropServices;
public class CredMan {
  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
  public struct CREDENTIAL { public int Flags; public int Type; public string TargetName; public string Comment; public long LastWritten; public int CredentialBlobSize; public IntPtr CredentialBlob; public int Persist; public int AttributeCount; public IntPtr Attributes; public string TargetAlias; public string UserName; }
  [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  public static extern bool CredRead(string target, int type, int flags, out IntPtr cred);
  [DllImport("advapi32.dll")]
  public static extern void CredFree(IntPtr cred);
}
"@
$ptr = [IntPtr]::Zero
if (-not [CredMan]::CredRead("git:https://github.com", 1, 0, [ref]$ptr)) { Write-Output "NO_CREDENTIAL"; exit 1 }
$c = [Runtime.InteropServices.Marshal]::PtrToStructure($ptr, [type][CredMan+CREDENTIAL])
$token = [Runtime.InteropServices.Marshal]::PtrToStringUni($c.CredentialBlob, [int]($c.CredentialBlobSize / 2))
[CredMan]::CredFree($ptr)
if (-not $token) { Write-Output "EMPTY_TOKEN"; exit 1 }

$h = @{ Authorization = "Bearer $token"; Accept = "application/vnd.github+json"; "User-Agent" = "surrect-release" }
$token = $null
$notes = @'
## Bring your lost files back — and prove every one.

Deleted photos, a formatted drive, a memory card that went silent. Install, pick the drive, get your files back with their real names — plus a fingerprint proving each one is intact.

**What you get:** dual-engine recovery (Surrect's own fast engine + genuine PhotoRec 7.2), deleted-file listing with real folder paths, broken-video/archive reassembly, safe whole-disk copying, live-drive reading, health-checked drives, and a full proof report.

**Measured on a 1TB test:** 99.4% found, 0 false alarms from 20 decoys, 20/20 broken videos reassembled byte-perfect. Details in the repo (score.json).

**Install:** download `Surrect_0.1.0_x64-setup.exe` below, click through, done. No Python or tech skills needed.

Surrect's own code is MIT licensed. The bundled PhotoRec 7.2 binary is GPL v2+ (Christophe GRENIER) — see THIRD_PARTY.txt in the repo.
'@
$body = @{ tag_name = "v0.1.0"; name = "Surrect v0.1.0"; body = $notes; draft = $false; prerelease = $false } | ConvertTo-Json
$rel = Invoke-RestMethod -Uri "https://api.github.com/repos/Henoch4/Surrect/releases" -Method Post -Headers $h -Body ([System.Text.Encoding]::UTF8.GetBytes($body)) -ContentType "application/json"
Write-Output ("RELEASE id=" + $rel.id + " tag=" + $rel.tag_name)
$up = $rel.upload_url -replace '\{\?.*$', ''
$base = "C:\Users\Henoch\Documents\Programming Folder\file-recovery-study\surrect-desktop\src-tauri\target\release\bundle"
foreach ($f in @("$base\nsis\Surrect_0.1.0_x64-setup.exe", "$base\msi\Surrect_0.1.0_x64_en-US.msi")) {
    $a = Invoke-RestMethod -Uri ($up + "?name=" + [IO.Path]::GetFileName($f)) -Method Post `
        -Headers ($h + @{"Content-Type" = "application/octet-stream" }) -InFile $f
    Write-Output ("ASSET " + $a.name + " " + $a.size + " bytes")
}
Write-Output DONE
