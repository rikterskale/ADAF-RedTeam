<#
.SYNOPSIS
Creates dedicated, disposable-lab objects for ADAF-RedTeam Tier A certification.

.DESCRIPTION
Run only on a GOAD domain controller or management host with the ActiveDirectory
PowerShell module and domain-admin rights. The script is dry-run by default.
Use -Apply only after the coach verifies the isolated GOAD lab and snapshot.
It never uses, modifies, or grants rights to GOAD's existing training accounts.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)][string]$ExpectedDomain,
    [Parameter(Mandatory = $true)][switch]$IUnderstandThisIsAnIsolatedGOADLab,
    [switch]$Apply,
    [switch]$IncludeDcsyncRights,
    [switch]$IncludeLapsAcl,
    [string]$ProfileOuName = 'ADAF-Certification',
    [securestring]$AccountPassword
)

$ErrorActionPreference = 'Stop'

function Ensure-Ou([string]$Name, [string]$Path) {
    $dn = "OU=$Name,$Path"
    if (-not (Get-ADOrganizationalUnit -Identity $dn -ErrorAction SilentlyContinue)) {
        if ($PSCmdlet.ShouldProcess($dn, 'Create certification organizational unit')) {
            New-ADOrganizationalUnit -Name $Name -Path $Path -ProtectedFromAccidentalDeletion $true | Out-Null
        }
    }
    return $dn
}

function Ensure-User([string]$Name, [string]$Path, [bool]$NoPreauth) {
    $user = Get-ADUser -Filter "SamAccountName -eq '$Name'" -Properties DoesNotRequirePreAuth -ErrorAction SilentlyContinue
    if (-not $user) {
        if (-not $AccountPassword) { throw 'AccountPassword is required with -Apply to create dedicated test users.' }
        if ($PSCmdlet.ShouldProcess($Name, 'Create dedicated certification user')) {
            New-ADUser -Name $Name -SamAccountName $Name -Path $Path -Enabled $true -AccountPassword $AccountPassword -PasswordNeverExpires $true -DoesNotRequirePreAuth $NoPreauth | Out-Null
        }
    } elseif ($user.DoesNotRequirePreAuth -ne $NoPreauth) {
        if ($PSCmdlet.ShouldProcess($Name, 'Set certification preauthentication state')) { Set-ADAccountControl -Identity $user -DoesNotRequirePreAuth $NoPreauth }
    }
    return Get-ADUser -Identity $Name
}

function Ensure-Group([string]$Name, [string]$Path) {
    $group = Get-ADGroup -Filter "SamAccountName -eq '$Name'" -ErrorAction SilentlyContinue
    if (-not $group -and $PSCmdlet.ShouldProcess($Name, 'Create dedicated certification group')) {
        New-ADGroup -Name $Name -SamAccountName $Name -GroupScope Global -GroupCategory Security -Path $Path | Out-Null
    }
    return Get-ADGroup -Identity $Name
}

if (-not $IUnderstandThisIsAnIsolatedGOADLab) { throw 'Refusing to continue without the isolated-GOAD acknowledgement.' }
Import-Module ActiveDirectory -ErrorAction Stop
$domain = Get-ADDomain
if ($domain.DNSRoot -ne $ExpectedDomain) { throw "Connected domain '$($domain.DNSRoot)' does not equal ExpectedDomain '$ExpectedDomain'." }
if (-not $Apply) { Write-Host 'PLAN ONLY: No directory changes were made. Re-run with -Apply after the GOAD coach confirms the lab snapshot.'; exit 0 }

$root = $domain.DistinguishedName
$ou = Ensure-Ou -Name $ProfileOuName -Path $root
if (-not $AccountPassword) { $AccountPassword = Read-Host 'Password for new dedicated certification users' -AsSecureString }
$asrepPositive = Ensure-User -Name 'ADAF-Cert-AsrepNoPreauth' -Path $ou -NoPreauth $true
$asrepNegative = Ensure-User -Name 'ADAF-Cert-AsrepPreauth' -Path $ou -NoPreauth $false
$serviceUser = Ensure-User -Name 'ADAF-Cert-KerbService' -Path $ou -NoPreauth $false
$spn = "HTTP/adaf-cert-web.$ExpectedDomain"
if (-not ((Get-ADUser -Identity $serviceUser -Properties ServicePrincipalName).ServicePrincipalName -contains $spn)) {
    if ($PSCmdlet.ShouldProcess($serviceUser.SamAccountName, "Add dedicated SPN $spn")) { Set-ADUser -Identity $serviceUser -Add @{servicePrincipalName = $spn} }
}

$dcsyncGroup = Ensure-Group -Name 'ADAF-Cert-DcsyncReaders' -Path $ou
$lapsGroup = Ensure-Group -Name 'ADAF-Cert-LapsReaders' -Path $ou
$gmsaGroup = Ensure-Group -Name 'ADAF-Cert-GmsaReaders' -Path $ou
$inventoryGroup = Ensure-Group -Name 'ADAF-Cert-InventoryGroup' -Path $ou
if ($PSCmdlet.ShouldProcess($inventoryGroup.SamAccountName, 'Add dedicated member for inventory test')) { Add-ADGroupMember -Identity $inventoryGroup -Members $asrepNegative -ErrorAction SilentlyContinue }

$lapsComputer = Get-ADComputer -Filter "SamAccountName -eq 'ADAF-Cert-Laps01`$'" -ErrorAction SilentlyContinue
if (-not $lapsComputer -and $PSCmdlet.ShouldProcess('ADAF-Cert-Laps01', 'Create dedicated certification computer object')) { New-ADComputer -Name 'ADAF-Cert-Laps01' -SamAccountName 'ADAF-Cert-Laps01$' -Path $ou | Out-Null }
$lapsComputer = Get-ADComputer -Identity 'ADAF-Cert-Laps01'
$gmsa = Get-ADServiceAccount -Identity 'ADAF-Cert-Gmsa' -ErrorAction SilentlyContinue
if (-not $gmsa -and $PSCmdlet.ShouldProcess('ADAF-Cert-Gmsa', 'Create dedicated certification gMSA')) { New-ADServiceAccount -Name 'ADAF-Cert-Gmsa' -DNSHostName "ADAF-Cert-Gmsa.$ExpectedDomain" -PrincipalsAllowedToRetrieveManagedPassword $gmsaGroup | Out-Null }
$gmsa = Get-ADServiceAccount -Identity 'ADAF-Cert-Gmsa'

if ($IncludeDcsyncRights) {
    $acl = Get-Acl -Path "AD:$root"
    foreach ($right in @('1131f6aa-9c07-11d1-f79f-00c04fc2dcd2', '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2')) {
        $guid = [guid]$right
        $existing = $acl.Access | Where-Object {
            $_.IdentityReference.Value -eq $dcsyncGroup.SID.Value -and
            $_.ObjectType -eq $guid -and $_.ActiveDirectoryRights.ToString().Contains('ExtendedRight')
        }
        if (-not $existing) { $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule($dcsyncGroup.SID, 'ExtendedRight', 'Allow', $guid))) }
    }
    if ($PSCmdlet.ShouldProcess($root, 'Write dedicated DCSync-reader ACL rules')) { Set-Acl -Path "AD:$root" -AclObject $acl }
}
if ($IncludeLapsAcl) {
    $acl = Get-Acl -Path "AD:$($lapsComputer.DistinguishedName)"
    $existing = $acl.Access | Where-Object {
        $_.IdentityReference.Value -eq $lapsGroup.SID.Value -and $_.ActiveDirectoryRights.ToString().Contains('GenericAll')
    }
    if (-not $existing) { $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule($lapsGroup.SID, 'GenericAll', 'Allow'))) }
    if ($PSCmdlet.ShouldProcess($lapsComputer.DistinguishedName, 'Grant GenericAll to the dedicated LAPS reader group')) { Set-Acl -Path "AD:$($lapsComputer.DistinguishedName)" -AclObject $acl }
}

$profilePath = Join-Path (Get-Location) 'certification-work\goad-profile.env.ps1'
New-Item -ItemType Directory -Path (Split-Path $profilePath) -Force | Out-Null
@(
    '# Generated GOAD certification profile. Fill only coach-approved bind/source values.'
    '$env:ADAF_RT_LAB = ''1'''
    "`$env:ADAF_RT_LAB_DOMAIN = '$ExpectedDomain'"
    '# $env:ADAF_RT_LAB_DC = ''<GOAD DC IP or FQDN>'''
    '# $env:ADAF_RT_LAB_SOURCE_ADDR = ''<operator VM IP>'''
    '# $env:ADAF_RT_LAB_BIND_USER = ''<dedicated bind UPN>'''
    "`$env:ADAF_RT_LAB_ASREP_ROASTABLE_USER = '$($asrepPositive.SamAccountName)'"
    "`$env:ADAF_RT_LAB_ASREP_PREAUTH_USER = '$($asrepNegative.SamAccountName)'"
    "`$env:ADAF_RT_LAB_KERBEROAST_SPN = '$spn'"
    "`$env:ADAF_RT_LAB_KERBEROAST_MISSING_SPN = 'HTTP/does-not-exist.$ExpectedDomain'"
    "`$env:ADAF_RT_LAB_TARGET_PRINCIPAL = '$($dcsyncGroup.SID.Value)'  # DCSync only when -IncludeDcsyncRights was used"
    "# LAPS: set TARGET_PRINCIPAL to '$($lapsGroup.SID.Value)' and use this computer DN when -IncludeLapsAcl was used"
    "`$env:ADAF_RT_LAB_LAPS_COMPUTER_DN = '$($lapsComputer.DistinguishedName)'"
    "# gMSA: set TARGET_PRINCIPAL to '$($gmsaGroup.SID.Value)' and use this gMSA DN"
    "`$env:ADAF_RT_LAB_GMSA_DN = '$($gmsa.DistinguishedName)'"
    "`$env:ADAF_RT_LAB_PRIV_GROUP_DN = '$($inventoryGroup.DistinguishedName)'"
) | Set-Content -LiteralPath $profilePath -Encoding utf8
Write-Host "PASS  Dedicated GOAD certification objects are ready in $ou"
Write-Host "PASS  Profile hints written to $profilePath (contains no passwords)"
Write-Host 'NEXT  Coach verifies values and expected verdicts before running the ADAF preflight.'
