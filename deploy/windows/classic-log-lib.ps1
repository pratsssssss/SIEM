# Same rule as Phase 7: ordinary logon types keep write access and lose read access.
# Event Log Readers (S-1-5-32-573) stays, because it is an empty, deliberate delegation group.
function Get-RestrictedAccess([string] $Sddl) {
  $Sddl -replace '\(A;;0x3;;;(IU|SU|S-1-5-3|S-1-5-33)\)', '(A;;0x2;;;$1)'
}

# Returns the access mask a SID holds in an SDDL string, summing its allow entries.
function Get-SddlMask([string] $Sddl, [string] $Sid) {
  $Descriptor = New-Object Security.AccessControl.RawSecurityDescriptor $Sddl
  $Mask = 0
  foreach ($Ace in $Descriptor.DiscretionaryAcl) {
    if ($Ace.AceType -eq 'AccessAllowed' -and $Ace.SecurityIdentifier.Value -eq $Sid) { $Mask = $Mask -bor $Ace.AccessMask }
  }
  $Mask
}
