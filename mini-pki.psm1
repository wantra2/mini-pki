<#
 .Synopsis
  This module provides tools to make a PKI

 .Description
  The function mini-pki can take different arguments in order to build a PKI

 .Parameter action
  Define which action is to be made.
  Available actions are: 
    create-ca -> Creates Root CA

 .Example
  mini-pki create-ca
  
#>
$current_drive_letter = (get-location).Drive.Name

$ca_root_dir = "/miniCA"
$ca_private_dir = "$ca_root_dir/private"
$ca_public_dir = "$ca_root_dir/public"
$ca_cert_dir = "$ca_root_dir/cert"
$ca_csr_dir = "$ca_root_dir/csr"

$directories = @($ca_root_dir, $ca_private_dir, $ca_public_dir, $ca_cert_dir, $ca_csr_dir)

$database = "$ca_root_dir/ca.db.index"
$serial = "$ca_root_dir/ca.db.serial"
$randfile = "$ca_root_dir/ca.db.rand"

$files = @($database, $serial, $randfile)

function create-ca {

  New-Item -ItemType "directory" -Path $directories -Force
  New-Item -ItemType "file" -Path $files -Force

  openssl.exe genrsa -des3 -out "$ca_private_dir/ca_private_key.pem" 2048

  icacls ($current_drive_letter + ":/$ca_private_dir") /grant:r Administrateur:F /T
}

$functions = @{
  "create-ca" = (Get-Item "function:create-ca").ScriptBlock
}

function mini-pki {
  param($action)

  Write-Output "Doing action $action"
  $functions[$action].Invoke()
}
Export-ModuleMember -Function mini-pki