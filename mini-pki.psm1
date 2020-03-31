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

$index = "$ca_root_dir/index.txt"
$serial = "$ca_root_dir/serial"
$crlnumber = "$ca_root_dir/crlnumber"

$files = @($index, $serial)

function create-ca {
  New-Item -ItemType "directory" -Path $directories -Force
  New-Item -ItemType "file" -Path $files -Force
  Add-Content -Path $serial -Value "01"                                                                                                               
  
  $subject = @("C=FR", "O=EPITA", "OU=SRS", "E=srs@epita.com", "CN=root")
  $subject_string = "/" + ($subject -join "/")

  openssl req -new -outform "PEM" -sha256 -newkey rsa:2048 -subj $subject_string -keyout "$ca_private_dir/caprivatekey.pem" -out "$ca_cert_dir/cacert.pem" -extensions "v3_ca" -days 3000 -x509 -nodes  

  openssl rsa -in "$ca_private_dir/caprivatekey.pem" -pubout -out "$ca_public_dir/capublickey.pem"
  icacls ($current_drive_letter + ":/$ca_private_dir") /grant:r Administrateur:F /T
}

function gencrl {
  New-Item -ItemType "file" -Path $crlnumber -Force
  Add-Content -Path $crlnumber -Value "01"

  openssl ca -gencrl -keyfile "$ca_private_dir/caprivatekey.pem" -cert "$ca_cert_dir/cacert.pem" -out "$ca_root_dir/crl.pem"  
}

$functions = @{
  "create-ca" = (Get-Item "function:create-ca").ScriptBlock
  "gencrl" = (Get-Item "function:gencrl").ScriptBlock
}

function mini-pki {
  param($action)

  Write-Output "Doing action $action"
  $functions[$action].Invoke()
}
Export-ModuleMember -Function mini-pki