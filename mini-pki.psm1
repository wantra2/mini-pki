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


function create-ca {
  $directories = @("miniCA", "miniCA\private", "miniCA\public", "miniCA\cert", "miniCA\csr")
  $files = @("miniCA\index.txt", "miniCA\openssl.cnf")
  New-Item -ItemType "directory" -Path $directories -Force
  icacls "miniCA\private" /grant:r Administrateur:F /T
  New-Item -ItemType "file" -Path $files -Force
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