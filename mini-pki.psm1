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
function mini-pki {
  param(
    $action
      )
  Write-Output "Doing action $action"
}
Export-ModuleMember -Function mini-pki