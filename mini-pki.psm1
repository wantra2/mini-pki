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

<# params:
	csr: The csr file name
	key: The keys files name
    Path: Optionnal, the path for the miniCA directory
#>
function user_req {
	Param (
		[Parameter(mandatory=$true)]	[String]$Key,
		[Parameter(mandatory=$true)]	[String]$Csr,
		[Parameter(mandatory=$false)] 	[String]$Path = "miniCA/"
	)
	
	openssl req -new -newkey rsa:2048 -sha256 `
    -keyout $Path"private\"$Key -out $Path"csr\"$Csr -config $Path"test.cnf"
}

function get_issuer_infos {
	Param ($File)
	$issuer_infos = openssl x509 -in  $File -issuer -noout
    $stripped_infos = $issuer_infos.Replace(" ", "").Remove(0,7).split(",")
    return $stripped_infos
}

function get_subject_infos {
	Param ($File)
	$issuer_infos = openssl req -subject -in  $File -noout
    $stripped_infos = $issuer_infos.Replace(" ", "").Remove(0,8).split(",")
    return $stripped_infos
}

<# params:
	Csr: The csr file name
	Pem: The output certificate filename
    Path: Optionnal, the path for the miniCA directory
#>
function user_sign {
	Param (
		[Parameter(mandatory=$true)]	[String]$Csr,
		[Parameter(mandatory=$true)]	[String]$Pem,
		[Parameter(mandatory=$false)] 	[String]$Path = ".\miniCA\"
	)

    $acIssuerInfos = get_issuer_infos $Path"cert\cacert.pem"

	$acCertInfos = [ordered]@{}
    $acIssuerInfos | ForEach-Object {
        $split_info = $_.split("=")
        $acCertInfos[$split_info[0]] = $split_info[1]
    }

    $csrSubjectInfos = get_subject_infos $Path"csr\"$Csr

	$csrCertInfos = [ordered]@{}
    $csrSubjectInfos | ForEach-Object {
        $split_info = $_.split("=")
        $csrCertInfos[$split_info[0]] = $split_info[1]
    }

    $tmp = openssl x509 -in $Path"cert\cacert.pem" -checkend 2592000 # 30 jours
    if ($LASTEXITCODE -eq 1){                          #font 2 592 000 secondes
        Write-Host "Failure: The AC certificate will expire in less than 30 days"`
         -ForegroundColor Red
        return
    }
    if ($csrCertInfos.C -ne $acCertInfos.C `
    -Or $csrCertInfos.O -ne $acCertInfos.O `
    -Or $csrCertInfos.OU -eq $null `
    -Or $csrCertInfos.L -eq $null `
    -Or $csrCertInfos.emailAddress -eq $null ){
        Write-Host "Failure: Incorrect CSR"`
         -ForegroundColor Red
        return 
    }

    $extensions = "[ user_cert_new ]`r`nnsComment`t`t= `"" + $csrCertInfos.CN + "`"`r`n" `
    + "nsCertType=`"client,email`"`r`n"
                       
    [System.IO.File]::WriteAllLines($Path + "tmp.cnf", $extensions)

    if (Test-Path $Path"cert\cacert.srl"){
        openssl x509 -req  -days 365 -in $Path"csr\"$Csr -out $Path"cert\"$Pem `
        -CA $Path"cert\cacert.pem" -CAkey $Path"private\caprivate.key" `
        -extfile $Path"tmp.cnf" -extensions "user_cert_new"
    }
    Else{
        openssl x509 -req  -days 365 -in $Path"csr\"$Csr -out $Path"cert\"$Pem `
        -CA $Path"cert\cacert.pem" -CAkey $Path"private\caprivate.key" `
        -CAcreateserial -CAserial $Path"cert\cacert.srl" `
        -extfile $Path"tmp.cnf" -extensions "user_cert_new"
    }
    Remove-Item -Path $Path + "tmp.cnf"
}


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
  "user-req" = (Get-Item "function:user_req").ScriptBlock
  "user-sign" = (Get-Item "function:user_sign").ScriptBlock
  }

function mini-pki {
  param($action, $param1, $param2, $param3)

  Write-Output "Doing action $action"
  $functions[$action].Invoke($param1, $param2, $param3)
}
Export-ModuleMember -Function mini-pki
