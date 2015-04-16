$agent = "Rackspace Management Interface"
$ukey = "User Key" #change this
$skey = "Secret Key" #change this too
$timestamp = Get-Date -Format yyyyMMddHHmmss

$domain_url = "https://api.emailsrvr.com/v1/domains/americanrw.com"
$mailbox_url = "rs/mailboxes"
$alias_url = "rs/aliases"

function hash{

<#
    .SYNOPSIS
        Builds a SHA1 Hash from a string.
#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$True)]
    [string]$string
    )

    $sha1 = New-Object System.Security.Cryptography.SHA1CryptoServiceProvider
    $bytes = [Text.Encoding]::ASCII.GetBytes($string)
    $hash = [Convert]::ToBase64String($sha1.ComputeHash($bytes))
    
    return $hash

}

function build_headers(){

<#
    .SYNOPSIS
        Builds a list of headers to authenticate the connection to Rackspace.
#>

    $hash = hash($ukey+$agent+$timestamp+$skey)
    $signature = "$ukey`:$timestamp`:$hash"
    $headers = @{"Accept" = "application/json"
                 "X-Api-Signature"="$signature"}
    
    return $headers
}

function Get-RSAlias{

<#
    .SYNOPSIS
        Displays a list of e-mail addresses associated with an alias.
    .EXAMPLE
        Get-RSAlias -Name orders
#> 

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$True, Position=1)]
    [string]$Name
    )

$headers = build_headers


 try {
      $response = Invoke-RestMethod "$domain_url/$alias_url/$Name" -Headers $headers -Method Get -UserAgent $agent
      return $response.emailAddressList.emailAddress
     }
catch {

    $response = $_
    Write-Error $response
    return $false > $null
     }

}

function Add-RSMailbox{

<#
    .SYNOPSIS
        Adds a new Mailbox to a domain. Must provide Password, First Name and Last Name
    .EXAMPLE
        Add-RSMailbox -Name bsmith -Password Secret! -FirstName Bob -LastName Smith
#>
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$True, Position=1)]
    [string]$Name,
    [Parameter(Mandatory=$True, Position=2)]
    [string]$Password,
    [Parameter(Mandatory=$True, Position=3)]
    [string]$FirstName,
    [Parameter(Mandatory=$True, Position=4)]
    [string]$LastName
    )


$headers = build_headers


$body = @{password = $password;size = '25600'}
if ($LastName) {$body.Add('lastName', $LastName)}
if ($FirstName) {$body.Add('firstName', $FirstName)}

try{

    $response = Invoke-RestMethod "$domain_url/$mailbox_url/$Name" -Body $body -Headers $headers -Method Post -UserAgent $agent
    return $response

    }
catch{

    $response = $_
    Write-Error $response
    return $false > $null

    }
}
