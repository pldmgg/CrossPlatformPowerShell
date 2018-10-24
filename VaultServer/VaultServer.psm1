[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"

# Get public and private function definition files.
[array]$Public  = Get-ChildItem -Path "$PSScriptRoot\Public\*.ps1" -ErrorAction SilentlyContinue
[array]$Private = Get-ChildItem -Path "$PSScriptRoot\Private\*.ps1" -ErrorAction SilentlyContinue
$ThisModule = $(Get-Item $PSCommandPath).BaseName

# Dot source the Private functions
foreach ($import in $Private) {
    try {
        . $import.FullName
    }
    catch {
        Write-Error -Message "Failed to import function $($import.FullName): $_"
    }
}

[System.Collections.Arraylist]$ModulesToInstallAndImport = @()
if (Test-Path "$PSScriptRoot/module.requirements.psd1") {
    $ModuleManifestData = Import-PowerShellDataFile "$PSScriptRoot/module.requirements.psd1"
    #$ModuleManifestData.Keys | Where-Object {$_ -ne "PSDependOptions"} | foreach {$null = $ModulesToinstallAndImport.Add($_)}
    $($ModuleManifestData.GetEnumerator()) | foreach {
        if ($_.Key -ne "PSDependOptions") {
            $PSObj = [pscustomobject]@{
                Name    = $_.Key
                Version = $_.Value.Version
            }
            $null = $ModulesToinstallAndImport.Add($PSObj)
        }
    }
}

if ($PSVersionTable.Platform -eq "Unix" -or $PSVersionTable.OS -match "Darwin") {
    $env:SudoPwdPrompt = $True

    if ($ModulesToInstallAndImport.Count -gt 0) {
        foreach ($ModuleItem in $ModulesToInstallAndImport) {
            if ($ModuleItem.Name -match "WinSSH|NTFSSecurity|WindowsCompatibility") {
                continue
            }

            if (!$(Get-Module -ListAvailable $ModuleItem.Name -ErrorAction SilentlyContinue)) {
                try {
                    Install-Module $ModuleItem.Name -AllowClobber -ErrorAction Stop
                }
                catch {
                    try {
                        Install-Module $ModuleItem.Name -AllowClobber -AllowPrerelease -ErrorAction Stop
                    }
                    catch {
                        Write-Error $_
                        Write-Error "Unable to import all Module dependencies! Please unload $ThisModule via 'Remove-Module $ThisModule'! Halting!"
                        $global:FunctionResult = "1"
                        return
                    }
                }
            }
            
            # Make sure the Module Manifest file name and the Module Folder name are exactly the same case
            $env:PSModulePath -split ':' | foreach {
                Get-ChildItem -Path $_ -Directory | Where-Object {$_ -match $ModuleItem.Name}
            } | foreach {
                $ManifestFileName = $(Get-ChildItem -Path $_ -Recurse -File | Where-Object {$_.Name -match "$($ModuleItem.Name)\.psd1"}).BaseName
                if (![bool]$($_.Name -cmatch $ManifestFileName)) {
                    Rename-Item $_ $ManifestFileName
                }
            }

            if (!$(Get-Module $ModuleItem.Name -ErrorAction SilentlyContinue)) {
                try {
                    Import-Module $ModuleItem.Name -ErrorAction Stop -WarningAction SilentlyContinue
                }
                catch {
                    Write-Error $_
                    Write-Error "Unable to import all Module dependencies! Please unload $ThisModule via 'Remove-Module $ThisModule'! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
            }
        }
    }
}

if (!$PSVersionTable.Platform -or $PSVersionTable.Platform -eq "Win32NT") {
    if ($ModulesToInstallAndImport.Count -gt 0) {
        # NOTE: If you're not sure if the Required Module is Locally Available or Externally Available,
        # add it the the -RequiredModules string array just to be certain
        $InvModDepSplatParams = @{
            RequiredModules                     = $ModulesToInstallAndImport
            InstallModulesNotAvailableLocally   = $True
            ErrorAction                         = "SilentlyContinue"
            WarningAction                       = "SilentlyContinue"
        }
        $ModuleDependenciesMap = InvokeModuleDependencies @InvModDepSplatParams
    }
}


# Public Functions


<#
    .SYNOPSIS
        This function is meant to make it easy to configure both the SSH Client and SSHD Server for Public
        Certificate Authentication. It can (and should) be run on BOTH the SSH Client and the SSHD Server.

        This function does the following:
            - Uses the Vault Server's SSH Host Signing Certificate Authority (CA) to sign the local host's
            ssh host key (i.e. 'C:\ProgramData\ssh\ssh_host_rsa_key.pub', resulting in
            C:\ProgramData\ssh\ssh_host_rsa_key-cert.pub)
            - Gets the Public Key of the CA used to sign User/Client SSH Keys from the Vault Server and adds it to:
                1) The file C:\ProgramData\ssh\authorized_keys as a string;
                2) The file C:\ProgramData\ssh\ssh_known_hosts as a string; and
                3) The dedicated file C:\ProgramData\ssh\ca_pub_key_of_client_signer.pub
            - Gets the Public Key of the CA used to sign Host/Machine SSH Keys from the Vault Server and adds it to:
                1) The file C:\ProgramData\ssh\authorized_keys as a string;
                2) The file C:\ProgramData\ssh\ssh_known_hosts as a string; and
                3) The dedicated file C:\ProgramData\ssh\ca_pub_key_of_host_signer.pub
            - Adds references to user accounts that you would like to grant ssh access to the local machine
            to C:\ProgramData\ssh\authorized_principals (includes both Local and Domain users)
            - Ensures NTFS filesystem permissions are set appropriately for the aforementioned files
            - Adds references to 'TrustedUserCAKeys' and 'AuthorizedPrincipalsFile' to
            C:\ProgramData\ssh\sshd_config

        IMPORTANT NOTE: Just in case any breaking/undesireable changes are made to the host's ssh configuration,
        all files that could potentially be changed are backed up to C:\ProgramData\ssh\Archive before any
        changes are actually made.

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER PublicKeyOfCAUsedToSignUserKeysFilePath
        This parameter is OPTIONAL, however, either -PublicKeyOfCAUsedToSignUserKeysFilePath,
        -PublicKeyOfCAUsedToSignUserKeysAsString, or -PublicKeyOfCAUsedToSignUserKeysVaultUrl is REQUIRED.

        This parameter takes a string that represents a path to a file that is the Public Key of the CA
        used to sign SSH User/Client Keys.

    .PARAMETER PublicKeyOfCAUsedToSignUserKeysAsString
        This parameter is OPTIONAL, however, either -PublicKeyOfCAUsedToSignUserKeysFilePath,
        -PublicKeyOfCAUsedToSignUserKeysAsString, or -PublicKeyOfCAUsedToSignUserKeysVaultUrl is REQUIRED.

        This parameter takes a string that represents the Public Key of the CA used to sign SSH User/Client
        Keys. The string must start with "ssh-rsa".

    .PARAMETER PublicKeyOfCAUsedToSignUserKeysVaultUrl
        This parameter is OPTIONAL, however, either -PublicKeyOfCAUsedToSignUserKeysFilePath,
        -PublicKeyOfCAUsedToSignUserKeysAsString, or -PublicKeyOfCAUsedToSignUserKeysVaultUrl is REQUIRED.

        This parameter takes a string that represents the URL of the Vault Server Rest API Endpoint that
        advertises the Public Key of the CA used to sign SSH User/Client Keys. The URL should be something like:
            https://<FQDNOfVaultServer>:8200/v1/ssh-client-signer/public_key

    .PARAMETER PublicKeyOfCAUsedToSignHostKeysFilePath
        This parameter is OPTIONAL, however, either -PublicKeyOfCAUsedToSignHostKeysFilePath,
        -PublicKeyOfCAUsedToSignhostKeysAsString, or -PublicKeyOfCAUsedToSignHostKeysVaultUrl is REQUIRED.

        This parameter takes a string that represents a path to a file that is the Public Key of the CA
        used to sign SSH Host/Machine Keys.

    .PARAMETER PublicKeyOfCAUsedToSignHostKeysAsString
        This parameter is OPTIONAL, however, either -PublicKeyOfCAUsedToSignHostKeysFilePath,
        -PublicKeyOfCAUsedToSignhostKeysAsString, or -PublicKeyOfCAUsedToSignHostKeysVaultUrl is REQUIRED.

        This parameter takes a string that represents the Public Key of the CA used to sign SSH Host/Machine
        Keys. The string must start with "ssh-rsa".

    .PARAMETER PublicKeyOfCAUsedToSignHostKeysVaultUrl
        This parameter is OPTIONAL, however, either -PublicKeyOfCAUsedToSignHostKeysFilePath,
        -PublicKeyOfCAUsedToSignhostKeysAsString, or -PublicKeyOfCAUsedToSignHostKeysVaultUrl is REQUIRED.

        This parameter takes a string that represents the URL of the Vault Server REST API Endpoint that
        advertises the Public Key of the CA used to sign SSH User/Client Keys. The URL should be something like:
            https://<FQDNOfVaultServer>:8200/v1/ssh-host-signer/public_key

    .PARAMETER AuthorizedUserPrincipals
        This parameter is OPTIONAL, but highly recommended.

        This parameter takes an array of strings, each of which represents either a Local User Account
        or a Domain User Account. Local User Accounts MUST be in the format <UserName>@<LocalHostComputerName> and
        Domain User Accounts MUST be in the format <UserName>@<DomainPrefix>. (To clarify DomainPrefix: if your
        domain is, for example, 'zero.lab', your DomainPrefix would be 'zero').

        These strings will be added to the file C:\ProgramData\ssh\authorized_principals, and these User Accounts
        will be permitted to SSH into the machine that this function is run on.

        You CAN use this parameter in conjunction with the -AuthorizedPrincipalsUserGroup parameter, and this function
        DOES check for repeats, so don't worry about overlap.

    .PARAMETER AuthorizedPrincipalsUserGroup
        This parameter is OPTIONAL.

        This parameter takes an array of strings that can be any combination of the following values:
            - AllUsers
            - LocalAdmins
            - LocalUsers
            - DomainAdmins
            - DomainUsers
        
        The value 'AllUsers' is the equivalent of specifying 'LocalAdmins','LocalUsers','DomainAdmins', and
        'DomainUsers'.

        Each User Account that is a member of the specified groups will be added to the file
        C:\ProgramData\ssh\authorized_principals, and these User Accounts will be permitted to SSH into the machine
        that this function is run on.

        You CAN use this parameter in conjunction with the -AuthorizedUserPrincipals parameter, and this function
        DOES check for repeats, so don't worry about overlap.

    .PARAMETER VaultSSHHostSigningUrl
        This parameter is OPTIONAL, but highly recommended.

        This parameter takes a string that represents the URL of the Vault Server REST API endpoint that is
        responsible for signing the Local Host's Host/Machine SSH Key. The URL should be something like:
            http://<FQDNOfVaultServer>:8200/v1/ssh-host-signer/sign/hostrole

        Using this parameter outputs the signed SSH Host/Machine Key file C:\ProgramData\ssh\ssh_host_rsa_key-cert.pub

    .PARAMETER VaultAuthToken
        This parameter is OPTIONAL, but becomes MANDATORY if you use the -VaultSSHHostSigningUrl parameter.
        It should only be used if you use the -VaultSSHHostSigningUrl parameter.

        This parameter takes a string that represents a Vault Authentiction token with permission to
        request that the Vault Server sign the Local Host's SSH Host/Machine Key.

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -
        
        PS C:\Users\zeroadmin> $AddCAPubKeyToSSHAndSSHDConfigSplatParams = @{
            PublicKeyOfCAUsedToSignUserKeysVaultUrl     = "$VaultServerBaseUri/ssh-client-signer/public_key"
            PublicKeyOfCAUsedToSignHostKeysVaultUrl     = "$VaultServerBaseUri/ssh-host-signer/public_key"
            AuthorizedPrincipalsUserGroup               = @("LocalAdmins","DomainAdmins")
            VaultSSHHostSigningUrl                      = "$VaultServerBaseUri/ssh-host-signer/sign/hostrole"
            VaultAuthToken                              = $ZeroAdminToken
        }
        PS C:\Users\zeroadmin> $AddCAPubKeysResult = Add-CAPubKeyToSSHAndSSHDConfig @AddCAPubKeyToSSHAndSSHDConfigSplatParams
#>
function Add-CAPubKeyToSSHAndSSHDConfig {
    [CmdletBinding(DefaultParameterSetName='VaultUrl')]
    Param(
        # NOTE: When reading 'PathToPublicKeyOfCAUsedToSign', please note that it is actually the CA's
        # **private key** that is used to do the signing. We just require the CA's public key to verify
        # that presented user keys signed by the CA's private key were, in fact, signed by the CA's private key
        [Parameter(Mandatory=$False)]
        [string]$PublicKeyOfCAUsedToSignUserKeysFilePath,

        [Parameter(Mandatory=$False)]
        [string]$PublicKeyOfCAUsedToSignUserKeysAsString,

        [Parameter(Mandatory=$False)]
        [string]$PublicKeyOfCAUsedToSignUserKeysVaultUrl, # Should be something like: http://192.168.2.12:8200/v1/ssh-client-signer/public_key

        [Parameter(Mandatory=$False)]
        [string]$PublicKeyOfCAUsedToSignHostKeysFilePath,

        [Parameter(Mandatory=$False)]
        [string]$PublicKeyOfCAUsedToSignHostKeysAsString,

        [Parameter(Mandatory=$False)]
        [string]$PublicKeyOfCAUsedToSignHostKeysVaultUrl, # Should be something like: http://192.168.2.12:8200/v1/ssh-host-signer/public_key

        [Parameter(Mandatory=$False)]
        [ValidatePattern("[\w]+@[\w]+")]
        [string[]]$AuthorizedUserPrincipals,

        [Parameter(Mandatory=$False)]
        [ValidateSet("AllUsers","LocalAdmins","LocalUsers","DomainAdmins","DomainUsers")]
        [string[]]$AuthorizedPrincipalsUserGroup,

        # Use the below $VaultSSHHostSigningUrl and $VaultAuthToken parameters if you want
        # C:\ProgramData\ssh\ssh_host_rsa_key.pub signed by the Vault Host Signing CA. This is highly recommended.
        [Parameter(Mandatory=$False)]
        [string]$VaultSSHHostSigningUrl, # Should be something like http://192.168.2.12:8200/v1/ssh-host-signer/sign/hostrole"

        [Parameter(Mandatory=$False)]
        [string]$VaultAuthToken
    )

    if ($($PSBoundParameters.Keys -match "UserKeys").Count -gt 1) {
        $ErrMsg = "The $($MyInvocation.MyCommand.Name) only takes one of the following parameters: " +
        "-PublicKeyOfCAUsedToSignUserKeysFilePath, -PublicKeyOfCAUsedToSignUserKeysAsString, -PublicKeyOfCAUsedToSignUserKeysVaultUrl"
        Write-Error $ErrMsg
    }
    if ($($PSBoundParameters.Keys -match "UserKeys").Count -eq 0) {
        $ErrMsg = "The $($MyInvocation.MyCommand.Name) MUST use one of the following parameters: " +
        "-PublicKeyOfCAUsedToSignUserKeysFilePath, -PublicKeyOfCAUsedToSignUserKeysAsString, -PublicKeyOfCAUsedToSignUserKeysVaultUrl"
        Write-Error $ErrMsg
    }

    if ($($PSBoundParameters.Keys -match "HostKeys").Count -gt 1) {
        $ErrMsg = "The $($MyInvocation.MyCommand.Name) only takes one of the following parameters: " +
        "-PublicKeyOfCAUsedToSignHostKeysFilePath, -PublicKeyOfCAUsedToSignHostKeysAsString, -PublicKeyOfCAUsedToSignHostKeysVaultUrl"
        Write-Error $ErrMsg
    }
    if ($($PSBoundParameters.Keys -match "HostKeys").Count -eq 0) {
        $ErrMsg = "The $($MyInvocation.MyCommand.Name) MUST use one of the following parameters: " +
        "-PublicKeyOfCAUsedToSignHostKeysFilePath, -PublicKeyOfCAUsedToSignHostKeysAsString, -PublicKeyOfCAUsedToSignHostKeysVaultUrl"
        Write-Error $ErrMsg
    }

    if (!$AuthorizedUserPrincipals -and !$AuthorizedPrincipalsUserGroup) {
        $AuthPrincErrMsg = "The $($MyInvocation.MyCommand.Name) function requires one of the following parameters: " +
        "-AuthorizedUserPrincipals, -AuthorizedPrincipalsUserGroup"
        Write-Error $AuthPrincErrMsg
        $global:FunctionResult = "1"
        return
    }

    if ($($VaultSSHHostSigningUrl -and !$VaultAuthToken) -or $(!$VaultSSHHostSigningUrl -and $VaultAuthToken)) {
        $ErrMsg = "If you would like this function to facilitate signing $env:ComputerName's ssh_host_rsa_key.pub, " +
        "both -VaultSSHHostSigningUrl and -VaultAuthToken parameters are required! Halting!"
        Write-Error $ErrMsg
        $global:FunctionResult = "1"
        return
    }

    # Setup our $Output Hashtable which we will add to as necessary as we go
    [System.Collections.ArrayList]$FilesUpdated = @()
    $Output = @{
        FilesUpdated = $FilesUpdated
    }


    # Make sure sshd service is installed and running. If it is, we shouldn't need to use
    # the New-SSHD server function
    if (![bool]$(Get-Service sshd -ErrorAction SilentlyContinue)) {
        if (![bool]$(Get-Service ssh-agent -ErrorAction SilentlyContinue)) {
            $InstallWinSSHSplatParams = @{
                GiveWinSSHBinariesPathPriority  = $True
                ConfigureSSHDOnLocalHost        = $True
                DefaultShell                    = "powershell"
                GitHubInstall                   = $True
                ErrorAction                     = "SilentlyContinue"
                ErrorVariable                   = "IWSErr"
            }

            try {
                $InstallWinSSHResults = Install-WinSSH @InstallWinSSHSplatParams -ErrorAction Stop
                if (!$InstallWinSSHResults) {throw "There was a problem with the Install-WinSSH function! Halting!"}

                $Output.Add("InstallWinSSHResults",$InstallWinSSHResults)
            }
            catch {
                Write-Error $_
                Write-Host "Errors for the Install-WinSSH function are as follows:"
                Write-Error $($IWSErr | Out-String)
                $global:FunctionResult = "1"
                return
            }
        }
        else {
            $NewSSHDServerSplatParams = @{
                ErrorAction         = "SilentlyContinue"
                ErrorVariable       = "SSHDErr"
                DefaultShell        = "powershell"
            }
            
            try {
                $NewSSHDServerResult = New-SSHDServer @NewSSHDServerSplatParams
                if (!$NewSSHDServerResult) {throw "There was a problem with the New-SSHDServer function! Halting!"}
            }
            catch {
                Write-Error $_
                Write-Host "Errors for the New-SSHDServer function are as follows:"
                Write-Error $($SSHDErr | Out-String)
                $global:FunctionResult = "1"
                return
            }
        }
    }

    if (Test-Path "$env:ProgramData\ssh\sshd_config") {
        $sshdir = "$env:ProgramData\ssh"
        $sshdConfigPath = "$sshdir\sshd_config"
    }
    elseif (Test-Path "$env:ProgramFiles\OpenSSH-Win64\sshd_config") {
        $sshdir = "$env:ProgramFiles\OpenSSH-Win64"
        $sshdConfigPath = "$env:ProgramFiles\OpenSSH-Win64\sshd_config"
    }
    if (!$sshdConfigPath) {
        Write-Error "Unable to find file 'sshd_config'! Halting!"
        $global:FunctionResult = "1"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        return
    }

    if ($VaultSSHHostSigningUrl) {
        # Make sure $VaultSSHHostSigningUrl is a valid Url
        try {
            $UriObject = [uri]$VaultSSHHostSigningUrl
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            if ($Output.Count -gt 0) {[pscustomobject]$Output}
            return
        }

        if (![bool]$($UriObject.Scheme -match "http")) {
            Write-Error "'$PublicKeyOfCAUsedToSignUserKeysVaultUrl' does not appear to be a URL! Halting!"
            $global:FunctionResult = "1"
            if ($Output.Count -gt 0) {[pscustomobject]$Output}
            return
        }

        # Try to sign this machine's host key (i.e. C:\ProgramData\ssh\ssh_host_rsa_key.pub)
        try {
            # The below 'Sign-SSHHostPublicKey' function outputs a PSCustomObject detailing what was done
            # to the sshd config (if anything). It also writes out C:\ProgramData\ssh\ssh_host_rsa_key-cert.pub
            $SignSSHHostKeySplatParams = @{
                VaultSSHHostSigningUrl      = $VaultSSHHostSigningUrl
                VaultAuthToken              = $VaultAuthToken
                ErrorAction                 = "Stop"
            }
            $SignSSHHostKeyResult = Sign-SSHHostPublicKey @SignSSHHostKeySplatParams | Where-Object {$_}
            if (!$SignSSHHostKeyResult) {throw "There was a problem with the Sign-SSHHostPublicKey function!"}
            $Output.Add("SignSSHHostKeyResult",$SignSSHHostKeyResult)
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            if ($Output.Count -gt 0) {[pscustomobject]$Output}
            return
        }
    }

    # We need to get $PublicKeyOfCAUsedToSignUserKeysAsString and $PublicKeyOfCAUsedToSignHostKeysAsString
    if ($PublicKeyOfCAUsedToSignUserKeysVaultUrl) {
        # Make sure $SiteUrl is a valid Url
        try {
            $UriObject = [uri]$PublicKeyOfCAUsedToSignUserKeysVaultUrl
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            if ($Output.Count -gt 0) {[pscustomobject]$Output}
            return
        }

        if (![bool]$($UriObject.Scheme -match "http")) {
            Write-Error "'$PublicKeyOfCAUsedToSignUserKeysVaultUrl' does not appear to be a URL! Halting!"
            $global:FunctionResult = "1"
            if ($Output.Count -gt 0) {[pscustomobject]$Output}
            return
        }

        try {
            $PublicKeyOfCAUsedToSignUserKeysAsString = $(Invoke-WebRequest -Uri $PublicKeyOfCAUsedToSignUserKeysVaultUrl).Content.Trim()
            if (!$PublicKeyOfCAUsedToSignUserKeysAsString) {throw "Invoke-WebRequest failed to get the CA's Public Key from Vault! Halting!"}
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            if ($Output.Count -gt 0) {[pscustomobject]$Output}
            return
        }
    }
    if ($PublicKeyOfCAUsedToSignHostKeysVaultUrl) {
        # Make sure $SiteUrl is a valid Url
        try {
            $UriObject = [uri]$PublicKeyOfCAUsedToSignHostKeysVaultUrl
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            if ($Output.Count -gt 0) {[pscustomobject]$Output}
            return
        }

        if (![bool]$($UriObject.Scheme -match "http")) {
            Write-Error "'$PublicKeyOfCAUsedToSignHostKeysVaultUrl' does not appear to be a URL! Halting!"
            $global:FunctionResult = "1"
            if ($Output.Count -gt 0) {[pscustomobject]$Output}
            return
        }

        try {
            $PublicKeyOfCAUsedToSignHostKeysAsString = $(Invoke-WebRequest -Uri $PublicKeyOfCAUsedToSignHostKeysVaultUrl).Content.Trim()
            if (!$PublicKeyOfCAUsedToSignHostKeysAsString) {throw "Invoke-WebRequest failed to get the CA's Public Key from Vault! Halting!"}
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            if ($Output.Count -gt 0) {[pscustomobject]$Output}
            return
        }
    }
    if ($PublicKeyOfCAUsedToSignUserKeysFilePath) {
        if (! $(Test-Path $PublicKeyOfCAUsedToSignUserKeysFilePath)) {
            Write-Error "The path '$PublicKeyOfCAUsedToSignUserKeysFilePath' was not found! Halting!"
            $global:FunctionResult = "1"
            if ($Output.Count -gt 0) {[pscustomobject]$Output}
            return
        }
        
        $PublicKeyOfCAUsedToSignUserKeysAsString = Get-Content $PublicKeyOfCAUsedToSignUserKeysFilePath
    }
    if ($PublicKeyOfCAUsedToSignHostKeysFilePath) {
        if (! $(Test-Path $PublicKeyOfCAUsedToSignHostKeysFilePath)) {
            Write-Error "The path '$PublicKeyOfCAUsedToSignHostKeysFilePath' was not found! Halting!"
            $global:FunctionResult = "1"
            if ($Output.Count -gt 0) {[pscustomobject]$Output}
            return
        }
        
        $PublicKeyOfCAUsedToSignHostKeysAsString = Get-Content $PublicKeyOfCAUsedToSignHostKeysFilePath
    }

    # Now we have $PublicKeyOfCAUsedToSignUserKeysAsString and $PublicKeyOfCAUsedToSignHostKeysAsString
    # Need to make sure these strings exist in dedicated files under $sshdir as well as in 
    # $sshdir/authorized_keys and $sshdir/ssh_known_hosts

    # Before adding these CA Public Keys to $sshdir/authorized_keys, if there's already an existing
    # $sshdir/authorized_keys, archive it in a folder called $sshdir/Archive so that we can revert if necessary
    if (Test-Path "$sshdir/authorized_keys") {
        if (!$(Test-Path "$sshdir/Archive")) {
            $null = New-Item -ItemType Directory -Path "$sshdir/Archive" -Force
        }
        Move-Item -Path "$sshdir/authorized_keys" -Destination "$sshdir/Archive" -Force
    }
    # Before adding these CA Public Keys to $sshdir/ssh_known_hosts, if there's already an existing
    # $sshdir/ssh_known_hosts, archive it in a folder called $sshdir/Archive so that we can revert if necessary
    if (Test-Path "$sshdir/ssh_known_hosts") {
        if (!$(Test-Path "$sshdir/Archive")) {
            $null = New-Item -ItemType Directory -Path "$sshdir/Archive" -Force
        }
        Move-Item -Path "$sshdir/ssh_known_hosts" -Destination "$sshdir/Archive" -Force
    }

    # Add the CA Public Certs to $sshdir/authorized_keys in their appropriate formats
    $ContentToAddToAuthKeys = @(
        "ssh-rsa-cert-v01@openssh.com " + $PublicKeyOfCAUsedToSignUserKeysAsString
        "ssh-rsa-cert-v01@openssh.com " + $PublicKeyOfCAUsedToSignHostKeysAsString
    )
    $ContentToAddToAuthKeysString = $ContentToAddToAuthKeys -join "`n"
    Add-Content -Path "$sshdir/authorized_keys" -Value $ContentToAddToAuthKeysString
    $null = $FilesUpdated.Add($(Get-Item "$sshdir/authorized_keys"))

    # Add the CA Public Certs to $sshdir/ssh_known_hosts in their appropriate formats
    $ContentToAddToKnownHosts = @(
        "@cert-authority * " + $PublicKeyOfCAUsedToSignUserKeysAsString
        "@cert-authority * " + $PublicKeyOfCAUsedToSignHostKeysAsString
    )
    $ContentToAddToKnownHostsString = $ContentToAddToKnownHosts -join "`n"
    Add-Content -Path $sshdir/ssh_known_hosts -Value $ContentToAddToKnownHostsString
    $null = $FilesUpdated.Add($(Get-Item "$sshdir/ssh_known_hosts"))

    # Make sure $PublicKeyOfCAUsedToSignUserKeysAsString and $PublicKeyOfCAUsedToSignHostKeysAsString are written
    # to their own dedicated files under $sshdir
    
    # If $PublicKeyOfCAUsedToSignUserKeysFilePath or $PublicKeyOfCAUsedToSignHostKeysFilePath were actually provided
    # maintain the same file name when writing to $sshdir
    if ($PSBoundParameters.ContainsKey('PublicKeyOfCAUsedToSignUserKeysFilePath')) {
        $UserCAPubKeyFileName = $PublicKeyOfCAUsedToSignUserKeysFilePath | Split-Path -Leaf
    }
    else {
        $UserCAPubKeyFileName = "ca_pub_key_of_client_signer.pub"
    }
    if ($PSBoundParameters.ContainsKey('PublicKeyOfCAUsedToSignHostKeysFilePath')) {
        $HostCAPubKeyFileName = $PublicKeyOfCAUsedToSignHostKeysFilePath | Split-Path -Leaf
    }
    else {
        $HostCAPubKeyFileName = "ca_pub_key_of_host_signer.pub"
    }

    if (Test-Path "$sshdir/$UserCAPubKeyFileName") {
        if (!$(Test-Path "$sshdir/Archive")) {
            $null = New-Item -ItemType Directory -Path "$sshdir/Archive" -Force
        }
        Move-Item -Path "$sshdir/$UserCAPubKeyFileName" -Destination "$sshdir/Archive" -Force
    }
    if (Test-Path "$sshdir/$HostCAPubKeyFileName") {
        if (!$(Test-Path "$sshdir/Archive")) {
            $null = New-Item -ItemType Directory -Path "$sshdir/Archive" -Force
        }
        Move-Item -Path "$sshdir/$HostCAPubKeyFileName" -Destination "$sshdir/Archive" -Force
    }

    Set-Content -Path "$sshdir/$UserCAPubKeyFileName" -Value $PublicKeyOfCAUsedToSignUserKeysAsString
    Set-Content -Path "$sshdir/$HostCAPubKeyFileName" -Value $PublicKeyOfCAUsedToSignHostKeysAsString
    $null = $FilesUpdated.Add($(Get-Item "$sshdir/$UserCAPubKeyFileName"))
    $null = $FilesUpdated.Add($(Get-Item "$sshdir/$HostCAPubKeyFileName"))
    

    # Next, we need to generate some content for $sshdir/authorized_principals

    # IMPORTANT NOTE: The Generate-AuthorizedPrincipalsFile will only ADD users to the $sshdir/authorized_principals
    # file (if they're not already in there). It WILL NOT delete or otherwise overwrite existing users in
    # $sshdir/authorized_principals
    $AuthPrincSplatParams = @{
        ErrorAction     = "Stop"
    }
    if ($(!$AuthorizedPrincipalsUserGroup -and !$AuthorizedUserPrincipals) -or
    $AuthorizedPrincipalsUserGroup -contains "AllUsers" -or
    $($AuthorizedPrincipalsUserGroup -contains "LocalAdmins" -and $AuthorizedPrincipalsUserGroup -contains "LocalUsers" -and
    $AuthorizedPrincipalsUserGroup -contains "DomainAdmins" -and $AuthorizedPrincipalsUserGroup -contains "DomainAdmins")
    ) {
        $AuthPrincSplatParams.Add("UserGroupToAdd",@("AllUsers"))
    }
    else {
        if ($AuthorizedPrincipalsUserGroup) {
            $AuthPrincSplatParams.Add("UserGroupToAdd",$AuthorizedPrincipalsUserGroup)
        }
        if ($AuthorizedUserPrincipals) {
            $AuthPrincSplatParams.Add("UsersToAdd",$AuthorizedUserPrincipals)
        }
    }

    try {
        $AuthorizedPrincipalsFile = Generate-AuthorizedPrincipalsFile @AuthPrincSplatParams
        if (!$AuthorizedPrincipalsFile) {throw "There was a problem with the Generate-AuthorizedPrincipalsFile function! Halting!"}

        $null = $FilesUpdated.Add($(Get-Item "$sshdir/authorized_principals"))        
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        return
    }

    # Now we need to fix permissions for $sshdir/authroized_principals...
    if ($PSVersionTable.PSEdition -eq "Core") {
        Invoke-WinCommand -ComputerName localhost -ScriptBlock {
            $SecurityDescriptor = Get-NTFSSecurityDescriptor -Path "$($args[0])/authorized_principals"
            $SecurityDescriptor | Disable-NTFSAccessInheritance -RemoveInheritedAccessRules
            $SecurityDescriptor | Clear-NTFSAccess
            $SecurityDescriptor | Add-NTFSAccess -Account "NT AUTHORITY\SYSTEM" -AccessRights "FullControl" -AppliesTo ThisFolderSubfoldersAndFiles
            $SecurityDescriptor | Add-NTFSAccess -Account "Administrators" -AccessRights "FullControl" -AppliesTo ThisFolderSubfoldersAndFiles
            $SecurityDescriptor | Set-NTFSSecurityDescriptor
        } -ArgumentList $sshdir
    }
    else {
        $SecurityDescriptor = Get-NTFSSecurityDescriptor -Path "$sshdir/authorized_principals"
        $SecurityDescriptor | Disable-NTFSAccessInheritance -RemoveInheritedAccessRules
        $SecurityDescriptor | Clear-NTFSAccess
        $SecurityDescriptor | Add-NTFSAccess -Account "NT AUTHORITY\SYSTEM" -AccessRights "FullControl" -AppliesTo ThisFolderSubfoldersAndFiles
        $SecurityDescriptor | Add-NTFSAccess -Account "Administrators" -AccessRights "FullControl" -AppliesTo ThisFolderSubfoldersAndFiles
        $SecurityDescriptor | Set-NTFSSecurityDescriptor
    }

    # Now that we have set content for $PublicKeyOfCAUsedToSignUserKeysFilePath, $sshdir/authorized_principals, and
    # $sshdir/authorized_keys, we need to update sshd_config to reference these files

    $PubKeyOfCAUserKeysFilePathForwardSlashes = "$sshdir\$UserCAPubKeyFileName" -replace '\\','/'
    $TrustedUserCAKeysOptionLine = "TrustedUserCAKeys $PubKeyOfCAUserKeysFilePathForwardSlashes"
    # For more information about authorized_principals content (specifically about setting specific commands and roles
    # for certain users), see: https://framkant.org/2017/07/scalable-access-control-using-openssh-certificates/
    $AuthPrincFilePathForwardSlashes = "$sshdir\authorized_principals" -replace '\\','/'
    $AuthorizedPrincipalsOptionLine = "AuthorizedPrincipalsFile $AuthPrincFilePathForwardSlashes"
    $AuthKeysFilePathForwardSlashes = "$sshdir\authorized_keys" -replace '\\','/'
    $AuthorizedKeysFileOptionLine = "AuthorizedKeysFile $AuthKeysFilePathForwardSlashes"

    [System.Collections.ArrayList]$sshdContent = Get-Content $sshdConfigPath

    # Determine if sshd_config already has the 'TrustedUserCAKeys' option active
    $ExistingTrustedUserCAKeysOption = $sshdContent -match "TrustedUserCAKeys" | Where-Object {$_ -notmatch "#"}

    # Determine if sshd_config already has 'AuthorizedPrincipals' option active
    $ExistingAuthorizedPrincipalsFileOption = $sshdContent -match "AuthorizedPrincipalsFile" | Where-Object {$_ -notmatch "#"}

    # Determine if sshd_config already has 'AuthorizedKeysFile' option active
    $ExistingAuthorizedKeysFileOption = $sshdContent -match "AuthorizedKeysFile" | Where-Object {$_ -notmatch "#"}
    
    if (!$ExistingTrustedUserCAKeysOption) {
        # If sshd_config already has the 'Match User' option available, don't touch it, else add it with ForceCommand
        try {
            Add-Content -Value $TrustedUserCAKeysOptionLine -Path $sshdConfigPath
            $SSHDConfigContentChanged = $True
            [System.Collections.ArrayList]$sshdContent = Get-Content $sshdConfigPath
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            if ($Output.Count -gt 0) {[pscustomobject]$Output}
            return
        }
    }
    else {
        if ($ExistingTrustedUserCAKeysOption -ne $TrustedUserCAKeysOptionLine) {
            $UpdatedSSHDConfig = $sshdContent -replace [regex]::Escape($ExistingTrustedUserCAKeysOption),"$TrustedUserCAKeysOptionLine"

            try {
                Set-Content -Value $UpdatedSSHDConfig -Path $sshdConfigPath
                $SSHDConfigContentChanged = $True
                [System.Collections.ArrayList]$sshdContent = Get-Content $sshdConfigPath
            }
            catch {
                Write-Error $_
                $global:FunctionResult = "1"
                if ($Output.Count -gt 0) {[pscustomobject]$Output}
                return
            }
        }
        else {
            Write-Warning "The specified 'TrustedUserCAKeys' option is already active in the the sshd_config file. No changes made."
        }
    }

    if (!$ExistingAuthorizedPrincipalsFileOption) {
        try {
            Add-Content -Value $AuthorizedPrincipalsOptionLine -Path $sshdConfigPath
            $SSHDConfigContentChanged = $True
            [System.Collections.ArrayList]$sshdContent = Get-Content $sshdConfigPath
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            if ($Output.Count -gt 0) {[pscustomobject]$Output}
            return
        }
    }
    else {
        if ($ExistingAuthorizedPrincipalsFileOption -ne $AuthorizedPrincipalsOptionLine) {
            $UpdatedSSHDConfig = $sshdContent -replace [regex]::Escape($ExistingAuthorizedPrincipalsFileOption),"$AuthorizedPrincipalsOptionLine"

            try {
                Set-Content -Value $UpdatedSSHDConfig -Path $sshdConfigPath
                $SSHDConfigContentChanged = $True
                [System.Collections.ArrayList]$sshdContent = Get-Content $sshdConfigPath
            }
            catch {
                Write-Error $_
                $global:FunctionResult = "1"
                if ($Output.Count -gt 0) {[pscustomobject]$Output}
                return
            }
        }
        else {
            Write-Warning "The specified 'AuthorizedPrincipalsFile' option is already active in the the sshd_config file. No changes made."
        }
    }

    if (!$ExistingAuthorizedKeysFileOption) {
        try {
            Add-Content -Value $AuthorizedKeysFileOptionLine -Path $sshdConfigPath
            $SSHDConfigContentChanged = $True
            [System.Collections.ArrayList]$sshdContent = Get-Content $sshdConfigPath
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            if ($Output.Count -gt 0) {[pscustomobject]$Output}
            return
        }
    }
    else {
        if ($ExistingAuthorizedKeysFileOption -ne $AuthorizedKeysFileOptionLine) {
            $UpdatedSSHDConfig = $sshdContent -replace [regex]::Escape($ExistingAuthorizedKeysFileOption),"$AuthorizedKeysFileOptionLine"

            try {
                Set-Content -Value $UpdatedSSHDConfig -Path $sshdConfigPath
                $SSHDConfigContentChanged = $True
                [System.Collections.ArrayList]$sshdContent = Get-Content $sshdConfigPath
            }
            catch {
                Write-Error $_
                $global:FunctionResult = "1"
                if ($Output.Count -gt 0) {[pscustomobject]$Output}
                return
            }
        }
        else {
            Write-Warning "The specified 'AuthorizedKeysFile' option is already active in the the sshd_config file. No changes made."
        }
    }

    if ($SSHDConfigContentChanged) {
        $null = $FilesUpdated.Add($(Get-Item $sshdConfigPath))
        
        try {
            Restart-Service sshd -ErrorAction Stop
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            if ($Output.Count -gt 0) {[pscustomobject]$Output}
            return
        }
    }

    [pscustomobject]$Output
}


<#
    .SYNOPSIS
        This function connects to a Remote Host via ssh and adds the specified User/Client SSH Public Key to
        the ~/.ssh/authorized_keys file on that Remote Host. As long as you can connect to the Remote Host via
        ssh, this function will work with both Windows and Linux targets.

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER PublicKeyPath
        This parameter is MANDATORY.

        This parameter takes a string that represents the full path to the SSH User/Client Public Key that you
        would like to add to the Remote Host's ~/.ssh/authorized_keys file.

    .PARAMETER RemoteHost
        This parameter is MANDATORY.

        This parameter takes a string that represents an IP Address or DNS-Resolvable name to a remote host
        running an sshd server.

    .PARAMETER RemoteHostUserName
        This parameter is MANDATORY,

        This parameter takes a string that represents the User Name you would like to use to ssh
        into the Remote Host.

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> $SplatParams = @{
            PublicKeyPath       = "$HOME\.ssh\id_rsa.pub"
            RemoteHost          = "Ubuntu18.zero.lab"
            RemoteHostUserName  = "zero\zeroadmin"
        }
        PS C:\Users\zeroadmin> Add-PublicKeyToRemoteHost @SplatParams
#>
function Add-PublicKeyToRemoteHost {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$PublicKeyPath,

        [Parameter(Mandatory=$True)]
        [string]$RemoteHost,

        [Parameter(Mandatory=$True)]
        [string]$RemoteHostUserName
    )

    #region >> Prep

    if ($PSVersionTable.Platform -eq "Unix" -or $PSVersionTable.OS -match "Darwin" -and $env:SudoPwdPrompt) {
        if (GetElevation) {
            Write-Error "You should not be running the VaultServer Module as root! Halting!"
            $global:FunctionResult = "1"
            return
        }
        RemoveMySudoPwd
        NewCronToAddSudoPwd
        $env:SudoPwdPrompt = $False
    }

    if (!$(Test-Path $PublicKeyPath)) {
        Write-Error "The path $PublicKeyPath was not found! Halting!"
        $global:FunctionResult = "1"
        return
    }

    try {
        $RemoteHostNetworkInfo = ResolveHost -HostNameOrIP $RemoteHost -ErrorAction Stop
    }
    catch {
        Write-Error "Unable to resolve $RemoteHost! Halting!"
        $global:FunctionResult = "1"
        return
    }    
    
    if (![bool]$(Get-Command ssh -ErrorAction SilentlyContinue)) {
        Write-Error "Unable to find ssh.exe! Halting!"
        $global:FunctionResult = "1"
        return
    }

    $PubKeyContent = Get-Content $PublicKeyPath

    #endregion >> Prep


    #region >> Main

    if ($RemoteHostNetworkInfo.FQDN) {
        $RemoteHostLocation = $RemoteHostNetworkInfo.FQDN
    }
    elseif ($RemoteHostNetworkInfo.HostName) {
        $RemoteHostLocation = $RemoteHostNetworkInfo.HostName
    }
    elseif ($RemoteHostNetworkInfo.IPAddressList[0]) {
        $RemoteHostLocation = $RemoteHostNetworkInfo.IPAddressList[0]
    }

    #ssh -t $RemoteHostUserName@$RemoteHostLocation "echo '$PubKeyContent' >> ~/.ssh/authorized_keys"
    if ($RemoteHostUserName -match "\\|@") {
        if ($RemoteHostUserName -match "\\") {
            $DomainPrefix = $($RemoteHostUserName -split "\\")[0]
        }
        if ($RemoteHostUserName -match "@") {
            $DomainPrefix = $($RemoteHostUserName -split "\\")[-1]
        }
    }

    if (!$DomainPrefix) {
        ssh -o "StrictHostKeyChecking=no" -o "BatchMode=yes" -t $RemoteHostUserName@$RemoteHostLocation "echo '$PubKeyContent' >> ~/.ssh/authorized_keys"
    }
    else {
        ssh -o "StrictHostKeyChecking=no" -o "BatchMode=yes" -t $RemoteHostUserName@$DomainPrefix@$RemoteHostLocation "echo '$PubKeyContent' >> ~/.ssh/authorized_keys"
    }

    #endregion >> Main
}


<#
    .SYNOPSIS
        This function uses the HashiCorp Vault Server's REST API to configure the Vault Server for
        LDAP Authrntication.

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER VaultServerNetworkLocation
        This parameter is MANDATORY.

        This parameter takes a string that represents the network location (IP Address or DNS-Resolvable)
        of the Vault Server.

    .PARAMETER VaultServerPort
        This parameter is MANDATORY.

        This parameter takes an integer that represents a Port Number (8200, etc). The Vault Server
        typically uses port 8200.

    .PARAMETER EncrytNetworkTraffic
        This parameter is OPTIONAL, but is set by default to be $True.

        This parameter is a switch. If used, the Vault Server will be configured to encrypt network
        traffic via TLS.

        IMPORTANT NOTE: NEVER set this parameter to $False unless you are simply testing the Vault Server
        in Development Mode. In production, you MUST encrypt network traffic to/from the Vault Server,
        and therefore, this parameter must be $True.

    .PARAMETER VaultAuthToken
        This parameter is MANDATORY.

        This parameter takes a string that represents a Vault Authentiction token with permission to
        configure teh Vault Server for LDAP Authentication.

    .PARAMETER VaultLogFileName
        This parameter is OPTIONAL, but is set to 'vault_audit.log' by default.

        This parameter takes a string that represents the name of the log file on the Vault Server that
        logs all activity (i.e. Vault Operator Command Line as well as REST API calls).

    .PARAMETER VaultLogEndPointName
        This parameter is OPTIONAL, but is set to 'default-audit'.

        This parameter takes a string that represents the name of the Vault Server REST API Endpoint
        used to enable and configure the Vault Server activity log. For context, this value is used
        with a REST API URL similar to:
            "$VaultServerBaseUri/sys/audit/$VaultLogEndPointName"

    .PARAMETER PerformOptionalSteps
        This parameter is OPTIONAL, but highly recommended.

        This parameter is a switch. If used, the following additional configuration operations will
        be performed on the Vault Server:
            - A backup root token with username 'backupadmin' will be created.
            - A 'custom-root' policy will be created and applied to the "VaultAdmins" Group (which must already exist
            in LDAP). This policy effectively grants all users in the "VaultAdmins" Group root access to the Vault Server.
            - A 'vaultusers' policy will be created and applied to the "VaultUsers" Group (which must already exist
            in LDAP). Users in the "VaultUsers" Group will have all permissions except 'delete' and 'sudo'.

    .PARAMETER LDAPServerHostNameOrIP
        This parameter is MANDATORY.

        This parameter takes a string that represents either the IP Address or DNS-Resolvable name of
        the LDAP Server. In a Windows environment, this would be a Domain Controller.

    .PARAMETER LDAPServicePort
        This parameter is MANDATORY.

        This parameter takes an integer with possible values: 389, 636, 3268, or 3269. Depending
        on how you have LDAP configured, use the appropriate port number. If you are not sure,
        use the TestLDAP function to determine which ports are in use.

    .PARAMETER BindUserDN
        This parameter is MANDATORY.

        This parameter takes a string that represents an LDAP Path to a User Account Object - somthing like:
            cn=vault,ou=OrgUsers,dc=zero,dc=lab

        This User Account will be used by the Vault Server to search the LDAP database and confirm
        credentials for the user trying to login to the Vault Server against the LDAP database. This
        LDAP account should be dedicated for use by the Vault Server and should not have any other purpose.

    .PARAMETER LDAPBindCredentials
        This parameter is MANDATORY.

        This parameter takes a PSCredential. Th e UserName should corredpound to the UserName provided to the
        -BindUserDN parameter, but should be in format <DomainPrefix>\<UserName>. So, to be consistent with
        the example provided in the -BindUserDN comment-based-help, you could create the value for
        -LDAPBindCredentials via:
            $Creds = [pscredential]::new("zero\vault",$(Read-Host "Please Enter the Password for 'zero\vault'" -AsSecureString))

    .PARAMETER LDAPUserOUDN
        This parameter is MANDATORY.

        This parameter takes a string tht represents an LDAP Path to an Organizational Unit (OU) that Vault
        will search in order to find User Accounts. To stay consistent with the example provided in the
        comment-based-help for the -BindUserDN parameter, this would be:
            ou=OrgUsers,dc=zero,dc=lab

    .PARAMETER LDAPGroupOUDN
        This parameter is MANDATORY.

        This parameter takes a string that represents an LDAP Path to the Organizational Unit (OU) that
        contains the Security Groups "VaultAdmins" and "VaultUsers". This could be something like:
            ou=Groups,dc=zero,dc=lab

    .PARAMETER LDAPVaultUsersSecurityGroupDN
        This parameter is OPTIONAL, however, it becomes MANDATORY when the -PerformOptionalSteps parameter is used.

        This parameter takes a string that represents the LDAP Path to the "VaultUsers" Security Group. To be
        consistent with the example provided in teh comment-based-help for the -LDAPGroupOUDN parameter, this
        should be something like:
            cn=VaultUsers,ou=Groups,dc=zero,dc=lab

        IMPORTANT NOTE: The Common Name (CN) for this LDAP Path MUST be 'VaultUsers'

    .PARAMETER LDAPVaultAdminsSecurityGroupDN
        This parameter is OPTIONAL, however, it becomes MANDATORY when the -PerformOptionalSteps parameter is used.

        This parameter takes a string that represents the LDAP Path to the "VaultAdmins" Security Group. To be
        consistent with the example provided in teh comment-based-help for the -LDAPGroupOUDN parameter, this
        should be something like:
            cn=VaultAdmins,ou=Groups,dc=zero,dc=lab

        IMPORTANT NOTE: The Common Name (CN) for this LDAP Path MUST be 'VaultAdmins'

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> $ConfigureVaultLDAPSplatParams = @{
            VaultServerNetworkLocation      = "vaultserver.zero.lab"
            VaultServerPort                 = 8200
            VaultAuthToken                  = $VaultAuthToken
            LDAPServerHostNameOrIP          = "ZeroDC01.zero.lab"
            LDAPServicePort                 = 636
            LDAPBindCredentials             = $LDAPBindCredentials
            BindUserDN                      = "cn=vault,ou=OrgUsers,dc=zero,dc=lab"
            LDAPUserOUDN                    = "ou=OrgUsers,dc=zero,dc=lab"
            LDAPGroupOUDN                   = "ou=Groups,dc=zero,dc=lab"
            PerformOptionalSteps            = $True
            LDAPVaultUsersSecurityGroupDN   = "cn=VaultUsers,ou=Groups,dc=zero,dc=lab"
            LDAPVaultAdminsSecurityGroupDN  = "cn=VaultAdmins,ou=Groups,dc=zero,dc=lab"
        }
        PS C:\Users\zeroadmin> $ConfigureVaultLDAPResult = Configure-VaultServerForLDAPAuth @ConfigureVaultLDAPSplatParams
        
#>
function Configure-VaultServerForLDAPAuth {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True)]
        [string]$VaultServerNetworkLocation, # Should be an IP Address of DNS-Resolvable HostName/FQDN

        [Parameter(Mandatory=$True)]
        [int]$VaultServerPort, # Typically 8200

        [Parameter(Mandatory=$False)]
        [switch]$EncryptNetworkTraffic = $True, # Impacts using http/https, Vault Config, Generating TLS Certificates

        [Parameter(Mandatory=$True)]
        [string]$VaultAuthToken, # Get this via manual step preceeding this function using Vault CmdLine - 'vault operator init' 

        [Parameter(Mandatory=$False)]
        [string]$VaultLogFileName = "vault_audit.log",

        [Parameter(Mandatory=$False)]
        [string]$VaultLogEndPointName = "default-audit",

        # Creates backup root token with username 'backupadmin',
        # Creates 'custom-root' policy applied to "VaultAdmins" group (all permissions)
        # Creates 'vaultusers' policy applied to "VaultUsers" group (all permissions except 'delete' and 'sudo')
        [Parameter(Mandatory=$False)]
        [switch]$PerformOptionalSteps,

        [Parameter(Mandatory=$True)]
        [string]$LDAPServerHostNameOrIP,

        [Parameter(Mandatory=$True)]
        [ValidateSet(389,636,3268,3269)]
        [int]$LDAPServicePort,

        [Parameter(Mandatory=$True)]
        [string]$BindUserDN, # Should be a path to a User Account LDAP object, like cn=vault,ou=OrgUsers,dc=zero,dc=lab

        # Should be a non-privileged LDAP/AD account whose sole purpose is allowing Vault to read the LDAP Database
        [Parameter(Mandatory=$True)]
        [pscredential]$LDAPBindCredentials,
        
        [Parameter(Mandatory=$True)]
        [string]$LDAPUserOUDN, # Something like ou=OrgUsers,dc=zero,dc=lab
    
        [Parameter(Mandatory=$True)]
        [string]$LDAPGroupOUDN, # Something like ou=Groups,dc=zero,dc=lab

        [Parameter(Mandatory=$False)]
        [ValidatePattern("^cn=VaultUsers")]
        [string]$LDAPVaultUsersSecurityGroupDN, # Something like cn=VaultUsers,ou=Groups,dc=zero,dc=lab

        [Parameter(Mandatory=$False)]
        [ValidatePattern("^cn=VaultAdmins")]
        [string]$LDAPVaultAdminsSecurityGroupDN # Something like cn=VaultAdmins,ou=Groups,dc=zero,dc=lab
    )

    #region >> Variable/Parameter Transforms and PreRun Prep

    [Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"

    # Create $Ouput Hashtable so we can add to it as we go and return whatever was done in case of error
    $Output = [ordered]@{}

    if ($EncryptNetworkTraffic) {
        $VaultServerBaseUri = "https://$VaultServerNetworkLocation" + ":$VaultServerPort/v1"
    }
    else {
        $VaultServerBaseUri = "http://$VaultServerNetworkLocation" + ":$VaultServerPort/v1"
    }

    if ($PerformOptionalSteps) {
        if (!$LDAPVaultUsersSecurityGroupDN -or !$LDAPVaultAdminsSecurityGroupDN) {
            Write-Error "When using the -PerformOptionalSteps switch, you must also supply values for -LDAPVaultUsersSecurityGroupDN and -LDAPVaultAdminsSecurityGroupDN! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    # Make sure we can reach the LDAP Server
    try {
        $LDAPServerNetworkInfo = ResolveHost -HostNameOrIP $LDAPServerHostNameOrIP
        if (!$LDAPServerNetworkInfo) {throw "Unable to resolve $LDAPServerHostNameOrIP! Halting!"}
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    # Make sure $LDAPBindCredentials work
    $CurrentlyLoadedAssemblies = [System.AppDomain]::CurrentDomain.GetAssemblies()

    if (![bool]$($CurrentlyLoadedAssemblies -match "System.DirectoryServices.AccountManagement")) {
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement
    }
    $SimpleDomain = $LDAPServerNetworkInfo.Domain
    $SimpleDomainWLDAPPort = $SimpleDomain + ":$LDAPServicePort"
    [System.Collections.ArrayList]$DomainLDAPContainersPrep = @()
    foreach ($Section in $($SimpleDomain -split "\.")) {
        $null = $DomainLDAPContainersPrep.Add($Section)
    }
    $DomainLDAPContainers = $($DomainLDAPContainersPrep | foreach {"DC=$_"}) -join ", "

    try {
        $SimpleUserName = $($LDAPBindCredentials.UserName -split "\\")[1]
        $PasswordInPlainText = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($LDAPBindCredentials.Password))
        $PrincipleContext = [System.DirectoryServices.AccountManagement.PrincipalContext]::new(
            [System.DirectoryServices.AccountManagement.ContextType]::Domain,
            "$SimpleDomainWLDAPPort",
            "$DomainLDAPContainers",
            [System.DirectoryServices.AccountManagement.ContextOptions]::SimpleBind,
            "$($LDAPBindCredentials.UserName)",
            "$PasswordInPlainText"
        )

        try {
            $UserPrincipal = [System.DirectoryServices.AccountManagement.UserPrincipal]::FindByIdentity($PrincipleContext, [System.DirectoryServices.AccountManagement.IdentityType]::SamAccountName, "$SimpleUserName")
            $LDAPBindCredentialsAreValid = $True
        }
        catch {
            throw "The credentials provided to the -LDAPBindCredentials parameter are not valid for the domain $SimpleDomain! Halting!"
        }

        if ($LDAPBindCredentialsAreValid) {
            # Determine if the User Account is locked
            $AccountLocked = $UserPrincipal.IsAccountLockedOut()

            if ($AccountLocked -eq $True) {
                throw "The provided UserName $($LDAPBindCredentials.Username) is locked! Please unlock it before additional attempts at getting working credentials!"
            }
        }
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }


    # NOTE: With .Net, LDAP URIs always start with 'LDAP' - never lowercase and never with an 's|S' (i.e. never LDAPS|ldaps),
    # regardless of port
    $LDAPUri = "LDAP://$($LDAPServerNetworkInfo.FQDN):$LDAPServicePort"

    # Make sure $LDAPUserOUDN exists
    try {
        $LDAPUserOUDNDirectoryEntry = [System.DirectoryServices.DirectoryEntry]("$LDAPUri/$LDAPUserOUDN")
        $LDAPUserOUDNDirectoryEntry.Close()
    }
    catch {
        Write-Error "The LDAP Object $LDAPUserOUDN cannot be found! Halting!"
        $global:FunctionResult = "1"
        return
    }

    # Make sure $LDAPGroupOUDN exists
    try {
        $LDAPGroupOUDNDirectoryEntry = [System.DirectoryServices.DirectoryEntry]("$LDAPUri/$LDAPGroupOUDN")
        $LDAPGroupOUDNDirectoryEntry.Close()
    }
    catch {
        Write-Error "The LDAP Object $LDAPGroupOUDN cannot be found! Halting!"
        $global:FunctionResult = "1"
        return
    }

    $HeadersParameters = @{
        "X-Vault-Token" = $VaultAuthToken
    }

    #endregion >> Variable/Parameter Transforms and PreRun Prep


    #region >> Main Body
    
    # Turn on Vault Audit Log
    # Vault CmdLine Equivalent:
    #   vault audit enable file file_path=/vault/logs/vault_audit.log
    $jsonRequest = @"
{
    "type": "file",
    "options": {
        "path": "/vault/logs/$VaultLogFileName"
    }
}
"@
    try {
        # Validate JSON
        $JsonRequestAsSingleLineString = $jsonRequest | ConvertFrom-Json -EA Stop | ConvertTo-Json -Compress -EA Stop
    }
    catch {
        Write-Error "There was a problem with the JSON for Turning on the Audit Log! Halting!"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }
    $IWRSplatParams = @{
        Uri         = "$VaultServerBaseUri/sys/audit/$VaultLogEndPointName"
        Headers     = $HeadersParameters
        Body        = $JsonRequestAsSingleLineString
        Method      = "Put"
    }
    $TurnOnAuditLog = Invoke-RestMethod @IWRSplatParams
    $ConfirmAuditLogIsOn = $(Invoke-RestMethod -Uri "$VaultServerBaseUri/sys/audit" -Headers $HeadersParameters -Method Get).data
    if (!$ConfirmAuditLogIsOn) {
        Write-Error "Cannot confirm that the Vault Audit Log is turned on! Halting!"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }
    $Output.Add("EnableAuditLog",$ConfirmAuditLogIsOn)

    # Create a new policy that effectively has root access to Vault, and call it 'custom-root'. This policy will be applied
    # to Vault Administrators later on
    $jsonRequest = @"
{
    "policy": "path \"*\" {\n    capabilities = [\"create\", \"read\", \"update\", \"delete\", \"list\", \"sudo\"]\n}"
}
"@
    try {
        # Validate JSON
        $JsonRequestAsSingleLineString = $jsonRequest | ConvertFrom-Json -EA Stop | ConvertTo-Json -Compress -EA Stop
    }
    catch {
        Write-Error "There was a problem with the JSON for creating the 'custom-root' policy! Halting!"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }
    $IWRSplatParams = @{
        Uri         = "$VaultServerBaseUri/sys/policy/custom-root"
        Headers     = $HeadersParameters
        Body        = $JsonRequestAsSingleLineString
        Method      = "Put"
    }
    $RootPolicyResponse = Invoke-RestMethod @IWRSplatParams
    $ConfirmRootPolicy = Invoke-RestMethod -Uri "$VaultServerBaseUri/sys/policy/custom-root" -Headers $HeadersParameters -Method Get
    if (!$ConfirmRootPolicy) {
        Write-Error "Cannot confirm that the Vault policy 'custom-root' has been enabled! Halting!"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }
    $Output.Add("CreateCustomRootPolicy",$ConfirmRootPolicy)

    # Create a policy that is for typical Vault Users (i.e. not Vault Admins), that allows for everything except
    # delete and sudo. Change according to your preferences.
    $jsonRequest = @"
{
    "policy": "path \"*\" {\n    capabilities = [\"create\", \"read\", \"update\", \"list\"]\n}"
}
"@
    try {
        # Validate JSON
        $JsonRequestAsSingleLineString = $jsonRequest | ConvertFrom-Json -EA Stop | ConvertTo-Json -Compress -EA Stop
    }
    catch {
        Write-Error "There was a problem with the JSON for creating the 'vaultusers' policy! Halting!"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }
    $IWRSplatParams = @{
        Uri         = "$VaultServerBaseUri/sys/policy/vaultusers"
        Headers     = $HeadersParameters
        Body        = $JsonRequestAsSingleLineString
        Method      = "Put"
    }
    $VaultUsersPolicyResponse = Invoke-RestMethod @IWRSplatParams
    $ConfirmVaultUsersPolicy = Invoke-RestMethod -Uri "$VaultServerBaseUri/sys/policy/vaultusers" -Headers $HeadersParameters -Method Get
    if (!$ConfirmVaultUsersPolicy) {
        Write-Error "Cannot confirm that the Vault policy 'vaultusers' has been enabled! Halting!"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }
    $Output.Add("CreateVaultUsersPolicy",$ConfirmVaultUsersPolicy)

    if ($PerformOptionalSteps) {
        # Create a user other than the initial root (i.e. the token $VaultAuthToken that we've been using thus far) that has root privileges
        # via the 'custom-root' policy. This is just for a backup root account for emergencies
        # Vault CmdLine Equivalent:
        #   vault token create -policy=custom-root -display-name="backupadmin" -ttl="8760h" -renewable=true -metadata=user=backupadmin
        $jsonRequest = @"
{
    "policies": [
        "custom-root"
    ],
    "meta": {
        "user": "backupadmin"
    },
    "ttl": "8760h",
    "renewable": true
}
"@
        try {
            # Validate JSON
            $JsonRequestAsSingleLineString = $jsonRequest | ConvertFrom-Json -EA Stop | ConvertTo-Json -Compress -EA Stop
        }
        catch {
            Write-Error "There was a problem with the JSON for creating the 'backupadmin' Vault Token! Halting!"
            if ($Output.Count -gt 0) {[pscustomobject]$Output}
            $global:FunctionResult = "1"
            return
        }
        $IWRSplatParams = @{
            Uri         = "$VaultServerBaseUri/auth/token/create"
            Headers     = $HeadersParameters
            Body        = $JsonRequestAsSingleLineString
            Method      = "Post"
        }
        $NewUserTokenResponse = Invoke-RestMethod @IWRSplatParams
        if (!$NewUserTokenResponse) {
            Write-Error "There was a problem creating the 'backupadmin' Vault Token! Halting!"
            $global:FunctionResult = "1"
            return
        }
        $Output.Add("BackupRootToken",$NewUserTokenResponse)
    }

    # Enable LDAP Authentication
    #   vault auth enable ldap -description="Login with LDAP"
    $jsonRequest = @"
{
    "type": "ldap",
    "description": "Login with LDAP"
}
"@
    try {
        # Validate JSON
        $JsonRequestAsSingleLineString = $jsonRequest | ConvertFrom-Json -EA Stop | ConvertTo-Json -Compress -EA Stop
    }
    catch {
        Write-Error "There was a problem with the JSON for enabling the Vault LDAP Authentication Method! Halting!"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }
    $IWRSplatParams = @{
        Uri         = "$VaultServerBaseUri/sys/auth/ldap"
        Headers     = $HeadersParameters
        Body        = $JsonRequestAsSingleLineString
        Method      = "Post"
    }
    $EnableLDAPResponse = Invoke-RestMethod @IWRSplatParams
    $ConfirmLDAPEnabled = Invoke-RestMethod -Uri "$VaultServerBaseUri/sys/auth" -Headers $HeadersParameters -Method Get
    if (!$ConfirmLDAPEnabled) {
        Write-Error "There was a problem enabling the LDAP Authentication Method for the Vault Server! Halting!"
    }
    $Output.Add("LDAPAuthEngineEnabled",$ConfirmLDAPEnabled)

    # Next, we need the LDAP Server's Root CA Public Certificate
    try {
        $GetLDAPCertSplatParams = @{
            LDAPServerHostNameOrIP      = $LDAPServerNetworkInfo.FQDN
            Port                        = $LDAPServicePort
            ErrorAction                 = "Stop"
        }
        if ($LDAPServicePort -eq 389 -or $LDAPServicePort -eq 3268) {
            $GetLDAPCertSplatParams.Add("UseOpenSSL",$True)
        }

        $GetLDAPCertResult = Get-LDAPCert @GetLDAPCertSplatParams
        if (!$GetLDAPCertResult) {throw "The Get-LDAPCert function failed! Is your LDAP implementation using TLS? Halting!"}
        $RootCertificateInPemFormat = $GetLDAPCertResult.RootCACertificateInfo.PemFormat -join "`n"
        if (!$RootCertificateInPemFormat) {throw "The Get-LDAPCert function failed to get the Root CA Certificate in the LDAP Endpoint's Certificate Chain! Halting!"}
    }
    catch {
        Write-Error $_
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }

    # The Vault Server handles LDAP Uris as expected (as opposed to .Net counterpart in above
    # 'Variable/Parameter Transforms and PreRun Prep' region) 
    if ($LDAPServicePort -eq 389 -or $LDAPServicePort -eq 3268) {
        $LDAPUriForVault = "ldap://$($LDAPServerNetworkInfo.FQDN):$LDAPServicePort"
    }
    if ($LDAPServicePort -eq 636 -or $LDAPServicePort -eq 3269) {
        $LDAPUriForVault = "ldaps://$($LDAPServerNetworkInfo.FQDN):$LDAPServicePort"
    }

    $jsonRequest = @"
{
    "url": "$LDAPUriForVault",
    "userattr": "samaccountname",
    "userdn": "$LDAPUserOUDN",
    "discoverdn": "true",
    "groupdn": "$LDAPGroupOUDN",
    "groupfilter": "(&(objectClass=group)(member:1.2.840.113556.1.4.1941:={{.UserDN}}))",
    "groupattr": "cn",
    "certificate": "$RootCertificateInPemFormat",
    "insecure_tls": "false",
    "starttls": "true",
    "binddn": "$BindUserDN",
    "bindpass": "$PasswordInPlainText",
    "deny_null_bind": "true",
    "tls_max_version": "tls12",
    "tls_min_version": "tls12"
}
"@
    try {
        # Validate JSON
        $JsonRequestAsSingleLineString = $jsonRequest | ConvertFrom-Json -EA Stop | ConvertTo-Json -Compress -EA Stop
    }
    catch {
        Write-Error "There was a problem with the JSON for establishing Vault's LDAP configuration! Halting!"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }
    $IWRSplatParams = @{
        Uri         = "$VaultServerBaseUri/auth/ldap/config"
        Headers     = $HeadersParameters
        Body        = $JsonRequestAsSingleLineString
        Method      = "Post"
    }
    $LDAPAuthConfigResponse = Invoke-RestMethod @IWRSplatParams
    $ConfirmLDAPAuthConfig = Invoke-RestMethod -Uri "$VaultServerBaseUri/auth/ldap/config" -Headers $HeadersParameters -Method Get
    if (!$ConfirmLDAPAuthConfig) {
        Write-Error "There was a problem setting the Vault LDAP Authentication configuration! Halting!"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }
    $Output.Add("LDAPAuthConfiguration",$ConfirmLDAPAuthConfig)
    # Remove $PasswordInPlainText from Memory as best we can
    $PasswordInPlainText = $null
    $PrincipleContext = $null
    $jsonRequest = $null
    $JsonRequestAsSingleLineString = $null


    if ($PerformOptionalSteps) {
        # Apply the 'custom-root' policy to the AD User Group 'VaultAdmins'
        # Vault Cmdline equivalent is:
        #   vault write auth/ldap/groups/VaultAdmins policies=custom-root

        # Make sure $LDAPVaultAdminsSecurityGroupDN exists
        try {
            $LDAPVaultAdminsSecurityGroupDNDirectoryEntry = [System.DirectoryServices.DirectoryEntry]("$LDAPUri/$LDAPVaultAdminsSecurityGroupDN")
            $LDAPVaultAdminsSecurityGroupDNDirectoryEntry.Close()
        }
        catch {
            Write-Error "The LDAP Object $LDAPVaultAdminsSecurityGroupDN cannot be found! Halting!"
            $global:FunctionResult = "1"
            if ($Output.Count -gt 0) {[pscustomobject]$Output}
            return
        }

        $jsonRequest = @"
{
    "policies": "custom-root"
}
"@
        try {
            # Validate JSON
            $JsonRequestAsSingleLineString = $jsonRequest | ConvertFrom-Json -EA Stop | ConvertTo-Json -Compress -EA Stop
        }
        catch {
            Write-Error "There was a problem with the JSON for applying the 'custom-root' policy to the VaultAdmins Security Group! Halting!"
            $global:FunctionResult = "1"
            return
        }
        $IWRSplatParams = @{
            Uri         = "$VaultServerBaseUri/auth/ldap/groups/VaultAdmins"
            Headers     = $HeadersParameters
            Body        = $JsonRequestAsSingleLineString
            Method      = "Post"
        }
        $ApplyPolicyToVaultAdminsGroup = Invoke-WebRequest @IWRSplatParams
        $ConfirmPolicyOnVaultAdmins = Invoke-RestMethod -Uri "$VaultServerBaseUri/auth/ldap/groups/VaultAdmins" -Headers $HeadersParameters -Method Get
        if (!$ConfirmPolicyOnVaultAdmins) {
            Write-Error "Unable to confirm that the 'custom-root' Vault Policy was applied to the LDAP Security Group 'VaultAdmins'! Halting!"
            if ($Output.Count -gt 0) {[pscustomobject]$Output}
            $global:FunctionResult = "1"
            return
        }
        $Output.Add("AppliedVaultAdminsPolicy",$ConfirmPolicyOnVaultAdmins)

        # Apply the 'vaultusers' policy to the AD User Group 'VaultUsers'
        # Vault Cmdline equivalent is:
        #   vault write auth/ldap/groups/VaultUsers policies=vaultusers

        # Make sure $LDAPVaultUsersSecurityGroupDN exists
        try {
            $LDAPVaultUsersSecurityGroupDNDirectoryEntry = [System.DirectoryServices.DirectoryEntry]("$LDAPUri/$LDAPVaultUsersSecurityGroupDN")
            $LDAPVaultUsersSecurityGroupDNDirectoryEntry.Close()
        }
        catch {
            Write-Error "The LDAP Object $LDAPVaultUsersSecurityGroupDN cannot be found! Halting!"
            if ($Output.Count -gt 0) {[pscustomobject]$Output}
            $global:FunctionResult = "1"
            return
        }

        $jsonRequest = @"
{
    "policies": "vaultusers"
}
"@
        try {
            $JsonRequestAsSingleLineString = $jsonRequest | ConvertFrom-Json -EA Stop | ConvertTo-Json -Compress -EA Stop
        }
        catch {
            Write-Error "There was a problem with the JSON for applying the 'vaultusers' policy to the VaulUsers Security Group! Halting!"
            if ($Output.Count -gt 0) {[pscustomobject]$Output}
            $global:FunctionResult = "1"
            return
        }
        $IWRSplatParams = @{
            Uri         = "$VaultServerBaseUri/auth/ldap/groups/VaultUsers"
            Headers     = $HeadersParameters
            Body        = $JsonRequestAsSingleLineString
            Method      = "Post"
        }
        $ApplyPolicyToVaultUsersGroup = Invoke-WebRequest @IWRSplatParams
        $ConfirmPolicyOnVaultUsers = Invoke-RestMethod -Uri "$VaultServerBaseUri/auth/ldap/groups/VaultUsers" -Headers $HeadersParameters -Method Get
        if (!$ConfirmPolicyOnVaultUsers) {
            Write-Error "Unable to confirm that the 'vaultusers' Vault Policy was applied to the LDAP Security Group 'VaultUsers'! Halting!"
            if ($Output.Count -gt 0) {[pscustomobject]$Output}
            $global:FunctionResult = "1"
            return
        }
        $Output.Add("AppliedVaultUsersPolicy",$ConfirmPolicyOnVaultUsers)
    }

[pscustomobject]$Output

    #endregion >> Main Body

}


<#
    .SYNOPSIS
        This function uses the Hashicorp Vault Server's REST API to configure the Vault Server for
        SSH Public Key Authentication and Management.

        The following actions are performed on teh Vault Server (via the REST API):
            - The Vault SSH User/Client Key Signer is enabled
            - A Certificate Authority (CA) for the SSH User/Client Key Signer is created
            - The Vault SSH Host/Machine Key Signer is enabled
            - A Certificate Authority (CA) for the SSH Host/Machine Key Signer is created
            - The Vault the SSH User/Client Signer Role Endpoint is configured
            - The Vault the SSH Host/Machine Signer Role Endpoint is configured

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER VaultServerBaseUri
        This parameter is MANDATORY.

        This parameter takes a string that represents Base Uri for the Vault Server REST API. It should be
        something like:
            "https://vaultserver.zero.lab:8200/v1"

    .PARAMETER DomainCredentialsWithAdminAccessToVault
        This parameter is OPTIONAL. However, either this parameter or the -VaultAuthToken parameter is REQUIRED.

        This parameter takes a PSCredential. Assuming that LDAP Authenitcation is already enabled and configured
        onthe Vault Server, create a PSCredential that is a member of the "VaultAdmins" Security Group (or
        equivalent) in LDAP.
            $Creds = [pscredential]::new("zero\zeroadmin",$(Read-Host "Please Enter the Password for 'zero\zeroadmin'" -AsSecureString))

    .PARAMETER VaultAuthToken
        This parameter is OPTIONAL. However, either this parameter or the -DomainCredentialsWithAdminAccessToVault
        parameter is REQUIRED.

        This parameter takes a string that represents a Vault Authentication Token that has privileges to make
        configuration changes to the Vault Server.

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> $ConfigureVaultSSHMgmt = Configure-VaultServerForSSHManagement -VaultServerBaseUri $VaultServerBaseUri -VaultAuthToken $ZeroAdminToken
        
#>
function Configure-VaultServerForSSHManagement {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True)]
        [ValidatePattern("\/v1$")]
        [string]$VaultServerBaseUri,

        [Parameter(Mandatory=$False)]
        [pscredential]$DomainCredentialsWithAdminAccessToVault,

        [Parameter(Mandatory=$False)]
        [string]$VaultAuthToken
    )

    if ($(!$VaultAuthToken -and !$DomainCredentialsWithAdminAccessToVault) -or $($VaultAuthToken -and $DomainCredentialsWithAdminAccessToVault)) {
        Write-Error "The $($MyInvocation.MyCommand.Name) function requires one (no more, no less) of the following parameters: [-DomainCredentialsWithAdminAccessToVault, -VaultAuthToken] Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($DomainCredentialsWithAdminAccessToVault) {
        $GetVaultLoginSplatParams = @{
            VaultServerBaseUri                     = $VaultServerBaseUri
            DomainCredentialsWithAccessToVault     = $DomainCredentialsWithAdminAccessToVault
            ErrorAction                            = "Stop"
        }

        try {
            $VaultAuthToken = Get-VaultLogin @GetVaultLoginSplatParams
            if (!$VaultAuthToken) {throw "The Get-VaultLogin function failed! Halting!"}
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }
    }

    $HeadersParameters = @{
        "X-Vault-Token" = $VaultAuthToken
    }

    # Create $Output HashTable to add results as we go...
    $Output = [ordered]@{}

    # We'll be configuring a Certificate Authority for ssh client key signing, and a Certificate Authority for
    # ssh machine host key signing
    
    ##### ENABLE SSH CLIENT CERT SIGNING #####

    # Vault CmdLine equivalent of below HTTP Request -
    #     vault secrets enable -path=ssh-client-signer ssh
    $jsonRequest = @"
{
    "type": "ssh",
    "description": "SSH Client Signer"
}
"@
    try {
        # Validate JSON
        $JsonRequestAsSingleLineString = $jsonRequest | ConvertFrom-Json -EA Stop | ConvertTo-Json -Compress -EA Stop
    }
    catch {
        Write-Error "There was a problem with the JSON for enabling the Vault SSH Client Signer! Halting!"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }
    $IWRSplatParams = @{
        Uri         = "$VaultServerBaseUri/sys/mounts/ssh-client-signer"
        Headers     = $HeadersParameters
        Body        = $JsonRequestAsSingleLineString
        Method      = "Post"
    }
    $EnableSSHClientSigner = Invoke-RestMethod @IWRSplatParams
    $ConfirmSSHClientSignerEnabledPrep = Invoke-RestMethod -Uri "$VaultServerBaseUri/sys/mounts" -Headers $HeadersParameters -Method Get
    if (!$ConfirmSSHClientSignerEnabledPrep) {
        Write-Error "There was a problem confirming that the Vault SSH Client Signer was enabled! Halting!"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }
    $ConfirmSSHClientSignerEnabled = $($ConfirmSSHClientSignerEnabledPrep.data | Get-Member -MemberType Properties).Name -contains "ssh-client-signer/"
    $Output.Add("SSHClientSignerEnabled",$ConfirmSSHClientSignerEnabled)

    # Create A Certificate Authority dedicated to SSH Client Certs and Generate a Public/Private Key Pair for the CA
    # Vault CmdLine equivalent of below HTTP Request -
    #     vault write ssh-client-signer/config/ca generate_signing_key=true
    $jsonRequest = @"
{
    "generate_signing_key": true
}
"@
    try {
        # Validate JSON
        $JsonRequestAsSingleLineString = $jsonRequest | ConvertFrom-Json -EA Stop | ConvertTo-Json -Compress -EA Stop
    }
    catch {
        Write-Error "There was a problem with the JSON for creating the SSH Client Signer Certificate Authority! Halting!"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }
    $IWRSplatParams = @{
        Uri         = "$VaultServerBaseUri/ssh-client-signer/config/ca"
        Headers     = $HeadersParameters
        Body        = $JsonRequestAsSingleLineString
        Method      = "Post"
    }
    $CreateSSHClientCA = Invoke-RestMethod @IWRSplatParams
    $SSHClientCAPublicKey = Invoke-RestMethod -Uri "$VaultServerBaseUri/ssh-client-signer/public_key" -Method Get
    if (!$SSHClientCAPublicKey) {
        Write-Error "There was a problem getting the Public Key of the SSH Client Signer Certificate Authority! Halting!"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }
    $Output.Add("SSHClientSignerCAPublicKey",$SSHClientCAPublicKey)


    ##### ENABLE SSH HOST CERT SIGNING #####

    # Vault CmdLine equivalent of below HTTP Request -
    # vault secrets enable -path=ssh-host-signer ssh
    $jsonRequest = @"
{
    "type": "ssh",
    "description": "SSH Host Signer"
}
"@
    try {
        # Validate JSON
        $JsonRequestAsSingleLineString = $jsonRequest | ConvertFrom-Json -EA Stop | ConvertTo-Json -Compress -EA Stop
    }
    catch {
        Write-Error "There was a problem with the JSON for enabling the Vault SSH Host Signer! Halting!"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }
    $IWRSplatParams = @{
        Uri         = "$VaultServerBaseUri/sys/mounts/ssh-host-signer"
        Headers     = $HeadersParameters
        Body        = $JsonRequestAsSingleLineString
        Method      = "Post"
    }
    $EnableSSHHostSigner = Invoke-WebRequest @IWRSplatParams
    $ConfirmSSHHostSignerEnabledPrep = Invoke-RestMethod -Uri "$VaultServerBaseUri/sys/mounts" -Headers $HeadersParameters -Method Get
    if (!$ConfirmSSHHostSignerEnabledPrep) {
        Write-Error "There was a problem confirming that the Vault SSH Host Signer was enabled! Halting!"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }
    $ConfirmSSHHostSignerEnabled = $($ConfirmSSHHostSignerEnabledPrep.data | Get-Member -MemberType Properties).Name -contains "ssh-host-signer/"
    $Output.Add("SSHHostSignerEnabled",$ConfirmSSHHostSignerEnabled)

    # Create A Certificate Authority dedicated to SSH Host Certs and Generate a Public/Private Key Pair for the CA
    #     vault write ssh-host-signer/config/ca generate_signing_key=true
    $jsonRequest = @"
{
    "generate_signing_key": true
}
"@
    try {
        # Validate JSON
        $JsonRequestAsSingleLineString = $jsonRequest | ConvertFrom-Json -EA Stop | ConvertTo-Json -Compress -EA Stop
    }
    catch {
        Write-Error "There was a problem with the JSON for creating the SSH Host Signer Certificate Authority! Halting!"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }
    $IWRSplatParams = @{
        Uri         = "$VaultServerBaseUri/ssh-host-signer/config/ca"
        Headers     = $HeadersParameters
        Body        = $JsonRequestAsSingleLineString
        Method      = "Post"
    }
    $CreateSSHHostCA = Invoke-RestMethod @IWRSplatParams
    $SSHHostCAPublicKey = Invoke-RestMethod -Uri "$VaultServerBaseUri/ssh-host-signer/public_key" -Method Get
    if (!$SSHHostCAPublicKey) {
        Write-Error "There was a problem getting the Public Key of the SSH Host Signer Certificate Authority! Halting!"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }
    $Output.Add("SSHHostSignerCAPublicKey",$SSHHostCAPublicKey)

    # Extend Host Cert TTL to 10 years
    #     vault secrets tune -max-lease-ttl=87600h ssh-host-signer
    $jsonRequest = @"
{
    "max_lease_ttl": "87600h"
}
"@
    try {
        # Validate JSON
        $JsonRequestAsSingleLineString = $jsonRequest | ConvertFrom-Json -EA Stop | ConvertTo-Json -Compress -EA Stop
    }
    catch {
        Write-Error "There was a problem with the JSON for Tuning the SSH Host Signer! Halting!"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }
    $IWRSplatParams = @{
        Uri         = "$VaultServerBaseUri/sys/mounts/ssh-host-signer/tune"
        Headers     = $HeadersParameters
        Body        = $JsonRequestAsSingleLineString
        Method      = "Post"
    }
    $TuneHostSSHCertValidityPeriod = Invoke-RestMethod @IWRSplatParams
    $ConfirmSSHHostSignerTune = $(Invoke-RestMethod -Uri "$VaultServerBaseUri/sys/mounts" -Headers $HeadersParameters -Method Get).data.'ssh-host-signer/'.config
    if ($ConfirmSSHHostSignerTune.max_lease_ttl -ne 315360000) {
        Write-Error "There was a problem tuning the Vault Server to set max_lease_ttl for signed host ssh keys for 10 years. Halting!"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }
    $Output.Add("SSHHostSignerTuning",$ConfirmSSHHostSignerTune)


    ##### Configure the SSH Client Signer Role #####
    $DefaultUser = $($(whoami) -split "\\")[-1]
    
    $jsonRequest = @"
{
    "key_type": "ca",
    "default_user": "$DefaultUser",
    "allow_user_certificates": true,
    "allowed_users": "*",
    "ttl": "24h",
    "default_extensions": {
        "permit-pty": "",
        "permit-agent-forwarding": ""
    }
}
"@
    try {
        # Validate JSON
        $JsonRequestAsSingleLineString = $jsonRequest | ConvertFrom-Json -EA Stop | ConvertTo-Json -Compress -EA Stop
    }
    catch {
        Write-Error "There was a problem with the JSON for configuring the SSH Client Signer Role! Halting!"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }
    $IWRSplatParams = @{
        Uri         = "$VaultServerBaseUri/ssh-client-signer/roles/clientrole"
        Headers     = $HeadersParameters
        Body        = $JsonRequestAsSingleLineString
        Method      = "Post"
    }
    $SetSSHClientRole = Invoke-RestMethod @IWRSplatParams
    $ConfirmSSHClientRole = Invoke-RestMethod -Uri "$VaultServerBaseUri/ssh-client-signer/roles/clientrole" -Headers $HeadersParameters -Method Get
    if (!$ConfirmSSHClientRole.data) {
        Write-Error "There was a problem creating the the ssh-client-signer Role 'clientrole'! Halting!"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }
    $Output.Add("SSHClientSignerRole",$ConfirmSSHClientRole)

    ##### Configure the SSH Host Signer Role #####
    $jsonRequest = @"
{
    "key_type": "ca",
    "cert_type": "host",
    "allow_host_certificates": "true",
    "allowed_domains": "*",
    "allow_subdomains": "true",
    "ttl": "87600h",
    "default_extensions": {
        "permit-pty": "",
        "permit-agent-forwarding": ""
    }
}
"@
    try {
        # Validate JSON
        $JsonRequestAsSingleLineString = $jsonRequest | ConvertFrom-Json -EA Stop | ConvertTo-Json -Compress -EA Stop
    }
    catch {
        Write-Error "There was a problem with the JSON for configuring the SSH Host Signer Role! Halting!"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }
    $IWRSplatParams = @{
        Uri         = "$VaultServerBaseUri/ssh-host-signer/roles/hostrole"
        Headers     = $HeadersParameters
        Body        = $JsonRequestAsSingleLineString
        Method      = "Post"
    }
    $SetSSHHostRole = Invoke-RestMethod @IWRSplatParams
    $ConfirmSSHHostRole = Invoke-RestMethod -Uri "$VaultServerBaseUri/ssh-host-signer/roles/hostrole" -Headers $HeadersParameters -Method Get
    if (!$ConfirmSSHHostRole.data) {
        Write-Error "There was a problem creating the the ssh-host-signer Role 'hostrole'! Halting!"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }
    $Output.Add("SSHHostSignerRole",$ConfirmSSHHostRole)

    [pscustomobject]$Output
}


<#
    .SYNOPSIS
        This function adds the specified User Accounts (both Local and Domain) to the file 
        'C:\ProgramData\ssh\authorized_principals' on the Local Host. Adding these User Accounts
        to the 'authorized_principals' file allows these users to ssh into the Local Host.

        IMPORTANT NOTE: The Generate-AuthorizedPrincipalsFile will only ADD users to the authorized_principals
        file (if they're not already in there). It WILL NOT delete or otherwise overwrite existing users in the file

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER AuthorizedPrincipalsFileLocation
        This parameter is OPTIONAL.

        This parameter takes a string that represents the full path to desired location of the newly generated
        'authorized_principals' file. If this parameter is NOT used, the function will default to writing the
        'authorized_principals' file to the 'C:\ProgramData\ssh' directory. If that directory does not exist,
        then it will be written to the 'C:\Program Files\OpenSSH-Win64' directory. If that directory does not
        exist, the function will halt.

    .PARAMETER UserGroupToAdd
        This parameter is OPTIONAL, however, either this parameter or the -UsersToAdd parameter is REQUIRED.

        This parameter takes an array of strings. Possible string values are:
            - AllUsers
            - LocalAdmins
            - LocalUsers
            - DomainAdmins
            - DomainUsers
        
        Using "LocalAdmins" will add all User Accounts that are members of the Built-In 'Administrators' Security Group
        on the Local Host to the authorized_principals file.

        Using "LocalUsers" will add all user Accounts that are members of the Built-In 'Users' Security Group on
        the Local Host to the authorized_principals file.

        Using "DomainAdmins" will add all User Accounts that are members of the "Domain Admins" Security Group in
        Active Directory to the authorized_principals file.

        Using "Domain Users" will add all User Accounts that are members of the "Domain Users" Security Group in
        Active Directory to the authorized_principals file.

        Using "AllUsers" will add User Accounts that are members of all of the above Security Groups to the
        authorized_principals file.

        You CAN use this parameter in conjunction with the -UsersToAdd parameter, and this function
        DOES check for repeats, so don't worry about overlap.

    .PARAMETER UsersToAdd
        This parameter is OPTIONAL, however, either this parameter or the -UserGroupToAdd parameter is REQUIRED.

        This parameter takes an array of strings, each of which represents either a Local User Account
        or a Domain User Account. Local User Accounts MUST be in the format <UserName>@<LocalHostComputerName> and
        Domain User Accounts MUST be in the format <UserName>@<DomainPrefix>. (To clarify DomainPrefix: if your
        domain is, for example, 'zero.lab', your DomainPrefix would be 'zero').

        These strings will be added to the authorized_principals file, and these User Accounts
        will be permitted to SSH into the Local Host.

        You CAN use this parameter in conjunction with the -UserGroupToAdd parameter, and this function
        DOES check for repeats, so don't worry about overlap.

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> $AuthorizedPrincipalsFile = Generate-AuthorizedPrincipalsFile -UserGroupToAdd @("LocalAdmins","DomainAdmins")
        
#>
function Generate-AuthorizedPrincipalsFile {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [string]$AuthorizedPrincipalsFileLocation,

        [Parameter(Mandatory=$False)]
        [ValidateSet("AllUsers","LocalAdmins","LocalUsers","DomainAdmins","DomainUsers")]
        [string[]]$UserGroupToAdd,

        [Parameter(Mandatory=$False)]
        [ValidatePattern("[\w]+@[\w]+")]
        [string[]]$UsersToAdd
    )

    if ($PSVersionTable.Platform -eq "Unix" -or $PSVersionTable.OS -match "Darwin" -and $env:SudoPwdPrompt) {
        if (GetElevation) {
            Write-Error "You should not be running the VaultServer Module as root! Halting!"
            $global:FunctionResult = "1"
            return
        }
        RemoveMySudoPwd
        NewCronToAddSudoPwd
        $env:SudoPwdPrompt = $False
    }

    if (!$AuthorizedPrincipalsFileLocation) {
        if (!$PSVersionTable.Platform -or $PSVersionTable.Platform -eq "Win32NT") {
            $sshdir = "$env:ProgramData\ssh"
        }
        if ($PSVersionTable.Platform -eq "Unix" -or $PSVersionTable.OS -match "Darwin") {
            $sshdir = "/etc/ssh"
        }
        
        if (!$(Test-Path $sshdir)) {
            Write-Error "Unable to find $sshdir! Halting!"
            $global:FunctionResult = "1"
            return
        }

        $AuthorizedPrincipalsFileLocation = Join-Path $sshdir "authorized_principals"
    }

    $AuthorizedPrincipalsFileLocation = $AuthorizedPrincipalsFileLocation -replace '\\','/'

    # Get the content of $AuthorizedPrincipalsFileLocation to make sure we don't add anything that is already in there
    if (Test-Path $AuthorizedPrincipalsFileLocation) {
        $OriginalAuthPrincContent = Get-Content $AuthorizedPrincipalsFileLocation
    }

    if ($(!$UserGroupToAdd -and !$UsersToAdd) -or $UserGroupToAdd -contains "AllUsers") {
        $AllUsers = $True
    }
    if ($AllUsers) {
        $LocalAdmins = $True
        $LocalUsers = $True
        $DomainAdmins = $True
        $DomainUsers = $True
    }
    else {
        # Switch automatically loops through an array if the object passed is an array
        if ($UserGroupToAdd) {
            switch ($UserGroupToAdd) {
                'LocalAdmins'   {$LocalAdmins = $True}
                'LocalUsers'    {$LocalUsers = $True}
                'DomainAdmins'  {$DomainAdmins = $True}
                'DomainUsers'   {$DomainUsers = $True}
            }
        }
    }

    try {
        $ThisDomainName = GetDomainName -ErrorAction Stop
        $PartOfDomain = $True
    }
    catch {
        $PartOfDomain = $False
    }

    if (!$PartOfDomain) {
        if ($DomainAdmins) {
            $DomainAdmins = $False
        }
        if ($DomainUsers) {
            $DomainUsers = $False
        }
    }

    # Get ready to start writing to $sshdir\authorized_principals...

    $StreamWriter = [System.IO.StreamWriter]::new($AuthorizedPrincipalsFileLocation, $True)
    [System.Collections.ArrayList]$AccountsAdded = @()

    try {
        if ($LocalAdmins) {
            $LocalAdminAccounts = GetLocalGroupAndUsers

            if (!$PSVersionTable.Platform -or $PSVersionTable.Platform -eq "Win32NT") {
                $LocalAdminAccounts = $($LocalAdminAccounts | Where-Object {$_.Group -eq "Administrators"}).Users

                $AccountsReformatted = foreach ($LocalAcctName in $LocalAdminAccounts) {
                    $ActualHostName = $env:ComputerName

                    $ReformattedName = "$LocalAcctName@$($ActualHostName.ToLowerInvariant())"
                    $ReformattedName
                }
            }
            if ($PSVersionTable.Platform -eq "Unix" -or $PSVersionTable.OS -match "Darwin") {
                $LocalAdminAccounts = $($LocalAdminAccounts | Where-Object {$_.Group -eq "SudoUsers"}).Users

                $AccountsReformatted = foreach ($LocalAcctName in $LocalAdminAccounts) {
                    if ($env:HOSTNAME -match '\.') {
                        $ActualHostName = $($env:HOSTNAME -split '\.')[0]
                    }
                    else {
                        $ActualHostName = $env:HOSTNAME
                    }

                    $ReformattedName = "$LocalAcctName@$($ActualHostName.ToLowerInvariant())"
                    $ReformattedName
                }
            }

            foreach ($Acct in $AccountsReformatted) {
                if ($AccountsAdded -notcontains $Acct -and $OriginalAuthPrincContent -notcontains $Acct) {
                    # NOTE: $True below means that the content will *appended* to $AuthorizedPrincipalsFileLocation
                    $StreamWriter.WriteLine($Acct)

                    # Keep track of the accounts we're adding...
                    $null = $AccountsAdded.Add($Acct)
                }
            }
        }

        if ($LocalUsers) {
            $LocalAdminAccounts = GetLocalGroupAndUsers

            if (!$PSVersionTable.Platform -or $PSVersionTable.Platform -eq "Win32NT") {
                $LocalAdminAccounts = $($LocalAdminAccounts | Where-Object {$_.Group -eq "Users"}).Users

                $AccountsReformatted = foreach ($LocalAcctName in $LocalAdminAccounts) {
                    $ActualHostName = $env:ComputerName

                    $ReformattedName = "$LocalAcctName@$($ActualHostName.ToLowerInvariant())"
                    $ReformattedName
                }
            }

            if ($PSVersionTable.Platform -eq "Unix" -or $PSVersionTable.OS -match "Darwin") {
                $LocalAdminAccounts = $($LocalAdminAccounts | Where-Object {$_.Group -eq "humanusers"}).Users

                
            }

            foreach ($Acct in $AccountsReformatted) {
                if ($AccountsAdded -notcontains $Acct -and $OriginalAuthPrincContent -notcontains $Acct) {
                    # NOTE: $True below means that the content will *appended* to $AuthorizedPrincipalsFileLocation
                    $StreamWriter.WriteLine($Acct)

                    # Keep track of the accounts we're adding...
                    $null = $AccountsAdded.Add($Acct)
                }
            }
        }

        if ($DomainAdmins) {
            if (!$UserObjectsInLDAP) {
                try {
                    $UserObjectsInLDAP = GetUserObjectsInLDAP -ErrorAction Stop
                    if (!$UserObjectsInLDAP) {throw "Problem with GetUserObjectsInLDAP function! Halting!"}
                }
                catch {
                    Write-Error $_
                    $global:FunctionResult = "1"
                    throw
                }
            }

            foreach ($DirectoryEntry in $UserObjectsInLDAP) {
                if (![bool]$($DirectoryEntry | Get-Member -MemberType NoteProperty -Name Groups)) {
                    $searcher = [System.DirectoryServices.DirectorySearcher]::new($DirectoryEntry)
                    $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Base
                    $searcher.ExtendedDN = [System.DirectoryServices.ExtendedDN]::Standard
                    $searcher.PropertiesToLoad.Clear()
                    $null = $searcher.PropertiesToLoad.Add("memberof")
                    $Groups = $searcher.FindOne().Properties.memberof | foreach {$($_ -split ';')[-1]}
                    $DirectoryEntry | Add-Member -Type NoteProperty -Name Groups -Value $Groups -Force
                }
            }

            $DomainAdminsPrep = $UserObjectsInLDAP | Where-Object {$_.Groups -match "Domain Admins"}
            $DomainAdminAccounts = $DomainAdminsPrep.Name | foreach {
                if ($_ -match '=') {
                    $($_ -split "=")[-1]
                }
                else {
                    $_
                }
            }

            $AccountsReformatted = $DomainAdminAccounts | foreach {
                if (![System.String]::IsNullOrWhiteSpace($_)) {
                    $_ + "@" + $ThisDomainName.ToLowerInvariant()
                }
            }

            foreach ($Acct in $AccountsReformatted) {
                if ($AccountsAdded -notcontains $Acct -and $OriginalAuthPrincContent -notcontains $Acct) {
                    # NOTE: $True below means that the content will *appended* to $AuthorizedPrincipalsFileLocation
                    $StreamWriter.WriteLine($Acct)

                    # Keep track of the accounts we're adding...
                    $null = $AccountsAdded.Add($Acct)
                }
            }
        }

        if ($DomainUsers) {
            if (!$UserObjectsInLDAP) {
                try {
                    $UserObjectsInLDAP = GetUserObjectsInLDAP -ErrorAction Stop
                    if (!$UserObjectsInLDAP) {throw "Problem with GetUserObjectsInLDAP function! Halting!"}
                }
                catch {
                    Write-Error $_
                    $global:FunctionResult = "1"
                    throw
                }
            }

            foreach ($DirectoryEntry in $UserObjectsInLDAP) {
                if (![bool]$($DirectoryEntry | Get-Member -MemberType NoteProperty -Name Groups)) {
                    $searcher = [System.DirectoryServices.DirectorySearcher]::new($DirectoryEntry)
                    $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Base
                    $searcher.ExtendedDN = [System.DirectoryServices.ExtendedDN]::Standard
                    $searcher.PropertiesToLoad.Clear()
                    $null = $searcher.PropertiesToLoad.Add("memberof")
                    $null = $searcher.PropertiesToLoad.Add("distinguishedname")
                    $Groups = $searcher.FindOne().Properties.memberof | foreach {$($_ -split ';')[-1]}
                    $DirectoryEntry | Add-Member -Type NoteProperty -Name Groups -Value $Groups -Force
                }
            }

            $DomainUsersPrep = $UserObjectsInLDAP | Where-Object {$_.Groups -match "Domain Users"}
            $DomainUserAccounts = $DomainUsersPrep.Name | foreach {
                if ($_ -match '=') {
                    $($_ -split "=")[-1]
                }
                else {
                    $_
                }
            }

            $AccountsReformatted = $DomainUserAccounts | foreach {
                if (![System.String]::IsNullOrWhiteSpace($_)) {
                    $_ + "@" + $ThisDomainName.ToLowerInvariant()
                }
            }

            foreach ($Acct in $AccountsReformatted) {
                if ($AccountsAdded -notcontains $Acct -and $OriginalAuthPrincContent -notcontains $Acct) {
                    # NOTE: $True below means that the content will *appended* to $AuthorizedPrincipalsFileLocation
                    $StreamWriter.WriteLine($Acct)

                    # Keep track of the accounts we're adding...
                    $null = $AccountsAdded.Add($Acct)
                }
            }
        }

        if ($UsersToAdd) {
            foreach ($Acct in $UsersToAdd) {
                if ($AccountsAdded -notcontains $Acct -and $OriginalAuthPrincContent -notcontains $Acct) {
                    # NOTE: $True below means that the content will *appended* to $AuthorizedPrincipalsFileLocation
                    $StreamWriter.WriteLine($Acct)

                    # Keep track of the accounts we're adding...
                    $null = $AccountsAdded.Add($Acct)
                }
            }
        }

        $StreamWriter.Close()

        Get-Item $AuthorizedPrincipalsFileLocation
    }
    catch {
        $StreamWriter.Close()
    }
}


<#
    .SYNOPSIS
        This function generates:
            - An ArrayList of PSCustomObjects that describes the contents of each of the files within the
            "$HOME\.ssh" directory
            - An .xml file that can be ingested by the 'Import-CliXml' cmdlet to generate
            the aforementioned ArrayList of PSCustomObjects in future PowerShell sessions.
            
            Each PSCustomObject in the ArrayList contains information similar to:

                File     : C:\Users\zeroadmin\.ssh\PwdProtectedPrivKey
                FileType : RSAPrivateKey
                Contents : {-----BEGIN RSA PRIVATE KEY-----, Proc-Type: 4,ENCRYPTED, DEK-Info: AES-128-CBC,27E137C044FC7857DAAC05C408472EF8, ...}
                Info     : {-----BEGIN RSA PRIVATE KEY-----, Proc-Type: 4,ENCRYPTED, DEK-Info: AES-128-CBC,27E137C044FC7857DAAC05C408472EF8, ...}

        By default, the .xml file is written to "$HOME\.ssh\SSHDirectoryFileInfo.xml"

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER PathToHomeDotSSHDirectory
        This parameter is OPTIONAL.

        This parameter takes a string that represents a full path to the User's .ssh directory. You should
        only use this parameter if the User's .ssh is NOT under "$HOME\.ssh" for some reason. 

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Generate-SSHUserDirFileInfo
        
#>
function Generate-SSHUserDirFileInfo {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [string]$PathToHomeDotSSHDirectory
    )

    if ($PSVersionTable.Platform -eq "Unix" -or $PSVersionTable.OS -match "Darwin" -and $env:SudoPwdPrompt) {
        if (GetElevation) {
            Write-Error "You should not be running the VaultServer Module as root! Halting!"
            $global:FunctionResult = "1"
            return
        }
        RemoveMySudoPwd
        NewCronToAddSudoPwd
        $env:SudoPwdPrompt = $False
    }

    # Make sure we have access to ssh binaries
    if (![bool]$(Get-Command ssh-keygen -ErrorAction SilentlyContinue)) {
        Write-Error "Unable to find 'ssh-keygen'! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if (!$PathToHomeDotSSHDirectory) {
        $PathToHomeDotSSHDirectory = Join-Path $HOME ".ssh"
    }

    # Get a list of all files under $HOME\.ssh
    [array]$SSHHomeFiles = Get-ChildItem -Path $PathToHomeDotSSHDirectory -File | Where-Object {$_.Name -ne "SSHDirectoryFileInfo.xml"}

    if ($SSHHomeFiles.Count -eq 0) {
        Write-Error "Unable to find any files under '$PathToHomeDotSSHDirectory'! Halting!"
        $global:FunctionResult = "1"
        return
    }

    [System.Collections.ArrayList]$ArrayOfPSObjects = @()
    foreach ($File in $SSHHomeFiles.FullName) {
        #Write-Host "Analyzing file '$File' ..."
        try {
            $GetSSHFileInfoResult = Get-SSHFileInfo -PathToKeyFile $File -ErrorAction Stop -WarningAction SilentlyContinue
            if (!$GetSSHFileInfoResult) {
                #Write-Warning "'$File' is not a valid Public Key, Private Key, or Public Key Certificate!"
                #Write-Host "Ensuring '$File' is UTF8 encoded and trying again..." -ForegroundColor Yellow
                Set-Content -Path $File -Value $(Get-Content $File) -Encoding UTF8
            }

            $GetSSHFileInfoResult = Get-SSHFileInfo -PathToKeyFile $File -ErrorAction Stop -WarningAction SilentlyContinue
            if (!$GetSSHFileInfoResult) {
                Write-Verbose "'$File' is definitley not a valid Public Key, Private Key, or Public Key Certificate!"
            }

            # Sample Output:
            # NOTE: Possible values for the 'FileType' property are 'RSAPrivateKey','RSAPublicKey', and 'RSAPublicKeyCertificate'
            <#
                File     : C:\Users\zeroadmin\.ssh\PwdProtectedPrivKey
                FileType : RSAPrivateKey
                Contents : {-----BEGIN RSA PRIVATE KEY-----, Proc-Type: 4,ENCRYPTED, DEK-Info: AES-128-CBC,27E137C044FC7857DAAC05C408472EF8, ...}
                Info     : {-----BEGIN RSA PRIVATE KEY-----, Proc-Type: 4,ENCRYPTED, DEK-Info: AES-128-CBC,27E137C044FC7857DAAC05C408472EF8, ...}
            #>

            $null = $ArrayOfPSObjects.Add($GetSSHFileInfoResult)
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }
    }

    $ArrayOfPSObjects
    $ArrayOfPSObjects | Export-CliXml "$PathToHomeDotSSHDirectory\SSHDirectoryFileInfo.xml"
}


<#
    .SYNOPSIS
        This function gets the TLS certificate used by the LDAP server on the specified Port.

        The function outputs a PSCustomObject with the following properties:
            - LDAPEndpointCertificateInfo
            - RootCACertificateInfo
            - CertChainInfo
        
        The 'LDAPEndpointCertificateInfo' property is itself a PSCustomObject with teh following content:
            X509CertFormat      = $X509Cert2Obj
            PemFormat           = $PublicCertInPemFormat

        The 'RootCACertificateInfo' property is itself a PSCustomObject with teh following content:
            X509CertFormat      = $RootCAX509Cert2Obj
            PemFormat           = $RootCACertInPemFormat

        The 'CertChainInfo' property is itself a PSCustomObject with the following content:
            X509ChainFormat     = $CertificateChain
            PemFormat           = $CertChainInPemFormat
        ...where $CertificateChain is a System.Security.Cryptography.X509Certificates.X509Chain object.

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER LDAPServerHostNameOrIP
        This parameter is MANDATORY.

        This parameter takes a string that represents either the IP Address or DNS-Resolvable Name of the
        LDAP Server. If you're in a Windows environment, this is a Domain Controller's network location.

    .PARAMETER Port
        This parameter is MANDATORY.

        This parameter takes an integer that represents a port number that the LDAP Server is using that
        provides a TLS Certificate. Valid values are: 389, 636, 3268, 3269

    .PARAMETER UseOpenSSL
        This parameter is OPTIONAL. However, if $Port is 389 or 3268, then this parameter is MANDATORY.

        This parameter is a switch. If used, the latest OpenSSL available from
        http://wiki.overbyte.eu/wiki/index.php/ICS_Download will be downloaded and made available
        in the current PowerShell Session's $env:Path.


    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Fix-SSHPermissions
        
#>
function Get-LDAPCert {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True)]
        [string]$LDAPServerHostNameOrIP,

        [Parameter(Mandatory=$True)]
        [ValidateSet(389,636,3268,3269)]
        [int]$Port,

        [Parameter(Mandatory=$False)]
        [switch]$UseOpenSSL
    )

    #region >> Pre-Run Check

    try {
        $LDAPServerNetworkInfo = ResolveHost -HostNameOrIP $LDAPServerHostNameOrIP
        if (!$LDAPServerNetworkInfo) {throw "Unable to resolve $LDAPServerHostNameOrIP! Halting!"}
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    #endregion >> Pre-Run Check
    

    #region >> Main Body

    if ($UseOpenSSL) {
        # Check is openssl.exe is already available
        if ([bool]$(Get-Command openssl -ErrorAction SilentlyContinue)) {
            # Check to make sure the version is at least 1.1.0
            $OpenSSLExeInfo = Get-Item $(Get-Command openssl).Source
            $OpenSSLExeVersion = [version]$($OpenSSLExeInfo.VersionInfo.ProductVersion -split '-')[0]
        }

        # We need at least vertion 1.1.0 of OpenSSL
        if ($OpenSSLExeVersion.Major -lt 1 -or 
        $($OpenSSLExeVersion.Major -eq 1 -and $OpenSSLExeVersion.Minor -lt 1)
        ) {
            [Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"
            $OpenSSLWinBinariesUrl = "http://wiki.overbyte.eu/wiki/index.php/ICS_Download"
            $IWRResult = Invoke-WebRequest -Uri $OpenSSLWinBinariesUrl
            $LatestOpenSSLWinBinaryLinkObj = $($IWRResult.Links | Where-Object {$_.innerText -match "OpenSSL Binaries" -and $_.href -match "\.zip"})[0]
            $LatestOpenSSLWinBinaryUrl = $LatestOpenSSLWinBinaryLinkObj.href
            $OutputFileName = $($LatestOpenSSLWinBinaryUrl -split '/')[-1]
            $OutputFilePath = "$HOME\Downloads\$OutputFileName"
            Invoke-WebRequest -Uri $LatestOpenSSLWinBinaryUrl -OutFile $OutputFilePath

            if (!$(Test-Path "$HOME\Downloads\$OutputFileName")) {
                Write-Error "Problem downloading the latest OpenSSL Windows Binary from $LatestOpenSSLWinBinaryUrl ! Halting!"
                $global:FunctionResult = "1"
                return
            }

            $OutputFileItem = Get-Item $OutputFilePath
            $ExpansionDirectory = $OutputFileItem.Directory.FullName + "\" + $OutputFileItem.BaseName
            if (!$(Test-Path $ExpansionDirectory)) {
                $null = New-Item -ItemType Directory -Path $ExpansionDirectory -Force
            }
            else {
                Remove-Item "$ExpansionDirectory\*" -Recurse -Force
            }

            $null = Expand-Archive -Path "$HOME\Downloads\$OutputFileName" -DestinationPath $ExpansionDirectory -Force

            # Add $ExpansionDirectory to $env:Path
            $CurrentEnvPathArray = $env:Path -split ";"
            if ($CurrentEnvPathArray -notcontains $ExpansionDirectory) {
                # Place $ExpansionDirectory at start so latest openssl.exe get priority
                $env:Path = "$ExpansionDirectory;$env:Path"
            }
        }

        if (![bool]$(Get-Command openssl -ErrorAction SilentlyContinue)) {
            Write-Error "Problem setting openssl.exe to `$env:Path! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    if ($Port -eq 389 -or $Port -eq 3268) {
        if (!$UseOpenSSL) {
            Write-Error "Unable to get LDAP Certificate on port $Port using StartTLS without openssl.exe! Try the -UseOpenSSL switch. Halting!"
            $global:FunctionResult = "1"
            return
        }

        $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
        #$ProcessInfo.WorkingDirectory = $BinaryPath | Split-Path -Parent
        $ProcessInfo.FileName = $(Get-Command openssl).Source
        $ProcessInfo.RedirectStandardError = $true
        $ProcessInfo.RedirectStandardOutput = $true
        #$ProcessInfo.StandardOutputEncoding = [System.Text.Encoding]::Unicode
        #$ProcessInfo.StandardErrorEncoding = [System.Text.Encoding]::Unicode
        $ProcessInfo.UseShellExecute = $false
        $ProcessInfo.Arguments = "s_client -connect $($LDAPServerNetworkInfo.FQDN):$Port -starttls ldap -showcerts"
        $Process = New-Object System.Diagnostics.Process
        $Process.StartInfo = $ProcessInfo
        $Process.Start() | Out-Null
        # Sometimes openssl.exe hangs, so, we'll give it 5 seconds before killing
        # Below $FinishedInAlottedTime returns boolean true/false
        $FinishedInAlottedTime = $Process.WaitForExit(5000)
        if (!$FinishedInAlottedTime) {
            $Process.Kill()
        }
        $stdout = $Process.StandardOutput.ReadToEnd()
        $stderr = $Process.StandardError.ReadToEnd()
        $OpenSSLResult = $stdout + $stderr

        # Parse the output of openssl
        $OpenSSLResultLineBreaks = $OpenSSLResult -split "`n"
        $IndexOfBeginCert = $OpenSSLResultLineBreaks.IndexOf($($OpenSSLResultLineBreaks -match "BEGIN CERTIFICATE"))
        $IndexOfEndCert = $OpenSSLResultLineBreaks.IndexOf($($OpenSSLResultLineBreaks -match "End CERTIFICATE"))

        if ($IndexOfBeginCert -eq "-1" -or $IndexOfEndCert -eq "-1") {
            Write-Error "Unable to find Certificate in openssl output! Halting!"
            $global:FunctionResult = "1"
            return
        }
        
        $PublicCertInPemFormat = $OpenSSLResultLineBreaks[$IndexOfBeginCert..$IndexOfEndCert]

        # Get $X509Cert2Obj
        $PemString = $($PublicCertInPemFormat | Where-Object {$_ -notmatch "CERTIFICATE"}) -join "`n"
        $byteArray = [System.Convert]::FromBase64String($PemString)
        $X509Cert2Obj = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($byteArray)
    }

    if ($Port -eq 636 -or $Port -eq 3269) {
        if ($UseOpenSSL) {
            $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
            #$ProcessInfo.WorkingDirectory = $BinaryPath | Split-Path -Parent
            $ProcessInfo.FileName = $(Get-Command openssl).Source
            $ProcessInfo.RedirectStandardError = $true
            $ProcessInfo.RedirectStandardOutput = $true
            #$ProcessInfo.StandardOutputEncoding = [System.Text.Encoding]::Unicode
            #$ProcessInfo.StandardErrorEncoding = [System.Text.Encoding]::Unicode
            $ProcessInfo.UseShellExecute = $false
            $ProcessInfo.Arguments = "s_client -connect $($LDAPServerNetworkInfo.FQDN):$Port"
            $Process = New-Object System.Diagnostics.Process
            $Process.StartInfo = $ProcessInfo
            $Process.Start() | Out-Null
            # Sometimes openssl.exe hangs, so, we'll give it 5 seconds before killing
            # Below $FinishedInAlottedTime returns boolean true/false
            $FinishedInAlottedTime = $Process.WaitForExit(5000)
            if (!$FinishedInAlottedTime) {
                $Process.Kill()
            }
            $stdout = $Process.StandardOutput.ReadToEnd()
            $stderr = $Process.StandardError.ReadToEnd()
            $OpenSSLResult = $stdout + $stderr

            # Parse the output of openssl
            $OpenSSLResultLineBreaks = $OpenSSLResult -split "`n"
            $IndexOfBeginCert = $OpenSSLResultLineBreaks.IndexOf($($OpenSSLResultLineBreaks -match "BEGIN CERTIFICATE"))
            $IndexOfEndCert = $OpenSSLResultLineBreaks.IndexOf($($OpenSSLResultLineBreaks -match "End CERTIFICATE"))
            
            if ($IndexOfBeginCert -eq "-1" -or $IndexOfEndCert -eq "-1") {
                Write-Error "Unable to find Certificate in openssl output! Halting!"
                $global:FunctionResult = "1"
                return
            }

            $PublicCertInPemFormat = $OpenSSLResultLineBreaks[$IndexOfBeginCert..$IndexOfEndCert]

            # Get $X509Cert2Obj
            $PemString = $($PublicCertInPemFormat | Where-Object {$_ -notmatch "CERTIFICATE"}) -join "`n"
            $byteArray = [System.Convert]::FromBase64String($PemString)
            $X509Cert2Obj = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($byteArray)
        }
        else {
            $X509Cert2Obj = Check-Cert -IPAddress $LDAPServerNetworkInfo.IPAddressList[0] -Port $Port
            $PublicCertInPemFormatPrep = "-----BEGIN CERTIFICATE-----`n" + 
                [System.Convert]::ToBase64String($X509Cert2Obj.RawData, [System.Base64FormattingOptions]::InsertLineBreaks) + 
                "`n-----END CERTIFICATE-----"
            $PublicCertInPemFormat = $PublicCertInPemFormatPrep -split "`n"
        }
    }

    $CertificateChain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
    $null = $CertificateChain.Build($X509Cert2Obj)
    [System.Collections.ArrayList]$CertsInPemFormat = @()
    foreach ($Cert in $CertificateChain.ChainElements.Certificate) {
        $CertInPemFormatPrep = "-----BEGIN CERTIFICATE-----`n" + 
        [System.Convert]::ToBase64String($Cert.RawData, [System.Base64FormattingOptions]::InsertLineBreaks) + 
        "`n-----END CERTIFICATE-----"
        $CertInPemFormat = $CertInPemFormatPrep -split "`n"
        
        $null = $CertsInPemFormat.Add($CertInPemFormat)
    }
    $CertChainInPemFormat = $($CertsInPemFormat | Out-String).Trim()

    $RootCAX509Cert2Obj = $CertificateChain.ChainElements.Certificate | Where-Object {$_.Issuer -eq $_.Subject}
    $RootCAPublicCertInPemFormatPrep = "-----BEGIN CERTIFICATE-----`n" + 
        [System.Convert]::ToBase64String($RootCAX509Cert2Obj.RawData, [System.Base64FormattingOptions]::InsertLineBreaks) + 
        "`n-----END CERTIFICATE-----"
    $RootCACertInPemFormat = $RootCAPublicCertInPemFormatPrep -split "`n"

    # Create Output

    $LDAPEndpointCertificateInfo = [pscustomobject]@{
        X509CertFormat      = $X509Cert2Obj
        PemFormat           = $PublicCertInPemFormat
    }

    $RootCACertificateInfo = [pscustomobject]@{
        X509CertFormat      = $RootCAX509Cert2Obj
        PemFormat           = $RootCACertInPemFormat
    }

    $CertChainInfo = [pscustomobject]@{
        X509ChainFormat     = $CertificateChain
        PemFormat           = $CertChainInPemFormat
    }

    [pscustomobject]@{
        LDAPEndpointCertificateInfo  = $LDAPEndpointCertificateInfo
        RootCACertificateInfo        = $RootCACertificateInfo
        CertChainInfo                = $CertChainInfo
    }
    
    #endregion >> Main Body
}


<#
    .SYNOPSIS
        This function is used to determine the most efficient ssh.exe command that should work
        on the Remote Host (assuming the sshd server on the remote host is configured properly).

        By providing this function ONE of the following parameters...
            SSHKeyFilePath
            SSHPublicKeyFilePath
            SSHPrivateKeyFilePath
            SSHPublicCertFilePath
        ...this function will find all related files (as long as they're in the "$HOME\.ssh" directory
        or in the ssh-agent). Then, depending on the type of authentication you would like to use
        (which you sould specify using the -AuthMethod parameter), this function will output a PSCustomObject
        with properties similar to:
            PublicKeyAuthShouldWork (Boolean)
            PublicKeyCertificateAuthShouldWork (Boolean)
            SSHClientProblemDescription (String)
            FinalSSHExeCommand (String)
        
        The property 'PublicKeyAuthShouldWork' will appear only if -AuthMethod is "PublicKey".
        The property 'PublicKeyCertificateAuthShouldWork' will appear only if -AuthMethod is "PublicKeyCertificate".
        The property 'SSHClientProblemDescription' will appear only if an SSH Command cannot be determined.
        The property 'FinalSSHExeCommand' will always appear. It might be $null if a command cannot be determined.

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER SSHKeyFilePath
        This parameter is MANDATORY for its given Parameter Set.

        This parameter takes a string that represents a full path to an SSH Key/Cert file.

        This parameter should be used if you are certain that the specified file is related to SSH
        Authentication, but you are not sure if the file is a Public Key, Private Key, or Public Certificate.

        It is HIGHLY RECOMMENDED that you use this parameter instead of -SSHPublicKeyFilePath or
        -SSHPrivateKeyFilePath or -SSHPublicCertFilePath.

    .PARAMETER SSHPublicKeyFilePath
        This parameter is MANDATORY for its given Parameter Set.

        This parameter takes a string that represents a full path to an SSH Public Key file. If the file
        is NOT an SSH Public Key file, the function will halt.

    .PARAMETER SSHPrivateKeyFilePath
        This parameter is MANDATORY for its given Parameter Set.

        This parameter takes a string that represents a full path to an SSH Private Key file. If the file
        is NOT an SSH Private Key file, the function will halt.

    .PARAMETER SSHPublicCertFilePath
        This parameter is MANDATORY for its given Parameter Set.

        This parameter takes a string that represents a full path to an SSH Public Certificate file. If the file
        is NOT an SSH Public Certificate file, the function will halt.

    .PARAMETER AuthMethod
        This parameter is MANDATORY.

        This parameter takes a string that must be one of two values: "PublicKey", "PublicKeyCertificate"

        If you would like this function to output an ssh command that uses Public Key Authentication,
        use "PublicKey" for this parameter. If you would like this function to ouput an ssh command that
        uses Public Certificate Authentication, use "PublicKeyCertificate" for this parameter.

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Get-SSHClientAuthSanity -SSHKeyFilePath "$HOME\.ssh\id_rsa"
        
#>
function Get-SSHClientAuthSanity {
    [CmdletBinding(DefaultParameterSetName="UnknownKey")]
    Param(
        [Parameter(
            Mandatory=$True,
            ParameterSetName="UnknownKey"
        )]
        [string]$SSHKeyFilePath,

        [Parameter(
            Mandatory=$True,
            ParameterSetName="PublicKey"
        )]
        [string]$SSHPublicKeyFilePath,

        [Parameter(
            Mandatory=$True,
            ParameterSetName="PrivateKey"
        )]
        [string]$SSHPrivateKeyFilePath,

        [Parameter(
            Mandatory=$True,
            ParameterSetName="PublicCert"
        )]
        [string]$SSHPublicCertFilePath,

        [Parameter(Mandatory=$False)]
        [ValidateSet("PublicKey","PublicKeyCertificate")]
        [string]$AuthMethod = "PublicKey"
    )

    if ($PSVersionTable.Platform -eq "Unix" -or $PSVersionTable.OS -match "Darwin" -and $env:SudoPwdPrompt) {
        if (GetElevation) {
            Write-Error "You should not be running the VaultServer Module as root! Halting!"
            $global:FunctionResult = "1"
            return
        }
        RemoveMySudoPwd
        NewCronToAddSudoPwd
        $env:SudoPwdPrompt = $False
    }

    # Make sure we have access to ssh binaries
    if (![bool]$(Get-Command ssh-keygen -ErrorAction SilentlyContinue)) {
        Write-Error "Unable to find 'ssh-keygen'! Halting!"
        $global:FunctionResult = "1"
        return
    }

    $BoundParametersDictionary = $PSCmdlet.MyInvocation.BoundParameters
    [array]$UsedParameterNames = $($BoundParametersDictionary.GetEnumerator()).Key
    $SSHFilePathParameter = $UsedParameterNames | Where-Object {$_ -match "SSHKeyFilePath|SSHPublicKeyFilePath|SSHPrivateKeyFilePath|SSHPublicCertFilePath"}
    $SSHKeyFilePath = Get-Variable -Name $SSHFilePathParameter -ValueOnly

    # Make sure the SSHKeyFilePath exists
    if (!$(Test-Path $SSHKeyFilePath)) {
        Write-Error "The path '$SSHKeyFilePath' was not found! Halting!"
        $global:FunctionResult = "1"
        return
    }
    else {
        $SSHKeyFilePath = $(Resolve-Path $SSHKeyFilePath).Path
    }

    if ($SSHPublicCertFilePath) {
        $AuthMethod = "PublicKeyCertificate"
    }

    # Inspect the SSHKeyFile
    try {
        $CheckSSHKeyFile = Get-SSHFileInfo -PathToKeyFile $SSHKeyFilePath -ErrorAction Stop -WarningAction SilentlyContinue
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    if ($CheckSSHKeyFile.FileType -eq $null) {
        Write-Error "The file '$SSHKeyFilePath' does not appear to be an RSA Public Key, RSA Public Key Certificate, or RSA Private Key! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($SSHPublicKeyFilePath -and $CheckSSHKeyFile.FileType -ne "RSAPublicKey") {
        if ($CheckSSHKeyFile.FileType -eq "RSAPublicKeyCertificate") {
            $CorrectParameter = "SSHPublicKeyCertFilePath"
        }
        if ($CheckSSHKeyFile.FileType -eq "RSAPrivateKey") {
            $CorrectParameter = "SSHPrivateKeyCertFilePath"
        }
        
        $ParamErrMsg = "The file '$SSHPublicKeyFilePath' does not appear to be an RSA Public Key! " +
        "Instead, it appears to be an $($CheckSSHKeyFile.FileType)! Please use the -$CorrectParameter parameter instead. Halting!"
        Write-Error $ParamErrMsg
        $global:FunctionResult = "1"
        return
    }
    if ($SSHPublicCertFilePath -and $CheckSSHKeyFile.FileType -ne "RSAPublicKeyCertificate") {
        if ($CheckSSHKeyFile.FileType -eq "RSAPublicKey") {
            $CorrectParameter = "SSHPublicKeyFilePath"
        }
        if ($CheckSSHKeyFile.FileType -eq "RSAPrivateKey") {
            $CorrectParameter = "SSHPrivateKeyCertFilePath"
        }

        $ParamErrMsg = "The file '$SSHPublicKeyFilePath' does not appear to be an RSA Public Key! " +
        "Instead, it appears to be an $($CheckSSHKeyFile.FileType)! Please use the -$CorrectParameter parameter instead. Halting!"
        Write-Error $ParamErrMsg
        $global:FunctionResult = "1"
        return
    }
    if ($SSHPrivateKeyFilePath -and $CheckSSHKeyFile.FileType -ne "RSAPrivateKey") {
        if ($CheckSSHKeyFile.FileType -eq "RSAPublicKey") {
            $CorrectParameter = "SSHPublicKeyFilePath"
        }
        if ($CheckSSHKeyFile.FileType -eq "RSAPublicKeyCertificate") {
            $CorrectParameter = "SSHPublicKeyCertFilePath"
        }

        $ParamErrMsg = "The file '$SSHPublicKeyFilePath' does not appear to be an RSA Public Key! " +
        "Instead, it appears to be an $($CheckSSHKeyFile.FileType)! Please use the -$CorrectParameter parameter instead. Halting!"
        Write-Error $ParamErrMsg
        $global:FunctionResult = "1"
        return
    }

    if ($CheckSSHKeyFile.FileType -eq "RSAPublicKeyCertificate") {
        $SSHPublicCertFilePath = $CheckSSHKeyFile.File
    }
    if ($CheckSSHKeyFile.FileType -eq "RSAPublicKey") {
        $SSHPublicKeyFilePath = $CheckSSHKeyFile.File
    }
    if ($CheckSSHKeyFile.FileType -eq "RSAPrivateKey") {
        $SSHPrivateKeyFilePath = $CheckSSHKeyFile.File
    }

    if ($SSHPublicCertFilePath) {
        if ($(Get-Item $SSHPublicCertFilePath).Name -notmatch "-cert\.pub") {
            $SSHKeyFilePath = $SSHPublicCertFilePath -replace "\..*?$","-cert.pub"
            Rename-Item -Path $SSHPublicCertFilePath -NewName $SSHKeyFilePath
        }
    }
    if ($SSHPublicKeyFilePath) {
        if ($(Get-Item $SSHPublicKeyFilePath).Name -notmatch "\.pub") {
            $SSHKeyFilePath = $SSHPublicKeyFilePath -replace "\..*?$",".pub"
            Rename-Item -Path $SSHPublicKeyFilePath -NewName $SSHKeyFilePath
        }
    }
    if ($SSHPrivateKeyFilePath) {
        if ($(Get-Item $SSHPrivateKeyFilePath).Name -match "\..*?$" -and $(Get-Item $SSHPrivateKeyFilePath).Name -notmatch "\.pem$") {
            $SSHKeyFilePath = $SSHPrivateKeyFilePath -replace "\..*?$",""
            Rename-Item -Path $SSHPrivateKeyFilePath -NewName $SSHKeyFilePath
        }
    }

    $KeyFileParentDirectory = $SSHKeyFilePath | Split-Path -Parent

    # Inspect all files in $SSHKeyFilePath Parent Directory (should just be '$HOME/.ssh')
    try {
        $GenSSHDirFileInfoSplatParams = @{
            PathToHomeDotSSHDirectory       = $KeyFileParentDirectory
            WarningAction                   = "SilentlyContinue"
            ErrorAction                     = "Stop"
        }

        $SSHDirFileInfo = Generate-SSHUserDirFileInfo @GenSSHUserDirFileInfoSplatParams
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    # Get all related Key Files
    $FingerPrintRelevantString = $($CheckSSHKeyFile.FingerPrint -split " ")[1]
    $RelatedKeyFileInfoObjects = $SSHDirFileInfo | Where-Object {$_.FingerPrint -match [regex]::Escape($FingerPrintRelevantString)}

    if ($RelatedKeyFileInfoObjects.FileType -contains "RSAPublicKeyCertificate") {
        $AuthMethod = "PublicKeyCertificate"
    }
    # NOTE: Each PSCustomObject in the above $RelatedKeyFileInfoObjects has the following properties:
    # File - [string] Absolute File Path
    # FileType - [string] with possible values 'RSAPublicKey', 'RSAPrivateKey', 'RSAPublicKeyCertificate', 'PuttyCombinedPublicPrivateKey', or 'SSH2_RFC4716'
    # Contents - Result of `Get-Content` on File. Could be [string] or [string[]] if RSAPrivateKey, PuttyCombinedPublicPrivateKey, or SSH2_RFC4716
    # Info - Could be either result of `Get-Content` on File or an `ssh-keygen` command. Could be [string] or [string[]] depending
    # FingerPrint - Could be [string] or $null if PuttyCombinedPublicPrivateKey, or SSH2_RFC4716
    # PasswordProtected - Could be [bool] or $null if PuttyCombinedPublicPrivateKey, or SSH2_RFC4716

    # We're most likely going to need the fingerprints of the keys loaded in the ssh-agent, so get that info now
    $SSHAgentOutput = [scriptblock]::Create('ssh-add -L').InvokeReturnAsIs()
    if ($LASTEXITCODE -ne 0) {
        Write-Warning $Error[0].Exception.Message
    }
    
    if ($SSHAgentOutput) {
        $tempDirectory = [IO.Path]::Combine([IO.Path]::GetTempPath(), [IO.Path]::GetRandomFileName()) -replace "\..*?$",""
        $null = [IO.Directory]::CreateDirectory($tempDirectory)
        [System.Collections.ArrayList]$RSAPubKeyTempFiles = @()
        $Counter = 0
        foreach ($RSAPubKey in $SSHAgentOutput) {
            Set-Content -Path "$tempDirectory/RSAPubKey$Counter" -Value $RSAPubKey
            $null = $RSAPubKeyTempFiles.Add("$tempDirectory/RSAPubKey$Counter")
            $Counter++
        }
        [System.Collections.ArrayList]$SSHAgentKeyFingerPrintsInSSHAgent = @()
        foreach ($RSAPubKeyFile in $RSAPubKeyTempFiles) {
            $PSCustObj = [pscustomobject]@{
                File                = $RSAPubKeyFile
                FingerPrint         = [scriptblock]::Create("ssh-keygen -l -f $RSAPubKeyFile").InvokeReturnAsIs()
                Contents            = $(Get-Content $RSAPubKeyFile)
            }
            $null = $SSHAgentKeyFingerPrintsInSSHAgent.Add($PSCustObj)
        }
        # Cleanup
        Remove-Item $tempDirectory -Recurse -Force

        # Check to see if the Private Key is Loaded in the ssh-agent
        $RelevantString = $($CheckSSHKeyFile.FingerPrint -split " ")[1]
        if ($SSHAgentKeyFingerPrintsInSSHAgent.FingerPrint -match [regex]::Escape($RelevantString)) {
            $PrivateKeyIsLoadedInSSHAgent = $True
            if ($SSHAgentKeyFingerPrintsInSSHAgent.Count -eq 1) {
                $PositionOfLoadedPrivateKey = 0
            }
            elseif ($SSHAgentKeyFingerPrintsInSSHAgent.Count -gt 1) {
                $PositionOfLoadedPrivateKey = $SSHAgentKeyFingerPrintsInSSHAgent.FingerPrint.IndexOf($($SSHAgentKeyFingerPrintsInSSHAgent.FingerPrint -match [regex]::Escape($RelevantString)))
            }
        }
        else {
            $PrivateKeyIsLoadedInSSHAgent = $False
        }
    }

    [System.Collections.ArrayList]$NeededAdditionalSSHExeOptions = @()

    # If $AuthMethod is "PublicKey" we need to track down the Public Key and the Private Key
    if ($AuthMethod -eq "PublicKey") {
        # If we were provided the path to the Public Key, then we just need to track down the Private Key
        # It could either be in the same directory as the Public Key or in the ssh-agent
        if ($SSHPublicKeyFilePath) {
            # If `$RelatedKeyFileInfoObjects.Count -eq 1` then we know that the Private Key is NOT in $KeyFileParentDirectory,
            # so we have to look for it in the ssh-agent
            if ($RelatedKeyFileInfoObjects.Count -eq 1 -or
            $($($RelatedKeyFileInfoObjects.Count -ge 2 -and $RelatedKeyFileInfoObjects.FileType -notcontains "RSAPrivateKey"))
            ) {
                # If the corresponding Private Key isn't loaded in the ssh-agent, or if it's too far down in the list, then we have a problem
                if (!$PrivateKeyIsLoadedInSSHAgent -or $PositionOfLoadedPrivateKey -ge 4) {
                    if (!$PrivateKeyIsLoadedInSSHAgent) {
                        $SSHClientProblemDescription = "The Private Key is not on the filesystem under $KeyFileParentDirectory or loaded in the ssh-agent!"
                    }
                    if ($PositionOfLoadedPrivateKey -ge 4) {
                        $SSHClientProblemDescription = "The Private Key is not on the filesystem in same directory " +
                        "as the Public Key (i.e. $KeyFileParentDirectory). The Private Key IS loaded in the ssh-agent, " +
                        "however, it is not in the top 5 on the list, so the sshd server on the Remote Host will most " +
                        "likely reject authentication because of too many attempts!"
                        $PubKeyAuthShouldWork = $False
                    }
                    $PubKeyAuthShouldWork = $False
                }
                if ($PrivateKeyIsLoadedInSSHAgent -and $PositionOfLoadedPrivateKey -lt 4) {
                    $PubKeyAuthShouldWork = $True
                }
            }
            # If `$RelatedKeyFileInfoObjects.Count -eq 2`, then one of those is the RSAPublicKey, but we need to
            # confirm that the other is actually the RSAPrivateKey. If not, then we need to check the ssh-agent
            # for the Private Key.
            if ($RelatedKeyFileInfoObjects.Count -ge 2 -and $RelatedKeyFileInfoObjects.FileType -contains "RSAPrivateKey") {
                if (!$PrivateKeyIsLoadedInSSHAgent) {
                    $PubKeyAuthShouldWork = $True
                    if ($SSHAgentKeyFingerPrintsInSSHAgent.Count -gt 4) { 
                        $null = $NeededAdditionalSSHExeOptions.Add("IdentitiesOnly")
                    }
                    $null = $NeededAdditionalSSHExeOptions.Add("iPathToPrivateKey")
                    $FinalPathToPrivateKey = $($RelatedKeyFileInfoObjects | Where-Object {$_.FileType -eq "RSAPrivateKey"}).File
                }
                if ($PositionOfLoadedPrivateKey -ge 4) {
                    $PubKeyAuthShouldWork = $True
                    $null = $NeededAdditionalSSHExeOptions.Add("IdentitiesOnly")
                    $null = $NeededAdditionalSSHExeOptions.Add("iPathToPrivateKey")
                    $FinalPathToPrivateKey = $($RelatedKeyFileInfoObjects | Where-Object {$_.FileType -eq "RSAPrivateKey"}).File
                }
                if ($PrivateKeyIsLoadedInSSHAgent -and $PositionOfLoadedPrivateKey -lt 4) {
                    $PubKeyAuthShouldWork = $True
                }
            }
        }
        # If we are provided the Private Key, we should (just for organization's sake) make sure the corresponding
        # Public Key is in $KeyFileParentDirectory. Also, depending on if the Private Key is loaded in the ssh-agent,
        # we may or may not need `-i <PathToPrivateKey>` in the final ssh.exe command.
        if ($SSHPrivateKeyFilePath) {
            # If `$RelatedKeyFileInfoObjects.Count -eq 1`, then we only have the Private Key on the filesystem
            # under $KeyFileParentDirectory. So, we should create the Public Key File alongside it.
            if ($RelatedKeyFileInfoObjects.Count -eq 1 -or 
            $($RelatedKeyFileInfoObjects.Count -ge 2 -and $RelatedKeyFileInfoObjects.FileType -notcontains "RSAPublicKey")
            ) {
                $RSAPublicKeyString = ssh-keygen -y -f "$SSHPrivateKeyFilePath"
                Set-Content -Value $RSAPublicKeyString -Path "$SSHPrivateKeyFilePath.pub"
            }

            if (!$PrivateKeyIsLoadedInSSHAgent) {
                $PubKeyAuthShouldWork = $True
                if ($SSHAgentKeyFingerPrintsInSSHAgent.Count -gt 4) { 
                    $null = $NeededAdditionalSSHExeOptions.Add("IdentitiesOnly")
                }
                $null = $NeededAdditionalSSHExeOptions.Add("iPathToPrivateKey")
                $FinalPathToPrivateKey = $SSHPrivateKeyFilePath
            }
            if ($PositionOfLoadedPrivateKey -ge 4) {
                $PubKeyAuthShouldWork = $True
                $null = $NeededAdditionalSSHExeOptions.Add("IdentitiesOnly")
                $null = $NeededAdditionalSSHExeOptions.Add("iPathToPrivateKey")
                $FinalPathToPrivateKey = $SSHPrivateKeyFilePath
            }
            if ($PrivateKeyIsLoadedInSSHAgent -and $PositionOfLoadedPrivateKey -lt 4) {
                $PubKeyAuthShouldWork = $True
            }
        }
    }

    # If $AuthMethod is "PublicKeyCertificate", we need to track down the Public Key Certificate and the Private Key
    if ($AuthMethod -eq "PublicKeyCertificate") {
        if ($SSHPublicCertFilePath) {
            if ($RelatedKeyFileInfoObjects.Count -eq 1 -or 
            $($RelatedKeyFileInfoObjects.Count -ge 2 -and $RelatedKeyFileInfoObjects.FileType -notcontains "RSAPrivateKey")
            ) {
                # If `$RelatedKeyFileInfoObjects.Count -eq 1`, the only relevant SSH Key File we have in our $HOME\.ssh directory
                # is the Public Key Certificate

                # If the corresponding Private Key isn't loaded in the ssh-agent, then we have a problem...
                if (!$PrivateKeyIsLoadedInSSHAgent) {
                    $SSHClientProblemDescription = "Unable to find Private Key in ssh-agent or in same directory as the Public Key Certificate (i.e. $KeyFileParentDirectory)!"
                    $PubCertAuthShouldWork = $False
                }
                # If the Private Key IS Loaded in the ssh-agent, but it is too far down on the list, we have a problem...
                if ($PositionOfLoadedPrivateKey -ge 4) {
                    $SSHClientProblemDescription = "The Private Key is not on the filesystem in same directory " +
                    "as the Public Key (i.e. $KeyFileParentDirectory). The Private Key IS loaded in the ssh-agent, "
                    "however, it is not in the top 5 on the list, so the sshd server on the Remote Host will most " +
                    "likely reject authentication because of too many attempts!"
                    $PubCertAuthShouldWork = $False
                }
                if ($PrivateKeyIsLoadedInSSHAgent -and $PositionOfLoadedPrivateKey -lt 4) {
                    # Even if the Private Key is Loaded in the ssh-agent and it's low enough on the list,
                    # we need to make sure that the ssh-agent is aware of the Public Key Certificate specifically
                    #
                    # NOTE: In the below, we can use `$_.Contents -eq $(Get-Content $SSHPublicCertFilePath)`
                    # as opposed to `$(Compare-Object $_.Contents $(Get-Content $SSHPublicCertFilePath)) -eq $null` because
                    # each should be a single string (as opposed to an array of strings)
                    $PublicCertLoadedCheck = $SSHAgentKeyFingerPrintsInSSHAgent | Where-Object {
                        $_.FingerPrint -match [regex]::Escape($RelevantString) -and
                        $($($_.Contents -split " ")[0..1] -join " ") -eq $($($(Get-Content $SSHPublicCertFilePath) -split " ")[0..1] -join " ")
                    }
                    
                    if ($PublicCertLoadedCheck) {
                        $PubCertAuthShouldWork = $True
                    }
                    else {
                        $SSHClientProblemDescription = "The Private Key is loaded in the ssh-agent and it is low enough " +
                        "on the list of keys to present to the Remote Host, HOWEVER, the ssh-agent does not appear to be " +
                        "aware of the Public Key Certificate (i.e. 'ssh-add -L' will not contain the output of " +
                        "'Get-Content '$SSHPublicCertFilePath''. To remedy, remove the key from the ssh-agent via " +
                        "'ssh-add -d', ensure the Public Key Certificate is in the same directory as the Private Key, " +
                        "ensure the Public Key Certificate file has the same file name as the Private Key just appended " +
                        "with '-cert.pub', and add the Private Key to the ssh-agent via 'ssh-add <PathToPrivateKeyFile>' "
                        $PubCertAuthShouldWork = $False
                    }
                }
            }
            if ($RelatedKeyFileInfoObjects.Count -ge 2 -and $RelatedKeyFileInfoObjects.FileType -contains "RSAPrivateKey") {
                # One of these two objects is the Public Key Certificate. The other one is either the RSAPrivateKey
                # or the RSAPublicKey. If it's the RSAPrivateKey, we should generate the RSAPublicKey regardless
                # of whether or not the Private Key is loaded in the ssh-agent. We should also  make sure
                # the File Names of the RSAPrivateKey and RSAPublicKey resemble the File Name of RSAPublicKeyCertificate.
                # We should also note that if the Private Key isn't loaded in the ssh-agent, we'll need to use the
                # `-i <PathToPrivateKeyFile>` option in addition to the `-i <PathToPublicKeyCertificate>` with ssh.exe
                $PrivateKeyFileInfoObject = $RelatedKeyFileInfoObjects | Where-Object {$_.FileType -eq "RSAPrivateKey"}
                if ($RelatedKeyFileInfoObjects.FileType -notcontains "RSAPublicKey") {
                    $RSAPublicKeyString = ssh-keygen -y -f "$($PrivateKeyFileInfoObject.File)"
                    $OutputPath = "$($PrivateKeyFileInfoObject.File)" + ".pub"
                    Set-Content -Value $RSAPublicKeyString -Path $OutputPath
                }

                if (!$PrivateKeyIsLoadedInSSHAgent) {
                    $PubCertAuthShouldWork = $True
                    if ($SSHAgentKeyFingerPrintsInSSHAgent.Count -gt 4) { 
                        $null = $NeededAdditionalSSHExeOptions.Add("IdentitiesOnly")
                    }
                    $null = $NeededAdditionalSSHExeOptions.Add("iPathToPrivateKey")
                    $FinalPathToPrivateKey = $PrivateKeyFileInfoObject.File
                    $null = $NeededAdditionalSSHExeOptions.Add("iPathToPublicCert")
                    $FinalPathToPublicCert = $SSHPublicCertFilePath
                }
                if ($PositionOfLoadedPrivateKey -ge 4) {
                    $PubCertAuthShouldWork = $True
                    if ($SSHAgentKeyFingerPrintsInSSHAgent.Count -gt 4) { 
                        $null = $NeededAdditionalSSHExeOptions.Add("IdentitiesOnly")
                    }
                    $null = $NeededAdditionalSSHExeOptions.Add("iPathToPrivateKey")
                    $FinalPathToPrivateKey = $PrivateKeyFileInfoObject.File
                }
                if ($PrivateKeyIsLoadedInSSHAgent -and $PositionOfLoadedPrivateKey -lt 4) {
                    # Even if the Private Key is Loaded in the ssh-agent and it's low enough on the list,
                    # we need to make sure that the ssh-agent is aware of the Public Key Certificate specifically
                    #
                    # NOTE: In the below, we can use `$_.Contents -eq $(Get-Content $SSHPublicCertFilePath)`
                    # as opposed to `$(Compare-Object $_.Contents $(Get-Content $SSHPublicCertFilePath)) -eq $null` because
                    # each should be a single string (as opposed to an array of strings)
                    $PublicCertLoadedCheck = $SSHAgentKeyFingerPrintsInSSHAgent | Where-Object {
                        $_.FingerPrint -match [regex]::Escape($RelevantString) -and
                        $($($_.Contents -split " ")[0..1] -join " ") -eq $($($(Get-Content $SSHPublicCertFilePath) -split " ")[0..1] -join " ")
                    }
                    
                    if ($PublicCertLoadedCheck) {
                        $PubCertAuthShouldWork = $True
                    }
                    else {
                        $SSHClientProblemDescription = "The Private Key is loaded in the ssh-agent and it is low enough " +
                        "on the list of keys to present to the Remote Host, HOWEVER, the ssh-agent does not appear to be " +
                        "aware of the Public Key Certificate (i.e. 'ssh-add -L' will not contain the output of " +
                        "'Get-Content '$SSHPublicCertFilePath''. To remedy, remove the key from the ssh-agent via " +
                        "'ssh-add -d', ensure the Public Key Certificate is in the same directory as the Private Key, " +
                        "ensure the Public Key Certificate file has the same file name as the Private Key just appended " +
                        "with '-cert.pub', and add the Private Key to the ssh-agent via 'ssh-add <PathToPrivateKeyFile>' "
                        $PubCertAuthShouldWork = $False
                    }
                }
            }
        }
        if ($SSHPublicKeyFilePath) {
            # If the corresponding Private Key is loaded in the ssh-agent, then we need to make sure it reflects
            # a Public Key Certificate (i.e. content should not equal `Get-Content $SSHPublicKeyFile`).
            # If the corresponding Private Key is NOT Loaded in the ssh-agent, then it better be on the filesystem,
            # otherwise, we're out of luck.
            if ($RelatedKeyFileInfoObjects.Count -eq 1 -or 
            $($RelatedKeyFileInfoObjects.Count -ge 2 -and $RelatedKeyFileInfoObjects.FileType -notcontains "RSAPrivateKey")
            ) {
                if (!$PrivateKeyIsLoadedInSSHAgent) {
                    $PubCertAuthShouldWork = $False
                    $SSHClientProblemDescription = "Unable to find Private Key in ssh-agent or in same directory as the Public Key (i.e. $KeyFileParentDirectory)!"
                }
                if ($PositionOfLoadedPrivateKey -ge 4) {
                    $SSHClientProblemDescription = "The Private Key is not on the filesystem in same directory " +
                    "as the Public Key (i.e. $KeyFileParentDirectory). The Private Key IS loaded in the ssh-agent, "
                    "however, it is not in the top 5 on the list, so the sshd server on the Remote Host will most " +
                    "likely reject authentication because of too many attempts!"
                    $PubCertAuthShouldWork = $False
                }
                if ($PrivateKeyIsLoadedInSSHAgent -and $PositionOfLoadedPrivateKey -lt 4) {
                    # Even if the Private Key is Loaded in the ssh-agent and it's low enough on the list,
                    # we need to make sure that the ssh-agent is aware of the Public Key Certificate specifically
                    #
                    # NOTE: In the below, we can use `$_.Contents -eq $(Get-Content $SSHPublicCertFilePath)`
                    # as opposed to `$(Compare-Object $_.Contents $(Get-Content $SSHPublicCertFilePath)) -eq $null` because
                    # each should be a single string (as opposed to an array of strings)
                    $PublicCertLoadedCheck = $SSHAgentKeyFingerPrintsInSSHAgent | Where-Object {
                        $_.FingerPrint -match [regex]::Escape($RelevantString) -and
                        $($($_.Contents -split " ")[0..1] -join " ") -ne $($($(Get-Content $SSHPublicKeyFilePath) -split " ")[0..1] -join " ")
                    }
                    
                    if ($PublicCertLoadedCheck) {
                        $PubCertAuthShouldWork = $True
                    }
                    else {
                        $SSHClientProblemDescription = "The Private Key is loaded in the ssh-agent and it is low enough " +
                        "on the list of keys to present to the Remote Host, HOWEVER, the ssh-agent does not appear to be " +
                        "aware of the Public Key Certificate (i.e. 'ssh-add -L' will not contain the output of " +
                        "'Get-Content '$SSHPublicCertFilePath''. To remedy, remove the key from the ssh-agent via " +
                        "'ssh-add -d', ensure the Public Key Certificate is in the same directory as the Private Key, " +
                        "ensure the Public Key Certificate file has the same file name as the Private Key just appended " +
                        "with '-cert.pub', and add the Private Key to the ssh-agent via 'ssh-add <PathToPrivateKeyFile>' "
                        $PubCertAuthShouldWork = $False
                    }
                }
            }
            if ($RelatedKeyFileInfoObjects.Count -ge 2 -and $RelatedKeyFileInfoObjects.FileType -contains "RSAPrivateKey") {
                if (!$PrivateKeyIsLoadedInSSHAgent) {
                    # If the Private Key is not loaded in the ssh-agent, we need both the Private Key and the 
                    # Public Key Certificate on the filesystem. At this point we know we have the Private Key
                    # File, so now we have to check to see if we have the Public Key Certificate File
                    if ($RelatedKeyFileInfoObjects.FileType -notcontains "RSAPublicKeyCertificate") {
                        $SSHClientProblemDescription = "We are unable to find the RSA Public Key Certificate either on the filesystem (i.e. under $KeyFileParentDirectory), or loaded in the ssh-agent!"
                        $PubCertAuthShouldWork = $False
                    }
                    if ($RelatedKeyFileInfoObjects.FileType -contains "RSAPublicKeyCertificate") {
                        $PubCertAuthShouldWork = $True
                        
                        if ($SSHAgentKeyFingerPrintsInSSHAgent.Count -gt 4) { 
                            $null = $NeededAdditionalSSHExeOptions.Add("IdentitiesOnly")
                        }
                        $null = $NeededAdditionalSSHExeOptions.Add("iPathToPrivateKey")
                        $FinalPathToPrivateKey = $($RelatedKeyFileInfoObjects | Where-Object {$_.FileType -eq "RSAPrivateKey"}).File
                        $null = $NeededAdditionalSSHExeOptions.Add("iPathToPublicCert")
                        $FinalPathToPublicCert = $($RelatedKeyFileInfoObjects | Where-Object {$_.FileType -eq "RSAPublicKeyCertificate"}).File
                    }
                }
                if ($PositionOfLoadedPrivateKey -ge 4) {
                    # We need to determine if the output of `ssh-add -L` references the Public Key Certificate
                    # or just the Public Key. If it just references the Public Key, we're out of luck.
                    $PublicCertLoadedCheck = $SSHAgentKeyFingerPrintsInSSHAgent | Where-Object {
                        $_.FingerPrint -match [regex]::Escape($RelevantString) -and
                        $($($_.Contents -split " ")[0..1] -join " ") -ne $($($(Get-Content $SSHPublicKeyFilePath) -split " ")[0..1] -join " ")
                    }

                    if ($PublicCertLoadedCheck) {
                        # Even though the Private Key corresponding to a Public Key Certificate is loaded in the ssh-agent
                        # it's position is too high in the list. But what we can do is write the string to a file in 
                        # $KeyFileParentDirectory and use `-i` options
                        $PublicKeyCertificateString = $PublicCertLoadedCheck.Contents
                        Set-Content -Value $PublicKeyCertificateString -Path $($SSHPublicKeyFilePath -replace "\.pub","-cert.pub")

                        $null = $NeededAdditionalSSHExeOptions.Add("IdentitiesOnly")
                        $null = $NeededAdditionalSSHExeOptions.Add("iPathToPrivateKey")
                        $FinalPathToPrivateKey = $($RelatedKeyFileInfoObjects | Where-Object {$_.FileType -eq "RSAPrivateKey"}).File
                        $null = $NeededAdditionalSSHExeOptions.Add("iPathToPublicCert")
                        $FinalPathToPublicCert = $($SSHPublicKeyFilePath -replace "\.pub","-cert.pub")
                    }
                    if (!$PublicCertLoadedCheck) {
                        $SSHClientProblemDescription = "The corresponding Private Key is on the filesystem (i.e. under " +
                        "$KeyFileParentDirectory), and that private key is loaded in the ssh-agent, however, the ssh-agent " +
                        "does not appear to be aware of a Public Key Certificate (i.e. 'ssh-add -L' should NOT contain the " +
                        "same output as 'Get-Content $SSHPublicKeyFilePath'). To remedy, remove the key from the ssh-agent via " +
                        "'ssh-add -d', ensure the Public Key Certificate is in the same directory as the Private Key, " +
                        "ensure the Public Key Certificate file has the same file name as the Private Key just appended " +
                        "with '-cert.pub', and add the Private Key to the ssh-agent via 'ssh-add <PathToPrivateKeyFile>'"
                        $PubCertAuthShouldWork = $False
                    }
                }
                if ($PrivateKeyIsLoadedInSSHAgent -and $PositionOfLoadedPrivateKey -lt 4) {
                    # Even if the Private Key is Loaded in the ssh-agent and it's low enough on the list,
                    # we need to make sure that the ssh-agent is aware of the Public Key Certificate specifically
                    #
                    # NOTE: In the below, we can use `$_.Contents -eq $(Get-Content $SSHPublicCertFilePath)`
                    # as opposed to `$(Compare-Object $_.Contents $(Get-Content $SSHPublicCertFilePath)) -eq $null` because
                    # each should be a single string (as opposed to an array of strings)
                    $PublicCertLoadedCheck = $SSHAgentKeyFingerPrintsInSSHAgent | Where-Object {
                        $_.FingerPrint -match [regex]::Escape($RelevantString) -and
                        $($($_.Contents -split " ")[0..1] -join " ") -ne $($($(Get-Content $SSHPublicKeyFilePath) -split " ")[0..1] -join " ")
                    }
                    
                    if ($PublicCertLoadedCheck) {
                        $PubCertAuthShouldWork = $True
                    }
                    else {
                        $SSHClientProblemDescription = "The Private Key is loaded in the ssh-agent and it is low enough " +
                        "on the list of keys to present to the Remote Host, HOWEVER, the ssh-agent does not appear to be " +
                        "aware of a Public Key Certificate (i.e. 'ssh-add -L' contains the output of " +
                        "'Get-Content '$SSHPublicKeyFilePath'' instead of the Public Key Certificate string. " +
                        "To remedy, remove the key from the ssh-agent via 'ssh-add -d', ensure the Public Key Certificate " +
                        "is in the same directory as the Private Key, ensure the Public Key Certificate file has the same " +
                        "file name as the Private Key just appended with '-cert.pub', and add the Private Key to the " +
                        "ssh-agent via 'ssh-add <PathToPrivateKeyFile>'"
                        $PubCertAuthShouldWork = $False
                    }
                }
            }
        }
        if ($SSHPrivateKeyFilePath) {
            if ($RelatedKeyFileInfoObjects.Count -eq 1) {
                if (!$PrivateKeyIsLoadedInSSHAgent) {
                    $PubCertAuthShouldWork = $False
                    $SSHClientProblemDescription = "Unable to find Public Key Certificate either under $KeyFileParentDirectory or loaded in the ssh-agent!"
                }
                if ($PositionOfLoadedPrivateKey -ge 4) {
                    # We need to determine if the output of `ssh-add -L` references the Public Key Certificate
                    # or just the Public Key. If it just references the Public Key, we're out of luck.
                    $PubKeyContent = ssh-keygen -y -f "$SSHPrivateKeyFilePath"
                    $PublicCertLoadedCheck = $SSHAgentKeyFingerPrintsInSSHAgent | Where-Object {
                        $_.FingerPrint -match [regex]::Escape($RelevantString) -and
                        $($($_.Contents -split " ")[0..1] -join " ") -ne $($($PubKeyContent -split " ")[0..1] -join " ")
                    }

                    if ($PublicCertLoadedCheck) {
                        # Even though the Private Key corresponding to a Public Key Certificate is loaded in the ssh-agent
                        # it's position is too high in the list. But what we can do is write the string to a file in 
                        # $KeyFileParentDirectory and use `-i` options
                        $PublicKeyCertificateString = $PublicCertLoadedCheck.Contents
                        Set-Content -Value $PublicKeyCertificateString -Path "$SSHPrivateKeyFilePath-cert.pub"

                        $null = $NeededAdditionalSSHExeOptions.Add("IdentitiesOnly")
                        $null = $NeededAdditionalSSHExeOptions.Add("iPathToPrivateKey")
                        $FinalPathToPrivateKey = $($RelatedKeyFileInfoObjects | Where-Object {$_.FileType -eq "RSAPrivateKey"}).File
                        $null = $NeededAdditionalSSHExeOptions.Add("iPathToPublicCert")
                        $FinalPathToPublicCert = "$SSHPrivateKeyFilePath-cert.pub"
                    }
                    if (!$PublicCertLoadedCheck) {
                        $SSHClientProblemDescription = "The corresponding Private Key is on the filesystem (i.e. under " +
                        "$KeyFileParentDirectory), and that private key is loaded in the ssh-agent, however, the ssh-agent " +
                        "does not appear to be aware of a Public Key Certificate (i.e. 'ssh-add -L' should NOT contain the " +
                        "same output as 'ssh-keygen -y -f '$SSHPrivateKeyFilePath''). To remedy, remove the key from the ssh-agent via " +
                        "'ssh-add -d', ensure the Public Key Certificate is in the same directory as the Private Key, " +
                        "ensure the Public Key Certificate file has the same file name as the Private Key just appended " +
                        "with '-cert.pub', and add the Private Key to the ssh-agent via 'ssh-add <PathToPrivateKeyFile>'"
                        $PubCertAuthShouldWork = $False
                    }
                }
                if ($PrivateKeyIsLoadedInSSHAgent -and $PositionOfLoadedPrivateKey -lt 4) {
                    # Even if the Private Key is Loaded in the ssh-agent and it's low enough on the list,
                    # we need to make sure that the ssh-agent is aware of the Public Key Certificate specifically
                    #
                    # NOTE: In the below, we can use `$_.Contents -eq $(Get-Content $SSHPublicCertFilePath)`
                    # as opposed to `$(Compare-Object $_.Contents $(Get-Content $SSHPublicCertFilePath)) -eq $null` because
                    # each should be a single string (as opposed to an array of strings)
                    $PubKeyContent = ssh-keygen -y -f "$SSHPrivateKeyFilePath"
                    $PublicCertLoadedCheck = $SSHAgentKeyFingerPrintsInSSHAgent | Where-Object {
                        $_.FingerPrint -match [regex]::Escape($RelevantString) -and
                        $($_.Contents -split " ")[0..1] -ne $($PubKeyContent -split " ")[0..1]
                        $($($_.Contents -split " ")[0..1] -join " ") -ne $($($PubKeyContent -split " ")[0..1] -join " ")
                    }
                    
                    if ($PublicCertLoadedCheck) {
                        $PubCertAuthShouldWork = $True
                    }
                    else {
                        $SSHClientProblemDescription = "The Private Key is loaded in the ssh-agent and it is low enough " +
                        "on the list of keys to present to the Remote Host, HOWEVER, the ssh-agent does not appear to be " +
                        "aware of a Public Key Certificate (i.e. 'ssh-add -L' will not contain the output of " +
                        "'ssh-keygen -y -f '$SSHPrivateKeyFilePath''). To remedy, remove the key from the ssh-agent via " +
                        "'ssh-add -d', ensure the Public Key Certificate is in the same directory as the Private Key, " +
                        "ensure the Public Key Certificate file has the same file name as the Private Key just appended " +
                        "with '-cert.pub', and add the Private Key to the ssh-agent via 'ssh-add <PathToPrivateKeyFile>' "
                        $PubCertAuthShouldWork = $False
                    }
                }
            }
            if ($RelatedKeyFileInfoObjects.Count -ge 2) {
                if (!$PrivateKeyIsLoadedInSSHAgent) {
                    # If the Private Key is not loaded in the ssh-agent, we need both the Private Key and the 
                    # Public Key Certificate on the filesystem. At this point we know we have the Private Key
                    # File, so now we have to check to see if we have the Public Key Certificate File
                    if ($RelatedKeyFileInfoObjects.FileType -notcontains "RSAPublicKeyCertificate") {
                        $SSHClientProblemDescription = "We are unable to find the RSA Public Key Certificate either on the filesystem (i.e. under $KeyFileParentDirectory), or loaded in the ssh-agent!"
                        $PubCertAuthShouldWork = $False
                    }
                    if ($RelatedKeyFileInfoObjects.FileType -contains "RSAPublicKeyCertificate") {
                        $PubCertAuthShouldWork = $True
                        
                        if ($SSHAgentKeyFingerPrintsInSSHAgent.Count -gt 4) { 
                            $null = $NeededAdditionalSSHExeOptions.Add("IdentitiesOnly")
                        }
                        $null = $NeededAdditionalSSHExeOptions.Add("iPathToPrivateKey")
                        $FinalPathToPrivateKey = $($RelatedKeyFileInfoObjects | Where-Object {$_.FileType -eq "RSAPrivateKey"}).File
                        $null = $NeededAdditionalSSHExeOptions.Add("iPathToPublicCert")
                        $FinalPathToPublicCert = $($RelatedKeyFileInfoObjects | Where-Object {$_.FileType -eq "RSAPublicKeyCertificate"}).File
                    }
                }
                if ($PositionOfLoadedPrivateKey -ge 4) {
                    # We need to determine if the output of `ssh-add -L` references the Public Key Certificate
                    # or just the Public Key. If it just references the Public Key, we're out of luck.
                    $PubKeyContent = ssh-keygen -y -f "$SSHPrivateKeyFilePath"
                    $PublicCertLoadedCheck = $SSHAgentKeyFingerPrintsInSSHAgent | Where-Object {
                        $_.FingerPrint -match [regex]::Escape($RelevantString) -and
                        $($($_.Contents -split " ")[0..1] -join " ") -ne $($($PubKeyContent -split " ")[0..1] -join " ")
                    }

                    if ($PublicCertLoadedCheck) {
                        # Even though the Private Key corresponding to a Public Key Certificate is loaded in the ssh-agent
                        # it's position is too high in the list. But what we can do is write the string to a file in 
                        # $KeyFileParentDirectory and use `-i` options
                        $PublicKeyCertificateString = $PublicCertLoadedCheck.Contents
                        Set-Content -Value $PublicKeyCertificateString -Path "$SSHPrivateKeyFilePath-cert.pub"

                        $null = $NeededAdditionalSSHExeOptions.Add("IdentitiesOnly")
                        $null = $NeededAdditionalSSHExeOptions.Add("iPathToPrivateKey")
                        $FinalPathToPrivateKey = $($RelatedKeyFileInfoObjects | Where-Object {$_.FileType -eq "RSAPrivateKey"}).File
                        $null = $NeededAdditionalSSHExeOptions.Add("iPathToPublicCert")
                        $FinalPathToPublicCert = "$SSHPrivateKeyFilePath-cert.pub"
                    }
                    if (!$PublicCertLoadedCheck) {
                        $SSHClientProblemDescription = "The corresponding Private Key is on the filesystem (i.e. under " +
                        "$KeyFileParentDirectory), and that private key is loaded in the ssh-agent, however, the ssh-agent " +
                        "does not appear to be aware of a Public Key Certificate (i.e. 'ssh-add -L' should NOT contain the " +
                        "same output as 'ssh-keygen -y -f '$SSHPrivateKeyFilePath''). To remedy, remove the key from the ssh-agent via " +
                        "'ssh-add -d', ensure the Public Key Certificate is in the same directory as the Private Key, " +
                        "ensure the Public Key Certificate file has the same file name as the Private Key just appended " +
                        "with '-cert.pub', and add the Private Key to the ssh-agent via 'ssh-add <PathToPrivateKeyFile>'"
                        $PubCertAuthShouldWork = $False
                    }
                }
                if ($PrivateKeyIsLoadedInSSHAgent -and $PositionOfLoadedPrivateKey -lt 4) {
                    # Even if the Private Key is Loaded in the ssh-agent and it's low enough on the list,
                    # we need to make sure that the ssh-agent is aware of the Public Key Certificate specifically
                    #
                    # NOTE: In the below, we can use `$_.Contents -eq $(Get-Content $SSHPublicCertFilePath)`
                    # as opposed to `$(Compare-Object $_.Contents $(Get-Content $SSHPublicCertFilePath)) -eq $null` because
                    # each should be a single string (as opposed to an array of strings)
                    $PubKeyContent = ssh-keygen -y -f "$SSHPrivateKeyFilePath"
                    $PublicCertLoadedCheck = $SSHAgentKeyFingerPrintsInSSHAgent | Where-Object {
                        $_.FingerPrint -match [regex]::Escape($RelevantString) -and
                        $($_.Contents -split " ")[0..1] -ne $($PubKeyContent -split " ")[0..1]
                        $($($_.Contents -split " ")[0..1] -join " ") -ne $($($PubKeyContent -split " ")[0..1] -join " ")
                    }
                    
                    if ($PublicCertLoadedCheck) {
                        $PubCertAuthShouldWork = $True
                    }
                    else {
                        $SSHClientProblemDescription = "The Private Key is loaded in the ssh-agent and it is low enough " +
                        "on the list of keys to present to the Remote Host, HOWEVER, the ssh-agent does not appear to be " +
                        "aware of a Public Key Certificate (i.e. 'ssh-add -L' will not contain the output of " +
                        "'ssh-keygen -y -f '$SSHPrivateKeyFilePath''). To remedy, remove the key from the ssh-agent via " +
                        "'ssh-add -d', ensure the Public Key Certificate is in the same directory as the Private Key, " +
                        "ensure the Public Key Certificate file has the same file name as the Private Key just appended " +
                        "with '-cert.pub', and add the Private Key to the ssh-agent via 'ssh-add <PathToPrivateKeyFile>' "
                        $PubCertAuthShouldWork = $False
                    }
                }
            }
        }
    }

    if ($AuthMethod -eq "PublicKeyCertificate") {
        if ($PubCertAuthShouldWork) {
            $PublicCertificateFileInfo = $RelatedKeyFileInfoObjects | Where-Object {$_.FileType -eq "RSAPublicKeyCertificate"}
            # Finally, if we're checking Public Key Certificate Authentication, we need to figure out if we need to specify a
            # User Account other that the Currently Logged in user, so we need to look at the 'Principals' on the Public Key Certificate
            $IndexOfPrincipals = $PublicCertificateFileInfo.Info.IndexOf($($PublicCertificateFileInfo.Info -match "Principals:"))
            $IndexOfCriticalOptions = $PublicCertificateFileInfo.Info.IndexOf($($PublicCertificateFileInfo.Info -match "Critical Options:"))
            [array]$UserPrincipalsOnCert = $PublicCertificateFileInfo.Info[$($IndexOfPrincipals+1)..$($IndexOfCriticalOptions-1)] | foreach {$_.Trim()}
            $WhoAmIReformatted = $($(whoami) -split "\\")[1] + "@" + $($(whoami) -split "\\")[0]
            if ($UserPrincipalsOnCert -contains $WhoAmIReformatted) {
                $DomainAccount = $True
            }
        }
    }

    # Create Output PSObject
    $Output = [ordered]@{}
    if ($AuthMethod -eq "PublicKey") {
        $PubKeyAuthTestResult = if ($PubKeyAuthShouldWork) {$True} else {$False}
        $Output.Add("PublicKeyAuthShouldWork",$PubKeyAuthTestResult)
    }
    if ($AuthMethod -eq "PublicKeyCertificate") {
        $PubKeyCertAuthTestResult = if ($PubCertAuthShouldWork) {$True} else {$False}
        $Output.Add("PublicKeyCertificateAuthShouldWork",$PubKeyCertAuthTestResult)
    }
    if ($SSHClientProblemDescription) {
        $Output.Add("SSHClientProblemDescription",$SSHClientProblemDescription)
    }
    if ($NeededAdditionalSSHExeOptions) {
        [System.Collections.ArrayList]$AdditionalArguments = @()
        if ($NeededAdditionalSSHExeOptions -contains "IdentitiesOnly") {
            $null = $AdditionalArguments.Add('-o "IdentitiesOnly=true"')
        }
        if ($NeededAdditionalSSHExeOptions -contains "iPathToPrivateKey") {
            #$PrivateKeyFileInfoObject = $RelatedKeyFileInfoObjects | Where-Object {$_.FileType -eq "RSAPrivateKey"}
            $null = $AdditionalArguments.Add("-i `"$FinalPathToPrivateKey`"")
        }
        if ($NeededAdditionalSSHExeOptions -contains "iPathToPublicCert") {
            $null = $AdditionalArguments.Add("-i `"$FinalPathToPublicCert`"") 
        }
    }

    if ($AuthMethod -eq "PublicKeyCertificate") {
        [System.Collections.ArrayList]$PossibleUserAtRemoteHostFormats = @()
        foreach ($UserAcct in [array]$UserPrincipalsOnCert) {
            if ($DomainAccount) {
                if ($($UserAcct -split "@")[-1] -ne $($(whoami) -split "\\")[0]) {
                    $null = $PossibleUserAtRemoteHostFormats.Add("$($($UserAcct -split "@")[0])@<RemoteHost>")
                }
                else {
                    $null = $PossibleUserAtRemoteHostFormats.Add("$UserAcct@<RemoteHost>")
                }
            }
            else {
                $null = $PossibleUserAtRemoteHostFormats.Add("$UserAcct@<RemoteHost>")
            }
        }
        
        $UserAtRemoteHost = $PossibleUserAtRemoteHostFormats -join " OR "
    }
    else {
        $UserAtRemoteHost = "<user>@<RemoteHost>"
    }

    if ($AdditionalArguments.Count -gt 0) {
        $SSHExeCommand = "ssh $($AdditionalArguments -join " ") $UserAtRemoteHost"
    }
    else {
        $SSHExeCommand = "ssh $UserAtRemoteHost"
    }

    if ($SSHExeCommand) {
        $Output.Add("FinalSSHExeCommand",$SSHExeCommand)
    }

    #$Output.Add("RelatedKeyFileInfo",$RelatedKeyFileInfoObjects)

    [pscustomobject]$Output

}


<#
    .SYNOPSIS
        This function gets information about the specified SSH Key/Certificate file.

        Output is a PSCustomObject with the following properties...

            File                = $PathToKeyFile
            FileType            = $FileType
            Contents            = $Contents
            Info                = $Info
            FingerPrint         = $FingerPrint
            PasswordProtected   = $PasswordProtected

        ...where...
        
            - $PathToKeyFile is the path to the Key file specified by the -PathToKeyFile parameter,
            - $FileType is either "RSAPublicKey", "RSAPrivateKey", or "RSAPublicKeyCertificate"
            - $Contents is the result of: Get-Content $PathToKeyFile
            - $Info is the result of: ssh-keygen -l -f "$PathToKeyFile"
            - $FingerPrint is the fingerprint of the $PathToKeyFile
            - $PasswordProtected is a Boolean that indicates whether or not the file is password protected.

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER PathToKeyFile
        This parameter is MANDATORY.

        This parameter takes a string that represents the full path to the SSH Key/Cert File you would
        like to inspect.

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Get-SSHFileInfo -PathToKeyFile "$HOME\.ssh\id_rsa"
        
#>
function Get-SSHFileInfo {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$PathToKeyFile
    )

    # Make sure we have access to ssh binaries
    if (![bool]$(Get-Command ssh-keygen -ErrorAction SilentlyContinue)) {
        Write-Error "Unable to find 'ssh-keygen'! Halting!"
        $global:FunctionResult = "1"
        return
    }

    # Make sure the path exists
    if (!$(Test-Path $PathToKeyFile)) {
        Write-Error "Unable to find the path '$PathToKeyFile'! Halting!"
        $global:FunctionResult = "1"
        return
    }

    # This function can't validate .ppk files from putty, so just assume they're valid
    if ($(Get-Item $PathToKeyFile).Extension -eq ".ppk") {
        [pscustomobject]@{
            File                = $PathToKeyFile
            FileType            = "PuttyCombinedPublicPrivateKey"
            Contents            = $(Get-Content $PathToKeyFile)
            Info                = $(Get-Content $PathToKeyFile)
            FingerPrint         = $null
            PasswordProtected   = $null
        }
        
        return
    }

    #$SSHKeyGenParentDir = $(Get-Command ssh-keygen).Source | Split-Path -Parent
    $SSHKeyGenArguments = "-l -f `"$PathToKeyFile`""

    $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
    #$ProcessInfo.WorkingDirectory = $SSHKeyGenParentDir
    $ProcessInfo.FileName = $(Get-Command ssh-keygen).Source
    $ProcessInfo.RedirectStandardError = $true
    $ProcessInfo.RedirectStandardOutput = $true
    #$ProcessInfo.StandardOutputEncoding = [System.Text.Encoding]::Unicode
    #$ProcessInfo.StandardErrorEncoding = [System.Text.Encoding]::Unicode
    $ProcessInfo.UseShellExecute = $false
    $ProcessInfo.Arguments = $SSHKeyGenArguments
    $Process = New-Object System.Diagnostics.Process
    $Process.StartInfo = $ProcessInfo
    $Process.Start() | Out-Null
    # Below $FinishedInAlottedTime returns boolean true/false
    $FinishedInAlottedTime = $Process.WaitForExit(5000)
    if (!$FinishedInAlottedTime) {
        $Process.Kill()
        $ProcessKilled = $True
    }
    $stdout = $Process.StandardOutput.ReadToEnd()
    $stderr = $Process.StandardError.ReadToEnd()
    $SSHKeyGenOutput = $stdout + $stderr

    $KeyFileContent = Get-Content $PathToKeyFile
    if ($SSHKeyGenOutput -match "(RSA-CERT)") {
        $PublicKeyCertInfo = [scriptblock]::Create("ssh-keygen -L -f `"$PathToKeyFile`"").InvokeReturnAsIs()
        $PublicKeyCertContent = $KeyFileContent
        $FingerPrint = [scriptblock]::Create("ssh-keygen -l -f `"$PathToKeyFile`"").InvokeReturnAsIs()
        $IsPublicKeyCert = $True
    }
    elseif ($SSHKeyGenOutput -match "(RSA)") {
        # It could be either a Public Key or Private Key
        $PrivateKeyAttempt = Validate-SSHPrivateKey -PathToPrivateKeyFile $PathToKeyFile
        if (!$PrivateKeyAttempt.ValidSSHPrivateKeyFormat) {
            $IsPublicKey = $True
            $PublicKeyContent = $KeyFileContent
            $PublicKeyInfo = $FingerPrint = [scriptblock]::Create("ssh-keygen -l -f `"$PathToKeyFile`"").InvokeReturnAsIs()
        }
        else {
            $IsPrivateKey = $True
            $PrivateKeyContent = $PrivateKeyInfo = $KeyFileContent
            $FingerPrint = [scriptblock]::Create("ssh-keygen -l -f `"$PathToKeyFile`"").InvokeReturnAsIs()
            $PasswordProtected = $PrivateKeyAttempt.PasswordProtected
        }
    }
    elseif ($SSHKeyGenOutput -match "passphrase|pass phrase" -or $($SSHKeyGenOutput -eq $null -and $ProcessKilled)) {
        $IsPrivateKey = $True
        $PrivateKeyContent = $PrivateKeyInfo = $KeyFileContent
        $PasswordProtected = $True
    }
    elseif ($KeyFileContent.Count -gt 0) {
        if ($(Get-Content $PathToKeyFile)[0] -match "SSH2") {
            [pscustomobject]@{
                File                = $PathToKeyFile
                FileType            = "SSH2_RFC4716"
                Contents            = $(Get-Content $PathToKeyFile)
                Info                = $(Get-Content $PathToKeyFile)
                FingerPrint         = $null
                PasswordProtected   = $null
            }
        }

        return
    }
    else {
        $NotPubKeyPrivKeyOrPubCert = $True
    }

    if ($NotPubKeyPrivKeyOrPubCert) {
        Write-Warning "'$PathToKeyFile' is NOT a Public Key, Public Key Certificate, or Private Key"
    }
    else {
        if ($IsPublicKeyCert) {
            $FileType           = "RSAPublicKeyCertificate"
            $Contents           = $PublicKeyCertContent
            $Info               = $PublicKeyCertInfo
            $PasswordProtected  = $False
        }
        if ($IsPublicKey) {
            $FileType           = "RSAPublicKey"
            $Contents           = $PublicKeyContent
            $Info               = $PublicKeyInfo
            $PasswordProtected  = $False
        }
        if ($IsPrivateKey) {
            $FileType           = "RSAPrivateKey"
            $Contents           = $PrivateKeyContent
            $Info               = $PrivateKeyInfo
            $PasswordProtected  = $PrivateKeyAttempt.PasswordProtected
        }

        [pscustomobject]@{
            File                = $PathToKeyFile
            FileType            = $FileType
            Contents            = $Contents
            Info                = $Info
            FingerPrint         = $FingerPrint
            PasswordProtected   = $PasswordProtected
        }
    }
}


<#
    .SYNOPSIS
        This function uses the Vault Server REST API to return a list of Vault Token Accessors and associated
        information. (This function differes from the Get-VaultTokenAccessors function in that it provides
        additional information besides a simple list of Accessors).

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER VaultServerBaseUri
        This parameter is MANDATORY.

        This parameter takes a string that represents a Uri referencing the location of the Vault Server
        on your network. Example: "https://vaultserver.zero.lab:8200/v1"

    .PARAMETER VaultAuthToken
        This parameter is MANDATORY.

        This parameter takes a string that represents a Token for a Vault User that has permission to
        lookup Token Accessors using the Vault Server REST API.

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Get-VaultAccessorLookup -VaultServerBaseUri "https://vaultserver.zero.lab:8200/v1" -VaultAuthToken '434f37ca-89ae-9073-8783-087c268fd46f'
        
#>
function Get-VaultAccessorLookup {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$VaultServerBaseUri, # Should be something like "http://192.168.2.12:8200/v1"

        [Parameter(Mandatory=$True)]
        [string]$VaultAuthToken # Should be something like 'myroot' or '434f37ca-89ae-9073-8783-087c268fd46f'
    )

    if ($PSVersionTable.Platform -eq "Unix" -or $PSVersionTable.OS -match "Darwin" -and $env:SudoPwdPrompt) {
        if (GetElevation) {
            Write-Error "You should not be running the VaultServer Module as root! Halting!"
            $global:FunctionResult = "1"
            return
        }
        RemoveMySudoPwd
        NewCronToAddSudoPwd
        $env:SudoPwdPrompt = $False
    }

    # Make sure $VaultServerBaseUri is a valid Url
    try {
        $UriObject = [uri]$VaultServerBaseUri
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }
    if (![bool]$($UriObject.Scheme -match "http")) {
        Write-Error "'$VaultServerBaseUri' does not appear to be a URL! Halting!"
        $global:FunctionResult = "1"
        return
    }

    try {
        $VaultAuthTokenAccessors = Get-VaultTokenAccessors -VaultServerBaseUri $VaultServerBaseUri -VaultAuthToken $VaultAuthToken -ErrorAction Stop
        if (!$VaultAuthTokenAccessors) {throw "The Get-VaultTokenAccessors function failed! Halting!"}
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }
    
    foreach ($accessor in $VaultAuthTokenAccessors) {

        $jsonRequest = @"
{
    "accessor": "$accessor"
}
"@
        try {
            # Validate JSON
            $JsonRequestAsSingleLineString = $jsonRequest | ConvertFrom-Json -EA Stop | ConvertTo-Json -Compress -EA Stop
        }
        catch {
            Write-Error "There was a problem with the JSON! Halting!"
        }
        $IWRSplatParams = @{
            Uri         = "$VaultServerBaseUri/auth/token/lookup-accessor"
            Headers     = @{"X-Vault-Token" = "$VaultAuthToken"}
            Body        = $JsonRequestAsSingleLineString
            Method      = "Post"
        }
        
        $(Invoke-RestMethod @IWRSplatParams).data

    }
}


<#
    .SYNOPSIS
        This function outputs a Vault Authentication Token granted to the Domain User specified
        in the -DomainCredentialsWithAdminAccessToVault parameter.

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER VaultServerBaseUri
        This parameter is MANDATORY.

        This parameter takes a string that represents a Uri referencing the location of the Vault Server
        on your network. Example: "https://vaultserver.zero.lab:8200/v1"

    .PARAMETER DomainCredentialsWithAccessToVault
        This parameter is MANDATORY.

        This parameter takes a PSCredential. Example:
        $Creds = [pscredential]::new("zero\zeroadmin",$(Read-Host "Please enter the password for 'zero\zeroadmin'" -AsSecureString))

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Get-VaultLogin -VaultServerBaseUri "https://vaultserver.zero.lab:8200/v1" -DomainCredentialsWithAccessToVault $Creds
        
#>
function Get-VaultLogin {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True)]
        [ValidatePattern("\/v1$")]
        [string]$VaultServerBaseUri,

        [Parameter(Mandatory=$True)]
        [pscredential]$DomainCredentialsWithAccessToVault
    )

    [Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"

    # Make sure we can reach the Vault Server and that is in a state where we can actually use it.
    try {
        $VaultServerUpAndUnsealedCheck = Invoke-RestMethod "$VaultServerBaseUri/sys/health"
        if (!$VaultServerUpAndUnsealedCheck -or $VaultServerUpAndUnsealedCheck.initialized -ne $True -or
        $VaultServerUpAndUnsealedCheck.sealed -ne $False -or $VaultServerUpAndUnsealedCheck.standby -ne $False) {
            throw "The Vault Server is either not reachable or in a state where it cannot be used! Halting!"
        }
    }
    catch {
        Write-Error $_
        Write-Host "Use 'Invoke-RestMethod '$VaultServerBaseUri/sys/health' to investigate" -ForegroundColor Yellow
        $global:FunctionResult = "1"
        return
    }

    # Get the Domain User's Vault Token so that we can interact with Vault
    $UserName = $($DomainCredentialsWithAccessToVault.UserName -split "\\")[1]
    $PlainTextPwd = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($DomainCredentialsWithAccessToVault.Password))

    $jsonRequest = @"
{
    "password": "$PlainTextPwd"
}
"@
    try {
        $JsonRequestAsSingleLineString = $jsonRequest | ConvertFrom-Json -EA Stop | ConvertTo-Json -Compress -EA Stop
    }
    catch {
        Write-Error "There was a problem with the JSON for Turning on the Audit Log! Halting!"
        $global:FunctionResult = "1"
        return
    }
    $IWRSplatParams = @{
        Uri         = "$VaultServerBaseUri/auth/ldap/login/$UserName "
        Body        = $JsonRequestAsSingleLineString
        Method      = "Post"
    }
    $LDAPLoginResult = Invoke-RestMethod @IWRSplatParams
    $VaultAuthToken = $LDAPLoginResult.auth.client_token

    # Get rid of PlainText Password from Memory as best we can (this really doesn't do enough...)
    # https://get-powershellblog.blogspot.com/2017/06/how-safe-are-your-strings.html
    $jsonRequest = $null
    $PlainTextPwd = $null

    if (!$VaultAuthToken) {
        Write-Error "There was a problem getting the Vault Token for Domain User $UserName! Halting!"
        $global:FunctionResult = "1"
        return
    }
    else {
        $VaultAuthToken
    }
}


<#
    .SYNOPSIS
        This function uses the Vault Server REST API to return a list of Vault Token Accessors.

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER VaultServerBaseUri
        This parameter is MANDATORY.

        This parameter takes a string that represents a Uri referencing the location of the Vault Server
        on your network. Example: "https://vaultserver.zero.lab:8200/v1"

    .PARAMETER VaultAuthToken
        This parameter is MANDATORY.

        This parameter takes a string that represents a Token for a Vault User that has permission to
        lookup Token Accessors using the Vault Server REST API.

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Get-VaultTokenAccessors -VaultServerBaseUri "https://vaultserver.zero.lab:8200/v1" -VaultAuthToken '434f37ca-89ae-9073-8783-087c268fd46f'
        
#>
function Get-VaultTokenAccessors {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$VaultServerBaseUri, # Should be something like "http://192.168.2.12:8200/v1"

        [Parameter(Mandatory=$True)]
        [string]$VaultAuthToken # Should be something like 'myroot' or '434f37ca-89ae-9073-8783-087c268fd46f'
    )

    if ($PSVersionTable.Platform -eq "Unix" -or $PSVersionTable.OS -match "Darwin" -and $env:SudoPwdPrompt) {
        if (GetElevation) {
            Write-Error "You should not be running the VaultServer Module as root! Halting!"
            $global:FunctionResult = "1"
            return
        }
        RemoveMySudoPwd
        NewCronToAddSudoPwd
        $env:SudoPwdPrompt = $False
    }

    # Make sure $VaultServerBaseUri is a valid Url
    try {
        $UriObject = [uri]$VaultServerBaseUri
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }
    if (![bool]$($UriObject.Scheme -match "http")) {
        Write-Error "'$VaultServerBaseUri' does not appear to be a URL! Halting!"
        $global:FunctionResult = "1"
        return
    }

    $IWRSplatParams = @{
        Uri         = "$VaultServerBaseUri/auth/token/accessors"
        Headers     = @{"X-Vault-Token" = "$VaultAuthToken"}
        Body        = @{"list" = "true"}
        Method      = "Get"
    }
    
    $(Invoke-RestMethod @IWRSplatParams).data.keys
}


<#
    .SYNOPSIS
        This function uses the Vault Server REST API to return a list of Vault Tokens and associated information.

        IMPORTANT NOTE: This function will NOT work unless your Vault Server was created with a vault.hcl
        configuration that included:
            raw_storage_endpoint = true

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER VaultServerBaseUri
        This parameter is MANDATORY.

        This parameter takes a string that represents a Uri referencing the location of the Vault Server
        on your network. Example: "https://vaultserver.zero.lab:8200/v1"

    .PARAMETER VaultAuthToken
        This parameter is MANDATORY.

        This parameter takes a string that represents a Token for a Vault User that has (root) permission to
        lookup Tokens using the Vault Server REST API.

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Get-VaultTokens -VaultServerBaseUri "https://vaultserver.zero.lab:8200/v1" -VaultAuthToken '434f37ca-89ae-9073-8783-087c268fd46f'
        
#>
function Get-VaultTokens {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$VaultServerBaseUri, # Should be something like "http://192.168.2.12:8200/v1"

        [Parameter(Mandatory=$True)]
        [string]$VaultAuthToken # Should be something like 'myroot' or '434f37ca-89ae-9073-8783-087c268fd46f'
    )

    # Make sure $VaultServerBaseUri is a valid Url
    try {
        $UriObject = [uri]$VaultServerBaseUri
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }
    if (![bool]$($UriObject.Scheme -match "http")) {
        Write-Error "'$VaultServerBaseUri' does not appear to be a URL! Halting!"
        $global:FunctionResult = "1"
        return
    }

    # If $VaultServerBaseUri ends in '/', remove it
    if ($VaultServerBaseUri[-1] -eq "/") {
        $VaultServerBaseUri = $VaultServerBaseUri.Substring(0,$VaultServerBaseUri.Length-1)
    }

    $QueryParameters = @{
        list = "true"
    }
    $HeadersParameters = @{
        "X-Vault-Token" = $VaultAuthToken
    }
    $IWRSplatParamsForSaltedTokenIds = @{
        Uri         = "$VaultServerBaseUri/sys/raw/sys/token/id"
        Headers     = $HeadersParameters
        Body        = $QueryParameters
        Method      = "Get"
    }
    $SaltedTokenIds = $($(Invoke-WebRequest @IWRSplatParamsForSaltedTokenIds).Content | ConvertFrom-Json).data.keys
    if (!$SaltedTokenIds) {
        Write-Error "There was a problem accesing the endpoint '$VaultServerBaseUri/sys/raw/sys/token/id'. Was 'raw_storage_endpoint = true' set in your Vault Server 'vault.hcl' configuration? Halting!"
        $global:FunctionResult = "1"
        return
    }

    [System.Collections.ArrayList]$AvailableTokensPSObjects = @()
    foreach ($SaltedId in $SaltedTokenIds) {
        $IWRSplatParamsForTokenObjects = @{
            Uri         = "$VaultServerBaseUri/sys/raw/sys/token/id/$SaltedId"
            Headers     = $HeadersParameters
            Method      = "Get"
        }

        $PSObject = $($(Invoke-WebRequest @IWRSplatParamsForTokenObjects).Content | ConvertFrom-Json).data.value | ConvertFrom-Json
        
        $null = $AvailableTokensPSObjects.Add($PSObject)
    }

    $AvailableTokensPSObjects
}


<#
    .Synopsis
        Provides access to Windows Credential Manager basic functionality for client scripts. Allows the user
        to add, delete, and show credentials within the Windows Credential Manager.

        Refactored From: https://gallery.technet.microsoft.com/scriptcenter/PowerShell-Credentials-d44c3cde

        ****************** IMPORTANT ******************
        *
        * If you use this script from the PS console, you 
        * should ALWAYS pass the Target, User and Password
        * parameters using single quotes:
        * 
        *  .\CredMan.ps1 -AddCred -Target 'http://server' -User 'JoeSchmuckatelli' -Pass 'P@55w0rd!'
        * 
        * to prevent PS misinterpreting special characters 
        * you might use as PS reserved characters
        * 
        ****************** IMPORTANT ******************

    .Description
        See .SYNOPSIS

    .NOTES
        Original Author: Jim Harrison (jim@isatools.org)
        Date  : 2012/05/20
        Vers  : 1.5

    .PARAMETER AddCred
        This parameter is OPTIONAL.

        This parameter is a switch. Use it in conjunction with -Target, -User, and -Pass
        parameters to add a new credential or update existing credentials.

    .PARAMETER Comment
        This parameter is OPTIONAL.

        This parameter takes a string that represents additional information that you wish
        to place in the credentials comment field. Use with the -AddCred switch.

    .PARAMETER CredPersist
        This parameter is OPTIONAL, however, it has a default value of "ENTERPRISE".

        This parameter takes a string. Valid values are:
        "SESSION", "LOCAL_MACHINE", "ENTERPRISE"
        
        ENTERPRISE persistance means that the credentials will survive logoff and reboot.
        
    .PARAMETER CredType
        This parameter is OPTIONAL, however, it has a default value of "GENERIC".

        This parameter takes a string. Valid values are:
        "GENERIC", "DOMAIN_PASSWORD", "DOMAIN_CERTIFICATE",
        "DOMAIN_VISIBLE_PASSWORD", "GENERIC_CERTIFICATE", "DOMAIN_EXTENDED",
        "MAXIMUM", "MAXIMUM_EX"
        
        ****************** IMPORTANT ******************
        *
        * I STRONGLY recommend that you become familiar 
        * with http://msdn.microsoft.com/en-us/library/windows/desktop/aa374788(v=vs.85).aspx
        * before you create new credentials with -CredType other than "GENERIC"
        * 
        ****************** IMPORTANT ******************

    .PARAMETER DelCred
        This parameter is OPTIONAL.

        This parameter is a switch. Use it to remove existing credentials. If more than one
        credential sets have the same -Target, you must use this switch in conjunction with the
        -CredType parameter.

    .PARAMETER GetCred
        This parameter is OPTIONAL.

        This parameter is a switch. Use it to retrieve an existing credential. The
        -CredType parameter may be required to access the correct credential if more set
        of credentials have the same -Target.

    .PARAMETER Pass
        This parameter is OPTIONAL, however, it is MANDATORY if the -AddCred switch is used.

        This parameter takes a string that represents tha secret/password that you would like to store.

    .PARAMETER RunTests
        This parameter is OPTIONAL.

        This parameter is a switch. If used, the function will run built-in Win32 CredMan
        functionality tests.

    .PARAMETER ShoCred
        This parameter is OPTIONAL.

        This parameter is a switch. If used, the function will retrieve all credentials stored for
        the interactive user.

    .PARAMETER Target
        This parameter is OPTIONAL, however, it is MANDATORY unless the -ShoCred switch is used.

        This parameter takes a string that specifies the authentication target for the specified credentials
        If not specified, the value provided to the -User parameter is used.

    .PARAMETER User
        This parameter is OPTIONAL.

        This parameter takes a string that represents the credential's UserName.
        

    .LINK
        http://msdn.microsoft.com/en-us/library/windows/desktop/aa374788(v=vs.85).aspx
        http://stackoverflow.com/questions/7162604/get-cached-credentials-in-powershell-from-windows-7-credential-manager
        http://msdn.microsoft.com/en-us/library/windows/desktop/aa374788(v=vs.85).aspx
        http://blogs.msdn.com/b/peerchan/archive/2005/11/01/487834.aspx

    .EXAMPLE
        # Stores the credential for 'UserName' with a password of 'P@55w0rd!' for authentication against 'http://aserver' and adds a comment of 'cuziwanna'
        Manage-StoredCredentials -AddCred -Target 'http://aserver' -User 'UserName' -Password 'P@55w0rd!' -Comment 'cuziwanna'

    .EXAMPLE
        # Removes the credential used for the target 'http://aserver' as credentials type 'DOMAIN_PASSWORD'
        Manage-StoredCredentials -DelCred -Target 'http://aserver' -CredType 'DOMAIN_PASSWORD'

    .EXAMPLE
        # Retreives the credential used for the target 'http://aserver'
        Manage-StoredCredentials -GetCred -Target 'http://aserver'

    .EXAMPLE
        # Retrieves a summary list of all credentials stored for the interactive user
        Manage-StoredCredentials -ShoCred

    .EXAMPLE
        # Retrieves a detailed list of all credentials stored for the interactive user
        Manage-StoredCredentials -ShoCred -All

#>
function Manage-StoredCredentials {
    [CmdletBinding()]
    Param (
     [Parameter(Mandatory=$false)]
        [Switch] $AddCred,

     [Parameter(Mandatory=$false)]
        [Switch]$DelCred,
     
        [Parameter(Mandatory=$false)]
        [Switch]$GetCred,
     
        [Parameter(Mandatory=$false)]
        [Switch]$ShoCred,

     [Parameter(Mandatory=$false)]
        [Switch]$RunTests,
     
        [Parameter(Mandatory=$false)]
        [ValidateLength(1,32767) <# CRED_MAX_GENERIC_TARGET_NAME_LENGTH #>]
        [String]$Target,

     [Parameter(Mandatory=$false)]
        [ValidateLength(1,512) <# CRED_MAX_USERNAME_LENGTH #>]
        [String]$User,

     [Parameter(Mandatory=$false)]
        [ValidateLength(1,512) <# CRED_MAX_CREDENTIAL_BLOB_SIZE #>]
        [String]$Pass,

     [Parameter(Mandatory=$false)]
        [ValidateLength(1,256) <# CRED_MAX_STRING_LENGTH #>]
        [String]$Comment,

     [Parameter(Mandatory=$false)]
        [ValidateSet("GENERIC","DOMAIN_PASSWORD","DOMAIN_CERTIFICATE","DOMAIN_VISIBLE_PASSWORD",
        "GENERIC_CERTIFICATE","DOMAIN_EXTENDED","MAXIMUM","MAXIMUM_EX")]
        [String]$CredType = "GENERIC",

     [Parameter(Mandatory=$false)]
        [ValidateSet("SESSION","LOCAL_MACHINE","ENTERPRISE")]
        [String]$CredPersist = "ENTERPRISE"
    )

    #region Pinvoke
    #region Inline C#
    [String] $PsCredmanUtils = @"
    using System;
    using System.Runtime.InteropServices;

    namespace PsUtils
    {
        public class CredMan
        {
            #region Imports
            // DllImport derives from System.Runtime.InteropServices
            [DllImport("Advapi32.dll", SetLastError = true, EntryPoint = "CredDeleteW", CharSet = CharSet.Unicode)]
            private static extern bool CredDeleteW([In] string target, [In] CRED_TYPE type, [In] int reservedFlag);

            [DllImport("Advapi32.dll", SetLastError = true, EntryPoint = "CredEnumerateW", CharSet = CharSet.Unicode)]
            private static extern bool CredEnumerateW([In] string Filter, [In] int Flags, out int Count, out IntPtr CredentialPtr);

            [DllImport("Advapi32.dll", SetLastError = true, EntryPoint = "CredFree")]
            private static extern void CredFree([In] IntPtr cred);

            [DllImport("Advapi32.dll", SetLastError = true, EntryPoint = "CredReadW", CharSet = CharSet.Unicode)]
            private static extern bool CredReadW([In] string target, [In] CRED_TYPE type, [In] int reservedFlag, out IntPtr CredentialPtr);

            [DllImport("Advapi32.dll", SetLastError = true, EntryPoint = "CredWriteW", CharSet = CharSet.Unicode)]
            private static extern bool CredWriteW([In] ref Credential userCredential, [In] UInt32 flags);
            #endregion

            #region Fields
            public enum CRED_FLAGS : uint
            {
                NONE = 0x0,
                PROMPT_NOW = 0x2,
                USERNAME_TARGET = 0x4
            }

            public enum CRED_ERRORS : uint
            {
                ERROR_SUCCESS = 0x0,
                ERROR_INVALID_PARAMETER = 0x80070057,
                ERROR_INVALID_FLAGS = 0x800703EC,
                ERROR_NOT_FOUND = 0x80070490,
                ERROR_NO_SUCH_LOGON_SESSION = 0x80070520,
                ERROR_BAD_USERNAME = 0x8007089A
            }

            public enum CRED_PERSIST : uint
            {
                SESSION = 1,
                LOCAL_MACHINE = 2,
                ENTERPRISE = 3
            }

            public enum CRED_TYPE : uint
            {
                GENERIC = 1,
                DOMAIN_PASSWORD = 2,
                DOMAIN_CERTIFICATE = 3,
                DOMAIN_VISIBLE_PASSWORD = 4,
                GENERIC_CERTIFICATE = 5,
                DOMAIN_EXTENDED = 6,
                MAXIMUM = 7,      // Maximum supported cred type
                MAXIMUM_EX = (MAXIMUM + 1000),  // Allow new applications to run on old OSes
            }

            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            public struct Credential
            {
                public CRED_FLAGS Flags;
                public CRED_TYPE Type;
                public string TargetName;
                public string Comment;
                public DateTime LastWritten;
                public UInt32 CredentialBlobSize;
                public string CredentialBlob;
                public CRED_PERSIST Persist;
                public UInt32 AttributeCount;
                public IntPtr Attributes;
                public string TargetAlias;
                public string UserName;
            }

            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            private struct NativeCredential
            {
                public CRED_FLAGS Flags;
                public CRED_TYPE Type;
                public IntPtr TargetName;
                public IntPtr Comment;
                public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
                public UInt32 CredentialBlobSize;
                public IntPtr CredentialBlob;
                public UInt32 Persist;
                public UInt32 AttributeCount;
                public IntPtr Attributes;
                public IntPtr TargetAlias;
                public IntPtr UserName;
            }
            #endregion

            #region Child Class
            private class CriticalCredentialHandle : Microsoft.Win32.SafeHandles.CriticalHandleZeroOrMinusOneIsInvalid
            {
                public CriticalCredentialHandle(IntPtr preexistingHandle)
                {
                    SetHandle(preexistingHandle);
                }

                private Credential XlateNativeCred(IntPtr pCred)
                {
                    NativeCredential ncred = (NativeCredential)Marshal.PtrToStructure(pCred, typeof(NativeCredential));
                    Credential cred = new Credential();
                    cred.Type = ncred.Type;
                    cred.Flags = ncred.Flags;
                    cred.Persist = (CRED_PERSIST)ncred.Persist;

                    long LastWritten = ncred.LastWritten.dwHighDateTime;
                    LastWritten = (LastWritten << 32) + ncred.LastWritten.dwLowDateTime;
                    cred.LastWritten = DateTime.FromFileTime(LastWritten);

                    cred.UserName = Marshal.PtrToStringUni(ncred.UserName);
                    cred.TargetName = Marshal.PtrToStringUni(ncred.TargetName);
                    cred.TargetAlias = Marshal.PtrToStringUni(ncred.TargetAlias);
                    cred.Comment = Marshal.PtrToStringUni(ncred.Comment);
                    cred.CredentialBlobSize = ncred.CredentialBlobSize;
                    if (0 < ncred.CredentialBlobSize)
                    {
                        cred.CredentialBlob = Marshal.PtrToStringUni(ncred.CredentialBlob, (int)ncred.CredentialBlobSize / 2);
                    }
                    return cred;
                }

                public Credential GetCredential()
                {
                    if (IsInvalid)
                    {
                        throw new InvalidOperationException("Invalid CriticalHandle!");
                    }
                    Credential cred = XlateNativeCred(handle);
                    return cred;
                }

                public Credential[] GetCredentials(int count)
                {
                    if (IsInvalid)
                    {
                        throw new InvalidOperationException("Invalid CriticalHandle!");
                    }
                    Credential[] Credentials = new Credential[count];
                    IntPtr pTemp = IntPtr.Zero;
                    for (int inx = 0; inx < count; inx++)
                    {
                        pTemp = Marshal.ReadIntPtr(handle, inx * IntPtr.Size);
                        Credential cred = XlateNativeCred(pTemp);
                        Credentials[inx] = cred;
                    }
                    return Credentials;
                }

                override protected bool ReleaseHandle()
                {
                    if (IsInvalid)
                    {
                        return false;
                    }
                    CredFree(handle);
                    SetHandleAsInvalid();
                    return true;
                }
            }
            #endregion

            #region Custom API
            public static int CredDelete(string target, CRED_TYPE type)
            {
                if (!CredDeleteW(target, type, 0))
                {
                    return Marshal.GetHRForLastWin32Error();
                }
                return 0;
            }

            public static int CredEnum(string Filter, out Credential[] Credentials)
            {
                int count = 0;
                int Flags = 0x0;
                if (string.IsNullOrEmpty(Filter) ||
                    "*" == Filter)
                {
                    Filter = null;
                    if (6 <= Environment.OSVersion.Version.Major)
                    {
                        Flags = 0x1; //CRED_ENUMERATE_ALL_CREDENTIALS; only valid is OS >= Vista
                    }
                }
                IntPtr pCredentials = IntPtr.Zero;
                if (!CredEnumerateW(Filter, Flags, out count, out pCredentials))
                {
                    Credentials = null;
                    return Marshal.GetHRForLastWin32Error(); 
                }
                CriticalCredentialHandle CredHandle = new CriticalCredentialHandle(pCredentials);
                Credentials = CredHandle.GetCredentials(count);
                return 0;
            }

            public static int CredRead(string target, CRED_TYPE type, out Credential Credential)
            {
                IntPtr pCredential = IntPtr.Zero;
                Credential = new Credential();
                if (!CredReadW(target, type, 0, out pCredential))
                {
                    return Marshal.GetHRForLastWin32Error();
                }
                CriticalCredentialHandle CredHandle = new CriticalCredentialHandle(pCredential);
                Credential = CredHandle.GetCredential();
                return 0;
            }

            public static int CredWrite(Credential userCredential)
            {
                if (!CredWriteW(ref userCredential, 0))
                {
                    return Marshal.GetHRForLastWin32Error();
                }
                return 0;
            }

            #endregion

            private static int AddCred()
            {
                Credential Cred = new Credential();
                string Password = "Password";
                Cred.Flags = 0;
                Cred.Type = CRED_TYPE.GENERIC;
                Cred.TargetName = "Target";
                Cred.UserName = "UserName";
                Cred.AttributeCount = 0;
                Cred.Persist = CRED_PERSIST.ENTERPRISE;
                Cred.CredentialBlobSize = (uint)Password.Length;
                Cred.CredentialBlob = Password;
                Cred.Comment = "Comment";
                return CredWrite(Cred);
            }

            private static bool CheckError(string TestName, CRED_ERRORS Rtn)
            {
                switch(Rtn)
                {
                    case CRED_ERRORS.ERROR_SUCCESS:
                        Console.WriteLine(string.Format("'{0}' worked", TestName));
                        return true;
                    case CRED_ERRORS.ERROR_INVALID_FLAGS:
                    case CRED_ERRORS.ERROR_INVALID_PARAMETER:
                    case CRED_ERRORS.ERROR_NO_SUCH_LOGON_SESSION:
                    case CRED_ERRORS.ERROR_NOT_FOUND:
                    case CRED_ERRORS.ERROR_BAD_USERNAME:
                        Console.WriteLine(string.Format("'{0}' failed; {1}.", TestName, Rtn));
                        break;
                    default:
                        Console.WriteLine(string.Format("'{0}' failed; 0x{1}.", TestName, Rtn.ToString("X")));
                        break;
                }
                return false;
            }

            /*
             * Note: the Main() function is primarily for debugging and testing in a Visual 
             * Studio session.  Although it will work from PowerShell, it's not very useful.
             */
            public static void Main()
            {
                Credential[] Creds = null;
                Credential Cred = new Credential();
                int Rtn = 0;

                Console.WriteLine("Testing CredWrite()");
                Rtn = AddCred();
                if (!CheckError("CredWrite", (CRED_ERRORS)Rtn))
                {
                    return;
                }
                Console.WriteLine("Testing CredEnum()");
                Rtn = CredEnum(null, out Creds);
                if (!CheckError("CredEnum", (CRED_ERRORS)Rtn))
                {
                    return;
                }
                Console.WriteLine("Testing CredRead()");
                Rtn = CredRead("Target", CRED_TYPE.GENERIC, out Cred);
                if (!CheckError("CredRead", (CRED_ERRORS)Rtn))
                {
                    return;
                }
                Console.WriteLine("Testing CredDelete()");
                Rtn = CredDelete("Target", CRED_TYPE.GENERIC);
                if (!CheckError("CredDelete", (CRED_ERRORS)Rtn))
                {
                    return;
                }
                Console.WriteLine("Testing CredRead() again");
                Rtn = CredRead("Target", CRED_TYPE.GENERIC, out Cred);
                if (!CheckError("CredRead", (CRED_ERRORS)Rtn))
                {
                    Console.WriteLine("if the error is 'ERROR_NOT_FOUND', this result is OK.");
                }
            }
        }
    }
"@
    #endregion

    $PsCredMan = $null
    try
    {
     $PsCredMan = [PsUtils.CredMan]
    }
    catch
    {
     #only remove the error we generate
     try {$Error.RemoveAt($Error.Count-1)} catch {Write-Verbose "No past errors yet..."}
    
    }
    if($null -eq $PsCredMan)
    {
     Add-Type $PsCredmanUtils
    }
    #endregion

    #region Internal Tools
    [HashTable] $ErrorCategory = @{0x80070057 = "InvalidArgument";
                                   0x800703EC = "InvalidData";
                                   0x80070490 = "ObjectNotFound";
                                   0x80070520 = "SecurityError";
                                   0x8007089A = "SecurityError"}

    function Get-CredType {
     Param (
      [Parameter(Mandatory=$true)]
            [ValidateSet("GENERIC","DOMAIN_PASSWORD","DOMAIN_CERTIFICATE","DOMAIN_VISIBLE_PASSWORD",
      "GENERIC_CERTIFICATE","DOMAIN_EXTENDED","MAXIMUM","MAXIMUM_EX")]
            [String]$CredType
     )
     
     switch($CredType) {
      "GENERIC" {return [PsUtils.CredMan+CRED_TYPE]::GENERIC}
      "DOMAIN_PASSWORD" {return [PsUtils.CredMan+CRED_TYPE]::DOMAIN_PASSWORD}
      "DOMAIN_CERTIFICATE" {return [PsUtils.CredMan+CRED_TYPE]::DOMAIN_CERTIFICATE}
      "DOMAIN_VISIBLE_PASSWORD" {return [PsUtils.CredMan+CRED_TYPE]::DOMAIN_VISIBLE_PASSWORD}
      "GENERIC_CERTIFICATE" {return [PsUtils.CredMan+CRED_TYPE]::GENERIC_CERTIFICATE}
      "DOMAIN_EXTENDED" {return [PsUtils.CredMan+CRED_TYPE]::DOMAIN_EXTENDED}
      "MAXIMUM" {return [PsUtils.CredMan+CRED_TYPE]::MAXIMUM}
      "MAXIMUM_EX" {return [PsUtils.CredMan+CRED_TYPE]::MAXIMUM_EX}
     }
    }

    function Get-CredPersist {
     Param (
      [Parameter(Mandatory=$true)]
            [ValidateSet("SESSION","LOCAL_MACHINE","ENTERPRISE")]
            [String] $CredPersist
     )
     
     switch($CredPersist) {
      "SESSION" {return [PsUtils.CredMan+CRED_PERSIST]::SESSION}
      "LOCAL_MACHINE" {return [PsUtils.CredMan+CRED_PERSIST]::LOCAL_MACHINE}
      "ENTERPRISE" {return [PsUtils.CredMan+CRED_PERSIST]::ENTERPRISE}
     }
    }
    #endregion

    #region Dot-Sourced API
    function Del-Creds {
        <#
        .Synopsis
            Deletes the specified credentials

        .Description
            Calls Win32 CredDeleteW via [PsUtils.CredMan]::CredDelete

        .INPUTS
            See function-level notes

        .OUTPUTS
            0 or non-0 according to action success
            [Management.Automation.ErrorRecord] if error encountered

        .PARAMETER Target
            Specifies the URI for which the credentials are associated
          
        .PARAMETER CredType
            Specifies the desired credentials type; defaults to 
            "CRED_TYPE_GENERIC"
        #>

     Param (
      [Parameter(Mandatory=$true)]
            [ValidateLength(1,32767)]
            [String] $Target,

      [Parameter(Mandatory=$false)]
            [ValidateSet("GENERIC","DOMAIN_PASSWORD","DOMAIN_CERTIFICATE","DOMAIN_VISIBLE_PASSWORD",
      "GENERIC_CERTIFICATE","DOMAIN_EXTENDED","MAXIMUM","MAXIMUM_EX")]
            [String] $CredType = "GENERIC"
     )
     
     [Int]$Results = 0
     try {
      $Results = [PsUtils.CredMan]::CredDelete($Target, $(Get-CredType $CredType))
     }
     catch {
      return $_
     }
     if(0 -ne $Results) {
      [String]$Msg = "Failed to delete credentials store for target '$Target'"
      [Management.ManagementException] $MgmtException = New-Object Management.ManagementException($Msg)
      [Management.Automation.ErrorRecord] $ErrRcd = New-Object Management.Automation.ErrorRecord($MgmtException, $Results.ToString("X"), $ErrorCategory[$Results], $null)
      return $ErrRcd
     }
     return $Results
    }

    function Enum-Creds {
        <#
        .Synopsis
          Enumerates stored credentials for operating user

        .Description
          Calls Win32 CredEnumerateW via [PsUtils.CredMan]::CredEnum

        .INPUTS
          
        .OUTPUTS
          [PsUtils.CredMan+Credential[]] if successful
          [Management.Automation.ErrorRecord] if unsuccessful or error encountered

        .PARAMETER Filter
          Specifies the filter to be applied to the query
          Defaults to [String]::Empty
          
        #>

     Param (
      [Parameter(Mandatory=$false)]
            [AllowEmptyString()]
            [String]$Filter = [String]::Empty
     )
     
     [PsUtils.CredMan+Credential[]]$Creds = [Array]::CreateInstance([PsUtils.CredMan+Credential], 0)
     [Int]$Results = 0
     try {
      $Results = [PsUtils.CredMan]::CredEnum($Filter, [Ref]$Creds)
     }
     catch {
      return $_
     }
     switch($Results) {
            0 {break}
            0x80070490 {break} #ERROR_NOT_FOUND
            default {
          [String]$Msg = "Failed to enumerate credentials store for user '$Env:UserName'"
          [Management.ManagementException] $MgmtException = New-Object Management.ManagementException($Msg)
          [Management.Automation.ErrorRecord] $ErrRcd = New-Object Management.Automation.ErrorRecord($MgmtException, $Results.ToString("X"), $ErrorCategory[$Results], $null)
          return $ErrRcd
            }
     }
     return $Creds
    }

    function Read-Creds {
        <#
        .Synopsis
            Reads specified credentials for operating user

        .Description
            Calls Win32 CredReadW via [PsUtils.CredMan]::CredRead

        .INPUTS

        .OUTPUTS
            [PsUtils.CredMan+Credential] if successful
            [Management.Automation.ErrorRecord] if unsuccessful or error encountered

        .PARAMETER Target
            Specifies the URI for which the credentials are associated
            If not provided, the username is used as the target
          
        .PARAMETER CredType
            Specifies the desired credentials type; defaults to 
            "CRED_TYPE_GENERIC"
        #>

     Param (
      [Parameter(Mandatory=$true)]
            [ValidateLength(1,32767)]
            [String]$Target,

      [Parameter(Mandatory=$false)]
            [ValidateSet("GENERIC","DOMAIN_PASSWORD","DOMAIN_CERTIFICATE","DOMAIN_VISIBLE_PASSWORD",
      "GENERIC_CERTIFICATE","DOMAIN_EXTENDED","MAXIMUM","MAXIMUM_EX")]
            [String]$CredType = "GENERIC"
     )
     
        #CRED_MAX_DOMAIN_TARGET_NAME_LENGTH
     if ("GENERIC" -ne $CredType -and 337 -lt $Target.Length) { 
      [String]$Msg = "Target field is longer ($($Target.Length)) than allowed (max 337 characters)"
      [Management.ManagementException]$MgmtException = New-Object Management.ManagementException($Msg)
      [Management.Automation.ErrorRecord]$ErrRcd = New-Object Management.Automation.ErrorRecord($MgmtException, 666, 'LimitsExceeded', $null)
      return $ErrRcd
     }
     [PsUtils.CredMan+Credential]$Cred = New-Object PsUtils.CredMan+Credential
        [Int]$Results = 0
     try {
      $Results = [PsUtils.CredMan]::CredRead($Target, $(Get-CredType $CredType), [Ref]$Cred)
     }
     catch {
      return $_
     }
     
     switch($Results) {
            0 {break}
            0x80070490 {return $null} #ERROR_NOT_FOUND
            default {
          [String] $Msg = "Error reading credentials for target '$Target' from '$Env:UserName' credentials store"
          [Management.ManagementException]$MgmtException = New-Object Management.ManagementException($Msg)
          [Management.Automation.ErrorRecord]$ErrRcd = New-Object Management.Automation.ErrorRecord($MgmtException, $Results.ToString("X"), $ErrorCategory[$Results], $null)
          return $ErrRcd
            }
     }
     return $Cred
    }

    function Write-Creds {
        <#
        .Synopsis
          Saves or updates specified credentials for operating user

        .Description
          Calls Win32 CredWriteW via [PsUtils.CredMan]::CredWrite

        .INPUTS

        .OUTPUTS
          [Boolean] true if successful
          [Management.Automation.ErrorRecord] if unsuccessful or error encountered

        .PARAMETER Target
          Specifies the URI for which the credentials are associated
          If not provided, the username is used as the target
          
        .PARAMETER UserName
          Specifies the name of credential to be read
          
        .PARAMETER Password
          Specifies the password of credential to be read
          
        .PARAMETER Comment
          Allows the caller to specify the comment associated with 
          these credentials
          
        .PARAMETER CredType
          Specifies the desired credentials type; defaults to 
          "CRED_TYPE_GENERIC"

        .PARAMETER CredPersist
          Specifies the desired credentials storage type;
          defaults to "CRED_PERSIST_ENTERPRISE"
        #>

     Param (
      [Parameter(Mandatory=$false)]
            [ValidateLength(0,32676)]
            [String]$Target,

      [Parameter(Mandatory=$true)]
            [ValidateLength(1,512)]
            [String]$UserName,

      [Parameter(Mandatory=$true)]
            [ValidateLength(1,512)]
            [String]$Password,

      [Parameter(Mandatory=$false)]
            [ValidateLength(0,256)]
            [String]$Comment = [String]::Empty,

      [Parameter(Mandatory=$false)]
            [ValidateSet("GENERIC","DOMAIN_PASSWORD","DOMAIN_CERTIFICATE","DOMAIN_VISIBLE_PASSWORD",
      "GENERIC_CERTIFICATE","DOMAIN_EXTENDED","MAXIMUM","MAXIMUM_EX")]
            [String]$CredType = "GENERIC",

      [Parameter(Mandatory=$false)]
            [ValidateSet("SESSION","LOCAL_MACHINE","ENTERPRISE")]
            [String]$CredPersist = "ENTERPRISE"
     )

     if ([String]::IsNullOrEmpty($Target)) {
      $Target = $UserName
     }
        #CRED_MAX_DOMAIN_TARGET_NAME_LENGTH
     if ("GENERIC" -ne $CredType -and 337 -lt $Target.Length) {
      [String] $Msg = "Target field is longer ($($Target.Length)) than allowed (max 337 characters)"
      [Management.ManagementException] $MgmtException = New-Object Management.ManagementException($Msg)
      [Management.Automation.ErrorRecord] $ErrRcd = New-Object Management.Automation.ErrorRecord($MgmtException, 666, 'LimitsExceeded', $null)
      return $ErrRcd
     }
        if ([String]::IsNullOrEmpty($Comment)) {
            $Comment = [String]::Format("Last edited by {0}\{1} on {2}",$Env:UserDomain,$Env:UserName,$Env:ComputerName)
        }
     [String]$DomainName = [Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().DomainName
     [PsUtils.CredMan+Credential]$Cred = New-Object PsUtils.CredMan+Credential
     
        switch($Target -eq $UserName -and 
        $("CRED_TYPE_DOMAIN_PASSWORD" -eq $CredType -or "CRED_TYPE_DOMAIN_CERTIFICATE" -eq $CredType)) {
      $true  {$Cred.Flags = [PsUtils.CredMan+CRED_FLAGS]::USERNAME_TARGET}
      $false  {$Cred.Flags = [PsUtils.CredMan+CRED_FLAGS]::NONE}
     }
     $Cred.Type = Get-CredType $CredType
     $Cred.TargetName = $Target
     $Cred.UserName = $UserName
     $Cred.AttributeCount = 0
     $Cred.Persist = Get-CredPersist $CredPersist
     $Cred.CredentialBlobSize = [Text.Encoding]::Unicode.GetBytes($Password).Length
     $Cred.CredentialBlob = $Password
     $Cred.Comment = $Comment

     [Int] $Results = 0
     try {
      $Results = [PsUtils.CredMan]::CredWrite($Cred)
     }
     catch {
      return $_
     }

     if(0 -ne $Results) {
      [String] $Msg = "Failed to write to credentials store for target '$Target' using '$UserName', '$Password', '$Comment'"
      [Management.ManagementException] $MgmtException = New-Object Management.ManagementException($Msg)
      [Management.Automation.ErrorRecord] $ErrRcd = New-Object Management.Automation.ErrorRecord($MgmtException, $Results.ToString("X"), $ErrorCategory[$Results], $null)
      return $ErrRcd
     }
     return $Results
    }

    #endregion

    #region Cmd-Line functionality
    function CredManMain {
    #region Adding credentials
     if ($AddCred) {
      if([String]::IsNullOrEmpty($User) -or [String]::IsNullOrEmpty($Pass)) {
       Write-Host "You must supply a user name and password (target URI is optional)."
       return
      }
      # may be [Int32] or [Management.Automation.ErrorRecord]
      [Object]$Results = Write-Creds $Target $User $Pass $Comment $CredType $CredPersist
      if (0 -eq $Results) {
       [Object]$Cred = Read-Creds $Target $CredType
       if ($null -eq $Cred) {
        Write-Host "Credentials for '$Target', '$User' was not found."
        return
       }
       if ($Cred -is [Management.Automation.ErrorRecord]) {
        return $Cred
       }

                New-Variable -Name "AddedCredentialsObject" -Value $(
                    [pscustomobject][ordered]@{
                        UserName    = $($Cred.UserName)
                        Password    = $($Cred.CredentialBlob)
                        Target      = $($Cred.TargetName.Substring($Cred.TargetName.IndexOf("=")+1))
                        Updated     = "$([String]::Format('{0:yyyy-MM-dd HH:mm:ss}', $Cred.LastWritten.ToUniversalTime())) UTC"
                        Comment     = $($Cred.Comment)
                    }
                )

       return $AddedCredentialsObject
      }
      # will be a [Management.Automation.ErrorRecord]
      return $Results
     }
    #endregion 

    #region Removing credentials
     if ($DelCred) {
      if (-not $Target) {
       Write-Host "You must supply a target URI."
       return
      }
      # may be [Int32] or [Management.Automation.ErrorRecord]
      [Object]$Results = Del-Creds $Target $CredType 
      if (0 -eq $Results) {
       Write-Host "Successfully deleted credentials for '$Target'"
       return
      }
      # will be a [Management.Automation.ErrorRecord]
      return $Results
     }
    #endregion

    #region Reading selected credential
     if ($GetCred) {
      if(-not $Target) {
       Write-Host "You must supply a target URI."
       return
      }
      # may be [PsUtils.CredMan+Credential] or [Management.Automation.ErrorRecord]
      [Object]$Cred = Read-Creds $Target $CredType
      if ($null -eq $Cred) {
       Write-Host "Credential for '$Target' as '$CredType' type was not found."
       return
      }
      if ($Cred -is [Management.Automation.ErrorRecord]) {
       return $Cred
      }

            New-Variable -Name "AddedCredentialsObject" -Value $(
                [pscustomobject][ordered]@{
                    UserName    = $($Cred.UserName)
                    Password    = $($Cred.CredentialBlob)
                    Target      = $($Cred.TargetName.Substring($Cred.TargetName.IndexOf("=")+1))
                    Updated     = "$([String]::Format('{0:yyyy-MM-dd HH:mm:ss}', $Cred.LastWritten.ToUniversalTime())) UTC"
                    Comment     = $($Cred.Comment)
                }
            )

            return $AddedCredentialsObject
     }
    #endregion

    #region Reading all credentials
     if ($ShoCred) {
      # may be [PsUtils.CredMan+Credential[]] or [Management.Automation.ErrorRecord]
      [Object]$Creds = Enum-Creds
      if ($Creds -split [Array] -and 0 -eq $Creds.Length) {
       Write-Host "No Credentials found for $($Env:UserName)"
       return
      }
      if ($Creds -is [Management.Automation.ErrorRecord]) {
       return $Creds
      }

            $ArrayOfCredObjects = @()
      foreach($Cred in $Creds) {
                New-Variable -Name "AddedCredentialsObject" -Value $(
                    [pscustomobject][ordered]@{
                        UserName    = $($Cred.UserName)
                        Password    = $($Cred.CredentialBlob)
                        Target      = $($Cred.TargetName.Substring($Cred.TargetName.IndexOf("=")+1))
                        Updated     = "$([String]::Format('{0:yyyy-MM-dd HH:mm:ss}', $Cred.LastWritten.ToUniversalTime())) UTC"
                        Comment     = $($Cred.Comment)
                    }
                ) -Force

                $AddedCredentialsObject | Add-Member -MemberType NoteProperty -Name "Alias" -Value "$($Cred.TargetAlias)"
                $AddedCredentialsObject | Add-Member -MemberType NoteProperty -Name "AttribCnt" -Value "$($Cred.AttributeCount)"
                $AddedCredentialsObject | Add-Member -MemberType NoteProperty -Name "Attribs" -Value "$($Cred.Attributes)"
                $AddedCredentialsObject | Add-Member -MemberType NoteProperty -Name "Flags" -Value "$($Cred.Flags)"
                $AddedCredentialsObject | Add-Member -MemberType NoteProperty -Name "PwdSize" -Value "$($Cred.CredentialBlobSize)"
                $AddedCredentialsObject | Add-Member -MemberType NoteProperty -Name "Storage" -Value "$($Cred.Persist)"
                $AddedCredentialsObject | Add-Member -MemberType NoteProperty -Name "Type" -Value "$($Cred.Type)"

                $ArrayOfCredObjects +=, $AddedCredentialsObject
      }
      return $ArrayOfCredObjects
     }
    #endregion

    #region Run basic diagnostics
     if($RunTests) {
      [PsUtils.CredMan]::Main()
     }
    #endregion
    }
    #endregion

    CredManMain
}


<#
    .SYNOPSIS
        This function creates a new SSH User/Client key pair and has the Vault Server sign the Public Key,
        returning a '-cert.pub' file that can be used for Public Key Certificate SSH Authentication.

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER VaultServerBaseUri
        This parameter is MANDATORY.

        This parameter takes a string that represents a Uri referencing the location of the Vault Server
        on your network. Example: "https://vaultserver.zero.lab:8200/v1"

    .PARAMETER DomainCredentialsWithAccessToVault
        This parameter is OPTIONAL, however, either -DomainCredentialsWithAccessToVault or -VaultAuthToken are REQUIRED.

        This parameter takes a PSCredential. Example:
        $Creds = [pscredential]::new("zero\zeroadmin",$(Read-Host "Please enter the password for 'zero\zeroadmin'" -AsSecureString))

    .PARAMETER VaultAuthToken
        This parameter is OPTIONAL, however, either -DomainCredentialsWithAccessToVault or -VaultAuthToken are REQUIRED.

        This parameter takes a string that represents a Token for a Vault User that has (root) permission to
        lookup Tokens using the Vault Server REST API.

    .PARAMETER NewSSHKeyName
        This parameter is MANDATORY.

        This parameter takes a string that represents the file name that you would like to give to the new
        SSH User/Client Keys.

    .PARAMETER NewSSHKeyPurpose
        This parameter is OPTIONAL.

        This parameter takes a string that represents a very brief description of what the new SSH Keys
        will be used for. This description will be added to the Comment section when the new keys are
        created.

    .PARAMETER NewSSHKeyPwd
        This parameter is OPTIONAL.

        This parameter takes a SecureString that represents the password used to protect the new
        Private Key file that is created.

    .PARAMETER BlankSSHPrivateKeyPwd
        This parameter is OPTIONAL.

        This parameter is a switch. Use it to ensure that the newly created Private Key is NOT password
        protected.

    .PARAMETER AddToSSHAgent
        This parameter is OPTIONAL, but recommended.

        This parameter is a switch. If used, the new SSH Key Pair will be added to the ssh-agent service.

    .PARAMETER RemovePrivateKey
        This parameter is OPTIONAL. This parameter should only be used in conjunction with the
        -AddtoSSHAgent switch.

        This parameter is a switch. If used, the newly created Private Key will be added to the ssh-agent
        and deleted from the filesystem.

    .PARAMETER SSHAgentExpiry
        This parameter is OPTIONAL. This parameter should only be used in conjunction with the
        -AddtoSSHAgent switch.

        This parameter takes an integer that specifies the number of seconds that the ssh key identity will
        remain in the ssh-agent - at which point it will expire and be removed from the ssh-agent.

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> $NewSSHCredentialsSplatParams = @{
            VaultServerBaseUri      = $VaultServerBaseUri
            VaultAuthToken          = $VaultAuthToken
            NewSSHKeyName           = $NewSSHKeyName
            AddToSSHAgent           = $True
        }
        PS C:\Users\zeroadmin> $NewSSHCredsResult = New-SSHCredentials @NewSSHCredentialsSplatParams
        
#>
function New-SSHCredentials {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True)]
        [ValidatePattern("\/v1$")]
        [string]$VaultServerBaseUri,

        [Parameter(Mandatory=$False)]
        [pscredential]$DomainCredentialsWithAccessToVault,

        [Parameter(Mandatory=$False)]
        [string]$VaultAuthToken,

        [Parameter(Mandatory=$True)]
        [string]$NewSSHKeyName,

        [Parameter(Mandatory=$False)]
        [ValidatePattern("^\w*$")] # No spaces allowed
        [string]$NewSSHKeyPurpose,

        [Parameter(Mandatory=$False)]
        [System.Security.SecureString]$NewSSHKeyPwd,

        [Parameter(Mandatory=$False)]
        [switch]$BlankSSHPrivateKeyPwd,

        [Parameter(Mandatory=$False)]
        [switch]$AddToSSHAgent,

        [Parameter(Mandatory=$False)]
        [switch]$RemovePrivateKey,

        [Parameter(Mandatory=$False)]
        [int]$SSHAgentExpiry
    )

    if ($PSVersionTable.Platform -eq "Unix" -or $PSVersionTable.OS -match "Darwin" -and $env:SudoPwdPrompt) {
        if (GetElevation) {
            Write-Error "You should not be running the VaultServer Module as root! Halting!"
            $global:FunctionResult = "1"
            return
        }
        RemoveMySudoPwd
        NewCronToAddSudoPwd
        $env:SudoPwdPrompt = $False
    }

    if ($(!$VaultAuthToken -and !$DomainCredentialsWithAccessToVault) -or $($VaultAuthToken -and $DomainCredentialsWithAccessToVault)) {
        Write-Error "The $($MyInvocation.MyCommand.Name) function requires one (no more, no less) of the following parameters: [-DomainCredentialsWithAccessToVault, -VaultAuthToken] Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($DomainCredentialsWithAccessToVault) {
        $GetVaultLoginSplatParams = @{
            VaultServerBaseUri                     = $VaultServerBaseUri
            DomainCredentialsWithAccessToVault     = $DomainCredentialsWithAccessToVault
            ErrorAction                            = "Stop"
        }

        try {
            $VaultAuthToken = Get-VaultLogin @GetVaultLoginSplatParams
            if (!$VaultAuthToken) {throw "The Get-VaultLogin function failed! Halting!"}
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }
    }

    $HeadersParameters = @{
        "X-Vault-Token" = $VaultAuthToken
    }

    # Generate an SSH key pair for zeroadmin
    $UserSSHDir = Join-Path $HOME .ssh
    if (!$(Test-Path $UserSSHDir)) {
        New-Item -ItemType Directory -Path $UserSSHDir
    }

    Push-Location $UserSSHDir

    $NewSSHKeySplatParams = @{
        NewSSHKeyName       = $NewSSHKeyName
        ErrorAction         = "Stop"
    }
    if ($NewSSHKeyPurpose) {
        $NewSSHKeySplatParams.Add("NewSSHKeyPurpose",$NewSSHKeyPurpose)
    }
    
    if ($NewSSHKeyPwd) {
        $KeyPwd = $NewSSHKeyPwd
    }
    if (!$BlankSSHPrivateKeyPwd -and !$NewSSHKeyPwd) {
        #$KeyPwd = Read-Host -Prompt "Please enter a password to protect the new SSH Private Key $NewSSHKeyName" -AsSecureString
        $BlankSSHPrivateKeyPwd = $True
    }
    if ($KeyPwd) {
        $NewSSHKeySplatParams.Add("NewSSHKeyPwd",$KeyPwd)
    }
    
    try {
        $NewSSHKeyResult = New-SSHKey @NewSSHKeySplatParams
        if (!$NewSSHKeyResult) {throw "There was a problem with the New-SSHKey function! Halting!"}
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    # Have Vault sign the User's New public key
    if ($DomainCredentialsWithAccessToVault) {
        $AuthorizedPrincipalUserPrep = $DomainCredentialsWithAccessToVault.UserName -split "\\"
        $AuthorizedPrincipalString = $AuthorizedPrincipalUserPrep[-1] + "@" + $AuthorizedPrincipalUserPrep[0]
    }
    else {
        $AuthorizedPrincipalString = $($(whoami) -split "\\")[-1] + "@" + $($(whoami) -split "\\")[0]
    }

    $SignSSHUserPubKeySplatParams = @{
        VaultSSHClientSigningUrl        = "$VaultServerBaseUri/ssh-client-signer/sign/clientrole"
        VaultAuthToken                  = $VaultAuthToken
        AuthorizedUserPrincipals        = @($AuthorizedPrincipalString)
        PathToSSHUserPublicKeyFile      = $NewSSHKeyResult.PublicKeyFilePath
        PathToSSHUserPrivateKeyFile     = $NewSSHKeyResult.PrivateKeyFilePath
        ErrorAction                     = "Stop"
    }
    if ($AddToSSHAgent) {
        $SignSSHUserPubKeySplatParams.Add("AddToSSHAgent",$True)
    }
    if ($SSHAgentExpiry) {
        $SignSSHUserPubKeySplatParams.Add("SSHAgentExpiry",$SSHAgentExpiry)
    }

    try {
        $SignSSHUserPublicKeyResult = Sign-SSHUserPublicKey @SignSSHUserPubKeySplatParams
        if (!$SignSSHUserPublicKeyResult) {throw "There was a problem with the Sign-SSHUserPublicKey function! Halting!"}
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    if ($RemovePrivateKey -and $SignSSHUserPublicKeyResult.AddedToSSHAgent) {
        Remove-Item $NewSSHKeyResult.PrivateKeyFilePath -Force
    }

    # Next, pull the Vault Host Signing CA Public Key and Vault Client (User) Signing CA Public Key into the necessary config files
    # NOTE: The Add-CAPubKeyToSSHAndSSHDConfig function will NOT do anything if it doesn't need to
    $AddCAPubKeyToSSHAndSSHDConfigSplatParams = @{
        PublicKeyOfCAUsedToSignUserKeysVaultUrl     = "$VaultServerBaseUri/ssh-client-signer/public_key"
        PublicKeyOfCAUsedToSignHostKeysVaultUrl     = "$VaultServerBaseUri/ssh-host-signer/public_key"
        AuthorizedUserPrincipals                    = @($AuthorizedPrincipalString)
        ErrorAction                                 = "Stop"
    }

    try {
        $AddCAPubKeyResult = Add-CAPubKeyToSSHAndSSHDConfig @AddCAPubKeyToSSHAndSSHDConfigSplatParams
    }
    catch {
        Write-Warning "There was a problem with the Add-CAPubKeyToSSHAndSSHDConfig function! The problem is as follows:"
        Write-Warning "$($_ | Out-String)"
        Write-Warning "SSH Cert Authentication may still work..."
    }

    # Finally, figure out the most efficient ssh command to use to remote into the remote host.
    $Output = Get-SSHClientAuthSanity -SSHKeyFilePath $NewSSHKeyResult.PublicKeyFilePath -AuthMethod PublicKeyCertificate
    if (Test-Path $NewSSHKeyResult.PrivateKeyFilePath) {
        $Output | Add-Member -Type NoteProperty -Name PrivateKeyPath -Value $NewSSHKeyResult.PrivateKeyFilePath
    }
    if (Test-Path $NewSSHKeyResult.PublicKeyFilePath) {
        $Output | Add-Member -Type NoteProperty -Name PublicKeyPath -Value $NewSSHKeyResult.PublicKeyFilePath
    }
    if (Test-Path $SignSSHUserPublicKeyResult.SignedCertFile.FullName) {
        $Output | Add-Member -Type NoteProperty -Name PublicCertPath -Value $SignSSHUserPublicKeyResult.SignedCertFile.FullName
    }

    $Output

    Pop-Location

}


<#
    .SYNOPSIS
        This function creates a new SSH Public/Private Key Pair. Optionally, add it to the ssh-agent.
        Optionally add the public key to a Remote Host's ~/.ssh/authorized_keys file.

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER NewSSHKeyName
        This parameter is MANDATORY.

        This parameter takes a string that represents the file name that you would like to give to the new
        SSH User/Client Keys.

    .PARAMETER NewSSHKeyPurpose
        This parameter is OPTIONAL.

        This parameter takes a string that represents a very brief description of what the new SSH Keys
        will be used for. This description will be added to the Comment section when the new keys are
        created.

    .PARAMETER NewSSHKeyPwd
        This parameter is OPTIONAL.

        This parameter takes a SecureString that represents the password used to protect the new
        Private Key file that is created.

    .PARAMETER BlankSSHPrivateKeyPwd
        This parameter is OPTIONAL.

        This parameter is a switch. Use it to ensure that the newly created Private Key is NOT password
        protected.

    .PARAMETER AddToSSHAgent
        This parameter is OPTIONAL, but recommended.

        This parameter is a switch. If used, the new SSH Key Pair will be added to the ssh-agent service.

    .PARAMETER RemovePrivateKey
        This parameter is OPTIONAL. This parameter should only be used in conjunction with the
        -AddtoSSHAgent switch.

        This parameter is a switch. If used, the newly created Private Key will be added to the ssh-agent
        and deleted from the filesystem.

    .PARAMETER RemoteHost
        This parameter is OPTIONAL. This parameter should only be used in conjunction with the
        -AddToRemoteHostAuthKeys switch.

        This parameter takes a string that represents the IP Address of DNS-Resolvable name of a Remote Host.
        The newly created public key will be added to the Remote Host's ~/.ssh/authorized_keys file. The
        Remote Host can be either Windows or Linux (as long as you can ssh to it from the local host).

    .PARAMETER AddToRemoteHostAuthKeys
        This parameter is OPTIONAL.

        This parameter is a switch. If used, the newly created Public Key will be added to the Remote Host's
        ~/.ssh/authorized_keys file. (Specify the Remote Host using the -RemoteHost parameter)

    .PARAMETER RemoteHostUserName
        This parameter is OPTIONAL. This parameter should only be used in conjunction with the
        -AddToRemoteHostAuthKeys parameter.

        This parameter takes a string that represents the name of the user with ssh access to
        the Remote Host (specified by the -RemoteHost parameter).

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> $SplatParams = @{
            NewSSHKeyName           = "ToRHServ01"
            NewSSHKeyPurpose        = "ForSSHToRHServ01"
            AddToSSHAgent           = $True
        }
        PS C:\Users\zeroadmin> New-SSHKey @SplatParams
        
#>
function New-SSHKey {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$NewSSHKeyName,

        [Parameter(Mandatory=$False)]
        [securestring]$NewSSHKeyPwd,

        [Parameter(Mandatory=$False)]
        [ValidatePattern("^\w*$")] # No spaces allowed
        [string]$NewSSHKeyPurpose,

        [Parameter(Mandatory=$False)]
        [switch]$AddToSSHAgent,

        [Parameter(Mandatory=$False)]
        [switch]$RemovePrivateKey,

        #[Parameter(Mandatory=$False)]
        #[switch]$ShowNextSteps,

        [Parameter(Mandatory=$False)]
        [string]$RemoteHost,

        [Parameter(Mandatory=$False)]
        [switch]$AddToRemoteHostAuthKeys,

        [Parameter(Mandatory=$False)]
        [string]$RemoteHostUserName
    )

    #region >> Prep

    if ($PSVersionTable.Platform -eq "Unix" -or $PSVersionTable.OS -match "Darwin" -and $env:SudoPwdPrompt) {
        if (GetElevation) {
            Write-Error "You should not be running the VaultServer Module as root! Halting!"
            $global:FunctionResult = "1"
            return
        }
        RemoveMySudoPwd
        NewCronToAddSudoPwd
        $env:SudoPwdPrompt = $False
    }

    if (!$PSVersionTable.Platform -or $PSVersionTable.Platform -eq "Win32NT") {
        try {
            if ($(Get-Module -ListAvailable).Name -notcontains 'WinSSH') {$null = Install-Module WinSSH -ErrorAction Stop}
            if ($(Get-Module).Name -notcontains 'WinSSH') {$null = Import-Module WinSSH -ErrorAction Stop}
            Import-Module "$($(Get-Module WinSSH).ModuleBase)\Await\Await.psd1" -ErrorAction Stop
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }

        try {
            $null = Stop-AwaitSession
        }
        catch {
            Write-Verbose $_.Exception.Message
        }
    }

    if ($PSVersionTable.Platform -eq "Unix" -or $PSVersionTable.OS -match "Darwin") {
        # Determine if we have required Linux commands
        [System.Collections.ArrayList]$LinuxCommands = @(
            "echo"
            "expect"
        )
        [System.Collections.ArrayList]$CommandsNotPresent = @()
        foreach ($CommandName in $LinuxCommands) {
            $CommandCheckResult = command -v $CommandName
            if (!$CommandCheckResult) {
                $null = $CommandsNotPresent.Add($CommandName)
            }
        }

        if ($CommandsNotPresent.Count -gt 0) {
            [System.Collections.ArrayList]$FailedInstalls = @()
            if ($CommandsNotPresent -contains "echo") {
                try {
                    $null = InstallLinuxPackage -PossiblePackageNames "coreutils" -CommandName "echo"
                }
                catch {
                    $null = $FailedInstalls.Add("coreutils")
                }
            }
            if ($CommandsNotPresent -contains "expect") {
                try {
                    $null = InstallLinuxPackage -PossiblePackageNames "expect" -CommandName "expect"
                }
                catch {
                    $null = $FailedInstalls.Add("expect")
                }
            }
    
            if ($FailedInstalls.Count -gt 0) {
                Write-Error "The following Linux packages are required, but were not able to be installed:`n$($FailedInstalls -join "`n")`nHalting!"
                $global:FunctionResult = "1"
                return
            }
        }

        [System.Collections.ArrayList]$CommandsNotPresent = @()
        foreach ($CommandName in $LinuxCommands) {
            $CommandCheckResult = command -v $CommandName
            if (!$CommandCheckResult) {
                $null = $CommandsNotPresent.Add($CommandName)
            }
        }
    
        if ($CommandsNotPresent.Count -gt 0) {
            Write-Error "The following Linux commands are required, but not present on $env:ComputerName:`n$($CommandsNotPresent -join "`n")`nHalting!"
            $global:FunctionResult = "1"
            return
        }
    }

    if (!$(Get-Command ssh-keygen -ErrorAction SilentlyContinue)) {
        Write-Error "Unable to find ssh-keygen! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($AddToSSHAgent) {
        if (!$(Get-Command ssh-add -ErrorAction SilentlyContinue)) {
            Write-Error "Unable to find ssh-add! Halting!"
            $global:FunctionResult = "1"
            return
        }

        if (!$PSVersionTable.Platform -or $PSVersionTable.Platform -eq "Win32NT") {
            if ($(Get-Service ssh-agent).Status -ne "Running") {
                $SSHDErrMsg = "The ssh-agent service is NOT curently running! No ssh key pair has been created. Please ensure that the " +
                "ssh-agent and sshd services are running and try again. Halting!'"
                Write-Error $SSHDErrMsg
                $global:FunctionResult = "1"
                return
            }
        }
    }

    if ($AddToRemoteHostAuthKeys -and !$RemoteHost) {
        $RemoteHost = Read-Host -Prompt "Please enter an IP, FQDN, or DNS-resolvable Host Name that represents the Remote Host you would like to share your new public key with."
    }
    if ($RemoteHost -and !$AddToRemoteHostAuthKeys) {
        $AddToRemoteHostAuthKeys = $True
    }

    if ($RemoteHost) {
        try {
            $RemoteHostNetworkInfo = ResolveHost -HostNameOrIP $RemoteHost -ErrorAction Stop
        }
        catch {
            Write-Error "Unable to resolve $RemoteHost! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    if ($RemoteHost -or $AddToRemoteHostAuthKeys -and !$RemoteHostUserName) {
        $RemoteHostUserName = Read-Host -Prompt "Please enter a UserName that has access to $RemoteHost"
    }

    $UserSSHDir = Join-Path $HOME ".ssh"
    if (!$(Test-Path $UserSSHDir)) {
        $null = New-Item -Type Directory -Path $UserSSHDir
    }

    $SSHKeyOutFile = Join-Path $UserSSHDir $NewSSHKeyName

    if ($NewSSHKeyPwd) {
        $NewSSHKeyPwdPT = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($NewSSHKeyPwd))
    }

    if ($NewSSHKeyPurpose) {
        #$SSHKeyGenArgumentsString = "-t rsa -b 2048 -f `"$SSHKeyOutFile`" -q -N `"$NewSSHKeyPwdPT`" -C `"$NewSSHKeyPurpose`""
        $NewSSHKeyPurpose = $NewSSHKeyPurpose -replace "[\s]",""
        $SSHKeyGenArgumentsString = "-t rsa -b 2048 -f `"$SSHKeyOutFile`" -q -C `"$NewSSHKeyPurpose`""
        $SSHKeyGenArgumentsStringForExpect = "-t rsa -b 2048 -f \`"$SSHKeyOutFile\`" -q -C \`"$NewSSHKeyPurpose\`""
    }
    else {
        #$SSHKeyGenArgumentsString = "-t rsa -b 2048 -f `"$SSHKeyOutFile`" -q -N `"$NewSSHKeyPwd`""
        $SSHKeyGenArgumentsString = "-t rsa -b 2048 -f `"$SSHKeyOutFile`" -q"
        $SSHKeyGenArgumentsStringForExpect = "-t rsa -b 2048 -f \`"$SSHKeyOutFile\`" -q"
    }
    
    #endregion >> Prep


    #region >> Main

    if (!$PSVersionTable.Platform -or $PSVersionTable.Platform -eq "Win32NT") {
        $sshkeygenParentDir = $(Get-Command ssh-keygen).Source | Split-Path -Parent

        #region >> Await Attempt 1 of 2

        # Create new public/private keypair
        $null = Start-AwaitSession
        Start-Sleep -Seconds 1
        $null = Send-AwaitCommand '$host.ui.RawUI.WindowTitle = "PSAwaitSession"'
        $PSAwaitProcess = $($(Get-Process | Where-Object {$_.Name -eq "powershell"}) | Sort-Object -Property StartTime -Descending)[0]
        Start-Sleep -Seconds 1
        $null = Send-AwaitCommand "`$env:Path = '$env:Path'; Push-Location '$sshkeygenParentDir'"
        Start-Sleep -Seconds 1
        $null = Send-AwaitCommand -Command $([scriptblock]::Create("ssh-keygen $SSHKeyGenArgumentsString; Test-Path $SSHKeyOutFile"))
        Start-Sleep -Seconds 2

        $PassphraseOrOverwriteExistingKey = Receive-AwaitResponse

        [System.Collections.ArrayList]$CheckForExpectedResponses = @()
        $null = $CheckForExpectedResponses.Add($PassphraseOrOverwriteExistingKey)
        $Counter = 0
        while (![bool]$($($CheckForExpectedResponses -split "`n") -match [regex]::Escape("Enter passphrase (empty for no passphrase):")) -and
        ![bool]$($($CheckForExpectedResponses -split "`n") -match [regex]::Escape("Overwrite (y/n)?")) -and $Counter -le 30
        ) {
            $PassphraseOrOverwriteExistingKey = Receive-AwaitResponse
            $null = $CheckForExpectedResponses.Add($PassphraseOrOverwriteExistingKey)
            if ($CheckResponsesOutput -match "must be greater than zero" -or @($CheckResponsesOutput)[-1] -notmatch "[a-zA-Z]") {
                break
            }
            Start-Sleep -Seconds 1
            $Counter++
        }
        if ($Counter -eq 31) {
            Write-Verbose "sshkeygen attempt timed out!"

            if ($PSAwaitProcess.Id) {
                try {
                    $null = Stop-AwaitSession
                }
                catch {
                    if ($PSAwaitProcess.Id -eq $PID) {
                        Write-Error "The PSAwaitSession never spawned! Halting!"
                        $global:FunctionResult = "1"
                        return
                    }
                    else {
                        if ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                            Stop-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue
                        }
                        $Counter = 0
                        while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue) -and $Counter -le 15) {
                            Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                            Start-Sleep -Seconds 1
                            $Counter++
                        }
                    }
                }
                $PSAwaitProcess = $null
            }
        }

        #endregion >> Await Attempt 1 of 2

        $CheckResponsesOutput = $CheckForExpectedResponses | foreach {$_ -split "`n"}
            
        #region >> Await Attempt 2 of 2
        
        # If $CheckResponsesOutput contains the string "must be greater than zero", then something broke with the Await Module.
        # Most of the time, just trying again resolves any issues
        if ($CheckResponsesOutput -match "must be greater than zero" -or @($CheckResponsesOutput)[-1] -notmatch "[a-zA-Z]" -or
        $CheckResponsesOutput -match "background process reported an error") {
            if ($PSAwaitProcess.Id) {
                try {
                    $null = Stop-AwaitSession
                }
                catch {
                    if ($PSAwaitProcess.Id -eq $PID) {
                        Write-Error "The PSAwaitSession never spawned! Halting!"
                        $global:FunctionResult = "1"
                        return
                    }
                    else {
                        if ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                            Stop-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue
                        }
                        $Counter = 0
                        while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue) -and $Counter -le 15) {
                            Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                            Start-Sleep -Seconds 1
                            $Counter++
                        }
                    }
                }
            }

            # Create new public/private keypair
            $null = Start-AwaitSession
            Start-Sleep -Seconds 1
            $null = Send-AwaitCommand '$host.ui.RawUI.WindowTitle = "PSAwaitSession"'
            $PSAwaitProcess = $($(Get-Process | Where-Object {$_.Name -eq "powershell"}) | Sort-Object -Property StartTime -Descending)[0]
            Start-Sleep -Seconds 1
            $null = Send-AwaitCommand "`$env:Path = '$env:Path'; Push-Location '$sshkeygenParentDir'"
            Start-Sleep -Seconds 1
            $null = Send-AwaitCommand -Command $([scriptblock]::Create("ssh-keygen $SSHKeyGenArgumentsString"))
            Start-Sleep -Seconds 2

            $PassphraseOrOverwriteExistingKey = Receive-AwaitResponse

            [System.Collections.ArrayList]$CheckForExpectedResponses = @()
            $null = $CheckForExpectedResponses.Add($PassphraseOrOverwriteExistingKey)
            $Counter = 0
            while (![bool]$($($CheckForExpectedResponses -split "`n") -match [regex]::Escape("Enter passphrase (empty for no passphrase):")) -and
            ![bool]$($($CheckForExpectedResponses -split "`n") -match [regex]::Escape("Overwrite (y/n)?")) -and $Counter -le 30
            ) {
                $PassphraseOrOverwriteExistingKey = Receive-AwaitResponse
                $null = $CheckForExpectedResponses.Add($PassphraseOrOverwriteExistingKey)
                Start-Sleep -Seconds 1
                $Counter++
            }
            if ($Counter -eq 31) {
                Write-Error "sshkeygen attempt timed out!"
                $global:FunctionResult = "1"

                #$CheckForExpectedResponses

                if ($PSAwaitProcess.Id) {
                    try {
                        $null = Stop-AwaitSession
                    }
                    catch {
                        if ($PSAwaitProcess.Id -eq $PID) {
                            Write-Error "The PSAwaitSession never spawned! Halting!"
                            $global:FunctionResult = "1"
                            return
                        }
                        else {
                            if ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                Stop-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue
                            }
                            $Counter = 0
                            while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue) -and $Counter -le 15) {
                                Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                                Start-Sleep -Seconds 1
                                $Counter++
                            }
                        }
                    }
                }

                return
            }
        }

        #endregion >> Await Attempt 2 of 2

        $CheckResponsesOutput = $CheckForExpectedResponses | foreach {$_ -split "`n"}

        # At this point, if we don't have the expected output, we need to fail
        if ($CheckResponsesOutput -match "must be greater than zero" -or @($CheckResponsesOutput)[-1] -notmatch "[a-zA-Z]" -or
        $CheckResponsesOutput -match "background process reported an error") {
            if ($CheckResponsesOutput -match "must be greater than zero" -or @($CheckResponsesOutput)[-1] -notmatch "[a-zA-Z]") {
                Write-Error "Something went wrong with the PowerShell Await Module! Halting!"
            }
            if ($CheckResponsesOutput -match "background process reported an error") {
                Write-Error "Please check your credentials! Halting!"
            }
            $global:FunctionResult = "1"

            if ($PSAwaitProcess.Id) {
                try {
                    $null = Stop-AwaitSession
                }
                catch {
                    if ($PSAwaitProcess.Id -eq $PID) {
                        Write-Error "The PSAwaitSession never spawned! Halting!"
                        $global:FunctionResult = "1"
                        return
                    }
                    else {
                        if ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                            Stop-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue
                        }
                        $Counter = 0
                        while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue) -and $Counter -le 15) {
                            Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                            Start-Sleep -Seconds 1
                            $Counter++
                        }
                    }
                }
            }

            return
        }

        # Now we should either have a prompt to accept the host key, a prompt for a password, or it already worked...

        if ($CheckResponsesOutput -match [regex]::Escape("Overwrite (y/n)?")) {
            $null = Send-AwaitCommand "y"
            Start-Sleep -Seconds 3
            
            # This will either not prompt at all or prompt for a password
            $PassphraseOrOverwriteExistingKey = Receive-AwaitResponse

            [System.Collections.ArrayList]$CheckExpectedSendYesOutput = @()
            $null = $CheckExpectedSendYesOutput.Add($PassphraseOrOverwriteExistingKey)
            $Counter = 0
            while (![bool]$($($CheckExpectedSendYesOutput -split "`n") -match [regex]::Escape("Enter passphrase (empty for no passphrase):")) -and $Counter -le 30) {
                $PassphraseOrOverwriteExistingKey = Receive-AwaitResponse
                $null = $CheckExpectedSendYesOutput.Add($PassphraseOrOverwriteExistingKey)
                Start-Sleep -Seconds 1
                $Counter++
            }
            if ($Counter -eq 31) {
                Write-Error "Sending 'y' to overwrite the existing ssh key timed out!"
                $global:FunctionResult = "1"
                
                $CheckForExpectedResponses

                if ($PSAwaitProcess.Id) {
                    try {
                        $null = Stop-AwaitSession
                    }
                    catch {
                        if ($PSAwaitProcess.Id -eq $PID) {
                            Write-Error "The PSAwaitSession never spawned! Halting!"
                            $global:FunctionResult = "1"
                            return
                        }
                        else {
                            if ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                Stop-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue
                            }
                            $Counter = 0
                            while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue) -and $Counter -le 15) {
                                Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                                Start-Sleep -Seconds 1
                                $Counter++
                            }
                        }
                    }
                }

                return
            }

            $CheckSendYesOutput = $CheckExpectedSendYesOutput | foreach {$_ -split "`n"}
        }

        if ($CheckSendYesOutput -match [regex]::Escape("Enter passphrase (empty for no passphrase):") -or
        $CheckResponsesOutput -match [regex]::Escape("Enter passphrase (empty for no passphrase):")
        ) {
            if ($NewSSHKeyPwd) {
                $null = Send-AwaitCommand $NewSSHKeyPwdPT
            }
            else {
                $null = Send-AwaitCommand ""
            }
            Start-Sleep -Seconds 3

            $PassphraseOrOverwriteExistingKey = Receive-AwaitResponse

            [System.Collections.ArrayList]$CheckExpectedSendPwdOutput = @()
            $null = $CheckExpectedSendPwdOutput.Add($PassphraseOrOverwriteExistingKey)
            $Counter = 0
            while (![bool]$($CheckExpectedSendPwdOutput -match [regex]::Escape("Enter same passphrase again:")) -and $Counter -le 30) {
                $PassphraseOrOverwriteExistingKey = Receive-AwaitResponse
                $null = $CheckExpectedSendPwdOutput.Add($PassphraseOrOverwriteExistingKey)
                Start-Sleep -Seconds 1
                $Counter++
            }
            if ($Counter -eq 31) {
                Write-Error "Sending the initial password for the private key timed out!"
                $global:FunctionResult = "1"

                $CheckExpectedSendPwdOutput
                
                if ($PSAwaitProcess.Id) {
                    try {
                        $null = Stop-AwaitSession
                    }
                    catch {
                        if ($PSAwaitProcess.Id -eq $PID) {
                            Write-Error "The PSAwaitSession never spawned! Halting!"
                            $global:FunctionResult = "1"
                            return
                        }
                        else {
                            if ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                Stop-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue
                            }
                            $Counter = 0
                            while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue) -and $Counter -le 15) {
                                Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                                Start-Sleep -Seconds 1
                                $Counter++
                            }
                        }
                    }
                }

                return
            }

            $CheckSendPwdOutput = $CheckExpectedSendPwdOutput | foreach {$_ -split "`n"}

            if ($CheckSendPwdOutput -match [regex]::Escape("Enter same passphrase again:")) {
                if ($NewSSHKeyPwd) {
                    $null = Send-AwaitCommand $NewSSHKeyPwdPT
                }
                else {
                    $null = Send-AwaitCommand ""
                }
                Start-Sleep -Seconds 3

                $PassphraseOrOverwriteExistingKey = Receive-AwaitResponse

                if (!$OutputPrep) {
                    [System.Collections.ArrayList]$OutputPrep = @()
                    if (![System.String]::IsNullOrWhiteSpace($SuccessOrAcceptHostKeyOrPwdPrompt)) {
                        $null = $OutputPrep.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                    }
                }
                $Counter = 0
                while (![bool]$($($OutputPrep -split "`n") -match "True") -and $Counter -le $CounterLimit) {
                    $PassphraseOrOverwriteExistingKey = Receive-AwaitResponse
                    $null = $OutputPrep.Add($PassphraseOrOverwriteExistingKey)
                    Start-Sleep -Seconds 1
                    $Counter++
                }
                if ($Counter -eq 31) {
                    Write-Error "Sending the password again timed out!"
                    $global:FunctionResult = "1"

                    $OutputPrep
                    
                    if ($PSAwaitProcess.Id) {
                        try {
                            $null = Stop-AwaitSession
                        }
                        catch {
                            if ($PSAwaitProcess.Id -eq $PID) {
                                Write-Error "The PSAwaitSession never spawned! Halting!"
                                $global:FunctionResult = "1"
                                return
                            }
                            else {
                                if ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                    Stop-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue
                                }
                                $Counter = 0
                                while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue) -and $Counter -le 15) {
                                    Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                                    Start-Sleep -Seconds 1
                                    $Counter++
                                }
                            }
                        }
                    }

                    return
                }
            }
        }
    
        $SSHKeyGenOutput = $OutputPrep
    }
    if ($PSVersionTable.Platform -eq "Unix" -or $PSVersionTable.OS -match "Darwin") {
        if ($AddToSSHAgent) {
            # Check to see if the ssh-agent is running
            #[scriptblock]::Create('ssh-add -L').InvokeReturnAsIs()
            $SSHAgentProcesses = Get-Process -Name ssh-agent -IncludeUserName -ErrorAction SilentlyContinue | Where-Object {$_.UserName -eq $env:USER}
            if ($SSHAgentProcesses.Count -gt 0) {
                $LatestSSHAgentProcess = $(@($SSHAgentProcesses) | Sort-Object StartTime)[-1]
                $env:SSH_AUTH_SOCK = $(Get-ChildItem /tmp -Recurse -File | Where-Object {$_.FullName -match "\.$($LatestSSHAgentProcess.Id-1)"}).FullName
                $env:SSH_AGENT_PID = $LatestSSHAgentProcess.Id
            }
            else {                
                $SSHAgentInfo = ssh-agent
                $env:SSH_AUTH_SOCK = $($($($SSHAgentInfo -match "AUTH_SOCK") -replace 'SSH_AUTH_SOCK=','') -split ';')[0]
                $env:SSH_AGENT_PID = $($($($SSHAgentInfo -match "SSH_AGENT_PID") -replace 'SSH_AGENT_PID=','') -split ';')[0]
            }
        }

        [System.Collections.ArrayList]$ExpectScriptPrep = @(
            'expect - << EOF'
            'set timeout 20'
        )
        if ($NewSSHKeyPwdPT) {
            $null = $ExpectScriptPrep.Add("set password $NewSSHKeyPwdPT")
        }

        [System.Collections.ArrayList]$ExpectScriptPrep2 = @(
            'set prompt \"(>|:|#|\\\\\\$)\\\\s+\\$\"'
            "spawn ssh-keygen $SSHKeyGenArgumentsStringForExpect"
            'match_max 100000'
            'expect {'
            '    \"*Overwrite (y*\" {'
            '        send -- \"y\r\"'
            '        exp_continue'
            '    }'
            '    \"*(empty for no passphrase)*\" {'
        )
        if ($NewSSHKeyPwdPT) {
            $null = $ExpectScriptPrep2.Add('        send -- \"\$password\r\"')
        }
        else {
            $null = $ExpectScriptPrep2.Add('        send -- \"\r\"')
        }

        [System.Collections.ArrayList]$ExpectScriptPrep3 = @(
            '        expect \"*Enter same passphrase again*\"'
            '    }'
            '}'
        )
        if ($NewSSHKeyPwdPT) {
            $null = $ExpectScriptPrep3.Add('send -- \"\$password\r\"')
        }
        else {
            $null = $ExpectScriptPrep3.Add('send -- \"\r\"')
        }

        foreach ($Line in $ExpectScriptPrep2) {
            $null = $ExpectScriptPrep.Add($Line)
        }
        foreach ($Line in $ExpectScriptPrep3) {
            $null = $ExpectScriptPrep.Add($Line)
        }

        $null = $ExpectScriptPrep.Add('expect eof')
        $null = $ExpectScriptPrep.Add('EOF')
        
        $ExpectScript = $ExpectScriptPrep -join "`n"

        Write-Host "`$ExpectScript is:`n$ExpectScript"
        $ExpectScript | Export-CliXml "$HOME/ExpectScriptA.xml"
        
        # The below $ExpectOutput is an array of strings
        $ExpectOutput = bash -c "$ExpectScript"

        $SSHKeyGenOutput = $ExpectOutput
    }

    $PubPrivKeyPairFiles = Get-ChildItem -Path $UserSSHDir -File | Where-Object {$_.Name -match "$NewSSHKeyName"}
    $PubKey = $PubPrivKeyPairFiles | Where-Object {$_.Extension -eq ".pub"}
    $PrivKey = $PubPrivKeyPairFiles | Where-Object {$_.Extension -ne ".pub"}

    if (!$PubKey -or !$PrivKey) {
        if (!$PSVersionTable.Platform -or $PSVersionTable.Platform -eq "Win32NT") {
            $Counter = 0
            if ($PSAwaitProcess.Id) {
                try {
                    $null = Stop-AwaitSession
                }
                catch {
                    if ($PSAwaitProcess.Id -eq $PID) {
                        Write-Error "The PSAwaitSession never spawned! Halting!"
                        $global:FunctionResult = "1"
                        return
                    }
                    else {
                        if ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                            Stop-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue
                        }
                        $Counter = 0
                        while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue) -and $Counter -le 15) {
                            Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                            Start-Sleep -Seconds 1
                            $Counter++
                        }
                    }
                }
            }
        }

        Write-Error "The New SSH Key Pair was NOT created! Please review the output of ssh-keygen below. Halting!"
        $global:FunctionResult = "1"
        $SSHKeyGenOutput
        return
    }

    if ($AddToSSHAgent) {
        # Add the New Private Key to the ssh-agent
        $null = [scriptblock]::Create("ssh-add $($PrivKey.FullName)").InvokeReturnAsIs()
        if ($LASTEXITCODE -ne 0) {
            Write-Warning $Error[0].Exception.Message
            Write-Warning "There was a problem adding $($PrivKey.FullName) to the ssh-agent PID $env:SSH_AGENT_PID!"
        }

        [System.Collections.ArrayList]$PublicKeysAccordingToSSHAgent = @()
        $(ssh-add -L) | foreach {
            $null = $PublicKeysAccordingToSSHAgent.Add($_)
        }
        $ThisPublicKeyAccordingToSSHAgent = $PublicKeysAccordingToSSHAgent | Where-Object {$_ -match "$NewSSHKeyName$"}
        [System.Collections.ArrayList]$CharacterCountArray = @()
        $ThisPublicKeyAccordingToSSHAgent -split " " | foreach {
            $null = $CharacterCountArray.Add($_.Length)
        }
        $LongestStringLength = $($CharacterCountArray | Measure-Object -Maximum).Maximum
        $ArrayPositionBeforeComment = $CharacterCountArray.IndexOf([int]$LongestStringLength)
        $PublicKeySansCommentFromSSHAgent = $($ThisPublicKeyAccordingToSSHAgent -split " ")[0..$ArrayPositionBeforeComment] -join " "

        $ThisPublicKeyAccordingToFile = Get-Content $PubKey.FullName
        [System.Collections.ArrayList]$CharacterCountArray = @()
        $ThisPublicKeyAccordingToFile -split " " | foreach {
            $null = $CharacterCountArray.Add($_.Length)
        }
        $LongestStringLength = $($CharacterCountArray | Measure-Object -Maximum).Maximum
        $ArrayPositionBeforeComment = $CharacterCountArray.IndexOf([int]$LongestStringLength)
        $PublicKeySansCommentFromFile = $($ThisPublicKeyAccordingToFile -split " ")[0..$ArrayPositionBeforeComment] -join " "

        if ($PublicKeySansCommentFromSSHAgent -ne $PublicKeySansCommentFromFile) {
            Write-Warning "The public key according to the ssh-agent does NOT match the public key content in $($PubKey.FullName)! It appears the private key was never added to the ssh-agent!"
        }

        Write-Host "The Private Key $PublicKeyLocationFinal has been added to the ssh-agent service." -ForegroundColor Green
        
        if (!$RemovePrivateKey) {
            Write-Host "It is now safe to delete the private key (i.e. $($PrivKey.FullName)) since it has been added to the ssh-agent." -ForegroundColor Green
        }
    }

    if ($AddToRemoteHostAuthKeys) {
        if ($RemoteHostNetworkInfo.FQDN) {
            $RemoteHostLocation = $RemoteHostNetworkInfo.FQDN
        }
        elseif ($RemoteHostNetworkInfo.HostName) {
            $RemoteHostLocation = $RemoteHostNetworkInfo.HostName
        }
        elseif ($RemoteHostNetworkInfo.IPAddressList[0]) {
            $RemoteHostLocation = $RemoteHostNetworkInfo.IPAddressList[0]
        }
        
        try {
            Add-PublicKeyToRemoteHost -PublicKeyPath $PubKey.FullName -RemoteHost $RemoteHostLocation -RemoteHostUserName $RemoteHostUserName -ErrorAction Stop
        }
        catch {
            Write-Error "Unable to add the public key to the authorized_keys file on $RemoteHost! Halting!"
            $global:FunctionResult = "1"
            return
        }
        
        if (!$AddToSSHAgent) {
            Write-Host "You can now ssh to $RemoteHost using public key authentication using the following command:" -ForegroundColor Green
            Write-Host "    ssh -i $PubKey.FullName $RemoteHostUserName@$RemoteHostLocation" -ForegroundColor Green
        }
        else {
            Write-Host "You can now ssh to $RemoteHost using public key authentication using the following command:" -ForegroundColor Green
            Write-Host "    ssh $RemoteHostUserName@$RemoteHostLocation" -ForegroundColor Green
        }
    }

    [pscustomobject]@{
        PublicKeyFilePath       = $PubKey.FullName
        PrivateKeyFilePath      = if (!$RemovePrivateKey) {$PrivKey.FullName} else {"PrivateKey was deleted after being added to the ssh-agent"}
        PublicKeyContent        = Get-Content $(Join-Path $UserSSHDir "$NewSSHKeyName.pub")
    }

    ##### END Main Body #####

}


<#
    .SYNOPSIS
        This function revokes the Vault Token for the specified User.

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER VaultServerBaseUri
        This parameter is MANDATORY.

        This parameter takes a string that represents a Uri referencing the location of the Vault Server
        on your network. Example: "https://vaultserver.zero.lab:8200/v1"

    .PARAMETER VaultAuthToken
        This parameter is MANDATORY.

        This parameter takes a string that represents a Token for a Vault User that has (root) permission to
        lookup and delete Tokens using the Vault Server REST API.

    .PARAMETER VaultUserToDelete
        This parameter is MANDATORY.

        This parameter takes a string that represents the name of the user that you would like to revoke Tokens
        for. The UserName should match the .meta.username property from objects returned by the
        Get-VaultAccessorLookup function - which itself should match the Basic UserName in Active Directory.
        (For example, if the Domain User is 'zero\jsmith' the "Basic UserName" is 'jsmith', which
        is the value that you should supply to this paramter)

        IMPORTANT NOTE: ALL tokens granted to the specified user will be revoked.

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> $SplatParams = @{
            VaultServerBaseUri      = $VaultServerBaseUri
            VaultAuthToken          = $ZeroAdminToken
            VaultuserToDelete       = "jsmith"
        }
        PS C:\Users\zeroadmin> Revoke-VaultToken @SplatParams
        
#>
function Revoke-VaultToken {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$VaultServerBaseUri, # Should be something like "http://192.168.2.12:8200/v1"

        [Parameter(Mandatory=$True)]
        [string]$VaultAuthToken, # Should be something like 'myroot' or '434f37ca-89ae-9073-8783-087c268fd46f'

        [Parameter(Mandatory=$True)]
        [string[]]$VaultUserToDelete # Should match .meta.username for the Accessor Lookup
    )

    if ($PSVersionTable.Platform -eq "Unix" -or $PSVersionTable.OS -match "Darwin" -and $env:SudoPwdPrompt) {
        if (GetElevation) {
            Write-Error "You should not be running the VaultServer Module as root! Halting!"
            $global:FunctionResult = "1"
            return
        }
        RemoveMySudoPwd
        NewCronToAddSudoPwd
        $env:SudoPwdPrompt = $False
    }

    # Make sure $VaultServerBaseUri is a valid Url
    try {
        $UriObject = [uri]$VaultServerBaseUri
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }
    if (![bool]$($UriObject.Scheme -match "http")) {
        Write-Error "'$VaultServerBaseUri' does not appear to be a URL! Halting!"
        $global:FunctionResult = "1"
        return
    }

    # If $VaultServerBaseUri ends in '/', remove it
    if ($VaultServerBaseUri[-1] -eq "/") {
        $VaultServerBaseUri = $VaultServerBaseUri.Substring(0,$VaultServerBaseUri.Length-1)
    }

    try {
        $AccessorInfo = Get-VaultAccessorLookup -VaultServerBaseUri $VaultServerBaseUri -VaultAuthToken $VaultAuthToken -ErrorAction Stop
        if (!$AccessorInfo) {throw "Ther Get-VaultAccessorLookup function failed! Halting!"}
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    $AccessorToDelete = $($AccessorInfo | Where-Object {$_.meta.username -eq $VaultUserToDelete}).accessor
    if (!$AccessorToDelete) {
        Write-Error "Unable to find Accessor matching username $VaultUserToDelete! Halting!"
        $global:FunctionResult = "1"
        return
    }

    $jsonRequest = @"
{
    "accessor": "$AccessorToDelete"
}
"@
    try {
        # Validate JSON
        $JsonRequestAsSingleLineString = $jsonRequest | ConvertFrom-Json -EA Stop | ConvertTo-Json -Compress -EA Stop
    }
    catch {
        Write-Error "There was a problem with the JSON for deleting an accessor! Halting!"
    }
    $IWRSplatParams = @{
        Uri         = "$VaultServerBaseUri/auth/token/revoke-accessor"
        Headers     = @{"X-Vault-Token" = "$VaultAuthToken"}
        Body        = $JsonRequestAsSingleLineString
        Method      = "Post"
    }
    $RevokeTokenResult = Invoke-RestMethod @IWRSplatParams
    # NOTE: Revoking a Token does Not produce output, to $RevokeJSmithTokenResult should be $null

    # Make sure it no longer exists
    try {
        $AccessorInfo = Get-VaultAccessorLookup -VaultServerBaseUri $VaultServerBaseUri -VaultAuthToken $VaultAuthToken -ErrorAction Stop
        if (!$AccessorInfo) {throw "Ther Get-VaultAccessorLookup function failed! Halting!"}
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    $AccessorStillExists = $($AccessorInfo | Where-Object {$_.meta.username -eq $VaultUserToDelete}).accessor
    if ($AccessorStillExists) {
        Write-Error "There was a problem deleting the accessor $AccessorToDelete for user $VaultUserToDelete! Halting!"
        $global:FunctionResult = '1'
        return
    }

    "Success"
}


<#
    .SYNOPSIS
        This function (via teh Vault Server REST API) asks the Vault Server to sign the Local Host's
        SSH Host Key (i.e. 'C:\ProgramData\ssh\ssh_host_rsa_key.pub', resulting in output
        'C:\ProgramData\ssh\ssh_host_rsa_key-cert.pub').

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER VaultSSHHostSigningUrl
        This parameter is MANDATORY.

        This parameter takes a string that represents the Vault Server REST API endpoint responsible
        for signing Host/Machine SSH Keys. The Url should be something like:
            https://vaultserver.zero.lab:8200/v1/ssh-host-signer/sign/hostrole

    .PARAMETER VaultAuthToken
        This parameter is MANDATORY.

        This parameter takes a string that represents a Vault Authentication Token that has
        permission to request SSH Host Key Signing via the Vault Server REST API.

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Sign-SSHHostPublicKey -VaultSSHHostSigningUrl $VaultSSHHostSigningUrl -VaultAuthToken $ZeroAdminToken
        
#>
function Sign-SSHHostPublicKey {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$VaultSSHHostSigningUrl, # Should be something like "http://192.168.2.12:8200/v1/ssh-host-signer/sign/hostrole"

        [Parameter(Mandatory=$True)]
        [string]$VaultAuthToken # Should be something like 'myroot' or '434f37ca-89ae-9073-8783-087c268fd46f'
    )

    #region >> Prep

    if ($PSVersionTable.Platform -eq "Unix" -or $PSVersionTable.OS -match "Darwin" -and $env:SudoPwdPrompt) {
        if (GetElevation) {
            Write-Error "You should not be running the VaultServer Module as root! Halting!"
            $global:FunctionResult = "1"
            return
        }
        RemoveMySudoPwd
        NewCronToAddSudoPwd
        $env:SudoPwdPrompt = $False
    }

    if (!$PSVersionTable.Platform -or $PSVersionTable.Platform -eq "Win32NT") {
        # Make sure sshd service is installed and running. If it is, we shouldn't need to use
        # the New-SSHD server function
        if (![bool]$(Get-Service sshd -ErrorAction SilentlyContinue)) {
            if (![bool]$(Get-Service ssh-agent -ErrorAction SilentlyContinue)) {
                $InstallWinSSHSplatParams = @{
                    GiveWinSSHBinariesPathPriority  = $True
                    ConfigureSSHDOnLocalHost        = $True
                    DefaultShell                    = "pwsh"
                    ErrorAction                     = "SilentlyContinue"
                    ErrorVariable                   = "IWSErr"
                }

                try {
                    $InstallWinSSHResults = Install-WinSSH @InstallWinSSHSplatParams -ErrorAction Stop
                    if (!$InstallWinSSHResults) {throw "There was a problem with the Install-WinSSH function! Halting!"}
                }
                catch {
                    Write-Error $_
                    Write-Host "Errors for the Install-WinSSH function are as follows:"
                    Write-Error $($IWSErr | Out-String)
                    $global:FunctionResult = "1"
                    return
                }
            }
            else {
                $NewSSHDServerSplatParams = @{
                    ErrorAction         = "SilentlyContinue"
                    ErrorVariable       = "SSHDErr"
                    DefaultShell        = "powershell"
                }
                
                try {
                    $NewSSHDServerResult = New-SSHDServer @NewSSHDServerSplatParams
                    if (!$NewSSHDServerResult) {throw "There was a problem with the New-SSHDServer function! Halting!"}
                }
                catch {
                    Write-Error $_
                    Write-Host "Errors for the New-SSHDServer function are as follows:"
                    Write-Error $($SSHDErr | Out-String)
                    $global:FunctionResult = "1"
                    return
                }
            }
        }

        if (Test-Path "$env:ProgramData\ssh") {
            $sshdir = "$env:ProgramData\ssh"
        }
        elseif (Test-Path "$env:ProgramFiles\OpenSSH-Win64") {
            $sshdir = "$env:ProgramFiles\OpenSSH-Win64"
        }
        if (!$sshdir) {
            Write-Error "Unable to find ssh directory at '$env:ProgramData\ssh' or '$env:ProgramFiles\OpenSSH-Win64'! Halting!"
            $global:FunctionResult = "1"
            return
        }

        $PathToSSHHostPublicKeyFile = "$sshdir\ssh_host_rsa_key.pub"
        $sshdConfigPath = "$sshdir\sshd_config"

        if (!$(Test-Path $PathToSSHHostPublicKeyFile)) {
            Write-Error "Unable to find the SSH RSA Host Key for $env:ComputerName at path '$PathToSSHHostPublicKeyFile'! Halting!"
            $global:FunctionResult = "1"
            return
        }
        
        $SignedPubKeyCertFilePath = $PathToSSHHostPublicKeyFile -replace "\.pub","-cert.pub"
    }
    elseif ($PSVersionTable.Platform -eq "Unix" -or $PSVersionTable.OS -match "Darwin") {
        $sshdir = "/etc/ssh"
        $sshdConfigPath = "$sshdir/sshd_config"
        $PathToSSHHostPublicKeyFile = "$sshdir/ssh_host_rsa_key.pub"

        if (!$(Test-Path $PathToSSHHostPublicKeyFile)) {
            Write-Error "Unable to find the SSH RSA Host Key for $env:HostName at path '$PathToSSHHostPublicKeyFile'! Halting!"
            $global:FunctionResult = "1"
            return
        }
        
        $SignedPubKeyCertFilePath = $PathToSSHHostPublicKeyFile -replace "\.pub","-cert.pub"
    }

    # Make sure $VaultSSHHostSigningUrl is a valid Url
    try {
        $UriObject = [uri]$VaultSSHHostSigningUrl
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    if (![bool]$($UriObject.Scheme -match "http")) {
        Write-Error "'$VaultSSHHostSigningUrl' does not appear to be a URL! Halting!"
        $global:FunctionResult = "1"
        return
    }

    # If $VaultSSHHostSigningUrl ends in '/', remove it
    if ($VaultSSHHostSigningUrl[-1] -eq "/") {
        $VaultSSHHostSigningUrl = $VaultSSHHostSigningUrl.Substring(0,$VaultSSHHostSigningUrl.Length-1)
    }

    #endregion >> Prep

    #region >> Main

    # HTTP API Request
    # The below removes 'comment' text from the Host Public key because sometimes it can cause problems
    # with the below json
    $PubKeyContent = $($(Get-Content $PathToSSHHostPublicKeyFile) -split "[\s]")[0..1] -join " "

    $jsonRequest = @"
{
    "cert_type": "host",
    "extension": {
      "permit-pty": "",
      "permit-agent-forwarding": ""
    },
    "public_key": "$PubKeyContent"
  }
"@
    $JsonRequestAsSingleLineString = $jsonRequest | ConvertFrom-Json | ConvertTo-Json -Compress

    $HeadersParameters = @{
        "X-Vault-Token" = $VaultAuthToken
    }
    $IWRSplatParams = @{
        Uri         = $VaultSSHHostSigningUrl
        Headers     = $HeadersParameters
        Body        = $JsonRequestAsSingleLineString
        Method      = "Post"
    }

    $SignedSSHClientPubKeyCertResponse = Invoke-WebRequest @IWRSplatParams
    Set-Content -Value $($SignedSSHClientPubKeyCertResponse.Content | ConvertFrom-Json).data.signed_key.Trim() -Path $SignedPubKeyCertFilePath

    # Make sure permissions on "$sshdir/ssh_host_rsa_key-cert.pub" are set properly
    if ($PSVersionTable.PSEdition -eq "Core" -and $PSVersionTable.Platform -eq "Win32NT") {
        $null = Invoke-WinCommand -ComputerName localhost -ScriptBlock {
            $SecurityDescriptor = Get-NTFSSecurityDescriptor -Path $args[0]
            $SecurityDescriptor | Disable-NTFSAccessInheritance -RemoveInheritedAccessRules
            $SecurityDescriptor | Clear-NTFSAccess
            $SecurityDescriptor | Add-NTFSAccess -Account "NT AUTHORITY\SYSTEM" -AccessRights "FullControl" -AppliesTo ThisFolderSubfoldersAndFiles
            $SecurityDescriptor | Add-NTFSAccess -Account "Administrators" -AccessRights "FullControl" -AppliesTo ThisFolderSubfoldersAndFiles
            $SecurityDescriptor | Add-NTFSAccess -Account "NT AUTHORITY\Authenticated Users" -AccessRights "ReadAndExecute, Synchronize" -AppliesTo ThisFolderSubfoldersAndFiles
            $SecurityDescriptor | Set-NTFSSecurityDescriptor
        } -ArgumentList $SignedPubKeyCertFilePath
    }
    elseif ($PSVersionTable.PSEdition -eq "Desktop") {
        $SecurityDescriptor = Get-NTFSSecurityDescriptor -Path $SignedPubKeyCertFilePath
        $null = $SecurityDescriptor | Disable-NTFSAccessInheritance -RemoveInheritedAccessRules
        $null = $SecurityDescriptor | Clear-NTFSAccess
        $null = $SecurityDescriptor | Add-NTFSAccess -Account "NT AUTHORITY\SYSTEM" -AccessRights "FullControl" -AppliesTo ThisFolderSubfoldersAndFiles
        $null = $SecurityDescriptor | Add-NTFSAccess -Account "Administrators" -AccessRights "FullControl" -AppliesTo ThisFolderSubfoldersAndFiles
        $null = $SecurityDescriptor | Add-NTFSAccess -Account "NT AUTHORITY\Authenticated Users" -AccessRights "ReadAndExecute, Synchronize" -AppliesTo ThisFolderSubfoldersAndFiles
        $null = $SecurityDescriptor | Set-NTFSSecurityDescriptor
    }
    elseif ($PSVersionTable.Platform -eq "Unix" -or $PSVersionTable.OS -match "Darwin") {
        chmod 644 "$SignedPubKeyCertFilePath"
    }

    # Update sshd_config
    [System.Collections.ArrayList]$sshdContent = Get-Content $sshdConfigPath

    # Determine if sshd_config already has the 'HostCertificate' option active
    $ExistingHostCertificateOption = $sshdContent -match "HostCertificate" | Where-Object {$_ -notmatch "#"}
    $HostCertificatePath =  $PathToSSHHostPublicKeyFile -replace "\.pub","-cert.pub"
    $HostCertificateOptionLine = "HostCertificate $HostCertificatePathWithForwardSlashes"
    
    if (!$ExistingHostCertificateOption) {
        try {
            $LineNumberToInsertOn = $sshdContent.IndexOf($($sshdContent -match "HostKey .*ssh_host_rsa_key$")) + 1
            [System.Collections.ArrayList]$sshdContent.Insert($LineNumberToInsertOn, $HostCertificateOptionLine)
            Set-Content -Value $sshdContent -Path $sshdConfigPath
            $SSHDConfigContentChanged = $True
            [System.Collections.ArrayList]$sshdContent = Get-Content $sshdConfigPath
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }
    }
    else {
        if ($ExistingHostCertificateOption -ne $HostCertificateOptionLine) {
            $UpdatedSSHDConfig = $sshdContent -replace [regex]::Escape($ExistingHostCertificateOption),"$HostCertificateOptionLine"

            try {
                Set-Content -Value $UpdatedSSHDConfig -Path $sshdConfigPath
                $SSHDConfigContentChanged = $True
                [System.Collections.ArrayList]$sshdContent = Get-Content $sshdConfigPath
            }
            catch {
                Write-Error $_
                $global:FunctionResult = "1"
                return
            }
        }
        else {
            Write-Warning "The specified 'HostCertificate' option is already active in the the sshd_config file. No changes made."
        }
    }

    [pscustomobject]@{
        SignedPubKeyCertFile        = Get-Item $SignedPubKeyCertFilePath
        SSHDConfigContentChanged    = if ($SSHDConfigContentChanged) {$True} else {$False}
        SSHDContentThatWasAdded     = if ($SSHDConfigContentChanged) {$HostCertificateOptionLine}
    }

    #endregion >> Main
}


<#
    .SYNOPSIS
        This function signs an SSH Client/User Public Key (for example, "$HOME\.ssh\id_rsa.pub") resulting
        in a Public Certificate (for example, "$HOME\.ssh\id_rsa-cert.pub"). This Public Certificate can
        then be used for Public Key Certificate SSH Authentication.

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER VaultSSHClientSigningUrl
        This parameter is MANDATORY.

        This parameter takes a string that represents the Vault Server REST API endpoint responsible
        for signing Client/User SSH Keys. The Url should be something like:
            https://vaultserver.zero.lab:8200/v1/ssh-client-signer/sign/clientrole

    .PARAMETER VaultAuthToken
        This parameter is MANDATORY.

        This parameter takes a string that represents a Vault Authentication Token that has
        permission to request SSH User/Client Key Signing via the Vault Server REST API.

    .PARAMETER AuthorizedUserPrincipals
        This parameter is MANDATORY.

        This parameter takes a string or array of strings that represent the User or Users that will
        be using the Public Key Certificate to SSH into remote machines.

        Local User Accounts MUST be in the format <UserName>@<LocalHostComputerName> and
        Domain User Accounts MUST be in the format <UserName>@<DomainPrefix>. (To clarify DomainPrefix: if your
        domain is, for example, 'zero.lab', your DomainPrefix would be 'zero').

    .PARAMETER PathToSSHUserPublicKeyFile
        This parameter is MANDATORY.

        This parameter takes a string that represents the full path to the SSH Public Key that you would like
        the Vault Server to sign. Example: "$HOME\.ssh\id_rsa.pub"

    .PARAMETER PathToSSHUserPrivateKeyFile
        This parameter is OPTIONAL, but becomes MANDATORY if you want to add the signed Public Key Certificate to
        the ssh-agent service.

        This parameter takes a string that represents a full path to the SSH User/Client private key file.

    .PARAMETER AddToSSHAgent
        This parameter is OPTIONAL.

        This parameter is a switch. If used, the signed Public Key Certificate will be added to the ssh-agent service.

    .PARAMETER SSHAgentExpiry
        This parameter is OPTIONAL. This parameter should only be used in conjunction with the
        -AddtoSSHAgent switch.

        This parameter takes an integer that specifies the number of seconds that the ssh key identity will
        remain in the ssh-agent - at which point it will expire and be removed from the ssh-agent.

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> $SplatParams = @{
            VaultSSHClientSigningUrl    = $VaultSSHClientSigningUrl
            VaultAuthToken              = $ZeroAdminToken
            AuthorizedUserPrincipals    = @("zeroadmin@zero")
            PathToSSHUserPublicKeyFile  = "$HOME\.ssh\zeroadmin_id_rsa.pub"
            PathToSSHUserPrivateKeyFile = "$HOME\.ssh\zeroadmin_id_rsa"
            AddToSSHAgent               = $True
        }
        PS C:\Users\zeroadmin> Sign-SSHUserPublicKey @SplatParams
        
#>
function Sign-SSHUserPublicKey {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$VaultSSHClientSigningUrl, # Should be something like "http://192.168.2.12:8200/v1/ssh-client-signer/sign/clientrole"

        [Parameter(Mandatory=$True)]
        [string]$VaultAuthToken, # Should be something like 'myroot' or '434f37ca-89ae-9073-8783-087c268fd46f'

        [Parameter(Mandatory=$True)]
        [ValidatePattern("[\w]+@[\w]+")]
        [string[]]$AuthorizedUserPrincipals, # Should be in format <User>@<HostNameOrDomainPrefix> - and can be an array of strings

        [Parameter(Mandatory=$True)]
        [ValidatePattern("\.pub")]
        [string]$PathToSSHUserPublicKeyFile,

        [Parameter(Mandatory=$False)]
        [string]$PathToSSHUserPrivateKeyFile,

        [Parameter(Mandatory=$False)]
        [switch]$AddToSSHAgent,

        [Parameter(Mandatory=$False)]
        [int]$SSHAgentExpiry
    )

    #region >> Prep

    if ($PSVersionTable.Platform -eq "Unix" -or $PSVersionTable.OS -match "Darwin" -and $env:SudoPwdPrompt) {
        if (GetElevation) {
            Write-Error "You should not be running the VaultServer Module as root! Halting!"
            $global:FunctionResult = "1"
            return
        }
        RemoveMySudoPwd
        NewCronToAddSudoPwd
        $env:SudoPwdPrompt = $False
    }

    if ($AddedToSSHAgent) {
        if (!$(Get-Command ssh-add -ErrorAction SilentlyContinue)) {
            Write-Error "Unable to find ssh-add! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }
    
    if (!$(Test-Path $PathToSSHUserPublicKeyFile)) {
        Write-Error "The path '$PathToSSHUserPublicKeyFile' was not found! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($PathToSSHUserPrivateKeyFile) {
        $CorrespondingPrivateKeyPath = $PathToSSHUserPrivateKeyFile
    }
    else {
        $CorrespondingPrivateKeyPath = $PathToSSHUserPublicKeyFile -replace "\.pub",""
    }

    if ($PathToSSHUserPrivateKeyFile) {
        if (!$(Test-Path $CorrespondingPrivateKeyPath)) {
            Write-Error "Unable to find expected path to corresponding private key, i.e. '$CorrespondingPrivateKeyPath'! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    $SignedPubKeyCertFilePath = $PathToSSHUserPublicKeyFile -replace "\.pub","-cert.pub"
    
    if ($PathToSSHUserPrivateKeyFile) {
        # Check to make sure the user private key isn't password protected. If it is, things break
        # with current Windows OpenSSH implementation
        try {
            $ValidateSSHPrivateKeyResult = Validate-SSHPrivateKey -PathToPrivateKeyFile $CorrespondingPrivateKeyPath -ErrorAction Stop
            if (!$ValidateSSHPrivateKeyResult) {throw "There was a problem with the Validate-SSHPrivateKey function! Halting!"}

            if (!$ValidateSSHPrivateKeyResult.ValidSSHPrivateKeyFormat) {
                throw "'$CorrespondingPrivateKeyPath' is not in a valid format! Double check with: ssh-keygen -y -f `"$CorrespondingPrivateKeyPath`""
            }
            if ($ValidateSSHPrivateKeyResult.PasswordProtected) {
                $KeysCurrentlyInAgent = ssh-add -L
                if (![bool]$($KeysCurrentlyInAgent -match $CorrespondingPrivateKeyPath)) {
                    throw "'$CorrespondingPrivateKeyPath' is password protected and it has not been loaded into the ssh-agent! This means there will be a prompt! Halting!"
                }
            }
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }
    }

    # Make sure $VaultSSHClientSigningUrl is a valid Url
    try {
        $UriObject = [uri]$VaultSSHClientSigningUrl
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    if (![bool]$($UriObject.Scheme -match "http")) {
        Write-Error "'$VaultSSHClientSigningUrl' does not appear to be a URL! Halting!"
        $global:FunctionResult = "1"
        return
    }

    # If $VaultSSHClientSigningUrl ends in '/', remove it
    if ($VaultSSHClientSigningUrl[-1] -eq "/") {
        $VaultSSHClientSigningUrl = $VaultSSHClientSigningUrl.Substring(0,$VaultSSHClientSigningUrl.Length-1)
    }

    #endregion >> Prep

    #region >> Main

    # HTTP API Request
    # The below removes 'comment' text from the Host Public key because sometimes it can cause problems
    # with the below json
    $PubKeyContent = $($(Get-Content $PathToSSHUserPublicKeyFile) -split "[\s]")[0..1] -join " "
    $ValidPrincipalsCommaSeparated = $AuthorizedUserPrincipals -join ','
    # In the below JSON, <HostNameOrDomainPre> - Use the HostName if user is a Local Account and the DomainPre if the user
    # is a Domain Account
    <#
    $jsonRequest = @"
{
    "cert_type": "user",
    "valid_principals": "$ValidPrincipalsCommaSeparated",
    "extension": {
        "permit-pty": "",
        "permit-agent-forwarding": ""
    },
    "public_key": "$PubKeyContent"
}
"@
    #>

    $jsonRequest = @"
{
    "cert_type": "user",
    "valid_principals": "$ValidPrincipalsCommaSeparated",
    "extension": {
        "permit-pty": "",
        "permit-agent-forwarding": "",
        "permit-X11-forwarding": "",
        "permit-port-forwarding": "",
        "permit-user-rc": ""
    },
    "public_key": "$PubKeyContent"
}
"@

    $JsonRequestAsSingleLineString = $jsonRequest | ConvertFrom-Json | ConvertTo-Json -Compress

    $HeadersParameters = @{
        "X-Vault-Token" = $VaultAuthToken
    }
    $IWRSplatParams = @{
        Uri         = $VaultSSHClientSigningUrl
        Headers     = $HeadersParameters
        Body        = $JsonRequestAsSingleLineString
        Method      = "Post"
    }

    $SignedSSHClientPubKeyCertResponse = Invoke-WebRequest @IWRSplatParams
    Set-Content -Value $($SignedSSHClientPubKeyCertResponse.Content | ConvertFrom-Json).data.signed_key.Trim() -Path $SignedPubKeyCertFilePath

    if ($AddToSSHAgent) {
        $null = [scriptblock]::Create("ssh-add `"$CorrespondingPrivateKeyPath`"").InvokeReturnAsIs()
        if ($LASTEXITCODE -ne 0) {
            Write-Warning $Error[0].Exception.Message
        }

        if ($SSHAgentExpiry) {
            $null = [scriptblock]::Create("ssh-add -t $SSHAgentExpiry").InvokeReturnAsIs()
            if ($LASTEXITCODE -ne 0) {
                Write-Warning $Error[0].Exception.Message
            }
        }
        
        $AddedToSSHAgent = $True
    }

    $Output = @{
        SignedCertFile = $(Get-Item $SignedPubKeyCertFilePath)
    }
    if ($AddedToSSHAgent) {
        $Output.Add("AddedToSSHAgent",$True)
    }

    [pscustomobject]$Output

    #endregion >> Main
}


<#
    .SYNOPSIS
        This function is meant to determine the following:
            - Whether or not the specified file is, in fact, an SSH Private Key
            - If the SSH Private Key File is password protected
        
        In order to test if we have a valid Private Key, and if that Private Key
        is password protected, we try and generate a Public Key from it using ssh-keygen.
        Depending on the output of ssh-keygen, we can make a determination.

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER PathToPrivateKeyFile
        This parameter is MANDATORY.

        This parameter takes a string that represents a full path to the file that we believe is
        a valid SSH Private Key that we want to test.

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Validate-SSHPrivateKey -PathToPrivateKeyFile "$HOME\.ssh\random"
        
#>
function Validate-SSHPrivateKey {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$PathToPrivateKeyFile
    )

    if ($PSVersionTable.Platform -eq "Unix" -or $PSVersionTable.OS -match "Darwin" -and $env:SudoPwdPrompt) {
        if (GetElevation) {
            Write-Error "You should not be running the VaultServer Module as root! Halting!"
            $global:FunctionResult = "1"
            return
        }
        RemoveMySudoPwd
        NewCronToAddSudoPwd
        $env:SudoPwdPrompt = $False
    }

    # Make sure we have access to ssh binaries
    if (![bool]$(Get-Command ssh-keygen -ErrorAction SilentlyContinue)) {
        Write-Error "Unable to find 'ssh-keygen' binary! Halting!"
        $global:FunctionResult = "1"
        return
    }

    # Make sure the path exists
    if (!$(Test-Path $PathToPrivateKeyFile)) {
        Write-Error "Unable to find the path '$PathToPrivateKeyFile'! Halting!"
        $global:FunctionResult = "1"
        return
    }

    $SSHKeyGenParentDir = $(Get-Command ssh-keygen).Source | Split-Path -Parent
    $SSHKeyGenArguments = "-y -f `"$PathToPrivateKeyFile`""

    $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
    #$ProcessInfo.WorkingDirectory = $SSHKeyGenParentDir
    $ProcessInfo.FileName = $(Get-Command ssh-keygen).Source
    $ProcessInfo.RedirectStandardError = $true
    $ProcessInfo.RedirectStandardOutput = $true
    #$ProcessInfo.StandardOutputEncoding = [System.Text.Encoding]::Unicode
    #$ProcessInfo.StandardErrorEncoding = [System.Text.Encoding]::Unicode
    $ProcessInfo.UseShellExecute = $false
    $ProcessInfo.Arguments = $SSHKeyGenArguments
    $Process = New-Object System.Diagnostics.Process
    $Process.StartInfo = $ProcessInfo
    $Process.Start() | Out-Null
    # Below $FinishedInAlottedTime returns boolean true/false
    $FinishedInAlottedTime = $Process.WaitForExit(5000)
    if (!$FinishedInAlottedTime) {
        $Process.Kill()
        $ProcessKilled = $True
    }
    $stdout = $Process.StandardOutput.ReadToEnd()
    $stderr = $Process.StandardError.ReadToEnd()
    $SSHKeyGenOutput = $stdout + $stderr

    if ($SSHKeyGenOutput -match "invalid format") {
        $ValidSSHPrivateKeyFormat = $False
        $PasswordProtected = $False
    }
    if ($SSHKeyGenOutput -match "ssh-rsa AA") {
        $ValidSSHPrivateKeyFormat = $True
        $PasswordProtected = $False
    }
    if ($SSHKeyGenOutput -match "passphrase|pass phrase" -or $($SSHKeyGenOutput -eq $null -and $ProcessKilled)) {
        $ValidSSHPrivateKeyFormat = $True
        $PasswordProtected = $True
    }

    [pscustomobject]@{
        ValidSSHPrivateKeyFormat        = $ValidSSHPrivateKeyFormat
        PasswordProtected               = $PasswordProtected
    }
}



if ($PSVersionTable.Platform -eq "Win32NT" -and $PSVersionTable.PSEdition -eq "Core") {
    if (![bool]$(Get-Module -ListAvailable WindowsCompatibility)) {
        try {
            Install-Module WindowsCompatibility -ErrorAction Stop
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }
    }
    if (![bool]$(Get-Module WindowsCompatibility)) {
        try {
            Import-Module WindowsCompatibility -ErrorAction Stop
        }
        catch {
            Write-Error $_
            Write-Warning "The $ThisModule Module was NOT loaded successfully! Please run:`n    Remove-Module $ThisModule"
            $global:FunctionResult = "1"
            return
        }
    }
}

[System.Collections.ArrayList]$script:FunctionsForSBUse = @(
    ${Function:AddMySudoPwd}.Ast.Extent.Text
    ${Function:AddWinRMTrustedHost}.Ast.Extent.Text
    ${Function:AddWinRMTrustLocalHost}.Ast.Extent.Text
    ${Function:ConvertFromHCLToPrintF}.Ast.Extent.Text
    ${Function:GetComputerObjectsInLDAP}.Ast.Extent.Text
    ${Function:GetCurrentuser}.Ast.Extent.Text
    ${Function:GetDomainController}.Ast.Extent.Text
    ${Function:GetDomainName}.Ast.Extent.Text
    ${Function:GetElevation}.Ast.Extent.Text
    ${Function:GetGroupObjectsInLDAP}.Ast.Extent.Text
    ${Function:GetLinuxOctalPermissions}.Ast.Extent.Text
    ${Function:GetLocalGroupAndUsers}.Ast.Extent.Text
    ${Function:GetLocalUserAndGroups}.Ast.Extent.Text
    ${Function:GetModuleDependencies}.Ast.Extent.Text
    ${Function:GetMySudoStatus}.Ast.Extent.Text
    ${Function:GetUserObjectsInLDAP}.Ast.Extent.Text
    ${Function:InstallLinuxPackage}.Ast.Extent.Text
    ${Function:InvokeModuleDependencies}.Ast.Extent.Text
    ${Function:InvokePSCompatibility}.Ast.Extent.Text
    ${Function:ManualPSGalleryModuleInstall}.Ast.Extent.Text
    ${Function:NewCronToAddSudoPwd}.Ast.Extent.Text
    ${Function:NewUniqueString}.Ast.Extent.Text
    ${Function:RemoveMySudoPwd}.Ast.Extent.Text
    ${Function:ResolveHost}.Ast.Extent.Text
    ${Function:TestIsValidIPAddress}.Ast.Extent.Text
    ${Function:TestLDAP}.Ast.Extent.Text
    ${Function:TestPort}.Ast.Extent.Text
    ${Function:UnzipFile}.Ast.Extent.Text
    ${Function:Add-CAPubKeyToSSHAndSSHDConfig}.Ast.Extent.Text
    ${Function:Add-PublicKeyToRemoteHost}.Ast.Extent.Text
    ${Function:Configure-VaultServerForLDAPAuth}.Ast.Extent.Text
    ${Function:ConfigureVaultServerForSSHManagement}.Ast.Extent.Text
    ${Function:Get-LDAPCert}.Ast.Extent.Text
    ${Function:Get-SSHClientAuthSanity}.Ast.Extent.Text
    ${Function:Get-SSHFileInfo}.Ast.Extent.Text
    ${Function:Get-VaultAccessorLookup}.Ast.Extent.Text
    ${Function:Get-VaultLogin}.Ast.Extent.Text
    ${Function:Get-VaultTokenAccessors}.Ast.Extent.Text
    ${Function:Get-VaultTokens}.Ast.Extent.Text
    ${Function:Manage-StoredCredentials}.Ast.Extent.Text
    ${Function:New-SSHCredentials}.Ast.Extent.Text
    ${Function:New-SSHKey}.Ast.Extent.Text
    ${Function:Revoke-VaultToken}.Ast.Extent.Text
    ${Function:Sign-SSHHostPublicKey}.Ast.Extent.Text
    ${Function:Sign-SSHUserPublicKey}.Ast.Extent.Text
    ${Function:Validate-SSHPrivateKey}.Ast.Extent.Text
)

# Below $opensslkeysource from http://www.jensign.com/opensslkey/index.html
$script:opensslkeysource = @'

//**********************************************************************************
//
// OpenSSLKey
// .NET 2.0  OpenSSL Public & Private Key Parser
//
// Copyright (c) 2008  JavaScience Consulting,  Michel Gallant
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//***********************************************************************************
//
//  opensslkey.cs
//
//  Reads and parses:
//    (1) OpenSSL PEM or DER public keys
//    (2) OpenSSL PEM or DER traditional SSLeay private keys (encrypted and unencrypted)
//    (3) PKCS #8 PEM or DER encoded private keys (encrypted and unencrypted)
//  Keys in PEM format must have headers/footers .
//  Encrypted Private Key in SSLEay format not supported in DER
//  Removes header/footer lines.
//  For traditional SSLEAY PEM private keys, checks for encrypted format and
//  uses PBE to extract 3DES key.
//  For SSLEAY format, only supports encryption format: DES-EDE3-CBC
//  For PKCS #8, only supports PKCS#5 v2.0  3des.
//  Parses private and public key components and returns .NET RSA object.
//  Creates dummy unsigned certificate linked to private keypair and
//  optionally exports to pkcs #12
//
// See also: 
//  http://www.openssl.org/docs/crypto/pem.html#PEM_ENCRYPTION_FORMAT 
//**************************************************************************************

using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Runtime.InteropServices;
using System.Security;
using System.Diagnostics;
using System.ComponentModel;


namespace JavaScience {

    public class Win32 {
        [DllImport("crypt32.dll", SetLastError=true)]
            public static extern IntPtr CertCreateSelfSignCertificate(
                IntPtr hProv,
                ref CERT_NAME_BLOB pSubjectIssuerBlob,
                uint dwFlagsm,
                ref CRYPT_KEY_PROV_INFO pKeyProvInfo,
                IntPtr pSignatureAlgorithm,
                IntPtr pStartTime,
                IntPtr pEndTime,
                IntPtr other) ;
         [DllImport("crypt32.dll", SetLastError=true)]
            public static extern bool CertStrToName(
                uint dwCertEncodingType,
                String pszX500,
                uint dwStrType,
                IntPtr pvReserved,
                [In, Out] byte[] pbEncoded,
                ref uint pcbEncoded,
                IntPtr other);
         [DllImport("crypt32.dll", SetLastError=true)]
            public static extern bool CertFreeCertificateContext(
                IntPtr hCertStore);
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CRYPT_KEY_PROV_INFO {
        [MarshalAs(UnmanagedType.LPWStr)]  public String pwszContainerName;  
        [MarshalAs(UnmanagedType.LPWStr)]  public String pwszProvName;  
        public uint dwProvType;  
        public uint dwFlags;  
        public uint cProvParam;
        public IntPtr rgProvParam;
        public uint dwKeySpec;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CERT_NAME_BLOB {
        public int cbData;
        public IntPtr pbData;
    }

public class opensslkey {
    const  String pemprivheader = "-----BEGIN RSA PRIVATE KEY-----" ;
    const  String pemprivfooter   = "-----END RSA PRIVATE KEY-----" ;
    const  String pempubheader = "-----BEGIN PUBLIC KEY-----" ;
    const  String pempubfooter   = "-----END PUBLIC KEY-----" ;
    const  String pemp8header = "-----BEGIN PRIVATE KEY-----" ;
    const  String pemp8footer   = "-----END PRIVATE KEY-----" ;
    const  String pemp8encheader = "-----BEGIN ENCRYPTED PRIVATE KEY-----" ;
    const  String pemp8encfooter   = "-----END ENCRYPTED PRIVATE KEY-----" ;

    // static byte[] pempublickey;
    // static byte[] pemprivatekey;
    // static byte[] pkcs8privatekey;
    // static byte[] pkcs8encprivatekey;

    static bool verbose = false;

    public static void Main(String[] args) {
  
        if(args.Length == 1)
            if(args[0].ToUpper() == "V")
                verbose = true;

        Console.ForegroundColor = ConsoleColor.Gray;
        Console.Write("\nRSA public, private or PKCS #8  key file to decode: ");
        String filename = Console.ReadLine().Trim();
        if (filename == "")  //exit while(true) loop
            return;
        if (!File.Exists(filename)) {
            Console.WriteLine("File \"{0}\" does not exist!\n", filename);
            return; 
        }

        StreamReader sr = File.OpenText(filename);
        String pemstr = sr.ReadToEnd().Trim();
        sr.Close();
        if(pemstr.StartsWith("-----BEGIN"))
            DecodePEMKey(pemstr);
        else
            DecodeDERKey(filename);
    }

    // ------- Decode PEM pubic, private or pkcs8 key ----------------
    public static void DecodePEMKey(String pemstr) {
        byte[] pempublickey;
        byte[] pemprivatekey;
        byte[] pkcs8privatekey;
        byte[] pkcs8encprivatekey;

        if(pemstr.StartsWith(pempubheader) && pemstr.EndsWith(pempubfooter)) {
            Console.WriteLine("Trying to decode and parse a PEM public key ..");
            pempublickey = DecodeOpenSSLPublicKey(pemstr);
            if(pempublickey != null)
            {
                if(verbose)
                  showBytes("\nRSA public key", pempublickey) ;
                //PutFileBytes("rsapubkey.pem", pempublickey, pempublickey.Length) ;
                RSACryptoServiceProvider rsa =  DecodeX509PublicKey(pempublickey);
                Console.WriteLine("\nCreated an RSACryptoServiceProvider instance\n") ;
                String xmlpublickey =rsa.ToXmlString(false) ;
                Console.WriteLine("\nXML RSA public key:  {0} bits\n{1}\n", rsa.KeySize, xmlpublickey) ;
            }       
        }
        else if(pemstr.StartsWith(pemprivheader) && pemstr.EndsWith(pemprivfooter)) {
            Console.WriteLine("Trying to decrypt and parse a PEM private key ..");
            pemprivatekey = DecodeOpenSSLPrivateKey(pemstr);
            if(pemprivatekey != null)
            {
                if(verbose)
                  showBytes("\nRSA private key", pemprivatekey) ;
                //PutFileBytes("rsaprivkey.pem", pemprivatekey, pemprivatekey.Length) ;
                RSACryptoServiceProvider rsa =  DecodeRSAPrivateKey(pemprivatekey);
                Console.WriteLine("\nCreated an RSACryptoServiceProvider instance\n") ;
                String xmlprivatekey =rsa.ToXmlString(true) ;
                Console.WriteLine("\nXML RSA private key:  {0} bits\n{1}\n", rsa.KeySize, xmlprivatekey) ;
                ProcessRSA(rsa);
            }
        }
        else if(pemstr.StartsWith(pemp8header) && pemstr.EndsWith(pemp8footer)) {
            Console.WriteLine("Trying to decode and parse as PEM PKCS #8 PrivateKeyInfo ..");
            pkcs8privatekey = DecodePkcs8PrivateKey(pemstr);
            if(pkcs8privatekey != null)
            {
                if(verbose)
                  showBytes("\nPKCS #8 PrivateKeyInfo", pkcs8privatekey) ;
                //PutFileBytes("PrivateKeyInfo", pkcs8privatekey, pkcs8privatekey.Length) ;
                RSACryptoServiceProvider rsa =  DecodePrivateKeyInfo(pkcs8privatekey);
                if(rsa !=null) 
                {
                 Console.WriteLine("\nCreated an RSACryptoServiceProvider instance\n") ;
                 String xmlprivatekey =rsa.ToXmlString(true) ;
                 Console.WriteLine("\nXML RSA private key:  {0} bits\n{1}\n", rsa.KeySize, xmlprivatekey) ;
                 ProcessRSA(rsa) ; 
                }
                else
                Console.WriteLine("\nFailed to create an RSACryptoServiceProvider");
            }       
        }
        else if(pemstr.StartsWith(pemp8encheader) && pemstr.EndsWith(pemp8encfooter)) {
            Console.WriteLine("Trying to decode and parse as PEM PKCS #8 EncryptedPrivateKeyInfo ..");
            pkcs8encprivatekey = DecodePkcs8EncPrivateKey(pemstr);
            if(pkcs8encprivatekey != null) {
                if(verbose)
                  showBytes("\nPKCS #8 EncryptedPrivateKeyInfo", pkcs8encprivatekey) ;
                //PutFileBytes("EncryptedPrivateKeyInfo", pkcs8encprivatekey, pkcs8encprivatekey.Length) ;
                RSACryptoServiceProvider rsa =  DecodeEncryptedPrivateKeyInfo(pkcs8encprivatekey);
                if(rsa !=null) 
                {
                 Console.WriteLine("\nCreated an RSACryptoServiceProvider instance\n") ;
                 String xmlprivatekey =rsa.ToXmlString(true) ;
                 Console.WriteLine("\nXML RSA private key:  {0} bits\n{1}\n", rsa.KeySize, xmlprivatekey) ;
                  ProcessRSA(rsa) ;
                }
                else
                Console.WriteLine("\nFailed to create an RSACryptoServiceProvider");
            }       
        }
        else {
            Console.WriteLine("Not a PEM public, private key or a PKCS #8");
            return;
        }
    }

    // ------- Decode PEM pubic, private or pkcs8 key ----------------
    public static void DecodeDERKey(String filename) {
        RSACryptoServiceProvider rsa = null ;
        byte[] keyblob = GetFileBytes(filename);
        if(keyblob == null)
            return;

        rsa =  DecodeX509PublicKey(keyblob);
        if (rsa !=null) {
            Console.WriteLine("\nA valid SubjectPublicKeyInfo\n") ;
            Console.WriteLine("\nCreated an RSACryptoServiceProvider instance\n") ;
            String xmlpublickey =rsa.ToXmlString(false) ;
            Console.WriteLine("\nXML RSA public key:  {0} bits\n{1}\n", rsa.KeySize, xmlpublickey) ;
            return;
        }       

        rsa =  DecodeRSAPrivateKey(keyblob);
        if (rsa != null) {
            Console.WriteLine("\nA valid RSAPrivateKey\n") ;
            Console.WriteLine("\nCreated an RSACryptoServiceProvider instance\n") ;
            String xmlprivatekey =rsa.ToXmlString(true) ;
            Console.WriteLine("\nXML RSA private key:  {0} bits\n{1}\n", rsa.KeySize, xmlprivatekey) ;
            ProcessRSA(rsa) ;
            return;
        }

        rsa =  DecodePrivateKeyInfo(keyblob);   //PKCS #8 unencrypted
        if(rsa !=null) {
            Console.WriteLine("\nA valid PKCS #8 PrivateKeyInfo\n") ;
            Console.WriteLine("\nCreated an RSACryptoServiceProvider instance\n") ;
            String xmlprivatekey =rsa.ToXmlString(true) ;
            Console.WriteLine("\nXML RSA private key:  {0} bits\n{1}\n", rsa.KeySize, xmlprivatekey) ;
            ProcessRSA(rsa);
            return;
        }

        rsa =  DecodeEncryptedPrivateKeyInfo(keyblob);  //PKCS #8 encrypted
        if(rsa !=null) {
            Console.WriteLine("\nA valid PKCS #8 EncryptedPrivateKeyInfo\n") ;
            Console.WriteLine("\nCreated an RSACryptoServiceProvider instance\n") ;
            String xmlprivatekey =rsa.ToXmlString(true) ;
            Console.WriteLine("\nXML RSA private key:  {0} bits\n{1}\n", rsa.KeySize, xmlprivatekey) ;
            ProcessRSA(rsa);
            return;
        }
        Console.WriteLine("Not a binary DER public, private or PKCS #8 key");
        return;
    }

    public static void ProcessRSA(RSACryptoServiceProvider rsa) {
        if(verbose)
            showRSAProps(rsa);
        Console.Write("\n\nExport RSA private key to PKCS #12 file?  (Y or N) ");
        String resp = Console.ReadLine().ToUpper() ;
        if (resp == "Y"  || resp == "YES")
            RSAtoPKCS12(rsa) ;
    }

    //--------  Generate pkcs #12 from an RSACryptoServiceProvider  ---------
    public static void RSAtoPKCS12(RSACryptoServiceProvider rsa) {
        CspKeyContainerInfo keyInfo = rsa.CspKeyContainerInfo;
        String keycontainer = keyInfo.KeyContainerName;
        uint keyspec    = (uint) keyInfo.KeyNumber;
        String provider = keyInfo.ProviderName;
        uint cspflags = 0;  //CryptoAPI Current User store;   LM would be CRYPT_MACHINE_KEYSET  = 0x00000020
        String fname = keycontainer + ".p12" ;
        //---- need to pass in rsa since underlying keycontainer is not persisted and might be deleted too quickly ---
        byte[] pkcs12 = GetPkcs12(rsa, keycontainer, provider, keyspec , cspflags) ;
        if ( (pkcs12 !=null)  && verbose)
            showBytes("\npkcs #12", pkcs12);
        if(pkcs12 !=null){
            PutFileBytes(fname, pkcs12, pkcs12.Length) ;
            Console.WriteLine("\nWrote pkc #12 file '{0}'\n",  fname) ;
            }
        else
            Console.WriteLine("\nProblem getting pkcs#12") ;
    }

    //--------   Get the binary PKCS #8 PRIVATE key   --------
    public static byte[] DecodePkcs8PrivateKey(String instr) {
        const  String pemp8header = "-----BEGIN PRIVATE KEY-----" ;
        const  String pemp8footer   = "-----END PRIVATE KEY-----" ;
        String pemstr = instr.Trim() ;
        byte[] binkey;
        if(!pemstr.StartsWith(pemp8header) || !pemstr.EndsWith(pemp8footer))
            return null;
        StringBuilder sb = new StringBuilder(pemstr) ;
        sb.Replace(pemp8header, "") ;  //remove headers/footers, if present
        sb.Replace(pemp8footer, "") ;

        String pubstr = sb.ToString().Trim();   //get string after removing leading/trailing whitespace

        try {  
            binkey = Convert.FromBase64String(pubstr) ;
        } catch(System.FormatException) {       //if can't b64 decode, data is not valid
            return null;
        }
        return binkey;
     }

//------- Parses binary asn.1 PKCS #8 PrivateKeyInfo; returns RSACryptoServiceProvider ---
public static RSACryptoServiceProvider DecodePrivateKeyInfo(byte[] pkcs8)
 {
 // encoded OID sequence for  PKCS #1 rsaEncryption szOID_RSA_RSA = "1.2.840.113549.1.1.1"
 // this byte[] includes the sequence byte and terminal encoded null 
   byte[] SeqOID = {0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00} ;
   byte[] seq = new byte[15];
 // ---------  Set up stream to read the asn.1 encoded SubjectPublicKeyInfo blob  ------
  MemoryStream  mem = new MemoryStream(pkcs8) ;
  int lenstream = (int) mem.Length;
  BinaryReader binr = new BinaryReader(mem) ;    //wrap Memory Stream with BinaryReader for easy reading
  byte bt = 0;
  ushort twobytes = 0;

try{

twobytes = binr.ReadUInt16();
if(twobytes == 0x8130)  //data read as little endian order (actual data order for Sequence is 30 81)
    binr.ReadByte();    //advance 1 byte
else if(twobytes == 0x8230)
    binr.ReadInt16();   //advance 2 bytes
else
    return null;


bt = binr.ReadByte();
if(bt != 0x02)
    return null;

twobytes = binr.ReadUInt16();

if(twobytes != 0x0001)
    return null;

seq = binr.ReadBytes(15);       //read the Sequence OID
if(!CompareBytearrays(seq, SeqOID)) //make sure Sequence for OID is correct
    return null;

bt = binr.ReadByte();
if(bt != 0x04)  //expect an Octet string 
    return null;

bt = binr.ReadByte();       //read next byte, or next 2 bytes is  0x81 or 0x82; otherwise bt is the byte count
if(bt == 0x81)
    binr.ReadByte();
else
 if(bt == 0x82)
    binr.ReadUInt16();
//------ at this stage, the remaining sequence should be the RSA private key

  byte[] rsaprivkey = binr.ReadBytes((int)(lenstream -mem.Position)) ;
    RSACryptoServiceProvider rsacsp = DecodeRSAPrivateKey(rsaprivkey);
  return rsacsp;
}

 catch(Exception){
    return null; 
  }

 finally { binr.Close(); }

 }

//--------   Get the binary PKCS #8 Encrypted PRIVATE key   --------
public static byte[] DecodePkcs8EncPrivateKey(String instr) 
  {
 const  String pemp8encheader = "-----BEGIN ENCRYPTED PRIVATE KEY-----" ;
 const  String pemp8encfooter   = "-----END ENCRYPTED PRIVATE KEY-----" ;
  String pemstr = instr.Trim() ;
  byte[] binkey;
       if(!pemstr.StartsWith(pemp8encheader) || !pemstr.EndsWith(pemp8encfooter))
    return null;
       StringBuilder sb = new StringBuilder(pemstr) ;
       sb.Replace(pemp8encheader, "") ;  //remove headers/footers, if present
       sb.Replace(pemp8encfooter, "") ;

String pubstr = sb.ToString().Trim();   //get string after removing leading/trailing whitespace

   try{  
     binkey = Convert.FromBase64String(pubstr) ;
    }
   catch(System.FormatException) {      //if can't b64 decode, data is not valid
    return null;
    }
  return binkey;
 }


//------- Parses binary asn.1 EncryptedPrivateKeyInfo; returns RSACryptoServiceProvider ---
public static RSACryptoServiceProvider DecodeEncryptedPrivateKeyInfo(byte[] encpkcs8)
 {
 // encoded OID sequence for  PKCS #1 rsaEncryption szOID_RSA_RSA = "1.2.840.113549.1.1.1"
 // this byte[] includes the sequence byte and terminal encoded null 
   byte[] OIDpkcs5PBES2 = {0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05,  0x0D } ;
   byte[] OIDpkcs5PBKDF2  = {0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05,  0x0C } ;
   byte[] OIDdesEDE3CBC = {0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x03, 0x07} ;
   byte[] seqdes = new byte[10] ;
   byte[] seq = new byte[11];
   byte[] salt ;
   byte[] IV;
   byte[] encryptedpkcs8;
   byte[] pkcs8;

   int saltsize, ivsize, encblobsize;
   int iterations;

 // ---------  Set up stream to read the asn.1 encoded SubjectPublicKeyInfo blob  ------
  MemoryStream  mem = new MemoryStream(encpkcs8) ;
  int lenstream = (int) mem.Length;
  BinaryReader binr = new BinaryReader(mem) ;    //wrap Memory Stream with BinaryReader for easy reading
  byte bt = 0;
  ushort twobytes = 0;

try{

twobytes = binr.ReadUInt16();
if(twobytes == 0x8130)  //data read as little endian order (actual data order for Sequence is 30 81)
    binr.ReadByte();    //advance 1 byte
else if(twobytes == 0x8230)
    binr.ReadInt16();   //advance 2 bytes
else
    return null;

twobytes = binr.ReadUInt16();   //inner sequence
if(twobytes == 0x8130)
    binr.ReadByte();
else if(twobytes == 0x8230)
    binr.ReadInt16();


seq = binr.ReadBytes(11);       //read the Sequence OID
if(!CompareBytearrays(seq, OIDpkcs5PBES2))  //is it a OIDpkcs5PBES2 ?
    return null;

twobytes = binr.ReadUInt16();   //inner sequence for pswd salt
if(twobytes == 0x8130)
    binr.ReadByte();
else if(twobytes == 0x8230)
    binr.ReadInt16();

twobytes = binr.ReadUInt16();   //inner sequence for pswd salt
if(twobytes == 0x8130)
    binr.ReadByte();
else if(twobytes == 0x8230)
    binr.ReadInt16();

seq = binr.ReadBytes(11);       //read the Sequence OID
if(!CompareBytearrays(seq, OIDpkcs5PBKDF2)) //is it a OIDpkcs5PBKDF2 ?
    return null;

twobytes = binr.ReadUInt16();
if(twobytes == 0x8130)
    binr.ReadByte();
else if(twobytes == 0x8230)
    binr.ReadInt16();

bt = binr.ReadByte();
if(bt != 0x04)      //expect octet string for salt
    return null;
saltsize = binr.ReadByte();
salt = binr.ReadBytes(saltsize);

if(verbose)
    showBytes("Salt for pbkd", salt);
bt=binr.ReadByte();
if (bt != 0x02)     //expect an integer for PBKF2 interation count
    return null;

int itbytes = binr.ReadByte();  //PBKD2 iterations should fit in 2 bytes.
if(itbytes ==1)
    iterations = binr.ReadByte();
else if(itbytes == 2)
    iterations = 256*binr.ReadByte() + binr.ReadByte();
else
    return null;
if(verbose)
    Console.WriteLine("PBKD2 iterations {0}", iterations);

twobytes = binr.ReadUInt16();
if(twobytes == 0x8130)
    binr.ReadByte();
else if(twobytes == 0x8230)
    binr.ReadInt16();


seqdes = binr.ReadBytes(10);        //read the Sequence OID
if(!CompareBytearrays(seqdes, OIDdesEDE3CBC))   //is it a OIDdes-EDE3-CBC ?
    return null;

bt = binr.ReadByte();
if(bt != 0x04)      //expect octet string for IV
    return null;
ivsize = binr.ReadByte();   // IV byte size should fit in one byte (24 expected for 3DES)
IV= binr.ReadBytes(ivsize);
if(verbose)
    showBytes("IV for des-EDE3-CBC", IV);

bt=binr.ReadByte();
if(bt != 0x04)      // expect octet string for encrypted PKCS8 data
    return null;


bt = binr.ReadByte();

if(bt == 0x81)
    encblobsize = binr.ReadByte();  // data size in next byte
else if(bt == 0x82)
    encblobsize = 256*binr.ReadByte() + binr.ReadByte() ;
else
    encblobsize = bt;       // we already have the data size


encryptedpkcs8 = binr.ReadBytes(encblobsize) ;
//if(verbose)
//  showBytes("Encrypted PKCS8 blob", encryptedpkcs8) ;


SecureString secpswd = GetSecPswd("Enter password for Encrypted PKCS #8 ==>") ;
pkcs8 = DecryptPBDK2(encryptedpkcs8, salt, IV, secpswd, iterations) ;
if(pkcs8 == null)   // probably a bad pswd entered.
    return null;

//if(verbose)
//  showBytes("Decrypted PKCS #8", pkcs8) ;
 //----- With a decrypted pkcs #8 PrivateKeyInfo blob, decode it to an RSA ---
  RSACryptoServiceProvider rsa =  DecodePrivateKeyInfo(pkcs8) ;
  return rsa;
}

 catch(Exception){
    return null; 
  }

 finally { binr.Close(); }


 }

    //  ------  Uses PBKD2 to derive a 3DES key and decrypts data --------
    public static byte[] DecryptPBDK2(byte[] edata, byte[] salt, byte[]IV, SecureString secpswd, int iterations)
    {
        CryptoStream decrypt = null;

        IntPtr unmanagedPswd = IntPtr.Zero;
        byte[] psbytes = new byte[secpswd.Length] ;
        unmanagedPswd = Marshal.SecureStringToGlobalAllocAnsi(secpswd);
        Marshal.Copy(unmanagedPswd, psbytes, 0, psbytes.Length) ;
        Marshal.ZeroFreeGlobalAllocAnsi(unmanagedPswd);

      try
        {
        Rfc2898DeriveBytes kd = new Rfc2898DeriveBytes(psbytes, salt, iterations);
        TripleDES decAlg = TripleDES.Create();
        decAlg.Key = kd.GetBytes(24);
        decAlg.IV = IV;
        MemoryStream memstr = new MemoryStream();
        decrypt = new CryptoStream(memstr,decAlg.CreateDecryptor(), CryptoStreamMode.Write);
        decrypt.Write(edata, 0, edata.Length);
        decrypt.Flush();
        decrypt.Close() ;   // this is REQUIRED.
        byte[] cleartext = memstr.ToArray();
        return cleartext;
        }
       catch (Exception e)
        { 
         Console.WriteLine("Problem decrypting: {0}", e.Message) ;
         return null;
        }
    }

    //--------   Get the binary RSA PUBLIC key   --------
    public static byte[] DecodeOpenSSLPublicKey(String instr) {
        const  String pempubheader = "-----BEGIN PUBLIC KEY-----" ;
        const  String pempubfooter   = "-----END PUBLIC KEY-----" ;
        String pemstr = instr.Trim() ;
        byte[] binkey;
        if (!pemstr.StartsWith(pempubheader) || !pemstr.EndsWith(pempubfooter))
            return null;
        StringBuilder sb = new StringBuilder(pemstr) ;
        sb.Replace(pempubheader, "") ;  //remove headers/footers, if present
        sb.Replace(pempubfooter, "") ;

        String pubstr = sb.ToString().Trim();   //get string after removing leading/trailing whitespace

        try {
            binkey = Convert.FromBase64String(pubstr) ;
        }
        catch(System.FormatException) {     //if can't b64 decode, data is not valid
            return null;
        }
        return binkey;
    }

//------- Parses binary asn.1 X509 SubjectPublicKeyInfo; returns RSACryptoServiceProvider ---
public static RSACryptoServiceProvider DecodeX509PublicKey(byte[] x509key)
 {
 // encoded OID sequence for  PKCS #1 rsaEncryption szOID_RSA_RSA = "1.2.840.113549.1.1.1"
   byte[] SeqOID = {0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00} ;
   byte[] seq = new byte[15];
 // ---------  Set up stream to read the asn.1 encoded SubjectPublicKeyInfo blob  ------
  MemoryStream  mem = new MemoryStream(x509key) ;
  BinaryReader binr = new BinaryReader(mem) ;    //wrap Memory Stream with BinaryReader for easy reading
  byte bt = 0;
  ushort twobytes = 0;

try{

twobytes = binr.ReadUInt16();
if(twobytes == 0x8130)  //data read as little endian order (actual data order for Sequence is 30 81)
    binr.ReadByte();    //advance 1 byte
else if(twobytes == 0x8230)
    binr.ReadInt16();   //advance 2 bytes
else
    return null;

seq = binr.ReadBytes(15);       //read the Sequence OID
if(!CompareBytearrays(seq, SeqOID)) //make sure Sequence for OID is correct
    return null;

twobytes = binr.ReadUInt16();
if(twobytes == 0x8103)  //data read as little endian order (actual data order for Bit String is 03 81)
    binr.ReadByte();    //advance 1 byte
else if(twobytes == 0x8203)
    binr.ReadInt16();   //advance 2 bytes
else
    return null;

bt = binr.ReadByte();
if(bt != 0x00)      //expect null byte next
    return null;

twobytes = binr.ReadUInt16();
if(twobytes == 0x8130)  //data read as little endian order (actual data order for Sequence is 30 81)
    binr.ReadByte();    //advance 1 byte
else if(twobytes == 0x8230)
    binr.ReadInt16();   //advance 2 bytes
else
    return null;

twobytes = binr.ReadUInt16();
byte lowbyte = 0x00;
byte highbyte = 0x00;

if(twobytes == 0x8102)  //data read as little endian order (actual data order for Integer is 02 81)
    lowbyte = binr.ReadByte();  // read next bytes which is bytes in modulus
else if(twobytes == 0x8202) {
    highbyte = binr.ReadByte(); //advance 2 bytes
    lowbyte = binr.ReadByte();
    }
else
    return null;
 byte[] modint = {lowbyte, highbyte, 0x00, 0x00} ;   //reverse byte order since asn.1 key uses big endian order
 int modsize = BitConverter.ToInt32(modint, 0) ;

byte firstbyte = binr.ReadByte();
binr.BaseStream.Seek(-1, SeekOrigin.Current);

 if(firstbyte == 0x00)  {   //if first byte (highest order) of modulus is zero, don't include it
    binr.ReadByte();    //skip this null byte
    modsize -=1  ;  //reduce modulus buffer size by 1
    }

  byte[] modulus = binr.ReadBytes(modsize); //read the modulus bytes

  if(binr.ReadByte() != 0x02)           //expect an Integer for the exponent data
    return null;
  int expbytes = (int) binr.ReadByte() ;        // should only need one byte for actual exponent data (for all useful values)
  byte[] exponent = binr.ReadBytes(expbytes);


  showBytes("\nExponent", exponent);
  showBytes("\nModulus", modulus) ;    

 // ------- create RSACryptoServiceProvider instance and initialize with public key -----
  RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
  RSAParameters RSAKeyInfo = new RSAParameters();
  RSAKeyInfo.Modulus = modulus;
  RSAKeyInfo.Exponent = exponent;
  RSA.ImportParameters(RSAKeyInfo);
  return RSA;
 }
 catch(Exception){
    return null; 
  }

 finally { binr.Close(); }

}

    //------- Parses binary ans.1 RSA private key; returns RSACryptoServiceProvider  ---
    public static RSACryptoServiceProvider DecodeRSAPrivateKey(byte[] privkey) {
        byte[] MODULUS, E, D, P, Q, DP, DQ, IQ ;

        // ---------  Set up stream to decode the asn.1 encoded RSA private key  ------
        MemoryStream  mem = new MemoryStream(privkey) ;
        BinaryReader binr = new BinaryReader(mem) ;    //wrap Memory Stream with BinaryReader for easy reading
        byte bt = 0;
        ushort twobytes = 0;
        int elems = 0;
        try {
            twobytes = binr.ReadUInt16();
            if(twobytes == 0x8130)  //data read as little endian order (actual data order for Sequence is 30 81)
                binr.ReadByte();    //advance 1 byte
            else if(twobytes == 0x8230)
                binr.ReadInt16();   //advance 2 bytes
            else
                return null;

            twobytes = binr.ReadUInt16();
            if(twobytes != 0x0102)  //version number
                return null;
            bt = binr.ReadByte();
            if(bt !=0x00)
                return null;

            //------  all private key components are Integer sequences ----
            elems = GetIntegerSize(binr);
            MODULUS = binr.ReadBytes(elems);

            elems = GetIntegerSize(binr);
            E = binr.ReadBytes(elems) ;

            elems = GetIntegerSize(binr);
            D = binr.ReadBytes(elems) ;

            elems = GetIntegerSize(binr);
            P = binr.ReadBytes(elems) ;

            elems = GetIntegerSize(binr);
            Q = binr.ReadBytes(elems) ;

            elems = GetIntegerSize(binr);
            DP = binr.ReadBytes(elems) ;

            elems = GetIntegerSize(binr);
            DQ = binr.ReadBytes(elems) ;

            elems = GetIntegerSize(binr);
            IQ = binr.ReadBytes(elems) ;

            if(verbose) {
                showBytes("\nModulus", MODULUS) ;    
                showBytes("\nExponent", E);
                showBytes("\nD", D);
                showBytes("\nP", P);
                showBytes("\nQ", Q);
                showBytes("\nDP", DP);
                showBytes("\nDQ", DQ);
                showBytes("\nIQ", IQ);
            }

            // ------- create RSACryptoServiceProvider instance and initialize with public key -----
            RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
            RSAParameters RSAparams = new RSAParameters();
            RSAparams.Modulus =MODULUS;
            RSAparams.Exponent = E;
            RSAparams.D = D;
            RSAparams.P = P;
            RSAparams.Q = Q;
            RSAparams.DP = DP;
            RSAparams.DQ = DQ;
            RSAparams.InverseQ = IQ;
            RSA.ImportParameters(RSAparams);
            return RSA;
        } catch(Exception){
            return null; 
        } finally { 
            binr.Close(); 
        }
    }

private static int GetIntegerSize(BinaryReader binr) {
  byte bt = 0;
  byte lowbyte = 0x00;
  byte highbyte = 0x00;
  int count = 0;
 bt = binr.ReadByte();
if(bt != 0x02)      //expect integer
    return 0;
bt = binr.ReadByte();

if(bt == 0x81)
    count = binr.ReadByte();    // data size in next byte
else
if(bt == 0x82) {
    highbyte = binr.ReadByte(); // data size in next 2 bytes
    lowbyte = binr.ReadByte();
    byte[] modint = {lowbyte, highbyte, 0x00, 0x00} ;
    count = BitConverter.ToInt32(modint, 0) ;
    }
else {
    count = bt;     // we already have the data size
}



 while(binr.ReadByte() == 0x00) {   //remove high order zeros in data
    count -=1;
    }
 binr.BaseStream.Seek(-1, SeekOrigin.Current);      //last ReadByte wasn't a removed zero, so back up a byte
 return count;
}




//-----  Get the binary RSA PRIVATE key, decrypting if necessary ----
public static byte[] DecodeOpenSSLPrivateKey(String instr) 
  {
  const  String pemprivheader = "-----BEGIN RSA PRIVATE KEY-----" ;
  const  String pemprivfooter   = "-----END RSA PRIVATE KEY-----" ;
  String pemstr = instr.Trim() ;
  byte[] binkey;
       if(!pemstr.StartsWith(pemprivheader) || !pemstr.EndsWith(pemprivfooter))
    return null;

       StringBuilder sb = new StringBuilder(pemstr) ;
        sb.Replace(pemprivheader, "") ;  //remove headers/footers, if present
        sb.Replace(pemprivfooter, "") ;

String pvkstr = sb.ToString().Trim();   //get string after removing leading/trailing whitespace

   try{        // if there are no PEM encryption info lines, this is an UNencrypted PEM private key
    binkey = Convert.FromBase64String(pvkstr) ;
    return binkey;
    }
   catch(System.FormatException) {      //if can't b64 decode, it must be an encrypted private key
    //Console.WriteLine("Not an unencrypted OpenSSL PEM private key");  
    }

 StringReader str = new StringReader(pvkstr);

//-------- read PEM encryption info. lines and extract salt -----
 if(!str.ReadLine().StartsWith("Proc-Type: 4,ENCRYPTED")) 
    return null;
 String saltline = str.ReadLine();
 if(!saltline.StartsWith("DEK-Info: DES-EDE3-CBC,") )
    return null;
 String saltstr =  saltline.Substring(saltline.IndexOf(",") + 1).Trim() ;
 byte[] salt = new byte[saltstr.Length/2]; 
 for (int i=0; i <salt.Length; i++)  
    salt[i] = Convert.ToByte(saltstr.Substring (i*2, 2), 16); 
 if(! (str.ReadLine() == ""))
    return null;

//------ remaining b64 data is encrypted RSA key ----
String encryptedstr =  str.ReadToEnd() ;

 try{   //should have b64 encrypted RSA key now
    binkey = Convert.FromBase64String(encryptedstr) ;
 }
   catch(System.FormatException) {  // bad b64 data.
    return null;
    }

//------ Get the 3DES 24 byte key using PDK used by OpenSSL ----

    SecureString  despswd = GetSecPswd("Enter password to derive 3DES key==>") ;
   //Console.Write("\nEnter password to derive 3DES key: ");
   //String pswd = Console.ReadLine();
  byte[] deskey = GetOpenSSL3deskey(salt, despswd, 1, 2);    // count=1 (for OpenSSL implementation); 2 iterations to get at least 24 bytes
  if(deskey == null)
    return null;
  //showBytes("3DES key", deskey) ;

//------ Decrypt the encrypted 3des-encrypted RSA private key ------
 byte[] rsakey = DecryptKey(binkey, deskey, salt);  //OpenSSL uses salt value in PEM header also as 3DES IV
if(rsakey !=null) 
    return rsakey;  //we have a decrypted RSA private key
else {
    Console.WriteLine("Failed to decrypt RSA private key; probably wrong password.");
    return null;
   }
 }


    // ----- Decrypt the 3DES encrypted RSA private key ----------
    public static byte[] DecryptKey(byte[] cipherData, byte[] desKey, byte[] IV) {
        MemoryStream memst = new MemoryStream(); 
        TripleDES alg = TripleDES.Create(); 
        alg.Key = desKey; 
        alg.IV = IV; 
        try {
            CryptoStream cs = new CryptoStream(memst, alg.CreateDecryptor(), CryptoStreamMode.Write); 
            cs.Write(cipherData, 0, cipherData.Length); 
            cs.Close(); 
        } catch(Exception exc) {
            Console.WriteLine(exc.Message); 
            return null;
        }
        byte[] decryptedData = memst.ToArray(); 
        return decryptedData; 
    }

//-----   OpenSSL PBKD uses only one hash cycle (count); miter is number of iterations required to build sufficient bytes ---
 private static byte[] GetOpenSSL3deskey(byte[] salt, SecureString secpswd, int count, int miter )  {
    IntPtr unmanagedPswd = IntPtr.Zero;
    int HASHLENGTH = 16;    //MD5 bytes
    byte[] keymaterial = new byte[HASHLENGTH*miter] ;     //to store contatenated Mi hashed results


    byte[] psbytes = new byte[secpswd.Length] ;
    unmanagedPswd = Marshal.SecureStringToGlobalAllocAnsi(secpswd);
    Marshal.Copy(unmanagedPswd, psbytes, 0, psbytes.Length) ;
    Marshal.ZeroFreeGlobalAllocAnsi(unmanagedPswd);

    //UTF8Encoding utf8 = new UTF8Encoding();
    //byte[] psbytes = utf8.GetBytes(pswd);

    // --- contatenate salt and pswd bytes into fixed data array ---
    byte[] data00 = new byte[psbytes.Length + salt.Length] ;
    Array.Copy(psbytes, data00, psbytes.Length);        //copy the pswd bytes
    Array.Copy(salt, 0, data00, psbytes.Length, salt.Length) ;  //concatenate the salt bytes

    // ---- do multi-hashing and contatenate results  D1, D2 ...  into keymaterial bytes ----
    MD5 md5 = new MD5CryptoServiceProvider();
    byte[] result = null;
    byte[] hashtarget = new byte[HASHLENGTH + data00.Length];   //fixed length initial hashtarget

    for(int j=0; j<miter; j++)
    {
    // ----  Now hash consecutively for count times ------
    if(j == 0)
        result = data00;    //initialize 
    else {
        Array.Copy(result, hashtarget, result.Length);
        Array.Copy(data00, 0, hashtarget, result.Length, data00.Length) ;
        result = hashtarget;
            //Console.WriteLine("Updated new initial hash target:") ;
            //showBytes(result) ;
    }

    for(int i=0; i<count; i++)
        result = md5.ComputeHash(result);
     Array.Copy(result, 0, keymaterial, j*HASHLENGTH, result.Length);  //contatenate to keymaterial
    }
    //showBytes("Final key material", keymaterial);
    byte[] deskey = new byte[24];
   Array.Copy(keymaterial, deskey, deskey.Length) ;

   Array.Clear(psbytes, 0,  psbytes.Length);
   Array.Clear(data00, 0, data00.Length) ;
   Array.Clear(result, 0, result.Length) ;
   Array.Clear(hashtarget, 0, hashtarget.Length) ;
   Array.Clear(keymaterial, 0, keymaterial.Length) ;

   return deskey; 
 }






//------   Since we are using an RSA with nonpersisted keycontainer, must pass it in to ensure it isn't colledted  -----
private static byte[] GetPkcs12(RSA rsa, String keycontainer, String cspprovider, uint KEYSPEC, uint cspflags)
 {
  byte[] pfxblob    = null;
  IntPtr hCertCntxt = IntPtr.Zero;

  String DN = "CN=Opensslkey Unsigned Certificate";

    hCertCntxt =  CreateUnsignedCertCntxt(keycontainer, cspprovider, KEYSPEC, cspflags, DN) ;
    if(hCertCntxt == IntPtr.Zero){
        Console.WriteLine("Couldn't create an unsigned-cert\n") ;
        return null;
    }
 try{
    X509Certificate cert = new X509Certificate(hCertCntxt) ;    //create certificate object from cert context.
    //X509Certificate2UI.DisplayCertificate(new X509Certificate2(cert)) ;   // display it, showing linked private key
    SecureString pswd = GetSecPswd("Set PFX Password ==>") ;
    pfxblob = cert.Export(X509ContentType.Pkcs12, pswd);
  }

 catch(Exception exc) 
 { 
    Console.WriteLine( "BAD RESULT" + exc.Message);
    pfxblob = null;
 }
    
rsa.Clear() ;
if(hCertCntxt != IntPtr.Zero)
    Win32.CertFreeCertificateContext(hCertCntxt) ;
  return pfxblob;
}




private static IntPtr CreateUnsignedCertCntxt(String keycontainer, String provider, uint KEYSPEC, uint cspflags, String DN) {
 const uint AT_KEYEXCHANGE  = 0x00000001;
 const uint AT_SIGNATURE        = 0x00000002;
 const uint CRYPT_MACHINE_KEYSET    = 0x00000020;
 const uint PROV_RSA_FULL       = 0x00000001;
 const String MS_DEF_PROV       = "Microsoft Base Cryptographic Provider v1.0";
 const String MS_STRONG_PROV    =  "Microsoft Strong Cryptographic Provider";
 const String MS_ENHANCED_PROV  = "Microsoft Enhanced Cryptographic Provider v1.0";
 const uint CERT_CREATE_SELFSIGN_NO_SIGN        = 1 ;
 const uint X509_ASN_ENCODING   = 0x00000001;
 const uint CERT_X500_NAME_STR  = 3;
 IntPtr hCertCntxt = IntPtr.Zero;
 byte[] encodedName = null;
 uint cbName = 0;

 if( provider != MS_DEF_PROV && provider != MS_STRONG_PROV && provider != MS_ENHANCED_PROV)
    return IntPtr.Zero;
 if(keycontainer == "")
    return IntPtr.Zero;
 if( KEYSPEC != AT_SIGNATURE &&  KEYSPEC != AT_KEYEXCHANGE)
    return IntPtr.Zero;
 if(cspflags != 0 && cspflags != CRYPT_MACHINE_KEYSET)   //only 0 (Current User) keyset is currently used.
    return IntPtr.Zero;
if (DN == "")
    return IntPtr.Zero;


if(Win32.CertStrToName(X509_ASN_ENCODING, DN, CERT_X500_NAME_STR, IntPtr.Zero, null, ref cbName, IntPtr.Zero))
 {
    encodedName = new byte[cbName] ;
    Win32.CertStrToName(X509_ASN_ENCODING, DN, CERT_X500_NAME_STR, IntPtr.Zero, encodedName, ref cbName, IntPtr.Zero);
 }

  CERT_NAME_BLOB subjectblob = new CERT_NAME_BLOB();
  subjectblob.pbData = Marshal.AllocHGlobal(encodedName.Length);
  Marshal.Copy(encodedName, 0, subjectblob.pbData, encodedName.Length);
  subjectblob.cbData = encodedName.Length;

  CRYPT_KEY_PROV_INFO pInfo = new CRYPT_KEY_PROV_INFO();
  pInfo.pwszContainerName = keycontainer;
  pInfo.pwszProvName = provider;
  pInfo.dwProvType = PROV_RSA_FULL;
  pInfo.dwFlags = cspflags;
  pInfo.cProvParam = 0;
  pInfo.rgProvParam = IntPtr.Zero;
  pInfo.dwKeySpec = KEYSPEC;

 hCertCntxt = Win32.CertCreateSelfSignCertificate(IntPtr.Zero, ref subjectblob, CERT_CREATE_SELFSIGN_NO_SIGN, ref pInfo, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
 if(hCertCntxt == IntPtr.Zero)
     showWin32Error(Marshal.GetLastWin32Error());
 Marshal.FreeHGlobal(subjectblob.pbData);
 return hCertCntxt ;
}




 private static SecureString GetSecPswd(String prompt)
  {
        SecureString password = new SecureString();

        Console.ForegroundColor = ConsoleColor.Gray;
        Console.Write(prompt);
        Console.ForegroundColor = ConsoleColor.Magenta;

        while (true)
            {
            ConsoleKeyInfo cki = Console.ReadKey(true);
                if (cki.Key == ConsoleKey.Enter)
                {
                    Console.ForegroundColor = ConsoleColor.Gray;
                    Console.WriteLine();
                    return password;
                }
                else if (cki.Key == ConsoleKey.Backspace)
                {
                    // remove the last asterisk from the screen...
                    if (password.Length > 0)
                    {
                        Console.SetCursorPosition(Console.CursorLeft - 1, Console.CursorTop);
                        Console.Write(" ");
                        Console.SetCursorPosition(Console.CursorLeft - 1, Console.CursorTop);
                        password.RemoveAt(password.Length - 1);
                    }
                }
                else if (cki.Key == ConsoleKey.Escape)
                {
                    Console.ForegroundColor = ConsoleColor.Gray;
                    Console.WriteLine();
                    return password;
                }
                else if (Char.IsLetterOrDigit(cki.KeyChar) || Char.IsSymbol(cki.KeyChar))
                {
                    if (password.Length < 20)
                    {
                        password.AppendChar(cki.KeyChar);
                        Console.Write("*");
                    }
                    else
                    {
                        Console.Beep();
                    }
                } 
                else
                {
                    Console.Beep();
                }
            }
  }

    private static bool CompareBytearrays(byte [] a, byte[] b) {
        if(a.Length != b.Length)
            return false;
        int i =0;
        foreach(byte c in a) {
            if(c != b[i] ) 
                return false;
            i++;
        }
        return true;
     } 

    private static void showRSAProps(RSACryptoServiceProvider rsa) {
        Console.WriteLine("RSA CSP key information:");
        CspKeyContainerInfo keyInfo = rsa.CspKeyContainerInfo;
        Console.WriteLine("Accessible property: " + keyInfo.Accessible);
        Console.WriteLine("Exportable property: " + keyInfo.Exportable);
        Console.WriteLine("HardwareDevice property: " + keyInfo.HardwareDevice);
        Console.WriteLine("KeyContainerName property: " + keyInfo.KeyContainerName);
        Console.WriteLine("KeyNumber property: " + keyInfo.KeyNumber.ToString());
        Console.WriteLine("MachineKeyStore property: " + keyInfo.MachineKeyStore);
        Console.WriteLine("Protected property: " + keyInfo.Protected);
        Console.WriteLine("ProviderName property: " + keyInfo.ProviderName);
        Console.WriteLine("ProviderType property: " + keyInfo.ProviderType);
        Console.WriteLine("RandomlyGenerated property: " + keyInfo.RandomlyGenerated);
        Console.WriteLine("Removable property: " + keyInfo.Removable);
        Console.WriteLine("UniqueKeyContainerName property: " + keyInfo.UniqueKeyContainerName);
    }

    private static void showBytes(String info, byte[] data){
        Console.WriteLine("{0}  [{1} bytes]", info, data.Length);
        for(int i=1; i<=data.Length; i++){  
            Console.Write("{0:X2}  ", data[i-1]) ;
            if(i%16 == 0)
                Console.WriteLine();
        }
        Console.WriteLine("\n\n");
    }


    private static byte[] GetFileBytes(String filename) {
        if(!File.Exists(filename))
            return null;
        Stream stream=new FileStream(filename,FileMode.Open);
        int datalen = (int)stream.Length;
        byte[] filebytes =new byte[datalen];
        stream.Seek(0,SeekOrigin.Begin);
        stream.Read(filebytes,0,datalen);
        stream.Close();
        return filebytes;
    }

    private static void PutFileBytes(String outfile, byte[] data, int bytes) {
        FileStream fs = null;
        if(bytes > data.Length) {
            Console.WriteLine("Too many bytes");
            return;
        }
        try {
            fs = new FileStream(outfile, FileMode.Create);
            fs.Write(data, 0, bytes);
        } catch(Exception e) {
            Console.WriteLine(e.Message) ; 
        }
        finally {
            fs.Close();
        }
    }

    private static void showWin32Error(int errorcode) {
        Win32Exception myEx=new Win32Exception(errorcode);
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine("Error code:\t 0x{0:X}", myEx.ErrorCode);
        Console.WriteLine("Error message:\t {0}\n", myEx.Message);
        Console.ForegroundColor = ConsoleColor.Gray;
    }


    }
}

'@

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUQqK0SkBiFTVF4BL4I6ukZxyB
# EYWgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
# 9w0BAQsFADAwMQwwCgYDVQQGEwNMQUIxDTALBgNVBAoTBFpFUk8xETAPBgNVBAMT
# CFplcm9EQzAxMB4XDTE3MDkyMDIxMDM1OFoXDTE5MDkyMDIxMTM1OFowPTETMBEG
# CgmSJomT8ixkARkWA0xBQjEUMBIGCgmSJomT8ixkARkWBFpFUk8xEDAOBgNVBAMT
# B1plcm9TQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDCwqv+ROc1
# bpJmKx+8rPUUfT3kPSUYeDxY8GXU2RrWcL5TSZ6AVJsvNpj+7d94OEmPZate7h4d
# gJnhCSyh2/3v0BHBdgPzLcveLpxPiSWpTnqSWlLUW2NMFRRojZRscdA+e+9QotOB
# aZmnLDrlePQe5W7S1CxbVu+W0H5/ukte5h6gsKa0ktNJ6X9nOPiGBMn1LcZV/Ksl
# lUyuTc7KKYydYjbSSv2rQ4qmZCQHqxyNWVub1IiEP7ClqCYqeCdsTtfw4Y3WKxDI
# JaPmWzlHNs0nkEjvnAJhsRdLFbvY5C2KJIenxR0gA79U8Xd6+cZanrBUNbUC8GCN
# wYkYp4A4Jx+9AgMBAAGjggEqMIIBJjASBgkrBgEEAYI3FQEEBQIDAQABMCMGCSsG
# AQQBgjcVAgQWBBQ/0jsn2LS8aZiDw0omqt9+KWpj3DAdBgNVHQ4EFgQUicLX4r2C
# Kn0Zf5NYut8n7bkyhf4wGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwDgYDVR0P
# AQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUdpW6phL2RQNF
# 7AZBgQV4tgr7OE0wMQYDVR0fBCowKDAmoCSgIoYgaHR0cDovL3BraS9jZXJ0ZGF0
# YS9aZXJvREMwMS5jcmwwPAYIKwYBBQUHAQEEMDAuMCwGCCsGAQUFBzAChiBodHRw
# Oi8vcGtpL2NlcnRkYXRhL1plcm9EQzAxLmNydDANBgkqhkiG9w0BAQsFAAOCAQEA
# tyX7aHk8vUM2WTQKINtrHKJJi29HaxhPaHrNZ0c32H70YZoFFaryM0GMowEaDbj0
# a3ShBuQWfW7bD7Z4DmNc5Q6cp7JeDKSZHwe5JWFGrl7DlSFSab/+a0GQgtG05dXW
# YVQsrwgfTDRXkmpLQxvSxAbxKiGrnuS+kaYmzRVDYWSZHwHFNgxeZ/La9/8FdCir
# MXdJEAGzG+9TwO9JvJSyoGTzu7n93IQp6QteRlaYVemd5/fYqBhtskk1zDiv9edk
# mHHpRWf9Xo94ZPEy7BqmDuixm4LdmmzIcFWqGGMo51hvzz0EaE8K5HuNvNaUB/hq
# MTOIB5145K8bFOoKHO4LkTCCBc8wggS3oAMCAQICE1gAAAH5oOvjAv3166MAAQAA
# AfkwDQYJKoZIhvcNAQELBQAwPTETMBEGCgmSJomT8ixkARkWA0xBQjEUMBIGCgmS
# JomT8ixkARkWBFpFUk8xEDAOBgNVBAMTB1plcm9TQ0EwHhcNMTcwOTIwMjE0MTIy
# WhcNMTkwOTIwMjExMzU4WjBpMQswCQYDVQQGEwJVUzELMAkGA1UECBMCUEExFTAT
# BgNVBAcTDFBoaWxhZGVscGhpYTEVMBMGA1UEChMMRGlNYWdnaW8gSW5jMQswCQYD
# VQQLEwJJVDESMBAGA1UEAxMJWmVyb0NvZGUyMIIBIjANBgkqhkiG9w0BAQEFAAOC
# AQ8AMIIBCgKCAQEAxX0+4yas6xfiaNVVVZJB2aRK+gS3iEMLx8wMF3kLJYLJyR+l
# rcGF/x3gMxcvkKJQouLuChjh2+i7Ra1aO37ch3X3KDMZIoWrSzbbvqdBlwax7Gsm
# BdLH9HZimSMCVgux0IfkClvnOlrc7Wpv1jqgvseRku5YKnNm1JD+91JDp/hBWRxR
# 3Qg2OR667FJd1Q/5FWwAdrzoQbFUuvAyeVl7TNW0n1XUHRgq9+ZYawb+fxl1ruTj
# 3MoktaLVzFKWqeHPKvgUTTnXvEbLh9RzX1eApZfTJmnUjBcl1tCQbSzLYkfJlJO6
# eRUHZwojUK+TkidfklU2SpgvyJm2DhCtssFWiQIDAQABo4ICmjCCApYwDgYDVR0P
# AQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBS5d2bhatXq
# eUDFo9KltQWHthbPKzAfBgNVHSMEGDAWgBSJwtfivYIqfRl/k1i63yftuTKF/jCB
# 6QYDVR0fBIHhMIHeMIHboIHYoIHVhoGubGRhcDovLy9DTj1aZXJvU0NBKDEpLENO
# PVplcm9TQ0EsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNl
# cnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9emVybyxEQz1sYWI/Y2VydGlmaWNh
# dGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlv
# blBvaW50hiJodHRwOi8vcGtpL2NlcnRkYXRhL1plcm9TQ0EoMSkuY3JsMIHmBggr
# BgEFBQcBAQSB2TCB1jCBowYIKwYBBQUHMAKGgZZsZGFwOi8vL0NOPVplcm9TQ0Es
# Q049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENO
# PUNvbmZpZ3VyYXRpb24sREM9emVybyxEQz1sYWI/Y0FDZXJ0aWZpY2F0ZT9iYXNl
# P29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRob3JpdHkwLgYIKwYBBQUHMAKG
# Imh0dHA6Ly9wa2kvY2VydGRhdGEvWmVyb1NDQSgxKS5jcnQwPQYJKwYBBAGCNxUH
# BDAwLgYmKwYBBAGCNxUIg7j0P4Sb8nmD8Y84g7C3MobRzXiBJ6HzzB+P2VUCAWQC
# AQUwGwYJKwYBBAGCNxUKBA4wDDAKBggrBgEFBQcDAzANBgkqhkiG9w0BAQsFAAOC
# AQEAszRRF+YTPhd9UbkJZy/pZQIqTjpXLpbhxWzs1ECTwtIbJPiI4dhAVAjrzkGj
# DyXYWmpnNsyk19qE82AX75G9FLESfHbtesUXnrhbnsov4/D/qmXk/1KD9CE0lQHF
# Lu2DvOsdf2mp2pjdeBgKMRuy4cZ0VCc/myO7uy7dq0CvVdXRsQC6Fqtr7yob9NbE
# OdUYDBAGrt5ZAkw5YeL8H9E3JLGXtE7ir3ksT6Ki1mont2epJfHkO5JkmOI6XVtg
# anuOGbo62885BOiXLu5+H2Fg+8ueTP40zFhfLh3e3Kj6Lm/NdovqqTBAsk04tFW9
# Hp4gWfVc0gTDwok3rHOrfIY35TGCAfUwggHxAgEBMFQwPTETMBEGCgmSJomT8ixk
# ARkWA0xBQjEUMBIGCgmSJomT8ixkARkWBFpFUk8xEDAOBgNVBAMTB1plcm9TQ0EC
# E1gAAAH5oOvjAv3166MAAQAAAfkwCQYFKw4DAhoFAKB4MBgGCisGAQQBgjcCAQwx
# CjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGC
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFCh/Qu53VJTf+IR1
# PH+hErpZLSpZMA0GCSqGSIb3DQEBAQUABIIBAAGyjsOm5O6rzstXGu2OZm+s6sAd
# JDypkZrx9YV/xnaiZU+pz4JrVTs/b6DenJq7jJUVRXKJiPemTHAdvYrGw6K+my7N
# XDIO+M5wgNclN42GZafzSgr+ewhuEzyqf2E/l504GAPVSZRaei3GPl29THy52ste
# 9gQoJ2lAilOIJKOpPNNOFF6oVK16NnP5KlNnNExBgaL8xejTaoFAgPmqep4V2Mme
# Odfb6KPPJG5aOfoiNXbwHecLOWmNqRYSeAHjOi6YEHEr7DRnZp6A6k0ICZq9gPAU
# e5YeV7quPfnuYnkBquvwTQVMgAkYPbpd4lRlrwtn4X6GOxlfDb/DQ7TQNAo=
# SIG # End signature block
