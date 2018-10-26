function Get-GroupObjectsInLDAP {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [int]$ObjectCount = 0,

        [Parameter(Mandatory=$False)]
        [string]$Domain,

        [Parameter(Mandatory=$False)]
        [pscredential]$LDAPCreds
    )

    #region >> Helper Functions

    function Test-IsValidIPAddress([string]$IPAddress) {
        [boolean]$Octets = (($IPAddress.Split(".") | Measure-Object).Count -eq 4) 
        [boolean]$Valid  =  ($IPAddress -as [ipaddress]) -as [boolean]
        Return  ($Valid -and $Octets)
    }

    function Get-Elevation {
        if ($PSVersionTable.PSEdition -eq "Desktop" -or $PSVersionTable.Platform -eq "Win32NT" -or $PSVersionTable.PSVersion.Major -le 5) {
            [System.Security.Principal.WindowsPrincipal]$currentPrincipal = New-Object System.Security.Principal.WindowsPrincipal(
                [System.Security.Principal.WindowsIdentity]::GetCurrent()
            )
    
            [System.Security.Principal.WindowsBuiltInRole]$administratorsRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator
    
            if($currentPrincipal.IsInRole($administratorsRole)) {
                return $true
            }
            else {
                return $false
            }
        }
        
        if ($PSVersionTable.Platform -eq "Unix") {
            if ($(whoami) -eq "root") {
                return $true
            }
            else {
                return $false
            }
        }
    }

    function Resolve-Host {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$True)]
            [string]$HostNameOrIP
        )
    
        #region >> Main
    
        $RemoteHostNetworkInfoArray = @()
        if (!$(Test-IsValidIPAddress -IPAddress $HostNameOrIP)) {
            try {
                $HostNamePrep = $HostNameOrIP
                [System.Collections.ArrayList]$RemoteHostArrayOfIPAddresses = @()
                $IPv4AddressFamily = "InterNetwork"
                $IPv6AddressFamily = "InterNetworkV6"
    
                $ResolutionInfo = [System.Net.Dns]::GetHostEntry($HostNamePrep)
                $ResolutionInfo.AddressList | Where-Object {
                    $_.AddressFamily -eq $IPv4AddressFamily
                } | foreach {
                    if ($RemoteHostArrayOfIPAddresses -notcontains $_.IPAddressToString) {
                        $null = $RemoteHostArrayOfIPAddresses.Add($_.IPAddressToString)
                    }
                }
            }
            catch {
                Write-Verbose "Unable to resolve $HostNameOrIP when treated as a Host Name (as opposed to IP Address)!"
    
                if ($HostNameOrIP -match "\.") {
                    try {
                        $HostNamePrep = $($HostNameOrIP -split "\.")[0]
                        Write-Verbose "Trying to resolve $HostNameOrIP using only HostName: $HostNamePrep!"
    
                        [System.Collections.ArrayList]$RemoteHostArrayOfIPAddresses = @()
                        $ResolutionInfo = [System.Net.Dns]::GetHostEntry($HostNamePrep)
                        $ResolutionInfo.AddressList | Where-Object {
                            $_.AddressFamily -eq $IPv4AddressFamily
                        } | foreach {
                            if ($RemoteHostArrayOfIPAddresses -notcontains $_.IPAddressToString) {
                                $null = $RemoteHostArrayOfIPAddresses.Add($_.IPAddressToString)
                            }
                        }
                    }
                    catch {
                        Write-Verbose "Unable to resolve $HostNamePrep!"
                    }
                }
            }
        }
        if (Test-IsValidIPAddress -IPAddress $HostNameOrIP) {
            try {
                $HostIPPrep = $HostNameOrIP
                [System.Collections.ArrayList]$RemoteHostArrayOfIPAddresses = @()
                $null = $RemoteHostArrayOfIPAddresses.Add($HostIPPrep)
    
                $ResolutionInfo = [System.Net.Dns]::GetHostEntry($HostIPPrep)
    
                [System.Collections.ArrayList]$RemoteHostFQDNs = @() 
                $null = $RemoteHostFQDNs.Add($ResolutionInfo.HostName)
            }
            catch {
                Write-Verbose "Unable to resolve $HostNameOrIP when treated as an IP Address (as opposed to Host Name)!"
            }
        }
    
        if ($RemoteHostArrayOfIPAddresses.Count -eq 0) {
            Write-Error "Unable to determine IP Address of $HostNameOrIP! Halting!"
            $global:FunctionResult = "1"
            return
        }
    
        # At this point, we have $RemoteHostArrayOfIPAddresses...
        [System.Collections.ArrayList]$RemoteHostFQDNs = @()
        foreach ($HostIP in $RemoteHostArrayOfIPAddresses) {
            try {
                $FQDNPrep = [System.Net.Dns]::GetHostEntry($HostIP).HostName
            }
            catch {
                Write-Verbose "Unable to resolve $HostIP. No PTR Record? Please check your DNS config."
                continue
            }
            if ($RemoteHostFQDNs -notcontains $FQDNPrep) {
                $null = $RemoteHostFQDNs.Add($FQDNPrep)
            }
        }
    
        if ($RemoteHostFQDNs.Count -eq 0) {
            $null = $RemoteHostFQDNs.Add($ResolutionInfo.HostName)
        }
    
        [System.Collections.ArrayList]$HostNameList = @()
        [System.Collections.ArrayList]$DomainList = @()
        foreach ($fqdn in $RemoteHostFQDNs) {
            $PeriodCheck = $($fqdn | Select-String -Pattern "\.").Matches.Success
            if ($PeriodCheck) {
                $HostName = $($fqdn -split "\.")[0]
                $Domain = $($fqdn -split "\.")[1..$($($fqdn -split "\.").Count-1)] -join '.'
            }
            else {
                $HostName = $fqdn
                $Domain = "Unknown"
            }
    
            $null = $HostNameList.Add($HostName)
            $null = $DomainList.Add($Domain)
        }
    
        if ($RemoteHostFQDNs[0] -eq $null -and $HostNameList[0] -eq $null -and $DomainList -eq "Unknown" -and $RemoteHostArrayOfIPAddresses) {
            [System.Collections.ArrayList]$SuccessfullyPingedIPs = @()
            # Test to see if we can reach the IP Addresses
            foreach ($ip in $RemoteHostArrayOfIPAddresses) {
                try {
                    $null = [System.Net.NetworkInformation.Ping]::new().Send($ip,1000)
                    $null = $SuccessfullyPingedIPs.Add($ip)
                }
                catch {
                    Write-Verbose "Unable to ping $ip..."
                    continue
                }
            }
        }
    
        $FQDNPrep = if ($RemoteHostFQDNs) {$RemoteHostFQDNs[0]} else {$null}
        if ($FQDNPrep -match ',') {
            $FQDN = $($FQDNPrep -split ',')[0]
        }
        else {
            $FQDN = $FQDNPrep
        }
    
        $DomainPrep = if ($DomainList) {$DomainList[0]} else {$null}
        if ($DomainPrep -match ',') {
            $Domain = $($DomainPrep -split ',')[0]
        }
        else {
            $Domain = $DomainPrep
        }
    
        $IPAddressList = [System.Collections.ArrayList]@($(if ($SuccessfullyPingedIPs) {$SuccessfullyPingedIPs} else {$RemoteHostArrayOfIPAddresses}))
        $HName = if ($HostNameList) {$HostNameList[0].ToLowerInvariant()} else {$null}
    
        if ($SuccessfullyPingedIPs.Count -eq 0 -and !$FQDN -and !$HostName -and !$Domain) {
            Write-Error "Unable to resolve $HostNameOrIP! Halting!"
            $global:FunctionResult = "1"
            return
        }
    
        [pscustomobject]@{
            IPAddressList   = $IPAddressList
            PingSuccess     = $($SuccessfullyPingedIPs.Count -gt 0)
            FQDN            = $FQDN
            HostName        = $HName
            Domain          = $Domain
        }
    
        #endregion >> Main
    
    }

    function Install-LinuxPackage {
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory=$True)]
            [string[]]$PossiblePackageNames,
    
            [Parameter(Mandatory=$True)]
            [string]$CommandName
        )
    
        if (!$(command -v $CommandName)) {
            foreach ($PackageName in $PossiblePackageNames) {
                if ($(command -v pacman)) {
                    $null = sudo pacman -S $PackageName --noconfirm *> $null
                }
                elseif ($(command -v yum)) {
                    $null = sudo yum -y install $PackageName *> $null
                }
                elseif ($(command -v dnf)) {
                    $null = sudo dnf -y install $PackageName *> $null
                }
                elseif ($(command -v apt)) {
                    $null = sudo apt-get -y install $PackageName *> $null
                }
                elseif ($(command -v zypper)) {
                    $null = sudo zypper install $PackageName --non-interactive *> $null
                }
    
                if ($(command -v $CommandName)) {
                    break
                }
            }
    
            if (!$(command -v $CommandName)) {
                Write-Error "Unable to find the command $CommandName! Install unsuccessful! Halting!"
                $global:FunctionResult = "1"
                return
            }
            else {
                Write-Host "$PackageName was successfully installed!" -ForegroundColor Green
            }
        }
        else {
            Write-Warning "The command $CommandName is already available!"
            return
        }
    }

    function Download-NuGetPackage {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$True)]
            [string]$AssemblyName,
    
            [Parameter(Mandatory=$False)]
            [string]$NuGetPkgDownloadDirectory,
    
            [Parameter(Mandatory=$False)]
            [switch]$AllowPreRelease,
    
            [Parameter(Mandatory=$False)]
            [switch]$Silent
        )
    
        #region >> Helper Functions
        
        function Get-NativePath {
            [CmdletBinding()]
            Param( 
                [Parameter(Mandatory=$True)]
                [string[]]$PathAsStringArray
            )
        
            $PathAsStringArray = foreach ($pathPart in $PathAsStringArray) {
                $SplitAttempt = $pathPart -split [regex]::Escape([IO.Path]::DirectorySeparatorChar)
                
                if ($SplitAttempt.Count -gt 1) {
                    foreach ($obj in $SplitAttempt) {
                        $obj
                    }
                }
                else {
                    $pathPart
                }
            }
            $PathAsStringArray = $PathAsStringArray -join [IO.Path]::DirectorySeparatorChar
        
            $PathAsStringArray
        
        }
        
        #endregion >> Helper Functions
    
        #region >> Prep
    
        if ($PSVersionTable.Platform -ne $null -and $PSVersionTable.Platform -ne "Win32NT" -and !$NuGetPkgDownloadDirectory) {
            Write-Error "On this OS Platform (i.e. $($PSVersionTable.Platform)), the -NuGetPkgDownloadDirectory parameter is required! Halting!"
            $global:FunctionResult = "1"
            return
        }
        
        if ($($PSVersionTable.Platform -ne $null -and $PSVersionTable.Platform -ne "Win32NT") -or $NuGetPkgDownloadDirectory) {
            #$NuGetPackageUri = "https://www.nuget.org/api/v2/package/$AssemblyName"
            #$NuGetPackageUri = "https://api.nuget.org/v3-flatcontainer/{id-lower}/{version-lower}/{id-lower}.{version-lower}.nupkg"
            if ($AllowPreRelease) {
                $SearchNuGetPackageUri = "https://api-v2v3search-0.nuget.org/query?q=$AssemblyName&prerelease=true"
            }
            else {
                $SearchNuGetPackageUri = "https://api-v2v3search-0.nuget.org/query?q=$AssemblyName&prerelease=false"
            }
            $VersionCheckPrep = $($(Invoke-RestMethod -Uri $SearchNuGetPackageUri).data | Where-Object {$_.id -eq $AssemblyName}).versions
            $LatestVersion = $VersionCheckPrep[-1].Version
            $LowercaseAssemblyName = $AssemblyName.ToLowerInvariant()
            $NuGetPackageUri = "https://api.nuget.org/v3-flatcontainer/$LowercaseAssemblyName/$LatestVersion/$LowercaseAssemblyName.$LatestVersion.nupkg"
    
            $OutFileBaseName = "$LowercaseAssemblyName.$LatestVersion.zip"
            $DllFileName = $OutFileBaseName -replace "zip","dll"
    
            if ($NuGetPkgDownloadDirectory) {
                $NuGetPkgDownloadPath = Join-Path $NuGetPkgDownloadDirectory $OutFileBaseName
                $NuGetPkgExtractionDirectory = Join-Path $NuGetPkgDownloadDirectory $AssemblyName
                if (!$(Test-Path $NuGetPkgDownloadDirectory)) {
                    $null = New-Item -ItemType Directory -Path $NuGetPkgDownloadDirectory -Force
                }
                if (!$(Test-Path $NuGetPkgExtractionDirectory)) {
                    $null = New-Item -ItemType Directory -Path $NuGetPkgExtractionDirectory -Force
                }
            }
        }
        if ($($PSVersionTable.PSEdition -eq "Desktop" -or $PSVersionTable.Platform -eq "Win32NT") -and !$NuGetPkgDownloadDirectory) {
            $NuGetConfigContent = Get-Content $(Get-NativePath @($env:AppData, "NuGet", "nuget.config"))
            $NuGetRepoPathCheck = $NuGetConfigContent | Select-String -Pattern '<add key="repositoryPath" value=' -ErrorAction SilentlyContinue
            if ($NuGetRepoPathCheck -ne $null) {
                $NuGetPackagesPath = $($($NuGetRepoPathCheck.Line.Trim() -split 'value=')[-1] -split ' ')[0] -replace '"',''
            }
            else {
                $NuGetPackagesPath = Get-NativePath @($HOME, ".nuget", "packages")
            }
    
            if (!$(Test-Path $NuGetPackagesPath)) {
                $null = New-Item -ItemType Directory -Path $NuGetPackagesPath -Force
            }
    
            $NuGetPkgExtractionDirectory = Get-NativePath @($NuGetPackagesPath, $AssemblyName)
        }
    
        if ($PSVersionTable.PSEdition -eq "Core") {
            $PossibleSubDirs = @(
                [pscustomobject]@{
                    Preference      = 4
                    SubDirectory    = $(Get-NativePath @("lib", "netstandard1.3"))
                }
                [pscustomobject]@{
                    Preference      = 3
                    SubDirectory    = $(Get-NativePath @("lib", "netstandard1.6"))
                }
                [pscustomobject]@{
                    Preference      = 1
                    SubDirectory    = $(Get-NativePath @("lib", "netstandard2.0"))
                }
                [pscustomobject]@{
                    Preference      = 2
                    SubDirectory    = $(Get-NativePath @("lib", "netcoreapp2.0"))
                }
            )
        }
        else {
            $PossibleSubDirs = @(
                [pscustomobject]@{
                    Preference      = 8
                    SubDirectory    = $(Get-NativePath @("lib", "net40"))
                }
                [pscustomobject]@{
                    Preference      = 7
                    SubDirectory    = $(Get-NativePath @("lib", "net45"))
                }
                [pscustomobject]@{
                    Preference      = 6
                    SubDirectory    = $(Get-NativePath @("lib", "net451"))
                }
                [pscustomobject]@{
                    Preference      = 5
                    SubDirectory    = $(Get-NativePath @("lib", "net46"))
                }
                [pscustomobject]@{
                    Preference      = 4
                    SubDirectory    = $(Get-NativePath @("lib", "net461"))
                }
                [pscustomobject]@{
                    Preference      = 3
                    SubDirectory    = $(Get-NativePath @("lib", "net462"))
                }
                [pscustomobject]@{
                    Preference      = 2
                    SubDirectory    = $(Get-NativePath @("lib", "net47"))
                }
                [pscustomobject]@{
                    Preference      = 1
                    SubDirectory    = $(Get-NativePath @("lib", "net471"))
                }
                [pscustomobject]@{
                    Preference      = 15
                    SubDirectory    = $(Get-NativePath @("lib", "netstandard1.0"))
                }
                [pscustomobject]@{
                    Preference      = 14
                    SubDirectory    = $(Get-NativePath @("lib", "netstandard1.1"))
                }
                [pscustomobject]@{
                    Preference      = 13
                    SubDirectory    = $(Get-NativePath @("lib", "netstandard1.2"))
                }
                [pscustomobject]@{
                    Preference      = 12
                    SubDirectory    = $(Get-NativePath @("lib", "netstandard1.3"))
                }
                [pscustomobject]@{
                    Preference      = 11
                    SubDirectory    = $(Get-NativePath @("lib", "netstandard1.4"))
                }
                [pscustomobject]@{
                    Preference      = 10
                    SubDirectory    = $(Get-NativePath @("lib", "netstandard1.5"))
                }
                [pscustomobject]@{
                    Preference      = 9
                    SubDirectory    = $(Get-NativePath @("lib", "netstandard1.6"))
                }
                [pscustomobject]@{
                    Preference      = 16
                    SubDirectory    = $(Get-NativePath @("lib", "netstandard2.0"))
                }
                [pscustomobject]@{
                    Preference      = 17
                    SubDirectory    = $(Get-NativePath @("lib", "netcoreapp2.0"))
                }
            )
        }
    
        #endregion >> Prep
    
        
        #region >> Main
    
        if ($($PSVersionTable.PSEdition -eq "Desktop" -or $PSVersionTable.Platform -eq "Win32NT") -and !$NuGetPkgDownloadDirectory) {
            if (!$(Get-Command nuget.exe -ErrorAction SilentlyContinue)) {
                $NugetPath = Join-Path $($NuGetPackagesPath | Split-Path -Parent) nuget.exe
                if(!$(Test-Path $NugetPath)) {
                    Invoke-WebRequest -uri 'https://dist.nuget.org/win-x86-commandline/latest/nuget.exe' -OutFile $NugetPath
                }
                $NugetDir = $NugetPath | Split-Path -Parent
    
                # Update PowerShell $env:Path
                [System.Collections.Arraylist][array]$CurrentEnvPathArray = $env:Path -split ';' | Where-Object {![System.String]::IsNullOrWhiteSpace($_)} | Sort-Object | Get-Unique
                if ($CurrentEnvPathArray -notcontains $NugetDir) {
                    $CurrentEnvPathArray.Insert(0,$NugetDir)
                    $env:Path = $CurrentEnvPathArray -join ';'
                }
                
                # Update SYSTEM Path
                $RegistrySystemPath = 'HKLM:\System\CurrentControlSet\Control\Session Manager\Environment'
                $CurrentSystemPath = $(Get-ItemProperty -Path $RegistrySystemPath -Name PATH).Path
                [System.Collections.Arraylist][array]$CurrentSystemPathArray = $CurrentSystemPath -split ';' | Where-Object {![System.String]::IsNullOrWhiteSpace($_)} | Sort-Object | Get-Unique
                if ($CurrentSystemPathArray -notcontains $NugetDir) {
                    $CurrentSystemPathArray.Insert(0,$NugetDir)
                    $UpdatedSystemPath = $CurrentSystemPathArray -join ';'
                    Set-ItemProperty -Path $RegistrySystemPath -Name PATH -Value $UpdatedSystemPath
                }   
            }
    
            try {
                $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
                #$ProcessInfo.WorkingDirectory = $NuGetPackagesPath
                $ProcessInfo.FileName = $(Get-Command nuget).Source
                $ProcessInfo.RedirectStandardError = $true
                $ProcessInfo.RedirectStandardOutput = $true
                $ProcessInfo.UseShellExecute = $false
                if ($AllowPreRelease) {
                    $ProcessInfo.Arguments = "install $AssemblyName -PreRelease"
                }
                else {
                    $ProcessInfo.Arguments = "install $AssemblyName"
                }
                $Process = New-Object System.Diagnostics.Process
                $Process.StartInfo = $ProcessInfo
                $Process.Start() | Out-Null
                $stdout = $($Process.StandardOutput.ReadToEnd()).Trim()
                $stderr = $($Process.StandardError.ReadToEnd()).Trim()
                $AllOutput = $stdout + $stderr
                $AllOutput = $AllOutput -split "`n"
    
                if ($stderr -match "Unable to find package") {
                    throw
                }
    
                $NuGetPkgExtractionDirectory = $(Get-ChildItem -Path $NuGetPackagesPath -Directory | Where-Object {$_.Name -eq $AssemblyName} | Sort-Object -Property CreationTime)[-1].FullName
            }
            catch {
                Write-Error $_
                Write-Error "NuGet.exe was unable to find a package called $AssemblyName! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
        if ($($PSVersionTable.Platform -ne $null -and $PSVersionTable.Platform -ne "Win32NT") -or $NuGetPkgDownloadDirectory) {
            try {
                # Download the NuGet Package
                if (!$Silent) {
                    Write-Host "Downloading $AssemblyName NuGet Package to $NuGetPkgDownloadPath ..."
                }
                Invoke-WebRequest -Uri $NuGetPackageUri -OutFile $NuGetPkgDownloadPath
                if (!$Silent) {
                    Write-Host "NuGet Package has been downloaded to $NuGetPkgDownloadPath"
                }
            }
            catch {
                Write-Error "Unable to find $AssemblyName via the NuGet API! Halting!"
                $global:FunctionResult = "1"
                return
            }
    
            # Step through possble Zip File SubDirs and get the most highest available compatible version of the Assembly
            try {
                if (!$Silent) {
                    Write-Host "Attempting to extract NuGet zip file $NuGetPkgDownloadPath to $NuGetPkgExtractionDirectory ..."
                }
                if ($(Get-ChildItem $NuGetPkgExtractionDirectory).Count -gt 1) {
                    foreach ($item in $(Get-ChildItem $NuGetPkgExtractionDirectory)) {
                        if ($item.Extension -ne ".zip") {
                            $item | Remove-Item -Recurse -Force
                        }
                    }
                }
                Expand-Archive -Path $NuGetPkgDownloadPath -DestinationPath $NuGetPkgExtractionDirectory
                if (!$Silent) {
                    Write-Host "NuGet Package is available here: $NuGetPkgExtractionDirectory"
                }
            }
            catch {
                Write-Warning "The Unzip-File function failed with the following error:"
                Write-Error $$_
                $global:FunctionResult = "1"
                return
            }
        }
    
        [System.Collections.ArrayList]$NuGetPackageActualSubDirs = @()
        $(Get-ChildItem -Recurse $NuGetPkgExtractionDirectory -File -Filter "*.dll").DirectoryName | foreach {
            $null = $NuGetPackageActualSubDirs.Add($_)
        }
        
        $s = [IO.Path]::DirectorySeparatorChar
        [System.Collections.ArrayList]$FoundSubDirsPSObjects = @()
        foreach ($pdir in $PossibleSubDirs) {
            foreach ($adir in $NuGetPackageActualSubDirs) {
                $IndexOfSlash = $pdir.SubDirectory.IndexOf($s)
                $pdirToRegexPattern = {
                    $UpdatedString = $pdir.SubDirectory.Remove($IndexOfSlash, 1)
                    $UpdatedString.Insert($IndexOfSlash, [regex]::Escape($s))
                }.Invoke()
    
                if ($adir -match $pdirToRegexPattern) {
                    $FoundDirPSObj = [pscustomobject]@{
                        Preference   = $pdir.Preference
                        Directory    = $adir
                    }
                    $null = $FoundSubDirsPSObjects.Add($FoundDirPSObj)
                }
            }
        }
    
        $TargetDir = $($FoundSubDirsPSObjects | Sort-Object -Property Preference)[0].Directory
        $AssemblyPath = Get-NativePath @($TargetDir, $(Get-ChildItem $TargetDir -File -Filter "*.dll").Name)
        
        [pscustomobject]@{
            NuGetPackageDirectory   = $NuGetPkgExtractionDirectory
            AssemblyToLoad          = $AssemblyPath
        }
        
        #endregion >> Main
    
    }
    
    function Get-DomainName {
        [CmdletBinding()]
        Param()
    
        if (!$PSVersionTable.Platform -or $PSVersionTable.Platform -eq "Win32NT") {
            $Domain = $(Get-CimInstance Win32_ComputerSystem).Domain
        }
        if ($PSVersionTable.Platform -eq "Unix" -or $PSVersionTable.OS -match "Darwin") {
            $Domain = domainname
            if (!$Domain -or $Domain -eq "(none)") {
                $ThisHostNamePrep = hostname
                if ($ThisHostNamePrep -match "\.") {
                    $HostNameArray = $ThisHostNamePrep -split "\."
                    $ThisHostName = $HostNameArray[0]
                    $Domain = $HostNameArray[1..$HostNameArray.Count] -join '.'
                }
            }
                
            if (!$Domain) {
                $EtcHostsContent = Get-Content "/etc/hosts"
                $EtcHostsContentsArray = $(foreach ($HostLine in $EtcHostsContent) {
                    $HostLine -split "[\s]" | foreach {$_.Trim()}
                }) | Where-Object {![System.String]::IsNullOrWhiteSpace($_)}
                $PotentialStringsWithDomainName = $EtcHostsContentsArray | Where-Object {
                    $_ -notmatch "localhost" -and
                    $_ -notmatch "localdomain" -and
                    $_ -match "\." -and
                    $_ -match "[a-zA-Z]"
                } | Sort-Object | Get-Unique
    
                if ($PotentialStringsWithDomainName.Count -eq 0) {
                    Write-Error "Unable to determine domain for $(hostname)! Please use the -DomainName parameter and try again. Halting!"
                    $global:FunctionResult = "1"
                    return
                }
                
                [System.Collections.ArrayList]$PotentialDomainsPrep = @()
                foreach ($Line in $PotentialStringsWithDomainName) {
                    if ($Line -match "^\.") {
                        $null = $PotentialDomainsPrep.Add($Line.Substring(1,$($Line.Length-1)))
                    }
                    else {
                        $null = $PotentialDomainsPrep.Add($Line)
                    }
                }
                [System.Collections.ArrayList]$PotentialDomains = @()
                foreach ($PotentialDomain in $PotentialDomainsPrep) {
                    $RegexDomainPattern = "^([a-zA-Z0-9][a-zA-Z0-9-_]*\.)*[a-zA-Z0-9]*[a-zA-Z0-9-_]*[[a-zA-Z0-9]+$"
                    if ($PotentialDomain -match $RegexDomainPattern) {
                        $FinalPotentialDomain = $PotentialDomain -replace $ThisHostName,""
                        if ($FinalPotentialDomain -match "^\.") {
                            $null = $PotentialDomains.Add($FinalPotentialDomain.Substring(1,$($FinalPotentialDomain.Length-1)))
                        }
                        else {
                            $null = $PotentialDomains.Add($FinalPotentialDomain)
                        }
                    }
                }
    
                if ($PotentialDomains.Count -eq 1) {
                    $Domain = $PotentialDomains
                }
                else {
                    $Domain = $PotentialDomains[0]
                }
            }
        }
    
        if ($Domain) {
            $Domain
        }
        else {
            Write-Error "Unable to determine Domain Name! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    function Get-DomainController {
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory=$False)]
            [String]$Domain,
    
            [Parameter(Mandatory=$False)]
            [switch]$UseLogonServer
        )
    
        #region >> Helper Functions
    
        function Parse-NLTest {
            [CmdletBinding()]
            Param (
                [Parameter(Mandatory=$True)]
                [string]$Domain
            )
    
            while ($Domain -notmatch "\.") {
                Write-Warning "The provided value for the -Domain parameter is not in the correct format. Please use the entire domain name (including periods)."
                $Domain = Read-Host -Prompt "Please enter the full domain name (including periods)"
            }
    
            if (![bool]$(Get-Command nltest -ErrorAction SilentlyContinue)) {
                Write-Error "Unable to find nltest.exe! Halting!"
                $global:FunctionResult = "1"
                return
            }
    
            $DomainPrefix = $($Domain -split '\.')[0]
            $PrimaryDomainControllerPrep = Invoke-Expression "nltest /dclist:$DomainPrefix 2>null"
            if (![bool]$($PrimaryDomainControllerPrep | Select-String -Pattern 'PDC')) {
                Write-Error "Can't find the Primary Domain Controller for domain $DomainPrefix"
                return
            }
            $PrimaryDomainControllerPrep = $($($PrimaryDomainControllerPrep -match 'PDC').Trim() -split ' ')[0]
            if ($PrimaryDomainControllerPrep -match '\\\\') {
                $PrimaryDomainController = $($PrimaryDomainControllerPrep -replace '\\\\','').ToLower() + ".$Domain"
            }
            else {
                $PrimaryDomainController = $PrimaryDomainControllerPrep.ToLower() + ".$Domain"
            }
    
            $PrimaryDomainController
        }

        #endregion >> Helper Functions

        #region >> Main
    
        if ($PSVersionTable.Platform -eq "Unix" -or $PSVersionTable.OS -match "Darwin") {
            # Determine if we have the required Linux commands
            [System.Collections.ArrayList]$LinuxCommands = @(
                "host"
                "hostname"
            )
            if (!$Domain) {
                $null = $LinuxCommands.Add("domainname")
            }
            [System.Collections.ArrayList]$CommandsNotPresent = @()
            foreach ($CommandName in $LinuxCommands) {
                $CommandCheckResult = command -v $CommandName
                if (!$CommandCheckResult) {
                    $null = $CommandsNotPresent.Add($CommandName)
                }
            }
            if ($CommandsNotPresent.Count -gt 0) {
                Write-Error "The following Linux commands are required, but not present on $(hostname):`n$($CommandsNotPresent -join "`n")`nHalting!"
                $global:FunctionResult = "1"
                return
            }
    
            $ThisHostNamePrep = hostname
            $ThisHostName = $($ThisHostNamePrep -split "\.")[0]
    
            if (!$Domain) {
                $Domain = Get-DomainName
            }
    
            if (!$Domain) {
                Write-Error "Unable to determine domain for $ThisHostName! Please provide a domain to the -DomainName parameter and try again. Halting!"
                $global:FunctionResult = "1"
                return
            }
    
            $DomainControllerPrep = $(host -t srv _ldap._tcp.$Domain) -split "`n"
            $DomainControllerPrepA = if ($DomainControllerPrep.Count -gt 1) {
                $DomainControllerPrep | foreach {$($_ -split "[\s]")[-1]}
            } else {
                @($($DomainControllerPrep -split "[\s]")[-1])
            }
            $DomainControllers = $DomainControllerPrepA | foreach {
                if ($_[-1] -eq ".") {
                    $_.SubString(0,$($_.Length-1))
                }
                else {
                    $_
                }
            }
    
            $FoundDomainControllers = $DomainControllers
            $PrimaryDomainController = "unknown"
        }
    
        if (!$PSVersionTable.Platform -or $PSVersionTable.Platform -eq "Win32NT") {
            $ComputerSystemCim = Get-CimInstance Win32_ComputerSystem
            $PartOfDomain = $ComputerSystemCim.PartOfDomain
    
            if (!$PartOfDomain -and !$Domain) {
                Write-Error "$env:ComputerName is NOT part of a Domain and the -Domain parameter was not used in order to specify a domain! Halting!"
                $global:FunctionResult = "1"
                return
            }
            
            $ThisMachinesDomain = $ComputerSystemCim.Domain
    
            # If we're in a PSSession, [system.directoryservices.activedirectory] won't work due to Double-Hop issue
            # So just get the LogonServer if possible
            if ($Host.Name -eq "ServerRemoteHost" -or $UseLogonServer) {
                if (!$Domain -or $Domain -eq $ThisMachinesDomain) {
                    $Counter = 0
                    while ([string]::IsNullOrWhitespace($DomainControllerName) -or $Counter -le 20) {
                        $DomainControllerName = $(Get-CimInstance win32_ntdomain).DomainControllerName
                        if ([string]::IsNullOrWhitespace($DomainControllerName)) {
                            Write-Warning "The win32_ntdomain CimInstance has a null value for the 'DomainControllerName' property! Trying again in 15 seconds (will try for 5 minutes total)..."
                            Start-Sleep -Seconds 15
                        }
                        $Counter++
                    }
    
                    if ([string]::IsNullOrWhitespace($DomainControllerName)) {
                        $IPOfDNSServerWhichIsProbablyDC = $(Resolve-DNSName $ThisMachinesDomain).IPAddress
                        $DomainControllerFQDN = $(ResolveHost -HostNameOrIP $IPOfDNSServerWhichIsProbablyDC).FQDN
                    }
                    else {
                        $LogonServer = $($DomainControllerName | Where-Object {![string]::IsNullOrWhiteSpace($_)}).Replace('\\','').Trim()
                        $DomainControllerFQDN = $LogonServer + '.' + $RelevantSubCANetworkInfo.DomainName
                    }
    
                    [pscustomobject]@{
                        FoundDomainControllers      = [array]$DomainControllerFQDN
                        PrimaryDomainController     = $DomainControllerFQDN
                    }
    
                    return
                }
                else {
                    Write-Error "Unable to determine Domain Controller(s) network location due to the Double-Hop Authentication issue! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
            }
    
            if ($Domain) {
                try {
                    $Forest = [system.directoryservices.activedirectory.Forest]::GetCurrentForest()
                }
                catch {
                    Write-Verbose "Cannot connect to current forest."
                }
    
                if ($ThisMachinesDomain -eq $Domain -and $Forest.Domains -contains $Domain) {
                    [System.Collections.ArrayList]$FoundDomainControllers = $Forest.Domains | Where-Object {$_.Name -eq $Domain} | foreach {$_.DomainControllers} | foreach {$_.Name}
                    $PrimaryDomainController = $Forest.Domains.PdcRoleOwner.Name
                }
                if ($ThisMachinesDomain -eq $Domain -and $Forest.Domains -notcontains $Domain) {
                    try {
                        $GetCurrentDomain = [system.directoryservices.activedirectory.domain]::GetCurrentDomain()
                        [System.Collections.ArrayList]$FoundDomainControllers = $GetCurrentDomain | foreach {$_.DomainControllers} | foreach {$_.Name}
                        $PrimaryDomainController = $GetCurrentDomain.PdcRoleOwner.Name
                    }
                    catch {
                        try {
                            Write-Warning "Only able to report the Primary Domain Controller for $Domain! Other Domain Controllers most likely exist!"
                            Write-Warning "For a more complete list, try running this function on a machine that is part of the domain $Domain!"
                            $PrimaryDomainController = Parse-NLTest -Domain $Domain
                            [System.Collections.ArrayList]$FoundDomainControllers = @($PrimaryDomainController)
                        }
                        catch {
                            Write-Error $_
                            $global:FunctionResult = "1"
                            return
                        }
                    }
                }
                if ($ThisMachinesDomain -ne $Domain -and $Forest.Domains -contains $Domain) {
                    [System.Collections.ArrayList]$FoundDomainControllers = $Forest.Domains | foreach {$_.DomainControllers} | foreach {$_.Name}
                    $PrimaryDomainController = $Forest.Domains.PdcRoleOwner.Name
                }
                if ($ThisMachinesDomain -ne $Domain -and $Forest.Domains -notcontains $Domain) {
                    try {
                        Write-Warning "Only able to report the Primary Domain Controller for $Domain! Other Domain Controllers most likely exist!"
                        Write-Warning "For a more complete list, try running this function on a machine that is part of the domain $Domain!"
                        $PrimaryDomainController = Parse-NLTest -Domain $Domain
                        [System.Collections.ArrayList]$FoundDomainControllers = @($PrimaryDomainController)
                    }
                    catch {
                        Write-Error $_
                        $global:FunctionResult = "1"
                        return
                    }
                }
            }
            else {
                try {
                    $Forest = [system.directoryservices.activedirectory.Forest]::GetCurrentForest()
                    [System.Collections.ArrayList]$FoundDomainControllers = $Forest.Domains | foreach {$_.DomainControllers} | foreach {$_.Name}
                    $PrimaryDomainController = $Forest.Domains.PdcRoleOwner.Name
                }
                catch {
                    Write-Verbose "Cannot connect to current forest."
    
                    try {
                        $GetCurrentDomain = [system.directoryservices.activedirectory.domain]::GetCurrentDomain()
                        [System.Collections.ArrayList]$FoundDomainControllers = $GetCurrentDomain | foreach {$_.DomainControllers} | foreach {$_.Name}
                        $PrimaryDomainController = $GetCurrentDomain.PdcRoleOwner.Name
                    }
                    catch {
                        $Domain = $ThisMachinesDomain
    
                        try {
                            $CurrentUser = "$(whoami)"
                            Write-Warning "Only able to report the Primary Domain Controller for the domain that $env:ComputerName is joined to (i.e. $Domain)! Other Domain Controllers most likely exist!"
                            Write-Host "For a more complete list, try one of the following:" -ForegroundColor Yellow
                            if ($($CurrentUser -split '\\') -eq $env:ComputerName) {
                                Write-Host "- Try logging into $env:ComputerName with a domain account (as opposed to the current local account $CurrentUser" -ForegroundColor Yellow
                            }
                            Write-Host "- Try using the -Domain parameter" -ForegroundColor Yellow
                            Write-Host "- Run this function on a computer that is joined to the Domain you are interested in" -ForegroundColor Yellow
                            $PrimaryDomainController = Parse-NLTest -Domain $Domain
                            [System.Collections.ArrayList]$FoundDomainControllers = @($PrimaryDomainController)
                        }
                        catch {
                            Write-Error $_
                            $global:FunctionResult = "1"
                            return
                        }
                    }
                }
            }
        }
    
        [pscustomobject]@{
            FoundDomainControllers      = $FoundDomainControllers
            PrimaryDomainController     = $PrimaryDomainController
        }
    
        #endregion >> Main
    }

    function Test-LDAP {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory=$True)]
            [string]$ADServerHostNameOrIP
        )

        #region >> Prep
    
        if ($PSVersionTable.Platform -eq "Unix") {
            # If we're on Linux, we need the Novell .Net Core library
            try {
                $CurrentlyLoadedAssemblies = [System.AppDomain]::CurrentDomain.GetAssemblies()
                if (![bool]$($CurrentlyLoadedAssemblies -match [regex]::Escape("Novell.Directory.Ldap.NETStandard"))) {
                    $NovellDownloadDir = "$HOME/Novell.Directory.Ldap.NETStandard"
                    if (Test-Path $NovellDownloadDir) {
                        $null = Remove-Item -Path $NovellDownloadDir -Recurse -Force
                    }
    
                    $NovellPackageInfo = Download-NuGetPackage -AssemblyName "Novell.Directory.Ldap.NETStandard" -NuGetPkgDownloadDirectory $NovellDownloadDir -Silent
                    $AssemblyToLoadPath = $NovellPackageInfo.AssemblyToLoad
    
                    if (![bool]$($CurrentlyLoadedAssemblies -match [regex]::Escape("Novell.Directory.Ldap.NETStandard"))) {
                        $null = Add-Type -Path $AssemblyToLoadPath
                    }
                }
            }
            catch {
                Write-Error $_
                $global:FunctionResult = "1"
                return
            }
        }
    
        try {
            $ADServerNetworkInfo = Resolve-Host -HostNameOrIP $ADServerHostNameOrIP -ErrorAction Stop
        }
        catch {
            Write-Error "Unable to resolve $ADServerHostNameOrIP! Halting!"
            $global:FunctionResult = "1"
            return
        }
    
        if (!$ADServerNetworkInfo.FQDN) {
            Write-Error "Unable to determine FQDN of $ADServerHostNameOrIP! Halting!"
            $global:FunctionResult = "1"
            return
        }
    
        #endregion >> Prep
    
        #region >> Main
    
        $ADServerFQDN = $ADServerNetworkInfo.FQDN
    
        $LDAPPrep = "LDAP://" + $ADServerFQDN
    
        # Try Global Catalog First - It's faster and you can execute from a different domain and
        # potentially still get results
        try {
            $Port = "3269"
            $LDAP = $LDAPPrep + ":$Port"
            if ($PSVersionTable.Platform -eq "Unix") {
                $Connection = [Novell.Directory.Ldap.LdapConnection]::new()
                $Connection.Connect($ADServerFQDN,$Port)
                $Connection.Dispose()
            }
            else {
                $Connection = [System.DirectoryServices.DirectoryEntry]($LDAP)
                $Connection.Close()
            }
            $GlobalCatalogConfiguredForSSL = $True
        } 
        catch {
            if ($_.Exception.ToString() -match "The server is not operational") {
                Write-Warning "Either can't find LDAP Server or SSL on Global Catalog (3269) is not operational!"
            }
            elseif ($_.Exception.ToString() -match "The user name or password is incorrect") {
                Write-Warning "The current user $(whoami) does not have access!"
            }
            else {
                Write-Error $_
            }
        }
    
        try {
            $Port = "3268"
            $LDAP = $LDAPPrep + ":$Port"
            if ($PSVersionTable.Platform -eq "Unix") {
                $Connection = [Novell.Directory.Ldap.LdapConnection]::new()
                $Connection.Connect($ADServerFQDN,$Port)
                $Connection.Dispose()
            }
            else {
                $Connection = [System.DirectoryServices.DirectoryEntry]($LDAP)
                $Connection.Close()
            }
            $GlobalCatalogConfigured = $True
        } 
        catch {
            if ($_.Exception.ToString() -match "The server is not operational") {
                Write-Warning "Either can't find LDAP Server or Global Catalog (3268) is not operational!"
            }
            elseif ($_.Exception.ToString() -match "The user name or password is incorrect") {
                Write-Warning "The current user $(whoami) does not have access!"
            }
            else {
                Write-Error $_
            }
        }
      
        # Try the normal ports
        try {
            $Port = "636"
            $LDAP = $LDAPPrep + ":$Port"
            if ($PSVersionTable.Platform -eq "Unix") {
                $Connection = [Novell.Directory.Ldap.LdapConnection]::new()
                $Connection.Connect($ADServerFQDN,$Port)
                $Connection.Dispose()
            }
            else {
                $Connection = [System.DirectoryServices.DirectoryEntry]($LDAP)
                $Connection.Close()
            }
            $ConfiguredForSSL = $True
        } 
        catch {
            if ($_.Exception.ToString() -match "The server is not operational") {
                Write-Warning "Can't find LDAP Server or SSL (636) is NOT configured! Check the value provided to the -ADServerHostNameOrIP parameter!"
            }
            elseif ($_.Exception.ToString() -match "The user name or password is incorrect") {
                Write-Warning "The current user $(whoami) does not have access! Halting!"
            }
            else {
                Write-Error $_
            }
        }
    
        try {
            $Port = "389"
            $LDAP = $LDAPPrep + ":$Port"
            if ($PSVersionTable.Platform -eq "Unix") {
                $Connection = [Novell.Directory.Ldap.LdapConnection]::new()
                $Connection.Connect($ADServerFQDN,$Port)
                $Connection.Dispose()
            }
            else {
                $Connection = [System.DirectoryServices.DirectoryEntry]($LDAP)
                $Connection.Close()
            }
            $Configured = $True
        }
        catch {
            if ($_.Exception.ToString() -match "The server is not operational") {
                Write-Warning "Can't find LDAP Server (389)! Check the value provided to the -ADServerHostNameOrIP parameter!"
            }
            elseif ($_.Exception.ToString() -match "The user name or password is incorrect") {
                Write-Warning "The current user $(whoami) does not have access!"
            }
            else {
                Write-Error $_
            }
        }
    
        if (!$GlobalCatalogConfiguredForSSL -and !$GlobalCatalogConfigured -and !$ConfiguredForSSL -and !$Configured) {
            Write-Error "Unable to connect to $LDAPPrep! Halting!"
            $global:FunctionResult = "1"
            return
        }
    
        [System.Collections.ArrayList]$PortsThatWork = @()
        if ($GlobalCatalogConfigured) {$null = $PortsThatWork.Add("3268")}
        if ($GlobalCatalogConfiguredForSSL) {$null = $PortsThatWork.Add("3269")}
        if ($Configured) {$null = $PortsThatWork.Add("389")}
        if ($ConfiguredForSSL) {$null = $PortsThatWork.Add("636")}
    
        [pscustomobject]@{
            DirectoryEntryInfo                  = $Connection
            LDAPBaseUri                         = $LDAPPrep
            GlobalCatalogConfigured3268         = if ($GlobalCatalogConfigured) {$True} else {$False}
            GlobalCatalogConfiguredForSSL3269   = if ($GlobalCatalogConfiguredForSSL) {$True} else {$False}
            Configured389                       = if ($Configured) {$True} else {$False}
            ConfiguredForSSL636                 = if ($ConfiguredForSSL) {$True} else {$False}
            PortsThatWork                       = $PortsThatWork
        }
    
        #endregion >> Main
    }
    
    #endregion >> Helper Functions


    #region >> Prep
    
    if ($PSVersionTable.Platform -eq "Unix" -and !$LDAPCreds) {
        Write-Error "On this Platform (i.e. $($PSVersionTable.Platform)), you must provide credentials with access to LDAP/Active Directory using the -LDAPCreds parameter! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($LDAPCreds) {
        # Make sure the $LDAPCreds.UserName is in the correct format
        if ($LDAPCreds.UserName -notmatch "\\") {
            Write-Error "The -LDAPCreds UserName is NOT in the correct format! The format must be: <Domain>\<User>"
            $global:FunctionResult = "1"
            return
        }
    }

    if ($PSVersionTable.Platform -eq "Unix") {
        # Determine if we have the required Linux commands
        [System.Collections.ArrayList]$LinuxCommands = @(
            "echo"
            "host"
            "hostname"
            "ldapsearch"
            #"expect"
        )
        if (!$Domain) {
            $null = $LinuxCommands.Add("domainname")
        }
        [System.Collections.ArrayList]$CommandsNotPresent = @()
        foreach ($CommandName in $LinuxCommands) {
            $CommandCheckResult = command -v $CommandName
            if (!$CommandCheckResult) {
                $null = $CommandsNotPresent.Add($CommandName)
            }
        }

        if ($CommandsNotPresent.Count -gt 0) {
            [System.Collections.ArrayList]$FailedInstalls = @()
            if ($CommandsNotPresent -contains "echo" -or $CommandsNotPresent -contains "whoami") {
                try {
                    $null = Install-LinuxPackage -PossiblePackageNames "coreutils" -CommandName "echo"
                }
                catch {
                    $null = $FailedInstalls.Add("coreutils")
                }
            }
            if ($CommandsNotPresent -contains "host" -or $CommandsNotPresent -contains "hostname" -or $CommandsNotPresent -contains "domainname") {
                try {
                    $null = Install-LinuxPackage -PossiblePackageNames @("dnsutils","bindutils","bind-utils","bind-tools") -CommandName "nslookup"
                }
                catch {
                    $null = $FailedInstalls.Add("dnsutils_bindutils_bind-utils_bind-tools")
                }
            }
            if ($CommandsNotPresent -contains "ldapsearch") {
                try {
                    $null = Install-LinuxPackage -PossiblePackageNames "openldap-clients" -CommandName "ldapsearch"
                }
                catch {
                    $null = $FailedInstalls.Add("openldap-clients")
                }
            }
            <#
            if ($CommandsNotPresent -contains "expect") {
                try {
                    $null = Install-LinuxPackage -PossiblePackageNames "expect" -CommandName "expect"
                }
                catch {
                    $null = $FailedInstalls.Add("expect")
                }
            }
            #>
    
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

    # Below $LDAPInfo Output is PSCustomObject with properties: DirectoryEntryInfo, LDAPBaseUri,
    # GlobalCatalogConfigured3268, GlobalCatalogConfiguredForSSL3269, Configured389, ConfiguredForSSL636,
    # PortsThatWork
    try {
        if ($Domain) {
            $DomainControllerInfo = Get-DomainController -Domain $Domain -ErrorAction Stop
        }
        else {
            $DomainControllerInfo = Get-DomainController -ErrorAction Stop
        }

        if ($DomainControllerInfo.PrimaryDomainController -eq "unknown") {
            $PDC = $DomainControllerInfo.FoundDomainControllers[0]
        }
        else {
            $PDC = $DomainControllerInfo.PrimaryDomainController
        }

        $LDAPInfo = Test-LDAP -ADServerHostNameOrIP $PDC -ErrorAction Stop
        if (!$DomainControllerInfo) {throw "Problem with GetDomainController function! Halting!"}
        if (!$LDAPInfo) {throw "Problem with Test-LDAP function! Halting!"}
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    if (!$LDAPInfo.PortsThatWork) {
        Write-Error "Unable to access LDAP on $PDC! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($LDAPInfo.PortsThatWork -contains "389") {
        $Port = "389"
        $LDAPUri = $LDAPInfo.LDAPBaseUri + ":$Port"
    }
    elseif ($LDAPInfo.PortsThatWork -contains "3268") {
        $Port = "3268"
        $LDAPUri = $LDAPInfo.LDAPBaseUri + ":$Port"
    }
    elseif ($LDAPInfo.PortsThatWork -contains "636") {
        $Port = "636"
        $LDAPUri = $LDAPInfo.LDAPBaseUri + ":$Port"
    }
    elseif ($LDAPInfo.PortsThatWork -contains "3269") {
        $Port = "3269"
        $LDAPUri = $LDAPInfo.LDAPBaseUri + ":$Port"
    }

    #endregion >> Prep

    #region >> Main

    if ($PSVersionTable.Platform -eq "Unix") {
        $SimpleDomainPrep = $PDC -split "\."
        $SimpleDomain = $SimpleDomainPrep[1..$($SimpleDomainPrep.Count-1)] -join "."
        [System.Collections.ArrayList]$DomainLDAPContainersPrep = @()
        foreach ($Section in $($SimpleDomain -split "\.")) {
            $null = $DomainLDAPContainersPrep.Add($Section)
        }
        $DomainLDAPContainers = $($DomainLDAPContainersPrep | foreach {"DC=$_"}) -join ","
        $BindUserName = $LDAPCreds.UserName
        $BindUserNameForExpect = $BindUserName -replace [regex]::Escape('\'),'\\\'
        $BindPassword = $LDAPCreds.GetNetworkCredential().Password

        $ldapSearchOutput = ldapsearch -x -h $PDC -D $BindUserName -w $BindPassword -b $DomainLDAPContainers -s sub "(objectClass=group)" cn
        
        <#
        $ldapSearchCmdForExpect = "ldapsearch -x -h $PDC -D $BindUserNameForExpect -W -b `"$DomainLDAPContainers`" -s sub `"(objectClass=group)`" cn"

        [System.Collections.ArrayList]$ExpectScriptPrep = @(
            'expect - << EOF'
            'set timeout 120'
            "set password $BindPassword"
            'set prompt \"(>|:|#|\\\\\\$)\\\\s+\\$\"'
            "spawn $ldapSearchCmdForExpect"
            'match_max 100000'
            'expect \"Enter LDAP Password:\"'
            'send -- \"\$password\r\"'
            'expect -re \"\$prompt\"'
            'send -- \"exit\r\"'
            'expect eof'
            'EOF'
        )

        $ExpectScript = $ExpectScriptPrep -join "`n"

        #Write-Host "`$ExpectScript is:`n$ExpectScript"
        #$ExpectScript | Export-CliXml "$HOME/ExpectScript2.xml"
        
        # The below $ExpectOutput is an array of strings
        $ExpectOutput = $ldapSearchOutput = bash -c "$ExpectScript"
        #>

        $Groups = $ldapSearchOutput -match "cn:" | foreach {$_ -replace 'cn:[\s]+'}
        if ($ObjectCount -gt 0) {
            $Groups = $Groups[0..$($ObjectCount-1)]
        }
    }
    else {
        try {
            if ($LDAPCreds) {
                $LDAPUserName = $LDAPCreds.UserName
                $LDAPPassword = $LDAPCreds.GetNetworkCredential().Password
                $LDAPSearchRoot = [System.DirectoryServices.DirectoryEntry]::new($LDAPUri,$LDAPUserName,$LDAPPassword)
            }
            else {
                $LDAPSearchRoot = [System.DirectoryServices.DirectoryEntry]::new($LDAPUri)
            }
            $LDAPSearcher = [System.DirectoryServices.DirectorySearcher]::new($LDAPSearchRoot)
            $LDAPSearcher.Filter = "(&(objectCategory=Group))"
            $LDAPSearcher.SizeLimit = 0
            $LDAPSearcher.PageSize = 250
            $Groups = $LDAPSearcher.FindAll() | foreach {$_.GetDirectoryEntry()}

            if ($ObjectCount -gt 0) {
                $Groups = $Groups[0..$($ObjectCount-1)]
            }
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }
    }

    $Groups

    #endregion >> Main
}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUJuyzGHJrGkyCv11+gSeo6x2e
# iGygggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFJKD47LS2kmuBNjg
# am8fHennySD0MA0GCSqGSIb3DQEBAQUABIIBAJm5egEmAczzo2copu/l+kAaBrAz
# T6/wyaINSYYWmB8SPNovHCPPCq12b6rg9isFeNa8MRgVDNJwKWao923S87LRmL6O
# 72W5e/HuGrDkgELQxGf0c1B7taSB47P3Jqg1U+KVbuDQm/u51xQzM5dZqfZcWyY0
# pL3o9Ywevdq75CcveuUC1zrOGgzYsZwKLZk+r9F/hB58Ge6v6mLC8L+HKfClzn0w
# hFjQ1p66MzP2ni/6E/n/yjrPdxgrhLpLyx1mA0bpgj40DZrSmoBKNU5W5tW1PEYW
# Z04BiWu0/BH5DrJAiZ7YnDfCl0UXnQvROXX/8Hqk7fWlRQHgsKC02xKcpMI=
# SIG # End signature block
