# Example Usage: GetDomainController -Domain $(Get-CimInstance Win32_ComputerSystem).Domain
# If you don't specify -Domain, it defaults to the one you're currently on
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

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUZVj5szUJOCcyhSN15HjecMh9
# nq2gggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFLpVTW4/9OweALy0
# GdR6o2IJK+HyMA0GCSqGSIb3DQEBAQUABIIBAKImR5NPQFLPPRVeQHjHYBF18tFm
# FRBYwlX4Dt02ksl2w+uYznT3bpc+wcUer9xI4vDSidnH8OFabxptNqlEjEWrWtpy
# JdFCSC2SME6zPkdn5ZetdW3dMU9IWP+EbYHOxREInVKb5I1sZ0ngiGj/Q8BzuXJF
# riIjkbg0o9xTf44fO/66IeZtUmLIC+HunIofFL3E7yZE/nSy9+N8HQpAPBAGvb8h
# 8mIG32fMCnDPJ9d1mpvBuhP7Eb8Z7a3Tr8Q6itjvGIm6C5nFffKa9ogflAkZOIX4
# oTflmog83cZGvmZqcfUiQowA9oam0AI97Mgn+WFeA4WYpj+XNxPYFOV7N54=
# SIG # End signature block
