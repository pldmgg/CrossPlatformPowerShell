<#
    .SYNOPSIS
        Determines if the specified user has sudo privileges on a Remote Host, and if so, whether or not they are prompted for a
        sudo password when running 'sudo pwsh'.

        Returns a pscustomobject with bool properties 'HasSudoPrivileges' and 'PasswordPrompt'.

    .DESCRIPTION
        See SYNOPSIS

    .EXAMPLE
        # Launch pwsh and...

        Get-MySudoStatus
        
#>
function Get-MySudoStatus {
    [CmdletBinding()]
    Param()

    #region >> Helper Functions

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

    #endregion >> Helper Functions

    #region >> Prep

    if (Get-Elevation) {
        Write-Error "The Get-MySudoStatus function cannot be run as root! Halting!"
        $global:FunctionResult = "1"
        return
    }

    # On Linux, under a Domain Account, 'whoami' returns something like: zeroadmin@zero.lab
    # On Linux, under a Local Account, 'whoami' returns something like: vagrant
    # On Windows under a Domain Account, 'whoami' returns something like: zero\zeroadmin
    # On Windows under a Local Account, 'whoami' returns something like: pdadmin
    $UserName = whoami
    if (!$PSVersionTable.Platform -or $PSVersionTable.Platform -eq "Win32NT") {
        if ($UserName -match '\\') {
            $DomainNameShort = $($UserName -split '\\')[0]
            $UserNameShort = $($UserName -split '\\')[-1]
        }
        else {
            $UserNameShort = $UserName
        }
    }
    elseif ($PSVersionTable.Platform -eq "Unix" -or $PSVersionTable.OS -match "Darwin") {
        if ($UserName -match '@') {
            $DomainName = $($UserName -split "@")[-1]
            $DomainNameShort = $($DomainName -split '\.')[0]
            $UserNameShort = $($UserName -split "@")[0]
        }
        else {
            $UserNameShort = $UserName
        }
    }

    #endregion >> Prep

    #region >> Main

    $PSVerTablePwshBytes = [System.Text.Encoding]::Unicode.GetBytes('$PSVersionTable')
    $EncodedCommand = [Convert]::ToBase64String($PSVerTablePwshBytes)

    [System.Collections.ArrayList]$CheckSudoStatusScriptPrep = @(
        $('prompt=$(sudo -n pwsh -EncodedCommand {0} 2>&1)' -f $EncodedCommand)
        $('if [ $? -eq 0 ]; then echo {0}; elif echo $prompt | grep -q {1}; then echo {2}; else echo {3}; fi' -f "'NoPasswordPrompt'","'^sudo'","'PasswordPrompt'","'NoSudoPrivileges'")
    )
    $CheckSudoStatusScript = $CheckSudoStatusScriptPrep -join '; '
    $Output = bash -c "$CheckSudoStatusScript"
    
    if ($Output -match 'NoPasswordPrompt') {
        $FinalOutput = [pscustomobject]@{
            HasSudoPrivileges   = $True
            PasswordPrompt      = $False
            IsDomainAccount     = if ($DomainName -or $DomainNameShort) {$True} else {$False}
            DomainInfo          = [pscustomobject]@{
                DomainName  = $DomainName
                DomainNameShort = $DomainNameShort
                UserNameShort = $UserNameShort
            }
            BashOutput          = $Output
        }
    }
    elseif ($Output -match 'PasswordPrompt') {
        $FinalOutput = [pscustomobject]@{
            HasSudoPrivileges   = $True
            PasswordPrompt      = $True
            IsDomainAccount     = if ($DomainName -or $DomainNameShort) {$True} else {$False}
            DomainInfo          = [pscustomobject]@{
                DomainName  = $DomainName
                DomainNameShort = $DomainNameShort
                UserNameShort = $UserNameShort
            }
            BashOutput          = $Output
        }
    }
    elseif ($Output -match 'NoSudoPrivileges') {
        $FinalOutput = [pscustomobject]@{
            HasSudoPrivileges   = $False
            PasswordPrompt      = $False
            IsDomainAccount     = if ($DomainName -or $DomainNameShort) {$True} else {$False}
            DomainInfo          = [pscustomobject]@{
                DomainName  = $DomainName
                DomainNameShort = $DomainNameShort
                UserNameShort = $UserNameShort
            }
            BashOutput          = $Output
        }
    }

    $FinalOutput | ConvertTo-Json

    #endregion >> Main
}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQULBbPPU9P2wtKGfVjeejDRvEz
# 2aWgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFLS8UPOqPKlmBTyW
# CFg38PxaIFlSMA0GCSqGSIb3DQEBAQUABIIBAF00LbyEnwqj87B4lDBwVYuzQoNb
# gwo48sbufdocUcBkwJxO19hCA2SgMEMbEJI/w00YisEpyG23lJW1IlZ7N5mLCn3E
# fAOHOTL6ziHGLwJqvTJgtcrVx68fAXPMO5+ZX70LfpSt112n/PfVZ7YEFyLcXhZc
# irLp7H5pzZdQCVftQqOvxaX0kFgAHppAaKfXQr02nCha/Hdo3vEe9cXBlmlufWsi
# ed59Nm472LZAiK3KgG+GwcXh21mu0E5d7UzQe7m2evJtQH0ddpiVasLQXaSSHket
# vzgIUGtlmTJIL9AvHMOgBWwiUJn1PWzADun8cpHee1X6Gqf4gbPgdXvmklA=
# SIG # End signature block
