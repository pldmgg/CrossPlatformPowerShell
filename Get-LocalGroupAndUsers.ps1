if ($(!$PSVersionTable.Platform -or $PSVersionTable.Platform -eq "Win32NT") -and $PSVersionTable.PSEdition -eq "Core")
    try {
        $HelperFunctions = Get-ChildItem -Path $(Join-Path $PSScriptRoot "Helpers") -File -ErrorAction Stop
        foreach ($FileItem in $HelperFunctions) {
            . $FileItem.FullName
        }
        $ModuleDependenciesMap = InvokeModuleDependencies
    }
    catch {
        $ErrMsg = "The Get-LocalGroupAndUsers function requires the helper functions folder located here: " +
        "`nPlease make sure the folder is in the same directory as the Get-LocalGroupAndUsers function. Halting!"
        Write-Error $ErrMsg
        return
    }
}

function Get-LocalGroupAndUsers {
    [CmdletBinding()]
    Param()

    if (!$PSVersionTable.Platform -or $PSVersionTable.Platform -eq "Win32NT") {
        $AllLocalUsers = Get-LocalUser
        $AllLocalGroups = Get-LocalGroup

        [System.Collections.ArrayList]$AllLocalGroupMembership = @()
        foreach ($Group in $AllLocalGroups) {
            $Users = Get-LocalGroupMember $Group | Where-Object {$_.PrincipalSource -eq "Local"} | foreach {
                if ($_.Name -match '\\') {
                    $($_.Name -split '\\')[-1]
                }
                else {
                    $_.Name
                }
            }
            if ($Users) {
                $PSObject = [pscustomobject]@{
                    Group   = $Group.Name
                    Users   = @($Users)
                }
                $null = $AllLocalGroupMembership.Add($PSObject)
            }
        }

        $AllLocalGroupMembership
    }

    if ($PSVersionTable.Platform -eq "Unix" -or $PSVersionTable.OS -match "Darwin") {
        $AllUsers = $(bash -c "getent passwd") | foreach {$($_ -split ':')[0]}
        $AllGroups = $(bash -c "getent group") | foreach {$($_ -split ':')[0]}
        [System.Collections.ArrayList]$UserAndGroups = foreach ($User in $AllUsers) {
            $Groups = $(bash -c "getent group | grep $User") | foreach {$($_ -split ':')[0]}
            [pscustomobject]@{
                User    = $User
                Groups  = [System.Collections.ArrayList]@($Groups)
            }
        }

        [System.Collections.ArrayList]$GroupAndUsers = foreach ($Group in $AllGroups) {
            $Users = foreach ($UserObj in $UserAndGroups) {
                if ($UserObj.Groups -contains $Group) {
                    $UserObj.User
                }
            }
            [pscustomobject]@{
                Group   = $Group
                Users   = [System.Collections.ArrayList]@($Users)
            }
        }

        $ActualSudoUsersPrep = foreach ($User in $AllUsers) {
            bash -c "sudo -l -U $User"
        }
        $ActualSudoUsers = $ActualSudoUsersPrep -match "User.*may run .*:" | foreach {$($_ -replace 'User ','' -split ' may')[0]}
        $PSObject = [pscustomobject]@{
            Group   = "sudousers"
            Users   = $ActualSudoUsers
        }
        $null = $GroupAndUsers.Add($PSObject)

        $HumanUsersPrep = bash -c "awk -F: '`$3 >= 1000 && `$1 != `"nobody`" {print `$1}' /etc/passwd"
        $HumanUsers = $HumanUsersPrep | Where-Object {$_ -notmatch "nobody"}
        $PSObject = [pscustomobject]@{
            Group   = "humanusers"
            Users   = $HumanUsers
        }
        $null = $GroupAndUsers.Add($PSObject)

        foreach ($User in $ActualSudoUsers) {
            foreach ($obj in $UserAndGroups) {
                if ($obj.User -eq $User) {
                    $null = $obj.Groups.Add("sudousers")
                }
            }
        }

        foreach ($User in $HumanUsers) {
            foreach ($obj in $UserAndGroups) {
                if ($obj.User -eq $User) {
                    $null = $obj.Groups.Add("humanusers")
                }
            }
        }

        $GroupAndUsers
    }
}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUXMsEgyk+R7RVmRzjxf85BYN0
# lZ+gggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFBBd03GM1jzOIP/h
# K8q6in1fnhHBMA0GCSqGSIb3DQEBAQUABIIBAJLq1Mf8a2WvkqQw9bzlOMfIiz/b
# PB0fXvWo0dJFt12uosy6nkJTy+88pdWdbhQZXXypIpL0SKw183fdPusM4cM6PgFR
# o0bYxwn6Qk92psyLIQLQwtMTNj7sUEnKyGplZY45JA/zHJqmphSRof9PiAwMevKt
# gNkyqJzjBzF5b5pGRlnPxJ0KAzeQMYU7dChdt8+xuD1740bq0/EPYKApmSr8wMQx
# jVFepzsQk75h3c5k27ZaUO5hF0Us0M/9Bjx7x2lICuC/aReshYOJkulmk4HKMszW
# VIZLD/gYR4PToBCYj7hfiPfvdeH+JCnls2V80JDhbONmAHU+GFiJrKrdzMI=
# SIG # End signature block
