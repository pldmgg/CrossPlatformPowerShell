@{
    # Some defaults for all dependencies
    PSDependOptions = @{
        Target = '$ENV:USERPROFILE\Documents\WindowsPowerShell\Modules'
        AddToPath = $True
    }

    # Grab some modules without depending on PowerShellGet
    'WinSSH' = @{
        DependencyType  = 'PSGalleryNuget'
        Version         = 'Latest'
    }
    'WindowsCompatibility' = @{
        DependencyType  = 'PSGalleryNuget'
        Version         = 'Prerelease'
    }
    'NTFSSecurity' = @{
        DependencyType  = 'PSGalleryNuget'
        Version         = 'Latest'
    }
}
