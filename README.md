# CrossPlatformPowerShell

A collection of PowerShell functions that work on Windows Powershell 5.1 and PowerShell Core (Windows, Linux, and MacOS)

## Getting Started

Download the function you're interested to a file of the same name. Then, simply dotsource it:

```powershell
. ./<NameOfFunction>.ps1
```

IMPORTANT NOTE: On Windows, using PowerShell Core, some functions depend on the funcitons in the "Helper" folder. Simply place the "Helper" folder in the same directory as the function you would like to use. Functions that require these Helper functions will start with the following code:

```powershell
if ($(!$PSVersionTable.Platform -or $PSVersionTable.Platform -eq "Win32NT") -and $PSVersionTable.PSEdition -eq "Core") {
    try {
        $HelperFunctions = Get-ChildItem -Path $(Join-Path $PSScriptRoot "Helpers") -File -ErrorAction Stop
        foreach ($FileItem in $HelperFunctions) {
            . $FileItem.FullName
        }
        $ModuleDependenciesMap = InvokeModuleDependencies
    }
    catch {
        Write-Error $_
        $ErrMsg = "The Get-LocalGroupAndUsers function requires a Helper functions folder containing all functions located here: " +
        "https://github.com/pldmgg/CrossPlatformPowerShell/tree/master/Helpers" +
        "`nPlease make sure the Helpers folder is in the same directory as the Get-LocalGroupAndUsers function. Halting!"
        Write-Error $ErrMsg
        return
    }
}
``
