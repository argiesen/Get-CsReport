# Get-CsReport

This script analyzes your Lync and Skype for Business environment to provide an HTML report summarizing Active Directory, Topology, and user/object counts and server health information with resolution information to any issues that are discovered.

You may run this script directly from GitHub with the commands below:
```
$GetCsReport = Invoke-WebRequest https://raw.githubusercontent.com/argiesen/Get-CsReport/master/Get-CsReport.ps1
Invoke-Expression $($GetCsReport.Content)
```
