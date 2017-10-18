# Get-CsReport

This script analyzes your Lync and Skype for Business environment to provide an HTML report summarizing Active Directory, Topology, and user/object counts and server health information with resolution information to any issues that are discovered.

This script must be run from one of your Lync or Skype for Business servers. Currently Edge servers are not included. The resulting report will be saved to the desktop.

You may run this script directly from GitHub with the commands below:
```
Start-BitsTransfer https://raw.githubusercontent.com/argiesen/Get-CsReport/HTMLCSSTabbed/Get-CsReport.ps1 -Destination "$env:Temp\Get-CsReport.ps1"; Invoke-Expression "$env:Temp\Get-CsReport.ps1"
```
