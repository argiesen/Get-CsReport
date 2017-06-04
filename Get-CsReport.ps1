#https://sysadmins.lv/blog-en/test-whether-ca-server-is-online-and-which-interfaces-are-available.aspx
function Test-CAOnline {
	[CmdletBinding()]
	param(
		[Parameter(Position = 0)]
		[string]$Config,
		[switch]$ShowUI
	)
	
$signature = @"
[DllImport("Certadm.dll", CharSet=CharSet.Auto, SetLastError=true)]
public static extern bool CertSrvIsServerOnline(
	string pwszServerName,
	ref bool pfServerOnline
);
"@
	
    Add-Type -MemberDefinition $signature -Namespace CryptoAPI -Name CertAdm
    $CertConfig = New-Object -ComObject CertificateAuthority.Config
    if ($Config -ne "" -and !$Config.Contains("\")) {
        Write-Error -Category InvalidArgument -ErrorId InvalidArgumentException -Message "Config string must be passed in 'CAHostName\CAName' form."
        break
    } elseif ($Config -eq "" -and !$ShowUI) {
        try {$Config = $CertConfig.GetConfig(0x3)}
        catch {
            Write-Error -Category ObjectNotFound -ErrorId ObjectNotFoundElement -Message "Certificate Services are not installed on local computer."
            break
        }
    } elseif ($Config -eq "" -and $ShowUI) {
        $Config = $CertConfig.GetConfig(0x1)
    }
	
    if ($Config) {
        [void]($Config -match "(.+)\\(.+)")
        $Server = $matches[1]
        $CAName = $matches[2]
        $ServerStatus = $false
        $hresult = [CryptoAPI.CertAdm]::CertSrvIsServerOnline($Server,[ref]$ServerStatus)
        if ($ServerStatus) {
            $CertAdmin = New-Object -ComObject CertificateAuthority.Admin
            $CertRequest = New-Object -ComObject CertificateAuthority.Request
            $CA = New-Object psobject -Property @{
                Name = $CAName;
                ICertAdmin = $true;
                ICertRequest = $true
            }
            try {$retn = $CertAdmin.GetCAProperty($Config,0x6,0,4,0)}
            catch {$CA.ICertAdmin = $false}
            try {$retn = $CertRequest.GetCAProperty($Config,0x6,0,4,0)}
            catch {$CA.ICertRequest = $false}
            $CA
        } else {
            Write-Error -Category ObjectNotFound -ErrorId ObjectNotFoundException -Message "Unable to find a Certification Authority server on '$Server'."
        }
    } else {return}
}


#https://msdn.microsoft.com/en-us/library/hh925568%28v=vs.110%29.aspx
$VersionHashNDP = @{
	378389="4.5"
	378675="4.5.1"
	378758="4.5.1"
	379893="4.5.2"
	393295="4.6"
	393297="4.6"
	394254="4.6.1"
	394271="4.6.1"
	394747="4.6.2"
	394748="4.6.2"
	394802="4.6.2"
	394806="4.6.2"
	460798="4.7"
	460805="4.7"
}

$reportime = Get-Date

<# $HtmlHead="<html>
		   <style>
		   BODY{font-family: Arial; font-size: 10pt; margin:45px; padding:0;}
		   H1{font-size: 16px;}
		   H2{font-size: 14px;}
		   H3{font-size: 12px;}
		   TABLE{border: 1px solid black; border-collapse: collapse; font-size: 10pt;}
		   TH{border: 1px solid black; background: #dddddd; padding: 5px; color: #000000;}
		   TD{border: 1px solid black; padding: 5px;}
		   td.pass{background: #7FFF00;}
		   td.warn{background: #FFFF00;}
		   td.fail{background: #FF0000; color: #ffffff;}
		   td.info{background: #85D4FF;}
		   td.none{}
		   tr:nth-child(even){background: #dae5f4;}
		   tr:nth-child(odd){background: #b8d1f3;}
		   </style>
		   <body>
		   <h1 align=""center"">Lync/Skype for Business Topology Report</h1>
		   <h3 align=""center"">Generated: $reportime</h3>" #>
		   
$HtmlHead = "<html>
	<style>
	BODY{font-family: Arial; font-size: 10pt;}
	H1{font-size: 22px;}
	H2{font-size: 20px; padding-top: 10px;}
	H3{font-size: 16px; padding-top: 8px;}
	TABLE{border: 1px solid black; border-collapse: collapse; font-size: 8pt; table-layout: fixed;}
	TABLE.csservers{table-layout: auto; width: 850px;}
	TABLE.testresults{width: 850px;}
	TABLE.summary{text-align: center; width: auto;}
	TH{border: 1px solid black; background: #dddddd; padding: 5px; color: #000000;}
	TH.summary{width: 80px;}
	TH.test{width: 120px;}
	TH.description{width: 150px;}
	TH.outcome{width: 50px}
	TH.comments{width: 120px;}
	TH.details{width: 270px;}
	TH.reference{width: 60px;}
	TD{border: 1px solid black; padding: 5px; vertical-align: top;}
	td.pass{background: #7FFF00;}
	td.warn{background: #FFFF00;}
	td.fail{background: #FF0000; color: #ffffff;}
	td.info{background: #85D4FF;}
	td.none{}
	ul{list-style: inside; padding-left: 0px;}
	</style>
	<body>
	<h1>Skype for Business Report</h1>
	<p>Generated: $reportime</p>"

## Gather summary info
$htmltableheader = "<h2>Environment Overview</h2>
	<p></p>"

## Collect AD forest properties
#$adForest = Get-ADForest | Select-Object Name,RootDomain,ForestMode,DomainNamingMaster,SchemaMaster,@{name='Sites';expression={$_.Sites -join ','}},@{name='GlobalCatalogs';expression={$_.GlobalCatalogs -join ','}},@{name='UPNSuffixes';expression={$_.UPNSuffixes -join ','}}
#$adForest = Get-ADForest | Select-Object Name,RootDomain,ForestMode,DomainNamingMaster,SchemaMaster,@{name='Sites';expression={$_.Sites -join ','}},@{name='UPNSuffixes';expression={$_.UPNSuffixes -join ','}}
$adForest = Get-ADForest | Select-Object `
	Name,`
	RootDomain,`
	ForestMode,`
	Sites,`
	UPNSuffixes

## Collect AD domain properties
#$adDomain = Get-ADDomain | Select-Object Name,Forest,NetBIOSName,ParentDomain,@{name='ChildDomains';expression={$_.ChildDomains -join ','}},DomainMode,PDCEmulator,RIDMaster,InfrastructureMaster,@{name='ReadOnlyReplicaDirectoryServers';expression={$_.ReadOnlyReplicaDirectoryServers -join ','}}
$adDomain = Get-ADDomain | Select-Object `
	Name,`
	Forest,`
	NetBIOSName,`
	DNSRoot,`
	ParentDomain,`
	@{name='ChildDomains';expression={$_.ChildDomains -join ','}},`
	DomainMode

## Collect Domain Controllers
try {
	$adDomainControllers = Get-ADDomainController -Filter * | Select-Object `
		Site,`
		HostName,`
		IPv4Address,`
		OperatingSystem,`
		OperatingSystemVersion,`
		@{name='OperationMasterRoles';expression={$_.OperationMasterRoles -join ', '}},`
		IsGlobalCatalog,`
		IsReadOnly
}catch{
	#continue
}

## Collect users for global usage
$users = Get-CsUser -WarningAction SilentlyContinue -ErrorAction SilentlyContinue

## Collect users who are disabled in AD but enabled in Skype
$disabledAdUsers = Get-CsAdUser -ResultSize Unlimited | `
	Where-Object {$_.UserAccountControl -match "AccountDisabled" -and $_.Enabled -eq $true} | `
	Select-Object Name,Enabled,SipAddress

## Collect analog devices
$analogDevices = Get-CsAnalogDevice | Where-Object Enabled -eq $true
	
## Collect common area phones
$commonAreaPhones = Get-CsCommonAreaPhone | Where-Object Enabled -eq $true

## Find internal CAs
$adRoot = [ADSI]"LDAP://RootDSE"
$adDN = $adRoot.Get("rootDomainNamingContext")
$configRoot = [ADSI]"LDAP://CN=Configuration,$adDN"
$query = new-object System.DirectoryServices.DirectorySearcher($configRoot)
$query.filter = "(&(objectClass=PKIEnrollmentService)(CN=*))"
$query.SearchScope = "subtree"
$caResults = $query.findall()
$CAs = @()

foreach ($ca in $caResults){
	$output = $CA.GetDirectoryEntry()
	
	$caOut = "" | Select-Object CommonName,Server,WebServerTemplate,Online
	$caOut.Server = $output.dnsHostName | Out-String
	$caOut.CommonName = $output.cn | Out-String
	
	if (!((Test-CAOnline -Config "$($output.dnsHostName)\$($output.cn)" -ErrorAction SilentlyContinue).ICertRequest)){
		$caOut.Online = $false
		$CAs += $caOut
		continue
	}else{
		$caOut.Online = $true
	}
	
	if ($output.certificateTemplates -match "^WebServer$"){
		$caOut.WebServerTemplate = $true
	}else{
		$caOut.WebServerTemplate = $false
	}
	$CAs += $caOut
}

## Create global user summary table and populate
$globalSummary = "" | Select-Object Sites,Users,"Disabled Users","Voice Users","RCC Users","Analog Devices","Common Area Phones",Pools,Trunks
$globalSummary.Users = ($users | Where-Object {$_.Enabled -eq $true}).Count
$globalSummary."Disabled Users" = $disabledAdUsers.Count
$globalSummary."Voice Users" = ($users | Where-Object {$_.Enabled -eq $true -and $_.EnterpriseVoiceEnabled -eq $true}).Count
$globalSummary."RCC Users" = ($users | Where-Object {$_.Enabled -eq $true -and $_.RemoteCallControlTelephonyEnabled -eq $true}).Count
$globalSummary."Analog Devices" = $analogDevices.Count
$globalSummary."Common Area Phones" = $commonAreaPhones.Count
$globalSummary.Pools = (Get-CsPool | Where-Object Services -match "Registrar").Count
$globalSummary.Sites = (Get-CsSite).Count
$globalSummary.Trunks = (Get-CsTrunk).Count

## Build AD site HTML list
foreach ($site in $($adForest.Sites)){
	$adSites += "<li>$site</li>"
}
$adSites = "<ul>
	$adSites
	</ul>"

## Convert global summary tables to HTML and combine with body
$HtmlBody = "$htmltableheader
	<h3>Active Directory</h3>
	<p><b>Forest Name:</b> $($adForest.Name)</br>
	<b>Forest Mode:</b> $($adForest.ForestMode)</br>
	<b>Domain Name:</b> $($adDomain.DNSRoot) ($($adDomain.NetBIOSName))</br>
	<b>Domain Mode:</b> $($adDomain.DomainMode)</br>
	<b>UPN Suffixes:</b> $($adForest.UPNSuffixes)</br>
	<b>Sites:</b></br>
	$adSites</p>
	</br>"
	if ($adDomainControllers){
		$HtmlBody += "<h3>Domain Controllers</h3>
			<p>$($adDomainControllers | ConvertTo-Html -As Table -Fragment)</p>"
	}
	if ($CAs){
		$caHtmlTableHeader = "<table>
			<tr>
			<th>Common Name</th>
			<th>Server</th>
			<th>Online</th>
			</tr>"
	
		$caHtmlTable = "<h3>Certificate Authority</h3>"
		## Build CA HTML table rows
		foreach ($ca in $CAs){
			$htmlTableRow = "<tr>"
			$htmlTableRow += "<td>$($ca.CommonName)</td>"
			$htmlTableRow += "<td>$($ca.Server)</td>"
			if ($ca.Online){$style="none"}else{$style="fail"}
			$htmlTableRow += "<td class=""$style"">$($ca.Online)</td>"
			
			if (!($ca.Online)){$caWarnMessages += "<li>$($ca.Server): Server is unavailable.</li>"}
			if (!($ca.WebServerTemplate)){$caWarnMessages += "<li>$($ca.Server): Web server template is unavailable.</li>"}
			
			$caHtmlTable = $caHtmlTable + $htmlTableRow
		}
		
		$caHtmlTable = $caHtmlTableHeader + $caHtmlTable + "</table>"
		
		$HtmlBody += $caHtmlTable
		
		if ($caWarnMessages){
			$caHtmlWarn = "<p>Warning Items</p>
				<ul>
				$caWarnMessages
				</ul>"
			
			$HtmlBody = $HtmlBody + $caHtmlWarn
		}
	}
$HtmlBody += "<h3>Summary</h3>
	<p>$($globalSummary | ConvertTo-Html -As Table -Fragment)</p>"


if ($globalSummary."Disabled Users" -gt 0){$globalWarnMessages += "<li>Users exist that are disabled in AD but are enabled for Skype. These users may still be able to login to Skype.</li>"}
if ($globalWarnMessages){
	$globalHtmlWarn = "<p>Warning Items</p>
		<ul>
		$globalWarnMessages
		</ul>"

	$HtmlBody = $HtmlBody + $globalWarnMessages
}

## Gather sites info
$sites = Get-CsSite | Select-Object Identity,@{l='Name';e={$_.DisplayName}},Users,"Voice Users","RCC Users",Pools,Trunks
$pools = Get-CsPool | Where-Object Services -match "Registrar|PersistentChatServer|MediationServer|Director"

## Process each site in topology for site summary, then server summary
foreach ($site in $sites){
	$sitePools = $pools | Where-Object {$_.Site -eq $site.Identity} | Select-Object @{l='Name';e={$_.Fqdn}},Services,Users,"Voice Users","RCC Users"
	$site.Users = 0
	$site."Voice Users" = 0
	$site."RCC Users" = 0
	$site.Pools = (Get-CsPool | Where-Object {$_.Services -match "Registrar" -and $_.Site -eq $site.Identity}).Count
	$site.Trunks = (Get-CsTrunk | Where-Object SiteId -eq $site.Identity).Count
	$siteServers = @()
	
	## If pools exist in site, process pools for servers
	if ($sitePools){
		## Process pools in site
		foreach ($pool in $sitePools){
			#$pool.Name = $pool.Fqdn
			$pool.Users = ($users | Where-Object {$_.Enabled -eq $true -and $_.RegistrarPool -match $pool.Name}).Count
			$pool."Voice Users" = ($users | Where-Object {$_.Enabled -eq $true -and $_.EnterpriseVoiceEnabled -eq $true -and $_.RegistrarPool -match $pool.Name}).Count
			$pool."RCC Users" = ($users | Where-Object {$_.Enabled -eq $true -and $_.RemoteCallControlTelephonyEnabled -eq $true -and $_.RegistrarPool -match $pool.Name}).Count
			
			$site.Users = $site.Users + $pool.Users
			$site."Voice Users" = $site."Voice Users" + $pool."Voice Users"
			$site."RCC Users" = $site."RCC Users" + $pool."RCC Users"
			
			$servers = (Get-CsPool $pool.Name).Computers | Select-Object `
				Pool,`
				@{l='Server';e={$_}},`
				Role,`
				Hardware,`
				vmTools,`
				Sockets,`
				Cores,`
				Memory,`
				HDD,`
				PowerPlan,`
				Uptime,`
				OS,`
				DotNet,`
				DnsCheck,`
				LastUpdate,`
				Connectivity,`
				Permission
			
			## Process servers in pool
			foreach ($server in $servers){
				if ($pool.Services -match "Registrar" -and $pool.Services -match "UserServer"){
					$server.Role = "Front End"
				}elseif ($pool.Services -match "Registrar"){
					$server.Role = "SBA/SBS"
				}elseif ($pool.Services -match "Director"){
					$server.Role = "Director"
				}elseif ($pool.Services -match "PersistentChatServer"){
					$server.Role = "pChat"
				}elseif ($pool.Services -match "MediationServer"){
					$server.Role = "Mediation"
				}
				
				$server.Pool = $pool.Name
				$server.Connectivity = Test-Connection -ComputerName $server.Server -Count 1 -ErrorAction SilentlyContinue
				
				$error.Clear()
				Get-WmiObject Win32_ComputerSystem -ComputerName $server.Server -ErrorAction SilentlyContinue | Out-Null
				if ($error.Exception.Message -match "access denied"){
					$server.Permission = $false
				}else{
					$server.Permission = $true
				}
				
				if ($server.Connectivity -and $server.Permission){
					$computer = Get-WmiObject Win32_ComputerSystem -ComputerName $server.Server -ErrorAction SilentlyContinue
					if ($computer.Manufacturer -match "VMware"){
						$server.Hardware = "VMware"
					}elseif ($computer.Manufacturer -match "Microsoft"){
						$server.Hardware = "Microsoft"
					}else{
						$server.Hardware = "$($computer.Manufacturer) $($computer.Model)"
					}
					if ($server.Hardware -eq "VMware"){
						$server.vmTools = Invoke-Command -ComputerName $server.Server -ScriptBlock {Set-Location (Get-Item "HKLM:\Software\VMware, Inc.\VMware Tools").GetValue("InstallPath");Invoke-Expression ".\VMwareToolboxCmd.exe upgrade status"}
						if (!($server.vmTools)){
							$server.vmTools = "Not Installed"
						}elseif ($server.vmTools -match "up-to-date"){
							$server.vmTools = "Up-to-date"
						}else{
							$server.vmTools = "Update available"
						}
					}else{
						$server.vmTools = "N/A"
					}
					$processors = Get-WmiObject Win32_Processor -ComputerName $server.Server | Select-Object Name,MaxClockSpeed,CurrentClockSpeed,NumberOfCores,NumberOfLogicalProcessors
					$server.Sockets = $processors.Count
					if (!($server.Sockets)){$server.Sockets = 1}
					$server.Cores = $processors[0].NumberOfCores * ($processors | measure).Count
					$server.Memory = (Get-WmiObject Win32_OperatingSystem -ComputerName $server.Server | Select-Object @{l='TotalMemory';e={"{0:N2}" -f ($_.TotalVisibleMemorySize/1MB)}}).TotalMemory
					$server.HDD = Get-WmiObject Win32_Volume -Filter 'DriveType = 3' -ComputerName $server.Server | Where-Object DriveLetter -ne $null | Select-Object DriveLetter,Label,@{l='CapacityGB';e={$_.Capacity/1GB}},@{l='FreeSpaceGB';e={$_.FreeSpace/1GB}},@{l='FreeSpacePercent';e={($_.FreeSpace/$_.Capacity)*100}}
					$server.PowerPlan = (Get-WmiObject Win32_PowerPlan -ComputerName $server.Server -Namespace root\cimv2\power -Filter "IsActive='$true'").ElementName
					$boot = Get-WmiObject Win32_OperatingSystem -ComputerName $server.Server
					$server.Uptime = (($boot.ConvertToDateTime($boot.LocalDateTime) - $boot.ConvertToDateTime($boot.LastBootUpTime)).Days * 24) + ($boot.ConvertToDateTime($boot.LocalDateTime) - $boot.ConvertToDateTime($boot.LastBootUpTime)).Hours
					$server.OS = (Get-WmiObject Win32_OperatingSystem -ComputerName $server.Server).Caption
					$server.DotNet = Invoke-Command -ComputerName $server.Server -ScriptBlock {(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -Name "Release").Release}
					$server.DotNet = $VersionHashNDP.Item($server.DotNet)
					if (Resolve-DnsName $server.Server -DnsOnly -Type A -QuickTimeout){$server.DnsCheck = "Pass"}else{$server.DnsCheck = "Fail"}
					$server.LastUpdate = ((Get-HotFix -ComputerName $server.Server | Sort-Object InstalledOn -Descending -ErrorAction SilentlyContinue)[0]).InstalledOn
				}
			}
			
			## Aggregate servers from each pool in site
			$siteServers += $servers
		}
		
		foreach ($server in $siteServers){
			$style = "" | Select-Object Server,Hardware,vmTools,Sockets,Cores,Memory,HDD,PowerPlan,Uptime,OS,DotNet,DNS,LastUpdate
			#$hddList = @()
			if ($server.Connectivity -and $server.Permission){
				if ($server.vmTools -match "(Up-to-date|N/A)"){$style.vmTools = "none"}elseif($server.vmTools -match "Not Installed"){$style.vmTools = "fail"}else{$style.vmTools = "warn"}
				if ($server.Sockets -gt 2){$style.Sockets = "warn"}else{$style.Sockets = "none"}
				if (($server.Cores * $server.Sockets) -lt 6){$style.Cores = "warn"}else{$style.Cores = "none"}
				if ($server.Memory -lt 16){$style.Memory = "warn"}else{$style.Memory = "none"}
				$server.Memory = "$('{0:N2}GB' -f $server.Memory)"
				if ($server.HDD.FreeSpaceGB -lt 32){$style.HDD = "warn"}else{$style.HDD = "none"}
				<# foreach ($hdd in $server.HDD){
					$hddList += "$($hdd.DriveLetter) $('{0:N2}GB' -f $hdd.FreeSpaceGB)/$('{0:N2}GB' -f $hdd.CapacityGB)"
				} #>
				if ($server.PowerPlan -eq "High Performance"){$style.PowerPlan = "none"}else{$style.PowerPlan = "fail"}
				if ($server.Uptime -gt 2160){$style.Uptime = "warn"}else{$style.Uptime = "none"}
				if ($server.OS -notmatch "Server (2016|2012|2012 R2|2008 R2)"){$style.OS = "fail"}else{$style.OS = "none"}
				$server.OS = $server.OS -replace "Microsoft Windows",""
				if ($server.DotNet -notmatch "(4.6.2|4.5.2)"){$style.DotNet = "warn"}else{$style.DotNet = "none"}
				if ($server.DnsCheck -ne "Pass"){$style.DNS = "fail"}else{$style.DNS = "none"}
				if ($server.LastUpdate -lt (Get-Date).addDays(-90)){$style.LastUpdate = "warn"}else{$style.LastUpdate = "none"}
				$server.LastUpdate = ($server.LastUpdate).ToString('MM/dd/yyyy')
			}else{
				$style.Server = "fail"
				$style.vmTools = "none"
				$style.Sockets = "none"
				$style.Cores = "none"
				$style.Memory = "none"
				$style.HDD = "none"
				$style.PowerPlan = "none"
				$style.Uptime = "none"
				$style.OS = "none"
				$style.DotNet = "none"
				$style.DNS = "none"
				$style.LastUpdate = "none"
			}
			
			## Build servers HTML table header
			$siteServersHtmlTableHeader = "<table class=""csservers"">
				<tr>
				<th>Pool</th>
				<th>Server</th>
				<th>Role</th>
				<th>Hardware</th>
				<th>VMware Tools</th>
				<th>Sockets</th>
				<th>Cores</th>
				<th>Memory</th>
				<th>HDD</th>
				<th>Power Plan</th>
				<th>Uptime</th>
				<th>OS</th>
				<th>.NET</th>
				<th>DNS</th>
				<th>Last Update</th>
				</tr>"
							
			$siteServersHtmlTable = $siteServersHtmlTableHeader
			
			## Build servers HTML table rows
			$htmlTableRow = "<tr>"
			$htmlTableRow += "<td><b>$(($server.Pool).Split(".")[0])</b></td>"
			$htmlTableRow += "<td class=""$($style.Server)"">$(($server.Server).Split(".")[0])</td>"
			$htmlTableRow += "<td>$($server.Role)</td>"
			$htmlTableRow += "<td>$($server.Hardware)</td>"
			$htmlTableRow += "<td class=""$($style.vmTools)"">$($server.vmTools)</td>"
			$htmlTableRow += "<td class=""$($style.Sockets)"">$($server.Sockets)</td>"
			$htmlTableRow += "<td class=""$($style.Cores)"">$($server.Cores)</td>"
			$htmlTableRow += "<td class=""$($style.Memory)"">$($server.Memory)</td>"
			$htmlTableRow += "<td class=""$($style.HDD)""><ul>"
			foreach ($hdd in $server.HDD){
				$htmlTableRow += "<li>$($hdd.DriveLetter) $('{0:N2}GB' -f $hdd.FreeSpaceGB)/$('{0:N2}GB' -f $hdd.CapacityGB)</li>"
			}
			$htmlTableRow += "</ul></td>"
			$htmlTableRow += "<td class=""$($style.PowerPlan)"">$($server.PowerPlan)</td>"
			$htmlTableRow += "<td class=""$($style.Uptime)"">$($server.Uptime)</td>"
			$htmlTableRow += "<td class=""$($style.OS)"">$($server.OS)</td>"
			$htmlTableRow += "<td class=""$($style.DotNet)"">$($server.DotNet)</td>"
			$htmlTableRow += "<td class=""$($style.DNS)"">$($server.DnsCheck)</td>"
			$htmlTableRow += "<td class=""$($style.LastUpdate)"">$($server.LastUpdate)</td>"
			$htmlTableRow += "</tr>"
			
			$siteServersHtmlTable = $siteServersHtmlTable + $htmlTableRow
		}
		
		## Close servers HTML table
		$siteServersHtmlTable = $siteServersHtmlTable + "</table>"
		
		## Convert site header, site summary, and site server summary to HTML and combine with body
		$HtmlBody += "<h2>$($Site.Name) Breakdown</h2>
			<p>$($site | Select-Object * -ExcludeProperty Identity,Name | ConvertTo-Html -As Table -Fragment)</p>
			<p>$siteServersHtmlTable</p>
			</br>"
	}
}

## Close Report
$HtmlTail = "</body>
	</html>"

$htmlReport = $HtmlHead + $HtmlBody + $HtmlTail

$htmlReport | Out-File CsReport.html -Encoding UTF8

.\CsReport.html