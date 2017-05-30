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
	394806="4.6.2"
	460798="4.7"
}

$reportime = Get-Date

$HtmlHead="<html>
		   <style>
		   BODY{font-family: Arial; font-size: 8pt;}
		   H1{font-size: 16px;}
		   H2{font-size: 14px;}
		   H3{font-size: 12px;}
		   TABLE{border: 1px solid black; border-collapse: collapse; font-size: 8pt;}
		   TH{border: 1px solid black; background: #dddddd; padding: 5px; color: #000000;}
		   TD{border: 1px solid black; padding: 5px;}
		   td.pass{background: #7FFF00;}
		   td.warn{background: #FFE600;}
		   td.fail{background: #FF0000; color: #ffffff;}
		   td.info{background: #85D4FF;}
		   </style>
		   <body>
		   <h1 align=""center"">Skype for Business 2015 Report</h1>
		   <h3 align=""center"">Generated: $reportime</h3>"





## Gather summary info
<# $htmltableheader = "<h2>Summary</h2>
					<p>
					<table>
					<tr>
					<th>Sites</th>
					<th>Pools</th>
					<th>Trunks</th>
					<th>Users</th>
					<th>Voice Users</th>
					<th>RCC Users</th>
					</tr>"

$summaryHtmlTable = $htmlTableHeader #>

$htmltableheader = "<h2>Summary</h2>
					<p>"

$users = Get-CsUser -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
<# $totalUsers = ($users | where {$_.Enabled -eq $true}).Count
$totalEvUsers = ($users | where {$_.Enabled -eq $true -and $_.EnterpriseVoiceEnabled -eq $true}).Count
$totalRccUsers = ($users | where {$_.Enabled -eq $true -and $_.RemoteCallControlTelephonyEnabled -eq $true}).Count
$totalRegistrarPools = (Get-CsPool | where Services -match "Registrar").Count
$totalSites = (Get-CsSite).Count
$totalTrunks = (Get-CsTrunk).Count

$htmlTableRow = "<tr>"
$htmlTableRow += "<td>$($totalSites)</td>"
$htmlTableRow += "<td>$($totalRegistrarPools)</td>"
$htmlTableRow += "<td>$($totalTrunks)</td>"
$htmlTableRow += "<td>$($totalUsers)</td>"
$htmlTableRow += "<td>$($totalEvUsers)</td>"
$htmlTableRow += "<td>$($totalRccUsers)</td>"
$htmlTableRow += "</tr>"

$summaryHtmlTable = $summaryHtmlTable + $htmlTableRow
$SummaryHtml = $summaryHtmlTable + "</table></p>" #>

$userSummary = "" | select Users,"Voice Users","RCC Users",Pools,Sites,Trunks
$userSummary.Users = ($users | where {$_.Enabled -eq $true}).Count
$userSummary."Voice Users" = ($users | where {$_.Enabled -eq $true -and $_.EnterpriseVoiceEnabled -eq $true}).Count
$userSummary."RCC Users" = ($users | where {$_.Enabled -eq $true -and $_.RemoteCallControlTelephonyEnabled -eq $true}).Count
$userSummary.Pools = (Get-CsPool | where Services -match "Registrar").Count
$userSummary.Sites = (Get-CsSite).Count
$userSummary.Trunks = (Get-CsTrunk).Count

$SummaryHtml = $htmltableheader + ($userSummary | ConvertTo-Html -As Table -Fragment)

## Gather sites info
<# $htmltableheader = "<h2>Summary</h2>
					<p>
					<table>
					<tr>
					<th>Sites</th>
					<th>Pools</th>
					<th>Trunks</th>
					<th>Users</th>
					<th>Voice Users</th>
					<th>RCC Users</th>
					</tr>"
					
$siteSummaryHtmlTable = $htmlTableHeader #>

#$sites = Get-CsSite
$sites = Get-CsSite | select Identity,@{l='Name';e={$_.DisplayName}},Pools,Trunks,Users,"Voice Users","RCC Users"
$pools = Get-CsPool | where Services -match "Registrar|PersistentChatServer|MediationServer|Director"

foreach ($site in $sites){
	$sitePools = $pools | where {$_.Site -eq $site.Identity} | select @{l='Name';e={$_.Fqdn}},Services,Pools,Users,"Voice Users","RCC Users"
	$site.Users = 0
	$site."Voice Users" = 0
	$site."RCC Users" = 0
	$site.Pools = (Get-CsPool | where {$_.Services -match "Registrar" -and $_.Site -eq $site.Identity}).Count
	$site.Trunks = (Get-CsTrunk | where SiteId -eq $site.Identity).Count
	$siteServers = @()
	
	$siteServersHtml = "<h3>$($Site.Name) Servers</h3>
						<p>"
	
	if ($sitePools){
		## Begin list of pools by site
		foreach ($pool in $sitePools){
			#$pool.Name = $pool.Fqdn
			$pool.Users = ($users | where {$_.Enabled -eq $true -and $_.Registrar -eq $pool.Name}).Count
			$pool."Voice Users" = ($users | where {$_.Enabled -eq $true -and $_.EnterpriseVoiceEnabled -eq $true -and $_.Registrar -eq $pool.Name}).Count
			$pool."RCC Users" = ($users | where {$_.Enabled -eq $true -and $_.RemoteCallControlTelephonyEnabled -eq $true -and $_.Registrar -eq $pool.Name}).Count
			
			$site.Users = $site.Users + $pool.Users
			$site."Voice Users" = $site."Voice Users" + $pool."Voice Users"
			$site."RCC Users" = $site."RCC Users" + $pool."RCC Users"
			
			## Begin list of servers by pool
			#$AllPoolServersHtml = "<h3>Pool Servers</h3>"
			
			<# $htmlTableHeader = "<table>
								<tr>
								<th>Pool FQDN</th>
								<th>Server FQDN</th>
								<th>CPU Cores</th>
								<th>Memory</th>
								<th>Power Plan</th>
								<th>Uptime</th>
								<th>OS</th>
								<th>.NET Framework</th>
								<th>DNS</th>
								<th>Last Update</th>
								</tr>"
			
			$poolServersHtmlTable = $htmlTableHeader #>
			
			$servers = (Get-CsPool $pool.Name).Computers | select Pool,@{l='Server';e={$_}},Role,Sockets,Cores,Memory,"Power Plan",Uptime,"Operating System",".NET Framework",DnsCheck,"Last Update"
			
			foreach ($server in $servers){
				<# $entry = "" | select ServerFqdn,CpuCores,Memory,PowerPlan,Uptime,OSVersion,NetFrameworkVersion,DnsCheck,LastUpdate
				$entry.ServerFqdn = $server #>
				if ($pool.Services -match "Registrar"){
					$server.Role = "Front End"
				}elseif ($pool.Services -match "Director"){
					$server.Role = "Director"
				}elseif ($pool.Services -match "PersistentChatServer"){
					$server.Role = "pChat"
				}elseif ($pool.Services -match "MediationServer"){
					$server.Role = "Mediation"
				}
				$server.Pool = $pool.Name
				if (Test-Connection -ComputerName $server.Server -Count 1 -ErrorAction SilentlyContinue){
					$processors = Get-WmiObject Win32_Processor -ComputerName $server.Server | Select Name,MaxClockSpeed,CurrentClockSpeed,NumberOfCores,NumberOfLogicalProcessors
					$server.Sockets = $processors.Count
					$server.Cores = $processors[0].NumberOfCores * ($processors | measure).Count
					$server.Memory = (Get-WmiObject Win32_OperatingSystem -ComputerName $server.Server | select @{l='TotalMemory';e={"{0:N2}GB" -f ($_.TotalVisibleMemorySize/1MB)}}).TotalMemory
					$server."Power Plan" = (Get-WmiObject Win32_PowerPlan -ComputerName $server.Server -Namespace root\cimv2\power -Filter "IsActive='$true'").ElementName
					$boot = Get-WmiObject Win32_OperatingSystem -ComputerName $server.Server
					$server.Uptime = (($boot.ConvertToDateTime($boot.LocalDateTime) - $boot.ConvertToDateTime($boot.LastBootUpTime)).Days * 24) + ($boot.ConvertToDateTime($boot.LocalDateTime) - $boot.ConvertToDateTime($boot.LastBootUpTime)).Hours
					$server."Operating System" = (Get-WmiObject Win32_OperatingSystem -ComputerName $server.Server).Caption
					$server.".NET Framework" = Invoke-Command -ComputerName $server.Server -ScriptBlock {(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -Name "Release").Release}
					$server.".NET Framework" = $VersionHashNDP.Item($server.".NET Framework")
					if (Resolve-DnsName $server.Server -DnsOnly -Type A -QuickTimeout){$server.DnsCheck = "Pass"}else{$server.DnsCheck = "Fail"}
					$server."Last Update" = ((Get-HotFix -ComputerName $server.Server | Sort-Object InstalledOn -Descending -ErrorAction SilentlyContinue)[0]).InstalledOn -f "MM.dd.yy"
				}
				
				<# $htmlTableRow = "<tr>"
				$htmlTableRow += "<td>$($pool.Fqdn)</td>"
				$htmlTableRow += "<td>$($entry.ServerFqdn)</td>"
				$htmlTableRow += "<td>$($entry.CpuCores)</td>"
				$htmlTableRow += "<td>$($entry.Memory)</td>"
				$htmlTableRow += "<td>$($entry.PowerPlan)</td>"
				$htmlTableRow += "<td>$($entry.Uptime)</td>"
				$htmlTableRow += "<td>$($entry.OSVersion)</td>"
				$htmlTableRow += "<td>$($entry.NetFrameworkVersion)</td>"
				$htmlTableRow += "<td>$($entry.DnsCheck)</td>"
				$htmlTableRow += "<td>$($entry.LastUpdate)</td>"
				$htmlTableRow += "</tr>"
				
				$poolServersHtmlTable = $poolServersHtmlTable + $htmlTableRow #>
			}
			<# $poolServersHtmlTable = $poolServersHtmlTable + "</table></p>"
			$AllPoolServersHtml = $AllPoolServersHtml + $poolServersHtmlTable #>
			
			$siteServers += $servers
		} ## Close list of pools by site
		
		$site
		
		$SummaryHtml = $SummaryHtml + $siteServersHtml + ($site | select Name,Pools,Trunks,Users,"Voice Users","RCC Users" | ConvertTo-Html -As Table -Fragment) + "<p>" + ($siteServers | ConvertTo-Html -As Table -Fragment)
	}
}

## Close Report
$HtmlTail = "</body>
			 </html>"

$htmlreport = $HtmlHead + $SummaryHtml + $AllPoolServersHtml + $HtmlTail

$htmlreport | Out-File CsReport.html -Encoding UTF8

.\CsReport.html