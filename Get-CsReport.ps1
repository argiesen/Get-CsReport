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
$htmltableheader = "<h2>Summary</h2>
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

$summaryHtmlTable = $htmlTableHeader

$users = Get-CsUser -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
$totalUsers = ($users | where {$_.Enabled -eq $true}).Count
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
$SummaryHtml = $summaryHtmlTable + "</table></p>"


## Gather sites info
$htmltableheader = "<h2>Summary</h2>
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
						
$siteSummaryHtmlTable = $htmlTableHeader

$sites = Get-CsSite
$pools = Get-CsPool | where Services -match "Registrar|PersistentChatServer|MediationServer|Director"

foreach ($site in $sites){
	$sitePools = $pools | where {$_.Site -eq $site.Identity}
	$siteUsers = 0
	
	## Begin list of pools by site
	foreach ($pool in $sitepools){
		$poolName = $pool.Fqdn
		$poolUsers = ($users | where {$_.Enabled -eq $true -and $_.Registrar -eq $pool.Fqdn}).Count
		$poolEvUsers = ($users | where {$_.Enabled -eq $true -and $_.EnterpriseVoiceEnabled -eq $true -and $_.Registrar -eq $pool.Fqdn}).Count
		$poolRccUsers = ($users | where {$_.Enabled -eq $true -and $_.RemoteCallControlTelephonyEnabled -eq $true -and $_.Registrar -eq $pool.Fqdn}).Count
		
		$siteUsers = $siteUsers + $poolUsers
		
		## Begin list of servers by pool
		$AllPoolServersHtml = "<h3>Pool Servers</h3>"
		
		foreach ($pool in $pools){
			$htmlTableHeader = "<h3>$($pool.Fqdn)</h3>
								<p>
								<table>
								<tr>
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
			
			$poolServersHtmlTable = $htmlTableHeader
			
			$servers = (Get-CsPool $pool.Fqdn).Computers
			
			foreach ($server in $servers){
				$entry = "" | select ServerFqdn,CpuCores,Memory,PowerPlan,Uptime,OSVersion,NetFrameworkVersion,DnsCheck,LastUpdate
				$entry.ServerFqdn = $server
				if (Test-Connection -ComputerName $server -Count 1 -ErrorAction SilentlyContinue){
					$processors = Get-WmiObject Win32_Processor -ComputerName $server | Select Name,MaxClockSpeed,CurrentClockSpeed,NumberOfCores,NumberOfLogicalProcessors
					$entry.CpuCores = $processors[0].NumberOfCores * ($processors | measure).Count
					$entry.Memory = (Get-WmiObject Win32_OperatingSystem -ComputerName $server | select @{l='TotalMemory';e={"{0:N2}GB" -f ($_.TotalVisibleMemorySize/1MB)}}).TotalMemory
					$entry.PowerPlan = (Get-WmiObject Win32_PowerPlan -ComputerName $server -Namespace root\cimv2\power -Filter "IsActive='$true'").ElementName
					$boot = Get-WmiObject Win32_OperatingSystem -ComputerName $server
					$entry.Uptime = (($boot.ConvertToDateTime($boot.LocalDateTime) - $boot.ConvertToDateTime($boot.LastBootUpTime)).Days * 24) + ($boot.ConvertToDateTime($boot.LocalDateTime) - $boot.ConvertToDateTime($boot.LastBootUpTime)).Hours
					$entry.OSVersion = (Get-WmiObject Win32_OperatingSystem -ComputerName $server).Caption
					$entry.NetFrameworkVersion = Invoke-Command -ComputerName $server -ScriptBlock {(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -Name "Release").Release}
					if (Resolve-DnsName $server -DnsOnly -Type A -QuickTimeout){$entry.DnsCheck = "Pass"}else{$entry.DnsCheck = "Fail"}
					$entry.LastUpdate = ((Get-HotFix -ComputerName $server | Sort-Object InstalledOn -Descending -ErrorAction SilentlyContinue)[0]).InstalledOn -f "MM.dd.yy"
				}
				
				$htmlTableRow = "<tr>"
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
				
				$poolServersHtmlTable = $poolServersHtmlTable + $htmlTableRow
			}
			
			$poolServersHtmlTable = $poolServersHtmlTable + "</table></p>"
			$AllPoolServersHtml = $AllPoolServersHtml + $poolServersHtmlTable
		} ## Close list of servers by pool
	} ## Close list of pools by site
}

## Close Report
$HtmlTail = "</body>
			 </html>"

$htmlreport = $HtmlHead + $SummaryHtml + $AllPoolServersHtml + $HtmlTail

$htmlreport | Out-File CsReport.html -Encoding UTF8

.\CsReport.html