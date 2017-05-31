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
		   td.warn{background: #FFFF00;}
		   td.fail{background: #FF0000; color: #ffffff;}
		   td.info{background: #85D4FF;}
		   td.none{}
		   tr:nth-child(even){background: #dae5f4;}
		   tr:nth-child(odd){background: #b8d1f3;}
		   </style>
		   <body>
		   <h1 align=""center"">Lync/Skype for Business Topology Report</h1>
		   <h3 align=""center"">Generated: $reportime</h3>"

## Gather summary info
$htmltableheader = "<h2>Global Summary</h2>
					<p></p>"

## Collect users for global usage
$users = Get-CsUser -WarningAction SilentlyContinue -ErrorAction SilentlyContinue

## Create global user summary table and populate
$userSummary = "" | Select-Object Sites,Users,"Voice Users","RCC Users",Pools,Trunks
$userSummary.Users = ($users | Where-Object {$_.Enabled -eq $true}).Count
$userSummary."Voice Users" = ($users | Where-Object {$_.Enabled -eq $true -and $_.EnterpriseVoiceEnabled -eq $true}).Count
$userSummary."RCC Users" = ($users | Where-Object {$_.Enabled -eq $true -and $_.RemoteCallControlTelephonyEnabled -eq $true}).Count
$userSummary.Pools = (Get-CsPool | Where-Object Services -match "Registrar").Count
$userSummary.Sites = (Get-CsSite).Count
$userSummary.Trunks = (Get-CsTrunk).Count

## Convert global user summary table to HTML and combine with body
$SummaryHtml = $htmltableheader + ($userSummary | ConvertTo-Html -As Table -Fragment) + "<p></p>"

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
	
	$siteServersHtml = "<h3>$($Site.Name) Breakdown</h3>
						<p></p>"
	
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
				Connectivity
			
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
				if ($server.Connectivity){
					$computer = Get-WmiObject Win32_ComputerSystem
					if ($computer.Manufacturer -match "VMware"){
						$server.Hardware = "VMware"
					}elseif ($computer.Manufacturer -match "Microsoft"){
						$server.Hardware = "Microsoft"
					}else{
						$server.Hardware = "Physical"
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
		
		$htmlTableHeader = "<table>
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
							
		$siteServersHtmlTable = $htmlTableHeader
		
		foreach ($server in $siteServers){
			$style = "" | Select-Object Server,Hardware,vmTools,Sockets,Cores,Memory,HDD,PowerPlan,Uptime,OS,DotNet,DNS,LastUpdate
			if ($server.Connectivity){
				if ($server.vmTools -match "Up-to-date"){$style.vmTools = "none"}elseif($server.vmTools -match "Not Installed"){$style.vmTools = "fail"}else{$style.vmTools = "warn"}
				if ($server.Sockets -gt 2){$style.Sockets = "warn"}else{$style.Sockets = "none"}
				if (($server.Cores * $server.Sockets) -lt 6){$style.Cores = "warn"}else{$style.Cores = "none"}
				if ($server.Memory -lt 16){$style.Memory = "warn"}else{$style.Memory = "none"}
				$server.Memory = "$('{0:N2}GB' -f $server.Memory)"
				if ($server.HDD.FreeSpaceGB -lt 16){$style.HDD = "warn"}else{$style.HDD = "none"}
				$server.HDD = "$($server.HDD.DriveLetter) $('{0:N2}GB' -f $server.HDD.FreeSpaceGB)/$('{0:N2}GB' -f $server.HDD.CapacityGB)"
				if ($server.PowerPlan -eq "High Performance"){$style.PowerPlan = "none"}else{$style.PowerPlan = "fail"}
				if ($server.Uptime -gt 2160){$style.Uptime = "warn"}else{$style.Uptime = "none"}
				if ($server.OS -notmatch "Server (2016|2012|2012 R2|2008 R2)"){$style.OS = "fail"}else{$style.OS = "none"}
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
			
			$htmlTableRow = "<tr>"
			$htmlTableRow += "<td><b>$($server.Pool)</b></td>"
			$htmlTableRow += "<td class=""$($style.Server)"">$($server.Server)</td>"
			$htmlTableRow += "<td>$($server.Role)</td>"
			$htmlTableRow += "<td>$($server.Hardware)</td>"
			$htmlTableRow += "<td class=""$($style.vmTools)"">$($server.vmTools)</td>"
			$htmlTableRow += "<td class=""$($style.Sockets)"">$($server.Sockets)</td>"
			$htmlTableRow += "<td class=""$($style.Cores)"">$($server.Cores)</td>"
			$htmlTableRow += "<td class=""$($style.Memory)"">$($server.Memory)</td>"
			$htmlTableRow += "<td class=""$($style.HDD)"">$($server.HDD)</td>"
			$htmlTableRow += "<td class=""$($style.PowerPlan)"">$($server.PowerPlan)</td>"
			$htmlTableRow += "<td class=""$($style.Uptime)"">$($server.Uptime)</td>"
			$htmlTableRow += "<td class=""$($style.OS)"">$($server.OS)</td>"
			$htmlTableRow += "<td class=""$($style.DotNet)"">$($server.DotNet)</td>"
			$htmlTableRow += "<td class=""$($style.DNS)"">$($server.DnsCheck)</td>"
			$htmlTableRow += "<td class=""$($style.LastUpdate)"">$($server.LastUpdate)</td>"
			$htmlTableRow += "</tr>"
			
			$siteServersHtmlTable = $siteServersHtmlTable + $htmlTableRow
		}
		
		$siteServersHtmlTable = $siteServersHtmlTable + "</table></p>"
		
		## Convert site header, site summary, and site server summary to HTML and combine with body
		#$SummaryHtml = $SummaryHtml + $siteServersHtml + "<p></p>" + ($site | Select-Object * -ExcludeProperty Identity | ConvertTo-Html -As Table -Fragment) + "<p></p>" + ($siteServers | ConvertTo-Html -As Table -Fragment) + "<p></p>"
		$SummaryHtml = $SummaryHtml + $siteServersHtml + "<p></p>" + ($site | Select-Object * -ExcludeProperty Identity,Name | ConvertTo-Html -As Table -Fragment) + "<p></p>" + $siteServersHtmlTable + "<p></p>"
	}
}

## Close Report
$HtmlTail = "</body>
			 </html>"

$htmlreport = $HtmlHead + $SummaryHtml + $HtmlTail

$htmlreport | Out-File CsReport.html -Encoding UTF8

.\CsReport.html