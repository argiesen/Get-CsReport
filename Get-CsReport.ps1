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
    } else {
		return
	}
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

## Gather summary info

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
		@{name='HostName';expression={($_.HostName).ToLower()}},`
		@{name='IP Address';expression={$_.IPv4Address}},`
		@{name='OS';expression={$_.OperatingSystem -replace 'Windows ',''}},`
		@{name='OS Version';expression={$_.OperatingSystemVersion}},`
		@{name='Roles';expression={$_.OperationMasterRoles -join ', '}},`
		@{name='Global Catalog';expression={$_.IsGlobalCatalog}},`
		@{name='Read Only';expression={$_.IsReadOnly}}
}catch{
	#continue
}

## Collect users for global usage
$users = Get-CsUser -ResultSize Unlimited -WarningAction SilentlyContinue -ErrorAction SilentlyContinue

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
$globalSummary = "" | Select-Object Sites,Users,"Address Mismatch","AD Disabled","Admin Users","Voice Users","RCC Users","Analog","Common Area",RGS,Pools,Gateways
$globalSummary.Sites = (Get-CsSite).Count
$globalSummary.Users = ($users | Where-Object {$_.Enabled -eq $true}).Count
$globalSummary."Address Mismatch" = (Get-CsAdUser | Where-Object {($_.WindowsEmailAddress -and $_.SipAddress) -and ($_.WindowsEmailAddress -ne ($_.SipAddress -replace "sip:",""))}).Count
$globalSummary."AD Disabled" = $disabledAdUsers.Count
$globalSummary."Admin Users" = (Get-AdUser -Filter {adminCount -gt 0} -Properties adminCount -ResultSetSize $null | foreach{Get-CsUser $_.SamAccountName -ErrorAction SilentlyContinue}).Count
$globalSummary."Voice Users" = ($users | Where-Object {$_.Enabled -eq $true -and $_.EnterpriseVoiceEnabled -eq $true}).Count
$globalSummary."RCC Users" = ($users | Where-Object {$_.Enabled -eq $true -and $_.RemoteCallControlTelephonyEnabled -eq $true}).Count
$globalSummary."Analog" = $analogDevices.Count
$globalSummary."Common Area" = $commonAreaPhones.Count
$globalSummary.RGS = (Get-CsRgsWorkflow).Count
$globalSummary.Pools = (Get-CsPool | Where-Object Services -match "Registrar").Count
$globalSummary.Gateways = (Get-CsService -PstnGateway).Count

## Gather global CS info
$csSummary = "" | Select-Object CMS,SipDomain,MeetUrl,DialinUrl,AdminUrl
$csSummary.CMS = Get-CsService -CentralManagement | Select-Object SiteId,PoolFqdn,Version,Active
$csSummary.SipDomain = Get-CsSipDomain
$csSummary.MeetUrl = Get-CsSimpleUrlConfiguration | Select-Object -ExpandProperty SimpleUrl | Where-Object {$_.Component -eq "meet"}
$csSummary.DialinUrl = Get-CsSimpleUrlConfiguration | Select-Object -ExpandProperty SimpleUrl | Where-Object {$_.Component -eq "dialin"}
$csSummary.AdminUrl = Get-CsSimpleUrlConfiguration | Select-Object -ExpandProperty SimpleUrl | Where-Object {$_.Component -eq "cscp"}

## Gather sites info
$sites = Get-CsSite | Select-Object Identity,@{l='Name';e={$_.DisplayName}},Users,"Voice Users","RCC Users",Pools,Gateways
$pools = Get-CsPool | Where-Object Services -match "Registrar|PersistentChatServer|MediationServer|Director"

## Process each site in topology for site summary, then server summary
foreach ($site in $sites){
	$sitePools = $pools | `
		Where-Object {$_.Site -eq $site.Identity} | `
		Select-Object @{l='Name';e={$_.Fqdn}},Services,Users,"Voice Users","RCC Users"
	$site.Users = 0
	$site."Voice Users" = 0
	$site."RCC Users" = 0
	$site.Pools = (Get-CsPool | Where-Object {$_.Services -match "Registrar" -and $_.Site -eq $site.Identity}).Count
	$site.Gateways = (Get-CsService -PstnGateway | Where-Object SiteId -eq $site.Identity).Count
	$siteServers = @()
	$siteFailItems = @()
	$siteWarnItems = @()
	$siteInfoItems = @()
	
	## If pools exist in site, process pools for servers
	if ($sitePools){
		## Process pools in site
		foreach ($pool in $sitePools){
			$pool.Users = ($users | Where-Object {$_.Enabled -eq $true -and $_.RegistrarPool -match $pool.Name}).Count
			$pool."Voice Users" = ($users | Where-Object {$_.Enabled -eq $true -and $_.EnterpriseVoiceEnabled -eq $true -and $_.RegistrarPool -match $pool.Name}).Count
			$pool."RCC Users" = ($users | Where-Object {$_.Enabled -eq $true -and $_.RemoteCallControlTelephonyEnabled -eq $true -and $_.RegistrarPool -match $pool.Name}).Count
			
			$site.Users = $site.Users + $pool.Users
			$site."Voice Users" = $site."Voice Users" + $pool."Voice Users"
			$site."RCC Users" = $site."RCC Users" + $pool."RCC Users"
			
			$servers = (Get-CsPool $pool.Name).Computers | Select-Object `
				@{label='Site';expression={$site.Identity}},`
				Pool,`
				@{label='Server';expression={$_}},`
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
					Write-Verbose "$($server.Server) is not accessible."
					$server.Permission = $false
				}else{
					Write-Verbose "$($server.Server) is accessible."
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
						
		$siteServersHtmlTable = $null
		
		foreach ($server in $siteServers){
			#$style = "" | Select-Object Server,Hardware,vmTools,Sockets,Cores,Memory,HDD,PowerPlan,Uptime,OS,DotNet,DNS,LastUpdate
			## Build servers HTML table rows
			$htmlTableRow = "<tr>"
			$htmlTableRow += "<td><b>$(($server.Pool).Split(".")[0])</b></td>"
			if ($server.Connectivity -and $server.Permission){
				$htmlTableRow += "<td>$(($server.Server).Split(".")[0])</td>"
				$htmlTableRow += "<td>$($server.Role)</td>"
				$htmlTableRow += "<td>$($server.Hardware)</td>"
				if ($server.vmTools -match "(Up-to-date|N/A)"){
					$htmlTableRow += "<td>$($server.vmTools)</td>"
				}elseif($server.vmTools -match "Not Installed"){
					$htmlTableRow += "<td class=""fail"">$($server.vmTools)</td>"
					$siteFailItems += "<li>VMware Tools is not installed on one or more servers detected as VMware.</li>"
				}else{
					$htmlTableRow += "<td class=""warn"">$($server.vmTools)</td>"
					$siteWarnItems += "<li>VMware Tools is not up-to-date on one or more servers detected as VMware.</li>"
				}
				if ($server.Sockets -gt 2){
					$htmlTableRow += "<td class=""warn"">$($server.Sockets)</td>"
				}else{
					$htmlTableRow += "<td>$($server.Sockets)</td>"
				}
				if (($server.Cores * $server.Sockets) -lt 6){
					$htmlTableRow += "<td class=""warn"">$($server.Cores)</td>"
				}else{
					$htmlTableRow += "<td>$($server.Cores)</td>"
				}
				if ($server.Memory -lt 16){
					$server.Memory = "$('{0:N2}GB' -f $server.Memory)"
					$htmlTableRow += "<td class=""warn"">$($server.Memory)</td>"
				}else{
					$server.Memory = "$('{0:N2}GB' -f $server.Memory)"
					$htmlTableRow += "<td>$($server.Memory)</td>"
				}
				$server.Memory = "$('{0:N2}GB' -f $server.Memory)"
				if ($server.HDD.FreeSpaceGB -lt 32){
					$htmlTableRow += "<td class=""warn""><ul style='margin: 0;'>"
					foreach ($hdd in $server.HDD){
						$htmlTableRow += "<li>$($hdd.DriveLetter) $('{0:N2}GB' -f $hdd.FreeSpaceGB)/$('{0:N2}GB' -f $hdd.CapacityGB)</li>"
					}
				}else{
					$htmlTableRow += "<td><ul style='margin: 0;'>"
					foreach ($hdd in $server.HDD){
						$htmlTableRow += "<li>$($hdd.DriveLetter) $('{0:N2}GB' -f $hdd.FreeSpaceGB)/$('{0:N2}GB' -f $hdd.CapacityGB)</li>"
					}
				}
				$htmlTableRow += "</ul></td>"
				if ($server.PowerPlan -eq "High Performance"){
					$htmlTableRow += "<td>$($server.PowerPlan)</td>"
				}else{
					$htmlTableRow += "<td class=""fail"">$($server.PowerPlan)</td>"
					$siteFailItems += "<li>One or more servers' power plan is not set to high performance. See <a href='https://support.microsoft.com/en-us/help/2207548/slow-performance-on-windows-server-when-using-the-balanced-power-plan' target='_blank'>KB2207548</a>.</li>"
				}
				if ($server.Uptime -gt 2160){
					$htmlTableRow += "<td class=""warn"">$($server.Uptime)</td>"
				}else{
					$htmlTableRow += "<td>$($server.Uptime)</td>"
				}
				if ($server.OS -notmatch "Server (2012|2012 R2|2008 R2)"){
					$htmlTableRow += "<td class=""fail"">$($server.OS -replace 'Microsoft Windows ','')</td>"
					$siteFailItems += "<li>One or more servers was not running a supported OS. See <a href='https://technet.microsoft.com/en-us/library/dn951388.aspx?f=255&mspperror=-2147217396#Anchor_1' target='_blank'>Operating systems for Skype for Business Server 2015</a>.</li>"
				}else{
					$htmlTableRow += "<td>$($server.OS -replace 'Microsoft Windows ','')</td>"
				}
				if ($server.DotNet -notmatch "(4.6.2|4.5.2)"){
					$htmlTableRow += "<td class=""warn"">$($server.DotNet)</td>"
					$siteWarnItems += "<li>.NET Framework is not up-to-date on one or more servers. Version 4.5.2 or 4.6.2 is recommended. See <a href='https://blogs.technet.microsoft.com/nexthop/2016/02/11/on-net-framework-4-6-2-and-skype-for-businesslync-server-compatibility/'  target='_blank'>.NET Framework 4.6.2 and Skype for Business/Lync Server Compatibility</a></li>"
				}else{
					$htmlTableRow += "<td>$($server.DotNet)</td>"
				}
				if ($server.DnsCheck -ne "Pass"){
					$htmlTableRow += "<td class=""fail"">$($server.DnsCheck)</td>"
				}else{
					$htmlTableRow += "<td>$($server.DnsCheck)</td>"
				}
				if ($server.LastUpdate -lt (Get-Date).addDays(-90)){
					$server.LastUpdate = ($server.LastUpdate).ToString('MM/dd/yyyy')
					$htmlTableRow += "<td class=""warn"">$($server.LastUpdate)</td>"
				}else{
					$server.LastUpdate = ($server.LastUpdate).ToString('MM/dd/yyyy')
					$htmlTableRow += "<td>$($server.LastUpdate)</td>"
				}
			}else{
				$htmlTableRow += "<td class=""fail"">$(($server.Server).Split(".")[0])</td>"
				if (!($server.Connectivity)){
					$siteFailItems += "<li>One or more servers were not accessible or offline.</li>"
				}elseif (!($server.Permission)){
					$siteFailItems += "<li>One or more servers could not be queried due to permissions. Verify the user generating this report has local administrator rights on each server.</li>"
				}
				$htmlTableRow += "<td>$($server.Role)</td>"
				$htmlTableRow += "<td>$($server.Hardware)</td>"
				$htmlTableRow += "<td>$($server.vmTools)</td>"
				$htmlTableRow += "<td>$($server.Sockets)</td>"
				$htmlTableRow += "<td>$($server.Cores)</td>"
				$htmlTableRow += "<td>$($server.Memory)</td>"
				$htmlTableRow += "<td><ul style='margin: 0;'>"
				foreach ($hdd in $server.HDD){
					$htmlTableRow += "<li>$($hdd.DriveLetter) $('{0:N2}GB' -f $hdd.FreeSpaceGB)/$('{0:N2}GB' -f $hdd.CapacityGB)</li>"
				}
				$htmlTableRow += "</ul></td>"
				$htmlTableRow += "<td>$($server.PowerPlan)</td>"
				$htmlTableRow += "<td>$($server.Uptime)</td>"
				$htmlTableRow += "<td>$($server.OS -replace 'Microsoft Windows ','')</td>"
				$htmlTableRow += "<td>$($server.DotNet)</td>"
				$htmlTableRow += "<td>$($server.DnsCheck)</td>"
				$htmlTableRow += "<td>$($server.LastUpdate)</td>"
			}
			$htmlTableRow += "</tr>"
			
			## Build servers HTML table rows
			<# $htmlTableRow = "<tr>"
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
			$htmlTableRow += "<td class=""$($style.OS)"">$($server.OS -replace 'Microsoft Windows ','')</td>"
			$htmlTableRow += "<td class=""$($style.DotNet)"">$($server.DotNet)</td>"
			$htmlTableRow += "<td class=""$($style.DNS)"">$($server.DnsCheck)</td>"
			$htmlTableRow += "<td class=""$($style.LastUpdate)"">$($server.LastUpdate)</td>"
			$htmlTableRow += "</tr>" #>
			
			$siteServersHtmlTable += $htmlTableRow
		}
		
		## Convert site header, site summary, and site server summary to HTML and combine with body
		$siteHtmlBody += "<h3>$($Site.Name)</h3>
			<p>$($site | Select-Object * -ExcludeProperty Identity,Name | ConvertTo-Html -As Table -Fragment)</p>
			<p>
			<table class=""csservers"">
			<tr>
			<th width=""100px"">Pool</th>
			<th width=""100px"">Server</th>
			<th width=""60px"">Role</th>
			<th width=""100px"">Hardware</th>
			<th width=""70px"">VMware Tools</th>
			<th width=""40px"">Sockets</th>
			<th width=""40px"">Cores</th>
			<th width=""40px"">Memory</th>
			<th width=""130px"">HDD</th>
			<th width=""100px"">Power Plan</th>
			<th width=""40px"">Uptime</th>
			<th width=""120px"">OS</th>
			<th width=""30px"">.NET</th>
			<th width=""30px"">DNS</th>
			<th width=""50px"">Last Update</th>
			</tr>
			$siteServersHtmlTable
			</table>
			</p>"
		
		if ($siteFailItems){
			$siteHtmlFail = "<p>Failed Items</p>
				<ul>
				$($siteFailItems | Select-Object -Unique)
				</ul>"
		}else{
			$siteHtmlFail = $null
		}
		if ($siteWarnItems){
			$siteHtmlWarn = "<p>Warning Items</p>
				<ul>
				$($siteWarnItems | Select-Object -Unique)
				</ul>"
		}else{
			$siteHtmlWarn = $null
		}
		if ($siteInfoItems){
			$siteHtmlInfo = "<p>Info Items</p>
				<ul>
				$($siteInfoItems | Select-Object -Unique)
				</ul>"
		}else{
			$siteHtmlInfo = $null
		}
		
		$siteHtmlBody = "$siteHtmlBody
			$siteHtmlFail
			$siteHtmlWarn
			$siteHtmlInfo"
	}
}

## Header
$HtmlHead = "<html>
	<style>
	BODY{font-family: Calibri; font-size: 11pt; margin-top: 10px; margin-bottom: 60px;}
	H1{font-size: 22px;}
	H2{font-size: 19px; padding-top: 10px;}
	H3{font-size: 17px; padding-top: 8px;}
	TABLE{border: 1px solid black; border-collapse: collapse; font-size: 9pt; table-layout: fixed;}
	TABLE.csservers{table-layout: fixed;}
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
	TD{border: 1px solid black; padding: 5px; vertical-align: top; word-wrap:break-word;}
	td.pass{background: #7FFF00;}
	td.warn{background: #FFFF00;}
	td.fail{background: #FF0000; color: #ffffff;}
	td.info{background: #85D4FF;}
	tr:nth-child(even){background: #dae5f4;}
	tr:nth-child(odd){background: #b8d1f3;}
	ul.hdd{list-style: inside; padding-left: 0px; list-style-type:square;}
	ul{list-style: inside; padding-left: 0px; list-style-type:square; margin: -10px 0;}
	</style>
	<body>
	<h1>Skype for Business Report</h1>
	<p>Generated: $(Get-Date)</p>"

## Active Directory
foreach ($suffix in $($adForest.UPNSuffixes)){
	$adSuffixes += "<li>$suffix</li>"
}


## Build AD site HTML list
foreach ($site in $($adForest.Sites)){
	$adSites += "<li>$site</li>"
}

## Convert global summary tables to HTML and combine with AD body
$adHtmlBody = "<h2>Environment Overview</h2>
	<p></p>
	<h3>Active Directory</h3>
	<p><b>Forest Name:</b> $($adForest.Name)</br>
	<b>Forest Mode:</b> $($adForest.ForestMode)</br>
	<b>Domain Name:</b> $($adDomain.DNSRoot) ($($adDomain.NetBIOSName))</br>
	<b>Domain Mode:</b> $($adDomain.DomainMode)</br>
	<b>UPN Suffixes:</b>
	<ul>
	$adSuffixes
	</ul>
	</p>
	<p><b>Sites:</b>
	<ul>
	$adSites
	</ul>
	</p>"
	
## Convert Domain Controlers to HTML and combine with AD body
if ($adDomainControllers){
	$adHtmlBody += "<h3>Domain Controllers</h3>
		<p>$($adDomainControllers | ConvertTo-Html -As Table -Fragment)</p>"
}

## Certificate Authorities
if ($CAs){
	## Build CA HTML table rows
	foreach ($ca in $CAs){
		$htmlTableRow = "<tr>"
		$htmlTableRow += "<td>$($ca.CommonName)</td>"
		$htmlTableRow += "<td>$($ca.Server)</td>"
		if ($ca.Online){
			$htmlTableRow += "<td>$($ca.Online)</td>"
			if (!($ca.WebServerTemplate)){
				$caWarnItems += "<li>$($ca.Server): Web server template is unavailable.</li>"
			}
		}else{
			$htmlTableRow += "<td class=""fail"">$($ca.Online)</td>"
			$caWarnItems += "<li>$($ca.Server): CA server is unavailable.</li>"
		}
		
		$caHtmlTable += $htmlTableRow
	}
	
	if ($caWarnItems){
		$caHtmlWarn = "<p>Warning Items</p>
			<ul>
			$caWarnItems
			</ul>"
	}
	
	$caHtmlBody = "<h3>Certificate Authorities</h3>
		<table>
		<tr>
		<th>Common Name</th>
		<th>Server</th>
		<th>Online</th>
		</tr>
		$caHtmlTable
		</table>
		$caHtmlWarn"
}

## Generate global CS HTML
## Generate CMS HTML
$cmsHtml = "<b>Active CMS:</b> $(($csSummary.CMS | where Active -eq $true).PoolFqdn)"
if ($csSummary.CMS | where Active -eq $false){
	$cmsHtml += "</br><b>Backup CMS:</b> $(($csSummary.CMS | where Active -eq $false).PoolFqdn)"
}

## Generate SIP domains HTML
foreach ($sipDomain in $($csSummary.SipDomain)){
	if ($sipDomain.IsDefault){
		$sipDomainHtml += "<li>$($sipDomain.Name) (Default)</li>"
	}else{
		$sipDomainHtml += "<li>$($sipDomain.Name)</li>"
	}
}

## Generate meet URLs HTML
foreach ($meetUrl in $($csSummary.MeetUrl)){
	$meetUrlHtml += "<li>$($meetUrl.ActiveUrl) ($($meetUrl.Domain))</li>"
}

## Generate dialin URLs HTML
foreach ($dialinUrl in $($csSummary.DialinUrl)){
	$dialinUrlHtml += "<li>$($dialinUrl.ActiveUrl) ($($dialinUrl.Domain))</li>"
}

## Generate CS topology info HTML
$topologyHtml = "<p>$cmsHtml
	</br><b>SIP Domains:</b>
	<ul>
	$sipDomainHtml
	</ul></p>
	<p><b>Meet URLs:</b>
	<ul>
	$meetUrlHtml
	</ul></p>
	<p><b>Dailin URLs:</b>
	<ul>
	$dialinUrlHtml
	</ul></p>
	<p><b>Admin URL:</b> $($csSummary.AdminUrl.ActiveUrl)</p>"


## Global Users Summary


## Generate warning messages
if ($globalSummary."Address Mismatch" -gt 0){$userWarnItems += "<li>Users exist whose SIP address and primary STMP addresses do not match. This will cause Exchange integration issues for these users. See <a href='https://github.com/argiesen/Get-CsReport/wiki/User-Tests#address-mismatch' target='_blank'>Address Mistmatch</a>.</li>"}
if ($globalSummary."AD Disabled" -gt 0){$userWarnItems += "<li>Users exist that are disabled in AD but are enabled for Skype4B. These users may still be able to login to Skype4B. See <a href='https://github.com/argiesen/Get-CsReport/wiki/User-Tests/_edit#ad-disabled' target='_blank'>AD Disabled</a>.</li>"}
if ($globalSummary."Admin Users" -gt 0){$userInfoItems += "<li>Users exist with adminCount greater than 0. Attempts to modify these users Skype4B configurations may fail with access denied. See <a href='https://github.com/argiesen/Get-CsReport/wiki/User-Tests#admincount-greater-than-0' target='_blank'>adminCount greater than 0</a>.</li>"}

if ($userFailItems){
	$userHtmlFail = "<p>Failed Items</p>
		<ul>
		$userFailItems
		</ul>"
}
if ($userWarnItems){
	$userHtmlWarn = "<p>Warning Items</p>
		<ul>
		$userWarnItems
		</ul>"
}
if ($userInfoItems){
	$userHtmlInfo = "<p>Info Items</p>
		<ul>
		$userInfoItems
		</ul>"
}

$globalCsHtmlBody += "<h3>Skype for Business Server</h3>
	$topologyHtml
	<p>$($globalSummary | ConvertTo-Html -As Table -Fragment)</p>
	$userHtmlFail
	$userHtmlWarn
	$userHtmlInfo"

## Sites


## Close Report
$HtmlTail = "</body>
	</html>"

$htmlReport = $HtmlHead + $adHtmlBody + $caHtmlBody + $globalCsHtmlBody + $siteHtmlBody + $HtmlTail

$htmlReport | Out-File CsReport.html -Encoding UTF8

.\CsReport.html