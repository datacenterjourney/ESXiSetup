##########################
# Script to configure ESXi host after initial installation of OS and setting IP Address
# 
# Created by Manuel Martinez 4/6/2017
# 
# Updated by Manuel Martinez 3/2/2018
##########################

# Suppress Certificate Warnings
Set-PowerCLIConfiguration -Scope Session -InvalidCertificateAction Ignore -Confirm:$false | Out-Null

#region Static Variables Defined

    # Static Variables
    function StaticVariables () {
        $script:domain = "domain.com"
        $script:domainAlias = "domain"
        $script:esxName = $name + "." + $domain
        $script:dsname = $name + "_bfs"
        $script:adgroup = "vmware_admins"
        $script:subnet = "255.255.255.0"
        # ESXi 6.x License Key
        $script:licensekey6x = "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"
        # ESXi 5.x License Key
        $script:licensekey5x = "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"
    }
    
    # Switch statement to determine which set of variables to use based on the selection.
    function vCenterVariables () {
        switch ($vCenter) {
            vcenter1.domain.com {
                $script:dns1 = "10.10.10.101"
                $script:dns2 = "10.10.10.102"
                $script:ntp1 = "10.10.10.10"
                $script:ntp2 = "10.10.10.11"
                $script:searchdomain1 = "domain.com"
                $script:searchdomain2 = "devinf.domain.com"
            }
            vcenter2.domain.com {
                $script:dns1 = "10.14.10.101"
                $script:dns2 = "10.14.10.102"
                $script:ntp1 = "10.14.10.10"
                $script:ntp2 = "10.14.10.11"
                $script:searchdomain1 = "domain.com"
                $script:searchdomain2 = ""
            }
            Default {
                $script:dns1 = ""
                $script:dns2 = ""
                $script:ntp1 = ""
                $script:ntp2 = ""
                $script:searchdomain1 = ""
                $script:searchdomain2 = ""
                Write-Host "You didn't type in a valid vCenter name." -ForegroundColor Red}
        }
    }

#endregion

#region User Prompts
    
    # Prompt for IP of ESX host to configure
    function PromptIpToConfigure () {
        Write-Host "Enter the IP of the ESXi Host to configure: " -ForegroundColor Red -NoNewline
        $script:esxip = Read-Host
        Write-Host `r
    }

    # Prompt for Name to give ESX
    function PromptEsxName () {
        Write-Host "Enter the name you want to give the ESXi Host: " -ForegroundColor Red -NoNewline
        $script:name = Read-Host
        Write-Host `r
    }

    # Prompt for vMotion IP to give ESX
    function PromptVmotionIp () {
        Write-Host "Enter the vMotion IP you want to give the ESXi Host: " -ForegroundColor Red -NoNewline
        $script:vMotionIP = Read-Host
        Write-Host `r
    }

    # Prompts for ESXi root credentials
    function PromptRootCred () {
        Write-Host "Enter root credentials" -ForegroundColor Red
        $script:esxCred = Get-Credential -Message 'Enter the ESX root credentials'
    }

    # Prompts for vCenter credentials
    function PromptVcenterCred () {
        Write-Host "Enter vCenter credentials " -ForegroundColor Red
        $script:vCenterCred = Get-Credential -Message 'Enter your vCenter Credentials using allegiantair\'
    }

    # Prompts for AD credentials
    function PromptAdCred () {
        Write-Host "Enter AD credentials " -ForegroundColor Red
        $script:adCred = Get-Credential -Message "Enter your AD credentials"
    }

    # Menu that prompts for vCenter to add the host to
    function SelectAvCenter {
        param (
            [string]$Title = 'Pick A vCenter Server'
        )

        Write-Host "================ $Title ================" -ForegroundColor Cyan
        
        Write-Host "1: Press " -ForegroundColor Green -NoNewline
        Write-Host "'1' " -ForegroundColor Yellow -NoNewline
        Write-Host "for " -ForegroundColor Green -NoNewline
        Write-Host "vcenter1." -ForegroundColor Yellow
        Write-Host "2: Press " -ForegroundColor Green -NoNewline
        Write-Host "'2' " -ForegroundColor Yellow -NoNewline
        Write-Host "for " -ForegroundColor Green -NoNewline
        Write-Host "vcenter2." -ForegroundColor Yellow
        Write-Host "Q: Press " -ForegroundColor Green -NoNewline
        Write-Host "'Q' " -ForegroundColor Yellow -NoNewline
        Write-Host "to quit." -ForegroundColor Green
        Write-Host "=======================================================" -ForegroundColor Cyan
    }

    # vCenter selection output to variable
    function vCenterSelection () {
        SelectAvCenter -Title 'Pick A vCenter Server'
        $vcenter = Read-Host "Please select a vCenter server to connect to"
        Write-Host `r
        switch ($vCenter) {
            '1' {$script:vCenter = "vcenter1.domain.com"}
            '2' {$script:vCenter = "vcenter2.domain.com"}
            'q' {exit}
            Default {$script:vCenter = ""
                Write-Host "Hey " -ForegroundColor gray -NoNewline
                Write-Host "ding-dong " -ForegroundColor Yellow -NoNewline
                Write-Host "you didn't select a valid vCenter server." -ForegroundColor Gray
                exit}
        }
    }
    
#endregion

#region Funtions to perform actions

    # Create a Pause that requires 'Enter' key to be presssed to continue
    Function PauseContinue ($message){
        [void](Read-Host 'Press Enter to continue...')
    }

    # Reboot the ESX Server and display output of the process
    function RebootEsxServer () {
        # Reboot host
        Write-Host "The ESXi Host " -ForegroundColor Green -NoNewline
        Write-Host "$esxName " -ForegroundColor Yellow -NoNewline
        Write-Host "is going to reboot now" -ForegroundColor Green
        Restart-VMHost -VMHost $esxName -Confirm:$false | Out-Null

        # Wait for Server to show as down
        do {
            sleep 15
            $ServerState = (Get-VMHost $esxName).ConnectionState
        }
        while ($ServerState -ne "NotResponding")
        Write-Host "The ESXi Host " -ForegroundColor Green -NoNewline
        Write-Host "$esxName " -ForegroundColor Yellow -NoNewline
        Write-Host "is down" -ForegroundColor Green
    
        # Wait for server to reboot
        do {
            sleep 15
            $ServerState = (get-vmhost $esxName).ConnectionState
            Write-Host "Waiting for reboot to complete" -ForegroundColor Cyan
        }
        while ($ServerState -ne "Maintenance")
        Write-Host "The ESXi host " -ForegroundColor Green -NoNewline
        Write-Host "$esxName " -ForegroundColor Yellow -NoNewline
        Write-Host "is back up" -ForegroundColor Green
        
        # Exit maintenance mode
        Write-Host "The ESXi Host " -ForegroundColor Green -NoNewline
        Write-Host "$esxName " -ForegroundColor Yellow -NoNewline
        Write-Host "is exiting maintenance mode" -ForegroundColor Green
        Set-VMhost $esxName -State Connected | Out-Null
        Write-Host "** Reboot Complete **" -ForegroundColor Cyan
        Write-Host ""
    }

    # Connects to vCenter and displays a list of Clusters to add host to
    function SelectCluster () {
        Connect-VIServer -Server $vCenter -Credential $vCenterCred | Out-Null
        $clusters = Get-Cluster
        Write-Host "These are the clusters located in " -ForegroundColor Green -NoNewline
        Write-Host "$vCenter" -ForegroundColor Yellow
        foreach ($cluster in $clusters) {Write-Host $cluster `r -ForegroundColor Cyan}
        Write-Host `r
        Write-Host "What Cluster do you want to add the host(s) to?" -ForegroundColor Red
        $script:Cluster = Read-Host 'Cluster'
        Write-Host `r

        ## Get the datacenter location of the selected cluster
        $script:datacenter = Get-DataCenter -Cluster $cluster | Select-Object -ExpandProperty Name
    }

#endregion

#region vSwitch & vdSwitches

    # Create Distributed Switch
    function Create-VDSwitch () {
        ## Create new VDSwitch
        Write-Host "Creating a new distributed switch named: " -ForegroundColor Green -NoNewline
        Write-Host $vdSwitch -ForegroundColor Yellow
        New-VDSwitch -Name $vdSwitch -Location $datacenter -LinkDiscoveryProtocol "CDP" -LinkDiscoveryProtocolOperation "Listen" -Version "6.0.0" | Out-Null
    }

    # Add Host to new VDSwitch
    function AddEsxToVDSwitch () {
        Write-Host "Adding the host " -ForegroundColor Green -NoNewline
        Write-Host $esxName -ForegroundColor Yellow -NoNewline
        Write-Host "to the Distributed switch " -ForegroundColor Green -NoNewline
        Write-Host $vdSwitch -ForegroundColor Yellow
        Get-VDSwitch $vdSwitch | Add-VDSwitchVMHost -VMHost $esxName | Out-Null
    }

    # Create vMotion Port Group on new VDSwitch
    function CreateVmotionVDPG () {
        # Create Port group name by getting cluster name and removing everything before the '-'
        $clustername = $cluster.split('-')[1]
        $script:NewvMotionPG = "vMotion-" + $clustername

        # Create vMotion Port Group on new VDSwitch
        Write-Host "Creating the vMotion port group named: " -ForegroundColor Green -NoNewline
        Write-Host $NewvMotionPG -ForegroundColor Yellow
        Get-VDSwitch -Name $vdSwitch | New-VDPortgroup -Name $NewvMotionPG
    }
    
    # List dvSwitch that hosts in select cluster are in and asks for add or creation
    function CheckForVDSwitch () {
        $script:vdSwitch = Get-Cluster $cluster | Get-vmhost | Get-VDSwitch
        If ($vdSwitch -eq $null) {
            Write-Host "Hosts in " -ForegroundColor Green -NoNewline
            Write-Host "$cluster " -ForegroundColor Yellow -NoNewline
            Write-Host "are not connected to a distributed switch. " -ForegroundColor Green
            Write-host "Do you want to add them to an existing distributed switch? Type 'Yes' or 'No': " -ForegroundColor Red -NoNewline
            $script:ExistingVDSwitch = Read-Host
            switch ($ExistingVDSwitch) {
                yes {$script:AddVDSwitch = "yes"
                    $script:CreateVDSwitch = "no" }
                no {$script:AddVDSwitch = "no"
                    $script:CreateVDSwitch = 'yes'}
                default {$script:AddVDSwitch = ""
                    $script:CreateVDSwitch = ''
                Write-Host "How about you type a valid answer....." -ForegroundColor Gray}
            }
        }
        else {
            Write-Host "Hosts in " -ForegroundColor Green -NoNewline
            Write-Host "$cluster " -ForegroundColor Yellow -NoNewline
            Write-Host "are connected to " -ForegroundColor Green -NoNewline
            Write-Host "$vdSwitch " -ForegroundColor Yellow -NoNewline
            Write-Host "distributed switch. Do you want to add it to the same distributed switch? Type 'Yes' or 'No': " -ForegroundColor Green -NoNewline
            $script:CurrentVDSwitch = Read-Host 
            Write-Host `r
            switch ($CurrentVDSwitch) {
                yes {$script:AddVDSwitch = ""}
                no {$script:AddVDSwitch = "no"}
                default {$script:AddVDSwitch = ""
                Write-host "You need to type 'yes' or 'no' " -ForegroundColor Gray}
            }
        }
    }

    # Prompts for vdSwitch to connect host to or to create a new one
    function ConnectCreateVDSwitch () {
        If ($AddVDSwitch -eq "no"){
            Write-Host "Do you want to create a new distributed switch? Type 'Yes' or 'No': " -ForegroundColor Red -NoNewline 
            $script:createvdSwitch = Read-Host
            Write-Host "What do you want to name the distributed switch? Type name: " -ForegroundColor Red -NoNewline
            $script:vdSwitch = Read-Host
            Create-VDSwitch
        }
        elseif ($AddVDSwitch -eq "yes"){
            Write-Host "Here are the available distributed switches in " -ForegroundColor Green -NoNewline
            Write-Host "$vcenter " -ForegroundColor Yellow
            $script:createvdSwitch = "no"
            $vdSwitches = Get-VDSwitch
            foreach ($vds in $vdSwitches) {Write-Host $vds `r -ForegroundColor Cyan}
            Write-Host "Type the name of the distribued switch do you want to add the host(s) to? " -ForegroundColor Red -NoNewline
            $script:vdSwitch = Read-Host
            Write-Host `r
        }
        
    }

    # Show vMotion port configured on vdSwitch
    function ShowVmotionPG () {
        $script:vMotionPG = Get-VDSwitch $vdSwitch | Get-VDPortgroup | Where-Object {$_.Name -match 'vmotion'}
        Write-Host "The vMotion port group created on " -ForegroundColor Green -NoNewline
        Write-Host "$vdSwitch " -ForegroundColor Yellow -NoNewline
        Write-Host "is labeled " -ForegroundColor Green -NoNewline
        Write-Host "$vMotionPG " -ForegroundColor Yellow -NoNewline
        Write-Host `r
    }

        # Add ESXi host physical nics to specific DV Uplinks
        function AddVDUplinks(){
        $vmuplinks = @()
        $esxRef = Get-VDSwitch $vdSwitch | Get-VMHost | Where-Object {($_.Name -ne $esxName) -and ($_.Name -notmatch 'lhqmgmt*')} | Select -First 1
        $esxName2 = Get-VMhost $esxName
        $uplinks = Get-VDSwitch $vdSwitch | Get-VDPort -Uplink | Where-Object {$_.ProxyHost -like $esxRef.Name}

        $newuplinks = Get-VMHost $esxName2 | Get-VDSwitch | Get-VDPort -Uplink | Where-Object {$_.ProxyHost -like $esxName2.Name}
        $vdSwitch = Get-VDSwitch $vdSwitch

            foreach ($uplink in $uplinks){
                $obj = New-Object psobject -Property @{
                Name = $uplink.Name
                nic = $uplink.ConnectedEntity
            }
            
            $vmuplinks += $obj
        }

        $config = New-Object VMware.Vim.HostNetworkConfig
        $config.proxySwitch = New-Object VMware.Vim.HostProxySwitchConfig[] (1)
        $config.proxySwitch[0] = New-Object VMware.Vim.HostProxySwitchConfig
        $config.proxySwitch[0].changeOperation = "edit"
        $config.proxySwitch[0].uuid = $vdSwitch.Key
        $config.proxySwitch[0].spec = New-Object VMware.Vim.HostProxySwitchSpec
        $config.proxySwitch[0].spec.backing = New-Object VMware.Vim.DistributedVirtualSwitchHostMemberPnicBacking
        $config.proxySwitch[0].spec.backing.pnicSpec = New-Object VMware.Vim.DistributedVirtualSwitchHostMemberPnicSpec[] (6)

        $i = 0

            foreach ($vmuplink in $vmuplinks){
            $config.proxySwitch[0].spec.backing.pnicSpec[$i] = New-Object VMware.Vim.DistributedVirtualSwitchHostMemberPnicSpec
            $config.proxySwitch[0].spec.backing.pnicSpec[$i].pnicDevice = $vmuplink.nic
            $config.proxySwitch[0].spec.backing.pnicSpec[$i].uplinkPortKey =  ($newuplinks | Where-Object {$_.Name -eq $vmuplink.name}).key
            $i += 1
            }

        $_this = Get-View (Get-View $esxName2).ConfigManager.NetworkSystem
        $_this.UpdateNetworkConfig($config, "modify")
        }


#endregion

#region vCenter Actions

    # Disconnect from vCenter
    function vCenterDisconnect () {
        Disconnect-VIServer -Confirm:$false | Out-Null
    }

    # Connect to vCenter
    function vCenterConnect () {
        Connect-VIServer -Server $vCenter -Credential $vCenterCred | Out-Null
    }

    # Add ESX host to the domain and configure AD settings
    function AD-Auth () {
        # Add ESX host to domain to use AD Authentication
        Write-Host "Adding " -ForegroundColor Green -NoNewline
        Write-host "$esxname " -ForegroundColor Yellow -NoNewline
        Write-Host "to " -ForegroundColor Green -NoNewline
        Write-Host "$domain " -ForegroundColor Yellow -NoNewline
        Write-Host "for AD Authentication" -ForegroundColor Green
        Get-VMHostAuthentication $esxName | Set-VMHostAuthentication -JoinDomain -Domain $domain -Confirm:$false -Credential $adCred  | Out-Null

        # Configure ESX host to not auto add ESX Admins for AD Authentication
        Write-Host "Configuring " -ForegroundColor Green -NoNewline
        Write-host "$esxname " -ForegroundColor Yellow -NoNewline
        Write-Host "to not auto add " -ForegroundColor Green -NoNewline
        Write-Host "'ESX Admins' " -ForegroundColor Cyan -NoNewline
        Write-Host "group for AD Authentication" -ForegroundColor Green
        Get-VMHost $esxname | Get-AdvancedSetting -Name Config.HostAgent.Plugins.Hostsvc.esxAdminsGroupAutoAdd | Set-AdvancedSetting -Value:$false -Confirm:$false | Out-Null

        # Configure ESX host to use group 'vmware admins' for AD Authentication
        Write-Host "Configuring " -ForegroundColor Green -NoNewline
        Write-host "$esxname " -ForegroundColor Yellow -NoNewline
        Write-Host "to use " -ForegroundColor Green -NoNewline
        Write-Host "$adgroup " -ForegroundColor Yellow -NoNewline
        Write-Host "group for AD Authentication" -ForegroundColor Green
        Get-VMHost $esxname | Get-AdvancedSetting -Name Config.HostAgent.plugins.hostsvc.esxAdminsGroup | Set-AdvancedSetting -Value $adgroup -Confirm:$false | Out-Null
    }

    # Add VMHost to Cluster
    function ClusterEsxAdd () {
        Write-Host "Adding " -ForegroundColor Green -NoNewline
        Write-Host "$esxName " -ForegroundColor Yellow -NoNewline
        Write-Host "to " -ForegroundColor Green -NoNewline
        Write-Host "$Cluster " -ForegroundColor Yellow -NoNewline
        Write-Host "cluster" -ForegroundColor Green
        $location = Get-Cluster $Cluster
        Add-VMHost -Name $esxName -Location $location -Credential $esxCred -Force -Confirm:$false | Out-Null
    }

    # Assign License Keys to VMHost
    function AssignLicense () {
        Write-Host "Assigning the license key to the host " -ForegroundColor Green -NoNewline
        Write-Host "$esxName" -ForegroundColor Yellow
        $version = Get-VMHost $esxName | Select-Object Version
        if ($version -eq "6.0.0") {
            $licensekey = $licensekey6x
        }
        elseif ($version -eq "6.5.0") {
            $licensekey = $licensekey6x
        }
        else {
            $licensekey = $licensekey5x
        }
        Get-VMHost $esxName | Set-VMHost -LicenseKey $licensekey | Out-Null
    }

    # Rescan for new FC Storage
    function FcStorageRescan () {
        Write-Host "Rescanning the FC storage adapters for new Datastores" -ForegroundColor Green
        Get-VMHostStorage -VMHost $esxName -RescanAllHba | Out-Null
        Get-VMHostStorage -VMHost $esxName -RescanVmfs | Out-Null
    }

    # Add Host to VDSwitch
    function VDSwitchHostAdd () {
        Write-Host "Adding the host " -ForegroundColor Green -NoNewline
        Write-Host $esxName -ForegroundColor Yellow -NoNewline
        Write-Host " to the Distributed switch " -ForegroundColor Green -NoNewline
        Write-Host $vdSwitch -ForegroundColor Yellow
        Get-VDSwitch $vdSwitch | Add-VDSwitchVMHost -VMHost $esxName | Out-Null
    }

    # Configure vMotion port group settings (Enable vMotion, Set IP)
    function ConfigureVmotion () {
        Write-Host "Configuring vMotion port group on host " -ForegroundColor Green -NoNewline
        Write-Host $esxName -ForegroundColor Yellow -NoNewline
        Write-Host " with the following IP: " -ForegroundColor Green -NoNewline
        Write-Host $vMotionIP -ForegroundColor Yellow
        New-VMHostNetworkAdapter -VMHost $esxName -PortGroup $vMotionPG -VirtualSwitch $vdSwitch -IP $vMotionIP -SubnetMask $subnet -FaultToleranceLoggingEnabled:$false -ManagementTrafficEnabled:$false -VsanTrafficEnabled:$false -VMotionEnabled:$true | Out-Null
    }

    # Disable IPv6 on host and place into maintenance mode
    function DisableIPv6 () {
        Write-Host "Disabling IPv6 on ESX host: " -ForegroundColor Green -NoNewline
        Write-Host $esxName -ForegroundColor Yellow
        Get-VMHost $esxName | Get-VMHostNetwork | Set-VMHostNetwork -IPv6Enabled:$false -Confirm:$false | Out-Null
        Get-VMHost $esxName | Set-VMHost Maintenance -Confirm:$false | Out-Null
    }


#endregion

#region ESX Actions

    # AD group to add with local Admin access on ESX host
    function AD-GroupAdd () {
        Write-Host "Connecting directly to ESX host to set the AD group " -ForegroundColor Green -NoNewline
        Write-Host $adgroup -ForegroundColor Yellow -NoNewline
        Write-Host " as local Admins on " -ForegroundColor Green -NoNewline
        Write-Host $esxName -ForegroundColor Yellow
        Connect-VIServer $esxName -Credential $esxCred | Out-Null
        $script:vigroup = Get-VIAccount -Domain $DomainAlias -Group -id $adgroup
        $script:virole = Get-VIRole -Name "Admin"
        New-VIPermission -Principal $vigroup -Role $virole -Entity $esxName | Out-Null
        Disconnect-VIServer -Confirm:$false | Out-Null
    }

    # Testing successful AD domain add
    function AD-ESXLoginTest () {
        Write-Host "Testing to make sure AD group " -ForegroundColor Green -NoNewline
        Write-Host $adgroup -ForegroundColor Yellow -NoNewline
        Write-Host " is able to log in locally" -ForegroundColor Green
        if (Connect-VIServer -Server $esxName -Credential $vCenterCred -ErrorAction SilentlyContinue) {
            Write-Host 'Successful' -ForegroundColor Cyan
            Disconnect-VIServer -Confirm:$false | Out-Null
        }
        else {
            Write-Host 'Unable to Connect' -ForegroundColor Red
        }
    }

    # Connect to ESX Host by IP
    function EsxIP-Connect () {
        Write-Host "Connecting directly to ESXi host " -ForegroundColor Green -NoNewline
        Write-Host " $esxip" -ForegroundColor Yellow
        Write-Host `r
        Connect-VIServer $esxip -Credential $esxCred | Out-Null
        $script:vmhost = Get-View -ViewType HostSystem -Filter @{'name'=$esxip}
    }

    # Discconnect from ESX Host by IP
    function EsxIP-Disconnect () {
        Write-Host "Disconnecting from ESXi host " -ForegroundColor Green -NoNewline
        Write-Host " $esxip" -ForegroundColor Yellow
        Write-Host `r
        Disconnect-VIServer -Server $esxip -Confirm:$false
    }

    # Connect to ESX Host by Name
    function EsxName-Connect () {
        Write-Host "Connecting directly to ESXi host " -ForegroundColor Green -NoNewline
        Write-Host " $name" -ForegroundColor Yellow
        Write-Host `r
        Connect-VIServer -Server $name -Credential $esxCred | Out-Null
    }

    # Disconnect from ESX Host by Name
    function EsxName-Disconnect () {
        Write-Host "Disconnecting from ESXi host " -ForegroundColor Green -NoNewline
        Write-Host " $name" -ForegroundColor Yellow
        Write-Host `r
        Disconnect-VIServer -Server $name -Confirm:$false
    }

    # Rename ESX Host
    function ESX-Rename () {
        Write-Host "Renaming the ESXi host " -ForegroundColor Green -NoNewline
        Write-Host "$esxip " -ForegroundColor Yellow -NoNewline
        Write-Host "to " -ForegroundColor Green -NoNewline
        Write-Host "$name" -ForegroundColor Yellow
        Write-Host `r
        $script:esxcli = Get-EsxCli -VMHost $esxip -v2
        $esxcli.system.hostname.set.Invoke(@{host=$name}) | Out-Null

    }

    # Set both management vmnics as active
    function SetMgmtNicsActive () {
        Write-Host "Setting both management nics on ESXi Host " -ForegroundColor Green -NoNewline
        Write-Host "$name " -ForegroundColor Yellow -NoNewline
        Write-Host "as active" -ForegroundColor Green
        Write-Host `r
        $script:nics = Get-VirtualSwitch -Name vSwitch0 | Get-NicTeamingPolicy | Select-Object ActiveNic, StandbyNic
        Get-VirtualSwitch -Name vSwitch0 | Get-NicTeamingPolicy | Set-NicTeamingPolicy -MakeNicActive ($nics).StandbyNic -Confirm:$false | Out-Null
    }

    # Remove VM Network port group
    function RemoveVMNetworkPG () {
        Write-Host "Removing the VM Network port group" -ForegroundColor Green
        Get-VirtualSwitch -Name vSwitch0 | Get-VirtualPortGroup -Name "VM Network" | Remove-VirtualPortGroup -Confirm:$false
    }

    # Set ESX Host Current Time
    function SetEsxTime () {
        Write-Host "Setting the current time on " -ForegroundColor Green -NoNewline
        Write-Host "$name" -ForegroundColor Yellow
        $t = Get-Date
        $dst = Get-VMHost | ForEach-Object { Get-View $_.ExtensionData.ConfigManager.DateTimeSystem }
        $dst.UpdateDateTime((Get-Date($t.ToUniversalTime()) -format u))
    }

    # Set/Enable NTP Server
    function ConfigureNTP () {
        Write-Host "Configuring NTP settings on " -ForegroundColor Green -NoNewline
        Write-Host "$name " -ForegroundColor Yellow -NoNewline
        Write-Host "(NTP Servers " -ForegroundColor Green -NoNewline
        Write-Host "$ntp1 " -ForegroundColor Yellow -NoNewline
        Write-Host "& " -ForegroundColor Green -NoNewline 
        Write-Host "$ntp2" -ForegroundColor Yellow -NoNewline
        Write-Host "; Firewall Exceptions and Starting NTP Service)" -ForegroundColor Green
        Get-VMHost $name | Add-VMHostNtpServer -NtpServer $ntp1, $ntp2 | Out-Null
        Get-VMHost $name | Get-VMHostFirewallException | Where-Object {$_.Name -eq "NTP client"} | Set-VMHostFirewallException -Enabled:$true | Out-Null
        Get-VMHost $name | Get-VmHostService | Where-Object {$_.key -eq "ntpd"} | Start-VMHostService | Out-Null
        Get-VMHost $name | Get-VmHostService | Where-Object {$_.key -eq "ntpd"} | Set-VMHostService -policy "On" | Out-Null
        Get-VMHost $name | Get-VmHostService | Where-Object {$_.Key -eq 'ntpd'} | Restart-VMHostService -Confirm:$false | Out-Null
    }

    # Set DNS domain name and servers
    function ConfigureDNS () {
        Write-Host "Setting the DNS domain name " -ForegroundColor Green -NoNewline
        Write-Host "$domain; " -ForegroundColor Yellow -NoNewline
        Write-Host "Search Domain(s) " -ForegroundColor Green -NoNewline
        Write-Host "$searchdomain1 " -ForegroundColor Yellow -NoNewline
        Write-Host "& $searchdomain2 " -ForegroundColor Yellow -NoNewline
        Write-Host "; and DNS Addresses " -ForegroundColor Green -NoNewline
        Write-Host "$dns1 & $dns2" -ForegroundColor Yellow
        Write-Host `r
        Get-VMHostNetwork -VMHost $name | Set-VMHostNetwork -DomainName $domain -DnsAddress $dns1,$dns2 -SearchDomain $searchdomain1,$searchdomain2 | Out-Null
    }

    # Set ESXi Shell & SSH idle sessions to terminate after 5 minutes
    function SetShellIdleTimeout () {
        Write-Host "Setting the ESXi Shell & SSH idle sessions to terminate after 5 minutes" -ForegroundColor Green
        Get-VMHost $name | Get-AdvancedSetting -Name UserVars.ESXiShellInteractiveTimeOut | Set-AdvancedSetting -Value 300 -Confirm:$false | Out-Null
    }

    # Set Shell services timeout settings to 1hr
    function SetShellTimeout () {
        Write-Host "Setting Shell services timeout settings to 1hr" -ForegroundColor Green
        Get-VMHost $name | Get-AdvancedSetting -Name UserVars.ESXiShellTimeOut | Set-AdvancedSetting -Value 3600 -Confirm:$false | Out-Null
    }

    # Rename the local datastore 
    function RenameLocalDS () {
        Write-Host "Searching for local datastore with LUN 0 on host " -ForegroundColor Green -NoNewline
        Write-Host "$name " -ForegroundColor Yellow

        # Search defined VMhost for Boot Lun 0
        $esx = Get-View -ViewType HostSystem -Filter @{'name'=$name}
        $lun = $esx.Config.StorageDevice.ScsiTopology.Adapter.Target.Lun | Where-Object {($_.Lun -eq 0) -and ($_.Key -match '.{70}')} | Select-Object ScsiLun, Lun
        $scsi = $lun.scsilun | Select-Object -First 1
        $canonical = $esx.config.StorageDevice.scsilun | Select-Object UUId, Key, CanonicalName | Where-Object {$_.Key -eq $scsi}

        #$canonical.CanonicalName

        # Search VMHost Datastores and return datastore the matches Lun 0 in previous section
        $localdatastore = Get-VMHost -Name $name | Get-Datastore | Where-Object {$_.ExtensionData.Info.GetType().Name -eq "VmfsDatastoreInfo"} | ForEach-Object { 
        $Datastore = $_
        $Datastore.ExtensionData.Info.Vmfs.Extent | Select-Object -Property @{Name="Name";Expression={$Datastore.Name}}, DiskName | Where-Object {$_.DiskName -eq $canonical.CanonicalName}
        }
        # $localdatastore

        # Rename the local boot lun
        Write-Host "Renaming local datastore to " -ForegroundColor Green -NoNewline
        Write-Host "$dsname" -ForegroundColor Yellow
        Write-Host `r
        Get-VMHost $name | Get-Datastore $localdatastore.Name | Set-Datastore -Name $dsname | Out-Null

    }

    # Configure Scratch Partition -Location
    function ConfigureScratch () {
        $script:scratch = "/vmfs/volumes/" + $dsname + "/.locker-" + $name
        $script:directory = ".locker-" + $name

        Write-Host "Configuring the location of the scratch partition to the following location " -ForegroundColor Green -NoNewline
        Write-Host "$scratch" -ForegroundColor Yellow
        Get-Datastore $dsname | Out-Null
        New-PSDrive -Name "MountedDatastore" -Root \ -PSProvider VimDatastore -Datastore (Get-Datastore $dsname) | Out-Null
        Set-Location MountedDatastore:\ | Out-Null
        New-Item $directory -ItemType Directory | Out-Null

        #Get-VMHost $name | Get-AdvancedSetting -Name "ScratchConfig.ConfiguredScratchLocation" | Select-Object Name, Value
        Get-VMHost $name | Get-AdvancedSetting -Name "ScratchConfig.ConfiguredScratchLocation" | Set-AdvancedSetting -Value $scratch -Confirm:$false | Out-Null
        #Get-VMHost $name | Get-AdvancedSetting -Name "ScratchConfig.ConfiguredScratchLocation" | Select-Object Name, Value
        Set-Location  C:\Windows\system32 | Out-Null
    }

    # Place directly connected ESX host into Maintenance mode
    function EnterEsxNameMaintenance () {
        Write-Host "Placing Host " -ForegroundColor Green -NoNewline
        Write-Host "$name " -ForegroundColor Yellow -NoNewline
        Write-Host "into Maintenance mode" -ForegroundColor Green
        Write-Host `r
        Set-VMHost -VMHost $name Maintenance -Confirm:$false | Out-Null
        Write-Host "Successful" -ForegroundColor Cyan
    }

    # Place vCenter ESX host into Maintenance Mode
    function EnterEsxMaintenance () {
        Write-Host "Placing Host " -ForegroundColor Green -NoNewline
        Write-Host "$esxname " -ForegroundColor Yellow -NoNewline
        Write-Host "into Maintenance mode" -ForegroundColor Green
        Write-Host `r
        Set-VMHost -VMHost $esxname Maintenance -Confirm:$false | Out-Null
        Write-Host "Successful" -ForegroundColor Cyan
    }

    
#endregion

#region To Fix


#endregion

#region Do The Work
    
    # Prompt for IP of ESX host to configure
    PromptIpToConfigure
    
    # Prompt for vMotion IP to give ESX
    PromptVmotionIp

    # Prompt for Name to give ESX
    PromptEsxName

    # Prompts for ESXi root credentials
    PromptRootCred

    # Prompts for vCenter credentials
    PromptVcenterCred

    # Prompts for AD credentials
    PromptAdCred

    # Prompts for vCenter to connect to
    # SelectAvCenter

    # vCenter selection output to variable
    vCenterSelection

    # Connect to vCenter
    vCenterConnect

    # Connects to vCenter and displays a list of Clusters to add host to
    SelectCluster

    # List dvSwitch that hosts in select cluster are in and asks for add or creation
    CheckForVDSwitch

    # Prompts for vdSwitch to connect host to or to create a new one
    ConnectCreateVDSwitch

    # Show vMotion port configured on vdSwitch
    ShowVmotionPG

    # Disconnect from vCenter
    vCenterDisconnect

    # Static Variables
    StaticVariables

    # Switch statement to determine which set of variables to use based on the selection.
    vCenterVariables

    # Connect to ESX Host by IP
    EsxIP-Connect

    # Rename ESX Host
    ESX-Rename

    # Discconnect from ESX Host by IP
    EsxIP-Disconnect

    # Connect to ESX Host by Name
    EsxName-Connect

    # Set both management vmnics as active
    SetMgmtNicsActive

    # Remove VM Network port group
    RemoveVMNetworkPG

    # Set ESX Host Current Time
    SetEsxTime

    # Set/Enable NTP Server
    ConfigureNTP

    # Set DNS domain name and servers
    ConfigureDNS

    # Set ESXi Shell & SSH idle sessions to terminate after 5 minutes
    SetShellIdleTimeout

    # Set Shell services timeout settings to 1hr
    SetShellTimeout

    # Rename the local datastore
    RenameLocalDS

    # Configure Scratch Partition -Location
    ConfigureScratch

    # Place directly connected ESX host into Maintenance mode
    EnterEsxNameMaintenance

    # Disconnect from ESX Host by Name
    EsxName-Disconnect

    # Connect to vCenter
    vCenterConnect

    # Add VMHost to Cluster
    ClusterEsxAdd

    # Assign License Keys to VMHost
    AssignLicense

    # Rescan for new FC Storage
    FcStorageRescan

    # Add Host to new VDSwitch
    AddEsxToVDSwitch

    # Configure vMotion port group settings (Enable vMotion, Set IP)
    ConfigureVmotion

    # Add ESXi host physical nics to specific DV Uplinks
    AddVDUplinks

    # Wait for 10 seconds
    Start-Sleep -Seconds 10

    # Disable IPv6 on host and place into maintenance mode
    DisableIPv6

    # Pause for 10 seconds
    Start-Sleep -Seconds 10

    # Add ESX host to the domain and configure AD settings
    AD-Auth

    # Wait for 60 seconds
    Start-Sleep -Seconds 60

    # Reboot the ESX Server and display output of the process
    RebootEsxServer

    # Wait 16 min for AD replication
    Write-Host 'Waiting 16 minutes for AD replication before proceeding' -ForegroundColor Green
    Start-Sleep -Seconds 660

    # AD group to add with local Admin access on ESX host
    AD-GroupAdd

    # Testing successful AD domain add
    AD-ESXLoginTest

    # Completion 
    Write-Host "The ESXi host " -ForegroundColor Green -NoNewline
    Write-host "$esxname " -ForegroundColor Yellow -NoNewline
    Write-Host "has been successfully configured" -ForegroundColor Green
    Write-Host `r
    Write-Host `r
    Write-Host "Man that was hard work, but it's done now." -ForegroundColor Cyan
    Write-Host `r
    Write-Host `r

    PauseContinue

#endregion

