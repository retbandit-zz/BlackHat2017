function Invoke-Snitch9{

    <#

    .SYNOPSIS

    This module is focused on identifying tools commony used by Blue Teams such as Microsoft ATP, Sysmon, Event Log Forwarding, etc.
    If identified, the module first blocks communication to central logging and cloud based AV behavioural analysis tools.

    Snitch Function: Invoke-Snitch
    Author: Chris Thompson (@retBandit)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None
    
    .DESCRIPTION

    This module is focused on identifying and blocking logging tools commony used by Blue Teams such as Microsoft ATP, Sysmon, Event Log Forwarding, etc.

    .PARAMETER x

    Desc of param

    .Example

    C:\PS> Invoke-Snitch

    Description
    -----------
    This module is focused on identifying and blocking logging tools commony used by Blue Teams such as Microsoft ATP, Sysmon, Event Log Forwarding, etc.

    .Example


    #>

    
    #Define Cloud Security Vendor Address
    #Windows Defender ATP
        $MSATP1 = "securitycenter.windows.com"
        $MSATP2 = "winatp-gw-cus.microsoft.com"
        $MSATP3 = "winatp-gw-eus.microsoft.com"
        $MSATP4 = "winatp-gw-weu.microsoft.com"
        $MSATP5 = "winatp-gw-neu.microsoft.com"
        $MSATP6 = "us.vortex-win.data.microsoft.com"
        $MSATP7 = "eu.vortex-win.data.microsoft.com"
        $MSATP8 = "psapp.microsoft.com"
        $MSATP9 = "psappeu.microsoft.com"
        $MSATPURLs = $MSATP1,$MSATP2,$MSATP3,$MSATP4,$MSATP5,$MSATP6,$MSATP7,$MSATP8,$MSATP9

    #CrowdStrike Falcon
        $CSHOST1 = "ts01-b.cloudsink.net"
        $CSHOST2 = "lfodown01-b.cloudsink.net"
        $CSHOST3 = "lfoup01-b.cloudsink.net"
        $CSHOST4 = "term01-b-449152202.us-west-1.elb.amazonaws.com"
        $CSHOST5 = "lfodown01-b-2066797419.us-west-1.elb.amazonaws.com"
        $CSHOST6 = "lfoup01-b-1269267964.us-west-1.elb.amazonaws.com"
        $CSURLs = $CSHOST1,$CSHOST2,$CSHOST3
        $CSIP1 = "52.8.160.82"
        $CSIP2 = "52.8.54.244"
        $CSIP3 = "54.183.24.162"
        $CSIP4 = "54.193.27.226"
        $CSIP5 = "54.215.176.108"
        $CSIP6 = "54.67.96.255"
        $CSIP7 = "52.8.172.89"
        $CSIP8 = "52.8.61.206"
        $CSIP9 = "54.183.252.86"
        $CSIP10 = "54.193.29.47"
        $CSIP11 = "54.219.145.181"
        $CSIP12 = "54.67.99.247"
        $CSIP13 = "52.8.173.58"
        $CSIP14 = "54.183.122.156"
        $CSIP15 = "54.183.34.154"
        $CSIP16 = "54.193.67.98"
        $CSIP17 = "54.241.150.134"
        $CSIP18 = "52.8.32.113"
        $CSIP19 = "54.183.148.116"
        $CSIP20 = "54.183.39.68"
        $CSIP21 = "54.193.90.171"
        $CSIP22 = "54.241.161.60"
        $CSIP23 = "52.8.45.162"
        $CSIP24 = "54.183.148.43"
        $CSIP25 = "54.183.51.69"
        $CSIP26 = "54.215.131.232"
        $CSIP27 = "54.67.105.202"
        $CSIP28 = "52.8.52.230"
        $CSIP29 = "54.183.234.42"
        $CSIP30 = "54.193.117.199"
        $CSIP31 = "54.215.169.199"
        $CSIP32 = "54.67.123.150"
        $CSIPs = $CSIP1,$CSIP2,$CSIP3,$CSIP4,$CSIP5,$CSIP6,$CSIP7,$CSIP8,$CSIP9,$CSIP10,$CSIP11,$CSIP12,$CSIP13,$CSIP14,$CSIP15,$CSIP16,$CSIP17,$CSIP18,$CSIP19,$CSIP20,$CSIP21,$CSIP22,$CSIP23,$CSIP24,$CSIP25,$CSIP26,$CSIP27,$CSIP28,$CSIP29,$CSIP30,$CSIP31,$CSIP32


    #Checking for Behavioural Analysis AV security product processes and adding outbound FW blocks


        $CSCloudDynamicIPs = ($CSURLs | foreach {[System.Net.Dns]::GetHostAddresses($_) | Select-Object -ExpandProperty IPAddressToString}) |`
        Foreach-object {
        New-NetFirewallRule -DisplayName "Windows Diagnostics" -Direction Outbound -Action Block -RemoteAddress "$_"
        write-host "$_ - Outbound Firewall Block Was Added: $?"
        }
                    
        $CSCloudStaticIPs = ($CSIPs | foreach {($_) | Select-Object}) |`
        Foreach-object {
        New-NetFirewallRule -DisplayName "Windows Diagnostics" -Direction Outbound -Action Block -RemoteAddress "$_"
        write-host "$_ - Outbound Firewall Block Was Added: $?"
        }
        
    Write-Output "`n"


    #Checking for Event Log Forwarding and adding associated firewall blocks

    Write-Output "[*] Checking for Event Log Forwarding"
            Disable-NetFirewallRule –DisplayName "Windows Remote Management*"
            Disable-NetFirewallRule –DisplayName "Remote Event Log Management*"
            Disable-NetFirewallRule –DisplayName "Remote Event Monitor*"
            write-host "Disabled Firewall Rules for WinRM, Wecsrv: $?" "`n"
            Foreach ($ss in $services)
            {
            if ($ss.Name -like "*Wecsvc")
                {
                Write-Output  "Windows Event Collector Service is running, adding outbound firewall blocks for source initated subscriptions"
                New-NetFirewallRule -DisplayName "Disable Winrm HTTP Remote Management Outbound" -Direction Outbound -Action Block -LocalPort 5985 -Protocol TCP | out-null
                write-host "WinRM Outbound 5985 Firewall Block Was Added: $?"
                New-NetFirewallRule -DisplayName "Disable Winrm HTTPS Remote Management Outbound" -Direction Outbound -Action Block -LocalPort 5986 -Protocol TCP | out-null
                write-host "WinRM Outbound 5986 Firewall Block Was Added: $?" "`n"
                }
            if ($ss.Name -like "*winrm")
                {
                Write-Output "WinRM Service is running, adding inbound firewall blocks for collector initated subscriptions"
                Disable-NetFirewallRule –DisplayName "Windows Remote Management*"
                New-NetFirewallRule -DisplayName "Disable Winrm HTTP Remote Management Inbound" -Direction Inbound -Action Block -LocalPort 5985 -Protocol TCP | out-null
                write-host "WinRM Inbound 5985 Firewall Block Was Added: $?"
                New-NetFirewallRule -DisplayName "Disable Winrm HTTPS Remote Management Inbound" -Direction Inbound -Action Block -LocalPort 5986 -Protocol TCP | out-null
                write-host "WinRM Inbound 5986 Firewall Block Was Added: $?" "`n"
                }

            }

    #Checking for Event Log Forwarding and adding associated firewall blocks

    Write-Output "[*] Checking for Event Log Forwarding"
            Disable-NetFirewallRule –DisplayName "Windows Remote Management*"
            Disable-NetFirewallRule –DisplayName "Remote Event Log Management*"
            Disable-NetFirewallRule –DisplayName "Remote Event Monitor*"
            write-host "Disabled Firewall Rules for WinRM, Wecsrv: $?" "`n"
            Foreach ($ss in $services)
            {
            if ($ss.Name -like "*Wecsvc")
                {
                Write-Output  "Windows Event Collector Service is running, adding outbound firewall blocks for source initated subscriptions"
                New-NetFirewallRule -DisplayName "Disable Winrm HTTP Remote Management Outbound" -Direction Outbound -Action Block -LocalPort 5985 -Protocol TCP | out-null
                write-host "WinRM Outbound 5985 Firewall Block Was Added: $?"
                New-NetFirewallRule -DisplayName "Disable Winrm HTTPS Remote Management Outbound" -Direction Outbound -Action Block -LocalPort 5986 -Protocol TCP | out-null
                write-host "WinRM Outbound 5986 Firewall Block Was Added: $?" "`n"
                }
            if ($ss.Name -like "*winrm")
                {
                Write-Output "WinRM Service is running, adding inbound firewall blocks for collector initated subscriptions"
                Disable-NetFirewallRule –DisplayName "Windows Remote Management*"
                New-NetFirewallRule -DisplayName "Disable Winrm HTTP Remote Management Inbound" -Direction Inbound -Action Block -LocalPort 5985 -Protocol TCP | out-null
                write-host "WinRM Inbound 5985 Firewall Block Was Added: $?"
                New-NetFirewallRule -DisplayName "Disable Winrm HTTPS Remote Management Inbound" -Direction Inbound -Action Block -LocalPort 5986 -Protocol TCP | out-null
                write-host "WinRM Inbound 5986 Firewall Block Was Added: $?" "`n"
                }

            }

}

