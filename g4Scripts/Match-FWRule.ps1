function Match-FWRule{
<#
	.SYNOPSIS
	Matches a source and destination IP Address to Gen4 Rules from a CSV Export

	.DESCRIPTION
	This Function is meant to be used by Armor Engineers for the purpose of auditing and troubleshooting rules present in
    the Armor 'IMC/AMP' Environment. To utilize, you must first login to IMC and navigate to a customer account. Then go
    to 'SECURITY > FIREWALL'. Be sure to select the proper Datacenter location that you would like to audit. Then, at the
    bottom right-hand corner of the screen, you will have the option to export the rules. Export 'ALL' rules.

    To run function, Open Powershell, change to the directory of the function and run:
    . .\Match-FWRule.ps1
    or
    Import-Module .\Match-GWRule.ps1 -force -scope Global

	.PARAMETER csvfile
    This Paramert is required. This should be the CSV File location of Firewall Rules
    exported from IMC/AMP

	.PARAMETER Source
	Specify a Source IP Address. Locates all rules in CSV File with the IP.

	.PARAMETER Destination 
	Specify a Destination IP Address. Locates all rules in CSV File with the IP Address.

    .Parameter Action
    Allows viewing only 'Allow' rules, or only 'Block' rules. If this parameter is not specified, both Allow and Block rules will be displayed in results.

	.NOTES
	Author: Robin Fordham
    Contribution by: Brandon Spell
    Intellectual Property of Armor Defence Inc.
		
		
	.LINK
	https://armor.com

	.EXAMPLE

    PS C:\> Match-Gen4FwRule -csvfile 'C:\temp\rules.csv' -source '162.216.41.174' -destination '162.216.41.148' -port 25
    
        Number      : 504
        Name        : VDC services
        Action      : allow
        Source      : {100.68.151.0/24, 162.216.41.176, 162.216.41.177, 162.216.41.159...}
        Destination : {0.0.0.0/0, }
        Services    : {tcp/20, tcp/21, tcp/22, tcp/25...}

        Number      : 518
        Name        : Auto APP Inbound
        Action      : block
        Source      : {0.0.0.0/0, }
        Destination : {162.216.41.159, 204.13.110.37, 162.216.41.168, 162.216.41.160...}
        Services    : {icmp/echo-request, icmp/echo-reply, udp/1-65535, tcp/1-65535...}
    
    .Example
    PS C:\> Match-Gen4FwRule -csvfile 'C:\temp\rules.csv' -destination '162.216.41.174' -action Block


        Number      : 518
        Name        : Auto APP Inbound
        Action      : block
        Source      : {0.0.0.0/0, }
        Destination : {162.216.41.159, 204.13.110.37, 162.216.41.168, 162.216.41.160...}
        Services    : {icmp/echo-request, icmp/echo-reply, udp/1-65535, tcp/1-65535...}

        Number      : 519
        Name        : Auto DB Inbound
        Action      : block
        Source      : {0.0.0.0/0, }
        Destination : {74.120.217.243, 162.216.41.172, 162.216.41.165, 162.216.41.164...}
        Services    : {icmp/echo-request, icmp/echo-reply, udp/1-65535, tcp/1-65535...}
    
    .Example
    PS C:\> Match-Gen4FwRule -csvfile 'C:\temp\virmedica.csv' -source '162.216.41.174' -destination '162.216.41.148' |sort destination |select -First 4 |ft

        Number Name                      Action Source                                                               Destination                                                       Services
        ------ ----                      ------ ------                                                               -----------                                                       --------
        504    VDC services              allow  {100.68.151.0/24, 162.216.41.176, 162.216.41.177, 162.216.41.159...} {0.0.0.0/0, }                                                     {tcp/20, tcp/21, tcp/22, tcp/25...}
        28     TRAN05VML01 354hp98h7rofb allow  {162.216.41.83, 162.216.41.175, 162.216.41.174, 74.120.216.61...}    {0.0.0.0/0, }                                                     {icmp/echo-request, icmp/echo-reply, }
        503    Auto LB Outbound          allow  {162.216.41.176, 162.216.41.177, 162.216.41.174, 74.120.216.77...}   {0.0.0.0/0, }                                                     {icmp/echo-request, icmp/echo-reply, tcp/80, tcp/443...}
        4      SSH from Gen4             allow  {162.216.41.148, 162.216.41.149, 162.216.41.159, 162.216.41.160...}  {100.68.151.12, 100.68.153.11, 100.68.151.11, 199.180.184.234...} {icmp/echo-request, icmp/echo-reply, tcp/22, }

#>


 param (
    [Parameter(Mandatory=$true)][string]$csvfile,
    [Parameter(Mandatory=$false)][Net.IPAddress]$source=$null,
    [Parameter(Mandatory=$false)][Net.IPAddress]$destination=$null,
    [int]$port = $null,
    [ValidateSet('Block','Allow')][string]$action=$null,
    [string]$protocol = $null,
    $test

 )

 #Functions needed for script
    Begin{
        $MatchArray = [psobject][System.Collections.ArrayList]@()


        #Tests if 2 ip addresses are in the same network
        Function NetMatcher ([Net.IPAddress]$mask,[Net.IPAddress]$ip1,[Net.IPAddress]$ip2){

            if (($ip1.Address -band $mask.Address) -eq ($ip2.Address -band $mask.Address))
                {return $true}
            else
                {return $false}
            }

        #Returns IP and Mask array from a given ip and CIDR (\32 assumed if no CIDR is present)
        Function IpMask ([String]$text){
            $IpMask = $text.Split("/")
            #Items with no CIDR
            if ($IpMask.Length -eq 1){
                [Net.IPAddress]$ip = $IpMask[0]
                $IpMask[0] = $ip
                [Net.IPAddress]$mask = -bnot [uint32]0
                $IpMask += $mask
            }
            #Items with CIDR
            else{
                [Net.IPAddress]$ip = $IpMask[0]
                $IpMask[0] = $ip

                if ($IpMask -eq "0"){
                [Net.IPAddress]$mask =  [uint32]0
                }
                else{
                [Net.IPAddress]$WildMask = ((-bnot [uint32]0) -shl (32 - $IpMask[1]))
                $mask = $WildMask.GetAddressBytes()
                [Array]::Reverse($mask)
                $mask = ([System.Net.IPAddress]($mask -join '.'))
                }
                $IpMask[1] = $mask
            }
            return $IpMask
        }

        #takes start and end address and returns array of all addresses in the range #### DEPRECATED ###
        function ReturnIpRange ($start, $end) {
             $ip1 = ([System.Net.IPAddress]$start).GetAddressBytes()
             [Array]::Reverse($ip1)
             $ip1 = ([System.Net.IPAddress]($ip1 -join '.')).Address
             $ip2 = ([System.Net.IPAddress]$end).GetAddressBytes()
             [Array]::Reverse($ip2)
             $ip2 = ([System.Net.IPAddress]($ip2 -join '.')).Address

             for ($x=$ip1; $x -le $ip2; $x++) {
                 $ip = ([System.Net.IPAddress]$x).GetAddressBytes()
                 [Array]::Reverse($ip)
                 $ip -join '.'
            }
        }

        #Checks if an IP is in a range
        function IpRangeCheck ($Start, $End, $Ip){
            $Start = ([System.Net.IPAddress]$Start).GetAddressBytes()
            [Array]::Reverse($Start)
            $Start = [BitConverter]::ToUInt32($Start, 0)

            $End = ([System.Net.IPAddress]$End).GetAddressBytes()
            [Array]::Reverse($End)
            $End = [BitConverter]::ToUInt32($End, 0)

            $Ip = ([System.Net.IPAddress]$Ip).GetAddressBytes()
            [Array]::Reverse($Ip)
            $Ip = [BitConverter]::ToUInt32($Ip, 0)

            if ($Ip -ge $Start -and $Ip -le $End){
                return 1
                }
                else{
                return 0
                }
        }

        #Takes a string of IP addresses and an IP address, returns true is match is found
        Function CellIpMatch($cell,$ip){
            $Ips = $cell.Split(";")
            $IpMatch = 0   
            for ($i=0; $i -lt $Ips.length - 1; $i++)
                {
                    #Catch ranges
                    if ($Ips[$i] -match "-"){
                        if (IpRangeCheck $Ips[$i].split("-")[0] $Ips[$i].split("-")[1] $ip -eq 1){
                            $IpMatch = 1
                        }
                    }
                    else{       
              
                        $x = IpMask $Ips[$i]
                        if (NetMatcher $x[1] $x[0] $ip)
                            {
                            $IpMatch = 1
                            }
                    }
                   }
                   return $IpMatch
           }

        #Checks Port if supplied, returns true for valid match
        Function PortMatch ($cell, $Port){

            if ( -not $Port){
                return 1
            }
            if ($cell -match "^\d+-\d+$"){
                $Ports = $cell.split("-")
                if ([int]$port -ge [int]$Ports[0] -and [int]$Port -le [int]$Ports[1]){
                return 1
                }
                else{
                return 0
                }
            }

            if ($cell -match "^" + $Port + "$"){
                return 1
            }
            return 0
        }

        #Checks Proto if supplied, returns true for valid match
        Function ProtoMatch ($cell, $Proto){
        if ( -not $Proto){
            return 1
        }
        if ($cell -match $Proto){
            return 1
        }
        return 0
        }

        #Takes a Protocol csv cell, returns true for a  match on proto and port
        Function ServiceMatch ($cell, $Port, $Proto) {
            $Match = 0

            $Services = $Cell.split(";")
            for ($i=0; $i -lt $Services.length - 1; $i++){
                $ProtoPort = $Services[$i].split("/")
                if ((ProtoMatch $ProtoPort[0] $Proto) -and (PortMatch $ProtoPort[1] $Port)){
                    $Match = 1
                }
            }
            return $Match
        }

        ################ =============== Unit Tests =============== ################

        Function Test_NetMatcher {
            #Matching networks
            $ip1 = "128.0.0.0", "10.10.10.10", "10.10.10.10"
            $ip2 = "10.10.10.10", "10.10.10.10", "10.10.100.100"
            $Mask = "0.0.0.0", "255.255.255.255", "255.255.0.0"

            $Pass = 1
            for ($i=0; $i -lt $Ip1.length; $i++){
                if ((NetMatcher $Mask[$i] $ip1[$i] $ip2[$i]) -eq $false){
                    $Pass = 0
                    }
            }
            #differing networks
            $ip1 = "128.0.0.0", "10.10.10.11", "10.10.10.10"
            $ip2 = "10.10.10.10", "10.10.10.10", "10.11.100.100"
            $Mask = "128.0.0.0", "255.255.255.255", "255.255.0.0"
            for ($i=0; $i -lt $Ip1.length - 1; $i++){
                if ((NetMatcher $Mask[$i] $ip1[$i] $ip2[$i]) -eq $true){
                $Pass = 0
                }
            }

            if ($Pass -eq 1){
                Write-host "NetMatcher: `t pass"
            }
            else{
                Write-host "NetMatcher: `t fail"
            }


        }

        Function Test_IpMask {
            $Pass = 1

            $IpMasks = "0.0.0.0/0", "172.16.255.255/17", "192.168.1.100/32", "10.7.1.1/15"
            $Ips = [Net.IPAddress]("0.0.0.0"), [Net.IPAddress]("172.16.255.255"),[Net.IPAddress]("192.168.1.100"),[Net.IPAddress]("10.7.1.1")
            $Masks = [Net.IPAddress]("0.0.0.0"), [Net.IPAddress]("255.255.128.0"),[Net.IPAddress]("255.255.255.255"),[Net.IPAddress]("255.254.0.0")

            for ($i=0; $i -lt $Ips.length; $i++){
                 $Result = IpMask $IpMasks[$i]
                 if ($Result[0] -ne $Ips[$i] -or $Result[1] -ne $Masks[$i]){
                 $Pass =0
             }
            }
            if ($Pass -eq 1){
                Write-host "IpMask: `t`t pass"
            }
            else{
                Write-host "IpMask: `t`t fail"
            }
        }

        Function Test_ReturnIpRange{
            $Pass = 1

            $Start = "10.0.0.0"
            $End = "10.0.0.3"
            $Expected = [System.Net.IPAddress]"10.0.0.0", [System.Net.IPAddress]"10.0.0.1", [System.Net.IPAddress]"10.0.0.2", [System.Net.IPAddress]"10.0.0.3"
            $Result = ReturnIpRange $Start $End

            if (Compare-object -ReferenceObject $Expected -DifferenceObject $Result){
                $Pass = 0
            }

            $Start = "192.168.1.253"
            $End = "192.168.2.2"
            $Expected = [System.Net.IPAddress]"192.168.1.253", [System.Net.IPAddress]"192.168.1.254", [System.Net.IPAddress]"192.168.1.255", [System.Net.IPAddress]"192.168.2.0", [System.Net.IPAddress]"192.168.2.1", [System.Net.IPAddress]"192.168.2.2"
            $Result = ReturnIpRange $Start $End
            if (Compare-object -ReferenceObject $Expected -DifferenceObject $Result){
                $Pass = 0
            }
            if ($Pass -eq 1){
                Write-host "ReturnIpRange: `t pass"
            }
            else{
                Write-host "ReturnIpRange: `t fail"
            }
        }

        Function Test_IpRangeCheck ($Start, $End, $Ip){
            $Pass = 1

            $Start = "10.0.0.0", "10.0.0.0", "10.0.0.0", "192.168.1.1", "192.168.1.1", "192.168.1.1", "192.168.1.1", "192.168.1.1"
            $End = "10.0.0.1", "10.0.0.1", "10.0.0.1", "192.168.5.200", "192.168.5.200", "192.168.5.200", "192.168.5.200", "255.255.255.255"
            $Ip = "10.0.0.1", "10.0.0.1", "9.0.0.255", "192.168.1.100", "192.168.4.100", "192.168.0.100", "192.168.0.100", "200.200.200.200"
            $Result = 1, 1, 0, 1, 1, 0, 0, 1

            for ($i=0; $i -lt $Start.length; $i++){
                if ((IpRangeCheck $Start[$i] $End[$i] $Ip[$i]) -ne $Result[$i]){
                $pass = 0
                }
            }

            if ($Pass -eq 1){
                Write-host "IpRangeCheck: `t pass"
            }
            else{
                Write-host "IpRangeCheck: `t fail"
            }
        }

        Function Test_CellIpMatch{
        $Pass = 1

        $Cells = "172.22.0.0-172.22.1.255;148.25.46.33;172.16.23.200;120.120.120.120;", "192.168.1.1;", "192.168.1.1;177.28.1.0/25;", "172.22.0.0-172.22.1.255;148.25.46.33;172.16.23.200;120.120.120.120;"
        $IpsMatch = "172.22.1.200", "192.168.1.1", "177.28.1.120", "148.25.46.33"

        for ($i=0; $i -lt $Cells.length; $i++){
            if ((CellIpMatch $Cells[$i] $IpsMatch[$i]) -eq 0){
            $Pass = 0
            }
        }

        $Cells = "172.22.0.0-172.22.1.255;148.25.46.33;172.16.23.200;120.120.120.120;", "192.168.1.1;", "192.168.1.1;177.28.1.0/25;", "172.22.0.0-172.22.1.255;148.25.46.33;172.16.23.200;120.120.120.120;"
        $IpsMatch = "172.22.2.1", "192.168.1.2", "177.28.1.128", "148.25.46.34"

        for ($i=0; $i -lt $Cells.length; $i++){
            if ((CellIpMatch $Cells[$i] $IpsMatch[$i]) -eq 1){
            $Pass = 0
            }
        }

        if ($Pass -eq 1){
            Write-host "CellIpMatch: `t pass"
        }
        else{
            Write-host "CellIpMatch: `t fail"
        }
        }

        Function Test_PortMatch{
            $Pass = 1

            $TestCells = "65535", "1", "138", "445", "445", "445", "1-14", "3-14", "2-14", "2-14", "1-14", "1-65535", "1-65535", "1-65535"
            $TestPorts = "65535","1","138","445", "4", "5", "1", "14", "10", "1", "15", "100", "1", "65535"
            $Results = 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 1

            for ($i=0; $i -lt $TestCells.length; $i++){
                $Result = PortMatch $TestCells[$i] $TestPorts[$i] $Results[$i]
    
                if ($Result -ne $Results[$i]){
                $Pass =0
                }
            }


            if ($Pass -eq 1){
                Write-host "PortMatch: `t`t pass"
            }
            else{
                Write-host "PortMatch: `t`t fail"
            }
        }

        Function Test_ProtoMatch (){
            $Pass = 1

            $TestCells = "tcp", "udp", "icmp", "icmp", "udp", "tcp"
            $TestProtos = "tcp", "udp", "icmp", "", "tcp", "udp"
            $Results = 1, 1, 1, 1, 0, 0

            for ($i=0; $i -lt $TestCells.Length; $i++){
                $Result = ProtoMatch $TestCells[$i] $TestProtos[$i]
                if ($Result -ne $Results[$i]){
                $Pass =0
                }

            }

            if ($Pass -eq 1){
                Write-host "ProtoMatch: `t pass"
            }
            else{
                Write-host "ProtoMatch: `t fail"
            }
        }

        Function Test_ServiceMatch ($cell, $Port, $Proto){
            $Pass = 1

            $TestCells = "tcp/80;icmp/echo-reply;tcp/443;icmp/echo-request;", "tcp/80;icmp/echo-reply;tcp/443;icmp/echo-request;", "tcp/80;icmp/echo-reply;tcp/443;icmp/echo-request;", "tcp/80;icmp/echo-reply;tcp/443;icmp/echo-request;", "tcp/80;icmp/echo-reply;tcp/443;icmp/echo-request;", "tcp/80;icmp/echo-reply;tcp/443;icmp/echo-request;", "tcp/80;icmp/echo-reply;tcp/443;icmp/echo-request;"
            $TestProtos = "", "","tcp","udp", "","udp","icmp"
            $TestPorts = "", "80","","", "500","500",""
            $Results = 1,1,1,0,0,0,1

            for ($i=0; $i -lt $TestCells.Length; $i++){
                $Result = ServiceMatch $TestCells[$i] $TestPorts[$i] $TestProtos[$i]
                if ($Result -ne $Results[$i]){
                $Pass =0
   
                }
                }

            if ($Pass -eq 1){
                Write-host "ServiceMatch: `t pass"
            }
            else{
                Write-host "ServiceMatch: `t fail"
            }
        }

    }#End Begin

    Process{
        if ($test -eq $true){

            Test_NetMatcher
            Test_IpMask
            Test_ReturnIpRange
            Test_IpRangeCheck
            Test_CellIpMatch
            Test_PortMatch
            Test_ProtoMatch
            Test_ServiceMatch
        }#end IF


        elseif(Test-Path -Path $csvfile){
            $csvimport = Import-Csv -Path $csvfile 

            if($action -ne $null){
                switch($action){
                    
                    {$action -eq "block"}{$csvimport = $csvimport | where {$_.action -eq 'block'};break}
                    {$action -eq "allow"}{$csvimport = $csvimport | where {$_.action -eq 'allow'};break}
                    
                    }#end switch
            
            
            }#end IF

            switch($source -or $destination){

                {$source -eq $null -and $destination -eq $null}{Write-Warning "Please define Source and/or Destination";break}


                {$source -eq $null} {$csvimport = $csvimport |where{
                                            (CellIpMatch $_.Destinations $destination) -and
                                            (ServiceMatch $_.Services $Port $Protocol) -and
                                            ($_.Enabled -eq "TRUE")
                                        };break               
                                    }#end Switch-1

                {$destination -eq $null} {$csvimport = $csvimport |where{
                                            (CellIpMatch $_.Sources $source) -and
                                            (ServiceMatch $_.Services $Port $Protocol) -and
                                            ($_.Enabled -eq "TRUE")
                                        };break
                                    }#end Switch-2
                                            
                

                {$source -ne $null -and 
                $destination -ne $null}{$csvimport = $csvimport |where{
                                            (CellIpMatch $_.Sources $source) -and
                                            (CellIpMatch $_.Destinations $destination) -and
                                            (ServiceMatch $_.Services $Port $Protocol) -and
                                            ($_.Enabled -eq "TRUE")
                                        };break
                                    }#end Switch-3

                }#end Switch Statement

        }#end Elseif

        else{
            Write-Warning ("{0}: File does not exist!" -f $csvfile)
            exit
0        }#end Else
           
    }#End Process

    End{
        $csvimport | ForEach-Object{
            $Match = [pscustomobject]@{
                Number=$_.Order; 
                Name=$_.Name;
                Action=$_.Action; 
                Source=@(($_.Sources.split(";"))); 
                Destination=@($_.Destinations.split(";")); 
                Services=$_.Services.split(";")
                }
            $MatchArray.add($Match) | Out-Null
        } #end Foreach

        if($MatchArray -eq $null){
        Write-Warning "No Matches Found"
        }
        else{
        $MatchArray
        }
    
    }#End End

}#End Function

