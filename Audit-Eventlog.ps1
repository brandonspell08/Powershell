 #function Audit-Eventlog
  #  {
        [cmdletbinding()]
        Param(
            [string[]]$computername = 'localhost',
            [datetime]$starttime=(get-date).AddDays(-10),
            [datetime]$endtime=(Get-Date),
            [ValidateSet('Critical','Error','Warning','All')]
            [string[]]$eventlevel,
            [switch]$csvexport,
            [switch]$rcaexport

        )
        Begin
            {
                switch($eventlevel)
                    {
                        "All"      {break}
                        "Critical" {$level += '1'}
                        "Warning"  {$level += '2'}
                        "Error"    {$level += '3'}
                    }
                [psobject]$Global:resultsarray = @()
            }
        Process
            {
                $compprog = 0
                foreach($comp in $computername)
                    {
                        $compprog++
                        Write-Progress `
                            -Id 0 `
                            -Activity "Querying Server" `
                            -Status "Processing $compprog of $($computername.Count)" `
                            -CurrentOperation $comp `
                            -PercentComplete (($compprog/$computername.count)*100)
                            

                        $logs = Get-WinEvent -ListLog * -ComputerName $comp -Force -ErrorAction SilentlyContinue | where {$_.recordcount}

                        $logprog = 0

                        foreach($log in $logs)
                            {
                                $logprog++
                                Write-Progress `
                                    -Id 1 `
                                    -Activity "Querying Logs" `
                                    -Status "Processing $logprog of $($logs.Count)" `
                                    -CurrentOperation $log `
                                    -PercentComplete (($logprog/$logs.Count)*100)

                                $filterhash = 
                                    @{
                                        'Logname'=$log.logname
                                        'Starttime'=$starttime
                                        'endtime'=$endtime
                                    }
                                if($eventlevel)
                                    {
                                        $filterhash.Add('Level',$level)
                                    }
                                
                                $Global:resultsarray += Get-WinEvent -ComputerName $comp -FilterHashtable $filterhash -ErrorAction SilentlyContinue
                            }
                    }
            }
        End
            {
            if($csvexport)
                {
                    $path = "$env:USERPROFILE\desktop\Eventlogs_"+$((get-date).ToString("ddmmyyhhmm"))+".csv"
                    $resultsarray | select Timecreated,Id,Logname,LevelDisplayName,Message | Export-Csv -Path $path -NoTypeInformation

                    Write-Host "Events Saved to:`t" -NoNewline
                    Write-Host -ForegroundColor Yellow $path
                }

            if($rcaexport)
                {
                    $path = "$env:USERPROFILE\desktop\Eventlogs_"+$((get-date).ToString("ddmmyyhhmm"))+".xml"
                    $resultsarray | Export-Clixml -Depth 3 -Path $path

                    Write-Host "Events saved to:`t" -NoNewline
                    Write-Host -ForegroundColor Yellow $path
                }
            }
   # }

<#
Name                           Value                                           
----                           -----                                          
Verbose                        5                                              
Informational                  4                                              
Warning                        3                                              
Error                          2                                              
Critical                       1                                              
LogAlways                      0    
#>