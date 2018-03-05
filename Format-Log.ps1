function Format-Log  
    {
        param(
            [Parameter(
                ValueFromPipeline=$true,
                Position=0,
                Mandatory=$true
                )]
            [System.IO.FileInfo[]]$path = '$env:windir\debug\usermode\gpsvc.log',
            [Parameter(
                )]
            [ValidateSet('gplog','iislog')]
            [string]$logformat

            
        )

        foreach($file in $path)
            {

                if (!(Test-Path $file)) 
                    {
                        Write-Error -Message "Can't access logfile" -TargetObject $file -RecommendedAction "Check the path and try again.";return
                    }

                switch ($logformat)
                    {
                        "gplog"  {$regex = "(?<time>\d{2}:\d{2}:\d{2}:\d{3}) (?<message>.+)$"}
                        "iislog" {}
                    }
                
                

                # Get the content of gpsvc.log, ensuring that blank lines are excluded
                $log = Get-Content $path -Encoding Unicode | Where-Object {$_ -ne "" } 

                # Loop through each line in the log, and convert it to a custom object
                foreach ($line in $log) 
                    {
                        # Split the line, using our regular expression
                        $matchResult = $line | Select-String -Pattern $regex

                        # Split up the timestamp string, so that we can convert it to a DateTime object
                        $splitTime = $matchResult.Matches.Groups[3].Value -split ":"

                        # Create a custom object to store our parsed data, and put it onto the pipeline.
                        # Note that we're also converting the hex PID and TID values to decimal
                        [pscustomobject]@{
                            time = (Get-Date -Hour $splitTime[0] -Minute $splitTime[1] -Second $splitTime[2] -Millisecond $splitTime[3] -Format T)
                            message = $matchResult.Matches.Groups[4].Value
                        }
                    }
            }
    }
