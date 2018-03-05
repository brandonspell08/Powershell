<#        function dl-file($url,$filename)
            {
                $web = New-Object system.net.webclient
                Register-ObjectEvent `
                    -InputObject $web `
                    -EventName DownloadProgressChanged `
                    -SourceIdentifier WebClient.DownloadProgressChanged `
                    -Action { Write-Progress -Activity "Downloading: $($EventArgs.ProgressPercentage)% Completed" -Status $url -PercentComplete $EventArgs.ProgressPercentage} | Out-Null

                Register-ObjectEvent `
                    -InputObject $web `
                    -EventName DownloadFileCompleted `
                    -SourceIdentifier WebClient.DownloadFileComplete `
                    -Action { 
                                Write-Color -Text "Download Complete",$filename -Color Green,Magenta 
                                Unregister-Event -SourceIdentifier WebClient.DownloadProgressChanged
                                Unregister-Event -SourceIdentifier WebClient.DownloadFileComplete
                            }  | Out-Null
                try
                    {
                        $web.DownloadFile($url,$filename)

                    }
                catch [system.net.webexception]
                    {
                        Write-Warning "Unable to download File!!"
                        if($_.exception){ Write-Color "Error Details:`t",$_.exception.message -Color Yellow,Red}
                        elseif($_.message){Write-Color "Error Details:`t",$_.message -Color Yellow,Red}
                        else{$_}
                    }
                Finally
                    {
                        $web.Dispose()
                    }
            }
#>

        function dl-panopta($url,$filename)
            {
                $Global:dlfinished = $false
                $web = New-Object system.net.webclient
                Register-ObjectEvent `
                    -InputObject $web `
                    -EventName DownloadFileCompleted `
                    -SourceIdentifier WebClient.DownloadFileCompleted `
                    -Action {$Global:dlfinished = $true;Unregister-Event -SourceIdentifier 'webclient.downloadfilecompleted'} | Out-Null 
                try
                    {
                        $web.DownloadFileAsync($url,$filename)

                    }
                catch [system.net.webexception]
                    {
                        Write-Warning "Unable to download File!!"
                        if($_.exception){ Write-Color "Error Details:`t",$_.exception.message -Color Yellow,Red}
                        elseif($_.message){Write-Color "Error Details:`t",$_.message -Color Yellow,Red}
                        else{$_}
                    }
                Finally
                    {
                        $web.Dispose()
                    }
            }
