########################################################################### 
# 
# NAME: GetInvalidImagePathsV2.ps1 
# 
# AUTHOR:      Suhas Rao 
# REVISED BY:  Mark Stanfill 
# 
# COMMENT: This script was created to help minimize the time of parsing through the registry searching for invalid ImagePaths 
#          under the HKEY_LOCAL_MACHINESYSTEMCurrentControlSetServices keys. 
# 
#          For more details, search for “Enumeration of the files failed” in a blog posted on: 
#          http://blogs.technet.com/b/askcore/ 
# 
#    Disclaimer: 
#    
#    The sample scripts are not supported under any Microsoft standard support program or service. 
#    The sample scripts are provided AS IS without warranty of any kind. Microsoft further disclaims all implied warranties including, 
#    without limitation, any implied warranties of merchantability or of fitness for a particular purpose. 
#    The entire risk arising out of the use or performance of the sample scripts and documentation remains with you. 
#    In no event shall Microsoft, its authors, or anyone else involved in the creation, production, 
#    or delivery of the scripts be liable for any damages whatsoever (including, without limitation, 
#    damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss) 
#    arising out of the use of or inability to use the sample scripts or documentation, even if Microsoft has been advised of the possibility of such damages. 
# 
# 
# VERSION HISTORY: 
# 1.0 – Initial release 
# 2.0 – Included searching for spaces in the path 
# 
###########################################################################


$Verbose = $true;


if (($ARGS.Count -gt 0) -and ($ARGS[0] -ieq “-verbose”)) 
{ 
    $Verbose = $true; 
}


# 
# The list of possible reasons for failure 
# 
$FailureReasons = @{ 
                    “INVALID_CHARS”      = “The service path contains invalid characters. ” + 
                                           “Characters < > : `” | ? cannot be used in a file path.”; 
                    “INVALID_FORMAT”     = “The service path does not have a proper path format. ” + 
                                           “Only paths beginning with [<Drive>]: format are supported.”; 
                    “DOUBLE_SLASH”       = “The service path contains double inverted slashes. ” + 
                                           “UNC Network paths or paths containing double inverted slashes are not supported.”; 
                    “RELATIVE_PATH”      = “The service path is relative. ” + 
                                           “Only absolute paths are supported.”; 
                    “FOWARD_SLASH”       = “The service path contains a foward slash. ” + 
                                           “Only paths containing an inverted slash are supported.”; 
                    “REPARSE_POINT”      = “The service path contains a reparse point. ” + 
                                           “Paths containing a reparse point are not supported.”; 
                    “UNRECOGNIZED_PATH”  = “Unable to check the path. ” + 
                                           “Expecting the ImagePath for the service to be a .dll or .exe”; 
            “SPACE_IN_PATH”      = “The service path contains spaces, ” + 
                       “the whole path needs to be enclosed using double quotes”;


                   }


# 
# The failure INVALID_CHARS can occur due to the following type of characters 
# 
$InvalidChars   = @{ 
                    “*\*”   = “DOUBLE_SLASH”; 
                    “*..*” = “RELATIVE_PATH”; 
                    “*.*”  = “RELATIVE_PATH”; 
                    “*/*”    = “FOWARD_SLASH” 
            
                   }



# 
# Display the service info 
# 
function PrintServiceInfo([System.Management.ManagementObject] $Service, [string] $Header, 
                          [string] $Reason, [string] $Color='white') 
{ 
    $Name    = $Service.Name 
    $Caption = $Service.Caption 
    $Path    = $Service.PathName 
    $Info    = $FailureReasons.Item($Reason)

    Write-Host -ForegroundColor $Color “$Header`n” ` 
               ”    Service Name    : $Name`n” ` 
               ”    Service Caption : $Caption`n” ` 
               ”    Registry key    : HKEY_LOCAL_MACHINESYSTEM\CurrentControlSet\services\$NameImagePath`n” ` 
               ”    Value           : $Path`n” ` 
               ”    Reason          : $Info`n” ` 
               “`n” `
}


# 
# For verbose mode, print extra info for every path 
# 
function PrintStatus([Boolean] $IsBadPath) 
{ 
    if ($Verbose -eq $true) 
    { 
        if ($IsBadPath -eq $true) 
        { 
            Write-Host “ERROR” -ForegroundColor Red; 
        } 
        else 
        { 
            Write-Host “OK” -ForeGroundColor Green; 
        } 
    } 
}


# 
# This is a core function that fetches the service path given the input from registry 
# It expects the service path to be a .dll or .exe 
# 
function GetActualPathFromServiceImagePath([string] $ServiceImagePath) 
{ 
    $ActualPathName = $null 
    $IndexForPath   = $null


    $ExeIndex = $ServiceImagePath.ToLower().IndexOf(“.exe”); 
    $DllIndex = $ServiceImagePath.ToLower().IndexOf(“.dll”);


    ## 
    ## NOTE: Assumption is that the Service Path Always ends in dll or exe 
    ## 
    if(($ExeIndex -eq -1) -and ($DllIndex -eq -1)) 
    { 
        return $null 
    }


    ## 
    ## If the path contains both Dll And Exe then we should use the One that Comes First 
    ## 
    if(($ExeIndex -ne -1) -and ($DllIndex -ne -1)) 
    { 
        if($ExeIndex -gt $DllIndex) 
        { 
            $IndexForPath = $DllIndex +4; 
        } 
        else 
        { 
            $IndexForPath = $ExeIndex +4; 
        } 
    } 
    else 
    { 
        if($ExeIndex -eq -1) 
        { 
            $IndexForPath = $DllIndex +4; 
        } 
        else 
        { 
            $IndexForPath = $ExeIndex +4; 
        } 
    }



    $ActualPathName = $ServiceImagePath.Substring(0,$IndexForPath)


    $Quote = “`”” 
    if($ActualPathName.StartsWith($Quote)) 
    { 
        $ActualPathName = $ActualPathName.Remove(0,1); 
    }


    if ($ActualPathName.StartsWith(“\?”) -or $ActualPathName.StartsWith(“\.”)) 
    { 
        $ActualPathName = $ActualPathName.Substring(4); 
    }


    return $ActualPathName 
}



################################################################################## 
##                                  Main                                        ## 
##################################################################################


$Services         = Get-WmiObject Win32_Service 
$BadServices      = $null 
$Reasons          = $null 
$UnrecognizedPath = 0



for ($i = 0; $i -lt $Services.Count; $i++) 
{ 
    ## 
    ## Get the actual Exe Path 
    ## 
    $ActualPathName = GetActualPathFromServiceImagePath $Services[$i].PathName 
    if($ActualPathName -eq $null) 
    { 
        $Path             = $Services[$i].PathName 
        $Name             = $Services[$i].Name 
        $UnrecognizedPath = 1;


        PrintServiceInfo $Services[$i] “WARNING:” “UNRECOGNIZED_PATH” “Yellow” 
        continue; 
    }



########new 
#######make sure all paths with spaces have double quotes around them


if ( ($Services[$i].PathName -match “^[^x22].*s.*.exe.*” ) -eq $true) 
   { 
    $BadServices += ,$Services[$i]; 
    $Reasons += ,”SPACE_IN_PATH”;


    PrintStatus($true); 
    continue;



   }


 


 


    if ($Verbose -eq $true) 
    { 
        Write-Host -nonewline “Analyzing path ‘$ActualPathName’ …” 
    }


    ## 
    ## Check for Attributes 
    ## 
    if((Test-Path -IsValid $ActualPathName) -eq $False) 
    { 
        $BadServices += ,$Services[$i] ; 
        $Reasons     += ,”INVALID_CHARS”;


        PrintStatus($true); 
        continue; 
    }



    ## 
    ## Check for invalid chars 
    ## 
    foreach ($Key in $InvalidChars.Keys) 
    { 
        $Value = $InvalidChars.Item($Key);


        if ($ActualPathName -like $Key) 
        { 
            $temp = $Key.Replace(“*”,””)


            $BadServices += ,$Services[$i] 
            $Reasons     += ,$Value; 
        }


    }


    ## 
    ## The Start string must be in the below specified format 
    ## 
    if((($ActualPathName -match “^[a-z]:\”) -ne $true)) 
    { 
        $BadServices += ,$Services[$i] 
        $Reasons     += ,”INVALID_FORMAT”;


        PrintStatus($true); 
        continue; 
    }


    ## 
    ## Check for Reparse points 
    ## 
    $RootPath = [System.IO.Path]::GetPathRoot($ActualPathName)


    
    $Path = $ActualPathName 
    $DoesPathExist = Test-Path -Path $ActualPathName 
    while(($DoesPathExist -eq $true) -and ($Path -ne $RootPath)) 
    {


         $h = [System.IO.File]::GetAttributes($Path);


         if ($h.CompareTo([System.IO.FileAttributes]::ReparsePoint) -ge 0) 
         { 
            $BadServices += ,$Services[$i] 
            $Reasons     += ,”REPARSE_POINT”;


            PrintStatus($true); 
            break; 
         }


         if ($Path.Contains(“”) -ne $true) 
         { 
             break; 
         }


         $strPath = $Path.Substring(0,$Path.LastIndexOf(“”)); 
         $Path    = $strPath 
    }


    PrintStatus($false); 
}



if ($BadServices.Count -gt 0) 
{ 
    echo “” 
    echo “Following are the service(s) found to be reporting invalid paths.” 
    echo “”


    for ($i=0; $i-lt$BadServices.Count; $i++) 
    { 
        $Count   = $i + 1 
        PrintServiceInfo $BadServices[$i] “$Count.” $Reasons[$i] 
    } 
} 
elseif ($UnrecognizedPath -ne 1) 
{ 
    echo “” 
    Write-Host “No invalid service paths found.” -ForeGroundColor Green 
    echo “” 
}