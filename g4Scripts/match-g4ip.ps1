function match-g4ip($ips,$rules,[switch]$all){
    foreach($ip in $ips){
        foreach($rule in $rules){
            if($rule.source -match $ip){
                Write-Host -ForegroundColor Yellow "$ip present in Rule #$($rule.Number)"
            }
            elseif($all){
                Write-Host -ForegroundColor Red "$ip missing in in Rule#$($rule.number)"
            }
        }
    }
}
