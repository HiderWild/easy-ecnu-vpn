$ErrorActionPreference = "Stop"

Write-Host "=== EXV DTLS Diagnostics ==="
Get-Date -Format o

Write-Host "`n=== Adapters ==="
Get-NetAdapter |
    Sort-Object ifIndex |
    Format-Table ifIndex, Name, Status, MacAddress, LinkSpeed -AutoSize

Write-Host "`n=== IP Interfaces ==="
Get-NetIPInterface |
    Sort-Object InterfaceIndex, AddressFamily |
    Format-Table InterfaceIndex, InterfaceAlias, AddressFamily, NlMtu, InterfaceMetric, ConnectionState -AutoSize

Write-Host "`n=== IPv4 Routes ==="
$ipv4Routes = Get-NetRoute -AddressFamily IPv4
Write-Host ("Total IPv4 routes: {0}; showing first 80 sorted by route/interface metric." -f $ipv4Routes.Count)
$ipv4Routes |
    Sort-Object RouteMetric, InterfaceMetric |
    Select-Object -First 80 |
    Format-Table DestinationPrefix, NextHop, InterfaceAlias, RouteMetric, InterfaceMetric -AutoSize

Write-Host "`n=== DNS ==="
Get-DnsClientServerAddress |
    Format-Table InterfaceAlias, AddressFamily, ServerAddresses -AutoSize
