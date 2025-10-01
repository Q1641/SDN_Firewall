# ===========================
# AD Logon → Firewall Forwarder
# ===========================

function Normalize-Username {
    param($user)

    # Strip @DOMAIN if present
    if ($user -match "^(.*)@") {
        $user = $matches[1]
    }

    # Ignore machine accounts ending with $
    if ($user -like "*$") {
        return $null
    }

    return $user
}

function Normalize-IP {
    param($ip)

    if (-not $ip) { return $null }

    # Extract IPv4 if presented in IPv6 format (like ::ffff:10.10.0.11)
    if ($ip -match "^::ffff:(\d{1,3}(\.\d{1,3}){3})$") {
        return $matches[1]
    }

    # Skip IPv6 addresses
    if ($ip -match ":") {
        return $null
    }

    # Skip loopback
    if ($ip -eq "127.0.0.1") {
        return $null
    }

    # Only allow clean IPv4
    if ($ip -match "^\d{1,3}(\.\d{1,3}){3}$") {
        return $ip
    }

    return $null
}

# Subscribe to Security Event Log
$query = "SELECT * FROM __InstanceCreationEvent WITHIN 1 
          WHERE TargetInstance ISA 'Win32_NTLogEvent' 
          AND (TargetInstance.EventCode = '4624' 
            OR TargetInstance.EventCode = '4768' 
            OR TargetInstance.EventCode = '4769' 
            OR TargetInstance.EventCode = '4770') 
          AND TargetInstance.Logfile = 'Security'"

Register-WmiEvent -Query $query -SourceIdentifier "AuthWatcher"

Write-Host "Listening for 4624, 4768, 4769, 4770 events. Press Ctrl+C to stop..."

while ($true) {
    $evt = Wait-Event -SourceIdentifier "AuthWatcher"
    $event = $evt.SourceEventArgs.NewEvent.TargetInstance
    $evCode = $event.EventCode

    $user = ""
    $ip   = ""

    switch ($evCode) {
        4768 { $user = $event.InsertionStrings[0]; $ip = $event.InsertionStrings[9] }
        4769 { $user = $event.InsertionStrings[0]; $ip = $event.InsertionStrings[8] }
        4770 { $user = $event.InsertionStrings[0]; $ip = $event.InsertionStrings[8] }
        4624 { $user = $event.InsertionStrings[5]; $ip = $event.InsertionStrings[18] }
    }

    # Normalize username
    $user = Normalize-Username $user
    if (-not $user) {
        Write-Host "Skipping event ${evCode}: invalid user"
        Remove-Event -EventIdentifier $evt.EventIdentifier
        continue
    }

    # Normalize IP
    $ip = Normalize-IP $ip
    if (-not $ip) {
        Write-Host "Skipping event $evCode for user ${user}: invalid IP"
        Remove-Event -EventIdentifier $evt.EventIdentifier
        continue
    }

    # Get AD groups
    try {
        $groups = Get-ADUser -Identity $user -Properties MemberOf | 
                  Get-ADPrincipalGroupMembership | 
                  Select-Object -ExpandProperty Name 
    } catch {
        $groups = @()
    }

    Write-Host "Event ${evCode}: User=$user IP=$ip Groups=$groups"

    # Build payload
    $payload = @{
        user  = $user
        ip    = $ip
        group = $groups
        time  = (Get-Date).ToString("o")
    } | ConvertTo-Json

    try {
        Invoke-RestMethod -Uri "http://10.10.10.10:21012/" `
                          -Method Post `
                          -Body $payload `
                          -ContentType "application/json"
        Write-Host "ok"
    } catch {
        Write-Warning "POST failed for $ip : $($_.Exception.Message)"
    }

    Remove-Event -EventIdentifier $evt.EventIdentifier
}
