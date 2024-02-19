# By TSM (Skydoo ICT Team)
# v0.6 240219-1

# Chemin de base pour les scripts
$scriptsBasePath = "C:\Tools\"
# Chemin complet du script PowerShell
$scriptPath = Join-Path -Path $scriptsBasePath -ChildPath "blockIp.ps1"
# Nom de la tâche planifiée
$taskName = "_BlockIPsTask"
# Chemins et variables globales
$logPath = Join-Path -Path $scriptsBasePath -ChildPath "LogFile.log"
$blockLogFile = Join-Path -Path $scriptsBasePath -ChildPath "BlockLog.csv"
$attemptsLogPath = Join-Path -Path $scriptsBasePath -ChildPath "AttemptsLog.csv"
$logName = "Security"
$filter = "*[System[EventID=4625]]"

# URL du fichier RAW de WL sur GitHub
$whiteListUrl = "https://raw.githubusercontent.com/Risc-Skydoo/wl-ips/main/skydoo.txt"
# Chemin local où enregistrer le fichier de la liste blanche
$whiteListPath = Join-Path -Path $scriptsBasePath -ChildPath "Whitelist.txt"

# Téléchargement du fichier de white-list
function Update-Whitelist {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Url,

        [Parameter(Mandatory = $true)]
        [string]$DestinationPath
    )

    try {
        Invoke-WebRequest -Uri $Url -OutFile $DestinationPath -ErrorAction Stop
        Write-Log "La liste blanche a été mise à jour avec succès à partir de : $Url"
    } catch {
        Write-Log "Erreur lors de la mise à jour de la liste blanche à partir de : $Url. Détail de l'erreur : $_"
    }
}

# Vérification de l'existence de la tache planifiée
function Set-PersistentScheduledTask {
    param (
        [string]$TaskName,
        [string]$ScriptPath,
        [int]$RepeatIntervalMinutes
    )

    # Vérification de l'existence de la tâche
    $taskExists = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($null -ne $taskExists) {
        Write-Log "La tâche '$TaskName' existe déjà."
        return
    }

    # Configuration de l'action
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`""

    # Configuration du déclencheur pour une répétition continue
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes $RepeatIntervalMinutes) -RepetitionDuration (New-TimeSpan -Days 365)

    # Configuration des paramètres
    $taskSettings = New-ScheduledTaskSettingsSet

    # Ajout de -StartWhenAvailable après la création initiale
    $taskSettings.StartWhenAvailable = $true

    # Enregistrement de la tâche avec les paramètres configurés
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $taskSettings -RunLevel Highest -User "SYSTEM" -Force
    
    Write-Log "La tâche planifiée '$TaskName' a été créée et s'exécutera toutes les $RepeatIntervalMinutes minutes."
}

# Fonction pour écrire dans le journal
function Write-Log {
    param ([string]$message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp - $message"
    Add-Content -Path $logPath -Value $logEntry
}

# Fonction pour nettoyer le journal
function Clean-Log {
    param (
        [string]$logPath,
        [int]$days
    )
    $cutoffDate = (Get-Date).AddDays(-$days)
    $currentContent = Get-Content -Path $logPath
    $newContent = @()

    foreach ($line in $currentContent) {
        if ($line -match "^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}") {
            $timestamp = [datetime]::ParseExact($matches[0], "yyyy-MM-dd HH:mm:ss", $null)

            if ($timestamp -gt $cutoffDate) {
                $newContent += $line
            }
        }
    }

    $newContent | Set-Content -Path $logPath
    Write-Log "Fichier log nettoyé. Les entrées de plus de 24h ont été supprimées."
}

# Fonction pour ajouter une entrée de blocage
function Add-BlockLogEntry {
    param (
        [string]$ip,
        [datetime]$timestamp
    )
    "$ip,$timestamp" | Out-File -FilePath $blockLogFile -Append
}

# Fonction pour supprimer les blocages expirés
function Remove-ExpiredBlocks {
    if (Test-Path -Path $blockLogFile) {
        $currentEntries = Get-Content -Path $blockLogFile
        $updatedEntries = @()

        foreach ($entry in $currentEntries) {
            $parts = $entry -split ','
            $ip = $parts[0]
            $blockTime = [datetime]$parts[1]
            $currentTime = Get-Date

            if ($currentTime - $blockTime -gt [TimeSpan]::FromHours(24)) {
                # Supprime la règle de pare-feu
                $ruleName = "Block IP $ip"
                Get-NetFirewallRule -DisplayName $ruleName | Remove-NetFirewallRule
                Write-Log "Règle de pare-feu supprimée pour: $ip"
            } else {
                $updatedEntries += $entry
            }
        }

        # Met à jour le fichier log avec les entrées restantes
        $updatedEntries | Out-File -FilePath $blockLogFile
    }
}

# Vérifie si le fichier des tentatives existe
if (-not (Test-Path -Path $attemptsLogPath)) {
    # Crée le fichier s'il n'existe pas
    $null = New-Item -Path $attemptsLogPath -ItemType File
    Write-Log "Fichier des tentatives créé à : $attemptsLogPath"
}

# Fonction pour enregistrer une tentative
function Add-Attempt {
    param ([string]$ip)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$ip,$timestamp" | Out-File -FilePath $attemptsLogPath -Append
}

# Fonction pour vérifier le nombre de tentatives
function Check-Attempts {
    param ([string]$ip)
    $attempts = @(Get-Content -Path $attemptsLogPath | Where-Object { $_ -match "^$ip," })
    return $attempts.Count
}

# Fonction pour supprimer les tentatives après blocage
function Clear-Attempts {
    param ([string]$ip)
    $allAttempts = Get-Content -Path $attemptsLogPath
    $remainingAttempts = $allAttempts | Where-Object { -not ($_ -match "^$ip,") }
    $remainingAttempts | Set-Content -Path $attemptsLogPath
}

# Début du script

# Vérifie si le fichier de Log existe
if (-not (Test-Path -Path $logPath)) {
    # Crée le fichier s'il n'existe pas
    $null = New-Item -Path $logPath -ItemType File
    Write-Log "Fichier log créé à : $logPath"
}

Clean-Log -logPath $logPath -days 1
Write-Log "Début de l'exécution du script."
Set-PersistentScheduledTask -TaskName $taskName -ScriptPath $scriptPath -RepeatIntervalMinutes 10
Remove-ExpiredBlocks

# Appel de la fonction pour mettre à jour la liste blanche
Update-Whitelist -Url $whiteListUrl -DestinationPath $whiteListPath

# Calcul de la date de début pour filtrer les logs (15 minutes en arrière)
$startTime = (Get-Date).AddMinutes(-15)

# Tente de récupérer les événements récents
try {
    $events = Get-WinEvent -FilterHashtable @{
        LogName = $logName
        StartTime = $startTime
    } -ErrorAction Stop
    Write-Log "Logs des 15 dernières minutes récupérés avec succès."
} catch {
    Write-Log "Erreur lors de la récupération des logs: $_"
    exit
}

$ipsToBlock = @()

foreach ($event in $events) {
    if ($event.Message -match '\b\d{1,3}(\.\d{1,3}){3}\b') {
        $ip = $matches[0]
        if ($ip -notin $whitelist) {
            $attemptCount = Check-Attempts $ip
            if ($attemptCount -lt 3) {
                Add-Attempt $ip
                Write-Log "Tentative enregistrée pour $ip. Total tentatives: $($attemptCount + 1)"
            } else {
                # Ici, vous pourriez ajouter la logique pour bloquer l'adresse IP
                # et ensuite appeler Clear-Attempts pour réinitialiser le compteur pour cette IP
            }
        }
    }
}

foreach ($ip in $ipsToBlock) {
    $ruleName = "Block IP $ip"
    $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    if (-not $existingRule) {
        New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Action Block -RemoteAddress $ip
        Write-Log "Adresse IP bloquée avec succès: $ip"
        Add-BlockLogEntry -ip $ip -timestamp (Get-Date)
    } else {
        Write-Log "La règle existe déjà pour: $ip"
    }
}

Write-Log "Fin de l'exécution du script."
