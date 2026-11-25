<#
.SYNOPSIS
    Déploie un micro-service Windows exécuté sous un compte gMSA (Group Managed Service Account).

.DESCRIPTION
    Cas d'usage complet, hors création du gMSA (qui doit déjà exister dans l'AD) :
      1. Contrôle des prérequis (droits admin, module ActiveDirectory, gMSA existant).
      2. Install-ADServiceAccount + Test-ADServiceAccount (le serveur doit figurer dans
         PrincipalsAllowedToRetrieveManagedPassword du gMSA).
      3. (Option -DeploySample) compilation d'un micro-service HTTP de démonstration (/health).
      4. Dossiers et ACL au moindre privilège : lecture/exécution sur l'application,
         modification sur le dossier de logs du service.
      5. Droit "Ouvrir une session en tant que service" (SeServiceLogonRight) pour le gMSA.
      6. Création du service (sans mot de passe), démarrage Automatic (Delayed), actions de
         récupération (redémarrages automatiques), réservation d'URL http (urlacl) et règle
         de pare-feu optionnelle.
      7. Démarrage et vérification (état, compte d'exécution, test /health pour l'exemple).

    Sécurité (bonnes pratiques Microsoft / ANSSI) : aucun mot de passe manipulé, compte dédié
    sans ouverture de session interactive, moindre privilège sur les fichiers, pas de LocalSystem.

    Journalisation : un fichier .log et un fichier d'état .json (avant/après) sont écrits dans
    -ScriptLogDirectory. L'action Rollback rejoue le JSON en ordre inverse.
    Mode simulation : -WhatIf (rien n'est modifié, rien n'est écrit dans le journal d'état).

.PARAMETER Action
    Install (défaut) | Rollback | Status.

.PARAMETER ServiceName
    Nom court du service. Défaut : MicroSvcDemo.

.PARAMETER DisplayName
    Nom affiché. Défaut : Micro-service Demo (gMSA).

.PARAMETER Description
    Description du service.

.PARAMETER NoGmsa
    Avec -Action Install : crée le service SANS gMSA, sous -InitialAccount (LocalService par défaut).
    Le gMSA est associé ensuite avec -Action AssignGmsa (démarche didactique en deux temps).

.PARAMETER InitialAccount
    Compte provisoire utilisé avec -NoGmsa et restauré par le Rollback de AssignGmsa.
    Défaut : NT AUTHORITY\LocalService (moindre privilège, contrairement à LocalSystem).

.PARAMETER GmsaAccount
    gMSA existant : 'nom$', 'DOMAINE\nom$' ou 'nom'. Défaut : svc_microsvc$ (domaine courant).

.PARAMETER InstallDirectory
    Dossier de l'application. Défaut : C:\Services\MicroSvcDemo.

.PARAMETER BinaryPath
    Exécutable du service. Défaut : <InstallDirectory>\MicroSvcDemo.exe.

.PARAMETER Arguments
    Arguments de ligne de commande du binaire. Défaut : aucun.

.PARAMETER ServiceLogDirectory
    Dossier de logs applicatifs (droit Modify pour le gMSA). Défaut : <InstallDirectory>\logs.

.PARAMETER ScriptLogDirectory
    Dossier du journal et des états JSON du script. Défaut : C:\ProgramData\GmsaService\Logs.

.PARAMETER StartupType
    Automatic (défaut), AutomaticDelayedStart, Manual, Disabled.

.PARAMETER DependsOn
    Services requis. Défaut : Tcpip.

.PARAMETER Port
    Port HTTP du micro-service. Défaut : 8080. 0 = pas d'urlacl ni de pare-feu.

.PARAMETER OpenFirewall
    Crée une règle de pare-feu entrante TCP sur -Port.

.PARAMETER FirewallRemoteAddress
    Adresses autorisées par la règle de pare-feu. Défaut : LocalSubnet.

.PARAMETER DeploySample
    Compile et déploie le micro-service de démonstration (csc.exe du .NET Framework 4).

.PARAMETER SkipLogonRight
    Ne modifie pas la stratégie locale (à utiliser si le droit est géré par GPO).

.PARAMETER StateFile
    Fichier d'état JSON pour Rollback. Défaut : le plus récent pour ce service.

.PARAMETER StartTimeoutSeconds
    Délai d'attente du démarrage. Défaut : 30.

.EXAMPLE
    .\New-GmsaMicroService.ps1 -DeploySample -OpenFirewall -WhatIf
    Simule l'installation complète de l'exemple.

.EXAMPLE
    .\New-GmsaMicroService.ps1 -ServiceName MonApi -GmsaAccount 'CONTOSO\svc_api$' -BinaryPath 'D:\Apps\Api\Api.exe' -InstallDirectory 'D:\Apps\Api' -Port 5000 -OpenFirewall
    Installe un service existant sous le gMSA.

.EXAMPLE
    .\New-GmsaMicroService.ps1 -Action Status -ServiceName MicroSvcDemo

.EXAMPLE
    .\New-GmsaMicroService.ps1 -Action Rollback -ServiceName MicroSvcDemo
    Annule la dernière installation (service, urlacl, pare-feu, ACL, droit, installation gMSA).

.EXAMPLE
    # Étape 1 : service sans gMSA, étape 2 : association du gMSA
    .\New-GmsaMicroService.ps1 -NoGmsa -DeploySample -OpenFirewall
    .\New-GmsaMicroService.ps1 -Action AssignGmsa -GmsaAccount 'CONTOSO\svc_microsvc$'

.NOTES
    Version : 1.1.0 (2026-11-03)
    1.0.0 : version initiale. 1.1.0 : -NoGmsa (création sans gMSA) et action AssignGmsa (association a posteriori).
    Prérequis : Windows Server 2012 R2+, PowerShell 5.1+, RSAT AD PowerShell, session administrateur.
    Après ajout du serveur au gMSA, redémarrer le serveur (ou klist -li 0x3e7 purge) avant l'installation.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [ValidateSet('Install', 'AssignGmsa', 'Rollback', 'Status')]
    [string]$Action = 'Install',

    [ValidatePattern('^[A-Za-z0-9_.-]{1,80}$')]
    [string]$ServiceName = 'MicroSvcDemo',

    [string]$DisplayName = 'Micro-service Demo (gMSA)',
    [string]$Description = 'Micro-service exécuté sous un compte gMSA.',
    [string]$GmsaAccount = 'svc_microsvc$',
    [switch]$NoGmsa,
    [string]$InitialAccount = 'NT AUTHORITY\LocalService',
    [string]$InstallDirectory = 'C:\Services\MicroSvcDemo',
    [string]$BinaryPath = '',
    [string]$Arguments = '',
    [string]$ServiceLogDirectory = '',
    [string]$ScriptLogDirectory = 'C:\ProgramData\GmsaService\Logs',

    [ValidateSet('Automatic', 'AutomaticDelayedStart', 'Manual', 'Disabled')]
    [string]$StartupType = 'AutomaticDelayedStart',

    [string[]]$DependsOn = @('Tcpip'),

    [ValidateRange(0, 65535)]
    [int]$Port = 8080,

    [switch]$OpenFirewall,
    [string]$FirewallRemoteAddress = 'LocalSubnet',
    [switch]$DeploySample,
    [switch]$SkipLogonRight,
    [string]$StateFile = '',

    [ValidateRange(5, 600)]
    [int]$StartTimeoutSeconds = 30
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:ScriptVersion = '1.1.0'

if (-not $BinaryPath) { $BinaryPath = Join-Path $InstallDirectory 'MicroSvcDemo.exe' }
if (-not $ServiceLogDirectory) { $ServiceLogDirectory = Join-Path $InstallDirectory 'logs' }

#region Journalisation
$script:RunId = Get-Date -Format 'yyyyMMdd-HHmmss'
$script:LogFile = Join-Path $ScriptLogDirectory ("{0}-{1}-{2}.log" -f $ServiceName, $Action, $script:RunId)
$script:Operations = [System.Collections.Generic.List[object]]::new()
$script:StatePath = Join-Path $ScriptLogDirectory ("{0}-state-{1}.json" -f $ServiceName, $script:RunId)

function Write-SvcLog {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Sortie console colorée, doublée dans le journal')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR', 'PLAN', 'OK')][string]$Level = 'INFO'
    )
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    $color = switch ($Level) { 'ERROR' { 'Red' } 'WARN' { 'Yellow' } 'OK' { 'Green' } 'PLAN' { 'Cyan' } default { 'Gray' } }
    Write-Host $line -ForegroundColor $color
    if (-not (Test-Path -LiteralPath $ScriptLogDirectory)) {
        New-Item -ItemType Directory -Path $ScriptLogDirectory -Force -WhatIf:$false | Out-Null
    }
    Add-Content -LiteralPath $script:LogFile -Value $line -Encoding UTF8 -WhatIf:$false
}

function Save-State {
    param([string]$Status = 'InProgress')
    if ($WhatIfPreference) { return }
    $state = [ordered]@{
        Version     = $script:ScriptVersion
        Status      = $Status
        Date        = (Get-Date).ToString('o')
        Computer    = $env:COMPUTERNAME
        ServiceName = $ServiceName
        Gmsa        = $script:Gmsa
        Operations  = @($script:Operations)
    }
    $state | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $script:StatePath -Encoding UTF8 -WhatIf:$false
}

function Add-Operation {
    param([string]$Type, [hashtable]$Data = @{})
    $script:Operations.Add([pscustomobject](@{ Type = $Type; Time = (Get-Date).ToString('o') } + $Data))
    Save-State
}
#endregion

#region Utilitaires
function Test-IsAdministrator {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Resolve-GmsaName {
    param([string]$Name)
    $domain = $env:USERDOMAIN
    $sam = $Name
    if ($Name -match '^(?<d>[^\\]+)\\(?<n>.+)$') { $domain = $Matches['d']; $sam = $Matches['n'] }
    if (-not $sam.EndsWith('$')) { $sam += '$' }
    [pscustomobject]@{ Sam = $sam; Domain = $domain; Full = "$domain\$sam" }
}

function Get-AccountSid {
    param([string]$Account)
    ([Security.Principal.NTAccount]$Account).Translate([Security.Principal.SecurityIdentifier]).Value
}

function Invoke-Native {
    param([string]$File, [string[]]$ArgumentList)
    $out = & $File @ArgumentList 2>&1
    Write-SvcLog ("{0} {1} -> code {2}" -f $File, ($ArgumentList -join ' '), $LASTEXITCODE)
    if ($LASTEXITCODE -ne 0) { throw ("Échec {0} (code {1}) : {2}" -f $File, $LASTEXITCODE, ($out -join ' ')) }
    $out
}

function Add-DirectoryAcl {
    param([string]$Path, [string]$Account, [string]$Rights)
    $acl = Get-Acl -LiteralPath $Path
    $rule = [Security.AccessControl.FileSystemAccessRule]::new(
        $Account, $Rights, 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    $acl.AddAccessRule($rule)
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Invoke-AclRemoval {
    param([string]$Path, [string]$Account, [string]$Rights)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $acl = Get-Acl -LiteralPath $Path
    $rule = [Security.AccessControl.FileSystemAccessRule]::new(
        $Account, $Rights, 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    [void]$acl.RemoveAccessRule($rule)
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Invoke-LogonRightChange {
    # $Grant = $true : ajoute le SID à SeServiceLogonRight ; $false : le retire.
    param([string]$Sid, [bool]$Grant)
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("secedit-{0}" -f [guid]::NewGuid())
    New-Item -ItemType Directory -Path $tmp -Force -WhatIf:$false | Out-Null
    try {
        $cfg = Join-Path $tmp 'cur.inf'
        $new = Join-Path $tmp 'new.inf'
        $null = Invoke-Native -File 'secedit.exe' -ArgumentList @('/export', '/cfg', $cfg, '/areas', 'USER_RIGHTS', '/quiet')
        $line = (Get-Content -LiteralPath $cfg | Where-Object { $_ -match '^SeServiceLogonRight\s*=' } | Select-Object -First 1)
        $current = @()
        if ($line) { $current = @(($line -replace '^SeServiceLogonRight\s*=\s*', '').Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
        $has = $current -contains "*$Sid"
        if ($Grant -and $has) { return $false }
        if ((-not $Grant) -and (-not $has)) { return $false }
        $list = if ($Grant) { $current + "*$Sid" } else { @($current | Where-Object { $_ -ne "*$Sid" }) }
        $inf = @('[Unicode]', 'Unicode=yes', '[Version]', 'signature="$CHICAGO$"', 'Revision=1',
            '[Privilege Rights]', ('SeServiceLogonRight = ' + ($list -join ',')))
        Set-Content -LiteralPath $new -Value $inf -Encoding Unicode -WhatIf:$false
        $null = Invoke-Native -File 'secedit.exe' -ArgumentList @('/configure', '/db', (Join-Path $tmp 'tmp.sdb'), '/cfg', $new, '/areas', 'USER_RIGHTS', '/quiet')
        return $true
    }
    finally { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue -WhatIf:$false }
}

function Invoke-SampleBuild {
    param([string]$OutFile, [int]$ListenPort, [string]$LogDir, [string]$Name)
    $csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    if (-not (Test-Path -LiteralPath $csc)) { throw "csc.exe introuvable : $csc" }
    $src = @'
using System;
using System.IO;
using System.Net;
using System.Text;
using System.Threading;
using System.ServiceProcess;
using System.Security.Principal;

public class MicroSvc : ServiceBase
{
    private HttpListener listener;
    private Thread worker;
    private string logDir;
    private int port;

    public MicroSvc(string name, int port, string logDir)
    {
        this.ServiceName = name; this.port = port; this.logDir = logDir;
        this.CanStop = true;
    }

    private void Log(string msg)
    {
        try { File.AppendAllText(Path.Combine(logDir, "service.log"),
            DateTime.Now.ToString("s") + " " + msg + Environment.NewLine); } catch { }
    }

    protected override void OnStart(string[] args)
    {
        Directory.CreateDirectory(logDir);
        listener = new HttpListener();
        listener.Prefixes.Add("http://+:" + port + "/");
        listener.Start();
        Log("Demarre sous " + WindowsIdentity.GetCurrent().Name + " sur le port " + port);
        worker = new Thread(Loop); worker.IsBackground = true; worker.Start();
    }

    private void Loop()
    {
        while (listener.IsListening)
        {
            try
            {
                HttpListenerContext c = listener.GetContext();
                string body = "{\"status\":\"ok\",\"identity\":\"" +
                    WindowsIdentity.GetCurrent().Name.Replace("\\", "\\\\") +
                    "\",\"machine\":\"" + Environment.MachineName + "\",\"time\":\"" +
                    DateTime.UtcNow.ToString("o") + "\"}";
                byte[] b = Encoding.UTF8.GetBytes(body);
                c.Response.ContentType = "application/json";
                c.Response.OutputStream.Write(b, 0, b.Length);
                c.Response.Close();
            }
            catch { break; }
        }
    }

    protected override void OnStop()
    {
        Log("Arret");
        if (listener != null) { listener.Close(); }
    }

    public static void Main(string[] args)
    {
        int p = %PORT%; string d = @"%LOGDIR%"; string n = "%NAME%";
        ServiceBase.Run(new MicroSvc(n, p, d));
    }
}
'@
    $src = $src.Replace('%PORT%', [string]$ListenPort).Replace('%LOGDIR%', $LogDir).Replace('%NAME%', $Name)
    $srcFile = Join-Path ([IO.Path]::GetTempPath()) ("microsvc-{0}.cs" -f [guid]::NewGuid())
    Set-Content -LiteralPath $srcFile -Value $src -Encoding UTF8 -WhatIf:$false
    try {
        $null = Invoke-Native -File $csc -ArgumentList @('/nologo', '/target:exe', "/out:$OutFile",
            '/reference:System.ServiceProcess.dll', $srcFile)
    }
    finally { Remove-Item -LiteralPath $srcFile -Force -ErrorAction SilentlyContinue -WhatIf:$false }
}
#endregion

#region Install
function Install-GmsaLocal {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    $ad = Get-ADServiceAccount -Identity $script:Gmsa.Sam -Properties PrincipalsAllowedToRetrieveManagedPassword, Enabled
    Write-SvcLog "gMSA trouvé : $($ad.DistinguishedName) (Enabled=$($ad.Enabled))"
    if (-not $ad.Enabled) { throw 'Le gMSA est désactivé.' }

    $alreadyInstalled = $false
    try { $alreadyInstalled = [bool](Test-ADServiceAccount -Identity $script:Gmsa.Sam) } catch { $alreadyInstalled = $false }
    if ($alreadyInstalled) {
        Write-SvcLog 'gMSA déjà installé et valide sur ce serveur.' 'OK'
    }
    elseif ($PSCmdlet.ShouldProcess($script:Gmsa.Sam, 'Install-ADServiceAccount')) {
        Install-ADServiceAccount -Identity $script:Gmsa.Sam
        if (-not (Test-ADServiceAccount -Identity $script:Gmsa.Sam)) {
            throw "Test-ADServiceAccount a échoué : le serveur n'est pas dans PrincipalsAllowedToRetrieveManagedPassword (ou redémarrage requis)."
        }
        Write-SvcLog 'gMSA installé et testé.' 'OK'
        Add-Operation -Type 'InstallGmsa' -Data @{ Sam = $script:Gmsa.Sam }
    }
    else { Write-SvcLog "Install-ADServiceAccount $($script:Gmsa.Sam) puis Test-ADServiceAccount" 'PLAN' }
}

function Invoke-Install {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    $runAs = if ($NoGmsa) { $InitialAccount } else { $script:Gmsa.Full }
    Write-SvcLog "=== Installation du service '$ServiceName' sous $runAs ==="

    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
        throw "Le service '$ServiceName' existe déjà. Faire un Rollback ou choisir un autre nom."
    }
    if (-not $DeploySample -and -not (Test-Path -LiteralPath $BinaryPath)) {
        throw "Binaire introuvable : $BinaryPath (utiliser -DeploySample ou -BinaryPath)."
    }

    # 1. gMSA
    if (-not $NoGmsa) { Install-GmsaLocal }

    # 2. Dossiers
    foreach ($dir in @($InstallDirectory, $ServiceLogDirectory)) {
        if (Test-Path -LiteralPath $dir) { continue }
        if ($PSCmdlet.ShouldProcess($dir, 'Créer le dossier')) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            Add-Operation -Type 'CreateDirectory' -Data @{ Path = $dir }
            Write-SvcLog "Dossier créé : $dir" 'OK'
        }
        else { Write-SvcLog "Créer le dossier $dir" 'PLAN' }
    }

    # 3. Exemple
    if ($DeploySample) {
        if ($PSCmdlet.ShouldProcess($BinaryPath, 'Compiler le micro-service de démonstration')) {
            Invoke-SampleBuild -OutFile $BinaryPath -ListenPort $Port -LogDir $ServiceLogDirectory -Name $ServiceName
            Add-Operation -Type 'DeployFile' -Data @{ Path = $BinaryPath }
            Write-SvcLog "Exemple compilé : $BinaryPath" 'OK'
        }
        else { Write-SvcLog "Compiler l'exemple vers $BinaryPath" 'PLAN' }
    }

    # 4. ACL
    foreach ($acl in @(@{ P = $InstallDirectory; R = 'ReadAndExecute' }, @{ P = $ServiceLogDirectory; R = 'Modify' })) {
        if ($PSCmdlet.ShouldProcess($acl.P, "ACL $($acl.R) pour $($runAs)")) {
            Add-DirectoryAcl -Path $acl.P -Account $runAs -Rights $acl.R
            Add-Operation -Type 'AddAcl' -Data @{ Path = $acl.P; Account = $runAs; Rights = $acl.R }
            Write-SvcLog "ACL $($acl.R) ajoutée sur $($acl.P)" 'OK'
        }
        else { Write-SvcLog "ACL $($acl.R) sur $($acl.P) pour $($runAs)" 'PLAN' }
    }

    # 5. Droit d'ouverture de session en tant que service
    if (-not $SkipLogonRight -and -not $NoGmsa) {
        if ($PSCmdlet.ShouldProcess($runAs, 'Accorder SeServiceLogonRight')) {
            $sid = Get-AccountSid -Account $runAs
            if (Invoke-LogonRightChange -Sid $sid -Grant $true) {
                Add-Operation -Type 'GrantLogonRight' -Data @{ Sid = $sid }
                Write-SvcLog 'Droit "Ouvrir une session en tant que service" accordé (une GPO peut le redéfinir).' 'OK'
            }
            else { Write-SvcLog 'Droit déjà présent.' }
        }
        else { Write-SvcLog "Accorder SeServiceLogonRight à $($runAs)" 'PLAN' }
    }

    # 6. Service
    $cmd = '"{0}"' -f $BinaryPath
    if ($Arguments) { $cmd += " $Arguments" }
    if ($PSCmdlet.ShouldProcess($ServiceName, "Créer le service ($cmd)")) {
        $params = @{ Name = $ServiceName; BinaryPathName = $cmd; DisplayName = $DisplayName; Description = $Description }
        $params.StartupType = if ($StartupType -eq 'AutomaticDelayedStart') { 'Automatic' } else { $StartupType }
        if ($DependsOn) { $params.DependsOn = $DependsOn }
        New-Service @params | Out-Null
        Add-Operation -Type 'CreateService' -Data @{ Name = $ServiceName }
        $null = Invoke-Native -File 'sc.exe' -ArgumentList @('config', $ServiceName, 'obj=', $runAs)
        if ($StartupType -eq 'AutomaticDelayedStart') {
            $null = Invoke-Native -File 'sc.exe' -ArgumentList @('config', $ServiceName, 'start=', 'delayed-auto')
        }
        $null = Invoke-Native -File 'sc.exe' -ArgumentList @('failure', $ServiceName, 'reset=', '86400',
            'actions=', 'restart/5000/restart/15000/restart/60000')
        $null = Invoke-Native -File 'sc.exe' -ArgumentList @('failureflag', $ServiceName, '1')
        Write-SvcLog "Service créé sous $($runAs) avec récupération automatique." 'OK'
    }
    else { Write-SvcLog "Créer le service $ServiceName (obj=$($runAs), start=$StartupType, recovery restart x3)" 'PLAN' }

    # 7. urlacl et pare-feu
    if ($Port -gt 0) {
        $url = "http://+:$Port/"
        if ($PSCmdlet.ShouldProcess($url, "Réserver l'URL pour $($runAs)")) {
            $null = Invoke-Native -File 'netsh.exe' -ArgumentList @('http', 'add', 'urlacl', "url=$url", "user=$($runAs)")
            Add-Operation -Type 'AddUrlAcl' -Data @{ Url = $url }
            Write-SvcLog "urlacl $url réservée." 'OK'
        }
        else { Write-SvcLog "netsh http add urlacl url=$url user=$($runAs)" 'PLAN' }

        if ($OpenFirewall) {
            $rule = "$ServiceName (TCP $Port)"
            if ($PSCmdlet.ShouldProcess($rule, 'Créer la règle de pare-feu')) {
                New-NetFirewallRule -DisplayName $rule -Direction Inbound -Protocol TCP -LocalPort $Port `
                    -Action Allow -RemoteAddress $FirewallRemoteAddress -Profile Domain | Out-Null
                Add-Operation -Type 'AddFirewallRule' -Data @{ DisplayName = $rule }
                Write-SvcLog "Règle de pare-feu créée : $rule ($FirewallRemoteAddress, profil Domain)." 'OK'
            }
            else { Write-SvcLog "Règle de pare-feu entrante TCP $Port depuis $FirewallRemoteAddress" 'PLAN' }
        }
    }

    # 8. Démarrage et vérification
    if ($PSCmdlet.ShouldProcess($ServiceName, 'Démarrer et vérifier')) {
        Start-Service -Name $ServiceName
        (Get-Service -Name $ServiceName).WaitForStatus('Running', [TimeSpan]::FromSeconds($StartTimeoutSeconds))
        $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'"
        Write-SvcLog "État=$($svc.State) ; compte=$($svc.StartName) ; PID=$($svc.ProcessId)" 'OK'
        if ($svc.StartName -ne $runAs -and ($NoGmsa -or $svc.StartName -notlike "*$($script:Gmsa.Sam)")) {
            Write-SvcLog "Compte inattendu : $($svc.StartName)" 'WARN'
        }
        if ($DeploySample -and $Port -gt 0) {
            Start-Sleep -Seconds 2
            $r = Invoke-RestMethod -Uri "http://localhost:$Port/health" -TimeoutSec 10
            Write-SvcLog ("/health -> status={0} identity={1}" -f $r.status, $r.identity) 'OK'
        }
        Save-State -Status 'Completed'
    }
    else { Write-SvcLog "Démarrer $ServiceName et vérifier le compte d'exécution" 'PLAN' }
}
function Invoke-AssignGmsa {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    Write-SvcLog "=== Association du gMSA $($script:Gmsa.Full) au service '$ServiceName' ==="
    $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
    if (-not $svc) { throw "Service '$ServiceName' introuvable : l'installer d'abord (-Action Install -NoGmsa)." }
    $current = $svc.StartName
    Write-SvcLog "Compte actuel du service : $current"
    if ($current -eq $script:Gmsa.Full -or $current -like "*$($script:Gmsa.Sam)") { throw 'Le service utilise déjà ce gMSA.' }
    $wasRunning = ($svc.State -eq 'Running')

    # 1. gMSA
    Install-GmsaLocal

    # 2. ACL
    foreach ($acl in @(@{ P = $InstallDirectory; R = 'ReadAndExecute' }, @{ P = $ServiceLogDirectory; R = 'Modify' })) {
        if (-not (Test-Path -LiteralPath $acl.P)) { Write-SvcLog "Dossier absent, ACL ignorée : $($acl.P)" 'WARN'; continue }
        if ($PSCmdlet.ShouldProcess($acl.P, "ACL $($acl.R) pour $($script:Gmsa.Full)")) {
            Add-DirectoryAcl -Path $acl.P -Account $script:Gmsa.Full -Rights $acl.R
            Add-Operation -Type 'AddAcl' -Data @{ Path = $acl.P; Account = $script:Gmsa.Full; Rights = $acl.R }
            Write-SvcLog "ACL $($acl.R) ajoutée sur $($acl.P)" 'OK'
        }
        else { Write-SvcLog "ACL $($acl.R) sur $($acl.P) pour $($script:Gmsa.Full)" 'PLAN' }
    }

    # 3. Droit d'ouverture de session en tant que service
    if (-not $SkipLogonRight) {
        if ($PSCmdlet.ShouldProcess($script:Gmsa.Full, 'Accorder SeServiceLogonRight')) {
            $sid = Get-AccountSid -Account $script:Gmsa.Full
            if (Invoke-LogonRightChange -Sid $sid -Grant $true) {
                Add-Operation -Type 'GrantLogonRight' -Data @{ Sid = $sid }
                Write-SvcLog 'Droit "Ouvrir une session en tant que service" accordé.' 'OK'
            }
            else { Write-SvcLog 'Droit déjà présent.' }
        }
        else { Write-SvcLog "Accorder SeServiceLogonRight à $($script:Gmsa.Full)" 'PLAN' }
    }

    # 4. urlacl : la réservation appartient à l'ancien compte, on la réattribue
    if ($Port -gt 0) {
        $url = "http://+:$Port/"
        if ($PSCmdlet.ShouldProcess($url, "Réattribuer l'urlacl à $($script:Gmsa.Full)")) {
            $null = & netsh.exe http delete urlacl "url=$url" 2>&1
            $null = Invoke-Native -File 'netsh.exe' -ArgumentList @('http', 'add', 'urlacl', "url=$url", "user=$($script:Gmsa.Full)")
            Add-Operation -Type 'ReplaceUrlAcl' -Data @{ Url = $url; PreviousUser = $current }
            Write-SvcLog "urlacl $url réattribuée à $($script:Gmsa.Full)." 'OK'
        }
        else { Write-SvcLog "netsh http delete urlacl puis add urlacl url=$url user=$($script:Gmsa.Full)" 'PLAN' }
    }

    # 5. Changement de compte (sans mot de passe) et redémarrage
    if ($PSCmdlet.ShouldProcess($ServiceName, "sc config obj= $($script:Gmsa.Full) (redémarrage si en cours)")) {
        if ($wasRunning) { Stop-Service -Name $ServiceName -Force }
        $null = Invoke-Native -File 'sc.exe' -ArgumentList @('config', $ServiceName, 'obj=', $script:Gmsa.Full)
        Add-Operation -Type 'ChangeServiceAccount' -Data @{ Name = $ServiceName; PreviousAccount = $current; WasRunning = $wasRunning }
        Write-SvcLog "Compte du service : $current -> $($script:Gmsa.Full)" 'OK'
        Start-Service -Name $ServiceName
        (Get-Service -Name $ServiceName).WaitForStatus('Running', [TimeSpan]::FromSeconds($StartTimeoutSeconds))
        $new = Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'"
        Write-SvcLog "État=$($new.State) ; compte=$($new.StartName) ; PID=$($new.ProcessId)" 'OK'
        if ($Port -gt 0) {
            try {
                Start-Sleep -Seconds 2
                $r = Invoke-RestMethod -Uri "http://localhost:$Port/health" -TimeoutSec 10
                Write-SvcLog ("/health -> status={0} identity={1}" -f $r.status, $r.identity) 'OK'
            }
            catch { Write-SvcLog "/health non joignable (binaire personnalisé ?) : $($_.Exception.Message)" 'WARN' }
        }
        Save-State -Status 'Completed'
    }
    else { Write-SvcLog "sc config $ServiceName obj= $($script:Gmsa.Full) puis redémarrage et vérification" 'PLAN' }
}
#endregion

#region Rollback
function Invoke-Rollback {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    $file = $StateFile
    if (-not $file) {
        $file = Get-ChildItem -LiteralPath $ScriptLogDirectory -Filter "$ServiceName-state-*.json" -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1 -ExpandProperty FullName
    }
    if (-not $file -or -not (Test-Path -LiteralPath $file)) { throw 'Aucun fichier d''état trouvé (utiliser -StateFile).' }
    Write-SvcLog "=== Rollback depuis $file ==="
    $state = Get-Content -LiteralPath $file -Raw -Encoding UTF8 | ConvertFrom-Json
    $ops = @($state.Operations)
    [array]::Reverse($ops)

    foreach ($op in $ops) {
        try {
            switch ($op.Type) {
                'ChangeServiceAccount' {
                    if ($PSCmdlet.ShouldProcess($op.Name, "Restaurer le compte $($op.PreviousAccount)")) {
                        Stop-Service -Name $op.Name -Force -ErrorAction SilentlyContinue
                        $null = Invoke-Native -File 'sc.exe' -ArgumentList @('config', $op.Name, 'obj=', $op.PreviousAccount)
                        if ($op.WasRunning) { Start-Service -Name $op.Name }
                        Write-SvcLog "Compte du service restauré : $($op.PreviousAccount)." 'OK'
                    }
                    else { Write-SvcLog "sc config $($op.Name) obj= $($op.PreviousAccount)" 'PLAN' }
                }
                'ReplaceUrlAcl' {
                    if ($PSCmdlet.ShouldProcess($op.Url, "Réattribuer l'urlacl à $($op.PreviousUser)")) {
                        $null = & netsh.exe http delete urlacl "url=$($op.Url)" 2>&1
                        $null = Invoke-Native -File 'netsh.exe' -ArgumentList @('http', 'add', 'urlacl', "url=$($op.Url)", "user=$($op.PreviousUser)")
                        Write-SvcLog "urlacl $($op.Url) restaurée pour $($op.PreviousUser)." 'OK'
                    }
                    else { Write-SvcLog "Restaurer l'urlacl $($op.Url) pour $($op.PreviousUser)" 'PLAN' }
                }
                'CreateService' {
                    if (Get-Service -Name $op.Name -ErrorAction SilentlyContinue) {
                        if ($PSCmdlet.ShouldProcess($op.Name, 'Arrêter et supprimer le service')) {
                            Stop-Service -Name $op.Name -Force -ErrorAction SilentlyContinue
                            $null = Invoke-Native -File 'sc.exe' -ArgumentList @('delete', $op.Name)
                            Write-SvcLog "Service $($op.Name) supprimé." 'OK'
                        }
                        else { Write-SvcLog "Supprimer le service $($op.Name)" 'PLAN' }
                    }
                }
                'AddFirewallRule' {
                    if ($PSCmdlet.ShouldProcess($op.DisplayName, 'Supprimer la règle de pare-feu')) {
                        Remove-NetFirewallRule -DisplayName $op.DisplayName -ErrorAction SilentlyContinue
                        Write-SvcLog "Règle $($op.DisplayName) supprimée." 'OK'
                    }
                    else { Write-SvcLog "Supprimer la règle $($op.DisplayName)" 'PLAN' }
                }
                'AddUrlAcl' {
                    if ($PSCmdlet.ShouldProcess($op.Url, 'Supprimer l''urlacl')) {
                        $null = Invoke-Native -File 'netsh.exe' -ArgumentList @('http', 'delete', 'urlacl', "url=$($op.Url)")
                        Write-SvcLog "urlacl $($op.Url) supprimée." 'OK'
                    }
                    else { Write-SvcLog "Supprimer l'urlacl $($op.Url)" 'PLAN' }
                }
                'GrantLogonRight' {
                    if ($PSCmdlet.ShouldProcess($op.Sid, 'Retirer SeServiceLogonRight')) {
                        [void](Invoke-LogonRightChange -Sid $op.Sid -Grant $false)
                        Write-SvcLog 'Droit d''ouverture de session en tant que service retiré.' 'OK'
                    }
                    else { Write-SvcLog "Retirer SeServiceLogonRight pour $($op.Sid)" 'PLAN' }
                }
                'AddAcl' {
                    if ($PSCmdlet.ShouldProcess($op.Path, "Retirer l'ACL $($op.Rights)")) {
                        Invoke-AclRemoval -Path $op.Path -Account $op.Account -Rights $op.Rights
                        Write-SvcLog "ACL retirée sur $($op.Path)." 'OK'
                    }
                    else { Write-SvcLog "Retirer l'ACL $($op.Rights) sur $($op.Path)" 'PLAN' }
                }
                'DeployFile' {
                    if ((Test-Path -LiteralPath $op.Path) -and $PSCmdlet.ShouldProcess($op.Path, 'Supprimer le fichier déployé')) {
                        Remove-Item -LiteralPath $op.Path -Force
                        Write-SvcLog "Fichier $($op.Path) supprimé." 'OK'
                    }
                    elseif (Test-Path -LiteralPath $op.Path) { Write-SvcLog "Supprimer le fichier $($op.Path)" 'PLAN' }
                }
                'CreateDirectory' {
                    $empty = (Test-Path -LiteralPath $op.Path) -and -not (Get-ChildItem -LiteralPath $op.Path -Force -ErrorAction SilentlyContinue)
                    if ($empty -and $PSCmdlet.ShouldProcess($op.Path, 'Supprimer le dossier vide')) {
                        Remove-Item -LiteralPath $op.Path -Force
                        Write-SvcLog "Dossier $($op.Path) supprimé." 'OK'
                    }
                    elseif (Test-Path -LiteralPath $op.Path) { Write-SvcLog "Dossier $($op.Path) conservé (non vide, ou simulation)." 'INFO' }
                }
                'InstallGmsa' {
                    if ($PSCmdlet.ShouldProcess($op.Sam, 'Uninstall-ADServiceAccount (local uniquement)')) {
                        Uninstall-ADServiceAccount -Identity $op.Sam -Confirm:$false
                        Write-SvcLog "gMSA $($op.Sam) désinstallé de ce serveur (l'objet AD est conservé)." 'OK'
                    }
                    else { Write-SvcLog "Uninstall-ADServiceAccount $($op.Sam)" 'PLAN' }
                }
            }
        }
        catch { Write-SvcLog "Rollback $($op.Type) : $($_.Exception.Message)" 'ERROR' }
    }
}
#endregion

#region Status
function Get-Status {
    $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
    if (-not $svc) { Write-SvcLog "Service $ServiceName introuvable." 'WARN'; return }
    Write-SvcLog ("Service={0} État={1} Démarrage={2} Compte={3} Binaire={4}" -f $svc.Name, $svc.State, $svc.StartMode, $svc.StartName, $svc.PathName)
    try { Write-SvcLog ("Test-ADServiceAccount({0}) = {1}" -f $script:Gmsa.Sam, (Test-ADServiceAccount -Identity $script:Gmsa.Sam)) }
    catch { Write-SvcLog "Test-ADServiceAccount : $($_.Exception.Message)" 'WARN' }
}
#endregion

#region Main
try {
    $script:Gmsa = if ($NoGmsa -and $Action -eq 'Install') { $null } else { Resolve-GmsaName -Name $GmsaAccount }
    $gmsaLabel = if ($script:Gmsa) { $script:Gmsa.Full } else { "(aucun, compte provisoire $InitialAccount)" }
    Write-SvcLog "Démarrage v$($script:ScriptVersion) - Action=$Action Service=$ServiceName gMSA=$gmsaLabel WhatIf=$([bool]$WhatIfPreference)"

    if (-not (Test-IsAdministrator)) { throw 'Exécuter dans une session PowerShell élevée (administrateur).' }
    if ($script:Gmsa) {
        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
            throw 'Module ActiveDirectory absent. Installer RSAT : Install-WindowsFeature RSAT-AD-PowerShell'
        }
        Import-Module ActiveDirectory -ErrorAction Stop
    }

    switch ($Action) {
        'Install' { Invoke-Install; Save-State -Status 'Completed' }
        'AssignGmsa' { Invoke-AssignGmsa }
        'Rollback' { Invoke-Rollback }
        'Status' { Get-Status }
    }
    Write-SvcLog "Terminé. Journal : $($script:LogFile)" 'OK'
    if ($Action -in 'Install', 'AssignGmsa' -and -not $WhatIfPreference) { Write-SvcLog "État JSON : $($script:StatePath)" }
}
catch {
    Write-SvcLog $_.Exception.Message 'ERROR'
    if ($Action -in 'Install', 'AssignGmsa' -and $script:Operations.Count -gt 0) {
        Write-SvcLog "Installation partielle : lancer -Action Rollback pour annuler (état : $($script:StatePath))." 'WARN'
        Save-State -Status 'Failed'
    }
    exit 1
}
#endregion
