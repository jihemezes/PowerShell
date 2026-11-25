<#
    Script  : New-GmsaGui.ps1
    Version : 1.0.0 (2026-11-25)
    Auteur  : EZES Jean-Michel
    Avec la participation de l'IA : Claude (Anthropic)

.SYNOPSIS
    Assistant graphique de création d'un gMSA et du groupe d'ordinateurs autorisés à récupérer son mot de passe.

.DESCRIPTION
    Onglet 1 « gMSA et groupe »
      - Tier du compte (0, 1, 2) : propose l'OU <Tier{N}-gMSA>,OU=_ServiceAccounts-TM,<domaine> et un nom de groupe GG_T{N}_gMSA_<nom>.
      - Nom du gMSA (15 caractères maximum, sans '$'), nom DNS, description, intervalle de changement du mot de passe, SPN.
      - Sélection des OU par arborescence AD (OU du gMSA, OU du groupe).
      - Groupe autorisé à récupérer le mot de passe (PrincipalsAllowedToRetrieveManagedPassword) : nouveau groupe ou groupe existant.
      - Serveurs membres du groupe : recherche AD avec base de recherche au choix.
    Onglet 2 « Droits »
      - Types de chiffrement Kerberos (AES256 / AES128 par défaut, RC4 déconseillé).
      - Appartenance du gMSA à des groupes.
      - Délégations sur des OU au profit du gMSA (profils de droits prédéfinis, sans contrôle total).
      - Clé racine KDS : contrôle, et création optionnelle si absente (mode production ou laboratoire).

    Analyse : contrôle des prérequis (RSAT, clé KDS, OU, doublons de nom et de SPN, gMSA existant), respect du Tier model
    (aucune référence à un autre Tier dans les OU, groupes et serveurs ; contrôleurs de domaine réservés au Tier 0),
    puis affichage du plan d'exécution.

    Dry Run : la case « Mode simulation » est cochée au démarrage. Rien n'est écrit dans l'annuaire, le journal décrit chaque action.
    Rollback : chaque exécution réelle écrit un fichier d'état JSON (GmsaGui_State_<gMSA>_<date>.json). Le bouton « Rollback... »
    rejoue ce fichier en ordre inverse (ACE retirées, appartenances retirées, gMSA supprimé ou restauré, groupe supprimé).
    Le rollback respecte aussi la case « Mode simulation ». La clé racine KDS n'est jamais supprimée.
    Logs : tous les messages de la fenêtre sont écrits dans GmsaGui_<date>.log. Avant toute modification d'ACL, le descripteur
    de sécurité de l'OU est sauvegardé en SDDL (GmsaGui_AclBackup_*.sddl).

    Gmsa existant : si le compte existe déjà, il est mis à jour (groupe ajouté aux principaux autorisés, chiffrement, SPN ajoutés) ;
    son OU, sa description et son intervalle de mot de passe ne sont pas modifiés. Le rollback restaure les valeurs précédentes.

.PARAMETER LogFolder
    Dossier des journaux, fichiers d'état (rollback) et sauvegardes SDDL. Défaut : Documents\GmsaGui.

.PARAMETER Server
    Contrôleur de domaine à utiliser. Vide = PDC émulateur du domaine courant (évite les problèmes de réplication entre étapes).

.PARAMETER Tier
    Tier proposé au démarrage (0, 1 ou 2). Défaut : 1.

.PARAMETER ServiceAccountsOU
    Nom de l'OU racine des comptes de service. Défaut : _ServiceAccounts-TM.

.PARAMETER GmsaOuPattern
    Nom de l'OU des gMSA d'un Tier, {N} = numéro de Tier. Défaut : Tier{N}-gMSA.

.PARAMETER GroupNamePattern
    Nom proposé pour le groupe, {N} = Tier, {Name} = nom du gMSA. Défaut : GG_T{N}_gMSA_{Name}.

.PARAMETER TierPrefixes
    Préfixes reconnus comme référence de Tier dans les noms et DN (contrôle du Tier model). Défaut : T, Tier.

.EXAMPLE
    powershell.exe -STA -ExecutionPolicy Bypass -File .\New-GmsaGui.ps1
    Lance l'assistant (mode simulation activé).

.EXAMPLE
    .\New-GmsaGui.ps1 -Tier 0 -Server DC01.tiering.ad -LogFolder D:\Logs\gMSA
    Démarre sur le Tier 0, cible un contrôleur précis et redirige journaux et fichiers d'état.

.EXAMPLE
    # Rollback : bouton « Rollback... » > choisir GmsaGui_State_<gMSA>_<date>.json
    # (décocher « Mode simulation » pour l'appliquer réellement)

.NOTES
    Prérequis : Windows PowerShell 5.1, module RSAT ActiveDirectory (et KdsCmdlets pour la clé KDS), session -STA.
    Droits : création d'objets dans les OU choisies, modification des ACL pour les délégations, Domain Admins / Enterprise Admins
    pour créer la clé racine KDS.
    Après l'exécution, sur chaque serveur membre : redémarrer (ou « klist -li 0x3e7 purge ») pour que le nouveau groupe soit
    pris en compte, puis Test-ADServiceAccount <nom>.
    État des tests : syntaxe vérifiée ; non testé contre un Active Directory réel (voir le message de livraison).
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$LogFolder = (Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'GmsaGui'),
    [string]$Server = '',
    [ValidateRange(0, 2)][int]$Tier = 1,
    [string]$ServiceAccountsOU = '_ServiceAccounts-TM',
    [string]$GmsaOuPattern = 'Tier{N}-gMSA',
    [string]$GroupNamePattern = 'GG_T{N}_gMSA_{Name}',
    [string[]]$TierPrefixes = @('T', 'Tier')
)

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.DirectoryServices
[System.Windows.Forms.Application]::EnableVisualStyles()

# ----------------------------------------------------------------------------
# État global
# ----------------------------------------------------------------------------
$script:ScriptVersion     = '1.0.0'
$script:Server            = $Server
$script:DomainDN          = ''
$script:DomainFqdn        = ''
$script:AdReady           = $false
$script:AdAvailable       = [bool](Get-Module -ListAvailable -Name ActiveDirectory)
$script:AutoValues        = @{}
$script:Operations        = New-Object System.Collections.Generic.List[object]
$script:StatePath         = $null
$script:StateMeta         = $null
$script:RunStamp          = Get-Date -Format 'yyyyMMdd-HHmmss'
$script:LogFile           = $null
$script:txtLog            = $null
$script:VisibleContainers = @('Managed Service Accounts', 'Users', 'Computers')
$script:AdDrive           = 'GmsaAD'

# GUID de schéma et droits étendus (valeurs fixes, identiques dans toutes les forêts)
$script:Guid = [ordered]@{
    Empty              = [Guid]::Empty
    User               = [Guid]'bf967aba-0de6-11d0-a285-00aa003049e2'
    Computer           = [Guid]'bf967a86-0de6-11d0-a285-00aa003049e2'
    Group              = [Guid]'bf967a9c-0de6-11d0-a285-00aa003049e2'
    Member             = [Guid]'bf9679c0-0de6-11d0-a285-00aa003049e2'
    PwdLastSet         = [Guid]'bf967a0a-0de6-11d0-a285-00aa003049e2'
    LockoutTime        = [Guid]'28630ebf-41d5-11d1-a9c1-0000f80367c1'
    ResetPassword      = [Guid]'00299570-246d-11d0-a768-00aa006e0529'
}

function New-RuleSpec {
    param([string]$Rights, [Guid]$ObjectType = [Guid]::Empty, [string]$Inheritance, [Guid]$InheritedObjectType = [Guid]::Empty)
    [pscustomobject]@{
        Rights              = $Rights
        ObjectType          = $ObjectType.ToString()
        Inheritance         = $Inheritance
        InheritedObjectType = $InheritedObjectType.ToString()
    }
}

# Profils de délégation proposés (moindre privilège : aucun contrôle total, aucun WriteDacl / WriteOwner)
$G = $script:Guid
$script:DelegationProfiles = [ordered]@{
    'Read' = @{
        Label = 'Lecture : OU et tous ses objets'
        Help  = "Lecture de toutes les propriétés de l'OU et de ses descendants (GenericRead)."
        Rules = @( (New-RuleSpec -Rights 'GenericRead' -Inheritance 'All') )
    }
    'UsersManage' = @{
        Label = 'Utilisateurs : créer, supprimer, modifier'
        Help  = 'Création et suppression des comptes utilisateurs, lecture et écriture de toutes leurs propriétés.'
        Rules = @(
            (New-RuleSpec -Rights 'CreateChild, DeleteChild' -ObjectType $G.User -Inheritance 'All'),
            (New-RuleSpec -Rights 'ReadProperty, WriteProperty' -Inheritance 'Descendents' -InheritedObjectType $G.User)
        )
    }
    'UsersPassword' = @{
        Label = 'Utilisateurs : réinitialiser le mot de passe, déverrouiller'
        Help  = 'Droit étendu Reset Password, écriture de pwdLastSet (forcer le changement) et lockoutTime (déverrouillage).'
        Rules = @(
            (New-RuleSpec -Rights 'ExtendedRight' -ObjectType $G.ResetPassword -Inheritance 'Descendents' -InheritedObjectType $G.User),
            (New-RuleSpec -Rights 'ReadProperty, WriteProperty' -ObjectType $G.PwdLastSet -Inheritance 'Descendents' -InheritedObjectType $G.User),
            (New-RuleSpec -Rights 'ReadProperty, WriteProperty' -ObjectType $G.LockoutTime -Inheritance 'Descendents' -InheritedObjectType $G.User)
        )
    }
    'GroupsMembers' = @{
        Label = 'Groupes : gérer les membres'
        Help  = "Lecture et écriture de l'attribut member des groupes de l'OU."
        Rules = @( (New-RuleSpec -Rights 'ReadProperty, WriteProperty' -ObjectType $G.Member -Inheritance 'Descendents' -InheritedObjectType $G.Group) )
    }
    'ComputersManage' = @{
        Label = 'Ordinateurs : créer, supprimer, modifier'
        Help  = 'Création et suppression des comptes ordinateurs, écriture des propriétés, Reset Password et écritures validées (DNS, SPN).'
        Rules = @(
            (New-RuleSpec -Rights 'CreateChild, DeleteChild' -ObjectType $G.Computer -Inheritance 'All'),
            (New-RuleSpec -Rights 'ReadProperty, WriteProperty' -Inheritance 'Descendents' -InheritedObjectType $G.Computer),
            (New-RuleSpec -Rights 'ExtendedRight' -ObjectType $G.ResetPassword -Inheritance 'Descendents' -InheritedObjectType $G.Computer),
            (New-RuleSpec -Rights 'Self' -Inheritance 'Descendents' -InheritedObjectType $G.Computer)
        )
    }
}
Remove-Variable -Name G

# ----------------------------------------------------------------------------
# Journalisation et état (rollback)
# ----------------------------------------------------------------------------
function Initialize-LogFile {
    try {
        if (-not (Test-Path -LiteralPath $LogFolder)) { New-Item -ItemType Directory -Path $LogFolder -Force | Out-Null }
        $script:LogFile = Join-Path $LogFolder ("GmsaGui_{0}.log" -f $script:RunStamp)
    }
    catch { $script:LogFile = $null }
}

function Write-Log {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Message,
        [ValidateSet('INFO', 'OK', 'WARN', 'ERROR', 'PLAN', 'SIMU')][string]$Level = 'INFO'
    )
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    if ($script:txtLog) {
        $script:txtLog.AppendText($line + [Environment]::NewLine)
        [System.Windows.Forms.Application]::DoEvents()
    }
    else { Write-Verbose $line }
    if ($script:LogFile) {
        try { Add-Content -LiteralPath $script:LogFile -Value $line -Encoding UTF8 } catch { Write-Verbose $_.Exception.Message }
    }
}

function Start-RunState {
    param($Plan)
    $script:Operations = New-Object System.Collections.Generic.List[object]
    $safe = ($Plan.GmsaName -replace '[^A-Za-z0-9-]', '_')
    $script:StatePath = Join-Path $LogFolder ("GmsaGui_State_{0}_{1}.json" -f $safe, (Get-Date -Format 'yyyyMMdd-HHmmss'))
    $script:StateMeta = [ordered]@{
        Version  = $script:ScriptVersion
        Date     = (Get-Date).ToString('o')
        Operator = "$env:USERDOMAIN\$env:USERNAME"
        Computer = $env:COMPUTERNAME
        Server   = $script:Server
        Domain   = $script:DomainDN
        Gmsa     = $Plan.Sam
        Tier     = $Plan.Tier
    }
    Save-RunState -Status 'InProgress'
    Write-Log "Fichier d'état (rollback) : $($script:StatePath)"
}

function Save-RunState {
    param([string]$Status = 'InProgress')
    if (-not $script:StatePath) { return }
    $state = [ordered]@{}
    foreach ($k in $script:StateMeta.Keys) { $state[$k] = $script:StateMeta[$k] }
    $state['Status'] = $Status
    $state['Operations'] = @($script:Operations)
    $state | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $script:StatePath -Encoding UTF8
}

function Add-Operation {
    param([string]$Type, [hashtable]$Data = @{})
    $op = [ordered]@{ Type = $Type; Time = (Get-Date).ToString('o') }
    foreach ($k in $Data.Keys) { $op[$k] = $Data[$k] }
    $script:Operations.Add([pscustomobject]$op)
    Save-RunState -Status 'InProgress'
}

# ----------------------------------------------------------------------------
# Utilitaires
# ----------------------------------------------------------------------------
function Show-Msg {
    param([string]$Text, [string]$Icon = 'Information')
    [void][System.Windows.Forms.MessageBox]::Show($Text, 'gMSA', 'OK', $Icon)
}

function Confirm-Action {
    param([string]$Text)
    ([System.Windows.Forms.MessageBox]::Show($Text, 'Confirmation', 'YesNo', 'Warning')) -eq 'Yes'
}

function Test-AdReady {
    if ($script:AdReady) { return $true }
    Show-Msg "Active Directory n'est pas disponible (module RSAT ActiveDirectory absent ou domaine injoignable). Voir le journal." 'Warning'
    return $false
}

function ConvertTo-DnValue {
    param([string]$Value)
    $v = $Value -replace '([,\\#+<>;"=])', '\$1'
    if ($v.StartsWith(' ')) { $v = '\' + $v }
    if ($v.EndsWith(' ')) { $v = $v.Substring(0, $v.Length - 1) + '\ ' }
    $v
}

function ConvertTo-LdapValue {
    # Échappe une valeur pour un filtre LDAP ; -AllowWildcard conserve '*'
    param([string]$Value, [switch]$AllowWildcard)
    $v = $Value -replace '\\', '\5c' -replace '\(', '\28' -replace '\)', '\29' -replace "`0", '\00'
    if (-not $AllowWildcard) { $v = $v -replace '\*', '\2a' }
    $v
}

function Get-NonDcPart {
    param([string]$Text)
    (($Text -split '(?<!\\),') | Where-Object { $_.Trim() -notmatch '^DC=' }) -join ','
}

function Get-TierRefs {
    # Renvoie les numéros de Tier cités dans un nom ou un DN (hors composantes DC=)
    param([string]$Text)
    $part = Get-NonDcPart -Text $Text
    $alt = (($TierPrefixes | ForEach-Object { [regex]::Escape($_) + '[\s_-]?' }) -join '|')
    $found = @()
    for ($n = 0; $n -le 9; $n++) {
        if ($part -match ('(?<![A-Za-z0-9])(?:' + $alt + ')' + $n + '(?![0-9])')) { $found += $n }
    }
    $found
}

function Add-TierFinding {
    param($Result, $Plan, [string]$Label, [string]$Text, [switch]$Required)
    if (-not $Text) { return }
    $refs = @(Get-TierRefs -Text $Text)
    $others = @($refs | Where-Object { $_ -ne $Plan.Tier })
    if ($others.Count -gt 0) {
        $msg = "$Label : référence au Tier $($others -join ', ') dans '$(Get-NonDcPart $Text)' (Tier attendu : $($Plan.Tier))."
        if ($Plan.IgnoreTier) { $Result.Warnings.Add("$msg Contrôle ignoré à la demande.") } else { $Result.Errors.Add($msg) }
    }
    elseif ($Required -and ($refs -notcontains $Plan.Tier)) {
        $Result.Warnings.Add("$Label : aucune référence au Tier $($Plan.Tier) dans '$(Get-NonDcPart $Text)'.")
    }
}

function Get-GuidName {
    param([string]$Guid)
    foreach ($k in $script:Guid.Keys) { if ($script:Guid[$k].ToString() -eq $Guid) { return $k } }
    $Guid
}

function Format-RuleSpec {
    param($Rule)
    $o = Get-GuidName $Rule.ObjectType
    $i = Get-GuidName $Rule.InheritedObjectType
    "droits=$($Rule.Rights) ; objet=$o ; héritage=$($Rule.Inheritance) ; sur la classe=$i"
}

function ConvertTo-AdRule {
    param([string]$Sid, $Rule)
    New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList @(
        [System.Security.Principal.SecurityIdentifier]$Sid,
        [System.DirectoryServices.ActiveDirectoryRights]$Rule.Rights,
        [System.Security.AccessControl.AccessControlType]::Allow,
        [Guid]$Rule.ObjectType,
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]$Rule.Inheritance,
        [Guid]$Rule.InheritedObjectType)
}

function Test-AcePresent {
    param($Acl, [string]$Sid, $Rule)
    $want = ConvertTo-AdRule -Sid $Sid -Rule $Rule
    foreach ($a in $Acl.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier])) {
        if ($a.IdentityReference.Value -eq $Sid -and
            $a.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
            $a.ActiveDirectoryRights -eq $want.ActiveDirectoryRights -and
            $a.ObjectType -eq $want.ObjectType -and
            $a.InheritanceType -eq $want.InheritanceType -and
            $a.InheritedObjectType -eq $want.InheritedObjectType) { return $true }
    }
    return $false
}

function Get-AdPath {
    param([string]$Dn)
    "$($script:AdDrive):\$Dn"
}

function Test-AdObjectExists {
    param([string]$Dn)
    if (-not $Dn) { return $false }
    try { $null = Get-ADObject -Identity $Dn -Server $script:Server -ErrorAction Stop; return $true }
    catch { return $false }
}

function Get-KdsStatus {
    try { $keys = @(Get-KdsRootKey -ErrorAction Stop) }
    catch { return 'Unknown' }
    if ($keys.Count -eq 0) { return 'Missing' }
    if (@($keys | Where-Object { $_.EffectiveTime -le (Get-Date) }).Count -gt 0) { return 'Effective' }
    return 'Pending'
}

# ----------------------------------------------------------------------------
# Connexion à Active Directory
# ----------------------------------------------------------------------------
function Initialize-Ad {
    if (-not $script:AdAvailable) {
        Write-Log "Module ActiveDirectory (RSAT) absent : installer RSAT AD DS. L'interface reste utilisable pour préparer la saisie." 'ERROR'
        return
    }
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $p = @{ ErrorAction = 'Stop' }
        if ($script:Server) { $p.Server = $script:Server }
        $d = Get-ADDomain @p
        $script:DomainDN = $d.DistinguishedName
        $script:DomainFqdn = $d.DNSRoot
        if (-not $script:Server) { $script:Server = $d.PDCEmulator }
        if (-not (Get-PSDrive -Name $script:AdDrive -ErrorAction SilentlyContinue)) {
            New-PSDrive -Name $script:AdDrive -PSProvider ActiveDirectory -Root '//RootDSE/' -Server $script:Server -Scope Global | Out-Null
        }
        $script:AdReady = $true
        $script:lblDomain.Text = "Domaine : $($script:DomainFqdn)   |   Contrôleur : $($script:Server)"
        Write-Log "Connecté au domaine $($script:DomainFqdn) ($($script:DomainDN)) via $($script:Server)." 'OK'
        switch (Get-KdsStatus) {
            'Effective' { Write-Log 'Clé racine KDS effective présente.' 'OK' }
            'Pending'   { Write-Log "Une clé racine KDS existe mais n'est pas encore effective (réplication, 10 h)." 'WARN' }
            'Missing'   { Write-Log "Aucune clé racine KDS : cocher « Créer la clé racine KDS » (onglet Droits) ou la créer avant l'exécution." 'WARN' }
            default     { Write-Log 'Clé racine KDS non vérifiable avec ce compte.' 'WARN' }
        }
    }
    catch {
        Write-Log "Connexion AD impossible : $($_.Exception.Message)" 'ERROR'
    }
    Update-AutoFields
}

# ----------------------------------------------------------------------------
# Constructeurs de contrôles
# ----------------------------------------------------------------------------
function New-Ctl {
    param([string]$Type, [int]$X, [int]$Y, [int]$W = 0, [int]$H = 0, [string]$Text = '', $Parent = $null)
    $c = New-Object ("System.Windows.Forms.$Type")
    $c.Location = New-Object System.Drawing.Point($X, $Y)
    if ($W -gt 0 -and $H -gt 0) { $c.Size = New-Object System.Drawing.Size($W, $H) }
    elseif ($W -gt 0) { $c.Width = $W }
    elseif ($Type -in @('Label', 'CheckBox', 'RadioButton')) { $c.AutoSize = $true }
    if ($Text) { $c.Text = $Text }
    if ($Parent) { $Parent.Controls.Add($c) }
    return $c
}

function New-ListViewCtl {
    param([int]$X, [int]$Y, [int]$W, [int]$H, [string[]]$Columns, [int[]]$Widths, $Parent, [switch]$CheckBoxes)
    $lv = New-Ctl -Type 'ListView' -X $X -Y $Y -W $W -H $H -Parent $Parent
    $lv.View = 'Details'
    $lv.FullRowSelect = $true
    $lv.GridLines = $true
    $lv.HideSelection = $false
    $lv.CheckBoxes = [bool]$CheckBoxes
    for ($i = 0; $i -lt $Columns.Count; $i++) { [void]$lv.Columns.Add($Columns[$i], $Widths[$i]) }
    return $lv
}

function Add-ListItem {
    param($ListView, [string[]]$Texts, $Tag, [string]$Key)
    foreach ($it in $ListView.Items) { if ($it.Name -eq $Key) { return $false } }
    $item = New-Object System.Windows.Forms.ListViewItem -ArgumentList @(, [string[]]$Texts)
    $item.Name = $Key
    $item.Tag = $Tag
    $item.ToolTipText = $Key
    [void]$ListView.Items.Add($item)
    return $true
}

function Remove-SelectedItems {
    param($ListView)
    foreach ($it in @($ListView.SelectedItems)) { $ListView.Items.Remove($it) }
}

function Get-ListTags {
    param($ListView)
    foreach ($it in $ListView.Items) { $it.Tag }
}

function Set-AutoText {
    # Remplit un champ tant que l'utilisateur ne l'a pas modifié à la main
    param($TextBox, [string]$Key, [string]$Value)
    $prev = $script:AutoValues[$Key]
    if ([string]::IsNullOrEmpty($TextBox.Text) -or $TextBox.Text -eq $prev) { $TextBox.Text = $Value }
    $script:AutoValues[$Key] = $Value
}

# ----------------------------------------------------------------------------
# Boîtes de dialogue AD
# ----------------------------------------------------------------------------
function New-AdTreeNode {
    param([string]$Name, [string]$Dn)
    $n = New-Object System.Windows.Forms.TreeNode -ArgumentList $Name
    $n.Tag = $Dn
    $n.ToolTipText = $Dn
    [void]$n.Nodes.Add((New-Object System.Windows.Forms.TreeNode -ArgumentList '...'))
    return $n
}

function Expand-AdTreeNode {
    param($Node)
    if ($Node.Nodes.Count -ne 1 -or $null -ne $Node.Nodes[0].Tag) { return }
    $Node.Nodes.Clear()
    $kids = @(Get-ADObject -SearchBase ([string]$Node.Tag) -SearchScope OneLevel -Server $script:Server `
            -LDAPFilter '(|(objectClass=organizationalUnit)(objectClass=container))' |
        Where-Object { $_.ObjectClass -eq 'organizationalUnit' -or $script:VisibleContainers -contains $_.Name } |
        Sort-Object Name)
    foreach ($k in $kids) { [void]$Node.Nodes.Add((New-AdTreeNode -Name $k.Name -Dn $k.DistinguishedName)) }
}

function Select-AdContainer {
    param([string]$Title = "Sélectionner une unité d'organisation")
    if (-not (Test-AdReady)) { return $null }
    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text = $Title
    $dlg.ClientSize = New-Object System.Drawing.Size(560, 540)
    $dlg.StartPosition = 'CenterParent'
    $dlg.FormBorderStyle = 'FixedDialog'
    $dlg.MinimizeBox = $false
    $dlg.MaximizeBox = $false
    $dlg.Font = $script:form.Font

    $tv = New-Ctl -Type 'TreeView' -X 10 -Y 10 -W 540 -H 440 -Parent $dlg
    $tv.HideSelection = $false
    $tv.ShowNodeToolTips = $true
    $txtSel = New-Ctl -Type 'TextBox' -X 10 -Y 458 -W 540 -Parent $dlg
    $txtSel.ReadOnly = $true
    $btnOk = New-Ctl -Type 'Button' -X 360 -Y 495 -W 90 -H 30 -Text 'OK' -Parent $dlg
    $btnOk.DialogResult = 'OK'
    $btnCancel = New-Ctl -Type 'Button' -X 460 -Y 495 -W 90 -H 30 -Text 'Annuler' -Parent $dlg
    $btnCancel.DialogResult = 'Cancel'
    $dlg.AcceptButton = $btnOk
    $dlg.CancelButton = $btnCancel

    $root = New-AdTreeNode -Name $script:DomainFqdn -Dn $script:DomainDN
    [void]$tv.Nodes.Add($root)
    $tv.Add_BeforeExpand({
            param($s, $e)
            try { Expand-AdTreeNode -Node $e.Node }
            catch { Show-Msg "Lecture AD impossible : $($_.Exception.Message)" 'Error' }
        })
    $tv.Add_AfterSelect({ param($s, $e) $txtSel.Text = [string]$e.Node.Tag })
    $dlg.Add_Shown({ $root.Expand(); $tv.SelectedNode = $root })

    $result = $dlg.ShowDialog($script:form)
    $dn = $txtSel.Text
    $dlg.Dispose()
    if ($result -ne [System.Windows.Forms.DialogResult]::OK -or -not $dn) { return $null }
    return $dn
}

function Find-AdObjects {
    param([ValidateSet('computer', 'group')][string]$Class, [string]$Filter, [string]$Base)
    $f = ConvertTo-LdapValue -Value $Filter.Trim() -AllowWildcard
    if (-not $f.EndsWith('*')) { $f += '*' }
    $p = @{
        LDAPFilter    = "(&(objectCategory=$Class)(name=$f))"
        Server        = $script:Server
        ResultSetSize = 500
        Properties    = @('operatingSystem', 'description', 'userAccountControl', 'groupType', 'objectSid')
        ErrorAction   = 'Stop'
    }
    if ($Base) { $p.SearchBase = $Base }
    foreach ($o in @(Get-ADObject @p | Sort-Object Name)) {
        if ($Class -eq 'computer') {
            $isDc = (([int]$o.userAccountControl) -band 8192) -ne 0
            $info = [string]$o.operatingSystem
            if ($isDc) { $info = "$info (contrôleur de domaine)" }
        }
        else {
            $isDc = $false
            $gt = [int]$o.groupType
            $scope = if ($gt -band 2) { 'Global' } elseif ($gt -band 4) { 'Domaine local' } elseif ($gt -band 8) { 'Universel' } else { '?' }
            $cat = if ($gt -band 0x80000000) { 'Sécurité' } else { 'Distribution' }
            $info = "$cat / $scope"
        }
        [pscustomobject]@{
            Name = [string]$o.Name
            Dn   = [string]$o.DistinguishedName
            Info = $info
            IsDC = $isDc
            Sid  = [string]$o.objectSid.Value
        }
    }
}

function Select-AdObjects {
    param([ValidateSet('computer', 'group')][string]$Class, [string]$Title, [switch]$Single)
    if (-not (Test-AdReady)) { return @() }
    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text = $Title
    $dlg.ClientSize = New-Object System.Drawing.Size(700, 480)
    $dlg.StartPosition = 'CenterParent'
    $dlg.FormBorderStyle = 'FixedDialog'
    $dlg.MinimizeBox = $false
    $dlg.MaximizeBox = $false
    $dlg.Font = $script:form.Font

    [void](New-Ctl -Type 'Label' -X 10 -Y 14 -Text 'Nom (début, * accepté) :' -Parent $dlg)
    $txtF = New-Ctl -Type 'TextBox' -X 170 -Y 10 -W 250 -Parent $dlg
    $btnS = New-Ctl -Type 'Button' -X 430 -Y 9 -W 110 -H 25 -Text 'Rechercher' -Parent $dlg
    [void](New-Ctl -Type 'Label' -X 10 -Y 44 -Text 'Rechercher sous :' -Parent $dlg)
    $txtB = New-Ctl -Type 'TextBox' -X 170 -Y 40 -W 410 -Parent $dlg
    $txtB.Text = $script:DomainDN
    $btnB = New-Ctl -Type 'Button' -X 590 -Y 39 -W 100 -H 25 -Text 'Parcourir...' -Parent $dlg
    $lv = New-ListViewCtl -X 10 -Y 75 -W 680 -H 345 -Columns @('Nom', 'Informations', 'DN') -Widths @(140, 200, 320) -Parent $dlg -CheckBoxes:(-not $Single)
    $lv.MultiSelect = $false
    $lblN = New-Ctl -Type 'Label' -X 10 -Y 435 -Text '' -Parent $dlg
    $btnOk = New-Ctl -Type 'Button' -X 500 -Y 435 -W 90 -H 30 -Text 'OK' -Parent $dlg
    $btnOk.DialogResult = 'OK'
    $btnCancel = New-Ctl -Type 'Button' -X 600 -Y 435 -W 90 -H 30 -Text 'Annuler' -Parent $dlg
    $btnCancel.DialogResult = 'Cancel'
    $dlg.AcceptButton = $btnS
    $dlg.CancelButton = $btnCancel
    if ($Single) { $lblHint = 'Sélectionner une ligne puis OK.' } else { $lblHint = 'Cocher les lignes à ajouter puis OK.' }
    $lblN.Text = $lblHint

    $btnB.Add_Click({
            $d = Select-AdContainer -Title 'Base de recherche'
            if ($d) { $txtB.Text = $d }
        })
    $btnS.Add_Click({
            try {
                $dlg.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
                $lv.Items.Clear()
                $found = @(Find-AdObjects -Class $Class -Filter $txtF.Text -Base $txtB.Text)
                foreach ($o in $found) { [void](Add-ListItem -ListView $lv -Texts @($o.Name, $o.Info, $o.Dn) -Tag $o -Key $o.Dn) }
                $lblN.Text = "$($found.Count) résultat(s) (500 maximum). $lblHint"
            }
            catch { Show-Msg "Recherche impossible : $($_.Exception.Message)" 'Error' }
            finally { $dlg.Cursor = [System.Windows.Forms.Cursors]::Default }
        })
    $lv.Add_DoubleClick({ if ($Single -and $lv.SelectedItems.Count -eq 1) { $dlg.DialogResult = 'OK' } })

    $result = $dlg.ShowDialog($script:form)
    $sel = @()
    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        if ($Single) { foreach ($it in $lv.SelectedItems) { $sel += $it.Tag } }
        else { foreach ($it in $lv.CheckedItems) { $sel += $it.Tag } }
    }
    $dlg.Dispose()
    $sel
}

# ----------------------------------------------------------------------------
# Plan, analyse, exécution, rollback
# ----------------------------------------------------------------------------
function Update-AutoFields {
    $t = $script:cmbTier.SelectedIndex
    if ($t -lt 0) { return }
    $name = $script:txtName.Text.Trim()
    if ($script:DomainDN) {
        $ou = 'OU={0},OU={1},{2}' -f ($GmsaOuPattern -replace '\{N\}', $t), $ServiceAccountsOU, $script:DomainDN
        Set-AutoText -TextBox $script:txtGmsaOu -Key 'GmsaOu' -Value $ou
        Set-AutoText -TextBox $script:txtGroupOu -Key 'GroupOu' -Value $ou
    }
    if ($name -and $script:DomainFqdn) {
        Set-AutoText -TextBox $script:txtDns -Key 'Dns' -Value ("$name.$($script:DomainFqdn)".ToLower())
    }
    if ($name -and $script:rbGroupNew.Checked) {
        Set-AutoText -TextBox $script:txtGroupName -Key 'Group' -Value (($GroupNamePattern -replace '\{N\}', $t) -replace '\{Name\}', $name)
    }
    if (-not $script:txtDesc.Text -or $script:txtDesc.Text -eq $script:AutoValues['Desc']) {
        Set-AutoText -TextBox $script:txtDesc -Key 'Desc' -Value "gMSA Tier $t"
    }
}

function Get-UiPlan {
    $name = $script:txtName.Text.Trim()
    $sam = ''
    if ($name) { $sam = $name + '$' }
    $enc = @()
    if ($script:chkAes256.Checked) { $enc += 'AES256' }
    if ($script:chkAes128.Checked) { $enc += 'AES128' }
    if ($script:chkRc4.Checked) { $enc += 'RC4' }
    $spns = @($script:txtSpn.Lines | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Select-Object -Unique)
    $groupMode = 'Existing'
    if ($script:rbGroupNew.Checked) { $groupMode = 'New' }
    $kdsMode = 'Production'
    if ($script:cmbKds.SelectedIndex -eq 1) { $kdsMode = 'Lab' }
    [pscustomobject]@{
        Tier             = $script:cmbTier.SelectedIndex
        GmsaName         = $name
        Sam              = $sam
        DnsHostName      = $script:txtDns.Text.Trim()
        Description      = $script:txtDesc.Text.Trim()
        GmsaOu           = $script:txtGmsaOu.Text.Trim()
        PwdInterval      = [int]$script:numInterval.Value
        Spns             = $spns
        GroupMode        = $groupMode
        GroupName        = $script:txtGroupName.Text.Trim()
        GroupDn          = [string]$script:txtGroupName.Tag
        GroupScope       = [string]$script:cmbScope.SelectedItem
        GroupOu          = $script:txtGroupOu.Text.Trim()
        GroupDescription = $script:txtGroupDesc.Text.Trim()
        Servers          = @(Get-ListTags $script:lvServers)
        EncTypes         = $enc
        MemberOf         = @(Get-ListTags $script:lvMemberOf)
        Delegations      = @(Get-ListTags $script:lvDeleg)
        CreateKds        = $script:chkKds.Checked
        KdsMode          = $kdsMode
        IgnoreTier       = $script:chkIgnoreTier.Checked
        DryRun           = $script:chkDryRun.Checked
    }
}

function Test-Plan {
    param($Plan)
    $res = [pscustomobject]@{
        Errors        = New-Object System.Collections.Generic.List[string]
        Warnings      = New-Object System.Collections.Generic.List[string]
        KdsStatus     = 'Unknown'
        ExistingGmsa  = $null
        GmsaGroups    = @()
        GroupMembers  = @()
    }
    Write-Log '---------- Analyse ----------'
    if (-not $script:AdReady) {
        $res.Errors.Add('Active Directory indisponible (module RSAT absent ou domaine injoignable).')
        Write-AnalysisResult -Result $res
        return $res
    }
    $s = $script:Server

    # --- gMSA : nom, DNS, OU, chiffrement
    if (-not $Plan.GmsaName) { $res.Errors.Add('Nom du gMSA obligatoire.') }
    elseif ($Plan.GmsaName -notmatch '^[A-Za-z0-9][A-Za-z0-9-]{0,14}$') {
        $res.Errors.Add("Nom du gMSA '$($Plan.GmsaName)' invalide : 1 à 15 caractères, lettres, chiffres et tiret, sans '`$'.")
    }
    elseif ($Plan.GmsaName -match '^[0-9]+$') { $res.Errors.Add('Le nom du gMSA ne peut pas être uniquement numérique.') }
    if (-not $Plan.DnsHostName) { $res.Errors.Add('Nom DNS (DNSHostName) obligatoire.') }
    elseif ($Plan.DnsHostName -notmatch '^[A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9]$') { $res.Errors.Add("Nom DNS '$($Plan.DnsHostName)' invalide.") }
    if (@($Plan.EncTypes).Count -eq 0) { $res.Errors.Add('Cocher au moins un type de chiffrement Kerberos.') }
    elseif ($Plan.EncTypes -contains 'RC4') { $res.Warnings.Add('RC4 est autorisé : déconseillé (ANSSI, Microsoft). À réserver aux applications qui ne gèrent pas AES.') }
    foreach ($spn in $Plan.Spns) {
        if ($spn -notmatch '^[^/\s]+/[^\s]+$') { $res.Errors.Add("SPN '$spn' invalide (format attendu : classe/hôte[:port])."); continue }
        $hit = @(Get-ADObject -LDAPFilter "(servicePrincipalName=$(ConvertTo-LdapValue $spn))" -Server $s -Properties sAMAccountName)
        foreach ($h in $hit) {
            if ($h.sAMAccountName -ne $Plan.Sam) { $res.Errors.Add("SPN '$spn' déjà porté par $($h.DistinguishedName) (doublon Kerberos).") }
        }
    }

    # --- gMSA existant ?
    if ($Plan.Sam) {
        $same = @(Get-ADObject -LDAPFilter "(sAMAccountName=$(ConvertTo-LdapValue $Plan.Sam))" -Server $s)
        $other = @($same | Where-Object { $_.ObjectClass -ne 'msDS-GroupManagedServiceAccount' })
        if ($other.Count -gt 0) { $res.Errors.Add("Le nom '$($Plan.Sam)' est déjà utilisé par $($other[0].DistinguishedName) ($($other[0].ObjectClass)).") }
        elseif ($same.Count -gt 0) {
            $res.ExistingGmsa = Get-ADServiceAccount -Identity $same[0].DistinguishedName -Server $s `
                -Properties PrincipalsAllowedToRetrieveManagedPassword, 'msDS-SupportedEncryptionTypes', servicePrincipalName, memberOf
            $res.GmsaGroups = @($res.ExistingGmsa.memberOf)
            $res.Warnings.Add("Le gMSA existe déjà ($($res.ExistingGmsa.DistinguishedName)) : il sera mis à jour (principaux autorisés, chiffrement, SPN). OU, description et intervalle inchangés.")
            Add-TierFinding -Result $res -Plan $Plan -Label 'gMSA existant' -Text $res.ExistingGmsa.DistinguishedName -Required
        }
    }
    if (-not $res.ExistingGmsa) {
        if (-not $Plan.GmsaOu) { $res.Errors.Add('OU du gMSA obligatoire.') }
        elseif (-not (Test-AdObjectExists $Plan.GmsaOu)) { $res.Errors.Add("OU du gMSA introuvable : $($Plan.GmsaOu)") }
        Add-TierFinding -Result $res -Plan $Plan -Label 'OU du gMSA' -Text $Plan.GmsaOu -Required
    }

    # --- Clé KDS
    $res.KdsStatus = Get-KdsStatus
    switch ($res.KdsStatus) {
        'Effective' { }
        'Pending'   { $res.Errors.Add("La clé racine KDS n'est pas encore effective : attendre la fin du délai (10 h) avant de créer le gMSA.") }
        'Missing' {
            if (-not $Plan.CreateKds) { $res.Errors.Add("Aucune clé racine KDS : cocher « Créer la clé racine KDS si absente » (onglet Droits) ou exécuter Add-KdsRootKey.") }
            elseif ($Plan.KdsMode -eq 'Production') { $res.Warnings.Add("La clé KDS sera créée (mode production) : l'exécution réelle s'arrêtera ensuite, relancer dans 10 h pour créer le gMSA.") }
            else { $res.Warnings.Add('La clé KDS sera créée en mode laboratoire (effective immédiatement) : à ne pas utiliser en production.') }
        }
        default { $res.Warnings.Add('Clé racine KDS non vérifiable avec ce compte : la création du gMSA échouera si elle est absente.') }
    }

    # --- Groupe
    if ($Plan.GroupMode -eq 'New') {
        if (-not $Plan.GroupName) { $res.Errors.Add('Nom du groupe obligatoire.') }
        elseif ($Plan.GroupName -notmatch '^[^"/\\\[\]:;|=,+*?<>@]{1,64}$') { $res.Errors.Add(('Nom de groupe ''{0}'' invalide (64 caractères max, sans les caractères "/\[]:;|=,+*?<>@).' -f $Plan.GroupName)) }
        else {
            $g = @(Get-ADObject -LDAPFilter "(sAMAccountName=$(ConvertTo-LdapValue $Plan.GroupName))" -Server $s)
            if ($g.Count -gt 0) { $res.Errors.Add("Le nom '$($Plan.GroupName)' existe déjà ($($g[0].DistinguishedName)) : choisir « Utiliser un groupe existant ».") }
        }
        if (-not $Plan.GroupOu) { $res.Errors.Add('OU du groupe obligatoire.') }
        elseif (-not (Test-AdObjectExists $Plan.GroupOu)) { $res.Errors.Add("OU du groupe introuvable : $($Plan.GroupOu)") }
        Add-TierFinding -Result $res -Plan $Plan -Label 'OU du groupe' -Text $Plan.GroupOu -Required
        Add-TierFinding -Result $res -Plan $Plan -Label 'Nom du groupe' -Text $Plan.GroupName -Required
    }
    else {
        if (-not $Plan.GroupDn -and $Plan.GroupName) {
            try { $Plan.GroupDn = (Get-ADGroup -Identity $Plan.GroupName -Server $s -ErrorAction Stop).DistinguishedName } catch { $Plan.GroupDn = '' }
        }
        if (-not $Plan.GroupDn) { $res.Errors.Add('Groupe existant introuvable : utiliser le bouton « Choisir... ».') }
        else {
            try {
                $grp = Get-ADGroup -Identity $Plan.GroupDn -Server $s -Properties member -ErrorAction Stop
                if ($grp.GroupCategory -ne 'Security') { $res.Errors.Add("Le groupe $($grp.Name) n'est pas un groupe de sécurité.") }
                $res.GroupMembers = @($grp.member)
                Add-TierFinding -Result $res -Plan $Plan -Label 'Groupe existant' -Text $grp.DistinguishedName -Required
            }
            catch { $res.Errors.Add("Groupe introuvable : $($Plan.GroupDn)") }
        }
    }

    # --- Serveurs
    if (@($Plan.Servers).Count -eq 0) {
        $res.Warnings.Add("Aucun serveur dans le groupe : aucun ordinateur ne pourra récupérer le mot de passe tant que le groupe est vide.")
    }
    foreach ($srv in $Plan.Servers) {
        try {
            $c = Get-ADComputer -Identity $srv.Dn -Server $s -Properties userAccountControl -ErrorAction Stop
            if ((([int]$c.userAccountControl) -band 8192) -ne 0 -and $Plan.Tier -ne 0) {
                $msg = "Serveur $($c.Name) : contrôleur de domaine (Tier 0) autorisé sur un gMSA de Tier $($Plan.Tier)."
                if ($Plan.IgnoreTier) { $res.Warnings.Add("$msg Contrôle ignoré à la demande.") } else { $res.Errors.Add($msg) }
            }
            Add-TierFinding -Result $res -Plan $Plan -Label "Serveur $($c.Name)" -Text $c.DistinguishedName
        }
        catch { $res.Errors.Add("Serveur introuvable : $($srv.Dn)") }
    }

    # --- Appartenance à des groupes
    foreach ($m in $Plan.MemberOf) {
        try {
            $g = Get-ADGroup -Identity $m.Dn -Server $s -ErrorAction Stop
            $sid = $g.SID.Value
            if ($sid -match '-(512|518|519|520)$' -or $sid -in @('S-1-5-32-544', 'S-1-5-32-548', 'S-1-5-32-549', 'S-1-5-32-550', 'S-1-5-32-551')) {
                $res.Warnings.Add("Groupe $($g.Name) : groupe à privilèges élevés (Tier 0). À éviter pour un compte de service.")
            }
            Add-TierFinding -Result $res -Plan $Plan -Label "Groupe $($g.Name)" -Text $g.DistinguishedName
        }
        catch { $res.Errors.Add("Groupe introuvable : $($m.Dn)") }
    }

    # --- Délégations
    foreach ($d in $Plan.Delegations) {
        if (-not (Test-AdObjectExists $d.Ou)) { $res.Errors.Add("OU de délégation introuvable : $($d.Ou)") }
        Add-TierFinding -Result $res -Plan $Plan -Label "Délégation ($($d.Label))" -Text $d.Ou -Required
    }

    Write-AnalysisResult -Result $res
    Show-PlanSummary -Plan $Plan -Result $res
    return $res
}

function Write-AnalysisResult {
    param($Result)
    foreach ($w in $Result.Warnings) { Write-Log $w 'WARN' }
    foreach ($e in $Result.Errors) { Write-Log $e 'ERROR' }
    if ($Result.Errors.Count -eq 0) { Write-Log "Analyse terminée : aucune erreur bloquante, $($Result.Warnings.Count) avertissement(s)." 'OK' }
    else { Write-Log "Analyse terminée : $($Result.Errors.Count) erreur(s) bloquante(s), $($Result.Warnings.Count) avertissement(s)." 'ERROR' }
}

function Show-PlanSummary {
    param($Plan, $Result)
    Write-Log '---------- Plan ----------'
    if ($Result.KdsStatus -eq 'Missing' -and $Plan.CreateKds) { Write-Log "Créer la clé racine KDS (mode $($Plan.KdsMode))" 'PLAN' }
    if ($Plan.GroupMode -eq 'New') {
        Write-Log "Créer le groupe de sécurité $($Plan.GroupScope) '$($Plan.GroupName)' dans $($Plan.GroupOu)" 'PLAN'
    }
    else { Write-Log "Utiliser le groupe existant $($Plan.GroupDn)" 'PLAN' }
    foreach ($srv in $Plan.Servers) { Write-Log "Ajouter $($srv.Name) au groupe" 'PLAN' }
    $enc = $Plan.EncTypes -join ', '
    if ($Result.ExistingGmsa) {
        Write-Log "Mettre à jour le gMSA $($Plan.Sam) : groupe ajouté aux principaux autorisés, chiffrement $enc" 'PLAN'
    }
    else {
        Write-Log "Créer le gMSA $($Plan.Sam) (DNS $($Plan.DnsHostName)) dans $($Plan.GmsaOu), chiffrement $enc, mot de passe changé tous les $($Plan.PwdInterval) jours" 'PLAN'
    }
    foreach ($spn in $Plan.Spns) { Write-Log "SPN : $spn" 'PLAN' }
    foreach ($m in $Plan.MemberOf) { Write-Log "Ajouter le gMSA au groupe $($m.Name)" 'PLAN' }
    foreach ($d in $Plan.Delegations) { Write-Log "Délégation '$($d.Label)' sur $($d.Ou)" 'PLAN' }
}

function Invoke-Deployment {
    param($Plan)
    $dry = [bool]$Plan.DryRun
    $mode = 'RÉEL'
    if ($dry) { $mode = 'SIMULATION' }
    Write-Log "========== Exécution ($mode) : gMSA $($Plan.Sam) =========="
    $check = Test-Plan -Plan $Plan
    if ($check.Errors.Count -gt 0) {
        Write-Log 'Exécution annulée : corriger les erreurs bloquantes puis relancer.' 'ERROR'
        return
    }
    if (-not $dry) {
        $text = "Exécution RÉELLE dans $($script:DomainFqdn) :`n`n- gMSA $($Plan.Sam)`n- groupe $($Plan.GroupName)`n- $(@($Plan.Servers).Count) serveur(s), $(@($Plan.MemberOf).Count) groupe(s), $(@($Plan.Delegations).Count) délégation(s)`n`nContinuer ?"
        if (-not (Confirm-Action $text)) { Write-Log 'Exécution annulée par l''utilisateur.' 'WARN'; return }
        Start-RunState -Plan $Plan
    }
    $s = $script:Server
    $encString = $Plan.EncTypes -join ','
    $gmsaDn = $null
    $gmsaSid = $null

    try {
        # 1. Clé racine KDS
        if ($check.KdsStatus -eq 'Missing' -and $Plan.CreateKds) {
            if ($dry) { Write-Log "Créer la clé racine KDS (mode $($Plan.KdsMode))" 'SIMU' }
            else {
                if ($Plan.KdsMode -eq 'Lab') { $null = Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10)) }
                else { $null = Add-KdsRootKey -EffectiveImmediately }
                Add-Operation -Type 'KdsRootKey' -Data @{ Mode = $Plan.KdsMode }
                Write-Log "Clé racine KDS créée (mode $($Plan.KdsMode))." 'OK'
            }
            if ($Plan.KdsMode -eq 'Production') {
                if ($dry) { Write-Log "En exécution réelle, le script s'arrêterait ici (clé KDS effective dans 10 h)." 'WARN' }
                else {
                    Write-Log 'Clé KDS effective dans 10 h : relancer l''assistant ensuite pour créer le gMSA. Arrêt.' 'WARN'
                    Save-RunState -Status 'StoppedKdsPending'
                    return
                }
            }
        }

        # 2. Groupe
        $groupDn = $Plan.GroupDn
        $groupIsNew = $Plan.GroupMode -eq 'New'
        if ($groupIsNew) {
            $groupDn = 'CN={0},{1}' -f (ConvertTo-DnValue $Plan.GroupName), $Plan.GroupOu
            if ($dry) { Write-Log "Créer le groupe $($Plan.GroupScope) '$($Plan.GroupName)' dans $($Plan.GroupOu)" 'SIMU' }
            else {
                $gp = @{
                    Name           = $Plan.GroupName
                    SamAccountName = $Plan.GroupName
                    GroupScope     = $Plan.GroupScope
                    GroupCategory  = 'Security'
                    Path           = $Plan.GroupOu
                    Server         = $s
                    PassThru       = $true
                }
                if ($Plan.GroupDescription) { $gp.Description = $Plan.GroupDescription }
                $g = New-ADGroup @gp
                $groupDn = $g.DistinguishedName
                Add-Operation -Type 'CreateGroup' -Data @{ Dn = $groupDn; Name = $Plan.GroupName }
                Write-Log "Groupe créé : $groupDn" 'OK'
            }
        }

        # 3. Serveurs membres du groupe
        $members = @($check.GroupMembers)
        foreach ($srv in $Plan.Servers) {
            if ($members -contains $srv.Dn) { Write-Log "$($srv.Name) est déjà membre du groupe." 'INFO'; continue }
            if ($dry) { Write-Log "Ajouter $($srv.Name) au groupe $($Plan.GroupName)" 'SIMU'; continue }
            Add-ADGroupMember -Identity $groupDn -Members $srv.Dn -Server $s
            Add-Operation -Type 'AddMember' -Data @{ Group = $groupDn; Member = $srv.Dn }
            Write-Log "$($srv.Name) ajouté au groupe." 'OK'
        }

        # 4. gMSA
        $ex = $check.ExistingGmsa
        if ($ex) {
            $gmsaDn = $ex.DistinguishedName
            $gmsaSid = $ex.SID.Value
            $before = @($ex.PrincipalsAllowedToRetrieveManagedPassword | Where-Object { $_ })
            $beforeEnc = $ex.'msDS-SupportedEncryptionTypes'
            $currentSpns = @($ex.servicePrincipalName)
            $spnAdd = @($Plan.Spns | Where-Object { $currentSpns -notcontains $_ })
            $principals = @(@($before) + $groupDn | Select-Object -Unique)
            if ($dry) {
                Write-Log "Mettre à jour $($Plan.Sam) : principaux autorisés = $($principals -join ' ; '), chiffrement = $encString" 'SIMU'
                foreach ($spn in $spnAdd) { Write-Log "Ajouter le SPN $spn" 'SIMU' }
            }
            else {
                Set-ADServiceAccount -Identity $gmsaDn -PrincipalsAllowedToRetrieveManagedPassword $principals -KerberosEncryptionType $encString -Server $s
                if ($spnAdd.Count -gt 0) { Set-ADServiceAccount -Identity $gmsaDn -ServicePrincipalNames @{ Add = $spnAdd } -Server $s }
                Add-Operation -Type 'UpdateGmsa' -Data @{ Dn = $gmsaDn; BeforePrincipals = $before; BeforeEnc = $beforeEnc; AddedSpns = $spnAdd }
                Write-Log "gMSA mis à jour : $gmsaDn" 'OK'
            }
        }
        else {
            $gmsaDn = 'CN={0},{1}' -f (ConvertTo-DnValue $Plan.GmsaName), $Plan.GmsaOu
            if ($dry) {
                Write-Log "New-ADServiceAccount -Name $($Plan.GmsaName) -DNSHostName $($Plan.DnsHostName) -Path '$($Plan.GmsaOu)' -PrincipalsAllowedToRetrieveManagedPassword '$groupDn' -KerberosEncryptionType $encString -ManagedPasswordIntervalInDays $($Plan.PwdInterval)" 'SIMU'
            }
            else {
                $p = @{
                    Name                                       = $Plan.GmsaName
                    SamAccountName                             = $Plan.Sam
                    DNSHostName                                = $Plan.DnsHostName
                    Path                                       = $Plan.GmsaOu
                    PrincipalsAllowedToRetrieveManagedPassword = $groupDn
                    KerberosEncryptionType                     = $encString
                    ManagedPasswordIntervalInDays              = $Plan.PwdInterval
                    Enabled                                    = $true
                    Server                                     = $s
                    PassThru                                   = $true
                }
                if ($Plan.Description) { $p.Description = $Plan.Description }
                if (@($Plan.Spns).Count -gt 0) { $p.ServicePrincipalNames = [string[]]$Plan.Spns }
                $acc = New-ADServiceAccount @p
                $gmsaDn = $acc.DistinguishedName
                Add-Operation -Type 'CreateGmsa' -Data @{ Dn = $gmsaDn; Sam = $Plan.Sam }
                $gmsaSid = (Get-ADServiceAccount -Identity $gmsaDn -Server $s).SID.Value
                Write-Log "gMSA créé : $gmsaDn ($gmsaSid)" 'OK'
            }
        }

        # 5. Appartenance à des groupes
        foreach ($m in $Plan.MemberOf) {
            if (@($check.GmsaGroups) -contains $m.Dn) { Write-Log "Le gMSA est déjà membre de $($m.Name)." 'INFO'; continue }
            if ($dry) { Write-Log "Ajouter $($Plan.Sam) au groupe $($m.Name)" 'SIMU'; continue }
            Add-ADGroupMember -Identity $m.Dn -Members $gmsaDn -Server $s
            Add-Operation -Type 'AddMember' -Data @{ Group = $m.Dn; Member = $gmsaDn }
            Write-Log "gMSA ajouté au groupe $($m.Name)." 'OK'
        }

        # 6. Délégations sur des OU
        foreach ($d in $Plan.Delegations) {
            $rules = @($script:DelegationProfiles[$d.Profile].Rules)
            if ($dry) {
                foreach ($r in $rules) { Write-Log "ACE sur $($d.Ou) pour $($Plan.Sam) : $(Format-RuleSpec $r)" 'SIMU' }
                continue
            }
            $path = Get-AdPath $d.Ou
            $acl = Get-Acl -Path $path
            $safeOu = (($d.Ou -split '(?<!\\),')[0] -replace '[^A-Za-z0-9-]', '_')
            $backup = Join-Path $LogFolder ("GmsaGui_AclBackup_{0}_{1}.sddl" -f $safeOu, (Get-Date -Format 'yyyyMMdd-HHmmss'))
            Set-Content -LiteralPath $backup -Value $acl.Sddl -Encoding UTF8
            $added = @()
            foreach ($r in $rules) {
                if (Test-AcePresent -Acl $acl -Sid $gmsaSid -Rule $r) { Write-Log "ACE déjà présente sur $($d.Ou) : $(Format-RuleSpec $r)" 'INFO'; continue }
                $acl.AddAccessRule((ConvertTo-AdRule -Sid $gmsaSid -Rule $r))
                $added += $r
            }
            if ($added.Count -gt 0) {
                Set-Acl -Path $path -AclObject $acl
                foreach ($r in $added) {
                    Add-Operation -Type 'AddAce' -Data @{
                        Ou = $d.Ou; Sid = $gmsaSid; Rights = $r.Rights; ObjectType = $r.ObjectType
                        Inheritance = $r.Inheritance; InheritedObjectType = $r.InheritedObjectType; Backup = $backup
                    }
                }
                Write-Log "Délégation '$($d.Label)' appliquée sur $($d.Ou) ($($added.Count) ACE, sauvegarde : $backup)." 'OK'
            }
        }

        if ($dry) {
            Write-Log 'Simulation terminée : aucune modification. Décocher « Mode simulation » pour exécuter.' 'OK'
        }
        else {
            Save-RunState -Status 'Completed'
            Write-Log "Exécution terminée. Fichier d'état pour rollback : $($script:StatePath)" 'OK'
            Write-Log "Sur chaque serveur : redémarrer (ou klist -li 0x3e7 purge), puis Test-ADServiceAccount $($Plan.GmsaName)." 'INFO'
        }
    }
    catch {
        Write-Log "Erreur : $($_.Exception.Message)" 'ERROR'
        if (-not $dry -and $script:StatePath) {
            Save-RunState -Status 'Failed'
            Write-Log "Étapes déjà réalisées enregistrées : bouton « Rollback... » avec $($script:StatePath)" 'WARN'
        }
    }
}

function Invoke-Rollback {
    param([string]$StateFile, [bool]$DryRun)
    $state = Get-Content -LiteralPath $StateFile -Raw -Encoding UTF8 | ConvertFrom-Json
    $ops = @($state.Operations | Where-Object { $_ })
    [array]::Reverse($ops)
    $mode = 'RÉEL'
    if ($DryRun) { $mode = 'SIMULATION' }
    Write-Log "========== Rollback ($mode) : $StateFile =========="
    Write-Log "gMSA $($state.Gmsa), exécution du $($state.Date) par $($state.Operator), statut $($state.Status), $($ops.Count) opération(s)."
    if ($state.Status -eq 'RolledBack') { Write-Log 'Ce fichier a déjà été annulé.' 'WARN' }
    if ($state.Domain -and $state.Domain -ne $script:DomainDN) {
        Write-Log "Le fichier concerne le domaine $($state.Domain), domaine courant : $($script:DomainDN). Rollback annulé." 'ERROR'
        return
    }
    if (-not $DryRun -and -not (Confirm-Action "Annuler réellement $($ops.Count) opération(s) du gMSA $($state.Gmsa) ?")) {
        Write-Log 'Rollback annulé par l''utilisateur.' 'WARN'
        return
    }
    $s = $script:Server
    $fail = 0
    foreach ($op in $ops) {
        try {
            switch ($op.Type) {
                'AddAce' {
                    $txt = "Retirer l'ACE de $($op.Sid) sur $($op.Ou) : $(Format-RuleSpec $op)"
                    if ($DryRun) { Write-Log $txt 'SIMU' }
                    else {
                        $path = Get-AdPath $op.Ou
                        $acl = Get-Acl -Path $path
                        $acl.RemoveAccessRuleSpecific((ConvertTo-AdRule -Sid $op.Sid -Rule $op))
                        Set-Acl -Path $path -AclObject $acl
                        Write-Log $txt 'OK'
                    }
                }
                'AddMember' {
                    $txt = "Retirer $($op.Member) du groupe $($op.Group)"
                    if ($DryRun) { Write-Log $txt 'SIMU' }
                    else { Remove-ADGroupMember -Identity $op.Group -Members $op.Member -Confirm:$false -Server $s; Write-Log $txt 'OK' }
                }
                'UpdateGmsa' {
                    $prev = @($op.BeforePrincipals | Where-Object { $_ })
                    $spns = @($op.AddedSpns | Where-Object { $_ })
                    $txt = "Restaurer $($op.Dn) : principaux autorisés = $($prev -join ' ; '), msDS-SupportedEncryptionTypes = $($op.BeforeEnc), SPN retirés = $($spns -join ', ')"
                    if ($DryRun) { Write-Log $txt 'SIMU' }
                    else {
                        if ($prev.Count -gt 0) { Set-ADServiceAccount -Identity $op.Dn -PrincipalsAllowedToRetrieveManagedPassword $prev -Server $s }
                        else { Set-ADServiceAccount -Identity $op.Dn -Clear 'msDS-GroupMSAMembership' -Server $s }
                        if ($null -ne $op.BeforeEnc) { Set-ADServiceAccount -Identity $op.Dn -Replace @{ 'msDS-SupportedEncryptionTypes' = [int]$op.BeforeEnc } -Server $s }
                        else { Set-ADServiceAccount -Identity $op.Dn -Clear 'msDS-SupportedEncryptionTypes' -Server $s }
                        if ($spns.Count -gt 0) { Set-ADServiceAccount -Identity $op.Dn -ServicePrincipalNames @{ Remove = [string[]]$spns } -Server $s }
                        Write-Log $txt 'OK'
                    }
                }
                'CreateGmsa' {
                    $txt = "Supprimer le gMSA $($op.Dn)"
                    if ($DryRun) { Write-Log $txt 'SIMU' }
                    else { Remove-ADServiceAccount -Identity $op.Dn -Confirm:$false -Server $s; Write-Log $txt 'OK' }
                }
                'CreateGroup' {
                    $txt = "Supprimer le groupe $($op.Dn)"
                    if ($DryRun) { Write-Log $txt 'SIMU' }
                    else { Remove-ADGroup -Identity $op.Dn -Confirm:$false -Server $s; Write-Log $txt 'OK' }
                }
                'KdsRootKey' {
                    Write-Log "Clé racine KDS (mode $($op.Mode)) conservée volontairement : d'autres gMSA peuvent en dépendre." 'WARN'
                }
                default { Write-Log "Opération inconnue ignorée : $($op.Type)" 'WARN' }
            }
        }
        catch {
            $fail++
            Write-Log "Échec du rollback de $($op.Type) : $($_.Exception.Message)" 'ERROR'
        }
    }
    if ($DryRun) { Write-Log 'Simulation du rollback terminée : aucune modification.' 'OK'; return }
    $status = 'RolledBack'
    if ($fail -gt 0) { $status = 'RollbackPartial' }
    $state | Add-Member -NotePropertyName 'Status' -NotePropertyValue $status -Force
    $state | Add-Member -NotePropertyName 'RollbackDate' -NotePropertyValue (Get-Date).ToString('o') -Force
    $state | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $StateFile -Encoding UTF8
    if ($fail -gt 0) { Write-Log "Rollback partiel : $fail échec(s). Voir les erreurs ci-dessus." 'ERROR' }
    else { Write-Log 'Rollback terminé.' 'OK' }
}

function Invoke-UiAction {
    param([scriptblock]$Body)
    try {
        $script:form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
        $script:pnlButtons.Enabled = $false
        & $Body
    }
    catch { Write-Log "Erreur : $($_.Exception.Message)" 'ERROR' }
    finally {
        $script:pnlButtons.Enabled = $true
        $script:form.Cursor = [System.Windows.Forms.Cursors]::Default
    }
}

# ----------------------------------------------------------------------------
# Fenêtre principale
# ----------------------------------------------------------------------------
Initialize-LogFile

$script:form = New-Object System.Windows.Forms.Form
$script:form.Text = "Création d'un gMSA et de son groupe - v$($script:ScriptVersion)"
$script:form.ClientSize = New-Object System.Drawing.Size(980, 780)
$script:form.StartPosition = 'CenterScreen'
$script:form.FormBorderStyle = 'FixedDialog'
$script:form.MaximizeBox = $false
$script:form.Font = New-Object System.Drawing.Font('Segoe UI', 9)

$script:lblDomain = New-Ctl -Type 'Label' -X 12 -Y 12 -Text 'Domaine : (non connecté)' -Parent $script:form
$script:lblDomain.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)

$tabs = New-Ctl -Type 'TabControl' -X 10 -Y 38 -W 960 -H 460 -Parent $script:form
$tab1 = New-Object System.Windows.Forms.TabPage
$tab1.Text = '1. gMSA et groupe'
$tab1.UseVisualStyleBackColor = $true
$tab2 = New-Object System.Windows.Forms.TabPage
$tab2.Text = '2. Droits'
$tab2.UseVisualStyleBackColor = $true
$tabs.TabPages.Add($tab1)
$tabs.TabPages.Add($tab2)

# --- Onglet 1 : gMSA ---------------------------------------------------------
$gbGmsa = New-Ctl -Type 'GroupBox' -X 10 -Y 8 -W 460 -H 415 -Text 'Compte gMSA' -Parent $tab1
[void](New-Ctl -Type 'Label' -X 12 -Y 28 -Text 'Tier :' -Parent $gbGmsa)
$script:cmbTier = New-Ctl -Type 'ComboBox' -X 130 -Y 24 -W 120 -Parent $gbGmsa
$script:cmbTier.DropDownStyle = 'DropDownList'
[void]$script:cmbTier.Items.AddRange(@('Tier 0', 'Tier 1', 'Tier 2'))

[void](New-Ctl -Type 'Label' -X 12 -Y 58 -Text 'Nom (sans $) :' -Parent $gbGmsa)
$script:txtName = New-Ctl -Type 'TextBox' -X 130 -Y 54 -W 200 -Parent $gbGmsa
$script:txtName.MaxLength = 15
$script:lblCount = New-Ctl -Type 'Label' -X 340 -Y 58 -Text '0/15' -Parent $gbGmsa

[void](New-Ctl -Type 'Label' -X 12 -Y 88 -Text 'Nom DNS :' -Parent $gbGmsa)
$script:txtDns = New-Ctl -Type 'TextBox' -X 130 -Y 84 -W 315 -Parent $gbGmsa

[void](New-Ctl -Type 'Label' -X 12 -Y 118 -Text 'Description :' -Parent $gbGmsa)
$script:txtDesc = New-Ctl -Type 'TextBox' -X 130 -Y 114 -W 315 -Parent $gbGmsa

[void](New-Ctl -Type 'Label' -X 12 -Y 148 -Text 'OU du gMSA :' -Parent $gbGmsa)
$script:txtGmsaOu = New-Ctl -Type 'TextBox' -X 130 -Y 144 -W 230 -Parent $gbGmsa
$btnGmsaOu = New-Ctl -Type 'Button' -X 365 -Y 143 -W 80 -H 25 -Text 'Parcourir...' -Parent $gbGmsa

[void](New-Ctl -Type 'Label' -X 12 -Y 178 -Text 'Mot de passe :' -Parent $gbGmsa)
$script:numInterval = New-Ctl -Type 'NumericUpDown' -X 130 -Y 174 -W 60 -Parent $gbGmsa
$script:numInterval.Minimum = 1
$script:numInterval.Maximum = 365
$script:numInterval.Value = 30
[void](New-Ctl -Type 'Label' -X 195 -Y 178 -Text 'jours entre deux changements (fixé à la création)' -Parent $gbGmsa)

[void](New-Ctl -Type 'Label' -X 12 -Y 208 -Text 'SPN (un par ligne) :' -Parent $gbGmsa)
$script:txtSpn = New-Ctl -Type 'TextBox' -X 130 -Y 204 -W 315 -H 90 -Parent $gbGmsa
$script:txtSpn.Multiline = $true
$script:txtSpn.ScrollBars = 'Vertical'

$lblHelp1 = New-Ctl -Type 'Label' -X 12 -Y 305 -W 435 -H 100 -Parent $gbGmsa
$lblHelp1.ForeColor = [System.Drawing.Color]::DimGray
$lblHelp1.Text = "Le nom est limité à 15 caractères (le '`$' est ajouté automatiquement). L'OU, le nom DNS, la description et le nom du groupe sont proposés à partir du Tier et du nom, et restent modifiables. Exemple de SPN : HTTP/app01.tiering.ad. Les serveurs du groupe récupèrent le mot de passe du gMSA ; ils doivent appartenir au même Tier."

# --- Onglet 1 : groupe --------------------------------------------------------
$gbGroup = New-Ctl -Type 'GroupBox' -X 480 -Y 8 -W 460 -H 180 -Text 'Groupe autorisé à récupérer le mot de passe' -Parent $tab1
$script:rbGroupNew = New-Ctl -Type 'RadioButton' -X 12 -Y 24 -Text 'Créer un nouveau groupe' -Parent $gbGroup
$script:rbGroupNew.Checked = $true
$script:rbGroupExisting = New-Ctl -Type 'RadioButton' -X 220 -Y 24 -Text 'Utiliser un groupe existant' -Parent $gbGroup

[void](New-Ctl -Type 'Label' -X 12 -Y 58 -Text 'Nom :' -Parent $gbGroup)
$script:txtGroupName = New-Ctl -Type 'TextBox' -X 110 -Y 54 -W 250 -Parent $gbGroup
$script:btnPickGroup = New-Ctl -Type 'Button' -X 365 -Y 53 -W 80 -H 25 -Text 'Choisir...' -Parent $gbGroup
$script:btnPickGroup.Enabled = $false

[void](New-Ctl -Type 'Label' -X 12 -Y 88 -Text 'Étendue :' -Parent $gbGroup)
$script:cmbScope = New-Ctl -Type 'ComboBox' -X 110 -Y 84 -W 130 -Parent $gbGroup
$script:cmbScope.DropDownStyle = 'DropDownList'
[void]$script:cmbScope.Items.AddRange(@('Global', 'DomainLocal', 'Universal'))
$script:cmbScope.SelectedIndex = 0

[void](New-Ctl -Type 'Label' -X 12 -Y 118 -Text 'OU du groupe :' -Parent $gbGroup)
$script:txtGroupOu = New-Ctl -Type 'TextBox' -X 110 -Y 114 -W 250 -Parent $gbGroup
$script:btnGroupOu = New-Ctl -Type 'Button' -X 365 -Y 113 -W 80 -H 25 -Text 'Parcourir...' -Parent $gbGroup

[void](New-Ctl -Type 'Label' -X 12 -Y 148 -Text 'Description :' -Parent $gbGroup)
$script:txtGroupDesc = New-Ctl -Type 'TextBox' -X 110 -Y 144 -W 335 -Parent $gbGroup

# --- Onglet 1 : serveurs ------------------------------------------------------
$gbServers = New-Ctl -Type 'GroupBox' -X 480 -Y 193 -W 460 -H 230 -Text 'Serveurs membres du groupe' -Parent $tab1
$script:lvServers = New-ListViewCtl -X 12 -Y 22 -W 340 -H 195 -Columns @('Serveur', 'DN') -Widths @(110, 400) -Parent $gbServers
$btnAddSrv = New-Ctl -Type 'Button' -X 360 -Y 22 -W 88 -H 28 -Text 'Ajouter...' -Parent $gbServers
$btnDelSrv = New-Ctl -Type 'Button' -X 360 -Y 56 -W 88 -H 28 -Text 'Retirer' -Parent $gbServers

# --- Onglet 2 : chiffrement ---------------------------------------------------
$gbEnc = New-Ctl -Type 'GroupBox' -X 10 -Y 8 -W 300 -H 135 -Text 'Chiffrement Kerberos' -Parent $tab2
$script:chkAes256 = New-Ctl -Type 'CheckBox' -X 15 -Y 25 -Text 'AES256' -Parent $gbEnc
$script:chkAes256.Checked = $true
$script:chkAes128 = New-Ctl -Type 'CheckBox' -X 15 -Y 50 -Text 'AES128' -Parent $gbEnc
$script:chkAes128.Checked = $true
$script:chkRc4 = New-Ctl -Type 'CheckBox' -X 15 -Y 75 -Text 'RC4 (déconseillé)' -Parent $gbEnc
$lblRc4 = New-Ctl -Type 'Label' -X 15 -Y 100 -W 275 -H 30 -Text 'RC4 uniquement pour une application qui ne gère pas AES.' -Parent $gbEnc
$lblRc4.ForeColor = [System.Drawing.Color]::Firebrick

# --- Onglet 2 : clé KDS -------------------------------------------------------
$gbKds = New-Ctl -Type 'GroupBox' -X 10 -Y 150 -W 300 -H 150 -Text 'Clé racine KDS' -Parent $tab2
$script:chkKds = New-Ctl -Type 'CheckBox' -X 15 -Y 25 -Text 'Créer la clé racine KDS si absente' -Parent $gbKds
$script:cmbKds = New-Ctl -Type 'ComboBox' -X 15 -Y 52 -W 270 -Parent $gbKds
$script:cmbKds.DropDownStyle = 'DropDownList'
[void]$script:cmbKds.Items.AddRange(@('Production : effective après 10 h', 'Laboratoire : effective immédiatement'))
$script:cmbKds.SelectedIndex = 0
$lblKds = New-Ctl -Type 'Label' -X 15 -Y 82 -W 275 -H 60 -Parent $gbKds
$lblKds.ForeColor = [System.Drawing.Color]::DimGray
$lblKds.Text = "Une seule clé par forêt. En production, l'exécution s'arrête après sa création : relancer 10 h plus tard. Droits Domain Admins ou Enterprise Admins requis. Jamais supprimée par le rollback."

# --- Onglet 2 : appartenance --------------------------------------------------
$gbMember = New-Ctl -Type 'GroupBox' -X 320 -Y 8 -W 620 -H 150 -Text 'Le gMSA est membre des groupes' -Parent $tab2
$script:lvMemberOf = New-ListViewCtl -X 12 -Y 22 -W 495 -H 115 -Columns @('Groupe', 'Type', 'DN') -Widths @(150, 120, 350) -Parent $gbMember
$btnAddGrp = New-Ctl -Type 'Button' -X 518 -Y 22 -W 90 -H 28 -Text 'Ajouter...' -Parent $gbMember
$btnDelGrp = New-Ctl -Type 'Button' -X 518 -Y 56 -W 90 -H 28 -Text 'Retirer' -Parent $gbMember

# --- Onglet 2 : délégations ---------------------------------------------------
$gbDeleg = New-Ctl -Type 'GroupBox' -X 320 -Y 165 -W 620 -H 258 -Text 'Délégations de droits sur des OU (au profit du gMSA)' -Parent $tab2
$script:cmbProfile = New-Ctl -Type 'ComboBox' -X 12 -Y 24 -W 360 -Parent $gbDeleg
$script:cmbProfile.DropDownStyle = 'DropDownList'
foreach ($k in $script:DelegationProfiles.Keys) { [void]$script:cmbProfile.Items.Add($script:DelegationProfiles[$k].Label) }
$script:cmbProfile.SelectedIndex = 0
$btnAddDeleg = New-Ctl -Type 'Button' -X 380 -Y 22 -W 110 -H 27 -Text 'Ajouter une OU...' -Parent $gbDeleg
$btnDelDeleg = New-Ctl -Type 'Button' -X 498 -Y 22 -W 110 -H 27 -Text 'Retirer' -Parent $gbDeleg
$script:lblProfile = New-Ctl -Type 'Label' -X 12 -Y 55 -W 596 -H 32 -Parent $gbDeleg
$script:lblProfile.ForeColor = [System.Drawing.Color]::DimGray
$script:lvDeleg = New-ListViewCtl -X 12 -Y 90 -W 596 -H 155 -Columns @('Droit', 'OU') -Widths @(240, 450) -Parent $gbDeleg

# --- Bas de fenêtre : options, boutons, journal -------------------------------
$script:chkDryRun = New-Ctl -Type 'CheckBox' -X 12 -Y 506 -Text 'Mode simulation (Dry Run) : aucune modification dans l''annuaire' -Parent $script:form
$script:chkDryRun.Checked = $true
$script:chkDryRun.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
$script:chkIgnoreTier = New-Ctl -Type 'CheckBox' -X 520 -Y 506 -Text 'Ignorer les incohérences de Tier (déconseillé)' -Parent $script:form

$script:pnlButtons = New-Ctl -Type 'Panel' -X 10 -Y 532 -W 960 -H 36 -Parent $script:form
$btnAnalyze = New-Ctl -Type 'Button' -X 2 -Y 2 -W 120 -H 32 -Text 'Analyser' -Parent $script:pnlButtons
$script:btnRun = New-Ctl -Type 'Button' -X 130 -Y 2 -W 140 -H 32 -Text 'Simuler' -Parent $script:pnlButtons
$script:btnRun.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
$btnRollback = New-Ctl -Type 'Button' -X 278 -Y 2 -W 120 -H 32 -Text 'Rollback...' -Parent $script:pnlButtons
$btnLogs = New-Ctl -Type 'Button' -X 406 -Y 2 -W 140 -H 32 -Text 'Dossier des journaux' -Parent $script:pnlButtons
$btnClear = New-Ctl -Type 'Button' -X 554 -Y 2 -W 120 -H 32 -Text 'Effacer l''affichage' -Parent $script:pnlButtons

$script:txtLog = New-Ctl -Type 'TextBox' -X 10 -Y 574 -W 960 -H 196 -Parent $script:form
$script:txtLog.Multiline = $true
$script:txtLog.ReadOnly = $true
$script:txtLog.ScrollBars = 'Both'
$script:txtLog.WordWrap = $false
$script:txtLog.Font = New-Object System.Drawing.Font('Consolas', 9)

# ----------------------------------------------------------------------------
# Événements
# ----------------------------------------------------------------------------
function Update-GroupMode {
    $isNew = $script:rbGroupNew.Checked
    $script:btnPickGroup.Enabled = -not $isNew
    $script:txtGroupName.ReadOnly = -not $isNew
    $script:cmbScope.Enabled = $isNew
    $script:txtGroupOu.Enabled = $isNew
    $script:btnGroupOu.Enabled = $isNew
    $script:txtGroupDesc.Enabled = $isNew
    $script:txtGroupName.Tag = $null
    $script:txtGroupName.Text = ''
    $script:AutoValues['Group'] = ''
    Update-AutoFields
}

function Update-RunButton {
    if ($script:chkDryRun.Checked) {
        $script:btnRun.Text = 'Simuler'
        $script:btnRun.ForeColor = [System.Drawing.SystemColors]::ControlText
    }
    else {
        $script:btnRun.Text = 'Exécuter (réel)'
        $script:btnRun.ForeColor = [System.Drawing.Color]::Firebrick
    }
}

$script:cmbTier.Add_SelectedIndexChanged({ Update-AutoFields })
$script:txtName.Add_TextChanged({
        $n = $script:txtName.Text.Length
        $script:lblCount.Text = "$n/15"
        Update-AutoFields
        Set-AutoText -TextBox $script:txtGroupDesc -Key 'GroupDesc' -Value "Serveurs autorisés à récupérer le mot de passe du gMSA $($script:txtName.Text.Trim())`$"
    })
$script:rbGroupNew.Add_CheckedChanged({ Update-GroupMode })
$script:chkDryRun.Add_CheckedChanged({ Update-RunButton })
$script:cmbProfile.Add_SelectedIndexChanged({
        $key = @($script:DelegationProfiles.Keys)[$script:cmbProfile.SelectedIndex]
        $script:lblProfile.Text = $script:DelegationProfiles[$key].Help
    })

$btnGmsaOu.Add_Click({
        $dn = Select-AdContainer -Title 'OU du gMSA'
        if ($dn) { $script:txtGmsaOu.Text = $dn }
    })
$script:btnGroupOu.Add_Click({
        $dn = Select-AdContainer -Title 'OU du groupe'
        if ($dn) { $script:txtGroupOu.Text = $dn }
    })
$script:btnPickGroup.Add_Click({
        $sel = @(Select-AdObjects -Class 'group' -Title 'Groupe existant autorisé à récupérer le mot de passe' -Single)
        if ($sel.Count -gt 0) {
            $script:txtGroupName.Text = $sel[0].Name
            $script:txtGroupName.Tag = $sel[0].Dn
            Write-Log "Groupe existant sélectionné : $($sel[0].Dn)"
        }
    })
$btnAddSrv.Add_Click({
        foreach ($o in @(Select-AdObjects -Class 'computer' -Title 'Serveurs autorisés à récupérer le mot de passe')) {
            if ($o.IsDC) { Write-Log "$($o.Name) est un contrôleur de domaine (Tier 0)." 'WARN' }
            [void](Add-ListItem -ListView $script:lvServers -Texts @($o.Name, $o.Dn) -Tag $o -Key $o.Dn)
        }
    })
$btnDelSrv.Add_Click({ Remove-SelectedItems -ListView $script:lvServers })
$btnAddGrp.Add_Click({
        foreach ($o in @(Select-AdObjects -Class 'group' -Title 'Groupes dont le gMSA sera membre')) {
            [void](Add-ListItem -ListView $script:lvMemberOf -Texts @($o.Name, $o.Info, $o.Dn) -Tag $o -Key $o.Dn)
        }
    })
$btnDelGrp.Add_Click({ Remove-SelectedItems -ListView $script:lvMemberOf })
$btnAddDeleg.Add_Click({
        $key = @($script:DelegationProfiles.Keys)[$script:cmbProfile.SelectedIndex]
        $label = $script:DelegationProfiles[$key].Label
        $dn = Select-AdContainer -Title "OU à déléguer : $label"
        if ($dn) {
            $tag = [pscustomobject]@{ Ou = $dn; Profile = $key; Label = $label }
            [void](Add-ListItem -ListView $script:lvDeleg -Texts @($label, $dn) -Tag $tag -Key "$key|$dn")
        }
    })
$btnDelDeleg.Add_Click({ Remove-SelectedItems -ListView $script:lvDeleg })

$btnAnalyze.Add_Click({ Invoke-UiAction { $null = Test-Plan -Plan (Get-UiPlan) } })
$script:btnRun.Add_Click({ Invoke-UiAction { Invoke-Deployment -Plan (Get-UiPlan) } })
$btnRollback.Add_Click({
        Invoke-UiAction {
            if (-not (Test-AdReady)) { return }
            $ofd = New-Object System.Windows.Forms.OpenFileDialog
            $ofd.InitialDirectory = $LogFolder
            $ofd.Filter = "États gMSA (GmsaGui_State_*.json)|GmsaGui_State_*.json|JSON (*.json)|*.json"
            $ofd.Title = "Fichier d'état à annuler"
            if ($ofd.ShowDialog($script:form) -eq [System.Windows.Forms.DialogResult]::OK) {
                Invoke-Rollback -StateFile $ofd.FileName -DryRun $script:chkDryRun.Checked
            }
        }
    })
$btnLogs.Add_Click({
        if (Test-Path -LiteralPath $LogFolder) { Start-Process -FilePath 'explorer.exe' -ArgumentList "`"$LogFolder`"" }
    })
$btnClear.Add_Click({ $script:txtLog.Clear() })

$script:form.Add_Shown({
        Write-Log "Assistant gMSA v$($script:ScriptVersion) - journal : $($script:LogFile)"
        Invoke-UiAction { Initialize-Ad }
        $script:form.Activate()
    })

$script:cmbTier.SelectedIndex = $Tier
$script:lblProfile.Text = $script:DelegationProfiles['Read'].Help
Update-RunButton

if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
    Write-Warning 'Lancer PowerShell en mode STA : powershell.exe -STA -File .\New-GmsaGui.ps1'
}
[void]$script:form.ShowDialog()
$script:form.Dispose()
if (Get-PSDrive -Name $script:AdDrive -ErrorAction SilentlyContinue) { Remove-PSDrive -Name $script:AdDrive -ErrorAction SilentlyContinue }
