<#
    Script  : TierModel_Deployment_v1.1.ps1
    Version : 1.1 (2026-11-20)
    Auteur  : EZES Jean-Michel
    Avec la participation de l'IA : Claude (Anthropic)

.SYNOPSIS
    Assistant graphique de mise en place d'un Tier Model dans Active Directory.
    Onglet 1 : Création de la structure d'OU.
    Onglet 2 : Création des groupes de délégation et opérationnels (catalogue par Tier, imbrications AGDLP).
    Onglet 3 : Création et affectation des comptes d'administration de Tier (convention de nommage libre, OU et groupes liés aux onglets 1 et 2).

.DESCRIPTION
    - Propose une convention de nommage de base (modifiable) et la décline sur Tier0 / Tier1 / Tier2 + Legacy.
    - Aperçu en arbre : cases à cocher = OU à créer, F2 = renommer une OU, bleu = OU proposée (non demandée à l'origine).
    - Mode simulation (par défaut) : aucune création, uniquement le journal de ce qui serait fait.
    - Idempotent : les OU, groupes et comptes déjà existants sont ignorés.
    - Onglet 3 : un compte distinct par personne ET par Tier (T0/T1/T2), nom de compte / nom affiché construits depuis une
      convention modifiable (modèles courants proposés), OU par défaut = OU 'Administrateurs' du Tier (onglet 1), groupes par défaut
      déduits du catalogue de l'onglet 2 (refus des affectations inter-Tiers), mot de passe initial aléatoire (CSV à ACL restreinte),
      options de durcissement (compte sensible, Protected Users, carte à puce).
    - Journalisation : tous les messages sont aussi écrits dans un fichier journal ; la création de comptes écrit un fichier d'état JSON
      qui alimente le bouton 'Rollback...' (suppression des comptes créés, retrait des groupes ajoutés).

.PARAMETER LogFolder
    Dossier des journaux, fichiers d'état (rollback) et export des mots de passe. Défaut : Documents\TierModel.

.PARAMETER Server
    Contrôleur de domaine à utiliser (vide = détection automatique, PDC émulateur épinglé pour les créations).

.PARAMETER DomainDN
    DN du domaine proposé au démarrage (écrasé par la détection automatique si RSAT est présent).

.PARAMETER PasswordLength
    Longueur par défaut des mots de passe initiaux des comptes admins (14 à 64). Défaut : 24.

.EXAMPLE
    powershell.exe -STA -ExecutionPolicy Bypass -File .\TierModel_Deployment_v1.1.ps1
    Lance l'assistant avec les valeurs par défaut (mode simulation activé sur chaque onglet).

.EXAMPLE
    .\TierModel_Deployment_v1.1.ps1 -Server DC01.contoso.local -DomainDN 'DC=contoso,DC=local' -LogFolder D:\Logs\TierModel
    Cible un contrôleur précis et redirige journaux / fichiers d'état.

.EXAMPLE
    # Rollback : onglet 'Création Comptes Admins' > 'Rollback...' > choisir TierModel_AdminAccounts_State_<date>.json

.NOTES
    Prérequis : Windows PowerShell 5.1, module RSAT ActiveDirectory, droits de création d'OU sur le domaine.
    Lancement : powershell.exe -STA -ExecutionPolicy Bypass -File .\TierModel_Deployment_v1.1.ps1
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$LogFolder = (Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'TierModel'),
    [string]$Server = '',
    [string]$DomainDN = 'DC=domaine,DC=dom',
    [ValidateRange(14, 64)][int]$PasswordLength = 24
)

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

# ----------------------------------------------------------------------------
# État global
# ----------------------------------------------------------------------------
$script:ScriptVersion  = '1.1'
$script:LogFolder      = $LogFolder
$script:LogFile        = $null
$script:Updating       = $false
$script:ApplyingPreset = $false
$script:Customized     = $false   # vrai dès que l'utilisateur renomme / ajoute / retire une OU à la main
$script:Stats          = @{ Created = 0; Existing = 0; Simulated = 0; Errors = 0 }
$script:AdParams       = @{}
$script:InvalidChars   = '[,=+<>#;"\\/]'
$script:AdAvailable    = [bool](Get-Module -ListAvailable -Name ActiveDirectory)

# ----------------------------------------------------------------------------
# Modèles de conventions de nommage (base proposée + variantes)
# ----------------------------------------------------------------------------
$script:Presets = @(
    @{ AdminRoot = 'Admin-TM'; AdminTier = 'Adm-T{N}'; AdminLegacy = 'Adm-Legacy'; TierRoot = 'Tier{N}'; Prefix = 'T{N}'; LegacyPrefix = 'TL'; Sep = '-'; Lang = 0 },
    @{ AdminRoot = 'Admin-TM'; AdminTier = 'Adm-T{N}'; AdminLegacy = 'Adm-Legacy'; TierRoot = 'Tier{N}'; Prefix = 'T{N}'; LegacyPrefix = 'TL'; Sep = '-'; Lang = 1 },
    @{ AdminRoot = 'Admin_TM'; AdminTier = 'Adm_T{N}'; AdminLegacy = 'Adm_Legacy'; TierRoot = 'Tier{N}'; Prefix = 'T{N}'; LegacyPrefix = 'TL'; Sep = '_'; Lang = 0 }
)

# ----------------------------------------------------------------------------
# Modèles de structure (FR / EN). -Proposed = OU ajoutée par rapport à votre proposition.
# ChildPrefix : préfixe intermédiaire appliqué aux enfants (ex. Grp => T0-Grp-FiltresGPO)
# ----------------------------------------------------------------------------
function TN {
    param(
        [string]$FR,
        [string]$EN,
        [object[]]$Children = @(),
        [switch]$Proposed,
        [string]$ChildPrefix = ''
    )
    [pscustomobject]@{
        FR = $FR; EN = $EN; Children = @($Children)
        Proposed = [bool]$Proposed; ChildPrefix = $ChildPrefix
    }
}

function Get-AdminChildren {
    param([int]$Tier)
    $c = @(
        (TN 'Administrateurs' 'Administrators'),
        (TN 'GroupesAdmins' 'AdminGroups')
    )
    if ($Tier -eq 0) { $c += (TN 'ComptesUrgence' 'BreakGlass' -Proposed) }
    $c
}

function Get-TierChildren {
    param([int]$Tier)
    switch ($Tier) {
        0 {
            @(
                (TN 'Groupes' 'Groups' -ChildPrefix 'Grp' -Children @(
                    (TN 'FiltresGPO' 'GPOFilters'),
                    (TN 'Serveurs' 'Servers'),
                    (TN 'SUtilisateurs' 'SUsers'),
                    (TN 'Delegation' 'Delegation' -Proposed),
                    (TN 'Roles' 'Roles' -Proposed)
                )),
                (TN 'PAW' 'PAW'),
                (TN 'Serveurs' 'Servers' -Children @(
                    (TN 'RDPServeurs' 'RDPServers'),
                    (TN 'PKI' 'PKI'),
                    (TN 'ADFS' 'ADFS' -Proposed),
                    (TN 'Hyperviseurs' 'Hypervisors' -Proposed),
                    (TN 'Sauvegarde' 'Backup' -Proposed),
                    (TN 'EntraConnect' 'EntraConnect' -Proposed)
                )),
                (TN 'Services' 'Services'),
                (TN 'SuperUtilisateurs' 'SuperUsers')
            )
        }
        1 {
            @(
                (TN 'Groupes' 'Groups' -ChildPrefix 'Grp' -Children @(
                    (TN 'FiltresGPO' 'GPOFilters'),
                    (TN 'Serveurs' 'Servers'),
                    (TN 'SUtilisateurs' 'SUsers'),
                    (TN 'Delegation' 'Delegation' -Proposed),
                    (TN 'Roles' 'Roles' -Proposed)
                )),
                (TN 'PAW' 'PAW'),
                (TN 'Serveurs' 'Servers' -Children @(
                    (TN 'RDPServeurs' 'RDPServers'),
                    (TN 'Applications' 'Applications' -Proposed),
                    (TN 'BasesDeDonnees' 'Databases' -Proposed),
                    (TN 'Fichiers' 'FileServers' -Proposed),
                    (TN 'Web' 'Web' -Proposed),
                    (TN 'Messagerie' 'Messaging' -Proposed)
                )),
                (TN 'Services' 'Services'),
                (TN 'SuperUtilisateurs' 'SuperUsers')
            )
        }
        default {
            @(
                (TN 'Groupes' 'Groups' -ChildPrefix 'Grp' -Children @(
                    (TN 'FiltresGPO' 'GPOFilters'),
                    (TN 'Postes' 'Computers'),
                    (TN 'SUtilisateurs' 'SUsers'),
                    (TN 'Delegation' 'Delegation' -Proposed)
                )),
                (TN 'PAW' 'PAW'),
                (TN 'Postes' 'Workstations' -Children @(
                    (TN 'Fixes' 'Desktops'),
                    (TN 'Portables' 'Laptops'),
                    (TN 'VDI' 'VDI' -Proposed),
                    (TN 'Kiosques' 'Kiosks' -Proposed)
                )),
                (TN 'Utilisateurs' 'Users' -Proposed -Children @(
                    (TN 'Standard' 'Standard' -Proposed),
                    (TN 'VIP' 'VIP' -Proposed),
                    (TN 'Externes' 'External' -Proposed)
                )),
                (TN 'Imprimantes' 'Printers' -Proposed),
                (TN 'Services' 'Services'),
                (TN 'SuperUtilisateurs' 'SuperUsers')
            )
        }
    }
}

# ----------------------------------------------------------------------------
# Fonctions utilitaires
# ----------------------------------------------------------------------------
function Initialize-LogFile {
    try {
        if (-not (Test-Path -LiteralPath $script:LogFolder)) { [void](New-Item -ItemType Directory -Path $script:LogFolder -Force -ErrorAction Stop) }
        $script:LogFile = Join-Path $script:LogFolder ('TierModel_{0}.log' -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
    }
    catch { $script:LogFile = $null }
}
Initialize-LogFile

function Write-Log {
    param([string]$Message)
    $ts = Get-Date -Format 'HH:mm:ss'
    # Le message va dans le journal de l'onglet actif (et dans le fichier journal)
    $box = $script:txtLog
    if ($script:tab2 -and $script:tabs.SelectedTab -eq $script:tab2) { $box = $script:txtLog2 }
    elseif ($script:tab3 -and $script:tabs.SelectedTab -eq $script:tab3) { $box = $script:txtLog3 }
    $box.AppendText("[$ts] $Message`r`n")
    if ($script:LogFile) {
        try { Add-Content -LiteralPath $script:LogFile -Value ('[{0}] {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message) -Encoding UTF8 -ErrorAction Stop }
        catch { $script:LogFile = $null }
    }
    [System.Windows.Forms.Application]::DoEvents()
}

function Show-Message {
    param([string]$Text, [string]$Title = 'Tier Model', [string]$Icon = 'Information')
    [void][System.Windows.Forms.MessageBox]::Show($Text, $Title, 'OK', $Icon)
}

function Test-OUName {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return 'nom vide' }
    if ($Name -match $script:InvalidChars)   { return 'caractères interdits ( , = + < > # ; " \ / )' }
    if ($Name -ne $Name.Trim())              { return 'espace en début ou fin de nom' }
    if ($Name.Length -gt 64)                 { return 'plus de 64 caractères' }
    return $null
}

function New-TvNode {
    param([string]$Text, [bool]$Proposed = $false)
    $n = New-Object System.Windows.Forms.TreeNode($Text)
    $n.Checked = $true
    if ($Proposed) {
        $n.ForeColor = [System.Drawing.Color]::RoyalBlue
        $n.Tag = 'proposed'
    } else {
        $n.Tag = 'base'
    }
    $n
}

function Add-TplNodes {
    param($ParentNode, [object[]]$Templates, [string]$Prefix, [string]$Lang, [string]$ExtraPrefix, [bool]$IncludeProposed, [string]$Sep)
    foreach ($t in $Templates) {
        if ($t.Proposed -and -not $IncludeProposed) { continue }
        $node = New-TvNode -Text ($Prefix + $ExtraPrefix + $t.$Lang) -Proposed $t.Proposed
        [void]$ParentNode.Nodes.Add($node)
        $cp = ''
        if ($t.ChildPrefix) { $cp = $t.ChildPrefix + $Sep }
        if ($t.Children.Count -gt 0) {
            Add-TplNodes -ParentNode $node -Templates $t.Children -Prefix $Prefix -Lang $Lang `
                -ExtraPrefix $cp -IncludeProposed $IncludeProposed -Sep $Sep
        }
    }
}

function Get-CheckedCount {
    param($Nodes)
    $c = 0
    foreach ($n in $Nodes) {
        if ($n.Checked) { $c++; $c += Get-CheckedCount $n.Nodes }
    }
    $c
}

function Set-ChildrenChecked {
    param($Node, [bool]$State)
    foreach ($c in $Node.Nodes) {
        $c.Checked = $State
        Set-ChildrenChecked $c $State
    }
}

function Update-Count {
    $n = Get-CheckedCount $script:tv.Nodes
    $script:lblCount.Text = "$n OU sélectionnée(s)"
}

function Update-CustomBanner {
    $script:lblCustom.Visible = $script:Customized
}

function Confirm-Reset {
    if (-not $script:Customized) { return $true }
    $a = [System.Windows.Forms.MessageBox]::Show(
        "Le plan contient des modifications manuelles (renommages, ajouts, retraits).`nLes régénérer les perdra. Continuer ?",
        'Réinitialiser le plan', 'YesNo', 'Warning')
    return ($a -eq [System.Windows.Forms.DialogResult]::Yes)
}

function Get-TotalCount {
    param($Nodes)
    $c = 0
    foreach ($n in $Nodes) { $c++; $c += Get-TotalCount $n.Nodes }
    $c
}

function Test-SiblingName {
    param($Siblings, [string]$Name, $Except = $null)
    foreach ($s in $Siblings) {
        if ($null -ne $Except -and [object]::ReferenceEquals($s, $Except)) { continue }
        if ($s.Text -ieq $Name) { return $true }
    }
    return $false
}

function Read-TextDialog {
    param([string]$Title, [string]$Prompt, [string]$Default = '')
    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text = $Title
    $dlg.Font = $script:form.Font
    $dlg.FormBorderStyle = 'FixedDialog'
    $dlg.StartPosition = 'CenterParent'
    $dlg.MinimizeBox = $false
    $dlg.MaximizeBox = $false
    $dlg.ClientSize = New-Object System.Drawing.Size(430, 135)

    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Text = $Prompt
    $lbl.Location = New-Object System.Drawing.Point(12, 10)
    $lbl.Size = New-Object System.Drawing.Size(405, 45)
    $dlg.Controls.Add($lbl)

    $txt = New-Object System.Windows.Forms.TextBox
    $txt.Text = $Default
    $txt.Location = New-Object System.Drawing.Point(12, 62)
    $txt.Size = New-Object System.Drawing.Size(405, 23)
    $dlg.Controls.Add($txt)

    $ok = New-Object System.Windows.Forms.Button
    $ok.Text = 'OK'
    $ok.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $ok.Location = New-Object System.Drawing.Point(247, 98)
    $ok.Size = New-Object System.Drawing.Size(80, 28)
    $dlg.Controls.Add($ok)

    $cancel = New-Object System.Windows.Forms.Button
    $cancel.Text = 'Annuler'
    $cancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $cancel.Location = New-Object System.Drawing.Point(337, 98)
    $cancel.Size = New-Object System.Drawing.Size(80, 28)
    $dlg.Controls.Add($cancel)

    $dlg.AcceptButton = $ok
    $dlg.CancelButton = $cancel
    $result = $null
    if ($dlg.ShowDialog($script:form) -eq [System.Windows.Forms.DialogResult]::OK) { $result = $txt.Text.Trim() }
    $dlg.Dispose()
    return $result
}

function Add-CustomNode {
    param([bool]$AsChild)
    $sel = $script:tv.SelectedNode
    if ($AsChild -and -not $sel) {
        Show-Message "Sélectionnez d'abord l'OU parente dans l'arbre." 'Ajouter une OU' 'Information'
        return
    }
    if ($AsChild) {
        $siblings = $sel.Nodes
        $where = "sous '$($sel.Text)'"
    } elseif ($sel -and $sel.Parent) {
        $siblings = $sel.Parent.Nodes
        $where = "sous '$($sel.Parent.Text)' (même niveau que '$($sel.Text)')"
    } else {
        $siblings = $script:tv.Nodes
        $where = 'à la racine du domaine'
    }

    $name = Read-TextDialog 'Ajouter une OU' "Nom de la nouvelle OU, ajoutée $where :" ''
    if ($null -eq $name) { return }
    $err = Test-OUName $name
    if (-not $err -and (Test-SiblingName -Siblings $siblings -Name $name)) { $err = 'une OU de ce nom existe déjà à cet emplacement' }
    if ($err) { Show-Message "Nom d'OU invalide : $err" 'Ajouter une OU' 'Warning'; return }

    $script:Updating = $true
    try {
        $n = New-TvNode $name
        $n.ForeColor = [System.Drawing.Color]::SeaGreen
        $n.Tag = 'custom'
        [void]$siblings.Add($n)
        $p = $n.Parent
        while ($p) { $p.Checked = $true; $p = $p.Parent }
    }
    finally { $script:Updating = $false }
    if ($AsChild) { $sel.Expand() }
    $script:tv.SelectedNode = $n
    $n.EnsureVisible()
    $script:Customized = $true
    Update-CustomBanner
    Update-Count
}

function Start-Rename {
    $sel = $script:tv.SelectedNode
    if (-not $sel) { Show-Message "Sélectionnez d'abord une OU dans l'arbre." 'Renommer' 'Information'; return }
    $sel.BeginEdit()
}

function Remove-SelectedNode {
    $sel = $script:tv.SelectedNode
    if (-not $sel) { Show-Message "Sélectionnez d'abord une OU dans l'arbre." 'Retirer' 'Information'; return }
    $n = 1 + (Get-TotalCount $sel.Nodes)
    $a = [System.Windows.Forms.MessageBox]::Show(
        "Retirer '$($sel.Text)' et ses sous-OU ($n élément(s) au total) du plan ?`n`nAucune OU existante dans Active Directory n'est supprimée.",
        'Retirer du plan', 'YesNo', 'Question')
    if ($a -ne [System.Windows.Forms.DialogResult]::Yes) { return }
    $sel.Remove()
    $script:Customized = $true
    Update-CustomBanner
    Update-Count
}

function Update-Preview {
    param([switch]$Force)
    if ($script:ApplyingPreset) { return }
    if ($Force) { $script:Customized = $false }
    Update-CustomBanner
    if ($script:Customized) { return }   # plan modifié à la main : on ne l'écrase pas automatiquement
    $script:Updating = $true
    $tv = $script:tv
    $tv.BeginUpdate()
    try {
        $tv.Nodes.Clear()
        $lang = 'FR'
        if ($script:cmbLang.SelectedIndex -eq 1) { $lang = 'EN' }
        $sep  = $script:txtSep.Text
        $inc  = $script:chkProposed.Checked

        # --- OU racine d'administration ---
        $adm = New-TvNode $script:txtAdminRoot.Text
        [void]$tv.Nodes.Add($adm)

        foreach ($tier in 0, 1, 2) {
            $tn = New-TvNode ($script:txtAdminTier.Text -replace '\{N\}', $tier)
            [void]$adm.Nodes.Add($tn)
            $prefix = ($script:txtPrefix.Text -replace '\{N\}', $tier) + $sep
            Add-TplNodes -ParentNode $tn -Templates (Get-AdminChildren $tier) -Prefix $prefix -Lang $lang `
                -ExtraPrefix '' -IncludeProposed $inc -Sep $sep
        }

        # Legacy
        $ln = New-TvNode $script:txtAdminLegacy.Text
        [void]$adm.Nodes.Add($ln)
        $lprefix = $script:txtLegacyPrefix.Text + $sep
        Add-TplNodes -ParentNode $ln -Templates (Get-AdminChildren -1) -Prefix $lprefix -Lang $lang `
            -ExtraPrefix '' -IncludeProposed $inc -Sep $sep

        # Groupes organisationnels transverses (proposé)
        if ($inc) {
            $orgName = 'Adm' + $sep + 'GroupesOrg'
            if ($lang -eq 'EN') { $orgName = 'Adm' + $sep + 'OrgGroups' }
            [void]$adm.Nodes.Add((New-TvNode $orgName $true))
        }

        # --- OU racines de Tier ---
        foreach ($tier in 0, 1, 2) {
            $root = New-TvNode ($script:txtTierRoot.Text -replace '\{N\}', $tier)
            [void]$tv.Nodes.Add($root)
            $prefix = ($script:txtPrefix.Text -replace '\{N\}', $tier) + $sep
            Add-TplNodes -ParentNode $root -Templates (Get-TierChildren $tier) -Prefix $prefix -Lang $lang `
                -ExtraPrefix '' -IncludeProposed $inc -Sep $sep
        }

        $tv.ExpandAll()
        if ($tv.Nodes.Count -gt 0) { $tv.Nodes[0].EnsureVisible() }
    }
    finally {
        $tv.EndUpdate()
        $script:Updating = $false
    }
    Update-Count
}

function Set-Preset {
    param([int]$Index)
    $p = $script:Presets[$Index]
    $script:ApplyingPreset = $true
    try {
        $script:txtAdminRoot.Text    = $p.AdminRoot
        $script:txtAdminTier.Text    = $p.AdminTier
        $script:txtAdminLegacy.Text  = $p.AdminLegacy
        $script:txtTierRoot.Text     = $p.TierRoot
        $script:txtPrefix.Text       = $p.Prefix
        $script:txtLegacyPrefix.Text = $p.LegacyPrefix
        $script:txtSep.Text          = $p.Sep
        $script:cmbLang.SelectedIndex = $p.Lang
    }
    finally { $script:ApplyingPreset = $false }
    Update-Preview -Force
}

function Invoke-FieldChanged {
    if ($script:ApplyingPreset) { return }
    $script:ApplyingPreset = $true
    $script:cmbPreset.SelectedIndex = 3   # Personnalisée
    $script:ApplyingPreset = $false
    Update-Preview
}

function Find-Domain {
    if (-not $script:AdAvailable) { return }
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $p = @{}
        if ($script:txtServer.Text.Trim()) { $p.Server = $script:txtServer.Text.Trim() }
        $d = Get-ADDomain @p -ErrorAction Stop
        $script:txtDomain.Text = $d.DistinguishedName
        Write-Log "Domaine détecté : $($d.DNSRoot) ($($d.DistinguishedName))"
    }
    catch {
        Write-Log "Détection du domaine impossible : $($_.Exception.Message)"
    }
}

# ----------------------------------------------------------------------------
# Validation + création
# ----------------------------------------------------------------------------
function Test-Nodes {
    param($Nodes, $Errors, [string]$Path)
    $seen = @{}
    foreach ($n in $Nodes) {
        if (-not $n.Checked) { continue }
        $e = Test-OUName $n.Text
        if ($e) { $Errors.Add("'$($n.Text)' sous $Path : $e") }
        $k = $n.Text.ToLowerInvariant()
        if ($seen.ContainsKey($k)) { $Errors.Add("Doublon '$($n.Text)' sous $Path") } else { $seen[$k] = $true }
        Test-Nodes -Nodes $n.Nodes -Errors $Errors -Path ($Path + '/' + $n.Text)
    }
}

function Ensure-OU {
    param([string]$Name, [string]$ParentDN, [bool]$ParentExists, [bool]$WhatIfMode, [bool]$Protect)
    $dn = "OU=$Name,$ParentDN"
    $p  = $script:AdParams
    try {
        $exists = $false
        if ($ParentExists) {
            $safe  = $Name.Replace("'", "''")
            $found = Get-ADOrganizationalUnit -Filter "Name -eq '$safe'" -SearchBase $ParentDN -SearchScope OneLevel @p -ErrorAction Stop
            $exists = [bool]$found
        }
        if ($exists) {
            $script:Stats.Existing++
            Write-Log "[Existe]       $dn"
            return @{ DN = $dn; Exists = $true }
        }
        if ($WhatIfMode) {
            $script:Stats.Simulated++
            Write-Log "[Simulation]   Créerait $dn"
            return @{ DN = $dn; Exists = $false }
        }
        New-ADOrganizationalUnit -Name $Name -Path $ParentDN -Description "Tier Model - $Name" `
            -ProtectedFromAccidentalDeletion $Protect @p -ErrorAction Stop
        $script:Stats.Created++
        Write-Log "[Créée]        $dn"
        return @{ DN = $dn; Exists = $true }
    }
    catch {
        $script:Stats.Errors++
        Write-Log "[ERREUR]       $dn : $($_.Exception.Message)"
        return $null
    }
}

function Build-Node {
    param($Node, [string]$ParentDN, [bool]$ParentExists, [bool]$WhatIfMode, [bool]$Protect)
    if (-not $Node.Checked) { return }
    $r = Ensure-OU -Name $Node.Text -ParentDN $ParentDN -ParentExists $ParentExists -WhatIfMode $WhatIfMode -Protect $Protect
    if ($null -eq $r) { return }   # erreur : on n'essaie pas les enfants
    foreach ($c in $Node.Nodes) {
        Build-Node -Node $c -ParentDN $r.DN -ParentExists $r.Exists -WhatIfMode $WhatIfMode -Protect $Protect
    }
}

function Invoke-Creation {
    $domainDN = $script:txtDomain.Text.Trim()
    if ($domainDN -notmatch '^DC=[^,=]+(,DC=[^,=]+)*$') {
        Show-Message "Le DN du domaine est invalide.`nExemple : DC=domaine,DC=dom" 'Domaine' 'Warning'
        return
    }

    $errs = New-Object 'System.Collections.Generic.List[string]'
    Test-Nodes -Nodes $script:tv.Nodes -Errors $errs -Path $domainDN
    if ((Get-CheckedCount $script:tv.Nodes) -eq 0) { $errs.Add('Aucune OU sélectionnée.') }
    if ($errs.Count -gt 0) {
        Show-Message ("Corrigez les points suivants avant de continuer :`n`n" + ($errs -join "`n")) 'Validation' 'Warning'
        return
    }

    $whatIfMode = $script:chkWhatIf.Checked
    $protect    = $script:chkProtect.Checked
    $count      = Get-CheckedCount $script:tv.Nodes
    $mode       = 'CRÉATION RÉELLE'
    if ($whatIfMode) { $mode = 'SIMULATION (aucune modification)' }

    $ans = [System.Windows.Forms.MessageBox]::Show(
        "Mode : $mode`nDomaine : $domainDN`nOU sélectionnées : $count`n`nContinuer ?",
        'Confirmation', 'YesNo', 'Question')
    if ($ans -ne [System.Windows.Forms.DialogResult]::Yes) { return }

    $script:AdParams = @{}
    if ($script:txtServer.Text.Trim()) { $script:AdParams.Server = $script:txtServer.Text.Trim() }
    $script:Stats = @{ Created = 0; Existing = 0; Simulated = 0; Errors = 0 }

    $script:btnCreate.Enabled = $false
    $script:form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        Write-Log "=== Début ($mode) - $domainDN ==="
        foreach ($n in $script:tv.Nodes) {
            Build-Node -Node $n -ParentDN $domainDN -ParentExists $true -WhatIfMode $whatIfMode -Protect $protect
        }
        $s = $script:Stats
        Write-Log "=== Fin : $($s.Created) créée(s), $($s.Existing) existante(s), $($s.Simulated) simulée(s), $($s.Errors) erreur(s) ==="
    }
    catch {
        Write-Log "[ERREUR] $($_.Exception.Message)"
    }
    finally {
        $script:form.Cursor = [System.Windows.Forms.Cursors]::Default
        $script:btnCreate.Enabled = $script:AdAvailable
    }
}

# ----------------------------------------------------------------------------
# Helpers de construction d'interface
# ----------------------------------------------------------------------------
function New-Group {
    param($Parent, [string]$Text, [int]$X, [int]$Y, [int]$W, [int]$H)
    $g = New-Object System.Windows.Forms.GroupBox
    $g.Text = $Text
    $g.Location = New-Object System.Drawing.Point($X, $Y)
    $g.Size = New-Object System.Drawing.Size($W, $H)
    $Parent.Controls.Add($g)
    $g
}

function New-Lbl {
    param($Parent, [string]$Text, [int]$X, [int]$Y, [int]$W = 170)
    $l = New-Object System.Windows.Forms.Label
    $l.Text = $Text
    $l.Location = New-Object System.Drawing.Point($X, ($Y + 3))
    $l.Size = New-Object System.Drawing.Size($W, 20)
    $Parent.Controls.Add($l)
    $l
}

function New-Txt {
    param($Parent, [int]$X, [int]$Y, [int]$W, [string]$Text = '')
    $t = New-Object System.Windows.Forms.TextBox
    $t.Text = $Text
    $t.Location = New-Object System.Drawing.Point($X, $Y)
    $t.Size = New-Object System.Drawing.Size($W, 23)
    $Parent.Controls.Add($t)
    $t
}

function New-Combo {
    param($Parent, [int]$X, [int]$Y, [int]$W, [string[]]$Items)
    $c = New-Object System.Windows.Forms.ComboBox
    $c.DropDownStyle = 'DropDownList'
    $c.Location = New-Object System.Drawing.Point($X, $Y)
    $c.Size = New-Object System.Drawing.Size($W, 23)
    [void]$c.Items.AddRange([object[]]$Items)
    $Parent.Controls.Add($c)
    $c
}

# ----------------------------------------------------------------------------
# Interface
# ----------------------------------------------------------------------------
$script:form = New-Object System.Windows.Forms.Form
$form = $script:form
$form.Text = "Tier Model Active Directory - Assistant de déploiement - v$($script:ScriptVersion) - EZES Jean-Michel (avec l'IA Claude)"
# Taille adaptée à l'écran (évite que le bas de la fenêtre dépasse de l'écran)
$wa = [System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea
$form.ClientSize = New-Object System.Drawing.Size([Math]::Min(1060, $wa.Width - 20), [Math]::Min(790, $wa.Height - 60))
$form.MinimumSize = New-Object System.Drawing.Size(700, 480)
$form.StartPosition = 'CenterScreen'
$form.Font = New-Object System.Drawing.Font('Segoe UI', 9)

$tabs = New-Object System.Windows.Forms.TabControl
$tabs.Dock = 'Fill'
$form.Controls.Add($tabs)

# ===== Onglet 1 : Création Structure (d'autres onglets pourront être ajoutés à $tabs) =====
$tab1 = New-Object System.Windows.Forms.TabPage
$tab1.Text = 'Création Structure'
$tab1.UseVisualStyleBackColor = $true
[void]$tabs.TabPages.Add($tab1)
# Si la fenêtre est plus petite que la mise en page, l'onglet défile
$tab1.AutoScroll = $true
$tab1.AutoScrollMinSize = New-Object System.Drawing.Size(1050, 745)

# --- Convention de nommage ---
$g1 = New-Group $tab1 'Convention de nommage des OU' 10 10 400 350
[void](New-Lbl $g1 'Modèle prédéfini' 10 22 200)
$script:cmbPreset = New-Combo $g1 10 46 380 @(
    'Base proposée - FR (Admin-TM, Adm-T0, T0-Administrateurs...)',
    'Variante EN (Admin-TM, Adm-T0, T0-Administrators...)',
    'Variante FR avec underscores (Admin_TM, T0_Administrateurs...)',
    'Personnalisée')

$y = 84
[void](New-Lbl $g1 'OU racine administration' 10 $y);          $script:txtAdminRoot    = New-Txt $g1 190 $y 200; $y += 28
[void](New-Lbl $g1 'OU admin par Tier ({N})' 10 $y);           $script:txtAdminTier    = New-Txt $g1 190 $y 200; $y += 28
[void](New-Lbl $g1 'OU admin Legacy' 10 $y);                   $script:txtAdminLegacy  = New-Txt $g1 190 $y 200; $y += 28
[void](New-Lbl $g1 'OU racine par Tier ({N})' 10 $y);          $script:txtTierRoot     = New-Txt $g1 190 $y 200; $y += 28
[void](New-Lbl $g1 'Préfixe des OU enfants ({N})' 10 $y);      $script:txtPrefix       = New-Txt $g1 190 $y 200; $y += 28
[void](New-Lbl $g1 'Préfixe Legacy' 10 $y);                    $script:txtLegacyPrefix = New-Txt $g1 190 $y 200; $y += 28
[void](New-Lbl $g1 'Séparateur' 10 $y);                        $script:txtSep          = New-Txt $g1 190 $y 50;  $y += 28
[void](New-Lbl $g1 'Langue des noms' 10 $y);                   $script:cmbLang         = New-Combo $g1 190 $y 200 @('Français', 'English'); $y += 32

$script:chkProposed = New-Object System.Windows.Forms.CheckBox
$script:chkProposed.Text = 'Inclure les OU proposées (affichées en bleu)'
$script:chkProposed.Checked = $true
$script:chkProposed.Location = New-Object System.Drawing.Point(10, $y)
$script:chkProposed.Size = New-Object System.Drawing.Size(380, 22)
$g1.Controls.Add($script:chkProposed)

# --- Domaine ---
$g2 = New-Group $tab1 'Domaine cible' 10 365 400 100
[void](New-Lbl $g2 'DN du domaine' 10 22 100)
$script:txtDomain = New-Txt $g2 115 22 195 $DomainDN
[void](New-Lbl $g2 'Contrôleur (option.)' 10 54 105)
$script:txtServer = New-Txt $g2 115 54 195 $Server
$btnDetect = New-Object System.Windows.Forms.Button
$btnDetect.Text = 'Détecter'
$btnDetect.Location = New-Object System.Drawing.Point(318, 21)
$btnDetect.Size = New-Object System.Drawing.Size(72, 26)
$g2.Controls.Add($btnDetect)

# --- Options ---
$g3 = New-Group $tab1 'Options de création' 10 470 400 78
$script:chkProtect = New-Object System.Windows.Forms.CheckBox
$script:chkProtect.Text = 'Protéger contre la suppression accidentelle'
$script:chkProtect.Checked = $true
$script:chkProtect.Location = New-Object System.Drawing.Point(10, 22)
$script:chkProtect.Size = New-Object System.Drawing.Size(380, 22)
$g3.Controls.Add($script:chkProtect)
$script:chkWhatIf = New-Object System.Windows.Forms.CheckBox
$script:chkWhatIf.Text = 'Mode simulation (aucune OU créée)'
$script:chkWhatIf.Checked = $true
$script:chkWhatIf.Location = New-Object System.Drawing.Point(10, 47)
$script:chkWhatIf.Size = New-Object System.Drawing.Size(380, 22)
$g3.Controls.Add($script:chkWhatIf)

# --- Boutons ---
$btnRefresh = New-Object System.Windows.Forms.Button
$btnRefresh.Text = "Réinitialiser l'aperçu"
$btnRefresh.Location = New-Object System.Drawing.Point(10, 556)
$btnRefresh.Size = New-Object System.Drawing.Size(190, 34)
$tab1.Controls.Add($btnRefresh)

$script:btnCreate = New-Object System.Windows.Forms.Button
$script:btnCreate.Text = 'Créer la structure'
$script:btnCreate.Location = New-Object System.Drawing.Point(210, 556)
$script:btnCreate.Size = New-Object System.Drawing.Size(200, 34)
$script:btnCreate.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
$script:btnCreate.Enabled = $script:AdAvailable
$tab1.Controls.Add($script:btnCreate)

# --- Aperçu ---
$g4 = New-Group $tab1 'Aperçu de la structure' 420 10 620 585
$g4.Anchor = [System.Windows.Forms.AnchorStyles]'Top,Bottom,Left,Right'
$script:tv = New-Object System.Windows.Forms.TreeView
$script:tv.CheckBoxes = $true
$script:tv.LabelEdit = $true
$script:tv.HideSelection = $false
$script:tv.Scrollable = $true
$script:tv.Location = New-Object System.Drawing.Point(10, 86)
$script:tv.Size = New-Object System.Drawing.Size(600, 450)
$script:tv.Anchor = [System.Windows.Forms.AnchorStyles]'Top,Bottom,Left,Right'
$g4.Controls.Add($script:tv)

$lblHint = New-Object System.Windows.Forms.Label
$lblHint.Text = 'Cocher = créer | F2 = renommer | Inser = sous-OU | Suppr = retirer | Bleu = proposée | Vert = ajoutée'
$lblHint.Location = New-Object System.Drawing.Point(10, 540)
$lblHint.Size = New-Object System.Drawing.Size(600, 18)
$lblHint.Anchor = [System.Windows.Forms.AnchorStyles]'Bottom,Left'
$g4.Controls.Add($lblHint)

$script:lblCount = New-Object System.Windows.Forms.Label
$script:lblCount.Location = New-Object System.Drawing.Point(10, 561)
$script:lblCount.Size = New-Object System.Drawing.Size(170, 18)
$script:lblCount.Anchor = [System.Windows.Forms.AnchorStyles]'Bottom,Left'
$g4.Controls.Add($script:lblCount)

$script:lblCustom = New-Object System.Windows.Forms.Label
$script:lblCustom.Text = "Plan modifié à la main - 'Réinitialiser l'aperçu' pour régénérer"
$script:lblCustom.ForeColor = [System.Drawing.Color]::DarkOrange
$script:lblCustom.Location = New-Object System.Drawing.Point(180, 561)
$script:lblCustom.Size = New-Object System.Drawing.Size(430, 18)
$script:lblCustom.Anchor = [System.Windows.Forms.AnchorStyles]'Bottom,Left'
$script:lblCustom.Visible = $false
$g4.Controls.Add($script:lblCustom)

# --- Barre d'outils d'édition du plan ---
function New-ToolBtn {
    param($Parent, [string]$Text, [int]$X, [int]$W, [int]$Y = 21)
    $b = New-Object System.Windows.Forms.Button
    $b.Text = $Text
    $b.Location = New-Object System.Drawing.Point($X, $Y)
    $b.Size = New-Object System.Drawing.Size($W, 28)
    $Parent.Controls.Add($b)
    $b
}
$script:btnRename   = New-ToolBtn $g4 'Renommer'       10  80
$script:btnAddChild = New-ToolBtn $g4 '+ Sous-OU'      95  85
$script:btnAddSib   = New-ToolBtn $g4 '+ Même niveau'  185 105
$script:btnRemove   = New-ToolBtn $g4 'Retirer'        295 70
$script:btnExpand   = New-ToolBtn $g4 'Développer'     10  90  52
$script:btnCollapse = New-ToolBtn $g4 'Réduire'        105 80  52
$script:btnCheckAll = New-ToolBtn $g4 'Tout cocher'    200 95  52
$script:btnUncheckAll = New-ToolBtn $g4 'Tout décocher' 300 105 52
$script:btnSort     = New-ToolBtn $g4 "Rafraîchir l'aperçu" 410 150 52

# Menu contextuel (clic droit) sur l'arbre
$script:ctx = New-Object System.Windows.Forms.ContextMenuStrip
$script:miRename   = $script:ctx.Items.Add('Renommer (F2)')
$script:miAddChild = $script:ctx.Items.Add('Ajouter une sous-OU (Inser)')
$script:miAddSib   = $script:ctx.Items.Add('Ajouter une OU au même niveau')
$script:miRemove   = $script:ctx.Items.Add('Retirer du plan (Suppr)')
$script:tv.ContextMenuStrip = $script:ctx

# --- Journal ---
$g5 = New-Group $tab1 'Journal' 10 600 1030 140
$g5.Anchor = [System.Windows.Forms.AnchorStyles]'Bottom,Left,Right'
$script:txtLog = New-Object System.Windows.Forms.TextBox
$script:txtLog.Multiline = $true
$script:txtLog.ReadOnly = $true
$script:txtLog.ScrollBars = 'Vertical'
$script:txtLog.Font = New-Object System.Drawing.Font('Consolas', 9)
$script:txtLog.Location = New-Object System.Drawing.Point(10, 20)
$script:txtLog.Size = New-Object System.Drawing.Size(1010, 110)
$script:txtLog.Anchor = [System.Windows.Forms.AnchorStyles]'Top,Bottom,Left,Right'
$g5.Controls.Add($script:txtLog)

# ----------------------------------------------------------------------------
# Événements
# ----------------------------------------------------------------------------
$script:cmbPreset.add_SelectedIndexChanged({
    if ($script:ApplyingPreset) { return }
    $i = $script:cmbPreset.SelectedIndex
    if ($i -lt 0 -or $i -ge $script:Presets.Count) { return }
    if (-not (Confirm-Reset)) {
        $script:ApplyingPreset = $true
        $script:cmbPreset.SelectedIndex = 3
        $script:ApplyingPreset = $false
        return
    }
    Set-Preset $i
})

foreach ($c in @($script:txtAdminRoot, $script:txtAdminTier, $script:txtAdminLegacy, $script:txtTierRoot,
                 $script:txtPrefix, $script:txtLegacyPrefix, $script:txtSep)) {
    $c.add_TextChanged({ Invoke-FieldChanged })
}
$script:cmbLang.add_SelectedIndexChanged({ Invoke-FieldChanged })
$script:chkProposed.add_CheckedChanged({ Update-Preview })

$script:tv.add_AfterCheck({
    param($sender, $e)
    if ($script:Updating) { return }
    $script:Updating = $true
    try {
        Set-ChildrenChecked $e.Node $e.Node.Checked
        if ($e.Node.Checked) {
            $p = $e.Node.Parent
            while ($p) { $p.Checked = $true; $p = $p.Parent }
        }
    }
    finally { $script:Updating = $false }
    Update-Count
})

$script:tv.add_AfterLabelEdit({
    param($sender, $e)
    if ($null -eq $e.Label) { return }
    $err = Test-OUName $e.Label
    if (-not $err) {
        $sibs = $sender.Nodes
        if ($e.Node.Parent) { $sibs = $e.Node.Parent.Nodes }
        if (Test-SiblingName -Siblings $sibs -Name $e.Label -Except $e.Node) {
            $err = 'une OU de ce nom existe déjà au même niveau'
        }
    }
    if ($err) {
        $e.CancelEdit = $true
        Show-Message "Nom d'OU invalide : $err" 'Renommage' 'Warning'
        return
    }
    $script:Customized = $true
    Update-CustomBanner
})

$script:tv.add_KeyDown({
    param($sender, $e)
    switch ($e.KeyCode) {
        'F2'     { Start-Rename }
        'Insert' { Add-CustomNode $true }
        'Delete' { Remove-SelectedNode }
    }
})

# Clic droit : sélectionne d'abord le nœud sous la souris
$script:tv.add_MouseDown({
    param($sender, $e)
    if ($e.Button -eq [System.Windows.Forms.MouseButtons]::Right) {
        $hit = $sender.GetNodeAt($e.X, $e.Y)
        if ($hit) { $sender.SelectedNode = $hit }
    }
})

# Boutons / menu contextuel d'édition du plan
$script:btnRename.add_Click({ Start-Rename })
$script:btnAddChild.add_Click({ Add-CustomNode $true })
$script:btnAddSib.add_Click({ Add-CustomNode $false })
$script:btnRemove.add_Click({ Remove-SelectedNode })
function Set-AllChecked {
    param([bool]$State)
    $script:Updating = $true
    try {
        foreach ($n in $script:tv.Nodes) {
            $n.Checked = $State
            Set-ChildrenChecked $n $State
        }
    }
    finally { $script:Updating = $false }
    Update-Count
}
function Sort-TreeNodes {
    # Trie alphabétiquement chaque niveau en conservant les nœuds (cases, couleurs, ajouts, renommages, état déplié).
    param($Collection)
    if ($Collection.Count -eq 0) { return }
    $items = @(foreach ($n in $Collection) { [pscustomobject]@{ Node = $n; Exp = $n.IsExpanded; Text = $n.Text } })
    $sorted = @($items | Sort-Object Text)
    $Collection.Clear()
    foreach ($i in $sorted) {
        [void]$Collection.Add($i.Node)
        Sort-TreeNodes $i.Node.Nodes
        if ($i.Exp) { $i.Node.Expand() }
    }
}

function Invoke-RefreshPreview {
    $sel = $script:tv.SelectedNode
    $script:Updating = $true
    $script:tv.BeginUpdate()
    try { Sort-TreeNodes $script:tv.Nodes }
    finally {
        $script:tv.EndUpdate()
        $script:Updating = $false
    }
    if ($sel) { $script:tv.SelectedNode = $sel; $sel.EnsureVisible() }
    Update-Count
}

$script:btnSort.add_Click({ Invoke-RefreshPreview })

# Info-bulles pour lever toute ambiguïté
$script:tip = New-Object System.Windows.Forms.ToolTip
$script:tip.SetToolTip($script:btnSort, "Remet l'aperçu en ordre (tri alphabétique à chaque niveau).`nConserve vos cases, renommages et ajouts.")
$script:tip.SetToolTip($btnRefresh, "Régénère tout le plan depuis la convention de nommage.`nATTENTION : efface vos renommages, ajouts, retraits et cases décochées.")

$script:btnCheckAll.add_Click({ Set-AllChecked $true })
$script:btnUncheckAll.add_Click({ Set-AllChecked $false })
$script:btnExpand.add_Click({ $script:tv.ExpandAll() })
$script:btnCollapse.add_Click({
    $script:tv.CollapseAll()
    foreach ($n in $script:tv.Nodes) { $n.Expand() }   # garde le 1er niveau visible
})
$script:miRename.add_Click({ Start-Rename })
$script:miAddChild.add_Click({ Add-CustomNode $true })
$script:miAddSib.add_Click({ Add-CustomNode $false })
$script:miRemove.add_Click({ Remove-SelectedNode })

$btnDetect.add_Click({ Find-Domain })
$btnRefresh.add_Click({
    if (-not (Confirm-Reset)) { return }
    $i = $script:cmbPreset.SelectedIndex
    if ($i -ge 0 -and $i -lt $script:Presets.Count) { Set-Preset $i } else { Update-Preview -Force }
})
$script:btnCreate.add_Click({ Invoke-Creation })

$form.add_Shown({
    if (-not $script:AdAvailable) {
        Write-Log "Module ActiveDirectory (RSAT) introuvable : l'aperçu reste utilisable, la création est désactivée."
        Write-Log "Installation : Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"
    } else {
        Find-Domain
    }
    if ($script:LogFile) { Write-Log "Journal : $($script:LogFile)" }
})

# ----------------------------------------------------------------------------
# Démarrage
# ----------------------------------------------------------------------------
# ============================================================================
# Onglet 2 : Création Groupes
# ============================================================================
$script:GroupsGenerated = $false
$script:ApplyingGPreset = $false
$script:GStats = @{ Created = 0; Existing = 0; Simulated = 0; Members = 0; Warnings = 0; Errors = 0 }

# Modèles de noms de groupes ({N} = n° de Tier, {Name} = suffixe du groupe)
$script:GroupPresets = @(
    @{ Dlg = 'DLG_GG_T{N}_{Name}'; Grp = 'GRP_GG_T{N}-{Name}' },
    @{ Dlg = 'DLG_GG_T{N}_{Name}'; Grp = 'GRP_GG_T{N}_{Name}' }
)

function GDef {
    param(
        [string]$Key, [string]$Kind, [string]$Suffix, [string]$Display, [string]$Usage,
        [int[]]$Tiers, [string[]]$MemberOf = @(), [switch]$Option
    )
    [pscustomobject]@{
        Key = $Key; Kind = $Kind; Suffix = $Suffix; Display = $Display; Usage = $Usage
        Tiers = $Tiers; MemberOf = $MemberOf; Option = [bool]$Option
    }
}

# Catalogue des groupes (Kind : DLG = délégation, GRP = opérationnel). {N} = n° de Tier.
function Get-GroupCatalog {
    @(
        (GDef 'AdminsAD'     'DLG' 'Admins_AD'     'Administrateur AD T{N}'          "Délégation : administration d'Active Directory (domaine, contrôleurs de domaine)" @(0)),
        (GDef 'Ordinateurs'  'DLG' 'Ordinateurs'   'Admins Ordinateurs T{N}'         "Délégation : gestion des objets ordinateurs du Tier {N}" @(0, 1, 2)),
        (GDef 'GPO'          'DLG' 'GPO'           'Admins GPO T{N}'                 "Délégation : gestion des GPO du Tier {N}" @(0, 1, 2)),
        (GDef 'Groupes'      'DLG' 'Groupes'       'Admins Groupes T{N}'             "Délégation : gestion des groupes du Tier {N}" @(0, 1, 2)),
        (GDef 'Serveurs'     'DLG' 'Serveurs'      'Admins de serveurs membres T{N}' "Délégation : gestion des serveurs membres du Tier {N}" @(0, 1)),
        (GDef 'Services'     'DLG' 'Services'      'Admins Services T{N}'            "Délégation : gestion des comptes de service du Tier {N}" @(0, 1, 2)),
        (GDef 'Utilisateurs' 'DLG' 'Utilisateurs'  'Admins Utilisateurs T{N}'        "Délégation : gestion des utilisateurs du Tier {N}" @(0, 1, 2)),
        (GDef 'Global'       'DLG' 'Global_Admins' 'Administrateurs T{N}'            "Groupe d'agrégation : ses membres héritent des délégations portées par les groupes spécialisés dans lesquels il est imbriqué" @(0, 1, 2) -MemberOf @('AdminsAD', 'Ordinateurs', 'GPO', 'Groupes', 'Serveurs', 'Services', 'Utilisateurs')),

        (GDef 'AdmSrv'   'GRP' 'AdmServeurs'             'Admins Serveurs T{N}'  "Membre du groupe local 'Administrateurs' de tous les serveurs T{N} (sauf contrôleurs de domaine)" @(0, 1)),
        (GDef 'AdmPostes' 'GRP' 'AdmPostes'              'Admins Postes T{N}'    "Membre du groupe local 'Administrateurs' des postes de travail T{N}" @(2)),
        (GDef 'PAW'      'GRP' 'Utilisateurs-PAW'        'Admins PAW/AJS T{N}'   "Membre du groupe local 'Administrateurs' des postes d'administration T{N}" @(0, 1, 2)),
        (GDef 'Entra'    'GRP' 'Services-AdmSrv-EntraID' 'Admins EntraID T{N}'   "Membre du groupe local 'Administrateurs' du serveur EntraID" @(0) -Option),
        (GDef 'PKI'      'GRP' 'Utilisateurs-PKI'        'Admins PKI T{N}'       "Membre du groupe local 'Administrateurs' du serveur PKI subordonnée" @(0) -Option),
        (GDef 'Backup'   'GRP' 'Utilisateurs-Backup'     'Admins Backup T{N}'    "Membre du groupe local 'Administrateurs' des serveurs de la solution de sauvegarde" @(0, 1) -Option),
        (GDef 'SCCM'     'GRP' 'Utilisateurs-SCCM'       'Admins SCCM T{N}'      "Membre du groupe local 'Administrateurs' des serveurs SCCM" @(0, 1, 2) -Option)
    )
}

function Get-GroupName {
    param([string]$Kind, [int]$Tier, [string]$Suffix)
    $pattern = $script:txtPatGrp.Text.Trim()
    if ($Kind -eq 'DLG') { $pattern = $script:txtPatDlg.Text.Trim() }
    ($pattern -replace '\{N\}', "$Tier") -replace '\{Name\}', $Suffix
}

# OU cible par défaut, calculée avec la convention de nommage de l'onglet 1
function Get-DefaultGroupOU {
    param([string]$Kind, [int]$Tier)
    $lang = 'FR'
    if ($script:cmbLang.SelectedIndex -eq 1) { $lang = 'EN' }
    $sep    = $script:txtSep.Text
    $prefix = ($script:txtPrefix.Text -replace '\{N\}', "$Tier") + $sep
    if ($Kind -eq 'DLG') {
        $c = @(Get-AdminChildren $Tier)
        $ouName = $prefix + $c[1].$lang          # GroupesAdmins
        return ('\' + $script:txtAdminRoot.Text + '\' + ($script:txtAdminTier.Text -replace '\{N\}', "$Tier") + '\' + $ouName)
    }
    $tc  = @(Get-TierChildren $Tier)
    $grp = $tc[0]                                 # Groupes
    $su  = @($grp.Children | Where-Object { $_.FR -eq 'SUtilisateurs' })[0]
    return ('\' + ($script:txtTierRoot.Text -replace '\{N\}', "$Tier") + '\' + $prefix + $grp.$lang + '\' + $prefix + $grp.ChildPrefix + $sep + $su.$lang)
}

function Get-PlanPaths {
    param($Nodes, $List)
    foreach ($n in $Nodes) {
        if (-not $n.Checked) { continue }
        $List.Add('\' + $n.FullPath)
        Get-PlanPaths $n.Nodes $List
    }
}

function ConvertTo-OuDn {
    param([string]$Path, [string]$DomainDN)
    $parts = @(($Path.Trim().Trim('\') -split '\\') | Where-Object { $_ })
    [array]::Reverse($parts)
    (($parts | ForEach-Object { "OU=$_" }) -join ',') + ',' + $DomainDN
}

function Select-FromList {
    param([string]$Title, [string]$Prompt, [string[]]$Items, [string]$Current = '')
    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text = $Title
    $dlg.Font = $script:form.Font
    $dlg.FormBorderStyle = 'FixedDialog'
    $dlg.StartPosition = 'CenterParent'
    $dlg.MinimizeBox = $false
    $dlg.MaximizeBox = $false
    $dlg.ClientSize = New-Object System.Drawing.Size(560, 400)

    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Text = $Prompt
    $lbl.Location = New-Object System.Drawing.Point(12, 10)
    $lbl.Size = New-Object System.Drawing.Size(535, 34)
    $dlg.Controls.Add($lbl)

    $lb = New-Object System.Windows.Forms.ListBox
    $lb.Location = New-Object System.Drawing.Point(12, 48)
    $lb.Size = New-Object System.Drawing.Size(535, 300)
    $lb.HorizontalScrollbar = $true
    if ($Items.Count -gt 0) { [void]$lb.Items.AddRange([object[]]$Items) }
    if ($Current -and $lb.Items.Contains($Current)) { $lb.SelectedItem = $Current }
    $lb.add_DoubleClick({
        param($s, $e)
        if ($s.SelectedItem) { $f = $s.FindForm(); $f.DialogResult = [System.Windows.Forms.DialogResult]::OK; $f.Close() }
    })
    $dlg.Controls.Add($lb)

    $ok = New-Object System.Windows.Forms.Button
    $ok.Text = 'OK'
    $ok.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $ok.Location = New-Object System.Drawing.Point(377, 360)
    $ok.Size = New-Object System.Drawing.Size(80, 28)
    $dlg.Controls.Add($ok)

    $cancel = New-Object System.Windows.Forms.Button
    $cancel.Text = 'Annuler'
    $cancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $cancel.Location = New-Object System.Drawing.Point(467, 360)
    $cancel.Size = New-Object System.Drawing.Size(80, 28)
    $dlg.Controls.Add($cancel)

    $dlg.AcceptButton = $ok
    $dlg.CancelButton = $cancel
    $result = $null
    if ($dlg.ShowDialog($script:form) -eq [System.Windows.Forms.DialogResult]::OK -and $lb.SelectedItem) {
        $result = [string]$lb.SelectedItem
    }
    $dlg.Dispose()
    return $result
}

function Update-GroupCount {
    $n = 0; $t = 0
    foreach ($r in $script:dg.Rows) {
        $t++
        if ([bool]$r.Cells[0].Value) { $n++ }
    }
    $script:lblGCount.Text = "$n groupe(s) sélectionné(s) sur $t"
}

function Add-GroupRow {
    param([bool]$Create, [string]$Kind, [string]$TierLabel, [string]$Display, [string]$Name,
          [string]$OU, [string]$MemberOf, [string]$Usage, [string]$Style = 'base')
    $idx = $script:dg.Rows.Add([object[]]@($Create, $Kind, $TierLabel, $Display, $Name, $OU, $MemberOf, $Usage))
    $row = $script:dg.Rows[$idx]
    if ($Style -eq 'option') { $row.DefaultCellStyle.ForeColor = [System.Drawing.Color]::RoyalBlue }
    elseif ($Style -eq 'custom') { $row.DefaultCellStyle.ForeColor = [System.Drawing.Color]::SeaGreen }
    return $idx
}

function Update-GroupCatalog {
    param([switch]$NoConfirm)
    $patD = $script:txtPatDlg.Text.Trim()
    $patG = $script:txtPatGrp.Text.Trim()
    foreach ($pat in $patD, $patG) {
        if ($pat -notmatch '\{Name\}') {
            Show-Message "Chaque modèle de nom doit contenir {Name} (et en principe {N}).`nExemple : DLG_GG_T{N}_{Name}" 'Convention de nommage' 'Warning'
            return
        }
    }
    $tiers = @()
    if ($script:chkT0.Checked) { $tiers += 0 }
    if ($script:chkT1.Checked) { $tiers += 1 }
    if ($script:chkT2.Checked) { $tiers += 2 }
    if ($tiers.Count -eq 0) {
        Show-Message 'Cochez au moins un Tier.' 'Tiers à traiter' 'Information'
        return
    }
    if (-not $NoConfirm -and $script:dg.Rows.Count -gt 0) {
        $a = [System.Windows.Forms.MessageBox]::Show(
            "Le catalogue va être régénéré : vos modifications dans le tableau (noms, OU, ajouts, cases) seront perdues.`nContinuer ?",
            'Générer le catalogue', 'YesNo', 'Warning')
        if ($a -ne [System.Windows.Forms.DialogResult]::Yes) { return }
    }

    $catalog = @(Get-GroupCatalog)
    $script:dg.Rows.Clear()
    foreach ($t in $tiers) {
        $entries = @($catalog | Where-Object { $_.Tiers -contains $t })
        $names = @{}
        foreach ($e in $entries) { $names[$e.Key] = Get-GroupName $e.Kind $t $e.Suffix }
        foreach ($e in $entries) {
            $kindLabel = 'Délégation'
            if ($e.Kind -eq 'GRP') { $kindLabel = 'Opérationnel' }
            $style = 'base'
            $usage = $e.Usage -replace '\{N\}', "$t"
            if ($e.Option) {
                $style = 'option'
                $kindLabel += ' (option)'
                $usage = '[Option] ' + $usage
            }
            $member = (@($e.MemberOf | Where-Object { $names.ContainsKey($_) } | ForEach-Object { $names[$_] }) -join ';')
            [void](Add-GroupRow -Create (-not $e.Option) -Kind $kindLabel -TierLabel "T$t" `
                -Display ($e.Display -replace '\{N\}', "$t") -Name $names[$e.Key] `
                -OU (Get-DefaultGroupOU $e.Kind $t) -MemberOf $member -Usage $usage -Style $style)
        }
    }
    $script:GroupsGenerated = $true
    Update-GroupCount
}

function Set-GroupPreset {
    param([int]$Index)
    $p = $script:GroupPresets[$Index]
    $script:ApplyingGPreset = $true
    try {
        $script:txtPatDlg.Text = $p.Dlg
        $script:txtPatGrp.Text = $p.Grp
    }
    finally { $script:ApplyingGPreset = $false }
}

function Set-AllGroupsChecked {
    param([bool]$State)
    foreach ($r in $script:dg.Rows) { $r.Cells[0].Value = $State }
    Update-GroupCount
}

function Add-CustomGroupRow {
    $name = Read-TextDialog 'Ajouter un groupe' "Nom du groupe (sAMAccountName) :" ''
    if ($null -eq $name) { return }
    if ([string]::IsNullOrWhiteSpace($name)) { Show-Message 'Nom vide.' 'Ajouter un groupe' 'Warning'; return }
    $ou = ''
    $cur = $script:dg.CurrentRow
    if ($cur) { $ou = [string]$cur.Cells[5].Value }
    $idx = Add-GroupRow $true 'Personnalisé' '-' '' $name $ou '' '' 'custom'
    $script:dg.ClearSelection()
    $script:dg.Rows[$idx].Selected = $true
    $script:dg.CurrentCell = $script:dg.Rows[$idx].Cells[4]
    Update-GroupCount
}

function Remove-GroupRows {
    $rows = @($script:dg.SelectedRows)
    if ($rows.Count -eq 0) { Show-Message 'Sélectionnez une ou plusieurs lignes (clic sur la ligne).' 'Retirer' 'Information'; return }
    $a = [System.Windows.Forms.MessageBox]::Show("Retirer $($rows.Count) ligne(s) du tableau ?`n(Aucun groupe existant dans AD n'est supprimé.)", 'Retirer', 'YesNo', 'Question')
    if ($a -ne [System.Windows.Forms.DialogResult]::Yes) { return }
    foreach ($r in $rows) { $script:dg.Rows.Remove($r) }
    Update-GroupCount
}

function Set-SelectedGroupOU {
    $rows = @($script:dg.SelectedRows)
    if ($rows.Count -eq 0) { Show-Message 'Sélectionnez une ou plusieurs lignes (clic sur la ligne).' 'OU cible' 'Information'; return }
    $list = New-Object 'System.Collections.Generic.List[string]'
    Get-PlanPaths $script:tv.Nodes $list
    foreach ($r in $script:dg.Rows) {
        $v = [string]$r.Cells[5].Value
        if ($v) { $list.Add($v) }
    }
    $items = @($list | Sort-Object -Unique)
    $choice = Select-FromList 'OU cible' "Choisissez l'OU cible pour les $($rows.Count) ligne(s) sélectionnée(s) (plan de l'onglet 1 + OU déjà utilisées). Pour une autre OU, saisissez-la directement dans le tableau." $items ([string]$rows[0].Cells[5].Value)
    if ($choice) { foreach ($r in $rows) { $r.Cells[5].Value = $choice } }
}

# ---- Lecture / validation du plan de groupes ----
function Get-GroupPlan {
    # EndEdit() renvoie un booléen : sans [void] il polluait la sortie de la fonction
    # et devenait un faux "groupe" sans nom dans le plan.
    [void]$script:dg.EndEdit()
    $list =New-Object 'System.Collections.Generic.List[object]'
    foreach ($r in $script:dg.Rows) {
        if (-not [bool]$r.Cells[0].Value) { continue }
        $mem = @(([string]$r.Cells[6].Value -split '[;,]') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        $list.Add([pscustomobject]@{
            Display = ([string]$r.Cells[3].Value).Trim()
            Name    = ([string]$r.Cells[4].Value).Trim()
            OUPath  = ([string]$r.Cells[5].Value).Trim()
            MemberOf = $mem
            Usage   = ([string]$r.Cells[7].Value).Trim()
        })
    }
    $list
}

function Test-GroupPlan {
    param($Plan)
    $errs = New-Object 'System.Collections.Generic.List[string]'
    $seen = @{}
    foreach ($g in $Plan) {
        $n = $g.Name
        if ([string]::IsNullOrWhiteSpace($n)) { $errs.Add("Un groupe sélectionné n'a pas de nom."); continue }
        if ($n -match '["/\\\[\]:;|=,+*?<>@]') { $errs.Add("'$n' : caractères interdits dans le nom du groupe") }
        if ($n.EndsWith('.')) { $errs.Add("'$n' : le nom ne peut pas finir par un point") }
        if ($n.Length -gt 64) { $errs.Add("'$n' : plus de 64 caractères") }
        $k = $n.ToLowerInvariant()
        if ($seen.ContainsKey($k)) { $errs.Add("Doublon : '$n'") } else { $seen[$k] = $true }
        if ([string]::IsNullOrWhiteSpace($g.OUPath)) {
            $errs.Add("'$n' : OU cible manquante")
        } else {
            foreach ($seg in ($g.OUPath.Trim('\') -split '\\')) {
                $e = Test-OUName $seg
                if ($e) { $errs.Add("'$n' : OU cible '$($g.OUPath)' invalide ($e)"); break }
            }
        }
    }
    $errs
}

# ---- Accès AD ----
function Test-OuExists {
    param([string]$Dn)
    $p = $script:AdParams
    try { [void](Get-ADOrganizationalUnit -Identity $Dn @p -ErrorAction Stop); return $true }
    catch { return $false }
}

function Get-GroupByName {
    param([string]$Name)
    $p = $script:AdParams
    $safe = $Name.Replace("'", "''")
    Get-ADGroup -Filter "SamAccountName -eq '$safe'" -Properties MemberOf @p -ErrorAction Stop
}

function Invoke-GroupCreation {
    $domainDN = $script:txtDomain.Text.Trim()
    if ($domainDN -notmatch '^DC=[^,=]+(,DC=[^,=]+)*$') {
        Show-Message "Le DN du domaine (onglet Création Structure) est invalide.`nExemple : DC=domaine,DC=dom" 'Domaine' 'Warning'
        return
    }
    $plan = @(Get-GroupPlan)
    if ($plan.Count -eq 0) { Show-Message 'Aucun groupe sélectionné.' 'Création des groupes' 'Information'; return }
    $errs = @(Test-GroupPlan $plan)
    if ($errs.Count -gt 0) {
        Show-Message ("Corrigez les points suivants avant de continuer :`n`n" + ($errs -join "`n")) 'Validation' 'Warning'
        return
    }

    $whatIfMode = $script:chkWhatIf2.Checked
    $protect    = $script:chkProtect2.Checked
    $scope      = @('Global', 'DomainLocal', 'Universal')[$script:cmbScope.SelectedIndex]
    $mode = 'CRÉATION RÉELLE'
    if ($whatIfMode) { $mode = 'SIMULATION (aucune modification)' }
    $ans = [System.Windows.Forms.MessageBox]::Show(
        "Mode : $mode`nDomaine : $domainDN`nPortée : $scope`nGroupes sélectionnés : $($plan.Count)`n`nContinuer ?",
        'Confirmation', 'YesNo', 'Question')
    if ($ans -ne [System.Windows.Forms.DialogResult]::Yes) { return }

    $script:AdParams = @{}
    if ($script:txtServer.Text.Trim()) { $script:AdParams.Server = $script:txtServer.Text.Trim() }
    $script:GStats = @{ Created = 0; Existing = 0; Simulated = 0; Members = 0; Warnings = 0; Errors = 0 }

    $script:btnCreateGroups.Enabled = $false
    $script:tabs.Enabled = $false
    $script:form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        Write-Log "=== Début ($mode) - $domainDN ==="

        # Un seul contrôleur de domaine pour toute l'opération (évite les retards de réplication)
        if (-not $script:AdParams.ContainsKey('Server')) {
            try {
                $script:AdParams.Server = (Get-ADDomain -ErrorAction Stop).PDCEmulator
                Write-Log "Contrôleur utilisé : $($script:AdParams.Server)"
            }
            catch { Write-Log "[Avertissement] Contrôleur non épinglé : $($_.Exception.Message)" }
        }
        $p = $script:AdParams
        $known = @{}           # groupes qui existent ou existeront
        $existedBefore = @{}   # groupes déjà présents dans AD

        # --- Passe 1 : création des groupes ---
        foreach ($g in $plan) {
            try {
                $ouDn = ConvertTo-OuDn $g.OUPath $domainDN
                $existing = Get-GroupByName $g.Name
                if ($existing) {
                    $known[$g.Name] = $true
                    $existedBefore[$g.Name] = $true
                    $script:GStats.Existing++
                    Write-Log "[Existe]       $($existing.DistinguishedName)"
                    continue
                }
                if (-not (Test-OuExists $ouDn)) {
                    if ($whatIfMode) {
                        $script:GStats.Warnings++
                        Write-Log "[Avertissement] OU cible absente : $ouDn (à créer avec l'onglet Création Structure)"
                    } else {
                        $script:GStats.Errors++
                        Write-Log "[ERREUR]       $($g.Name) : OU cible introuvable ($ouDn). Créez-la d'abord."
                        continue
                    }
                }
                if ($whatIfMode) {
                    $known[$g.Name] = $true
                    $script:GStats.Simulated++
                    Write-Log "[Simulation]   Créerait $($g.Name) ($scope) dans $ouDn"
                    continue
                }
                $ng = @{ Name = $g.Name; SamAccountName = $g.Name; GroupScope = $scope; GroupCategory = 'Security'; Path = $ouDn }
                if ($g.Display) { $ng.DisplayName = $g.Display }
                if ($g.Usage)   { $ng.Description = $g.Usage }
                $newG = New-ADGroup @ng -PassThru @p -ErrorAction Stop
                if ($protect) { Set-ADObject -Identity $newG.DistinguishedName -ProtectedFromAccidentalDeletion $true @p -ErrorAction Stop }
                $known[$g.Name] = $true
                $script:GStats.Created++
                Write-Log "[Créé]         $($newG.DistinguishedName)"
            }
            catch {
                $script:GStats.Errors++
                Write-Log "[ERREUR]       $($g.Name) : $($_.Exception.Message)"
            }
        }

        # --- Passe 2 : imbrications (Membre de) ---
        foreach ($g in $plan) {
            if (-not $known.ContainsKey($g.Name)) { continue }
            foreach ($parent in $g.MemberOf) {
                try {
                    if ($parent -ieq $g.Name) { continue }
                    $pg = Get-GroupByName $parent
                    if (-not $pg -and -not ($whatIfMode -and $known.ContainsKey($parent))) {
                        $script:GStats.Warnings++
                        Write-Log "[Avertissement] Groupe parent introuvable : $parent (imbrication de $($g.Name) ignorée)"
                        continue
                    }
                    $cg = $null
                    if ($existedBefore.ContainsKey($g.Name) -or -not $whatIfMode) { $cg = Get-GroupByName $g.Name }
                    if ($pg -and $cg -and ($cg.MemberOf -contains $pg.DistinguishedName)) {
                        Write-Log "[Existe]       $($g.Name) est déjà membre de $parent"
                        continue
                    }
                    if ($whatIfMode) {
                        $script:GStats.Simulated++
                        Write-Log "[Simulation]   Ajouterait $($g.Name) comme membre de $parent"
                        continue
                    }
                    if (-not $cg) { throw "groupe $($g.Name) introuvable après création" }
                    Add-ADGroupMember -Identity $pg.DistinguishedName -Members $cg.DistinguishedName @p -ErrorAction Stop
                    $script:GStats.Members++
                    Write-Log "[Imbriqué]     $($g.Name) -> $parent"
                }
                catch {
                    $script:GStats.Errors++
                    Write-Log "[ERREUR]       $($g.Name) -> $parent : $($_.Exception.Message)"
                }
            }
        }

        $s = $script:GStats
        Write-Log "=== Fin : $($s.Created) créé(s), $($s.Existing) existant(s), $($s.Members) imbrication(s), $($s.Simulated) simulée(s), $($s.Warnings) avertissement(s), $($s.Errors) erreur(s) ==="
    }
    catch {
        Write-Log "[ERREUR] $($_.Exception.Message)"
    }
    finally {
        $script:form.Cursor = [System.Windows.Forms.Cursors]::Default
        $script:tabs.Enabled = $true
        $script:btnCreateGroups.Enabled = $script:AdAvailable
    }
}

# ---- Interface de l'onglet 2 ----
$tab2 = New-Object System.Windows.Forms.TabPage
$tab2.Text = 'Création Groupes'
$tab2.UseVisualStyleBackColor = $true
[void]$tabs.TabPages.Add($tab2)
$tab2.AutoScroll = $true
$tab2.AutoScrollMinSize = New-Object System.Drawing.Size(1050, 745)

# Convention de nommage des groupes
$gg1 = New-Group $tab2 'Convention de nommage des groupes' 10 10 540 165
[void](New-Lbl $gg1 'Modèle prédéfini' 10 22 145)
$script:cmbGPreset = New-Combo $gg1 160 22 370 @(
    'Selon le document (DLG_GG_T0_... / GRP_GG_T0-...)',
    'Homogène (DLG_GG_T0_... / GRP_GG_T0_...)',
    'Personnalisée')
[void](New-Lbl $gg1 'Groupes de délégation' 10 52 145)
$script:txtPatDlg = New-Txt $gg1 160 52 370
[void](New-Lbl $gg1 'Groupes opérationnels' 10 80 145)
$script:txtPatGrp = New-Txt $gg1 160 80 370
[void](New-Lbl $gg1 'Portée des groupes' 10 108 145)
$script:cmbScope = New-Combo $gg1 160 108 200 @('Global (GG)', 'DomainLocal', 'Universal')
$script:cmbScope.SelectedIndex = 0
$lblTok = New-Object System.Windows.Forms.Label
$lblTok.Text = "{N} = n° de Tier   {Name} = suffixe du groupe.   'Générer le catalogue' applique les modèles."
$lblTok.ForeColor = [System.Drawing.Color]::DimGray
$lblTok.Location = New-Object System.Drawing.Point(10, 140)
$lblTok.Size = New-Object System.Drawing.Size(520, 18)
$gg1.Controls.Add($lblTok)

# Tiers
$gg2 = New-Group $tab2 'Tiers à traiter' 560 10 170 165
$script:chkT0 = New-Object System.Windows.Forms.CheckBox
$script:chkT0.Text = 'Tier 0'; $script:chkT0.Checked = $true
$script:chkT0.Location = New-Object System.Drawing.Point(15, 28); $script:chkT0.Size = New-Object System.Drawing.Size(140, 22)
$script:chkT1 = New-Object System.Windows.Forms.CheckBox
$script:chkT1.Text = 'Tier 1'
$script:chkT1.Location = New-Object System.Drawing.Point(15, 58); $script:chkT1.Size = New-Object System.Drawing.Size(140, 22)
$script:chkT2 = New-Object System.Windows.Forms.CheckBox
$script:chkT2.Text = 'Tier 2'
$script:chkT2.Location = New-Object System.Drawing.Point(15, 88); $script:chkT2.Size = New-Object System.Drawing.Size(140, 22)
$gg2.Controls.Add($script:chkT0); $gg2.Controls.Add($script:chkT1); $gg2.Controls.Add($script:chkT2)

# Options
$gg3 = New-Group $tab2 'Options de création' 740 10 300 165
$script:chkProtect2 = New-Object System.Windows.Forms.CheckBox
$script:chkProtect2.Text = 'Protéger contre la suppression accidentelle'
$script:chkProtect2.Checked = $true
$script:chkProtect2.Location = New-Object System.Drawing.Point(10, 24); $script:chkProtect2.Size = New-Object System.Drawing.Size(285, 22)
$gg3.Controls.Add($script:chkProtect2)
$script:chkWhatIf2 = New-Object System.Windows.Forms.CheckBox
$script:chkWhatIf2.Text = 'Mode simulation (aucun groupe créé)'
$script:chkWhatIf2.Checked = $true
$script:chkWhatIf2.Location = New-Object System.Drawing.Point(10, 50); $script:chkWhatIf2.Size = New-Object System.Drawing.Size(285, 22)
$gg3.Controls.Add($script:chkWhatIf2)
$lblInfo2 = New-Object System.Windows.Forms.Label
$lblInfo2.Text = "Domaine et contrôleur : repris de l'onglet Création Structure. Les OU cibles doivent exister (créez-les d'abord)."
$lblInfo2.ForeColor = [System.Drawing.Color]::DimGray
$lblInfo2.Location = New-Object System.Drawing.Point(10, 84); $lblInfo2.Size = New-Object System.Drawing.Size(285, 70)
$gg3.Controls.Add($lblInfo2)

# Barre d'outils
function New-Btn2 {
    param([string]$Text, [int]$X, [int]$W)
    $b = New-Object System.Windows.Forms.Button
    $b.Text = $Text
    $b.Location = New-Object System.Drawing.Point($X, 182)
    $b.Size = New-Object System.Drawing.Size($W, 28)
    $tab2.Controls.Add($b)
    $b
}
$script:btnGen      = New-Btn2 'Générer le catalogue' 10  150
$script:btnAddGrp   = New-Btn2 '+ Groupe'             165 80
$script:btnSetOU    = New-Btn2 'OU cible...'          250 90
$script:btnDelGrp   = New-Btn2 'Retirer'              345 70
$script:btnGCheck   = New-Btn2 'Tout cocher'          420 90
$script:btnGUncheck = New-Btn2 'Tout décocher'        515 100
$script:btnCreateGroups = New-Btn2 'Créer les groupes' 830 210
$script:btnCreateGroups.Anchor = [System.Windows.Forms.AnchorStyles]'Top,Right'
$script:btnCreateGroups.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
$script:btnCreateGroups.Enabled = $script:AdAvailable

# Tableau des groupes
$script:dg = New-Object System.Windows.Forms.DataGridView
$dg = $script:dg
$dg.Location = New-Object System.Drawing.Point(10, 216)
$dg.Size = New-Object System.Drawing.Size(1030, 370)
$dg.Anchor = [System.Windows.Forms.AnchorStyles]'Top,Bottom,Left,Right'
$dg.BackgroundColor = [System.Drawing.Color]::White
$dg.AllowUserToAddRows = $false
$dg.AllowUserToDeleteRows = $false
$dg.AllowUserToResizeRows = $false
$dg.RowHeadersVisible = $false
$dg.MultiSelect = $true
$dg.SelectionMode = 'FullRowSelect'
$dg.ColumnHeadersHeightSizeMode = 'DisableResizing'
$dg.ColumnHeadersHeight = 28
$dg.DefaultCellStyle.WrapMode = [System.Windows.Forms.DataGridViewTriState]::True
$dg.AutoSizeRowsMode = 'AllCells'
$dg.AllowUserToResizeColumns = $true     # largeur des colonnes réglable à la souris
$dg.ScrollBars = 'Both'

$cCreate = New-Object System.Windows.Forms.DataGridViewCheckBoxColumn
$cCreate.HeaderText = 'Créer'; $cCreate.Width = 50; $cCreate.AutoSizeMode = 'None'
$cKind = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$cKind.HeaderText = 'Type'; $cKind.Width = 105; $cKind.ReadOnly = $true; $cKind.AutoSizeMode = 'None'
$cTier = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$cTier.HeaderText = 'Tier'; $cTier.Width = 45; $cTier.ReadOnly = $true; $cTier.AutoSizeMode = 'None'
$cDisp = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$cDisp.HeaderText = 'Nom affiché'; $cDisp.AutoSizeMode = 'None'; $cDisp.Width = 130; $cDisp.MinimumWidth = 40
$cName = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$cName.HeaderText = 'Nom du groupe (compte)'; $cName.AutoSizeMode = 'None'; $cName.Width = 175; $cName.MinimumWidth = 40
$cOU = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$cOU.HeaderText = 'OU cible'; $cOU.AutoSizeMode = 'None'; $cOU.Width = 170; $cOU.MinimumWidth = 40
$cMem = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$cMem.HeaderText = 'Membre de (groupes AD, séparés par ;)'; $cMem.AutoSizeMode = 'None'; $cMem.Width = 170; $cMem.MinimumWidth = 40
$cUse = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$cUse.HeaderText = 'Usage / rôle (description)'; $cUse.AutoSizeMode = 'None'; $cUse.Width = 160; $cUse.MinimumWidth = 40
[void]$dg.Columns.AddRange([System.Windows.Forms.DataGridViewColumn[]]@($cCreate, $cKind, $cTier, $cDisp, $cName, $cOU, $cMem, $cUse))
$tab2.Controls.Add($dg)

$script:lblGCount = New-Object System.Windows.Forms.Label
$script:lblGCount.Location = New-Object System.Drawing.Point(10, 592)
$script:lblGCount.Size = New-Object System.Drawing.Size(250, 18)
$script:lblGCount.Anchor = [System.Windows.Forms.AnchorStyles]'Bottom,Left'
$tab2.Controls.Add($script:lblGCount)
$lblGHint = New-Object System.Windows.Forms.Label
$lblGHint.Text = 'Cellules modifiables | Bleu = groupe optionnel (décoché) | Vert = groupe ajouté | "OU cible..." : choisir l''OU des lignes sélectionnées'
$lblGHint.Location = New-Object System.Drawing.Point(265, 592)
$lblGHint.Size = New-Object System.Drawing.Size(775, 18)
$lblGHint.Anchor = [System.Windows.Forms.AnchorStyles]'Bottom,Left,Right'
$tab2.Controls.Add($lblGHint)

# Journal
$gg5 = New-Group $tab2 'Journal' 10 614 1030 126
$gg5.Anchor = [System.Windows.Forms.AnchorStyles]'Bottom,Left,Right'
$script:txtLog2 = New-Object System.Windows.Forms.TextBox
$script:txtLog2.Multiline = $true
$script:txtLog2.ReadOnly = $true
$script:txtLog2.ScrollBars = 'Vertical'
$script:txtLog2.Font = New-Object System.Drawing.Font('Consolas', 9)
$script:txtLog2.Location = New-Object System.Drawing.Point(10, 20)
$script:txtLog2.Size = New-Object System.Drawing.Size(1010, 96)
$script:txtLog2.Anchor = [System.Windows.Forms.AnchorStyles]'Top,Bottom,Left,Right'
$gg5.Controls.Add($script:txtLog2)

# ---- Événements de l'onglet 2 ----
$script:cmbGPreset.add_SelectedIndexChanged({
    if ($script:ApplyingGPreset) { return }
    $i = $script:cmbGPreset.SelectedIndex
    if ($i -ge 0 -and $i -lt $script:GroupPresets.Count) { Set-GroupPreset $i }
})
foreach ($c in @($script:txtPatDlg, $script:txtPatGrp)) {
    $c.add_TextChanged({
        if ($script:ApplyingGPreset) { return }
        $script:ApplyingGPreset = $true
        $script:cmbGPreset.SelectedIndex = 2
        $script:ApplyingGPreset = $false
    })
}
$script:btnGen.add_Click({ Update-GroupCatalog })
$script:btnAddGrp.add_Click({ Add-CustomGroupRow })
$script:btnSetOU.add_Click({ Set-SelectedGroupOU })
$script:btnDelGrp.add_Click({ Remove-GroupRows })
$script:btnGCheck.add_Click({ Set-AllGroupsChecked $true })
$script:btnGUncheck.add_Click({ Set-AllGroupsChecked $false })
$script:btnCreateGroups.add_Click({ Invoke-GroupCreation })
$script:dg.add_CurrentCellDirtyStateChanged({
    if ($script:dg.IsCurrentCellDirty) { $script:dg.CommitEdit([System.Windows.Forms.DataGridViewDataErrorContexts]::Commit) }
})
$script:dg.add_CellValueChanged({ Update-GroupCount })
$script:dg.add_DataError({ param($s, $e) $e.ThrowException = $false })

# Génération paresseuse du catalogue à la première ouverture de l'onglet (utilise la convention de l'onglet 1)
$tabs.add_SelectedIndexChanged({
    if ($script:tabs.SelectedTab -eq $script:tab2 -and -not $script:GroupsGenerated) {
        Update-GroupCatalog -NoConfirm
    }
})

$script:cmbGPreset.SelectedIndex = 0
Set-GroupPreset 0
Update-GroupCount

# ============================================================================
# Onglet 3 : Création Comptes Admins
# ============================================================================
$script:ApplyingAPreset = $false
$script:AStats = @{ Created = 0; Existing = 0; Simulated = 0; Members = 0; Warnings = 0; Errors = 0 }

# Conventions de nommage courantes des comptes d'administration de Tier.
# Jetons : {N} n° de Tier | {Login} compte standard | {First} prénom | {Last} nom | {LAST} nom en MAJUSCULES | {F} initiale du prénom | {L} initiale du nom
$script:AdminPresets = @(
    @{ Sam = 'adm-t{N}-{Login}';       Display = '{First} {LAST} (Admin T{N})';   Label = 'adm-t0-jdupont   (adm-t{N}-{Login}) - cohérent avec les OU Adm-T0' },
    @{ Sam = '{Login}-t{N}';           Display = '{First} {LAST} (Admin T{N})';   Label = 'jdupont-t0   ({Login}-t{N}) - suffixe de Tier' },
    @{ Sam = 't{N}-{Login}';           Display = 'T{N} - {First} {LAST}';         Label = 't0-jdupont   (t{N}-{Login}) - préfixe de Tier' },
    @{ Sam = 'adm{N}.{Login}';         Display = 'ADM{N} - {First} {LAST}';       Label = 'adm0.jdupont   (adm{N}.{Login})' },
    @{ Sam = '{Login}_adm{N}';         Display = '{First} {LAST} (ADM{N})';       Label = 'jdupont_adm0   ({Login}_adm{N})' },
    @{ Sam = 'adm-t{N}-{F}{Last}';     Display = '{First} {LAST} (Admin T{N})';   Label = 'adm-t0-jdupont   (adm-t{N}-{F}{Last}) - construit depuis prénom/nom' },
    @{ Sam = 'adm{N}-{First}.{Last}';  Display = '{First} {LAST} (Admin T{N})';   Label = 'adm0-jean.dupont   (adm{N}-{First}.{Last})' }
)

# Profils de groupes affectés par défaut (liés au catalogue de l'onglet Création Groupes)
$script:AdminProfiles = @(
    "Groupe global d'administration du Tier (Administrateurs T{N}) uniquement",
    'Groupe global + groupe opérationnel Admins Serveurs (T0/T1) ou Postes (T2)',
    'Groupe global + opérationnel + Admins PAW',
    'Aucun groupe (affectation manuelle)'
)

function ConvertTo-AsciiToken {
    # Supprime accents, espaces et caractères non autorisés (noms de connexion / UPN)
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    # Table explicite (indépendante de la normalisation Unicode) puis décomposition pour les autres lettres accentuées
    $from = 'ÀÁÂÃÄÅÇÈÉÊËÌÍÎÏÑÒÓÔÕÖØÙÚÛÜÝàáâãäåçèéêëìíîïñòóôõöøùúûüýÿ'
    $to   = 'AAAAAACEEEEIIIINOOOOOOUUUUYaaaaaaceeeeiiiinoooooouuuuyy'
    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $Text.ToCharArray()) {
        $i = $from.IndexOf($ch)
        if ($i -ge 0) { [void]$sb.Append($to[$i]) }
        elseif ($ch -eq [char]0x0153) { [void]$sb.Append('oe') }
        elseif ($ch -eq [char]0x0152) { [void]$sb.Append('OE') }
        elseif ($ch -eq [char]0x00E6) { [void]$sb.Append('ae') }
        elseif ($ch -eq [char]0x00DF) { [void]$sb.Append('ss') }
        else { [void]$sb.Append($ch) }
    }
    $clean = New-Object System.Text.StringBuilder
    foreach ($ch in $sb.ToString().Normalize([System.Text.NormalizationForm]::FormD).ToCharArray()) {
        if ([System.Globalization.CharUnicodeInfo]::GetUnicodeCategory($ch) -ne [System.Globalization.UnicodeCategory]::NonSpacingMark) { [void]$clean.Append($ch) }
    }
    return ($clean.ToString() -replace '[^A-Za-z0-9._-]', '')
}

function Expand-AdminPattern {
    param([string]$Pattern, [int]$Tier, [string]$First, [string]$Last, [string]$Login, [bool]$Ascii)
    $f = $First; $l = $Last; $lg = $Login
    if ($Ascii) {
        $f  = ConvertTo-AsciiToken $First
        $l  = ConvertTo-AsciiToken $Last
        $lg = ConvertTo-AsciiToken $Login
    }
    $initF = ''; if ($f.Length -gt 0) { $initF = $f.Substring(0, 1) }
    $initL = ''; if ($l.Length -gt 0) { $initL = $l.Substring(0, 1) }
    $r = $Pattern.Replace('{N}', "$Tier").Replace('{Login}', $lg).Replace('{First}', $f).Replace('{FIRST}', $f.ToUpperInvariant())
    $r = $r.Replace('{Last}', $l).Replace('{LAST}', $l.ToUpperInvariant()).Replace('{F}', $initF.ToLowerInvariant()).Replace('{L}', $initL.ToLowerInvariant())
    return $r
}

function Get-UpnSuffix {
    $s = $script:txtUpnSuffix.Text.Trim()
    if ($s) { return $s.TrimStart('@') }
    $parts = @(($script:txtDomain.Text.Trim() -split ',') | ForEach-Object { if ($_ -match '^\s*DC=(.+)$') { $Matches[1] } })
    return ($parts -join '.')
}

function Get-AdminIdentity {
    param([string]$First, [string]$Last, [string]$Login, [int]$Tier)
    $sam  = Expand-AdminPattern -Pattern $script:txtPatSam.Text.Trim()  -Tier $Tier -First $First -Last $Last -Login $Login -Ascii $true
    $disp = Expand-AdminPattern -Pattern $script:txtPatDisp.Text.Trim() -Tier $Tier -First $First -Last $Last -Login $Login -Ascii $false
    [pscustomobject]@{ Sam = $sam; Display = $disp }
}

# OU par défaut des comptes admins d'un Tier, d'après la convention de l'onglet 1 (\Admin-TM\Adm-T0\T0-Administrateurs)
function Get-DefaultAdminOU {
    param([int]$Tier)
    $lang = 'FR'
    if ($script:cmbLang.SelectedIndex -eq 1) { $lang = 'EN' }
    $sep    = $script:txtSep.Text
    $prefix = ($script:txtPrefix.Text -replace '\{N\}', "$Tier") + $sep
    $c = @(Get-AdminChildren $Tier)
    return ('\' + $script:txtAdminRoot.Text + '\' + ($script:txtAdminTier.Text -replace '\{N\}', "$Tier") + '\' + $prefix + $c[0].$lang)
}

# Groupes par défaut selon le profil, résolus via les modèles de nom de l'onglet Création Groupes
function Get-AdminProfileGroups {
    param([int]$Tier, [int]$ProfileIndex)
    $keys = @()
    switch ($ProfileIndex) {
        0 { $keys = @('Global') }
        1 { $keys = @('Global', 'AdmSrv', 'AdmPostes') }
        2 { $keys = @('Global', 'AdmSrv', 'AdmPostes', 'PAW') }
        default { $keys = @() }
    }
    $cat = @(Get-GroupCatalog)
    $names = @()
    foreach ($k in $keys) {
        $e = @($cat | Where-Object { $_.Key -eq $k -and $_.Tiers -contains $Tier })[0]
        if ($e) { $names += (Get-GroupName $e.Kind $Tier $e.Suffix) }
    }
    return $names
}

# Table nom de groupe -> n° de Tier du catalogue (détection des affectations inter-Tiers)
function Get-TierGroupMap {
    $map = @{}
    foreach ($e in @(Get-GroupCatalog)) {
        foreach ($t in $e.Tiers) { $map[(Get-GroupName $e.Kind $t $e.Suffix).ToLowerInvariant()] = $t }
    }
    return $map
}

function New-RandomPassword {
    param([int]$Length = 24)
    if ($Length -lt 14) { $Length = 14 }
    $sets = @('ABCDEFGHJKLMNPQRSTUVWXYZ', 'abcdefghijkmnopqrstuvwxyz', '23456789', '!#$%&*+-=?@^_')
    $all = ($sets -join '')
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $buf = New-Object 'byte[]' 4
    $next = {
        param([int]$Max)
        $limit = [uint64]4294967296 - ([uint64]4294967296 % [uint64]$Max)
        do { $rng.GetBytes($buf); $v = [uint64][BitConverter]::ToUInt32($buf, 0) } while ($v -ge $limit)
        [int]($v % [uint64]$Max)
    }
    try {
        $chars = New-Object 'System.Collections.Generic.List[char]'
        foreach ($s in $sets) { $chars.Add($s[(& $next $s.Length)]) }
        while ($chars.Count -lt $Length) { $chars.Add($all[(& $next $all.Length)]) }
        # mélange de Fisher-Yates
        for ($i = $chars.Count - 1; $i -gt 0; $i--) {
            $j = & $next ($i + 1)
            $tmp = $chars[$i]; $chars[$i] = $chars[$j]; $chars[$j] = $tmp
        }
        return (-join $chars)
    }
    finally { $rng.Dispose() }
}

function Protect-SecretFile {
    # Restreint l'ACL du fichier à l'utilisateur courant (héritage supprimé)
    param([string]$Path)
    $acl = Get-Acl -LiteralPath $Path
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($r in @($acl.Access)) { [void]$acl.RemoveAccessRule($r) }
    $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($me, 'FullControl', 'Allow')
    $acl.AddAccessRule($rule)
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Test-AdminSam {
    param([string]$Sam)
    if ([string]::IsNullOrWhiteSpace($Sam)) { return 'nom de compte vide' }
    if ($Sam.Length -gt 20) { return "plus de 20 caractères ($($Sam.Length)) - limite sAMAccountName" }
    if ($Sam -match '["/\\\[\]:;|=,+*?<>@\s]') { return 'caractères interdits dans le nom de compte' }
    if ($Sam.EndsWith('.')) { return 'ne peut pas finir par un point' }
    if ($Sam -match '^\d+$') { return 'ne peut pas être uniquement numérique' }
    return $null
}

# ---- Tableau ----
function Update-AdminCount {
    $n = 0; $t = 0
    foreach ($r in $script:dga.Rows) { $t++; if ([bool]$r.Cells[0].Value) { $n++ } }
    $script:lblACount.Text = "$n compte(s) sélectionné(s) sur $t"
}

function Add-AdminRow {
    param([bool]$Create, [int]$Tier, [string]$First, [string]$Last, [string]$Login,
          [string]$Sam, [string]$Display, [string]$OU, [string]$MemberOf, [string]$Style = 'base')
    $idx = $script:dga.Rows.Add([object[]]@($Create, "T$Tier", $First, $Last, $Login, $Sam, $Display, $OU, $MemberOf, ''))
    if ($Style -eq 'custom') { $script:dga.Rows[$idx].DefaultCellStyle.ForeColor = [System.Drawing.Color]::SeaGreen }
    return $idx
}

function Get-RowTier {
    param($Row)
    return [int](([string]$Row.Cells[1].Value) -replace '\D', '')
}

function Add-AdminAccounts {
    # Une personne x N Tiers = N comptes distincts (un compte par Tier - principe du Tier Model)
    param([string]$First, [string]$Last, [string]$Login, [int[]]$Tiers)
    $added = 0
    foreach ($t in $Tiers) {
        $id = Get-AdminIdentity $First $Last $Login $t
        $dup = $false
        foreach ($r in $script:dga.Rows) { if (([string]$r.Cells[5].Value) -ieq $id.Sam) { $dup = $true } }
        if ($dup) { Write-Log "[Avertissement] Compte '$($id.Sam)' déjà dans le tableau - ignoré."; continue }
        $grp = (Get-AdminProfileGroups $t $script:cmbProfile.SelectedIndex) -join ';'
        [void](Add-AdminRow -Create $true -Tier $t -First $First -Last $Last -Login $Login -Sam $id.Sam -Display $id.Display `
            -OU (Get-DefaultAdminOU $t) -MemberOf $grp -Style 'custom')
        $added++
    }
    Update-AdminCount
    return $added
}

function Get-SelectedTiers {
    $t = @()
    if ($script:chkAT0.Checked) { $t += 0 }
    if ($script:chkAT1.Checked) { $t += 1 }
    if ($script:chkAT2.Checked) { $t += 2 }
    return $t
}

function Read-AdminDialog {
    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text = 'Ajouter un administrateur'
    $dlg.Font = $script:form.Font
    $dlg.FormBorderStyle = 'FixedDialog'
    $dlg.StartPosition = 'CenterParent'
    $dlg.MinimizeBox = $false; $dlg.MaximizeBox = $false
    $dlg.ClientSize = New-Object System.Drawing.Size(430, 215)
    [void](New-Lbl $dlg 'Prénom' 12 12 120);  $tF = New-Txt $dlg 140 12 275
    [void](New-Lbl $dlg 'Nom' 12 42 120);     $tL = New-Txt $dlg 140 42 275
    [void](New-Lbl $dlg 'Login du compte standard' 12 72 125); $tG = New-Txt $dlg 140 72 275
    $hint = New-Object System.Windows.Forms.Label
    $hint.Text = "Login vide = initiale du prénom + nom. Un compte sera créé pour chacun des Tiers cochés dans l'onglet ($((Get-SelectedTiers | ForEach-Object { "T$_" }) -join ', '))."
    $hint.ForeColor = [System.Drawing.Color]::DimGray
    $hint.Location = New-Object System.Drawing.Point(12, 106); $hint.Size = New-Object System.Drawing.Size(405, 50)
    $dlg.Controls.Add($hint)
    $ok = New-Object System.Windows.Forms.Button
    $ok.Text = 'OK'; $ok.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $ok.Location = New-Object System.Drawing.Point(247, 170); $ok.Size = New-Object System.Drawing.Size(80, 28)
    $dlg.Controls.Add($ok)
    $cancel = New-Object System.Windows.Forms.Button
    $cancel.Text = 'Annuler'; $cancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $cancel.Location = New-Object System.Drawing.Point(337, 170); $cancel.Size = New-Object System.Drawing.Size(80, 28)
    $dlg.Controls.Add($cancel)
    $dlg.AcceptButton = $ok; $dlg.CancelButton = $cancel
    $res = $null
    if ($dlg.ShowDialog($script:form) -eq [System.Windows.Forms.DialogResult]::OK) {
        $res = @{ First = $tF.Text.Trim(); Last = $tL.Text.Trim(); Login = $tG.Text.Trim() }
    }
    $dlg.Dispose()
    return $res
}

function Select-MultiFromList {
    param([string]$Title, [string]$Prompt, [string[]]$Items, [string[]]$Checked = @())
    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text = $Title
    $dlg.Font = $script:form.Font
    $dlg.FormBorderStyle = 'FixedDialog'
    $dlg.StartPosition = 'CenterParent'
    $dlg.MinimizeBox = $false; $dlg.MaximizeBox = $false
    $dlg.ClientSize = New-Object System.Drawing.Size(560, 400)
    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Text = $Prompt
    $lbl.Location = New-Object System.Drawing.Point(12, 10); $lbl.Size = New-Object System.Drawing.Size(535, 34)
    $dlg.Controls.Add($lbl)
    $cl = New-Object System.Windows.Forms.CheckedListBox
    $cl.CheckOnClick = $true
    $cl.HorizontalScrollbar = $true
    $cl.Location = New-Object System.Drawing.Point(12, 48); $cl.Size = New-Object System.Drawing.Size(535, 300)
    foreach ($i in $Items) { [void]$cl.Items.Add($i, ($Checked -contains $i)) }
    $dlg.Controls.Add($cl)
    $ok = New-Object System.Windows.Forms.Button
    $ok.Text = 'OK'; $ok.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $ok.Location = New-Object System.Drawing.Point(377, 360); $ok.Size = New-Object System.Drawing.Size(80, 28)
    $dlg.Controls.Add($ok)
    $cancel = New-Object System.Windows.Forms.Button
    $cancel.Text = 'Annuler'; $cancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $cancel.Location = New-Object System.Drawing.Point(467, 360); $cancel.Size = New-Object System.Drawing.Size(80, 28)
    $dlg.Controls.Add($cancel)
    $dlg.AcceptButton = $ok; $dlg.CancelButton = $cancel
    $result = $null
    if ($dlg.ShowDialog($script:form) -eq [System.Windows.Forms.DialogResult]::OK) {
        $result = @(foreach ($i in $cl.CheckedItems) { [string]$i })
    }
    $dlg.Dispose()
    return , $result
}

function Initialize-AdParams {
    $script:AdParams = @{}
    if ($script:txtServer.Text.Trim()) { $script:AdParams.Server = $script:txtServer.Text.Trim() }
}

function Add-AdminFromDialog {
    $r = Read-AdminDialog
    if ($null -eq $r) { return }
    if (-not $r.First -and -not $r.Last -and -not $r.Login) { Show-Message 'Renseignez au moins un nom ou un login.' 'Ajouter' 'Warning'; return }
    $tiers = @(Get-SelectedTiers)
    if ($tiers.Count -eq 0) { Show-Message 'Cochez au moins un Tier.' 'Tiers des comptes' 'Information'; return }
    $login = $r.Login
    if (-not $login) { $login = ((ConvertTo-AsciiToken $r.First).Substring(0, [Math]::Min(1, (ConvertTo-AsciiToken $r.First).Length)) + (ConvertTo-AsciiToken $r.Last)).ToLowerInvariant() }
    [void](Add-AdminAccounts $r.First $r.Last $login $tiers)
}

function Add-AdminFromAd {
    if (-not $script:AdAvailable) { Show-Message 'Module ActiveDirectory (RSAT) absent.' 'Depuis AD' 'Warning'; return }
    $tiers = @(Get-SelectedTiers)
    if ($tiers.Count -eq 0) { Show-Message 'Cochez au moins un Tier.' 'Tiers des comptes' 'Information'; return }
    $text = Read-TextDialog 'Rechercher dans AD' "Texte à rechercher (login, prénom, nom ou nom affiché) :" ''
    if ([string]::IsNullOrWhiteSpace($text)) { return }
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        Initialize-AdParams
        $p = $script:AdParams
        $t = $text.Trim().Replace('\', '\5c').Replace('*', '\2a').Replace('(', '\28').Replace(')', '\29')
        $flt = "(&(objectCategory=person)(objectClass=user)(|(sAMAccountName=*$t*)(sn=*$t*)(givenName=*$t*)(displayName=*$t*)))"
        $users = @(Get-ADUser -LDAPFilter $flt -Properties GivenName, Surname, DisplayName @p -ResultSetSize 200 -ErrorAction Stop)
    }
    catch { Write-Log "[ERREUR] Recherche AD : $($_.Exception.Message)"; return }
    if ($users.Count -eq 0) { Show-Message 'Aucun utilisateur trouvé.' 'Depuis AD' 'Information'; return }
    $map = @{}
    foreach ($u in ($users | Sort-Object SamAccountName)) { $map["$($u.SamAccountName)   -   $($u.DisplayName)"] = $u }
    $sel = @(Select-MultiFromList 'Utilisateurs AD' "Cochez les utilisateurs pour lesquels créer un compte d'administration (200 résultats max)." @($map.Keys | Sort-Object))
    $n = 0
    foreach ($k in $sel) {
        $u = $map[$k]
        $n += Add-AdminAccounts ([string]$u.GivenName) ([string]$u.Surname) ([string]$u.SamAccountName) $tiers
    }
    if ($sel.Count -gt 0) { Write-Log "$n compte(s) ajouté(s) au tableau depuis AD." }
}

function Import-AdminCsv {
    $tiers = @(Get-SelectedTiers)
    $ofd = New-Object System.Windows.Forms.OpenFileDialog
    $ofd.Filter = 'CSV (*.csv)|*.csv|Tous les fichiers (*.*)|*.*'
    $ofd.Title = 'CSV : Prenom;Nom;Login;Tiers (Tiers facultatif, ex. 0,1)'
    if ($ofd.ShowDialog($script:form) -ne [System.Windows.Forms.DialogResult]::OK) { return }
    try {
        $rows = @(Import-Csv -LiteralPath $ofd.FileName -Delimiter ';' -Encoding UTF8 -ErrorAction Stop)
    }
    catch { Write-Log "[ERREUR] Import CSV : $($_.Exception.Message)"; return }
    $n = 0
    foreach ($r in $rows) {
        $f = [string]($r.Prenom, $r.FirstName, $r.Prénom | Where-Object { $_ } | Select-Object -First 1)
        $l = [string]($r.Nom, $r.LastName, $r.Surname | Where-Object { $_ } | Select-Object -First 1)
        $g = [string]($r.Login, $r.Sam, $r.SamAccountName | Where-Object { $_ } | Select-Object -First 1)
        $tt = $tiers
        if ($r.Tiers) { $tt = @([regex]::Matches([string]$r.Tiers, '[0-2]') | ForEach-Object { [int]$_.Value } | Select-Object -Unique) }
        if (-not $g) { $g = ((ConvertTo-AsciiToken $f) + (ConvertTo-AsciiToken $l)).ToLowerInvariant() }
        if (-not $g -or $tt.Count -eq 0) { Write-Log "[Avertissement] Ligne CSV ignorée (login ou Tier manquant) : $f $l"; continue }
        $n += Add-AdminAccounts $f $l $g $tt
    }
    Write-Log "Import CSV : $n compte(s) ajouté(s) depuis $($ofd.FileName)"
}

function Update-AdminNames {
    if ($script:dga.Rows.Count -eq 0) { return }
    $a = [System.Windows.Forms.MessageBox]::Show(
        "Les noms de compte, noms affichés, OU et groupes de TOUTES les lignes vont être régénérés d'après la convention, la structure d'OU et le profil de groupes.`nVos modifications manuelles seront perdues. Continuer ?",
        'Appliquer la convention', 'YesNo', 'Warning')
    if ($a -ne [System.Windows.Forms.DialogResult]::Yes) { return }
    foreach ($r in $script:dga.Rows) {
        $t = Get-RowTier $r
        $id = Get-AdminIdentity ([string]$r.Cells[2].Value) ([string]$r.Cells[3].Value) ([string]$r.Cells[4].Value) $t
        $r.Cells[5].Value = $id.Sam
        $r.Cells[6].Value = $id.Display
        $r.Cells[7].Value = Get-DefaultAdminOU $t
        $r.Cells[8].Value = (Get-AdminProfileGroups $t $script:cmbProfile.SelectedIndex) -join ';'
        $r.Cells[9].Value = ''
    }
}

function Set-SelectedAdminOU {
    $rows = @($script:dga.SelectedRows)
    if ($rows.Count -eq 0) { Show-Message 'Sélectionnez une ou plusieurs lignes (clic sur la ligne).' 'OU cible' 'Information'; return }
    $list = New-Object 'System.Collections.Generic.List[string]'
    Get-PlanPaths $script:tv.Nodes $list
    foreach ($r in $script:dga.Rows) { $v = [string]$r.Cells[7].Value; if ($v) { $list.Add($v) } }
    $items = @($list | Sort-Object -Unique)
    $choice = Select-FromList 'OU cible' "Choisissez l'OU cible des $($rows.Count) compte(s) sélectionné(s) (plan de l'onglet Création Structure + OU déjà utilisées)." $items ([string]$rows[0].Cells[7].Value)
    if ($choice) { foreach ($r in $rows) { $r.Cells[7].Value = $choice } }
}

function Set-SelectedAdminGroups {
    $rows = @($script:dga.SelectedRows)
    if ($rows.Count -eq 0) { Show-Message 'Sélectionnez une ou plusieurs lignes (clic sur la ligne).' 'Groupes' 'Information'; return }
    $cat = @(Get-GroupCatalog)
    $cand = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($r in $rows) {
        $t = Get-RowTier $r
        foreach ($e in ($cat | Where-Object { $_.Tiers -contains $t })) { [void]$cand.Add((Get-GroupName $e.Kind $t $e.Suffix)) }
        foreach ($g in (([string]$r.Cells[8].Value) -split ';')) { if ($g.Trim()) { [void]$cand.Add($g.Trim()) } }
    }
    foreach ($r in $script:dg.Rows) { $n = ([string]$r.Cells[4].Value).Trim(); if ($n -and ([string]$r.Cells[2].Value) -in @(($rows | ForEach-Object { [string]$_.Cells[1].Value }))) { [void]$cand.Add($n) } }
    $cur = @(([string]$rows[0].Cells[8].Value -split ';') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $sel = Select-MultiFromList 'Groupes à affecter' "Groupes dont les $($rows.Count) compte(s) sélectionné(s) seront membres (catalogue de l'onglet Création Groupes, limité aux groupes du même Tier). Remplace la liste actuelle." @($cand | Sort-Object) $cur
    if ($null -ne $sel) { foreach ($r in $rows) { $r.Cells[8].Value = ($sel -join ';') } }
}

function Remove-AdminRows {
    $rows = @($script:dga.SelectedRows)
    if ($rows.Count -eq 0) { Show-Message 'Sélectionnez une ou plusieurs lignes (clic sur la ligne).' 'Retirer' 'Information'; return }
    $a = [System.Windows.Forms.MessageBox]::Show("Retirer $($rows.Count) ligne(s) du tableau ?`n(Aucun compte existant dans AD n'est supprimé.)", 'Retirer', 'YesNo', 'Question')
    if ($a -ne [System.Windows.Forms.DialogResult]::Yes) { return }
    foreach ($r in $rows) { $script:dga.Rows.Remove($r) }
    Update-AdminCount
}

function Set-AllAdminsChecked {
    param([bool]$State)
    foreach ($r in $script:dga.Rows) { $r.Cells[0].Value = $State }
    Update-AdminCount
}

# ---- Lecture / validation du plan ----
function Get-AdminPlan {
    [void]$script:dga.EndEdit()
    $list = New-Object 'System.Collections.Generic.List[object]'
    foreach ($r in $script:dga.Rows) {
        if (-not [bool]$r.Cells[0].Value) { continue }
        $mem = @(([string]$r.Cells[8].Value -split '[;,]') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        $list.Add([pscustomobject]@{
            Tier = (Get-RowTier $r); First = ([string]$r.Cells[2].Value).Trim(); Last = ([string]$r.Cells[3].Value).Trim()
            Login = ([string]$r.Cells[4].Value).Trim(); Sam = ([string]$r.Cells[5].Value).Trim()
            Display = ([string]$r.Cells[6].Value).Trim(); OUPath = ([string]$r.Cells[7].Value).Trim(); MemberOf = $mem
        })
    }
    return $list
}

function Test-AdminPlan {
    param($Plan)
    $errs = New-Object 'System.Collections.Generic.List[string]'
    $seen = @{}
    $map = Get-TierGroupMap
    foreach ($a in $Plan) {
        $n = $a.Sam
        $e = Test-AdminSam $n
        if ($e) { $errs.Add("'$n' (T$($a.Tier)) : $e") }
        if ($n) {
            $k = $n.ToLowerInvariant()
            if ($seen.ContainsKey($k)) { $errs.Add("Doublon : '$n'") } else { $seen[$k] = $true }
        }
        $cn = $a.Display; if (-not $cn) { $cn = $n }
        if ($cn.Length -gt 64) { $errs.Add("'$n' : nom affiché de plus de 64 caractères") }
        if ($cn -match '[\\"<>]|^\s|\s$|^#') { $errs.Add("'$n' : nom affiché invalide (caractères \ `" < > ou espace/# en bordure)") }
        if ([string]::IsNullOrWhiteSpace($a.OUPath)) { $errs.Add("'$n' : OU cible manquante") }
        else {
            foreach ($seg in ($a.OUPath.Trim('\') -split '\\')) {
                $x = Test-OUName $seg
                if ($x) { $errs.Add("'$n' : OU cible '$($a.OUPath)' invalide ($x)"); break }
            }
        }
        foreach ($g in $a.MemberOf) {
            $gk = $g.ToLowerInvariant()
            if ($map.ContainsKey($gk) -and $map[$gk] -ne $a.Tier) {
                $errs.Add("'$n' (T$($a.Tier)) : membre de '$g' (Tier $($map[$gk])) - violation du cloisonnement des Tiers")
            }
        }
    }
    return $errs
}

function Get-UserByName {
    param([string]$Sam)
    $p = $script:AdParams
    $safe = $Sam.Replace("'", "''")
    Get-ADUser -Filter "SamAccountName -eq '$safe'" -Properties MemberOf @p -ErrorAction Stop
}

function Test-AdminStatus {
    if (-not $script:AdAvailable) { Show-Message 'Module ActiveDirectory (RSAT) absent.' 'Vérifier' 'Warning'; return }
    $domainDN = $script:txtDomain.Text.Trim()
    if ($domainDN -notmatch '^DC=[^,=]+(,DC=[^,=]+)*$') { Show-Message 'Le DN du domaine (onglet Création Structure) est invalide.' 'Domaine' 'Warning'; return }
    $script:form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        Initialize-AdParams
        $planned = @{}
        foreach ($r in $script:dg.Rows) { if ([bool]$r.Cells[0].Value) { $planned[([string]$r.Cells[4].Value).Trim().ToLowerInvariant()] = $true } }
        foreach ($r in $script:dga.Rows) {
            $st = New-Object 'System.Collections.Generic.List[string]'
            try {
                if (Get-UserByName ([string]$r.Cells[5].Value).Trim()) { $st.Add('Compte existant') } else { $st.Add('À créer') }
                if (-not (Test-OuExists (ConvertTo-OuDn ([string]$r.Cells[7].Value) $domainDN))) { $st.Add('OU absente') }
                $miss = @()
                foreach ($g in (([string]$r.Cells[8].Value -split ';') | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
                    if (-not (Get-GroupByName $g) -and -not $planned.ContainsKey($g.ToLowerInvariant())) { $miss += $g }
                }
                if ($miss.Count -gt 0) { $st.Add("groupe(s) absent(s) : $($miss -join ',')") }
            }
            catch { $st.Add("Erreur : $($_.Exception.Message)") }
            $r.Cells[9].Value = ($st -join ' | ')
        }
        Write-Log 'Vérification AD terminée (colonne Statut AD).'
    }
    catch { Write-Log "[ERREUR] $($_.Exception.Message)" }
    finally { $script:form.Cursor = [System.Windows.Forms.Cursors]::Default }
}

function Save-AdminState {
    param($State, [string]$Path)
    try {
        $State | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $Path -Encoding UTF8
        Write-Log "Fichier d'état (rollback) : $Path"
    }
    catch { Write-Log "[ERREUR] Écriture du fichier d'état : $($_.Exception.Message)" }
}

function Invoke-AdminCreation {
    [Diagnostics.CodeAnalysis.SuppressMessage('PSAvoidUsingConvertToSecureStringWithPlainText', '', Justification = 'Mot de passe initial aléatoire généré localement, jamais journalisé ; exporté uniquement dans un CSV à ACL restreinte.')]
    param()
    $domainDN = $script:txtDomain.Text.Trim()
    if ($domainDN -notmatch '^DC=[^,=]+(,DC=[^,=]+)*$') {
        Show-Message "Le DN du domaine (onglet Création Structure) est invalide.`nExemple : DC=domaine,DC=dom" 'Domaine' 'Warning'
        return
    }
    $suffix = Get-UpnSuffix
    if (-not $suffix) { Show-Message 'Suffixe UPN introuvable : renseignez-le.' 'Suffixe UPN' 'Warning'; return }
    $plan = @(Get-AdminPlan)
    if ($plan.Count -eq 0) { Show-Message 'Aucun compte sélectionné.' 'Création des comptes' 'Information'; return }
    $errs = @(Test-AdminPlan $plan)
    if ($errs.Count -gt 0) {
        Show-Message ("Corrigez les points suivants avant de continuer :`n`n" + ($errs -join "`n")) 'Validation' 'Warning'
        return
    }
    $whatIfMode = $script:chkWhatIf3.Checked
    $mode = 'CRÉATION RÉELLE'
    if ($whatIfMode) { $mode = 'SIMULATION (aucune modification)' }
    $ans = [System.Windows.Forms.MessageBox]::Show(
        "Mode : $mode`nDomaine : $domainDN`nSuffixe UPN : $suffix`nComptes sélectionnés : $($plan.Count)`n`nContinuer ?",
        'Confirmation', 'YesNo', 'Question')
    if ($ans -ne [System.Windows.Forms.DialogResult]::Yes) { return }

    Initialize-AdParams
    $script:AStats = @{ Created = 0; Existing = 0; Simulated = 0; Members = 0; Warnings = 0; Errors = 0 }
    $pwdLen = [int]$script:numPwd.Value
    $pwdFile = $script:txtPwdFile.Text.Trim()
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $statePath = Join-Path $script:LogFolder "TierModel_AdminAccounts_State_$stamp.json"
    $pwdRows = New-Object 'System.Collections.Generic.List[object]'
    $state = [ordered]@{
        Version = $script:ScriptVersion; Date = (Get-Date -Format 's'); Domain = $domainDN
        Server = ''; Accounts = (New-Object 'System.Collections.Generic.List[object]')
    }

    $script:btnCreateAdmins.Enabled = $false
    $script:btnRollback.Enabled = $false
    $script:tabs.Enabled = $false
    $script:form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        Write-Log "=== Début ($mode) - $domainDN - $($plan.Count) compte(s) ==="
        if (-not $script:AdParams.ContainsKey('Server')) {
            try {
                $script:AdParams.Server = (Get-ADDomain -ErrorAction Stop).PDCEmulator
                Write-Log "Contrôleur utilisé : $($script:AdParams.Server)"
            }
            catch { Write-Log "[Avertissement] Contrôleur non épinglé : $($_.Exception.Message)" }
        }
        $p = $script:AdParams
        if ($p.ContainsKey('Server')) { $state.Server = $p.Server }

        # Groupes prévus dans l'onglet Création Groupes (acceptés en simulation même s'ils n'existent pas encore)
        $plannedGroups = @{}
        foreach ($r in $script:dg.Rows) { if ([bool]$r.Cells[0].Value) { $plannedGroups[([string]$r.Cells[4].Value).Trim().ToLowerInvariant()] = $true } }

        # Groupe 'Protected Users' (RID 525)
        $puGroup = $null
        if ($script:chkProtUsers.Checked) {
            try {
                $sid = (Get-ADDomain @p -ErrorAction Stop).DomainSID.Value
                $puGroup = Get-ADGroup -Identity "$sid-525" @p -ErrorAction Stop
            }
            catch { $script:AStats.Warnings++; Write-Log "[Avertissement] Groupe Protected Users introuvable (niveau fonctionnel < 2012 R2 ?) : $($_.Exception.Message)" }
        }

        foreach ($a in $plan) {
            $entry = [ordered]@{ Sam = $a.Sam; DN = ''; Created = $false; GroupsAdded = @() }
            $added = New-Object 'System.Collections.Generic.List[string]'
            try {
                $ouDn = ConvertTo-OuDn $a.OUPath $domainDN
                $upn = "$($a.Sam)@$suffix"
                $cn = $a.Display; if (-not $cn) { $cn = $a.Sam }
                $user = Get-UserByName $a.Sam
                $userExists = [bool]$user
                if ($userExists) {
                    $entry.DN = $user.DistinguishedName
                    $script:AStats.Existing++
                    Write-Log "[Existe]       $($user.DistinguishedName)"
                }
                else {
                    if (-not (Test-OuExists $ouDn)) {
                        if ($whatIfMode) {
                            $script:AStats.Warnings++
                            Write-Log "[Avertissement] OU cible absente : $ouDn (à créer avec l'onglet Création Structure)"
                        } else {
                            $script:AStats.Errors++
                            Write-Log "[ERREUR]       $($a.Sam) : OU cible introuvable ($ouDn). Créez-la d'abord."
                            continue
                        }
                    }
                    if ($whatIfMode) {
                        $script:AStats.Simulated++
                        Write-Log "[Simulation]   Créerait $($a.Sam) ($upn) 'T$($a.Tier)' dans $ouDn"
                    }
                    else {
                        $pw = New-RandomPassword $pwdLen
                        $nu = @{
                            Name = $cn; SamAccountName = $a.Sam; UserPrincipalName = $upn; DisplayName = $cn
                            Description = "Compte d'administration Tier $($a.Tier) de $($a.First) $($a.Last) ($($a.Login))".Replace('  ', ' ')
                            Path = $ouDn; AccountPassword = (ConvertTo-SecureString $pw -AsPlainText -Force); Enabled = $true
                            ChangePasswordAtLogon = $script:chkChangePwd.Checked
                            AccountNotDelegated = $script:chkNotDeleg.Checked
                        }
                        if ($script:chkSmartcard.Checked) { $nu.SmartcardLogonRequired = $true }
                        if ($a.First) { $nu.GivenName = $a.First }
                        if ($a.Last)  { $nu.Surname = $a.Last }
                        $newU = New-ADUser @nu -PassThru @p -ErrorAction Stop
                        $entry.DN = $newU.DistinguishedName
                        $entry.Created = $true
                        if ($script:chkProtect3.Checked) { Set-ADObject -Identity $newU.DistinguishedName -ProtectedFromAccidentalDeletion $true @p -ErrorAction Stop }
                        $script:AStats.Created++
                        Write-Log "[Créé]         $($newU.DistinguishedName)"
                        $pwdRows.Add([pscustomobject]@{ Compte = $a.Sam; UPN = $upn; MotDePasseInitial = $pw; DN = $newU.DistinguishedName })
                        $user = $newU
                        $userExists = $true
                    }
                }

                # --- Appartenance aux groupes (+ Protected Users) ---
                $targets = New-Object 'System.Collections.Generic.List[object]'
                foreach ($gName in $a.MemberOf) { $targets.Add(@{ Name = $gName; Group = $null; Kind = 'groupe' }) }
                if ($puGroup) { $targets.Add(@{ Name = $puGroup.Name; Group = $puGroup; Kind = 'Protected Users' }) }
                foreach ($t in $targets) {
                    try {
                        $g = $t.Group
                        if (-not $g) { $g = Get-GroupByName $t.Name }
                        if (-not $g) {
                            if ($whatIfMode -and $plannedGroups.ContainsKey($t.Name.ToLowerInvariant())) {
                                $script:AStats.Simulated++
                                Write-Log "[Simulation]   Ajouterait $($a.Sam) au groupe $($t.Name) (groupe à créer via l'onglet Création Groupes)"
                            } else {
                                $script:AStats.Warnings++
                                Write-Log "[Avertissement] Groupe introuvable : $($t.Name) (affectation de $($a.Sam) ignorée)"
                            }
                            continue
                        }
                        if ($userExists -and $user.MemberOf -contains $g.DistinguishedName) {
                            Write-Log "[Existe]       $($a.Sam) est déjà membre de $($g.Name)"
                            continue
                        }
                        if ($whatIfMode) {
                            $script:AStats.Simulated++
                            Write-Log "[Simulation]   Ajouterait $($a.Sam) au groupe $($g.Name)"
                            continue
                        }
                        Add-ADGroupMember -Identity $g.DistinguishedName -Members $entry.DN @p -ErrorAction Stop
                        $added.Add($g.DistinguishedName)
                        $script:AStats.Members++
                        Write-Log "[Affecté]      $($a.Sam) -> $($g.Name)"
                    }
                    catch {
                        $script:AStats.Errors++
                        Write-Log "[ERREUR]       $($a.Sam) -> $($t.Name) : $($_.Exception.Message)"
                    }
                }
            }
            catch {
                $script:AStats.Errors++
                Write-Log "[ERREUR]       $($a.Sam) : $($_.Exception.Message)"
            }
            finally {
                if ($entry.Created -or $added.Count -gt 0) {
                    $entry.GroupsAdded = $added.ToArray()
                    $state.Accounts.Add([pscustomobject]$entry)
                }
            }
        }

        if (-not $whatIfMode) {
            if ($pwdRows.Count -gt 0 -and $pwdFile) {
                try {
                    # Ne jamais écraser un export précédent : ajout de l'horodatage si le fichier existe déjà
                    if (Test-Path -LiteralPath $pwdFile) {
                        $pwdFile = Join-Path (Split-Path -Parent $pwdFile) ('{0}_{1}{2}' -f [IO.Path]::GetFileNameWithoutExtension($pwdFile), $stamp, [IO.Path]::GetExtension($pwdFile))
                    }
                    $dir = Split-Path -Parent $pwdFile
                    if ($dir -and -not (Test-Path -LiteralPath $dir)) { [void](New-Item -ItemType Directory -Path $dir -Force) }
                    $pwdRows | Export-Csv -LiteralPath $pwdFile -NoTypeInformation -Delimiter ';' -Encoding UTF8
                    Protect-SecretFile -Path $pwdFile
                    Write-Log "Mots de passe initiaux exportés : $pwdFile (accès limité à $env:USERNAME - à supprimer après remise aux administrateurs)"
                }
                catch { $script:AStats.Errors++; Write-Log "[ERREUR] Export des mots de passe : $($_.Exception.Message)" }
            }
            if ($state.Accounts.Count -gt 0) { Save-AdminState $state $statePath }
        }
        $s = $script:AStats
        Write-Log "=== Fin : $($s.Created) créé(s), $($s.Existing) existant(s), $($s.Members) affectation(s), $($s.Simulated) simulée(s), $($s.Warnings) avertissement(s), $($s.Errors) erreur(s) ==="
    }
    catch { Write-Log "[ERREUR] $($_.Exception.Message)" }
    finally {
        $pwdRows.Clear()
        $script:form.Cursor = [System.Windows.Forms.Cursors]::Default
        $script:tabs.Enabled = $true
        $script:btnCreateAdmins.Enabled = $script:AdAvailable
        $script:btnRollback.Enabled = $script:AdAvailable
    }
}

function Invoke-AdminRollback {
    $ofd = New-Object System.Windows.Forms.OpenFileDialog
    $ofd.Filter = "Fichier d'état (*.json)|TierModel_AdminAccounts_State_*.json;*.json"
    $ofd.Title = "Fichier d'état généré par une création de comptes"
    if (Test-Path -LiteralPath $script:LogFolder) { $ofd.InitialDirectory = $script:LogFolder }
    if ($ofd.ShowDialog($script:form) -ne [System.Windows.Forms.DialogResult]::OK) { return }
    try { $st = Get-Content -LiteralPath $ofd.FileName -Raw -Encoding UTF8 | ConvertFrom-Json }
    catch { Show-Message "Fichier d'état illisible : $($_.Exception.Message)" 'Rollback' 'Warning'; return }
    $accounts = @($st.Accounts)
    if ($accounts.Count -eq 0) { Show-Message 'Aucun compte dans ce fichier.' 'Rollback' 'Information'; return }
    $whatIfMode = $script:chkWhatIf3.Checked
    $mode = 'ANNULATION RÉELLE'
    if ($whatIfMode) { $mode = 'SIMULATION (aucune modification)' }
    $nbCreated = @($accounts | Where-Object { $_.Created }).Count
    $ans = [System.Windows.Forms.MessageBox]::Show(
        "Mode : $mode`nFichier : $($ofd.FileName)`nComptes créés qui seront SUPPRIMÉS : $nbCreated`nComptes existants dont les affectations de groupes ajoutées seront retirées : $($accounts.Count - $nbCreated)`n`nContinuer ?",
        'Rollback', 'YesNo', 'Warning')
    if ($ans -ne [System.Windows.Forms.DialogResult]::Yes) { return }

    Initialize-AdParams
    if ($st.Server) { $script:AdParams.Server = [string]$st.Server }
    elseif ($script:txtServer.Text.Trim()) { $script:AdParams.Server = $script:txtServer.Text.Trim() }
    $p = $script:AdParams
    $script:tabs.Enabled = $false
    $script:form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    $ok = 0; $err = 0
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        Write-Log "=== Début rollback ($mode) - $($ofd.FileName) ==="
        [array]::Reverse($accounts)
        foreach ($a in $accounts) {
            try {
                $u = $null
                try { $u = Get-ADUser -Identity ([string]$a.DN) @p -ErrorAction Stop } catch { $u = $null }
                if (-not $u) { Write-Log "[Absent]       $($a.DN) : déjà supprimé ou introuvable"; continue }
                if ($a.Created) {
                    if ($whatIfMode) { Write-Log "[Simulation]   Supprimerait $($a.DN)"; continue }
                    Set-ADObject -Identity $u.DistinguishedName -ProtectedFromAccidentalDeletion $false @p -ErrorAction Stop
                    Remove-ADUser -Identity $u.DistinguishedName -Confirm:$false @p -ErrorAction Stop
                    Write-Log "[Supprimé]     $($a.DN)"
                    $ok++
                }
                else {
                    foreach ($gdn in @($a.GroupsAdded)) {
                        if ($whatIfMode) { Write-Log "[Simulation]   Retirerait $($a.Sam) du groupe $gdn"; continue }
                        Remove-ADGroupMember -Identity $gdn -Members $u.DistinguishedName -Confirm:$false @p -ErrorAction Stop
                        Write-Log "[Retiré]       $($a.Sam) <- $gdn"
                        $ok++
                    }
                }
            }
            catch { $err++; Write-Log "[ERREUR]       $($a.Sam) : $($_.Exception.Message)" }
        }
        Write-Log "=== Fin rollback : $ok action(s), $err erreur(s) ==="
    }
    catch { Write-Log "[ERREUR] $($_.Exception.Message)" }
    finally {
        $script:form.Cursor = [System.Windows.Forms.Cursors]::Default
        $script:tabs.Enabled = $true
    }
}

# ---- Interface de l'onglet 3 ----
$tab3 = New-Object System.Windows.Forms.TabPage
$script:tab3 = $tab3
$tab3.Text = 'Création Comptes Admins'
$tab3.UseVisualStyleBackColor = $true
[void]$tabs.TabPages.Add($tab3)
$tab3.AutoScroll = $true
$tab3.AutoScrollMinSize = New-Object System.Drawing.Size(1050, 745)

function New-Chk3 {
    param($Parent, [string]$Text, [int]$X, [int]$Y, [int]$W, [bool]$Checked)
    $c = New-Object System.Windows.Forms.CheckBox
    $c.Text = $Text; $c.Checked = $Checked
    $c.Location = New-Object System.Drawing.Point($X, $Y)
    $c.Size = New-Object System.Drawing.Size($W, 22)
    $Parent.Controls.Add($c)
    $c
}

# Convention de nommage des comptes
$ga1 = New-Group $tab3 "Convention de nommage des comptes d'administration" 10 10 540 215
[void](New-Lbl $ga1 'Modèle prédéfini' 10 22 145)
$script:cmbAPreset = New-Combo $ga1 160 22 370 @(($script:AdminPresets | ForEach-Object { $_.Label }) + 'Personnalisée')
[void](New-Lbl $ga1 'Nom de compte (SAM)' 10 52 145);   $script:txtPatSam  = New-Txt $ga1 160 52 370
[void](New-Lbl $ga1 'Nom affiché / CN' 10 80 145);      $script:txtPatDisp = New-Txt $ga1 160 80 370
[void](New-Lbl $ga1 'Suffixe UPN (vide = domaine)' 10 108 150); $script:txtUpnSuffix = New-Txt $ga1 160 108 370
[void](New-Lbl $ga1 'Profil de groupes' 10 136 145)
$script:cmbProfile = New-Combo $ga1 160 136 370 $script:AdminProfiles
$script:cmbProfile.SelectedIndex = 0
[void](New-Lbl $ga1 'Fichier mots de passe' 10 164 145)
$script:txtPwdFile = New-Txt $ga1 160 164 370 (Join-Path $script:LogFolder 'TierModel_AdminAccounts_InitialPasswords.csv')
$lblTok3 = New-Object System.Windows.Forms.Label
$lblTok3.Text = '{N} Tier  {Login} compte standard  {First} prénom  {Last} nom  {LAST} NOM  {F} initiale prénom  {L} initiale nom. Max. 20 car. pour le SAM.'
$lblTok3.ForeColor = [System.Drawing.Color]::DimGray
$lblTok3.Location = New-Object System.Drawing.Point(10, 190); $lblTok3.Size = New-Object System.Drawing.Size(525, 18)
$ga1.Controls.Add($lblTok3)

# Tiers + actions
$ga2 = New-Group $tab3 'Tiers des comptes' 560 10 170 215
$script:chkAT0 = New-Chk3 $ga2 'Tier 0' 15 24 140 $true
$script:chkAT1 = New-Chk3 $ga2 'Tier 1' 15 48 140 $false
$script:chkAT2 = New-Chk3 $ga2 'Tier 2' 15 72 140 $false
$script:btnCreateAdmins = New-Object System.Windows.Forms.Button
$script:btnCreateAdmins.Text = 'Créer les comptes'
$script:btnCreateAdmins.Location = New-Object System.Drawing.Point(10, 108); $script:btnCreateAdmins.Size = New-Object System.Drawing.Size(150, 38)
$script:btnCreateAdmins.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
$script:btnCreateAdmins.Enabled = $script:AdAvailable
$ga2.Controls.Add($script:btnCreateAdmins)
$script:btnRollback = New-Object System.Windows.Forms.Button
$script:btnRollback.Text = 'Rollback...'
$script:btnRollback.Location = New-Object System.Drawing.Point(10, 154); $script:btnRollback.Size = New-Object System.Drawing.Size(150, 32)
$script:btnRollback.Enabled = $script:AdAvailable
$ga2.Controls.Add($script:btnRollback)

# Options
$ga3 = New-Group $tab3 'Options de création' 740 10 300 215
$script:chkWhatIf3    = New-Chk3 $ga3 'Mode simulation (aucun compte créé)' 10 22 285 $true
$script:chkProtect3   = New-Chk3 $ga3 'Protéger contre la suppression accidentelle' 10 44 285 $true
$script:chkChangePwd  = New-Chk3 $ga3 'Changer le mot de passe à la 1re connexion' 10 66 285 $true
$script:chkNotDeleg   = New-Chk3 $ga3 'Compte sensible : ne peut pas être délégué' 10 88 285 $true
$script:chkProtUsers  = New-Chk3 $ga3 "Ajouter au groupe 'Protected Users'" 10 110 285 $true
$script:chkSmartcard  = New-Chk3 $ga3 'Carte à puce obligatoire (SmartcardLogonRequired)' 10 132 285 $false
[void](New-Lbl $ga3 'Longueur mot de passe' 10 160 150)
$script:numPwd = New-Object System.Windows.Forms.NumericUpDown
$script:numPwd.Minimum = 14; $script:numPwd.Maximum = 64; $script:numPwd.Value = $PasswordLength
$script:numPwd.Location = New-Object System.Drawing.Point(170, 160); $script:numPwd.Size = New-Object System.Drawing.Size(60, 23)
$ga3.Controls.Add($script:numPwd)
$lblOpt3 = New-Object System.Windows.Forms.Label
$lblOpt3.Text = 'Domaine / contrôleur : onglet Création Structure.'
$lblOpt3.ForeColor = [System.Drawing.Color]::DimGray
$lblOpt3.Location = New-Object System.Drawing.Point(10, 190); $lblOpt3.Size = New-Object System.Drawing.Size(285, 18)
$ga3.Controls.Add($lblOpt3)

# Barre d'outils
$script:ToolX3 = 10
function New-Btn3 {
    param([string]$Text, [int]$W)
    $b = New-Object System.Windows.Forms.Button
    $b.Text = $Text
    $b.Location = New-Object System.Drawing.Point($script:ToolX3, 232)
    $b.Size = New-Object System.Drawing.Size($W, 28)
    $tab3.Controls.Add($b)
    $script:ToolX3 += $W + 5
    $b
}
$script:btnApplyConv = New-Btn3 'Appliquer la convention' 150
$script:btnAddAdm    = New-Btn3 '+ Administrateur' 110
$script:btnFromAd    = New-Btn3 'Depuis AD...' 90
$script:btnCsv       = New-Btn3 'Import CSV...' 95
$script:btnAOU       = New-Btn3 'OU cible...' 85
$script:btnAGrp      = New-Btn3 'Groupes...' 80
$script:btnADel      = New-Btn3 'Retirer' 65
$script:btnACheckAd  = New-Btn3 'Vérifier dans AD' 110
$script:btnACheck    = New-Btn3 'Tout cocher' 85
$script:btnAUncheck  = New-Btn3 'Tout décocher' 95

# Tableau des comptes
$script:dga = New-Object System.Windows.Forms.DataGridView
$dga = $script:dga
$dga.Location = New-Object System.Drawing.Point(10, 266)
$dga.Size = New-Object System.Drawing.Size(1030, 326)
$dga.Anchor = [System.Windows.Forms.AnchorStyles]'Top,Bottom,Left,Right'
$dga.BackgroundColor = [System.Drawing.Color]::White
$dga.AllowUserToAddRows = $false
$dga.AllowUserToDeleteRows = $false
$dga.AllowUserToResizeRows = $false
$dga.RowHeadersVisible = $false
$dga.MultiSelect = $true
$dga.SelectionMode = 'FullRowSelect'
$dga.ColumnHeadersHeightSizeMode = 'DisableResizing'
$dga.ColumnHeadersHeight = 28
$dga.DefaultCellStyle.WrapMode = [System.Windows.Forms.DataGridViewTriState]::True
$dga.AutoSizeRowsMode = 'AllCells'
$dga.AllowUserToResizeColumns = $true
$dga.ScrollBars = 'Both'

function New-ACol {
    param([string]$Header, [int]$Width, [bool]$ReadOnly = $false)
    $c = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
    $c.HeaderText = $Header; $c.AutoSizeMode = 'None'; $c.Width = $Width; $c.MinimumWidth = 40; $c.ReadOnly = $ReadOnly
    $c
}
$aCreate = New-Object System.Windows.Forms.DataGridViewCheckBoxColumn
$aCreate.HeaderText = 'Créer'; $aCreate.Width = 50; $aCreate.AutoSizeMode = 'None'
[void]$dga.Columns.AddRange([System.Windows.Forms.DataGridViewColumn[]]@(
    $aCreate,
    (New-ACol 'Tier' 45 $true),
    (New-ACol 'Prénom' 85),
    (New-ACol 'Nom' 95),
    (New-ACol 'Login standard' 100),
    (New-ACol 'Compte admin (SAM)' 140),
    (New-ACol 'Nom affiché / CN' 170),
    (New-ACol 'OU cible' 200),
    (New-ACol 'Membre de (groupes AD, séparés par ;)' 220),
    (New-ACol 'Statut AD' 150 $true)))
$tab3.Controls.Add($dga)

$script:lblACount = New-Object System.Windows.Forms.Label
$script:lblACount.Location = New-Object System.Drawing.Point(10, 596)
$script:lblACount.Size = New-Object System.Drawing.Size(250, 18)
$script:lblACount.Anchor = [System.Windows.Forms.AnchorStyles]'Bottom,Left'
$tab3.Controls.Add($script:lblACount)
$lblAHint = New-Object System.Windows.Forms.Label
$lblAHint.Text = "Cellules modifiables | Vert = ajouté | Un compte par personne ET par Tier | Groupes/OU : liés à l'onglet Création Groupes / Structure"
$lblAHint.Location = New-Object System.Drawing.Point(265, 596)
$lblAHint.Size = New-Object System.Drawing.Size(775, 18)
$lblAHint.Anchor = [System.Windows.Forms.AnchorStyles]'Bottom,Left,Right'
$tab3.Controls.Add($lblAHint)

$ga5 = New-Group $tab3 'Journal' 10 618 1030 122
$ga5.Anchor = [System.Windows.Forms.AnchorStyles]'Bottom,Left,Right'
$script:txtLog3 = New-Object System.Windows.Forms.TextBox
$script:txtLog3.Multiline = $true; $script:txtLog3.ReadOnly = $true; $script:txtLog3.ScrollBars = 'Vertical'
$script:txtLog3.Font = New-Object System.Drawing.Font('Consolas', 9)
$script:txtLog3.Location = New-Object System.Drawing.Point(10, 20); $script:txtLog3.Size = New-Object System.Drawing.Size(1010, 92)
$script:txtLog3.Anchor = [System.Windows.Forms.AnchorStyles]'Top,Bottom,Left,Right'
$ga5.Controls.Add($script:txtLog3)

# ---- Événements de l'onglet 3 ----
function Set-AdminPreset {
    param([int]$Index)
    $p = $script:AdminPresets[$Index]
    $script:ApplyingAPreset = $true
    try { $script:txtPatSam.Text = $p.Sam; $script:txtPatDisp.Text = $p.Display }
    finally { $script:ApplyingAPreset = $false }
}
$script:cmbAPreset.add_SelectedIndexChanged({
    if ($script:ApplyingAPreset) { return }
    $i = $script:cmbAPreset.SelectedIndex
    if ($i -ge 0 -and $i -lt $script:AdminPresets.Count) { Set-AdminPreset $i }
})
foreach ($c in @($script:txtPatSam, $script:txtPatDisp)) {
    $c.add_TextChanged({
        if ($script:ApplyingAPreset) { return }
        $script:ApplyingAPreset = $true
        $script:cmbAPreset.SelectedIndex = $script:AdminPresets.Count
        $script:ApplyingAPreset = $false
    })
}
$script:btnApplyConv.add_Click({ Update-AdminNames })
$script:btnAddAdm.add_Click({ Add-AdminFromDialog })
$script:btnFromAd.add_Click({ Add-AdminFromAd })
$script:btnCsv.add_Click({ Import-AdminCsv })
$script:btnAOU.add_Click({ Set-SelectedAdminOU })
$script:btnAGrp.add_Click({ Set-SelectedAdminGroups })
$script:btnADel.add_Click({ Remove-AdminRows })
$script:btnACheckAd.add_Click({ Test-AdminStatus })
$script:btnACheck.add_Click({ Set-AllAdminsChecked $true })
$script:btnAUncheck.add_Click({ Set-AllAdminsChecked $false })
$script:btnCreateAdmins.add_Click({ Invoke-AdminCreation })
$script:btnRollback.add_Click({ Invoke-AdminRollback })
$script:dga.add_CurrentCellDirtyStateChanged({
    if ($script:dga.IsCurrentCellDirty) { $script:dga.CommitEdit([System.Windows.Forms.DataGridViewDataErrorContexts]::Commit) }
})
$script:dga.add_CellValueChanged({ Update-AdminCount })
$script:dga.add_DataError({ param($s, $e) $e.ThrowException = $false })

$script:tip.SetToolTip($script:btnApplyConv, "Recalcule noms, OU et groupes de toutes les lignes depuis la convention,`nla structure d'OU (onglet 1) et le catalogue de groupes (onglet 2).")
$script:tip.SetToolTip($script:btnRollback, "Annule un déploiement à partir de son fichier d'état JSON :`nsupprime les comptes créés et retire les groupes ajoutés.`nRespecte le mode simulation.")

$script:cmbAPreset.SelectedIndex = 0
Set-AdminPreset 0
Update-AdminCount

# ----------------------------------------------------------------------------
# Démarrage (onglet 1)
# ----------------------------------------------------------------------------
$script:cmbPreset.SelectedIndex = 0
Set-Preset 0
[void]$form.ShowDialog()
