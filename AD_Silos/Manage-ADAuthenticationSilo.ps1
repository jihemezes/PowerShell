#Requires -Version 5.1
<#
.SYNOPSIS
    Gestionnaire GRAPHIQUE de silos d'authentification Active Directory.

.DESCRIPTION
    *** OUTIL A INTERFACE GRAPHIQUE (Windows Forms) ***
    Ce script ne prend AUCUN parametre : il s'utilise exclusivement via sa fenetre.
    Lancez-le (clic droit > Executer avec PowerShell, ou  .\Manage-ADAuthSilo.ps1  depuis une
    console PowerShell) puis renseignez les onglets. Il ne s'execute pas en mode
    non interactif (tache planifiee, session sans bureau, Server Core sans session graphique).

    Il permet de declarer un silo d'authentification et sa politique associee, d'y rattacher
    des utilisateurs, des ordinateurs et des comptes de service, et surtout de verifier la
    configuration AVANT application afin d'eviter les blocages classiques (comptes verrouilles
    hors de leurs machines, assignation sans droit d'acces, enforcement premature, etc.).

    ------------------------------------------------------------------------------------
    PREREQUIS
    ------------------------------------------------------------------------------------
    Poste d'execution
      - Windows joint au domaine (ou ayant une ligne de vue sur un controleur de domaine),
        avec une session graphique interactive.
      - Windows PowerShell 5.1 (recommande). Le thread doit etre STA (valeur par defaut de
        powershell.exe).
      - Module PowerShell ActiveDirectory (RSAT : "Outils AD DS et AD LDS" /
        RSAT-AD-PowerShell), cmdlets *-ADAuthenticationPolicy* et *-ADAuthenticationPolicySilo*.
    Domaine / infrastructure
      - Niveau fonctionnel du domaine : Windows Server 2012 R2 minimum.
      - Controleurs de domaine sous Windows Server 2012 R2 ou ulterieur.
      - Pour la restriction de connexion (UserAllowedToAuthenticateFrom) : GPO activees sur
        les DC ("Prise en charge KDC des revendications, de l'authentification composee et du
        blindage Kerberos") ET sur les clients ("Prise en charge client Kerberos des
        revendications, de l'authentification composee et du blindage Kerberos").
      - Machines concernees : Windows 8 / Windows Server 2012 minimum.
    Droits
      - Droits suffisants pour creer/modifier des objets dans le conteneur
        "CN=AuthN Policy Configuration,CN=Services,CN=Configuration" (Domain Admins /
        Enterprise Admins ou delegation equivalente) et pour modifier les comptes cibles.

    ------------------------------------------------------------------------------------
    CAPACITES ET FONCTIONNALITES (par onglet)
    ------------------------------------------------------------------------------------
    1. Silo et politique : nom du silo, description, nom de la politique (propose
       automatiquement <silo>-Policy), duree de vie du TGT des utilisateurs, restriction
       optionnelle de la connexion aux seuls ordinateurs du silo, mode Audit (defaut) ou Enforce.
    2. Utilisateurs / 3. Ordinateurs / 4. Comptes de service (gMSA/MSA) : recherche dans l'AD
       (jusqu'a 200 resultats, jokers * acceptes), ajout unitaire ou par groupe
       (expansion recursive des membres), retrait de la liste.
    5. Verifications : controles automatiques classes OK / INFO / AVERT / ERREUR, notamment
         - niveau fonctionnel du domaine et validite des noms ;
         - duree de vie du TGT (45 minutes minimum) ;
         - compte deja assigne a un autre silo (un compte = un seul silo) ;
         - comptes desactives ;
         - restriction de connexion sans ordinateur dans le silo ;
         - ordinateurs trop anciens ou non Windows (revendications non prises en charge) ;
         - absence de controleur de domaine dans le silo ;
         - risque de verrouillage de l'administrateur courant (son poste n'est pas dans le silo) ;
         - passage direct en Enforce sans phase d'Audit.
       L'application est REFUSEE tant qu'une ERREUR subsiste.
    6. Commandes : apercu des cmdlets exactes qui seront executees, regeneration et
       enregistrement en fichier .ps1 (reutilisable / auditable / rejouable).
    7. Silos existants : liste des silos, mode, politique, comptes autorises ; diagnostic par
       compte (acces accorde / silo assigne) ; bascule Audit <-> Enforce (refusee s'il existe
       des comptes assignes sans droit d'acces) ; retrait de comptes ; reparation des
       incoherences ; suppression propre d'un silo.
    Ordre d'application : politique, silo, puis pour chaque compte (ordinateurs, services,
    utilisateurs) droit d'acces PUIS assignation. Un journal est affiche en bas de fenetre.

    ------------------------------------------------------------------------------------
    CONTRAINTES A CONNAITRE
    ------------------------------------------------------------------------------------
      - Un compte ne peut appartenir qu'a un seul silo.
      - Un silo n'accepte pas de groupes : les groupes sont convertis en comptes au moment de
        l'ajout (instantane). Les futurs membres du groupe ne sont PAS ajoutes automatiquement.
      - Une assignation sans droit d'acces bloque l'authentification du compte en Enforce.
      - Si la restriction de connexion est activee, tous les ordinateurs utilises par les
        utilisateurs du silo (postes, serveurs d'administration, DC si connexion RDP/console)
        doivent etre membres du silo.
      - Les comptes du silo doivent s'authentifier en Kerberos.
      - Conservez toujours un compte d'urgence (break-glass) HORS silo.

    ------------------------------------------------------------------------------------
    LIMITES DE L'OUTIL
    ------------------------------------------------------------------------------------
      - Interface graphique uniquement : pas de mode ligne de commande, pas de simulation
        (-WhatIf) ; utilisez l'onglet "Commandes" pour relire ce qui sera execute.
      - Un seul domaine / une seule foret a la fois (celui du contexte de l'utilisateur).
      - Seuls sont geres : la duree de vie du TGT des utilisateurs et la restriction
        "utilisateurs autorises a se connecter depuis les ordinateurs du silo". Non geres :
        durees de vie TGT des ordinateurs/services, UserAllowedToAuthenticateTo, conditions
        de revendications personnalisees, groupe Protected Users.
      - La mise a jour d'un silo existant ajoute des comptes mais ne retire pas ceux absents
        de la liste (utiliser l'onglet 7).
      - La suppression d'un silo conserve sa politique d'authentification.
      - Les GPO Kerberos (revendications / blindage), l'etat reel des clients et les
        evenements d'audit (journal AuthenticationPolicyFailures-DomainController) ne sont
        pas verifies automatiquement : un simple rappel est affiche.
      - Le developpement des groupes et la recherche sont limites aux objets lisibles par
        le compte qui execute l'outil.

.NOTES
    Commencez TOUJOURS en mode Audit, analysez les evenements d'audit sur les controleurs de
    domaine, testez avec un compte pilote, puis seulement passez en Enforce.
    Fichier encode en UTF-8 avec BOM (necessaire a PowerShell 5.1 pour les accents).

.EXAMPLE
    .\Manage-ADAuthSilo.ps1
    Ouvre la fenetre de gestion des silos (aucun parametre).
#>

Set-StrictMode -Off
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    [void][System.Windows.Forms.MessageBox]::Show("Le module PowerShell ActiveDirectory (RSAT) est introuvable.`r`nInstallez RSAT-AD-PowerShell puis relancez le script.", "Module manquant", 'OK', 'Error')
    exit 1
}
Import-Module ActiveDirectory -ErrorAction Stop

$script:polEdited = $false
$script:picked    = @()

# ---------------------------------------------------------------- Helpers generiques
function P($x, $y) { New-Object System.Drawing.Point($x, $y) }
function Z($w, $h) { New-Object System.Drawing.Size($w, $h) }

function New-Label([string]$text, $x, $y, $w = 290) {
    $l = New-Object System.Windows.Forms.Label
    $l.Text = $text; $l.Location = (P $x $y); $l.Size = (Z $w 22)
    $l.TextAlign = 'MiddleLeft'
    $l
}
function New-TextBox($x, $y, $w = 380) {
    $t = New-Object System.Windows.Forms.TextBox
    $t.Location = (P $x $y); $t.Size = (Z $w 24)
    $t
}
function New-Button([string]$text, $x, $y, $w = 150, $h = 28) {
    $b = New-Object System.Windows.Forms.Button
    $b.Text = $text; $b.Location = (P $x $y); $b.Size = (Z $w $h)
    $b
}
function New-ListView {
    $lv = New-Object System.Windows.Forms.ListView
    $lv.View = 'Details'; $lv.FullRowSelect = $true; $lv.GridLines = $true; $lv.MultiSelect = $true
    $lv
}

function Q([string]$s) { "'" + ($s -replace "'", "''") + "'" }

function Escape-Ldap([string]$s, [switch]$KeepWildcard) {
    $s = $s -replace '\\', '\5c'
    $s = $s -replace '\(', '\28'
    $s = $s -replace '\)', '\29'
    if (-not $KeepWildcard) { $s = $s -replace '\*', '\2a' }
    $s
}

function Log([string]$m) {
    $script:txtLog.AppendText(("[{0}] {1}`r`n" -f (Get-Date -Format 'HH:mm:ss'), $m))
    [System.Windows.Forms.Application]::DoEvents()
}

function Step([string]$text, [string]$kind) { [pscustomobject]@{ Text = $text; Kind = $kind } }

# ---------------------------------------------------------------- Recherche AD
function Find-AD([string]$Kind, [string]$Query) {
    $q = Escape-Ldap $Query -KeepWildcard
    switch ($Kind) {
        'User'     { Get-ADUser -LDAPFilter "(&(objectCategory=person)(objectClass=user)(anr=$q))" -Properties Enabled, Description -ResultSetSize 200 }
        'Computer' { Get-ADComputer -LDAPFilter "(anr=$q)" -Properties Enabled, OperatingSystem, PrimaryGroupID, Description -ResultSetSize 200 }
        'Service'  { Get-ADServiceAccount -LDAPFilter "(anr=$q)" -Properties Enabled, Description -ResultSetSize 200 }
        'Group'    { Get-ADGroup -LDAPFilter "(anr=$q)" -Properties Description -ResultSetSize 200 }
    }
}

function New-Acct($o, [string]$kind) {
    [pscustomobject]@{
        Kind = $kind; Name = $o.Name; Sam = $o.SamAccountName; Dn = $o.DistinguishedName
        Enabled = $o.Enabled; OS = $o.OperatingSystem; Pgid = $o.PrimaryGroupID
    }
}

function Show-SearchDialog([string]$Kind, [string]$Title) {
    $script:picked = @()
    $script:sdKind = $Kind
    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text = $Title; $dlg.Size = (Z 800 500); $dlg.StartPosition = 'CenterParent'
    $dlg.MinimizeBox = $false; $dlg.MaximizeBox = $false

    $dlg.Controls.Add((New-Label "Nom (les * sont acceptes) :" 10 12 170))
    $script:sdTb = New-TextBox 185 12 420
    $btnS = New-Button "Rechercher" 615 10 150 26
    $script:sdLv = New-ListView
    $script:sdLv.Location = (P 10 48); $script:sdLv.Size = (Z 765 360)
    $script:sdLv.Anchor = 'Top,Bottom,Left,Right'
    [void]$script:sdLv.Columns.Add('Nom', 230); [void]$script:sdLv.Columns.Add('SAM', 150); [void]$script:sdLv.Columns.Add('Info', 380)
    $btnOk = New-Button "Ajouter la selection" 520 420 150 28
    $btnOk.Anchor = 'Bottom,Right'
    $btnCancel = New-Button "Annuler" 680 420 95 28
    $btnCancel.Anchor = 'Bottom,Right'
    $btnCancel.DialogResult = 'Cancel'
    $dlg.CancelButton = $btnCancel
    $dlg.AcceptButton = $btnS

    $btnS.Add_Click({
        $script:sdLv.Items.Clear()
        if ([string]::IsNullOrWhiteSpace($script:sdTb.Text)) { return }
        try {
            $res = @(Find-AD $script:sdKind $script:sdTb.Text.Trim())
            foreach ($o in $res) {
                $it = New-Object System.Windows.Forms.ListViewItem([string]$o.Name)
                [void]$it.SubItems.Add([string]$o.SamAccountName)
                $info = if ($o.OperatingSystem) { $o.OperatingSystem } elseif ($o.Description) { $o.Description } else { $o.DistinguishedName }
                [void]$it.SubItems.Add([string]$info)
                $it.Tag = $o
                [void]$script:sdLv.Items.Add($it)
            }
            if ($res.Count -eq 0) { [void][System.Windows.Forms.MessageBox]::Show("Aucun resultat.", "Recherche") }
        } catch {
            [void][System.Windows.Forms.MessageBox]::Show($_.Exception.Message, "Erreur de recherche", 'OK', 'Error')
        }
    })
    $btnOk.Add_Click({
        $script:picked = @($script:sdLv.SelectedItems | ForEach-Object { $_.Tag })
        $dlg.DialogResult = 'OK'
        $dlg.Close()
    })
    $dlg.Controls.AddRange(@($script:sdTb, $btnS, $script:sdLv, $btnOk, $btnCancel))
    [void]$dlg.ShowDialog()
    $dlg.Dispose()
    return , @($script:picked)
}

function Expand-Groups([string]$Kind, $groups) {
    foreach ($g in $groups) {
        try {
            $members = @(Get-ADGroupMember -Identity $g.DistinguishedName -Recursive -ErrorAction Stop)
            Log ("Groupe '{0}' : {1} objet(s) trouves (recursif)." -f $g.Name, $members.Count)
            foreach ($m in $members) {
                if ($Kind -eq 'User' -and $m.objectClass -eq 'user') {
                    Get-ADUser -Identity $m.DistinguishedName -Properties Enabled
                } elseif ($Kind -eq 'Computer' -and $m.objectClass -eq 'computer') {
                    Get-ADComputer -Identity $m.DistinguishedName -Properties Enabled, OperatingSystem, PrimaryGroupID
                }
            }
        } catch {
            Log ("ERREUR lecture du groupe '{0}' : {1}" -f $g.Name, $_.Exception.Message)
        }
    }
}

function Add-ToList($lv, $a) {
    if ($lv.Items.ContainsKey($a.Dn)) { return }
    $it = New-Object System.Windows.Forms.ListViewItem([string]$a.Name)
    $it.Name = $a.Dn
    [void]$it.SubItems.Add([string]$a.Sam)
    $st = if ($a.Enabled -eq $false) { 'Desactive' } else { 'Actif' }
    [void]$it.SubItems.Add($st)
    [void]$it.SubItems.Add([string]$a.OS)
    [void]$it.SubItems.Add([string]$a.Dn)
    if ($a.Enabled -eq $false) { $it.ForeColor = [System.Drawing.Color]::Gray }
    $it.Tag = $a
    [void]$lv.Items.Add($it)
}

function Get-Accts($lv) { @($lv.Items | ForEach-Object { $_.Tag }) }

# ---------------------------------------------------------------- Fenetre principale
$form = New-Object System.Windows.Forms.Form
$form.Text = "Gestionnaire de silos d'authentification Active Directory"
$form.Size = (Z 1100 800); $form.StartPosition = 'CenterScreen'
$form.Font = New-Object System.Drawing.Font('Segoe UI', 9)

$tabs = New-Object System.Windows.Forms.TabControl
$tabs.Dock = 'Fill'

# ---- Onglet Configuration
$tpCfg = New-Object System.Windows.Forms.TabPage; $tpCfg.Text = '1. Silo et politique'
$tpCfg.Controls.Add((New-Label 'Nom du silo :' 20 20))
$txtSilo = New-TextBox 320 20 380
$tpCfg.Controls.Add($txtSilo)
$tpCfg.Controls.Add((New-Label 'Description :' 20 55))
$txtDesc = New-TextBox 320 55 380
$tpCfg.Controls.Add($txtDesc)
$tpCfg.Controls.Add((New-Label "Nom de la politique d'authentification :" 20 90))
$txtPol = New-TextBox 320 90 380
$tpCfg.Controls.Add($txtPol)
$tpCfg.Controls.Add((New-Label 'Duree de vie du TGT des utilisateurs (min, 45 mini) :' 20 125))
$numTgt = New-Object System.Windows.Forms.NumericUpDown
$numTgt.Location = (P 320 125); $numTgt.Size = (Z 100 24)
$numTgt.Minimum = 1; $numTgt.Maximum = 100000; $numTgt.Value = 600
$tpCfg.Controls.Add($numTgt)

$chkRestrict = New-Object System.Windows.Forms.CheckBox
$chkRestrict.Text = "Limiter la connexion des utilisateurs du silo aux ordinateurs du silo (UserAllowedToAuthenticateFrom)"
$chkRestrict.Location = (P 20 165); $chkRestrict.Size = (Z 900 24)
$tpCfg.Controls.Add($chkRestrict)

$gbMode = New-Object System.Windows.Forms.GroupBox
$gbMode.Text = 'Mode'; $gbMode.Location = (P 20 200); $gbMode.Size = (Z 700 62)
$rbAudit = New-Object System.Windows.Forms.RadioButton
$rbAudit.Text = "Audit (recommande : journalise sans bloquer)"; $rbAudit.Checked = $true
$rbAudit.Location = (P 15 24); $rbAudit.Size = (Z 320 24)
$rbEnforce = New-Object System.Windows.Forms.RadioButton
$rbEnforce.Text = "Enforce (applique et bloque)"; $rbEnforce.Location = (P 350 24); $rbEnforce.Size = (Z 300 24)
$gbMode.Controls.AddRange(@($rbAudit, $rbEnforce))
$tpCfg.Controls.Add($gbMode)

$lblInfo = New-Object System.Windows.Forms.Label
$lblInfo.Location = (P 20 280); $lblInfo.Size = (Z 1020 260)
$lblInfo.Text = @"
Bonnes pratiques pour eviter les blocages :

  - Commencez TOUJOURS en mode Audit. Analysez le journal "Microsoft-Windows-Authentication/AuthenticationPolicyFailures-DomainController" sur les controleurs de domaine, puis passez en Enforce.
  - Un silo n'accepte pas de groupes : les groupes sont developpes en comptes (instantane). Les futurs membres des groupes devront etre ajoutes au silo.
  - Si vous limitez la connexion aux ordinateurs du silo, TOUS les ordinateurs utilises par ces comptes (postes, serveurs d'administration, controleurs de domaine si connexion RDP/console) doivent etre dans le silo.
  - Prerequis : niveau fonctionnel du domaine 2012 R2 minimum ; GPO "Prise en charge KDC des revendications, de l'authentification composee et du blindage Kerberos" sur les DC ; GPO "Prise en charge client Kerberos des revendications..." sur les machines (Windows 8 / Server 2012 minimum).
  - Un compte ne peut appartenir qu'a un seul silo. Conservez un compte d'urgence (break-glass) hors silo.
  - Ordre applique par l'outil : politique, silo, puis pour chaque compte : droit d'acces PUIS assignation (une assignation sans droit d'acces bloque le compte).
"@
$tpCfg.Controls.Add($lblInfo)

$txtSilo.Add_TextChanged({ if (-not $script:polEdited) { $txtPol.Text = ($txtSilo.Text.Trim() + '-Policy') } })
$txtPol.Add_KeyPress({ $script:polEdited = $true })

# ---- Onglets membres
function New-MemberTab([string]$Title, [string]$Kind, [bool]$Groups, [string]$Help) {
    $tp = New-Object System.Windows.Forms.TabPage; $tp.Text = $Title
    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Text = $Help; $lbl.Dock = 'Top'; $lbl.Height = 46
    $lbl.Padding = New-Object System.Windows.Forms.Padding(6)
    $lv = New-ListView; $lv.Dock = 'Fill'
    foreach ($c in @(@('Nom', 200), @('SAM', 150), @('Etat', 80), @('Systeme', 200), @('DN', 500))) { [void]$lv.Columns.Add($c[0], $c[1]) }
    $pnl = New-Object System.Windows.Forms.Panel; $pnl.Dock = 'Bottom'; $pnl.Height = 42
    $ctx = @{ Kind = $Kind; List = $lv; Title = $Title }

    $b1 = New-Button 'Ajouter des comptes...' 10 7 170
    $b1.Tag = $ctx
    $b1.Add_Click({
        param($s, $e)
        $t = $s.Tag
        $sel = Show-SearchDialog $t.Kind ("Rechercher - " + $t.Title)
        foreach ($o in $sel) { Add-ToList $t.List (New-Acct $o $t.Kind) }
    })
    $pnl.Controls.Add($b1)

    $x = 190
    if ($Groups) {
        $b2 = New-Button 'Ajouter un groupe (expansion)...' 190 7 220
        $b2.Tag = $ctx
        $b2.Add_Click({
            param($s, $e)
            $t = $s.Tag
            $grp = Show-SearchDialog 'Group' "Rechercher un groupe"
            if (@($grp).Count -eq 0) { return }
            $n = 0
            foreach ($o in @(Expand-Groups $t.Kind $grp)) { Add-ToList $t.List (New-Acct $o $t.Kind); $n++ }
            Log ("{0} compte(s) ajoute(s) depuis les groupes selectionnes." -f $n)
        })
        $pnl.Controls.Add($b2)
        $x = 420
    }
    $b3 = New-Button 'Retirer la selection' $x 7 150
    $b3.Tag = $ctx
    $b3.Add_Click({
        param($s, $e)
        $t = $s.Tag
        foreach ($i in @($t.List.SelectedItems)) { $t.List.Items.Remove($i) }
    })
    $pnl.Controls.Add($b3)

    $tp.Controls.Add($lv); $tp.Controls.Add($pnl); $tp.Controls.Add($lbl)
    $lv.BringToFront()
    return [pscustomobject]@{ Page = $tp; List = $lv }
}

$tUsers = New-MemberTab '2. Utilisateurs' 'User' $true "Comptes utilisateurs soumis au silo. Les groupes sont developpes en comptes (instantane)."
$tComps = New-MemberTab '3. Ordinateurs' 'Computer' $true "Ordinateurs du silo. Si la restriction de connexion est activee, incluez tous les postes/serveurs utilises par les utilisateurs (et les DC si necessaire)."
$tSvc   = New-MemberTab '4. Comptes de service' 'Service' $false "Comptes de service geres (gMSA / MSA) membres du silo (optionnel)."
$lvUsers = $tUsers.List; $lvComps = $tComps.List; $lvSvc = $tSvc.List

# ---- Onglet Verifications
$tpCheck = New-Object System.Windows.Forms.TabPage; $tpCheck.Text = '5. Verifications'
$lvCheck = New-ListView; $lvCheck.Dock = 'Fill'; $lvCheck.MultiSelect = $false
[void]$lvCheck.Columns.Add('Niveau', 90); [void]$lvCheck.Columns.Add('Message', 1300)
$tpCheck.Controls.Add($lvCheck)

# ---- Onglet Apercu
$tpPrev = New-Object System.Windows.Forms.TabPage; $tpPrev.Text = '6. Commandes'
$txtPrev = New-Object System.Windows.Forms.TextBox
$txtPrev.Multiline = $true; $txtPrev.ReadOnly = $true; $txtPrev.ScrollBars = 'Both'; $txtPrev.WordWrap = $false
$txtPrev.Font = New-Object System.Drawing.Font('Consolas', 9); $txtPrev.Dock = 'Fill'
$pnlPrev = New-Object System.Windows.Forms.Panel; $pnlPrev.Dock = 'Bottom'; $pnlPrev.Height = 42
$btnPrevRef = New-Button 'Regenerer' 10 7 120
$btnPrevSave = New-Button 'Enregistrer en .ps1...' 140 7 170
$pnlPrev.Controls.AddRange(@($btnPrevRef, $btnPrevSave))
$tpPrev.Controls.Add($txtPrev); $tpPrev.Controls.Add($pnlPrev); $txtPrev.BringToFront()

# ---- Onglet Silos existants
$tpSilos = New-Object System.Windows.Forms.TabPage; $tpSilos.Text = '7. Silos existants'
$split = New-Object System.Windows.Forms.SplitContainer
$split.Dock = 'Fill'; $split.Orientation = 'Horizontal'; $split.SplitterDistance = 170
$lvS = New-ListView; $lvS.Dock = 'Fill'; $lvS.MultiSelect = $false
foreach ($c in @(@('Silo', 220), @('Mode', 80), @('Politique utilisateurs', 420), @('Comptes autorises', 120))) { [void]$lvS.Columns.Add($c[0], $c[1]) }
$lvD = New-ListView; $lvD.Dock = 'Fill'
foreach ($c in @(@('Compte (DN)', 450), @('Acces accorde', 100), @('Assigne', 80), @('Diagnostic', 500))) { [void]$lvD.Columns.Add($c[0], $c[1]) }
$split.Panel1.Controls.Add($lvS); $split.Panel2.Controls.Add($lvD)
$pnlS = New-Object System.Windows.Forms.Panel; $pnlS.Dock = 'Top'; $pnlS.Height = 42
$bRef = New-Button 'Actualiser' 10 7 100
$bTog = New-Button 'Basculer Audit/Enforce' 120 7 170
$bRem = New-Button 'Retirer le compte selectionne' 300 7 200
$bFix = New-Button 'Reparer les incoherences' 510 7 180
$bDel = New-Button 'Supprimer le silo' 700 7 140
$pnlS.Controls.AddRange(@($bRef, $bTog, $bRem, $bFix, $bDel))
$tpSilos.Controls.Add($split); $tpSilos.Controls.Add($pnlS); $split.BringToFront()

$tabs.TabPages.AddRange(@($tpCfg, $tUsers.Page, $tComps.Page, $tSvc.Page, $tpCheck, $tpPrev, $tpSilos))

# ---- Panneau bas : actions + journal
$pnlBottom = New-Object System.Windows.Forms.Panel
$pnlBottom.Dock = 'Bottom'; $pnlBottom.Height = 190
$btnCheck = New-Button 'Verifier la configuration' 10 6 200 30
$btnApply = New-Button 'Creer / Appliquer' 220 6 200 30
$btnApply.BackColor = [System.Drawing.Color]::FromArgb(220, 235, 250)
$txtLog = New-Object System.Windows.Forms.TextBox
$txtLog.Multiline = $true; $txtLog.ReadOnly = $true; $txtLog.ScrollBars = 'Vertical'
$txtLog.Font = New-Object System.Drawing.Font('Consolas', 9)
$txtLog.Location = (P 10 42); $txtLog.Size = (Z 1060 140); $txtLog.Anchor = 'Top,Bottom,Left,Right'
$pnlBottom.Controls.AddRange(@($btnCheck, $btnApply, $txtLog))
$script:txtLog = $txtLog

$form.Controls.Add($tabs)
$form.Controls.Add($pnlBottom)
$tabs.BringToFront()

# ---------------------------------------------------------------- Verifications
function Test-Config {
    $r = New-Object System.Collections.Generic.List[object]
    $sevEnf = if ($rbEnforce.Checked) { 'ERREUR' } else { 'AVERT' }
    $silo = $txtSilo.Text.Trim(); $pol = $txtPol.Text.Trim()
    $u = Get-Accts $lvUsers; $c = Get-Accts $lvComps; $sv = Get-Accts $lvSvc
    $restrict = $chkRestrict.Checked

    function Add-R($lvl, $msg) { $r.Add([pscustomobject]@{ Level = $lvl; Message = $msg }) }

    # Domaine
    try {
        $d = Get-ADDomain
        if ([int]$d.DomainMode -ge 6) { Add-R 'OK' ("Niveau fonctionnel du domaine : {0} (>= 2012 R2)." -f $d.DomainMode) }
        else { Add-R 'ERREUR' ("Niveau fonctionnel du domaine insuffisant : {0}. Les silos exigent 2012 R2 minimum." -f $d.DomainMode) }
    } catch { Add-R 'ERREUR' ("Impossible de contacter le domaine : {0}" -f $_.Exception.Message) }

    # Noms
    $existingSilo = $null
    if ([string]::IsNullOrWhiteSpace($silo)) { Add-R 'ERREUR' 'Le nom du silo est vide.' }
    elseif ($silo -match '[\\/\[\]:;|=,+*?<>"]') { Add-R 'ERREUR' 'Le nom du silo contient des caracteres interdits.' }
    else {
        try {
            $esc = $silo -replace "'", "''"
            $existingSilo = Get-ADAuthenticationPolicySilo -Filter "Name -eq '$esc'" -Properties Enforce -ErrorAction Stop
            if ($existingSilo) { Add-R 'INFO' ("Le silo '{0}' existe deja : il sera mis a jour (pas recree). Mode actuel : {1}." -f $silo, $(if ($existingSilo.Enforce) { 'Enforce' } else { 'Audit' })) }
            else { Add-R 'OK' ("Le silo '{0}' n'existe pas : il sera cree." -f $silo) }
        } catch { Add-R 'AVERT' ("Lecture des silos impossible : {0}" -f $_.Exception.Message) }
    }
    if ([string]::IsNullOrWhiteSpace($pol)) { Add-R 'ERREUR' "Le nom de la politique est vide." }
    else {
        try {
            $escp = $pol -replace "'", "''"
            if (Get-ADAuthenticationPolicy -Filter "Name -eq '$escp'" -ErrorAction Stop) { Add-R 'INFO' ("La politique '{0}' existe deja : elle sera mise a jour." -f $pol) }
        } catch { }
    }
    if ($numTgt.Value -lt 45) { Add-R 'ERREUR' "La duree de vie du TGT doit etre d'au moins 45 minutes." }
    else { Add-R 'OK' ("Duree de vie du TGT : {0} min." -f $numTgt.Value) }

    # Mode
    if ($rbEnforce.Checked) { Add-R 'AVERT' "Mode Enforce selectionne : privilegiez d'abord le mode Audit et analysez les evenements avant de bloquer." }
    else { Add-R 'OK' "Mode Audit : aucun blocage, les echecs sont uniquement journalises." }

    # Membres
    if ($u.Count -eq 0) { Add-R 'ERREUR' "Aucun compte utilisateur dans le silo." } else { Add-R 'OK' ("{0} utilisateur(s), {1} ordinateur(s), {2} compte(s) de service." -f $u.Count, $c.Count, $sv.Count) }

    $dis = @($u + $c + $sv | Where-Object { $_.Enabled -eq $false })
    if ($dis.Count -gt 0) { Add-R 'AVERT' ("{0} compte(s) desactive(s) dans la liste (ex. {1})." -f $dis.Count, $dis[0].Sam) }

    # Compte deja dans un autre silo
    foreach ($a in @($u + $c + $sv)) {
        try {
            $o = Get-ADObject -Identity $a.Dn -Properties 'msDS-AssignedAuthNPolicySilo' -ErrorAction Stop
            $cur = $o.'msDS-AssignedAuthNPolicySilo'
            if ($cur -and ((-not $existingSilo) -or ($cur -ne $existingSilo.DistinguishedName))) {
                Add-R 'ERREUR' ("{0} est deja assigne a un autre silo ({1}). Un compte ne peut appartenir qu'a un seul silo." -f $a.Sam, $cur)
            }
        } catch { Add-R 'ERREUR' ("Compte introuvable ou illisible : {0}" -f $a.Dn) }
    }

    # Restriction de connexion
    if ($restrict) {
        if ($c.Count -eq 0) { Add-R $sevEnf "Restriction de connexion activee mais AUCUN ordinateur dans le silo : les utilisateurs ne pourront se connecter nulle part." }
        else {
            $bad = @($c | Where-Object { $_.OS -and $_.OS -match 'Windows (XP|Vista|7|2000)|Server 2003|Server 2008' })
            foreach ($b in $bad) { Add-R $sevEnf ("{0} ({1}) ne gere pas les revendications/authentification composee : les utilisateurs seront refuses dessus." -f $b.Sam, $b.OS) }
            $unk = @($c | Where-Object { -not $_.OS -or $_.OS -notlike 'Windows*' })
            if ($unk.Count -gt 0) { Add-R 'AVERT' ("{0} ordinateur(s) sans systeme Windows connu (ex. {1}) : verifiez la prise en charge Kerberos des revendications." -f $unk.Count, $unk[0].Sam) }
            if (-not @($c | Where-Object { $_.Pgid -eq 516 })) {
                Add-R 'AVERT' "Aucun controleur de domaine dans le silo : si ces comptes se connectent aux DC (RDP/console/outils), ils seront refuses."
            }
        }
        $me = "$($env:COMPUTERNAME)$"
        $meU = @($u | Where-Object { $_.Sam -ieq $env:USERNAME })
        if ($meU.Count -gt 0 -and -not @($c | Where-Object { $_.Sam -ieq $me })) {
            Add-R $sevEnf ("Votre compte ({0}) est dans le silo mais cet ordinateur ({1}) n'y est pas : risque de vous verrouiller." -f $env:USERNAME, $env:COMPUTERNAME)
        }
        Add-R 'INFO' "Restriction de connexion : exige des GPO 'Prise en charge des revendications / authentification composee / blindage Kerberos' actives sur DC et clients."
    }
    Add-R 'INFO' "Gardez un compte d'urgence (break-glass) HORS du silo, et testez avec un compte pilote avant de generaliser."
    return , $r
}

function Run-Checks {
    $r = Test-Config
    $lvCheck.Items.Clear()
    foreach ($x in $r) {
        $it = New-Object System.Windows.Forms.ListViewItem([string]$x.Level)
        [void]$it.SubItems.Add([string]$x.Message)
        switch ($x.Level) {
            'ERREUR' { $it.ForeColor = [System.Drawing.Color]::Firebrick }
            'AVERT'  { $it.ForeColor = [System.Drawing.Color]::DarkOrange }
            'OK'     { $it.ForeColor = [System.Drawing.Color]::ForestGreen }
            default  { $it.ForeColor = [System.Drawing.Color]::DimGray }
        }
        [void]$lvCheck.Items.Add($it)
    }
    $tabs.SelectedTab = $tpCheck
    return , $r
}

# ---------------------------------------------------------------- Plan de commandes
function Get-Plan {
    $plan = New-Object System.Collections.Generic.List[object]
    $silo = $txtSilo.Text.Trim(); $pol = $txtPol.Text.Trim(); $desc = $txtDesc.Text.Trim()
    $enf = if ($rbEnforce.Checked) { '$true' } else { '$false' }
    $tgt = [int]$numTgt.Value
    $u = Get-Accts $lvUsers; $c = Get-Accts $lvComps; $sv = Get-Accts $lvSvc

    $polExists = $false; $siloExists = $false
    try { $e1 = $pol -replace "'", "''"; $polExists = [bool](Get-ADAuthenticationPolicy -Filter "Name -eq '$e1'" -ErrorAction Stop) } catch { }
    try { $e2 = $silo -replace "'", "''"; $siloExists = [bool](Get-ADAuthenticationPolicySilo -Filter "Name -eq '$e2'" -ErrorAction Stop) } catch { }

    $plan.Add((Step "# --- 1. Politique d'authentification ---" 'comment'))
    $verb = if ($polExists) { 'Set-ADAuthenticationPolicy -Identity' } else { 'New-ADAuthenticationPolicy -Name' }
    # New-* : -Enforce est un switch (absent = Audit). Set-* : -Enforce attend un booleen.
    $enfArg = if ($polExists) { " -Enforce $enf" } elseif ($rbEnforce.Checked) { ' -Enforce' } else { '' }
    $cmd = "$verb $(Q $pol) -UserTGTLifetimeMins $tgt$enfArg"
    if ($desc) { $cmd += " -Description $(Q $desc)" }
    if ($chkRestrict.Checked) {
        $sddl = 'O:SYG:SYD:(XA;OICI;CR;;;WD;(@USER.ad://ext/AuthenticationSilo == "' + $silo + '"))'
        $cmd += " -UserAllowedToAuthenticateFrom $(Q $sddl)"
    }
    if (-not $polExists) { $cmd += ' -ProtectedFromAccidentalDeletion $true' }
    $plan.Add((Step $cmd 'crit'))

    $plan.Add((Step "# --- 2. Silo ---" 'comment'))
    $verb = if ($siloExists) { 'Set-ADAuthenticationPolicySilo -Identity' } else { 'New-ADAuthenticationPolicySilo -Name' }
    $enfArg = if ($siloExists) { " -Enforce $enf" } elseif ($rbEnforce.Checked) { ' -Enforce' } else { '' }
    $cmd = "$verb $(Q $silo)$enfArg -UserAuthenticationPolicy $(Q $pol)"
    if ($c.Count -gt 0) { $cmd += " -ComputerAuthenticationPolicy $(Q $pol)" }
    if ($sv.Count -gt 0) { $cmd += " -ServiceAuthenticationPolicy $(Q $pol)" }
    if ($desc) { $cmd += " -Description $(Q $desc)" }
    if (-not $siloExists) { $cmd += ' -ProtectedFromAccidentalDeletion $true' }
    $plan.Add((Step $cmd 'crit'))

    $plan.Add((Step "# --- 3. Comptes : droit d'acces PUIS assignation (ordinateurs, services, utilisateurs) ---" 'comment'))
    foreach ($a in @($c) + @($sv) + @($u)) {
        $plan.Add((Step "Grant-ADAuthenticationPolicySiloAccess -Identity $(Q $silo) -Account $(Q $a.Dn)" 'cmd'))
        $plan.Add((Step "Set-ADAccountAuthenticationPolicySilo -Identity $(Q $a.Dn) -AuthenticationPolicySilo $(Q $silo)" 'cmd'))
    }
    $plan.Add((Step "# --- Controle ---" 'comment'))
    $plan.Add((Step "# Get-ADAuthenticationPolicySilo -Identity $(Q $silo) -Properties *" 'comment'))
    return , $plan
}

function Update-Preview {
    $lines = @("# Genere par Manage-ADAuthSilo.ps1 le $(Get-Date -Format 'yyyy-MM-dd HH:mm')", 'Import-Module ActiveDirectory', '$ErrorActionPreference = ''Stop''', '')
    $lines += @(Get-Plan | ForEach-Object { $_.Text })
    $txtPrev.Text = ($lines -join "`r`n")
}

function Invoke-Plan {
    $plan = Get-Plan
    $ErrorActionPreference = 'Stop'
    $err = 0
    foreach ($st in $plan) {
        if ($st.Kind -eq 'comment') { Log $st.Text; continue }
        try {
            [void](& ([scriptblock]::Create($st.Text)))
            Log ("  OK     " + $st.Text)
        } catch {
            $err++
            Log ("  ECHEC  " + $st.Text)
            Log ("         " + $_.Exception.Message)
            if ($st.Kind -eq 'crit') { Log "Etape critique en echec : arret."; break }
        }
    }
    if ($err -eq 0) { Log "Termine sans erreur." } else { Log ("Termine avec {0} erreur(s)." -f $err) }
}

# ---------------------------------------------------------------- Silos existants
function Refresh-Silos {
    $lvS.Items.Clear(); $lvD.Items.Clear()
    try {
        foreach ($s in @(Get-ADAuthenticationPolicySilo -Filter * -Properties *)) {
            $it = New-Object System.Windows.Forms.ListViewItem([string]$s.Name)
            [void]$it.SubItems.Add($(if ($s.Enforce) { 'Enforce' } else { 'Audit' }))
            [void]$it.SubItems.Add([string]$s.UserAuthenticationPolicy)
            $m = @($s.Members | Where-Object { $_ })
            [void]$it.SubItems.Add([string]$m.Count)
            if ($s.Enforce) { $it.ForeColor = [System.Drawing.Color]::Firebrick }
            $it.Tag = $s
            [void]$lvS.Items.Add($it)
        }
        Log ("{0} silo(s) charge(s)." -f $lvS.Items.Count)
    } catch { Log ("ERREUR lecture des silos : " + $_.Exception.Message) }
}

function Get-SiloState($s) {
    $granted  = @($s.Members | Where-Object { $_ })
    $assigned = @(Get-ADObject -LDAPFilter "(msDS-AssignedAuthNPolicySilo=$(Escape-Ldap $s.DistinguishedName))" | ForEach-Object { $_.DistinguishedName })
    $all = @($granted + $assigned | Sort-Object -Unique)
    foreach ($dn in $all) {
        [pscustomobject]@{ Dn = $dn; Granted = ($granted -contains $dn); Assigned = ($assigned -contains $dn) }
    }
}

function Show-SiloDetail {
    $lvD.Items.Clear()
    if ($lvS.SelectedItems.Count -eq 0) { return }
    $s = $lvS.SelectedItems[0].Tag
    try {
        foreach ($a in @(Get-SiloState $s)) {
            $it = New-Object System.Windows.Forms.ListViewItem([string]$a.Dn)
            [void]$it.SubItems.Add($(if ($a.Granted) { 'Oui' } else { 'NON' }))
            [void]$it.SubItems.Add($(if ($a.Assigned) { 'Oui' } else { 'NON' }))
            if ($a.Granted -and $a.Assigned) { [void]$it.SubItems.Add('OK'); $it.ForeColor = [System.Drawing.Color]::ForestGreen }
            elseif ($a.Assigned -and -not $a.Granted) { [void]$it.SubItems.Add("Assigne SANS droit d'acces : authentification REFUSEE (blocage en Enforce)"); $it.ForeColor = [System.Drawing.Color]::Firebrick }
            else { [void]$it.SubItems.Add("Acces accorde mais silo non assigne : le compte n'est pas protege"); $it.ForeColor = [System.Drawing.Color]::DarkOrange }
            $it.Tag = $a
            [void]$lvD.Items.Add($it)
        }
    } catch { Log ("ERREUR detail du silo : " + $_.Exception.Message) }
}

function Remove-AccountFromSilo($s, $a) {
    if ($a.Granted) {
        try { Revoke-ADAuthenticationPolicySiloAccess -Identity $s.DistinguishedName -Account $a.Dn -Confirm:$false -ErrorAction Stop; Log ("Acces revoque : " + $a.Dn) }
        catch { Log ("ECHEC revocation {0} : {1}" -f $a.Dn, $_.Exception.Message) }
    }
    if ($a.Assigned) {
        try { Set-ADObject -Identity $a.Dn -Clear 'msDS-AssignedAuthNPolicySilo' -ErrorAction Stop; Log ("Assignation supprimee : " + $a.Dn) }
        catch { Log ("ECHEC desassignation {0} : {1}" -f $a.Dn, $_.Exception.Message) }
    }
}

$lvS.Add_SelectedIndexChanged({ Show-SiloDetail })
$bRef.Add_Click({ Refresh-Silos })

$bTog.Add_Click({
    if ($lvS.SelectedItems.Count -eq 0) { return }
    $s = $lvS.SelectedItems[0].Tag
    $new = -not [bool]$s.Enforce
    if ($new) {
        $bad = @(Get-SiloState $s | Where-Object { $_.Assigned -and -not $_.Granted })
        if ($bad.Count -gt 0) {
            [void][System.Windows.Forms.MessageBox]::Show("Impossible de passer en Enforce : $($bad.Count) compte(s) sont assignes SANS droit d'acces (ils seraient bloques).`r`nUtilisez 'Reparer les incoherences' d'abord.", "Blocage evite", 'OK', 'Warning')
            return
        }
        if ([System.Windows.Forms.MessageBox]::Show("Passer le silo '$($s.Name)' en mode ENFORCE ?", "Confirmation", 'YesNo', 'Warning') -ne 'Yes') { return }
    }
    try {
        Set-ADAuthenticationPolicySilo -Identity $s.DistinguishedName -Enforce $new -ErrorAction Stop
        if ($s.UserAuthenticationPolicy) { Set-ADAuthenticationPolicy -Identity $s.UserAuthenticationPolicy -Enforce $new -ErrorAction Stop }
        Log ("Silo '{0}' passe en mode {1}." -f $s.Name, $(if ($new) { 'Enforce' } else { 'Audit' }))
    } catch { Log ("ECHEC bascule : " + $_.Exception.Message) }
    Refresh-Silos
})

$bRem.Add_Click({
    if ($lvS.SelectedItems.Count -eq 0 -or $lvD.SelectedItems.Count -eq 0) { return }
    $s = $lvS.SelectedItems[0].Tag
    if ([System.Windows.Forms.MessageBox]::Show("Retirer $($lvD.SelectedItems.Count) compte(s) du silo '$($s.Name)' ?", "Confirmation", 'YesNo', 'Question') -ne 'Yes') { return }
    foreach ($i in @($lvD.SelectedItems)) { Remove-AccountFromSilo $s $i.Tag }
    Refresh-Silos
})

$bFix.Add_Click({
    if ($lvS.SelectedItems.Count -eq 0) { return }
    $s = $lvS.SelectedItems[0].Tag
    $bad = @(Get-SiloState $s | Where-Object { -not ($_.Granted -and $_.Assigned) })
    if ($bad.Count -eq 0) { Log "Aucune incoherence."; return }
    if ([System.Windows.Forms.MessageBox]::Show("$($bad.Count) incoherence(s) : les comptes assignes sans acces recevront l'acces, les comptes avec acces mais non assignes seront assignes au silo. Continuer ?", "Reparation", 'YesNo', 'Question') -ne 'Yes') { return }
    foreach ($a in $bad) {
        try {
            if (-not $a.Granted) { Grant-ADAuthenticationPolicySiloAccess -Identity $s.DistinguishedName -Account $a.Dn -ErrorAction Stop; Log ("Acces accorde : " + $a.Dn) }
            if (-not $a.Assigned) { Set-ADAccountAuthenticationPolicySilo -Identity $a.Dn -AuthenticationPolicySilo $s.DistinguishedName -ErrorAction Stop; Log ("Assigne : " + $a.Dn) }
        } catch { Log ("ECHEC {0} : {1}" -f $a.Dn, $_.Exception.Message) }
    }
    Refresh-Silos
})

$bDel.Add_Click({
    if ($lvS.SelectedItems.Count -eq 0) { return }
    $s = $lvS.SelectedItems[0].Tag
    if ([System.Windows.Forms.MessageBox]::Show("Supprimer le silo '$($s.Name)' ?`r`nTous les comptes seront d'abord retires (acces + assignation). La politique associee est conservee.", "Suppression", 'YesNo', 'Warning') -ne 'Yes') { return }
    foreach ($a in @(Get-SiloState $s)) { Remove-AccountFromSilo $s $a }
    try {
        Set-ADAuthenticationPolicySilo -Identity $s.DistinguishedName -ProtectedFromAccidentalDeletion $false -ErrorAction Stop
        Remove-ADAuthenticationPolicySilo -Identity $s.DistinguishedName -Confirm:$false -ErrorAction Stop
        Log ("Silo '{0}' supprime." -f $s.Name)
    } catch { Log ("ECHEC suppression : " + $_.Exception.Message) }
    Refresh-Silos
})

# ---------------------------------------------------------------- Evenements globaux
$script:silosLoaded = $false
$tabs.Add_SelectedIndexChanged({
    if ($tabs.SelectedTab -eq $tpPrev) { Update-Preview }
    if ($tabs.SelectedTab -eq $tpSilos -and -not $script:silosLoaded) { $script:silosLoaded = $true; Refresh-Silos }
})
$btnPrevRef.Add_Click({ Update-Preview })
$btnPrevSave.Add_Click({
    Update-Preview
    $sfd = New-Object System.Windows.Forms.SaveFileDialog
    $sfd.Filter = 'Script PowerShell (*.ps1)|*.ps1'
    $sfd.FileName = ("Silo-{0}.ps1" -f $txtSilo.Text.Trim())
    if ($sfd.ShowDialog() -eq 'OK') {
        [System.IO.File]::WriteAllText($sfd.FileName, $txtPrev.Text, (New-Object System.Text.UTF8Encoding($true)))
        Log ("Script enregistre : " + $sfd.FileName)
    }
})

$btnCheck.Add_Click({
    $r = Run-Checks
    Log ("Verification : {0} erreur(s), {1} avertissement(s)." -f @($r | Where-Object Level -eq 'ERREUR').Count, @($r | Where-Object Level -eq 'AVERT').Count)
})

$btnApply.Add_Click({
    $r = Run-Checks
    $nErr = @($r | Where-Object Level -eq 'ERREUR').Count
    $nWarn = @($r | Where-Object Level -eq 'AVERT').Count
    if ($nErr -gt 0) {
        [void][System.Windows.Forms.MessageBox]::Show("$nErr erreur(s) detectee(s). Corrigez-les avant d'appliquer (voir l'onglet Verifications).", "Application refusee", 'OK', 'Error')
        return
    }
    $mode = if ($rbEnforce.Checked) { 'ENFORCE (blocage reel)' } else { 'AUDIT (sans blocage)' }
    $msg = "Appliquer le silo '$($txtSilo.Text.Trim())' en mode $mode ?"
    if ($nWarn -gt 0) { $msg += "`r`n`r`n$nWarn avertissement(s) en cours (voir l'onglet Verifications)." }
    if ([System.Windows.Forms.MessageBox]::Show($msg, "Confirmation", 'YesNo', 'Question') -ne 'Yes') { return }
    Invoke-Plan
    $script:silosLoaded = $false
})

Log "Pret. Renseignez le silo (onglet 1), les comptes (onglets 2 a 4), puis lancez 'Verifier la configuration'."
[void]$form.ShowDialog()