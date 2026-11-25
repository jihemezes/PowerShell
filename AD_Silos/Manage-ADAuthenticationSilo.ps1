# =====================================================================================
# Manage-ADAuthenticationSilo.ps1 - Version 1.4.0 - 2026-11-25
# =====================================================================================
#Requires -Version 5.1
<#
.SYNOPSIS
    Gestionnaire GRAPHIQUE de silos d'authentification Active Directory.

.DESCRIPTION
    *** OUTIL A INTERFACE GRAPHIQUE (Windows Forms) ***
    Ce script ne prend AUCUN parametre : il s'utilise exclusivement via sa fenetre.
    Lancez-le (clic droit > Executer avec PowerShell, ou  .\Manage-ADAuthenticationSilo.ps1  depuis une
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
      - Pour l'onglet 8 : droit de lecture des journaux d'evenements a distance sur les DC
        (groupe "Lecteurs des journaux d'evenements" ou administrateur) et pare-feu autorisant
        "Administration a distance du journal d'evenements" ; journal d'audit actif sur les DC.
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
       incoherences ; suppression propre d'un silo, avec en option la suppression de sa
       politique dans la meme operation (conservee automatiquement si un autre silo ou un
       compte l'utilise encore).
    8. Journaux DC : apres creation du silo, lit le journal
       "Microsoft-Windows-Authentication/AuthenticationPolicyFailures-DomainController" de
       TOUS les controleurs de domaine, ne retient que les echecs de politique (refus simules
       en Audit : ID 106/306 ; refus reels en Enforce : ID 105/305), filtre sur les comptes du
       silo et sur la periode choisie, puis rend un verdict "pret / a corriger" avant le
       passage en Enforce. Signale les DC injoignables et les journaux desactives (analyse
       incomplete) ; export CSV.
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
      - La suppression d'un silo conserve sa politique d'authentification, sauf si l'option
        "Supprimer aussi la politique" est cochee (et seulement si plus aucun autre silo ni
        compte ne l'utilise).
      - Les GPO Kerberos (revendications / blindage) et l'etat reel des clients ne sont pas
        verifies automatiquement : un rappel et une explication du blindage sont affiches
        (onglet 1) ; leurs effets se constatent dans les journaux (onglet 8).
      - Onglet 8 : l'interpretation des evenements repose sur les ID 105/106/305/306 (a
        confirmer sur votre version de Windows) ; au plus 5000 evenements par DC ; la
        fenetre est occupee pendant l'interrogation des DC ; seuls les evenements encore
        presents dans les journaux (taille/rotation) sont visibles ; l'absence d'evenement
        ne prouve pas qu'un compte s'est authentifie.
      - Le developpement des groupes et la recherche sont limites aux objets lisibles par
        le compte qui execute l'outil.

.NOTES
    VERSION 1.4.0 - 2026-11-25   (a mettre a jour a chaque modification : ici, ligne 2 du
    fichier et variable $script:AppVersion)

    HISTORIQUE
      1.4.0 2026-11-25  Zone d'information de l'onglet 1 : cadre ancre dans l'onglet avec
                        defilement (plus de texte coupe) ; versioning ajoute.
      1.3.0 2026-11-25  Onglet 8 "Journaux DC" ; option de suppression de la politique avec le
                        silo ; explication de la GPO Kerberos armoring (onglet 1).
      1.2.0 2026-11-19  En-tete detaille (prerequis, contraintes, capacites, limites).
      1.1.0 2026-11-19  Correctif : -Enforce est un switch sur New-ADAuthenticationPolicy[Silo].
      1.0.0 2026-11-19  Version initiale (interface graphique, verifications, silos existants).

    Commencez TOUJOURS en mode Audit, analysez les evenements d'audit sur les controleurs de
    domaine, testez avec un compte pilote, puis seulement passez en Enforce.
    Fichier encode en UTF-8 avec BOM (necessaire a PowerShell 5.1 pour les accents).

.EXAMPLE
    .\Manage-ADAuthSilo.ps1
    Ouvre la fenetre de gestion des silos (aucun parametre).
#>

Set-StrictMode -Off
$script:AppVersion = '1.4.0'   # a tenir a jour avec l'en-tete et l'historique
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
$form.Text = "Gestionnaire de silos d'authentification Active Directory - v$script:AppVersion"
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

$lblInfo = New-Object System.Windows.Forms.RichTextBox
$lblInfo.ReadOnly = $true; $lblInfo.WordWrap = $true; $lblInfo.ScrollBars = 'Vertical'
$lblInfo.BorderStyle = 'FixedSingle'; $lblInfo.BackColor = [System.Drawing.SystemColors]::Window
$lblInfo.DetectUrls = $false
$infoText = @"
Bonnes pratiques pour eviter les blocages :

  - Commencez TOUJOURS en mode Audit. Analysez le journal "Microsoft-Windows-Authentication/AuthenticationPolicyFailures-DomainController" sur les controleurs de domaine (onglet 8 "Journaux DC" : il lit les DC et ne garde que les entrees utiles), puis passez en Enforce.
  - Un silo n'accepte pas de groupes : les groupes sont developpes en comptes (instantane). Les futurs membres des groupes devront etre ajoutes au silo.
  - Si vous limitez la connexion aux ordinateurs du silo, TOUS les ordinateurs utilises par ces comptes (postes, serveurs d'administration, controleurs de domaine si connexion RDP/console) doivent etre dans le silo.
  - Prerequis : niveau fonctionnel du domaine 2012 R2 minimum ; GPO Kerberos armoring (voir ci-dessous) sur les DC et les clients.
  - Un compte ne peut appartenir qu'a un seul silo. Conservez un compte d'urgence (break-glass) hors silo.
  - Ordre applique par l'outil : politique, silo, puis pour chaque compte : droit d'acces PUIS assignation (une assignation sans droit d'acces bloque le compte).

GPO "Kerberos armoring" (blindage Kerberos / FAST) :

  - Role : protege l'authentification dans un tunnel chiffre et transmet au KDC l'identite de l'utilisateur ET de l'ordinateur ("authentification composee"). Indispensable a la restriction de connexion : sans lui, refus en Enforce (echecs journalises en Audit).
  - DC : Configuration ordinateur > Modeles d'administration > Systeme > KDC > "Prise en charge KDC des revendications, de l'authentification composee et du blindage Kerberos" = "Pris en charge" (recommande). "Echec des demandes non blindees" impose le blindage : a reserver a la fin, quand tous les clients sont valides.
  - Clients : Configuration ordinateur > Modeles d'administration > Systeme > Kerberos > "Prise en charge client Kerberos des revendications, de l'authentification composee et du blindage Kerberos" = Active.
  - Apres application (gpupdate /force) : nouvelle session utilisateur requise ; Windows 8 / Server 2012 minimum.
"@
$lblInfo.Text = ($infoText -replace "`r?`n", "`r`n")
# Les champs vont dans un panneau haut de hauteur fixe ; la zone d'information occupe tout le reste
# de l'onglet (Dock = Fill) : elle ne peut donc jamais deborder du cadre.
$pnlCfg = New-Object System.Windows.Forms.Panel
$pnlCfg.Dock = 'Top'; $pnlCfg.Height = 275
foreach ($ctl in @($tpCfg.Controls)) { $pnlCfg.Controls.Add($ctl) }
$lblInfo.Dock = 'Fill'
$tpCfg.Padding = New-Object System.Windows.Forms.Padding(8)
$tpCfg.Controls.Add($lblInfo); $tpCfg.Controls.Add($pnlCfg); $lblInfo.BringToFront()

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
$chkDelPol = New-Object System.Windows.Forms.CheckBox
$chkDelPol.Text = 'Supprimer aussi la politique'
$chkDelPol.Location = (P 850 10); $chkDelPol.Size = (Z 220 24)
$pnlS.Controls.AddRange(@($bRef, $bTog, $bRem, $bFix, $bDel, $chkDelPol))
$tpSilos.Controls.Add($split); $tpSilos.Controls.Add($pnlS); $split.BringToFront()

# ---- Onglet Journaux des controleurs de domaine
$tpLog = New-Object System.Windows.Forms.TabPage; $tpLog.Text = '8. Journaux DC'
$pnlL = New-Object System.Windows.Forms.Panel; $pnlL.Dock = 'Top'; $pnlL.Height = 80
$cbLogSilo = New-Object System.Windows.Forms.ComboBox
$cbLogSilo.DropDownStyle = 'DropDownList'; $cbLogSilo.Location = (P 60 10); $cbLogSilo.Size = (Z 260 24)
$numDays = New-Object System.Windows.Forms.NumericUpDown
$numDays.Location = (P 460 10); $numDays.Size = (Z 60 24); $numDays.Minimum = 1; $numDays.Maximum = 365; $numDays.Value = 7
$cbLogKind = New-Object System.Windows.Forms.ComboBox
$cbLogKind.DropDownStyle = 'DropDownList'; $cbLogKind.Location = (P 540 10); $cbLogKind.Size = (Z 300 24)
[void]$cbLogKind.Items.AddRange(@('Tous les refus de politique', 'Audit uniquement (refus simules)', 'Enforce uniquement (refus reels)'))
$cbLogKind.SelectedIndex = 0
$chkLogScope = New-Object System.Windows.Forms.CheckBox
$chkLogScope.Text = 'Uniquement les comptes du silo'; $chkLogScope.Checked = $true
$chkLogScope.Location = (P 850 10); $chkLogScope.Size = (Z 220 24)
$btnLogSilos = New-Button 'Actualiser les silos' 10 42 150 28
$btnLogRun = New-Button 'Analyser les controleurs de domaine' 170 42 250 28
$btnLogCsv = New-Button 'Exporter en CSV...' 430 42 160 28
$pnlL.Controls.AddRange(@((New-Label 'Silo :' 10 10 45), $cbLogSilo, (New-Label 'Jours :' 400 10 55), $numDays, $cbLogKind, $chkLogScope, $btnLogSilos, $btnLogRun, $btnLogCsv))
$txtVerdict = New-Object System.Windows.Forms.TextBox
$txtVerdict.Multiline = $true; $txtVerdict.ReadOnly = $true; $txtVerdict.ScrollBars = 'Vertical'
$txtVerdict.Dock = 'Top'; $txtVerdict.Height = 130
$txtVerdict.Text = ("Choisissez un silo, la periode, puis lancez l'analyse." + "`r`n" + "L'outil lit le journal Authentication\AuthenticationPolicyFailures-DomainController de CHAQUE controleur de domaine, ne retient que les echecs de politique d'authentification et rend un verdict avant le passage en Enforce.")
$lvLog = New-ListView; $lvLog.Dock = 'Fill'; $lvLog.MultiSelect = $false
foreach ($c in @(@('Heure', 140), @('DC', 170), @('ID', 50), @('Nature', 250), @('Compte concerne', 200), @('Details', 700))) { [void]$lvLog.Columns.Add($c[0], $c[1]) }
$tpLog.Controls.Add($lvLog); $tpLog.Controls.Add($txtVerdict); $tpLog.Controls.Add($pnlL); $lvLog.BringToFront()

$tabs.TabPages.AddRange(@($tpCfg, $tUsers.Page, $tComps.Page, $tSvc.Page, $tpCheck, $tpPrev, $tpSilos, $tpLog))

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

function Remove-PolicyIfUnused([string]$polDn) {
    $pname = (($polDn -split ',')[0]) -replace '^CN=', ''
    try {
        $users = @(Get-ADAuthenticationPolicySilo -Filter * -Properties UserAuthenticationPolicy, ComputerAuthenticationPolicy, ServiceAuthenticationPolicy -ErrorAction Stop |
            Where-Object { @([string]$_.UserAuthenticationPolicy, [string]$_.ComputerAuthenticationPolicy, [string]$_.ServiceAuthenticationPolicy) -contains $polDn })
        if ($users.Count -gt 0) {
            Log ("Politique '{0}' CONSERVEE : encore utilisee par le(s) silo(s) {1}." -f $pname, (($users | ForEach-Object { $_.Name }) -join ', '))
            return
        }
        $direct = @(Get-ADObject -LDAPFilter "(msDS-AssignedAuthNPolicy=$(Escape-Ldap $polDn))" -ErrorAction Stop)
        if ($direct.Count -gt 0) {
            Log ("Politique '{0}' CONSERVEE : directement assignee a {1} compte(s)." -f $pname, $direct.Count)
            return
        }
        Set-ADAuthenticationPolicy -Identity $polDn -ProtectedFromAccidentalDeletion $false -ErrorAction Stop
        Remove-ADAuthenticationPolicy -Identity $polDn -Confirm:$false -ErrorAction Stop
        Log ("Politique '{0}' supprimee." -f $pname)
    } catch { Log ("ECHEC suppression de la politique '{0}' : {1}" -f $pname, $_.Exception.Message) }
}

$bDel.Add_Click({
    if ($lvS.SelectedItems.Count -eq 0) { return }
    $s = $lvS.SelectedItems[0].Tag
    $delPol = $chkDelPol.Checked
    $polDns = @(@([string]$s.UserAuthenticationPolicy, [string]$s.ComputerAuthenticationPolicy, [string]$s.ServiceAuthenticationPolicy) | Where-Object { $_ } | Sort-Object -Unique)
    $polTxt = if ($delPol) {
        if ($polDns.Count -gt 0) { "La politique associee sera ensuite SUPPRIMEE (sauf si un autre silo ou un compte l'utilise encore)." } else { "Aucune politique n'est associee a ce silo." }
    } else { "La politique associee est conservee." }
    if ([System.Windows.Forms.MessageBox]::Show("Supprimer le silo '$($s.Name)' ?`r`nTous les comptes seront d'abord retires (acces + assignation).`r`n$polTxt", "Suppression", 'YesNo', 'Warning') -ne 'Yes') { return }
    foreach ($a in @(Get-SiloState $s)) { Remove-AccountFromSilo $s $a }
    $siloDeleted = $false
    try {
        Set-ADAuthenticationPolicySilo -Identity $s.DistinguishedName -ProtectedFromAccidentalDeletion $false -ErrorAction Stop
        Remove-ADAuthenticationPolicySilo -Identity $s.DistinguishedName -Confirm:$false -ErrorAction Stop
        $siloDeleted = $true
        Log ("Silo '{0}' supprime." -f $s.Name)
    } catch { Log ("ECHEC suppression : " + $_.Exception.Message) }
    if ($siloDeleted -and $delPol) {
        foreach ($pdn in $polDns) { Remove-PolicyIfUnused $pdn }
    } elseif ($delPol) {
        Log "Suppression du silo en echec : la politique n'est pas supprimee."
    }
    Refresh-Silos
})

# ---------------------------------------------------------------- Journaux des controleurs de domaine
$script:LogName    = 'Microsoft-Windows-Authentication/AuthenticationPolicyFailures-DomainController'
$script:siloByName = @{}
$script:logRows    = @()

function Get-EventClass([int]$id) {
    if (@(106, 306) -contains $id) { return 'AUDIT' }
    if (@(105, 305) -contains $id) { return 'ENFORCE' }
    return 'AUTRE'
}
function Get-EventNature([int]$id) {
    switch ($id) {
        105 { return 'ENFORCE - TGT refuse' }
        106 { return 'AUDIT - TGT aurait ete refuse' }
        305 { return 'ENFORCE - ticket de service refuse' }
        306 { return 'AUDIT - ticket de service aurait ete refuse' }
        default { return 'Autre evenement de politique' }
    }
}

function Load-LogSilos {
    $prev = [string]$cbLogSilo.SelectedItem
    $cbLogSilo.Items.Clear(); $script:siloByName = @{}
    try {
        foreach ($s in @(Get-ADAuthenticationPolicySilo -Filter * -Properties * -ErrorAction Stop | Sort-Object Name)) {
            $script:siloByName[$s.Name] = $s
            [void]$cbLogSilo.Items.Add($s.Name)
        }
    } catch { Log ("ERREUR lecture des silos : " + $_.Exception.Message) }
    $want = if ($prev) { $prev } elseif ($lvS.SelectedItems.Count -gt 0) { [string]$lvS.SelectedItems[0].Tag.Name } else { $txtSilo.Text.Trim() }
    $i = $cbLogSilo.Items.IndexOf($want)
    if ($i -ge 0) { $cbLogSilo.SelectedIndex = $i } elseif ($cbLogSilo.Items.Count -gt 0) { $cbLogSilo.SelectedIndex = 0 }
}

function Get-SiloSamNames($s) {
    $set = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($a in @(Get-SiloState $s)) {
        try {
            $o = Get-ADObject -Identity $a.Dn -Properties sAMAccountName -ErrorAction Stop
            if ($o.sAMAccountName) {
                [void]$set.Add([string]$o.sAMAccountName)
                [void]$set.Add(([string]$o.sAMAccountName).TrimEnd('$'))
            }
        } catch { Log ("Compte illisible : " + $a.Dn) }
    }
    return , $set
}

function Read-DcLog([string]$dc, [datetime]$since) {
    $res = @{ Events = @(); Error = $null; Enabled = $true }
    try {
        $lg = Get-WinEvent -ListLog $script:LogName -ComputerName $dc -ErrorAction Stop
        $res.Enabled = [bool]$lg.IsEnabled
    } catch { $res.Error = $_.Exception.Message; return $res }
    try {
        $res.Events = @(Get-WinEvent -ComputerName $dc -FilterHashtable @{ LogName = $script:LogName; StartTime = $since } -MaxEvents 5000 -ErrorAction Stop)
    } catch {
        if ($_.FullyQualifiedErrorId -notlike '*NoMatchingEventsFound*') { $res.Error = $_.Exception.Message }
    }
    return $res
}

function Convert-PolicyEvent($ev, [string]$dc, $names, $rx) {
    $vals = @()
    try {
        $x = [xml]$ev.ToXml()
        $vals = @($x.SelectNodes("//*[local-name()='Data']") | ForEach-Object { $_.InnerText } | Where-Object { $_ })
    } catch { }
    $msg = ''
    try { $msg = [string]$ev.Message } catch { }
    if ([string]::IsNullOrWhiteSpace($msg)) { $msg = ($vals -join ' | ') }
    $msg = ($msg -replace '\s+', ' ').Trim()
    if ($msg.Length -gt 400) { $msg = $msg.Substring(0, 400) + '...' }

    $matched = $null
    foreach ($v in $vals) {
        foreach ($cand in @($v, ($v -split '\\')[-1], ($v -split '@')[0])) {
            if ($cand -and $names.Contains($cand)) { $matched = $cand; break }
        }
        if ($matched) { break }
    }
    if (-not $matched -and $rx) {
        $m = $rx.Match(($vals -join ' ') + ' ' + $msg)
        if ($m.Success) { $matched = $m.Groups[1].Value }
    }
    $acct = if ($matched) { $matched } elseif ($vals.Count -gt 0) { $vals[0] } else { '' }
    [pscustomobject]@{
        Heure = $ev.TimeCreated; DC = $dc; Id = [int]$ev.Id; Classe = (Get-EventClass $ev.Id)
        Nature = (Get-EventNature $ev.Id); Compte = $acct; DansSilo = [bool]$matched; Details = $msg
    }
}

function Invoke-LogAnalysis {
    $name = [string]$cbLogSilo.SelectedItem
    if (-not $name) { [void][System.Windows.Forms.MessageBox]::Show("Selectionnez un silo (bouton 'Actualiser les silos' si la liste est vide).", "Journaux DC"); return }
    $s = $script:siloByName[$name]
    $since = (Get-Date).AddDays(-[double]$numDays.Value)
    $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    $lvLog.Items.Clear(); $script:logRows = @()
    try {
        Log ("Analyse des journaux DC - silo '{0}' - depuis le {1}." -f $name, $since.ToString('yyyy-MM-dd HH:mm'))
        $names = Get-SiloSamNames $s
        $rx = $null
        if ($names.Count -gt 0 -and $names.Count -le 2000) {
            $alt = (@($names | ForEach-Object { [regex]::Escape($_) }) -join '|')
            $rx = New-Object System.Text.RegularExpressions.Regex(('(?<![\w$.-])(' + $alt + ')(?![\w.-])'), 'IgnoreCase')
        }
        $dcs = @(Get-ADDomainController -Filter * -ErrorAction Stop | ForEach-Object { [string]$_.HostName })
        $all = New-Object System.Collections.Generic.List[object]
        $errs = @(); $off = @()
        foreach ($dc in $dcs) {
            Log ("  Lecture de {0}..." -f $dc)
            $r = Read-DcLog $dc $since
            if ($r.Error) { $errs += ("{0} ({1})" -f $dc, $r.Error); Log ("  ECHEC {0} : {1}" -f $dc, $r.Error); continue }
            if (-not $r.Enabled) { $off += $dc }
            foreach ($ev in $r.Events) { $all.Add((Convert-PolicyEvent $ev $dc $names $rx)) }
            Log ("  {0} : {1} evenement(s) de politique." -f $dc, @($r.Events).Count)
        }

        $scoped = @($all | Where-Object { (-not $chkLogScope.Checked) -or $_.DansSilo })
        $aud = @($scoped | Where-Object { $_.Classe -eq 'AUDIT' })
        $enf = @($scoped | Where-Object { $_.Classe -eq 'ENFORCE' })
        $view = switch ($cbLogKind.SelectedIndex) { 1 { $aud } 2 { $enf } default { $scoped } }
        $view = @($view | Sort-Object Heure -Descending)
        $script:logRows = $view

        foreach ($row in ($view | Select-Object -First 3000)) {
            $it = New-Object System.Windows.Forms.ListViewItem(([datetime]$row.Heure).ToString('yyyy-MM-dd HH:mm:ss'))
            [void]$it.SubItems.Add($row.DC); [void]$it.SubItems.Add([string]$row.Id)
            [void]$it.SubItems.Add($row.Nature); [void]$it.SubItems.Add($row.Compte); [void]$it.SubItems.Add($row.Details)
            if ($row.Classe -eq 'AUDIT') { $it.ForeColor = [System.Drawing.Color]::DarkOrange }
            elseif ($row.Classe -eq 'ENFORCE') { $it.ForeColor = [System.Drawing.Color]::Firebrick }
            [void]$lvLog.Items.Add($it)
        }

        $mode = if ($s.Enforce) { 'Enforce' } else { 'Audit' }
        $v = New-Object System.Collections.Generic.List[string]
        $v.Add(("Silo '{0}' (mode actuel : {1}) - {2} jour(s) - {3}/{4} DC interroge(s) - {5} evenement(s) retenu(s) sur {6} lu(s)." -f $name, $mode, $numDays.Value, ($dcs.Count - $errs.Count), $dcs.Count, $scoped.Count, $all.Count))
        $incomplete = $false
        if ($errs.Count -gt 0) {
            $incomplete = $true
            $v.Add("ATTENTION - analyse INCOMPLETE : DC non interrogeable(s) (droits 'Lecteurs des journaux d'evenements', pare-feu 'Administration a distance du journal d'evenements', DC arrete) :")
            foreach ($e in $errs) { $v.Add("   - " + $e) }
        }
        if ($off.Count -gt 0) {
            $incomplete = $true
            $v.Add("ATTENTION - journal DESACTIVE sur : " + ($off -join ', ') + " (aucun evenement n'est enregistre : activez-le avant de conclure).")
        }
        $color = 'ok'
        if ($aud.Count -gt 0) {
            $color = 'bad'
            $v.Add(("A CORRIGER AVANT ENFORCE : {0} refus simule(s) en Audit ({1} compte(s)). Ces authentifications seraient BLOQUEES en Enforce :" -f $aud.Count, @($aud | Group-Object Compte).Count))
            foreach ($g in @($aud | Group-Object Compte | Sort-Object Count -Descending | Select-Object -First 15)) { $v.Add(("   - {0} : {1} fois" -f $g.Name, $g.Count)) }
            $v.Add("Pistes : ordinateur utilise non membre du silo, GPO Kerberos armoring absente (DC ou client), OS trop ancien, compte non assigne.")
        }
        if ($enf.Count -gt 0) {
            $color = 'bad'
            $v.Add(("{0} refus REEL(S) (Enforce) : des authentifications sont deja bloquees par le silo." -f $enf.Count))
        }
        if ($aud.Count -eq 0 -and $enf.Count -eq 0) {
            if ($incomplete) { $color = 'warn'; $v.Add("Verdict : INDETERMINE (aucun refus vu, mais l'analyse est incomplete).") }
            else {
                $v.Add("Verdict : aucun refus simule ni reel sur la periode, sur tous les DC.")
                $v.Add("Avant de passer en Enforce, verifiez que la periode couvre un cycle d'usage complet (connexions des comptes pilotes, taches, services) : une absence d'evenement peut aussi signifier que le compte ne s'est pas authentifie.")
            }
        }
        $txtVerdict.Text = ($v -join "`r`n")
        $txtVerdict.BackColor = switch ($color) { 'bad' { [System.Drawing.Color]::MistyRose } 'warn' { [System.Drawing.Color]::LemonChiffon } default { [System.Drawing.Color]::Honeydew } }
        Log ("Analyse terminee : {0} refus simule(s), {1} refus reel(s)." -f $aud.Count, $enf.Count)
    } catch {
        Log ("ERREUR analyse des journaux : " + $_.Exception.Message)
        [void][System.Windows.Forms.MessageBox]::Show($_.Exception.Message, "Erreur d'analyse", 'OK', 'Error')
    } finally {
        $form.Cursor = [System.Windows.Forms.Cursors]::Default
    }
}

$btnLogSilos.Add_Click({ Load-LogSilos })
$btnLogRun.Add_Click({ Invoke-LogAnalysis })
$btnLogCsv.Add_Click({
    if (@($script:logRows).Count -eq 0) { [void][System.Windows.Forms.MessageBox]::Show("Rien a exporter : lancez d'abord une analyse.", "Export CSV"); return }
    $sfd = New-Object System.Windows.Forms.SaveFileDialog
    $sfd.Filter = 'CSV (*.csv)|*.csv'
    $sfd.FileName = ("Journaux-{0}-{1}.csv" -f $cbLogSilo.SelectedItem, (Get-Date -Format 'yyyyMMdd'))
    if ($sfd.ShowDialog() -eq 'OK') {
        $script:logRows | Select-Object Heure, DC, Id, Classe, Nature, Compte, DansSilo, Details | Export-Csv -Path $sfd.FileName -NoTypeInformation -Encoding UTF8
        Log ("Export CSV : " + $sfd.FileName)
    }
})

# ---------------------------------------------------------------- Evenements globaux
$script:silosLoaded = $false
$tabs.Add_SelectedIndexChanged({
    if ($tabs.SelectedTab -eq $tpPrev) { Update-Preview }
    if ($tabs.SelectedTab -eq $tpSilos -and -not $script:silosLoaded) { $script:silosLoaded = $true; Refresh-Silos }
    if ($tabs.SelectedTab -eq $tpLog) { Load-LogSilos }
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

Log ("Gestionnaire de silos v{0}." -f $script:AppVersion)
Log "Pret. Renseignez le silo (onglet 1), les comptes (onglets 2 a 4), puis lancez 'Verifier la configuration'."
[void]$form.ShowDialog()