<#
.SYNOPSIS
    Delegation de la gestion des comptes de service administres (gMSA / sMSA) sur une OU de Tier,
    au seul groupe d'administration du MEME Tier. Aucune permission transverse.

.DESCRIPTION
    Script unique et autonome. Il agit sur l'OU cible (-TargetOU) en deposant des ACE au profit
    du groupe delegue (-DelegateGroup). Tous les elements sont parametrables (OU, groupe, serveur,
    classes MSA, attributs, droits, Tier), rien n'est code en dur pour un domaine donne.

    Actions (parametre -Action) :
        Audit     Lecture seule : liste les ACE de l'OU, signale les principaux inattendus, les droits
                  herites du groupe delegue (= delegation transverse) et les droits non prevus.
        Apply     Controle de concordance de Tier, sauvegarde de l'ACL, puis application de la delegation
                  (et des regles d'audit SACL avec -IncludeAudit).
        Verify    Controle que les ACE prevues sont presentes et qu'il n'y a rien en plus.
                  Options : -ScanBaseDN (recherche de droits du groupe hors de l'OU cible),
                  -FunctionalTest (creation / modification / suppression reelles d'un compte MSA temporaire).
        Rollback  Retire uniquement les ACE ajoutees par ce script (avec les memes parametres).
        Restore   Restaure l'ACL complete de l'OU depuis une sauvegarde (-RestoreFile).

    Dry run : ajouter -WhatIf a Apply, Rollback ou Restore. Rien n'est ecrit dans l'annuaire.

    PERMISSIONS ACCORDEES (profil par defaut, groupe delegue uniquement) :
        Read    : lister le contenu de l'OU ; lire les proprietes des objets MSA enfants directs.
        Create  : creer des objets de classe msDS-GroupManagedServiceAccount / msDS-ManagedServiceAccount dans l'OU.
        Delete  : supprimer ces objets dans l'OU.
        Manage  : ecrire uniquement une liste d'attributs nommes sur les objets MSA enfants directs
                  (description, msDS-GroupMSAMembership, msDS-SupportedEncryptionTypes) et les ecritures
                  validees Validated-SPN et Validated-DNS-Host-Name.

    CE QUI N'EST PAS ACCORDE : aucun droit sur d'autres classes d'objets, aucun droit sur d'autres OU,
    aucun GenericAll / WriteDacl / WriteOwner, aucune ecriture sur userAccountControl (sauf
    -AllowEnableDisable), aucune ecriture sur msDS-AllowedToActOnBehalfOfOtherIdentity ni sur les attributs de
    delegation, aucun droit sur les objets ordinateur (donc pas de liaison sMSA <-> ordinateur).

.PARAMETER Action
    Audit | Apply | Verify | Rollback | Restore

.PARAMETER TargetOU
    DN de l'OU qui heberge les comptes MSA du Tier.

.PARAMETER DelegateGroup
    Groupe (DN, nom ou SID) qui recoit la delegation. Doit appartenir au meme Tier que l'OU.

.PARAMETER Server
    Controleur de domaine utilise. Defaut : emulateur PDC du domaine courant.
    Pour un autre domaine, indiquer un DC de ce domaine.

.PARAMETER BackupPath
    Dossier des sauvegardes d'ACL, exports CSV et journaux.

.PARAMETER MsaType
    gMSA | sMSA | Both. Classes d'objets concernees. Defaut : Both.

.PARAMETER Rights
    Sous-ensemble de Read, Create, Delete, Manage. Defaut : les quatre.

.PARAMETER GmsaAttributes
    Attributs inscriptibles sur les gMSA (lDAPDisplayName).

.PARAMETER SmsaAttributes
    Attributs inscriptibles sur les sMSA (lDAPDisplayName).

.PARAMETER ExtraAttributes
    Attributs supplementaires inscriptibles, ajoutes aux deux listes ci-dessus.

.PARAMETER ValidatedWrites
    Droits etendus d'ecriture validee (nom du CN dans CN=Extended-Rights). Defaut : Validated-SPN, Validated-DNS-Host-Name.

.PARAMETER AllowEnableDisable
    Ajoute l'ecriture de userAccountControl (activer / desactiver un compte MSA). Desactive par defaut.

.PARAMETER TierNumber
    Numero du Tier (0, 1, 2...). Sert au controle de concordance OU <-> groupe.

.PARAMETER TierPrefixes
    Prefixes reconnus dans les noms pour designer un Tier. Defaut : T, Tier (T0, Tier0, Tier 0...).

.PARAMETER SkipTierCheck
    Ignore le controle de concordance de Tier (deconseille).

.PARAMETER ScanBaseDN
    Avec Verify : DN de base d'une recherche de droits explicites du groupe delegue en dehors de l'OU cible
    (ex : le DN du domaine). Detecte une delegation transverse.

.PARAMETER IncludeAudit
    Gere aussi les regles d'audit (SACL) : evenements 5136, 5137, 5141. Necessite SeSecurityPrivilege.

.PARAMETER RestoreFile
    Fichier .sddl produit par une sauvegarde (action Restore).

.PARAMETER FunctionalTest
    Avec Verify : cree, modifie puis supprime un compte MSA temporaire dans l'OU cible.

.PARAMETER TestCredential
    Compte utilise pour le test fonctionnel (membre du groupe delegue, ou compte d'un autre Tier avec -ExpectDenied).

.PARAMETER ExpectDenied
    Avec -FunctionalTest : le test reussit si la creation est REFUSEE (test d'un compte d'un autre Tier).

.PARAMETER TestPrincipal
    Principal autorise a lire le mot de passe du gMSA de test. Defaut : le groupe delegue.

.PARAMETER TestNamePrefix
    Prefixe (8 caracteres max) du nom des comptes de test. Defaut : zMSAtest.

.PARAMETER TestDnsSuffix
    Suffixe DNS du gMSA de test. Defaut : DNS racine du domaine.

.EXAMPLE
    .\Set-MSADelegation.ps1 -Action Audit

.EXAMPLE
    .\Set-MSADelegation.ps1 -Action Apply -IncludeAudit -WhatIf

.EXAMPLE
    .\Set-MSADelegation.ps1 -Action Apply -IncludeAudit

.EXAMPLE
    .\Set-MSADelegation.ps1 -Action Verify -IncludeAudit -ScanBaseDN 'DC=tiering,DC=ad'

.EXAMPLE
    # Depuis une session ouverte avec un compte membre du groupe delegue : doit reussir.
    .\Set-MSADelegation.ps1 -Action Verify -FunctionalTest

.EXAMPLE
    # Avec un compte d'un autre Tier : doit etre refuse.
    .\Set-MSADelegation.ps1 -Action Verify -FunctionalTest -ExpectDenied -TestCredential (Get-Credential)

.EXAMPLE
    # Autre domaine / autre Tier : tout est parametrable.
    .\Set-MSADelegation.ps1 -Action Apply -Server dc01.corp.example -TierNumber 1 `
        -TargetOU 'OU=Tier1-MSA,OU=ServiceAccounts,DC=corp,DC=example' `
        -DelegateGroup 'CN=DLG_T1_ServiceAdmins,OU=Groups,OU=T1,DC=corp,DC=example' -WhatIf

.EXAMPLE
    .\Set-MSADelegation.ps1 -Action Rollback -IncludeAudit -WhatIf
    .\Set-MSADelegation.ps1 -Action Rollback -IncludeAudit

.EXAMPLE
    .\Set-MSADelegation.ps1 -Action Restore -RestoreFile C:\Temp\MSA-Delegation\MSA-OU-ACL-20261027-140000.sddl

.NOTES
    A executer depuis une PAW du Tier concerne, avec un compte autorise a modifier l'ACL de l'OU cible
    (Domain Admins / Enterprise Admins) pour Apply, Rollback et Restore.
    Prerequis gMSA : une cle racine KDS doit exister (Add-KdsRootKey, action non deleguee).
    Codes de sortie : 0 = succes, 1 = echec ou ecart constate.
    Fichier a enregistrer en UTF-8 avec BOM (compatibilite Windows PowerShell 5.1).
#>
#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet('Audit', 'Apply', 'Verify', 'Rollback', 'Restore')]
    [string]$Action,

    [string]$TargetOU = 'OU=Tier2-gMSA,OU=_ServiceAccounts-TM,DC=tiering,DC=ad',
    [string]$DelegateGroup = 'CN=DLG_GG_T2_Admins_AD,OU=Admin_TM_T2_Groups,OU=Admin_TM_T2,OU=_Admin_TM,DC=tiering,DC=ad',
    [string]$Server,
    [string]$BackupPath = 'C:\Temp\MSA-Delegation',

    [ValidateSet('gMSA', 'sMSA', 'Both')]
    [string]$MsaType = 'Both',

    [ValidateSet('Read', 'Create', 'Delete', 'Manage')]
    [string[]]$Rights = @('Read', 'Create', 'Delete', 'Manage'),

    [string[]]$GmsaAttributes = @('description', 'msDS-GroupMSAMembership', 'msDS-SupportedEncryptionTypes'),
    [string[]]$SmsaAttributes = @('description', 'msDS-SupportedEncryptionTypes'),
    [string[]]$ExtraAttributes = @(),
    [string[]]$ValidatedWrites = @('Validated-SPN', 'Validated-DNS-Host-Name'),
    [switch]$AllowEnableDisable,

    [ValidateRange(0, 9)]
    [int]$TierNumber = 0,
    [string[]]$TierPrefixes = @('T', 'Tier'),
    [switch]$SkipTierCheck,

    [string]$ScanBaseDN,
    [switch]$IncludeAudit,
    [string]$RestoreFile,

    [switch]$FunctionalTest,
    [pscredential]$TestCredential,
    [switch]$ExpectDenied,
    [string]$TestPrincipal,
    [ValidateLength(1, 8)]
    [string]$TestNamePrefix = 'zMSAtest',
    [string]$TestDnsSuffix
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Fonctions utilitaires (aucune ne depend de variables du script : tout passe par parametres)
# ---------------------------------------------------------------------------
function Write-Log {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [ValidateSet('INFO', 'OK', 'WARN', 'ERROR')][string]$Level = 'INFO'
    )
    $color = switch ($Level) {
        'OK'    { 'Green' }
        'WARN'  { 'Yellow' }
        'ERROR' { 'Red' }
        default { 'Cyan' }
    }
    Write-Host ("[{0}] [{1}] {2}" -f (Get-Date -Format 'HH:mm:ss'), $Level, $Message) -ForegroundColor $color
}

function Get-AceSid {
    param($Ace)
    try {
        return $Ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
    }
    catch {
        return [string]$Ace.IdentityReference
    }
}

function Save-Acl {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Acl,
        [Parameter(Mandatory = $true)][string]$Description
    )
    if ($WhatIfPreference) {
        Write-Log "[DRY RUN] $Description - aucune modification ecrite dans l'annuaire." 'WARN'
        return
    }
    Set-Acl -Path $Path -AclObject $Acl
    Write-Log $Description 'OK'
}

function Resolve-SchemaGuid {
    param(
        [Parameter(Mandatory = $true)][string]$Server,
        [Parameter(Mandatory = $true)][string]$SchemaNC,
        [Parameter(Mandatory = $true)][string]$LdapName,
        [Parameter(Mandatory = $true)][ValidateSet('classSchema', 'attributeSchema')][string]$SchemaClass
    )
    if ($LdapName -notmatch '^[A-Za-z0-9-]+$') { throw "Nom de schema invalide : '$LdapName'" }
    $obj = Get-ADObject -Server $Server -SearchBase $SchemaNC `
        -LDAPFilter "(&(objectClass=$SchemaClass)(lDAPDisplayName=$LdapName))" -Properties schemaIDGUID
    if (-not $obj) { return $null }
    return [Guid]::new([byte[]]$obj.schemaIDGUID)
}

function Resolve-ExtendedRightGuid {
    param(
        [Parameter(Mandatory = $true)][string]$Server,
        [Parameter(Mandatory = $true)][string]$ConfigNC,
        [Parameter(Mandatory = $true)][string]$RightName
    )
    if ($RightName -notmatch '^[A-Za-z0-9-]+$') { throw "Nom de droit etendu invalide : '$RightName'" }
    $obj = Get-ADObject -Server $Server -SearchBase "CN=Extended-Rights,$ConfigNC" `
        -LDAPFilter "(&(objectClass=controlAccessRight)(cn=$RightName))" -Properties rightsGuid
    if (-not $obj) { return $null }
    return [Guid]([string]$obj.rightsGuid)
}

function Get-NonDcDn {
    param([string]$Dn)
    return (($Dn -split '(?<!\\),') | Where-Object { $_.Trim() -notmatch '^DC=' }) -join ','
}

function New-TierPattern {
    param([string]$PrefixAlternation, [int]$Number)
    return '(?<![A-Za-z0-9])(?:' + $PrefixAlternation + ')' + $Number + '(?![0-9])'
}

function Test-TierConsistency {
    param(
        [Parameter(Mandatory = $true)][string]$TargetOuDn,
        [Parameter(Mandatory = $true)][string]$GroupDn,
        [Parameter(Mandatory = $true)][int]$TierNumber,
        [Parameter(Mandatory = $true)][string[]]$TierPrefixes
    )
    $prefixAlt = (($TierPrefixes | ForEach-Object { [regex]::Escape($_) + '\s*' }) -join '|')
    $own = New-TierPattern -PrefixAlternation $prefixAlt -Number $TierNumber
    $messages = New-Object System.Collections.Generic.List[string]
    $ok = $true

    $items = @(
        @{ Name = 'OU cible'; Dn = $TargetOuDn },
        @{ Name = 'Groupe delegue'; Dn = $GroupDn }
    )
    foreach ($item in $items) {
        $part = Get-NonDcDn -Dn $item.Dn
        if ($part -notmatch $own) {
            $ok = $false
            $messages.Add("$($item.Name) : aucune reference au Tier $TierNumber dans '$part'.")
        }
        for ($n = 0; $n -le 9; $n++) {
            if ($n -eq $TierNumber) { continue }
            if ($part -match (New-TierPattern -PrefixAlternation $prefixAlt -Number $n)) {
                $ok = $false
                $messages.Add("$($item.Name) : reference au Tier $n dans '$part' (attendu : Tier $TierNumber uniquement).")
            }
        }
    }
    return [pscustomobject]@{ Ok = $ok; Messages = $messages.ToArray() }
}

function Test-BroadPrincipal {
    param([string]$SidValue)
    if ($SidValue -in @('S-1-1-0', 'S-1-5-11', 'S-1-5-32-545', 'S-1-5-32-546')) { return $true }
    if ($SidValue -match '^S-1-5-21-\d+-\d+-\d+-(513|514|515)$') { return $true }
    return $false
}

function Test-ExpectedPrincipal {
    param([string]$SidValue)
    if ($SidValue -in @('S-1-5-18', 'S-1-5-32-544', 'S-1-3-0', 'S-1-5-10', 'S-1-5-9', 'S-1-5-11', 'S-1-5-32-554')) { return $true }
    if ($SidValue -match '^S-1-5-21-\d+-\d+-\d+-(512|518|519)$') { return $true }   # Domain / Schema / Enterprise Admins
    return $false
}

# --- Specifications des ACE ---------------------------------------------------
function New-Spec {
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][string]$Rights,
        [Guid]$ObjectType = [Guid]::Empty,
        [Parameter(Mandatory = $true)][string]$Inheritance,
        [Guid]$InheritedObjectType = [Guid]::Empty
    )
    return [pscustomobject]@{
        Label               = $Label
        Rights              = $Rights
        ObjectType          = $ObjectType
        Inheritance         = $Inheritance
        InheritedObjectType = $InheritedObjectType
    }
}

function Get-DelegationSpecs {
    param([Parameter(Mandatory = $true)]$Ctx)
    $specs = New-Object System.Collections.Generic.List[object]

    if ($Ctx.Rights -contains 'Read') {
        $specs.Add((New-Spec -Label 'OU : lister le contenu' -Rights 'ListChildren' -Inheritance 'None'))
    }
    foreach ($cls in $Ctx.Classes) {
        if ($Ctx.Rights -contains 'Read') {
            $specs.Add((New-Spec -Label ("{0} : lire les proprietes (enfants directs)" -f $cls.Label) `
                        -Rights 'ReadProperty' -Inheritance 'Children' -InheritedObjectType $cls.Guid))
        }
        $createDelete = @()
        if ($Ctx.Rights -contains 'Create') { $createDelete += 'CreateChild' }
        if ($Ctx.Rights -contains 'Delete') { $createDelete += 'DeleteChild' }
        if ($createDelete.Count -gt 0) {
            $specs.Add((New-Spec -Label ("{0} : {1} dans l'OU" -f $cls.Label, ($createDelete -join ' + ')) `
                        -Rights ($createDelete -join ', ') -ObjectType $cls.Guid -Inheritance 'None'))
        }
        if ($Ctx.Rights -contains 'Manage') {
            foreach ($attr in $cls.Attributes) {
                $specs.Add((New-Spec -Label ("{0} : ecrire {1}" -f $cls.Label, $attr.Name) `
                            -Rights 'WriteProperty' -ObjectType $attr.Guid -Inheritance 'Children' -InheritedObjectType $cls.Guid))
            }
            foreach ($vw in $Ctx.ValidatedWrites) {
                $specs.Add((New-Spec -Label ("{0} : ecriture validee {1}" -f $cls.Label, $vw.Name) `
                            -Rights 'Self' -ObjectType $vw.Guid -Inheritance 'Children' -InheritedObjectType $cls.Guid))
            }
        }
    }
    return $specs.ToArray()
}

function Get-AuditSpecs {
    param([Parameter(Mandatory = $true)]$Ctx)
    $specs = New-Object System.Collections.Generic.List[object]
    $specs.Add((New-Spec -Label 'OU : modification des proprietes / ACL / proprietaire' `
                -Rights 'WriteProperty, WriteDacl, WriteOwner' -Inheritance 'None'))
    foreach ($cls in $Ctx.Classes) {
        $specs.Add((New-Spec -Label ("{0} : creation / suppression" -f $cls.Label) `
                    -Rights 'CreateChild, DeleteChild' -ObjectType $cls.Guid -Inheritance 'None'))
        $specs.Add((New-Spec -Label ("{0} : modification des objets enfants" -f $cls.Label) `
                    -Rights 'WriteProperty, WriteDacl, WriteOwner' -Inheritance 'Children' -InheritedObjectType $cls.Guid))
    }
    return $specs.ToArray()
}

function ConvertTo-AccessRule {
    param([Parameter(Mandatory = $true)]$Spec, [Parameter(Mandatory = $true)]$Sid)
    $adRights = [System.DirectoryServices.ActiveDirectoryRights]$Spec.Rights
    $inherit  = [System.DirectoryServices.ActiveDirectorySecurityInheritance]$Spec.Inheritance
    $allow    = [System.Security.AccessControl.AccessControlType]::Allow
    return (New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList @(
            $Sid, $adRights, $allow, [Guid]$Spec.ObjectType, $inherit, [Guid]$Spec.InheritedObjectType))
}

function ConvertTo-AuditRule {
    param([Parameter(Mandatory = $true)]$Spec, [Parameter(Mandatory = $true)]$Sid)
    $adRights = [System.DirectoryServices.ActiveDirectoryRights]$Spec.Rights
    $inherit  = [System.DirectoryServices.ActiveDirectorySecurityInheritance]$Spec.Inheritance
    $success  = [System.Security.AccessControl.AuditFlags]::Success
    return (New-Object System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList @(
            $Sid, $adRights, $success, [Guid]$Spec.ObjectType, $inherit, [Guid]$Spec.InheritedObjectType))
}

function Show-Specs {
    param([object[]]$Specs)
    ($Specs | Select-Object Label, Rights, Inheritance, ObjectType, InheritedObjectType |
        Format-Table -AutoSize | Out-String -Width 250) | Write-Host
}

# --- Lecture / comparaison des ACL --------------------------------------------
function Get-AclReport {
    param($Acl)
    foreach ($ace in @($Acl.Access)) {
        [pscustomobject]@{
            Identity            = [string]$ace.IdentityReference
            SID                 = Get-AceSid $ace
            Type                = [string]$ace.AccessControlType
            Rights              = [string]$ace.ActiveDirectoryRights
            Inheritance         = [string]$ace.InheritanceType
            ObjectType          = $ace.ObjectType
            InheritedObjectType = $ace.InheritedObjectType
            Inherited           = $ace.IsInherited
        }
    }
}

function Find-SpecEntries {
    param(
        $Entries,
        [Parameter(Mandatory = $true)]$Spec,
        [Parameter(Mandatory = $true)][string]$TrusteeSid,
        [Parameter(Mandatory = $true)][ValidateSet('Access', 'Audit')][string]$Kind
    )
    $wantRights  = [System.DirectoryServices.ActiveDirectoryRights]$Spec.Rights
    $wantInherit = [System.DirectoryServices.ActiveDirectorySecurityInheritance]$Spec.Inheritance
    $wantObject  = [Guid]$Spec.ObjectType
    $wantInhObj  = [Guid]$Spec.InheritedObjectType
    foreach ($entry in @($Entries)) {
        if ($entry.IsInherited) { continue }
        if ((Get-AceSid $entry) -ne $TrusteeSid) { continue }
        if ($Kind -eq 'Access' -and $entry.AccessControlType -ne 'Allow') { continue }
        if ($Kind -eq 'Audit' -and $entry.AuditFlags -ne 'Success') { continue }
        if ($entry.ActiveDirectoryRights -ne $wantRights) { continue }
        if ($entry.InheritanceType -ne $wantInherit) { continue }
        if ($entry.ObjectType -ne $wantObject) { continue }
        if ($entry.InheritedObjectType -ne $wantInhObj) { continue }
        $entry
    }
}

function Test-SpecsPresent {
    param(
        [Parameter(Mandatory = $true)]$Acl,
        [Parameter(Mandatory = $true)][object[]]$Specs,
        [Parameter(Mandatory = $true)][string]$TrusteeSid,
        [Parameter(Mandatory = $true)][ValidateSet('Access', 'Audit')][string]$Kind
    )
    $allOk = $true
    $entries = @()
    if ($Kind -eq 'Access') { $entries = @($Acl.Access) } else { $entries = @($Acl.Audit) }
    $label = if ($Kind -eq 'Access') { 'ACE' } else { "Regle d'audit" }
    $index = 0
    foreach ($spec in $Specs) {
        $index++
        $found = @(Find-SpecEntries -Entries $entries -Spec $spec -TrusteeSid $TrusteeSid -Kind $Kind)
        if ($found.Count -gt 0) { Write-Log ("{0} {1} presente : {2}" -f $label, $index, $spec.Label) 'OK' }
        else { Write-Log ("{0} {1} ABSENTE : {2}" -f $label, $index, $spec.Label) 'ERROR'; $allOk = $false }
    }
    return $allOk
}

function Get-UnplannedGroupAces {
    param(
        [Parameter(Mandatory = $true)]$Acl,
        [Parameter(Mandatory = $true)][object[]]$Specs,
        [Parameter(Mandatory = $true)][string]$GroupSid
    )
    foreach ($entry in @($Acl.Access)) {
        if ($entry.IsInherited) { continue }
        if ((Get-AceSid $entry) -ne $GroupSid) { continue }
        $matched = $false
        foreach ($spec in $Specs) {
            if (@(Find-SpecEntries -Entries @($entry) -Spec $spec -TrusteeSid $GroupSid -Kind 'Access').Count -gt 0) {
                $matched = $true
                break
            }
        }
        if (-not $matched) { $entry }
    }
}

function Show-AclAudit {
    param(
        [Parameter(Mandatory = $true)]$Acl,
        [Parameter(Mandatory = $true)][string]$GroupSid,
        [Parameter(Mandatory = $true)][object[]]$Specs
    )
    $report = @(Get-AclReport -Acl $Acl)

    Write-Log "ACE explicites (non heritees) de l'OU :"
    ($report | Where-Object { -not $_.Inherited } |
        Format-Table Identity, Type, Rights, Inheritance, ObjectType, InheritedObjectType -AutoSize |
        Out-String -Width 250) | Write-Host

    $unexpected = @($report | Where-Object {
            -not $_.Inherited -and $_.SID -ne $GroupSid -and -not (Test-ExpectedPrincipal $_.SID)
        })
    if ($unexpected.Count -gt 0) {
        Write-Log "ACE explicites pour des principaux inattendus (a examiner, risque de permission transverse) :" 'WARN'
        ($unexpected | Format-Table Identity, Type, Rights, Inheritance -AutoSize | Out-String -Width 250) | Write-Host
    }
    else { Write-Log "Aucune ACE explicite pour un principal inattendu." 'OK' }

    $inheritedGroup = @($report | Where-Object { $_.Inherited -and $_.SID -eq $GroupSid })
    if ($inheritedGroup.Count -gt 0) {
        Write-Log "Le groupe delegue possede des droits HERITES sur l'OU (delegation posee plus haut = transverse) :" 'WARN'
        ($inheritedGroup | Format-Table Identity, Type, Rights, Inheritance -AutoSize | Out-String -Width 250) | Write-Host
    }
    else { Write-Log "Aucun droit herite pour le groupe delegue." 'OK' }

    $unplanned = @(Get-UnplannedGroupAces -Acl $Acl -Specs $Specs -GroupSid $GroupSid)
    if ($unplanned.Count -gt 0) {
        Write-Log "ACE explicites du groupe delegue NON PREVUES par ce script (droits en plus) :" 'WARN'
        ($unplanned | Format-Table IdentityReference, ActiveDirectoryRights, InheritanceType, ObjectType, InheritedObjectType -AutoSize |
            Out-String -Width 250) | Write-Host
    }
    else { Write-Log "Aucune ACE explicite non prevue pour le groupe delegue." 'OK' }

    return [pscustomobject]@{
        Report         = $report
        Unexpected     = $unexpected
        InheritedGroup = $inheritedGroup
        Unplanned      = $unplanned
    }
}

function Backup-Acl {
    param([Parameter(Mandatory = $true)]$Ctx)
    $file = Join-Path $Ctx.BackupPath "MSA-OU-ACL-$($Ctx.Stamp).sddl"
    try { $current = Get-Acl -Path $Ctx.AdPath -Audit }
    catch {
        Write-Log "Lecture de la SACL impossible (SeSecurityPrivilege ?). Sauvegarde de la DACL uniquement." 'WARN'
        $current = Get-Acl -Path $Ctx.AdPath
    }
    $sddl = $current.GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::All)
    [System.IO.File]::WriteAllText($file, $sddl)
    $csv = Join-Path $Ctx.BackupPath "MSA-OU-ACL-$($Ctx.Stamp).csv"
    Get-AclReport -Acl $current | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8 -WhatIf:$false
    Write-Log "Sauvegarde ACL (SDDL) : $file"
    Write-Log "Export ACL (CSV)      : $csv"
    return $file
}

function Find-GroupAceElsewhere {
    param(
        [Parameter(Mandatory = $true)][string]$Server,
        [Parameter(Mandatory = $true)][string]$BaseDn,
        [Parameter(Mandatory = $true)][string]$DriveName,
        [Parameter(Mandatory = $true)][string]$GroupSid,
        [Parameter(Mandatory = $true)][string]$ExcludeDn
    )
    $containers = @(Get-ADObject -Server $Server -SearchBase $BaseDn -SearchScope Subtree -ResultPageSize 500 `
            -LDAPFilter '(|(objectClass=organizationalUnit)(objectClass=container)(objectClass=domainDNS))')
    Write-Log "Analyse de $($containers.Count) conteneur(s) sous '$BaseDn'..."
    foreach ($container in $containers) {
        if ($container.DistinguishedName -eq $ExcludeDn) { continue }
        try { $containerAcl = Get-Acl -Path ("{0}:\{1}" -f $DriveName, $container.DistinguishedName) }
        catch {
            Write-Log "ACL illisible : $($container.DistinguishedName) ($($_.Exception.Message))" 'WARN'
            continue
        }
        foreach ($hit in @($containerAcl.Access | Where-Object { -not $_.IsInherited -and (Get-AceSid $_) -eq $GroupSid })) {
            [pscustomobject]@{
                Container   = $container.DistinguishedName
                Type        = [string]$hit.AccessControlType
                Rights      = [string]$hit.ActiveDirectoryRights
                Inheritance = [string]$hit.InheritanceType
            }
        }
    }
}

function Test-KdsRootKey {
    try { $keys = @(Get-KdsRootKey -ErrorAction Stop) }
    catch {
        Write-Log "Cle racine KDS non verifiable avec ce compte ($($_.Exception.Message))." 'WARN'
        return
    }
    if ($keys.Count -eq 0) {
        Write-Log "Aucune cle racine KDS : la creation de gMSA echouera tant qu'elle n'existe pas (Add-KdsRootKey, droit non delegue)." 'WARN'
        return
    }
    $effective = @($keys | Where-Object { $_.EffectiveTime -le (Get-Date) })
    if ($effective.Count -eq 0) { Write-Log "Une cle racine KDS existe mais n'est pas encore effective (delai de replication / 10 h)." 'WARN' }
    else { Write-Log "Cle racine KDS effective presente." 'OK' }
}

function Invoke-FunctionalTest {
    param([Parameter(Mandatory = $true)]$Ctx)

    if ($WhatIfPreference) {
        Write-Log "Le test fonctionnel cree de vrais objets : il est ignore en mode -WhatIf." 'WARN'
        return $true
    }
    $common = @{ Server = $Ctx.Server }
    if ($Ctx.TestCredential) { $common['Credential'] = $Ctx.TestCredential }
    $who = if ($Ctx.TestCredential) { $Ctx.TestCredential.UserName } else { "$env:USERDOMAIN\$env:USERNAME" }
    Write-Log "Test fonctionnel execute en tant que : $who (attendu : $(if ($Ctx.ExpectDenied) { 'CREATION REFUSEE' } else { 'ACCES AUTORISE' }))"

    $overallOk = $true
    foreach ($cls in $Ctx.Classes) {
        $name = '{0}{1}{2}' -f $Ctx.TestNamePrefix, $cls.Label.Substring(0, 1).ToLower(), ('{0:D4}' -f (Get-Random -Minimum 0 -Maximum 10000))
        $fqdn = '{0}.{1}' -f $name, $Ctx.TestDnsSuffix
        $spn  = "MSATEST/$name"
        $description = 'Test delegation - suppression automatique'
        Write-Log "--- Test $($cls.Label) : $name ---"

        $created = $false
        $createError = ''
        try {
            if ($cls.Label -eq 'gMSA') {
                New-ADServiceAccount @common -Name $name -DNSHostName $fqdn -Path $Ctx.TargetOU `
                    -PrincipalsAllowedToRetrieveManagedPassword $Ctx.TestPrincipal -ManagedPasswordIntervalInDays 30 `
                    -Description $description
            }
            else {
                New-ADServiceAccount @common -Name $name -RestrictToSingleComputer -Path $Ctx.TargetOU -Description $description
            }
            $created = $true
            Write-Log "Creation : OK" 'OK'
        }
        catch { $createError = $_.Exception.Message }

        $stepFailures = 0
        if ($created) {
            $steps = New-Object System.Collections.Generic.List[object]
            $steps.Add(@{ Label = 'Modification de description'; Block = { Set-ADServiceAccount @common -Identity $name -Description 'Test delegation - modifie' } })
            $steps.Add(@{ Label = 'Ajout d''un SPN (ecriture validee)'; Block = { Set-ADServiceAccount @common -Identity $name -Add @{ servicePrincipalName = $spn } } })
            $steps.Add(@{ Label = 'Retrait du SPN'; Block = { Set-ADServiceAccount @common -Identity $name -Remove @{ servicePrincipalName = $spn } } })
            $steps.Add(@{ Label = 'Types de chiffrement Kerberos'; Block = { Set-ADServiceAccount @common -Identity $name -KerberosEncryptionType AES256 } })
            if ($cls.Label -eq 'gMSA') {
                $steps.Add(@{ Label = 'Ecriture de msDS-GroupMSAMembership'; Block = { Set-ADServiceAccount @common -Identity $name -PrincipalsAllowedToRetrieveManagedPassword $Ctx.TestPrincipal } })
            }
            foreach ($step in $steps) {
                try { & $step.Block; Write-Log "$($step.Label) : OK" 'OK' }
                catch { $stepFailures++; Write-Log "$($step.Label) : ECHEC - $($_.Exception.Message)" 'ERROR' }
            }
            try {
                Remove-ADServiceAccount @common -Identity $name -Confirm:$false
                Write-Log "Suppression : OK" 'OK'
            }
            catch {
                $overallOk = $false
                Write-Log "Compte de test '$name' NON supprime : $($_.Exception.Message). A supprimer manuellement." 'ERROR'
            }
        }

        if ($Ctx.ExpectDenied) {
            if ($created) { $overallOk = $false; Write-Log "ECHEC : la creation aurait du etre refusee pour ce compte." 'ERROR' }
            else { Write-Log "Creation refusee comme attendu : $createError" 'OK' }
        }
        else {
            if (-not $created) { $overallOk = $false; Write-Log "Creation refusee ou en erreur : $createError" 'ERROR' }
            elseif ($stepFailures -gt 0) { $overallOk = $false }
        }
    }
    return $overallOk
}

# ---------------------------------------------------------------------------
# Initialisation
# ---------------------------------------------------------------------------
$exitCode = 0
$stamp    = Get-Date -Format 'yyyyMMdd-HHmmss'

if (-not (Test-Path -Path $BackupPath)) {
    New-Item -ItemType Directory -Path $BackupPath -Force -WhatIf:$false | Out-Null
}
$logFile = Join-Path $BackupPath "MSA-Delegation-$Action-$stamp.log"
Start-Transcript -Path $logFile -WhatIf:$false | Out-Null
Write-Host "Set-MSADelegation.ps1 - version 1.0 (fichier : $($MyInvocation.MyCommand.Path))" -ForegroundColor Magenta

$driveName = 'MSADELEG'

try {
    Import-Module ActiveDirectory

    if (-not $Server) { $Server = (Get-ADDomain).PDCEmulator }
    $domain   = Get-ADDomain -Server $Server
    $rootDse  = Get-ADRootDSE -Server $Server
    Write-Log "Action : $Action | DC : $Server | Domaine : $($domain.DNSRoot)$(if ($WhatIfPreference) { ' | MODE DRY RUN (-WhatIf)' })"
    Write-Log "OU cible : $TargetOU"

    # --- OU cible
    $ouObject = Get-ADObject -Identity $TargetOU -Server $Server -Properties objectClass
    if ($ouObject.objectClass -notin @('organizationalUnit', 'container')) {
        throw "L'objet cible n'est ni une OU ni un conteneur (classe : $($ouObject.objectClass))."
    }

    # --- Groupe delegue
    $group = Get-ADGroup -Identity $DelegateGroup -Server $Server
    $groupSid = $group.SID
    $groupSidValue = $groupSid.Value
    Write-Log "Groupe delegue : $($group.DistinguishedName) ($groupSidValue)"

    # --- Lecteur AD: pointe sur le DC choisi
    if (Get-PSDrive -Name $driveName -ErrorAction SilentlyContinue) { Remove-PSDrive -Name $driveName -Force -WhatIf:$false }
    New-PSDrive -Name $driveName -PSProvider ActiveDirectory -Root '//RootDSE/' -Server $Server -Scope Script -WhatIf:$false | Out-Null
    $adPath = "${driveName}:\$($ouObject.DistinguishedName)"
    if (-not (Test-Path -LiteralPath $adPath)) { throw "OU introuvable via le lecteur AD : $($ouObject.DistinguishedName)" }

    # --- Controle de concordance de Tier (OU <-> groupe)
    if (-not $SkipTierCheck -and $Action -ne 'Restore') {
        $tierCheck = Test-TierConsistency -TargetOuDn $ouObject.DistinguishedName -GroupDn $group.DistinguishedName `
            -TierNumber $TierNumber -TierPrefixes $TierPrefixes
        if ($tierCheck.Ok) {
            Write-Log "Concordance de Tier validee (Tier $TierNumber) : OU et groupe appartiennent au meme Tier." 'OK'
        }
        else {
            foreach ($msg in $tierCheck.Messages) { Write-Log $msg 'ERROR' }
            if ($Action -eq 'Apply') {
                throw "Controle de concordance de Tier en echec : delegation refusee. Corrigez les parametres ou utilisez -SkipTierCheck en connaissance de cause."
            }
            Write-Log "Controle de concordance de Tier en echec (action $Action poursuivie)." 'WARN'
            if ($Action -in @('Audit', 'Verify')) { $exitCode = 1 }
        }
    }
    elseif ($SkipTierCheck) {
        Write-Log "Controle de concordance de Tier IGNORE (-SkipTierCheck)." 'WARN'
    }

    # --- Resolution du schema : classes, attributs, droits etendus
    $schemaNC = $rootDse.schemaNamingContext
    $configNC = $rootDse.configurationNamingContext

    $classDefinitions = @()
    if ($MsaType -in @('gMSA', 'Both')) { $classDefinitions += [pscustomobject]@{ Label = 'gMSA'; LdapName = 'msDS-GroupManagedServiceAccount'; AttrNames = @($GmsaAttributes) } }
    if ($MsaType -in @('sMSA', 'Both')) { $classDefinitions += [pscustomobject]@{ Label = 'sMSA'; LdapName = 'msDS-ManagedServiceAccount'; AttrNames = @($SmsaAttributes) } }

    $classes = @()
    foreach ($definition in $classDefinitions) {
        $classGuid = Resolve-SchemaGuid -Server $Server -SchemaNC $schemaNC -LdapName $definition.LdapName -SchemaClass 'classSchema'
        if ($null -eq $classGuid) {
            if ($MsaType -eq 'Both') { Write-Log "Classe $($definition.LdapName) absente du schema : $($definition.Label) ignore." 'WARN'; continue }
            throw "Classe $($definition.LdapName) absente du schema."
        }
        $attrNames = @($definition.AttrNames) + @($ExtraAttributes)
        if ($AllowEnableDisable) { $attrNames += 'userAccountControl' }
        $attributes = @()
        foreach ($attrName in ($attrNames | Where-Object { $_ } | Select-Object -Unique)) {
            $attrGuid = Resolve-SchemaGuid -Server $Server -SchemaNC $schemaNC -LdapName $attrName -SchemaClass 'attributeSchema'
            if ($null -eq $attrGuid) { throw "Attribut '$attrName' introuvable dans le schema." }
            $attributes += [pscustomobject]@{ Name = $attrName; Guid = $attrGuid }
        }
        $classes += [pscustomobject]@{ Label = $definition.Label; LdapName = $definition.LdapName; Guid = $classGuid; Attributes = $attributes }
    }
    if ($classes.Count -eq 0) { throw "Aucune classe MSA disponible dans le schema." }

    $validatedWriteList = @()
    foreach ($rightName in ($ValidatedWrites | Where-Object { $_ } | Select-Object -Unique)) {
        $rightGuid = Resolve-ExtendedRightGuid -Server $Server -ConfigNC $configNC -RightName $rightName
        if ($null -eq $rightGuid) { throw "Droit etendu '$rightName' introuvable dans CN=Extended-Rights." }
        $validatedWriteList += [pscustomobject]@{ Name = $rightName; Guid = $rightGuid }
    }

    $effectiveDnsSuffix = if ($TestDnsSuffix) { $TestDnsSuffix } else { $domain.DNSRoot }
    $effectiveTestPrincipal = if ($TestPrincipal) { $TestPrincipal } else { $group.DistinguishedName }

    $ctx = [pscustomobject]@{
        Server          = $Server
        TargetOU        = $ouObject.DistinguishedName
        AdPath          = $adPath
        BackupPath      = $BackupPath
        Stamp           = $stamp
        Rights          = @($Rights)
        Classes         = $classes
        ValidatedWrites = $validatedWriteList
        TestCredential  = $TestCredential
        ExpectDenied    = [bool]$ExpectDenied
        TestPrincipal   = $effectiveTestPrincipal
        TestNamePrefix  = $TestNamePrefix
        TestDnsSuffix   = $effectiveDnsSuffix
    }

    $accessSpecs = @(Get-DelegationSpecs -Ctx $ctx)
    $auditSpecs  = @(Get-AuditSpecs -Ctx $ctx)
    $everyoneSid = New-Object System.Security.Principal.SecurityIdentifier -ArgumentList 'S-1-1-0'
    Write-Log "Classes : $((@($classes | ForEach-Object { $_.Label })) -join ', ') | Droits : $($Rights -join ', ') | $($accessSpecs.Count) ACE prevue(s)"

    # -----------------------------------------------------------------------
    # Execution de l'action
    # -----------------------------------------------------------------------
    switch ($Action) {

        'Audit' {
            $acl = Get-Acl -Path $adPath
            $result = Show-AclAudit -Acl $acl -GroupSid $groupSidValue -Specs $accessSpecs
            $csv = Join-Path $BackupPath "MSA-OU-Audit-$stamp.csv"
            $result.Report | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8 -WhatIf:$false
            Write-Log "Export CSV : $csv"
            if ($result.Unexpected.Count -gt 0 -or $result.InheritedGroup.Count -gt 0 -or $result.Unplanned.Count -gt 0) { $exitCode = 1 }
        }

        'Apply' {
            if (Test-BroadPrincipal -SidValue $groupSidValue) {
                throw "Groupe '$($group.Name)' refuse (groupe large : Everyone, Authenticated Users, Domain Users, Domain Computers...). Utilisez un groupe d'administration du Tier."
            }
            $null = Backup-Acl -Ctx $ctx

            if ($IncludeAudit) { $acl = Get-Acl -Path $adPath -Audit } else { $acl = Get-Acl -Path $adPath }

            Write-Log "ACE a appliquer :"
            Show-Specs -Specs $accessSpecs
            foreach ($spec in $accessSpecs) { $acl.AddAccessRule((ConvertTo-AccessRule -Spec $spec -Sid $groupSid)) }

            if ($IncludeAudit) {
                Write-Log "Regles d'audit a appliquer :"
                Show-Specs -Specs $auditSpecs
                foreach ($spec in $auditSpecs) { $acl.AddAuditRule((ConvertTo-AuditRule -Spec $spec -Sid $everyoneSid)) }
            }

            Save-Acl -Path $adPath -Acl $acl -Description "Delegation MSA appliquee a $($group.Name)"

            if (-not $WhatIfPreference) {
                Write-Log "Controle post-application :"
                if ($IncludeAudit) { $check = Get-Acl -Path $adPath -Audit } else { $check = Get-Acl -Path $adPath }
                $ok = Test-SpecsPresent -Acl $check -Specs $accessSpecs -TrusteeSid $groupSidValue -Kind 'Access'
                if ($IncludeAudit) { $ok = (Test-SpecsPresent -Acl $check -Specs $auditSpecs -TrusteeSid $everyoneSid.Value -Kind 'Audit') -and $ok }
                if (-not $ok) { $exitCode = 1 }
                $result = Show-AclAudit -Acl $check -GroupSid $groupSidValue -Specs $accessSpecs
                if ($result.Unplanned.Count -gt 0 -or $result.InheritedGroup.Count -gt 0) { $exitCode = 1 }
            }
            if ($IncludeAudit) {
                Write-Log "Rappel : activer 'DS Access > Audit Directory Service Changes' (Succes) par GPO sur les DC. Evenements : 5136, 5137, 5141." 'WARN'
            }
            if ($classes | Where-Object { $_.Label -eq 'gMSA' }) { Test-KdsRootKey }
        }

        'Verify' {
            if ($IncludeAudit) { $check = Get-Acl -Path $adPath -Audit } else { $check = Get-Acl -Path $adPath }
            $ok = Test-SpecsPresent -Acl $check -Specs $accessSpecs -TrusteeSid $groupSidValue -Kind 'Access'
            if ($IncludeAudit) { $ok = (Test-SpecsPresent -Acl $check -Specs $auditSpecs -TrusteeSid $everyoneSid.Value -Kind 'Audit') -and $ok }

            $result = Show-AclAudit -Acl $check -GroupSid $groupSidValue -Specs $accessSpecs
            if ($result.Unexpected.Count -gt 0 -or $result.InheritedGroup.Count -gt 0 -or $result.Unplanned.Count -gt 0) { $ok = $false }

            if ($ScanBaseDN) {
                $elsewhere = @(Find-GroupAceElsewhere -Server $Server -BaseDn $ScanBaseDN -DriveName $driveName `
                        -GroupSid $groupSidValue -ExcludeDn $ouObject.DistinguishedName)
                if ($elsewhere.Count -gt 0) {
                    Write-Log "Le groupe delegue a des droits explicites HORS de l'OU cible (delegation transverse) :" 'ERROR'
                    ($elsewhere | Format-Table Container, Type, Rights, Inheritance -AutoSize | Out-String -Width 250) | Write-Host
                    $ok = $false
                }
                else { Write-Log "Aucun droit explicite du groupe delegue hors de l'OU cible sous '$ScanBaseDN'." 'OK' }
            }
            if ($classes | Where-Object { $_.Label -eq 'gMSA' }) { Test-KdsRootKey }
            if ($FunctionalTest) { $ok = (Invoke-FunctionalTest -Ctx $ctx) -and $ok }

            if (-not $ok) { $exitCode = 1; Write-Log "Verification : ECART(S) CONSTATE(S)." 'ERROR' }
            else { Write-Log "Verification : CONFORME." 'OK' }
        }

        'Rollback' {
            $null = Backup-Acl -Ctx $ctx

            if ($IncludeAudit) { $acl = Get-Acl -Path $adPath -Audit } else { $acl = Get-Acl -Path $adPath }

            foreach ($spec in $accessSpecs) { $acl.RemoveAccessRuleSpecific((ConvertTo-AccessRule -Spec $spec -Sid $groupSid)) }
            if ($IncludeAudit) {
                foreach ($spec in $auditSpecs) { $acl.RemoveAuditRuleSpecific((ConvertTo-AuditRule -Spec $spec -Sid $everyoneSid)) }
            }

            Save-Acl -Path $adPath -Acl $acl -Description "ACE de delegation retirees pour $($group.Name)"

            if (-not $WhatIfPreference) {
                $check = Get-Acl -Path $adPath
                $remaining = @($check.Access | Where-Object { -not $_.IsInherited -and (Get-AceSid $_) -eq $groupSidValue })
                if ($remaining.Count -gt 0) {
                    Write-Log "Il reste $($remaining.Count) ACE explicite(s) pour $($group.Name) (posees avec d'autres parametres ou hors de ce script). Verifiez avec -Action Audit ou utilisez -Action Restore." 'WARN'
                    $exitCode = 1
                }
                else { Write-Log "Aucune ACE explicite restante pour $($group.Name)." 'OK' }
            }
        }

        'Restore' {
            if (-not $RestoreFile) { throw "Le parametre -RestoreFile est obligatoire avec -Action Restore." }
            if (-not (Test-Path -LiteralPath $RestoreFile)) { throw "Fichier introuvable : $RestoreFile" }

            $null = Backup-Acl -Ctx $ctx     # sauvegarde de l'etat courant avant restauration

            $sddl = [System.IO.File]::ReadAllText($RestoreFile).Trim()
            $acl  = Get-Acl -Path $adPath -Audit
            $acl.SetSecurityDescriptorSddlForm($sddl)

            Write-Log "Restauration de l'ACL COMPLETE de l'OU depuis : $RestoreFile" 'WARN'
            Save-Acl -Path $adPath -Acl $acl -Description "ACL de l'OU restauree"
        }
    }
}
catch {
    Write-Log "Erreur : $($_.Exception.Message)" 'ERROR'
    $exitCode = 1
}
finally {
    if (Get-PSDrive -Name $driveName -ErrorAction SilentlyContinue) {
        Remove-PSDrive -Name $driveName -Force -WhatIf:$false -ErrorAction SilentlyContinue
    }
    Write-Log "Journal : $logFile"
    Stop-Transcript | Out-Null
}

exit $exitCode