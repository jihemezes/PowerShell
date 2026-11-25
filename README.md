# 🛠️ Mes Scripts PowerShell

Ce dépôt me sert de boîte à outils personnelle pour centraliser mes scripts d'automatisation, d'audit et d'administration système. L'objectif est simple : éviter les tâches répétitives à la souris et garder sous la main des bouts de code propres, testés et réutilisables.

![Bannière PowerShell Active Directory](./assets/banner.png)


---

## 🗂️ Index des scripts

### 🏢 Active Directory (`/ActiveDirectory`)
Scripts dédiés à la gestion, l'audit et le nettoyage de l'annuaire.

| Script | Utilité | Impact |
| :--- | :--- | :--- |
| [`Manage-ADAuthenticationSilo.ps1`](./AD_Silos/Manage-ADAuthenticationSilo.ps1) *(Exemple)* |  Gestionnaire GRAPHIQUE de silos d'authentification Active Directory. | 🟢 Opérationnel |
| [`TierModel_Deployment_v1.1.ps1`](./Tiering_Model/TierModel_Deployment_v1.1.ps1) *(Exemple)* | Assistant graphique de mise en place d'un Tier Model dans Active Directory. | 🟡 En cours de développement |
| [`New-GmsaGui.ps1`](./Active_Directory/gMSA/New-GmsaGui.ps1) | Assistant GRAPHIQUE de création d'un gMSA et du groupe de serveurs autorisés à récupérer son mot de passe (OU, Tier, chiffrement, groupes, délégations). Dry Run, Rollback JSON, logs. | 🟡 Non testé sur AD réel |
| *À venir...* | *Emplacement pour le prochain script AD* | ⚪ - |

*(D'autres dossiers suivront au fil des besoins : Entra ID, Exchange, Windows Server, etc.)*

---

## ⚡ Utilisation rapide

### Récupérer le dépôt en local
```powershell
git clone https://github.com/TON-PSEUDO/TON-DEPOT.git
cd TON-DEPOT
```

### Lancer un script
Toujours vérifier l'aide intégrée ou faire un test à blanc avant de lancer en prod :

```powershell
# Voir la syntaxe et les paramètres
Get-Help .\ActiveDirectory\NomDuScript.ps1 -Full

# Simuler l'exécution sans rien modifier (si supporté par le script)
.\ActiveDirectory\NomDuScript.ps1 -WhatIf
```

---

## 🔧 Prérequis & Notes

* **Environnement :** PowerShell 5.1 ou PowerShell 7+.
* **Modules :** Le module `ActiveDirectory` (RSAT) est nécessaire pour le dossier AD.
  ```powershell
  # Installation rapide des outils RSAT AD sur Windows 10/11
  Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
  ```
* **Règle d'or :** Toujours tester sur une OU de test ou en environnement de lab avant de lancer une modification en masse sur la prod.# PowerShell
Dépot de mes scripts PowerShell pour l'admin Active Directory
