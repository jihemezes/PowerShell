# 🛠️ Mes Scripts PowerShell

Ce dépôt me sert de boîte à outils personnelle pour centraliser mes scripts d'automatisation, d'audit et d'administration système. L'objectif est simple : éviter les tâches répétitives à la souris et garder sous la main des bouts de code propres, testés et réutilisables.

![Bannière PowerShell Active Directory](./banner.png)
*(Astuce : tu peux enregistrer l'image générée juste au-dessus à la racine de ton dépôt sous le nom `banner.png` pour l'afficher ici !)*

---

## 🗂️ Index des scripts

### 🏢 Active Directory (`/ActiveDirectory`)
Scripts dédiés à la gestion, l'audit et le nettoyage de l'annuaire.

| Script | Utilité | Impact |
| :--- | :--- | :--- |
| [`Get-ADInactiveUsers.ps1`](./ActiveDirectory/Get-ADInactiveUsers.ps1) *(Exemple)* | Liste les comptes inactifs depuis $X$ jours et sort un export CSV. | 🟢 Lecture seule |
| [`New-ADBulkUsers.ps1`](./ActiveDirectory/New-ADBulkUsers.ps1) *(Exemple)* | Création d'utilisateurs en masse depuis un fichier CSV. | 🟡 Modification |
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
