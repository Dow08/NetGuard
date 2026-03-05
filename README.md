# 🔒 NetGuard Dashboard v2.1

**Dashboard local de surveillance réseau pour Freebox** — Monitore ton réseau domestique en temps réel depuis ton navigateur.

![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=flat-square&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-2.x-000000?style=flat-square&logo=flask)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-blue?style=flat-square)

---

## 📸 Aperçu

NetGuard se connecte à l'API locale de ta Freebox (Freebox OS) et te donne une visibilité complète sur ton réseau :

- Qui est connecté, depuis quand, avec quelle bande passante
- Quels sites sont visités par chaque appareil
- Les tentatives d'intrusion et les ports ouverts
- Les alertes en temps réel quand un nouvel appareil apparaît

**100% local** — Aucune donnée ne quitte ton réseau. Pas de cloud, pas de compte, pas de tracking.

---

## ✨ Fonctionnalités

| Module | Description |
|--------|-------------|
| **📡 Appareils** | Liste complète des appareils connectés (IP, MAC, fabricant, état). Approuver/bloquer chaque appareil. |
| **🗺️ Carte réseau** | Visualisation graphique du réseau groupée par type d'appareil (PC, smartphones, IoT...) |
| **🔔 Alertes temps réel** | Notification automatique quand un nouvel appareil se connecte ou se déconnecte |
| **🔍 Scan de vulnérabilités** | Scan de 26 ports courants par appareil avec évaluation du niveau de risque |
| **🌐 Capture DNS** | Log en temps réel de toutes les requêtes DNS du réseau (nécessite sudo/admin) |
| **📋 Agrégateur de sites** | Classement des domaines visités par appareil — vue globale ou par appareil |
| **📊 Bande passante** | Graphique en temps réel du download/upload avec historique |
| **⚡ Speed Test** | Test de vitesse intégré (ping, download, upload) |
| **⚙️ Infos système** | Température CPU, firmware, uptime de la Freebox |
| **📥 Export** | Export CSV des appareils, alertes, scans et données DNS |

---

## 🚀 Installation rapide

### Prérequis

- **Python 3.8+** ([python.org](https://python.org) — cocher "Add to PATH" sur Windows)
- Être connecté au **réseau Freebox** (WiFi ou Ethernet)

### 1. Cloner le repo

```bash
git clone https://github.com/TON_USERNAME/netguard.git
cd netguard
```

### 2. Installer les dépendances

```bash
pip install requests flask flask-cors
```

Optionnel (capture DNS, nécessite droits admin) :
```bash
pip install scapy
```

### 3. Lancer

```bash
python netguard_server.py
```

Avec capture DNS (Linux) :
```bash
sudo python3 netguard_server.py
```

### 4. Première connexion

Au premier lancement, la Freebox demande une autorisation :

- **Freebox avec écran LCD** : Validez directement sur la box
- **Freebox Pop/Mini (sans écran)** : Allez sur [mafreebox.freebox.fr](http://mafreebox.freebox.fr) → Paramètres → Gestion des accès → Applications → Recharger → Validez "NetGuard Dashboard"

Le token est sauvegardé dans `~/.netguard_token.json` — pas besoin de revalider.

### 5. Ouvrir le dashboard

👉 **http://localhost:8765**

---

## 🖥️ Démarrage automatique (Windows)

Pour que NetGuard se lance à chaque démarrage de Windows :

```
Clic droit sur install_startup.bat → Exécuter en tant qu'administrateur
```

Pour désactiver :
```
Clic droit sur remove_startup.bat → Exécuter en tant qu'administrateur
```

---

## 📁 Structure du projet

```
netguard/
├── netguard_server.py          # Serveur backend Python (API Freebox + Flask)
├── dashboard/
│   └── index.html              # Interface web (HTML/CSS/JS standalone)
├── install_startup.bat         # Installation démarrage auto Windows
├── remove_startup.bat          # Désinstallation démarrage auto
├── start.bat                   # Lanceur Windows
├── start.sh                    # Lanceur Linux
├── install.sh                  # Installation Linux
├── requirements.txt            # Dépendances Python
├── .gitignore                  # Fichiers à exclure de Git
├── LICENSE                     # Licence MIT
└── README.md                   # Ce fichier
```

### Données persistantes (créées automatiquement)

```
~/.netguard_data/
├── device_history.json         # Historique de connexion par appareil
├── known_devices.json          # Appareils approuvés/connus
├── alerts.json                 # Journal des alertes
├── dns_aggregated.json         # Agrégation DNS par appareil
└── netguard.log                # Logs du serveur

~/.netguard_token.json          # Token d'authentification Freebox
```

Toutes les données sont automatiquement purgées au-delà de **48 heures**.

---

## 🔌 API Endpoints

Le serveur expose une API REST sur `http://localhost:8765/api/` :

### Monitoring
| Endpoint | Méthode | Description |
|----------|---------|-------------|
| `/api/status` | GET | État de connexion et version |
| `/api/devices` | GET | Liste des appareils du réseau |
| `/api/bandwidth` | GET | Bande passante temps réel |
| `/api/bandwidth/history` | GET | Historique bande passante |
| `/api/system` | GET | Infos système Freebox |

### DNS & Sites
| Endpoint | Méthode | Description |
|----------|---------|-------------|
| `/api/dns/log` | GET | Requêtes DNS brutes capturées |
| `/api/dns/aggregated` | GET | Agrégation DNS par appareil |
| `/api/dns/aggregated/global` | GET | Top domaines tous appareils confondus |
| `/api/dns/aggregated/<device>` | GET | Domaines visités par un appareil |

### Sécurité
| Endpoint | Méthode | Description |
|----------|---------|-------------|
| `/api/alerts` | GET | Liste des alertes |
| `/api/alerts/unread` | GET | Nombre d'alertes non lues |
| `/api/alerts/read` | POST | Marquer toutes les alertes comme lues |
| `/api/intruders` | GET | Appareils non approuvés connectés |
| `/api/scan/<mac>` | POST | Lancer un scan de ports |
| `/api/scan/<mac>` | GET | Résultats du scan |
| `/api/scan/all` | POST | Scanner tous les appareils |
| `/api/scan/results` | GET | Tous les résultats de scan |
| `/api/speedtest` | POST | Lancer un speed test |

### Gestion
| Endpoint | Méthode | Description |
|----------|---------|-------------|
| `/api/known_devices` | GET | Liste des appareils connus |
| `/api/known_devices/<mac>/trust` | POST | Approuver un appareil |
| `/api/known_devices/<mac>/untrust` | POST | Retirer l'approbation |
| `/api/history` | GET | Résumé historique tous appareils |
| `/api/history/<mac>` | GET | Historique d'un appareil |

### Export
| Endpoint | Méthode | Description |
|----------|---------|-------------|
| `/api/export/devices/csv` | GET | Export appareils en CSV |
| `/api/export/alerts/csv` | GET | Export alertes en CSV |
| `/api/export/scan/csv` | GET | Export scans en CSV |
| `/api/export/dns/csv` | GET | Export agrégation DNS en CSV |

---

## 🔧 Configuration

Les paramètres principaux se trouvent en haut de `netguard_server.py` :

```python
FREEBOX_HOST = "http://mafreebox.freebox.fr"  # Adresse de la Freebox
LOG_RETENTION = 48 * 3600                       # Durée de rétention des logs (48h)
```

Le port par défaut est **8765**. Pour le changer, modifiez la variable `port` dans la fonction `main()`.

---

## 🔒 Sécurité & Vie privée

- **100% local** — Aucune donnée n'est envoyée à l'extérieur
- **Token sécurisé** — Le token Freebox est stocké avec permissions restrictives (`chmod 600`)
- **Pas de cloud** — Tout tourne sur votre machine
- **Pas de compte** — Aucune inscription, aucun tracking
- **Purge automatique** — Les données sont supprimées après 48h

Le serveur écoute sur `0.0.0.0:8765` par défaut (accessible depuis le réseau local). Pour restreindre à la machine locale uniquement, changez `host="0.0.0.0"` en `host="127.0.0.1"` dans `netguard_server.py`.

---

## 🐛 Dépannage

| Problème | Solution |
|----------|----------|
| "Impossible de contacter la Freebox" | Vérifiez que vous êtes sur le réseau Freebox |
| "Token expiré" | Supprimez `~/.netguard_token.json` et relancez |
| "404 Not Found" sur localhost:8765 | Vérifiez que `dashboard/index.html` existe dans le bon dossier |
| "Permission denied" (DNS sniffer) | Lancez avec `sudo` (Linux) ou en admin (Windows) |
| Pas de données DNS | Le sniffer nécessite `scapy` et les droits admin |
| La Freebox Pop n'a pas d'écran | Validez via Freebox OS → Gestion des accès → Applications |

---

## 📋 Compatibilité Freebox

| Modèle | API | Statut |
|--------|-----|--------|
| Freebox Pop | v15 | ✅ Testé |
| Freebox Delta | v8+ | ✅ Compatible |
| Freebox Ultra | v8+ | ✅ Compatible |
| Freebox Revolution | v6+ | ⚠️ Compatible (API limitée) |
| Freebox Mini 4K | v6+ | ⚠️ Compatible (API limitée) |

---

## 🤝 Contribuer

Les contributions sont les bienvenues ! N'hésitez pas à :

1. Fork le projet
2. Créer une branche (`git checkout -b feature/ma-feature`)
3. Commit (`git commit -m 'Ajout de ma feature'`)
4. Push (`git push origin feature/ma-feature`)
5. Ouvrir une Pull Request

### Idées d'améliorations

- [ ] Notifications Telegram/Discord
- [ ] GeoIP (localiser les destinations sur une carte monde)
- [ ] Wake-on-LAN depuis le dashboard
- [ ] Mode sombre/clair
- [ ] App mobile (PWA)
- [ ] Intégration Pi-hole

---

## 📄 Licence

Ce projet est sous licence MIT — voir le fichier [LICENSE](LICENSE) pour plus de détails.

---

## ⚠️ Avertissement

Cet outil est destiné à la surveillance de **votre propre réseau domestique**. L'utilisation pour surveiller des réseaux sans autorisation est illégale. Respectez la vie privée des utilisateurs de votre réseau et informez-les de la présence de cet outil.
