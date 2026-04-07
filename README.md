# ufw_deploy – Gestionnaire UFW pour nodes radioamateurs

Ce dépôt contient un script bash interactif `node-ufw-manager.sh` qui permet de configurer un firewall UFW (ou iptables) sur un node radioamateur, avec une politique par défaut `deny incoming` / `allow outgoing`, et un mode de test avec rollback au reboot si l’accès est perdu.

## Fonctionnalités principales

- Choix de l’interface réseau (priorité wg3 > wg2 > wg1 > wg0).  
- Autorisation du port SSH (22 ou ports personnalisés), depuis la plage WireGuard `44.27.27.XX/27` et depuis un ou plusieurs réseaux locaux (LAN + ZeroTier).  
- Configuration des ports EchoLink (UDP 5198, UDP 5199, TCP 5200).  
- Mode interactif : `mode test` (rollback automatique au reboot) et `mode statique` (appliqué de façon permanente).  
- Support UFW ou iptables, détectés automatiquement.  
- Possibilité de réexécuter le script pour ajouter de nouveaux ports entrants sans tout refaire.

## Télécharger et exécuter le script

Pour télécharger et lancer le script directement depuis le serveur (en root) :

```bash
curl -s -o node-ufw-manager.sh https://raw.githubusercontent.com/RadioamateursduFjord/ufw_deploy/main/node-ufw-manager.sh && \
chmod +x node-ufw-manager.sh && \
sudo ./node-ufw-manager.sh
```

## Lien vers le dépôt

- Dépôt GitHub : https://github.com/RadioamateursduFjord/ufw_deploy
- Script principal : https://github.com/RadioamateursduFjord/ufw_deploy/blob/main/node-ufw-manager.sh

## Conditions d’utilisation

- Ce script doit être exécuté en root.  
- Il est conçu pour Debian/Ubuntu avec UFW ou iptables.  
- Avant de l’exécuter en production, il est conseillé de le tester en **mode test** puis de le confirmer uniquement si l’accès SSH est resté fonctionnel.

