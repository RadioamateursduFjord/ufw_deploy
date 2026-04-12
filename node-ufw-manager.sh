#!/usr/bin/env bash
set -euo pipefail

TEST_FLAG="/var/lib/node-ufw-test-mode"
ROLLBACK_SCRIPT="/usr/local/sbin/node-ufw-rollback-on-boot.sh"
SYSTEMD_SERVICE="/etc/systemd/system/node-ufw-rollback.service"
STATE_DIR="/var/lib/node-ufw-manager"
BACKUP_FILE="$STATE_DIR/firewall-status-before-test.txt"
WG_RANGE="44.27.27.160/27"
ECHO_UDP_PORTS=(5198 5199)
ECHO_TCP_PORT=5200
DEFAULT_LOCAL_NET="192.168.0.0/24"
FIREWALL_BACKEND=""
LOCAL_NETS=()

need_root() {
  if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    echo "Ce script doit être exécuté en root." >&2
    exit 1
  fi
}

print_header() {
  echo
  echo "============================================================"
  echo "$1"
  echo "============================================================"
}

has_cmd() { command -v "$1" >/dev/null 2>&1; }

detect_firewall_backend() {
  local ufw_present=0 iptables_present=0 ufw_active=0 iptables_has_rules=0
  has_cmd ufw && ufw_present=1
  has_cmd iptables && iptables_present=1
  if (( ufw_present )) && ufw status 2>/dev/null | grep -qiE 'Status: active'; then ufw_active=1; fi
  if (( iptables_present )) && iptables -S 2>/dev/null | grep -qE '^-A |^-P INPUT (DROP|REJECT)|^-P FORWARD (DROP|REJECT)'; then iptables_has_rules=1; fi

  if (( ufw_active )); then
    FIREWALL_BACKEND="ufw"
  elif (( iptables_has_rules && ! ufw_present )); then
    FIREWALL_BACKEND="iptables"
  elif (( iptables_has_rules && ufw_present )); then
    echo "UFW est installé et des règles iptables existent déjà." >&2
    echo "UFW est privilégié pour éviter de mélanger deux modes d'administration." >&2
    FIREWALL_BACKEND="ufw"
  elif (( ufw_present )); then
    FIREWALL_BACKEND="ufw"
  elif (( iptables_present )); then
    FIREWALL_BACKEND="iptables"
  else
    FIREWALL_BACKEND="ufw"
  fi
}

ensure_backend_available() {
  if [[ "$FIREWALL_BACKEND" == "ufw" ]] && ! has_cmd ufw; then
    echo "UFW non détecté. Installation automatique..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y ufw
  fi
  if [[ "$FIREWALL_BACKEND" == "iptables" ]] && ! has_cmd iptables; then
    echo "iptables non détecté. Installation automatique..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y iptables
  fi
}

get_all_interfaces() {
  ip -o link show | awk -F': ' '{print $2}' | cut -d'@' -f1 | grep -v '^lo$'
}

choose_interface() {
  local -a interfaces=() preferred=(wg3 wg2 wg1 wg0)
  local default_iface="" i choice
  mapfile -t interfaces < <(get_all_interfaces)
  [[ ${#interfaces[@]} -gt 0 ]] || { echo "Aucune interface réseau exploitable détectée." >&2; exit 1; }

  for p in "${preferred[@]}"; do
    for iface in "${interfaces[@]}"; do
      if [[ "$iface" == "$p" ]]; then default_iface="$p"; break 2; fi
    done
  done
  [[ -n "$default_iface" ]] || default_iface="${interfaces[0]}"

  print_header "Sélection de l'interface WG"
  echo "Interfaces détectées :"
  for i in "${!interfaces[@]}"; do echo "  $((i+1))) ${interfaces[$i]}"; done
  echo
  echo "Interface proposée par défaut : $default_iface"
  read -r -p "Choisir le numéro d'interface [Entrée=$default_iface] : " choice
  if [[ -z "$choice" ]]; then SELECTED_IFACE="$default_iface"; return; fi
  if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#interfaces[@]} )); then
    SELECTED_IFACE="${interfaces[$((choice-1))]}"
    return
  fi
  echo "Choix invalide." >&2
  exit 1
}

detect_ssh_ports() {
  local files=() ports=() line port
  [[ -f /etc/ssh/sshd_config ]] && files+=(/etc/ssh/sshd_config)
  if compgen -G "/etc/ssh/sshd_config.d/*.conf" >/dev/null 2>&1; then
    while IFS= read -r line; do files+=("$line"); done < <(find /etc/ssh/sshd_config.d -maxdepth 1 -type f -name '*.conf' | sort)
  fi
  if [[ ${#files[@]} -gt 0 ]]; then
    while IFS= read -r line; do
      port="$(awk '{print $2}' <<< "$line")"
      [[ "$port" =~ ^[0-9]{1,5}$ ]] && ports+=("$port")
    done < <(grep -hE '^[[:space:]]*Port[[:space:]]+[0-9]+' "${files[@]}" 2>/dev/null || true)
  fi
  [[ ${#ports[@]} -gt 0 ]] || ports=(22)
  mapfile -t DETECTED_SSH_PORTS < <(printf '%s
' "${ports[@]}" | sort -n | awk '!seen[$0]++')
}

choose_ssh_ports() {
  local choice custom i p
  detect_ssh_ports
  print_header "Ports SSH"
  echo "Ports détectés dans sshd_config : ${DETECTED_SSH_PORTS[*]}"
  echo "1) Utiliser tous les ports SSH détectés"
  echo "2) Choisir un seul port parmi les ports détectés"
  echo "3) Saisie manuelle d'un ou plusieurs ports"
  read -r -p "Choix [Entrée=1] : " choice
  case "${choice:-1}" in
    1) SSH_PORTS=("${DETECTED_SSH_PORTS[@]}") ;;
    2)
      if [[ ${#DETECTED_SSH_PORTS[@]} -eq 1 ]]; then
        SSH_PORTS=("${DETECTED_SSH_PORTS[0]}")
      else
        echo "Ports détectés :"
        for i in "${!DETECTED_SSH_PORTS[@]}"; do echo "  $((i+1))) ${DETECTED_SSH_PORTS[$i]}"; done
        read -r -p "Choisir le numéro [Entrée=1] : " custom
        custom="${custom:-1}"
        [[ "$custom" =~ ^[0-9]+$ ]] || { echo "Choix invalide." >&2; exit 1; }
        (( custom >= 1 && custom <= ${#DETECTED_SSH_PORTS[@]} )) || { echo "Choix invalide." >&2; exit 1; }
        SSH_PORTS=("${DETECTED_SSH_PORTS[$((custom-1))]}")
      fi
      ;;
    3)
      read -r -p "Entrer un ou plusieurs ports séparés par des espaces [Entrée=${DETECTED_SSH_PORTS[*]}] : " custom
      custom="${custom:-${DETECTED_SSH_PORTS[*]}}"
      mapfile -t SSH_PORTS < <(tr ' ' '\n' <<< "$custom" | sed '/^$/d' | sort -n | awk '!seen[$0]++')
      ;;
    *) echo "Choix invalide." >&2; exit 1 ;;
  esac
  for p in "${SSH_PORTS[@]}"; do
    [[ "$p" =~ ^[0-9]{1,5}$ ]] || { echo "Port SSH invalide: $p" >&2; exit 1; }
    (( p >= 1 && p <= 65535 )) || { echo "Port SSH hors limites: $p" >&2; exit 1; }
  done
}

detect_local_networks() {
  local line iface cidr
  local -a nets=()
  while IFS= read -r line; do
    iface="$(awk '{print $2}' <<< "$line")"
    cidr="$(awk '{print $4}' <<< "$line")"
    [[ "$iface" == lo ]] && continue
    [[ "$iface" =~ ^wg[0-9]+$ ]] && continue
    [[ "$cidr" == 127.* ]] && continue
    [[ "$cidr" == 169.254.* ]] && continue
    if [[ "$cidr" =~ ^192\.168\.[0-9]+\.[0-9]+/[0-9]+$ || "$cidr" =~ ^10\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ || "$cidr" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\.[0-9]+\.[0-9]+/[0-9]+$ || "$iface" =~ ^zt[a-zA-Z0-9]+$ ]]; then
      nets+=("$iface $cidr")
    fi
  done < <(ip -o -f inet addr show scope global)
  if [[ ${#nets[@]} -eq 0 ]]; then
    mapfile -t nets < <(ip -o -f inet addr show scope global | awk '{print $2" "$4}')
  fi
  mapfile -t LOCAL_NET_CHOICES < <(printf '%s
' "${nets[@]}" | awk '!seen[$0]++')
}

choose_local_networks() {
  local choice item detected_net i
  LOCAL_NETS=()
  detect_local_networks
  print_header "Réseaux locaux autorisés pour SSH"
  if [[ ${#LOCAL_NET_CHOICES[@]} -gt 0 ]]; then
    echo "Réseaux détectés :"
    for i in "${!LOCAL_NET_CHOICES[@]}"; do echo "  $((i+1))) ${LOCAL_NET_CHOICES[$i]}"; done
    echo "  m) Saisie manuelle"
    read -r -p "Choisir un ou plusieurs réseaux (ex: 1 2 3) [Entrée=1] : " choice
    choice="${choice:-1}"
    if [[ "$choice" =~ ^[Mm]$ ]]; then
      read -r -p "Entrer un ou plusieurs réseaux CIDR séparés par des espaces [Entrée=$DEFAULT_LOCAL_NET] : " choice
      choice="${choice:-$DEFAULT_LOCAL_NET}"
      for item in $choice; do
        [[ "$item" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[1-2][0-9]|3[0-2])$ ]] || { echo "Format CIDR invalide: $item" >&2; exit 1; }
        LOCAL_NETS+=("$item")
      done
    else
      for item in $choice; do
        [[ "$item" =~ ^[0-9]+$ ]] || { echo "Choix invalide: $item" >&2; exit 1; }
        (( item >= 1 && item <= ${#LOCAL_NET_CHOICES[@]} )) || { echo "Choix invalide: $item" >&2; exit 1; }
        detected_net="${LOCAL_NET_CHOICES[$((item-1))]}"
        LOCAL_NETS+=("${detected_net#* }")
      done
    fi
  else
    read -r -p "Entrer un ou plusieurs réseaux CIDR séparés par des espaces [Entrée=$DEFAULT_LOCAL_NET] : " choice
    choice="${choice:-$DEFAULT_LOCAL_NET}"
    for item in $choice; do
      [[ "$item" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[1-2][0-9]|3[0-2])$ ]] || { echo "Format CIDR invalide: $item" >&2; exit 1; }
      LOCAL_NETS+=("$item")
    done
  fi
  mapfile -t LOCAL_NETS < <(printf '%s
' "${LOCAL_NETS[@]}" | awk '!seen[$0]++')
}

ufw_rule_already_present() { local needle="$1"; ufw status | grep -F -- "$needle" >/dev/null 2>&1; }
iptables_rule_exists() { iptables -C "$@" >/dev/null 2>&1; }

apply_rule_safe_ufw() {
  local cmd="$1" check="$2"
  if ufw_rule_already_present "$check"; then
    echo "= Règle déjà présente, ignorée : $check"
  else
    echo "+ $cmd"
    eval "$cmd"
  fi
}

iptables_enable_persistence_if_possible() {
  if dpkg -l 2>/dev/null | grep -q '^ii  iptables-persistent '; then
    netfilter-persistent save >/dev/null 2>&1 || true
  else
    echo "Note: iptables-persistent n'est pas installé; les règles iptables peuvent ne pas survivre à un reboot." >&2
  fi
}

setup_defaults_ufw() {
  echo "+ ufw --force reset"
  ufw --force reset
  echo "+ ufw default deny incoming"
  ufw default deny incoming
  echo "+ ufw default allow outgoing"
  ufw default allow outgoing
}

apply_base_rules_ufw() {
  local p net
  for p in "${SSH_PORTS[@]}"; do
    apply_rule_safe_ufw "ufw allow in on $SELECTED_IFACE proto tcp from $WG_RANGE to any port $p comment 'SSH via WG range'" "$p/tcp"
    for net in "${LOCAL_NETS[@]}"; do
      apply_rule_safe_ufw "ufw allow proto tcp from $net to any port $p comment 'SSH via local net'" "$p/tcp"
    done
  done
  apply_rule_safe_ufw "ufw allow in on $SELECTED_IFACE proto udp from any to any port ${ECHO_UDP_PORTS[0]} comment 'EchoLink UDP 5198'" "${ECHO_UDP_PORTS[0]}/udp"
  apply_rule_safe_ufw "ufw allow in on $SELECTED_IFACE proto udp from any to any port ${ECHO_UDP_PORTS[1]} comment 'EchoLink UDP 5199'" "${ECHO_UDP_PORTS[1]}/udp"
  apply_rule_safe_ufw "ufw allow in on $SELECTED_IFACE proto tcp from any to any port $ECHO_TCP_PORT comment 'EchoLink TCP 5200'" "$ECHO_TCP_PORT/tcp"
}

setup_defaults_iptables() {
  echo "+ iptables -F"
  iptables -F
  echo "+ iptables -X"
  iptables -X || true
  echo "+ iptables -P INPUT DROP"
  iptables -P INPUT DROP
  echo "+ iptables -P FORWARD DROP"
  iptables -P FORWARD DROP
  echo "+ iptables -P OUTPUT ACCEPT"
  iptables -P OUTPUT ACCEPT
  iptables_rule_exists INPUT -i lo -j ACCEPT || { echo "+ iptables -A INPUT -i lo -j ACCEPT"; iptables -A INPUT -i lo -j ACCEPT; }
  iptables_rule_exists INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT || { echo "+ iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"; iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT; }
}

apply_base_rules_iptables() {
  local p net
  for p in "${SSH_PORTS[@]}"; do
    iptables_rule_exists INPUT -i "$SELECTED_IFACE" -p tcp -s "$WG_RANGE" --dport "$p" -j ACCEPT || {
      echo "+ iptables -A INPUT -i $SELECTED_IFACE -p tcp -s $WG_RANGE --dport $p -j ACCEPT"
      iptables -A INPUT -i "$SELECTED_IFACE" -p tcp -s "$WG_RANGE" --dport "$p" -j ACCEPT
    }
    for net in "${LOCAL_NETS[@]}"; do
      iptables_rule_exists INPUT -p tcp -s "$net" --dport "$p" -j ACCEPT || {
        echo "+ iptables -A INPUT -p tcp -s $net --dport $p -j ACCEPT"
        iptables -A INPUT -p tcp -s "$net" --dport "$p" -j ACCEPT
      }
    done
  done
  iptables_rule_exists INPUT -i "$SELECTED_IFACE" -p udp --dport "${ECHO_UDP_PORTS[0]}" -j ACCEPT || {
    echo "+ iptables -A INPUT -i $SELECTED_IFACE -p udp --dport ${ECHO_UDP_PORTS[0]} -j ACCEPT"
    iptables -A INPUT -i "$SELECTED_IFACE" -p udp --dport "${ECHO_UDP_PORTS[0]}" -j ACCEPT
  }
  iptables_rule_exists INPUT -i "$SELECTED_IFACE" -p udp --dport "${ECHO_UDP_PORTS[1]}" -j ACCEPT || {
    echo "+ iptables -A INPUT -i $SELECTED_IFACE -p udp --dport ${ECHO_UDP_PORTS[1]} -j ACCEPT"
    iptables -A INPUT -i "$SELECTED_IFACE" -p udp --dport "${ECHO_UDP_PORTS[1]}" -j ACCEPT
  }
  iptables_rule_exists INPUT -i "$SELECTED_IFACE" -p tcp --dport "$ECHO_TCP_PORT" -j ACCEPT || {
    echo "+ iptables -A INPUT -i $SELECTED_IFACE -p tcp --dport $ECHO_TCP_PORT -j ACCEPT"
    iptables -A INPUT -i "$SELECTED_IFACE" -p tcp --dport "$ECHO_TCP_PORT" -j ACCEPT
  }
  # Autoriser ping (ICMP echo-request) sur wg0 et zt* (toutes sources)
iptables_rule_exists INPUT -i "$SELECTED_IFACE" -p icmp --icmp-type echo-request -j ACCEPT || {
  echo "+ iptables -I INPUT 3 -i $SELECTED_IFACE -p icmp --icmp-type echo-request -j ACCEPT"
  iptables -I INPUT 3 -i "$SELECTED_IFACE" -p icmp --icmp-type echo-request -j ACCEPT
}
# Pour ZeroTier (zt*)
for zt_iface in $(ip link show | grep -o 'zt[a-z0-9]*'); do
  iptables_rule_exists INPUT -i "$zt_iface" -p icmp --icmp-type echo-request -j ACCEPT || {
    echo "+ iptables -I INPUT 4 -i $zt_iface -p icmp --icmp-type echo-request -j ACCEPT"
    iptables -I INPUT 4 -i "$zt_iface" -p icmp --icmp-type echo-request -j ACCEPT
  }
  iptables_enable_persistence_if_possible
}

install_test_rollback_ufw() {
  mkdir -p "$STATE_DIR"
  ufw status numbered > "$BACKUP_FILE" || true
  mkdir -p /usr/local/sbin /var/lib
  cat > "$ROLLBACK_SCRIPT" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail
FLAG="/var/lib/node-ufw-test-mode"
if [[ -f "$FLAG" ]]; then
  /usr/sbin/ufw --force disable || true
  /usr/sbin/ufw --force reset || true
  rm -f "$FLAG"
fi
EOS
  chmod 700 "$ROLLBACK_SCRIPT"
  cat > "$SYSTEMD_SERVICE" <<EOS
[Unit]
Description=Rollback UFW test mode at boot if not confirmed
After=network-pre.target
Before=network.target
DefaultDependencies=no

[Service]
Type=oneshot
ExecStart=$ROLLBACK_SCRIPT

[Install]
WantedBy=multi-user.target
EOS
  touch "$TEST_FLAG"
  systemctl daemon-reload
  systemctl enable node-ufw-rollback.service >/dev/null
}

install_test_rollback_iptables() {
  mkdir -p "$STATE_DIR"
  iptables-save > "$BACKUP_FILE" 2>/dev/null || true
  mkdir -p /usr/local/sbin /var/lib
  cat > "$ROLLBACK_SCRIPT" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail
FLAG="/var/lib/node-ufw-test-mode"
if [[ -f "$FLAG" ]]; then
  /sbin/iptables -F || true
  /sbin/iptables -X || true
  /sbin/iptables -P INPUT ACCEPT || true
  /sbin/iptables -P FORWARD ACCEPT || true
  /sbin/iptables -P OUTPUT ACCEPT || true
  rm -f "$FLAG"
fi
EOS
  chmod 700 "$ROLLBACK_SCRIPT"
  cat > "$SYSTEMD_SERVICE" <<EOS
[Unit]
Description=Rollback iptables test mode at boot if not confirmed
After=network-pre.target
Before=network.target
DefaultDependencies=no

[Service]
Type=oneshot
ExecStart=$ROLLBACK_SCRIPT

[Install]
WantedBy=multi-user.target
EOS
  touch "$TEST_FLAG"
  systemctl daemon-reload
  systemctl enable node-ufw-rollback.service >/dev/null
}

confirm_test_mode() {
  if [[ ! -f "$TEST_FLAG" ]]; then echo "Aucun mode test en attente de confirmation."; return; fi
  rm -f "$TEST_FLAG"
  systemctl disable node-ufw-rollback.service >/dev/null 2>&1 || true
  [[ "$FIREWALL_BACKEND" == "iptables" ]] && iptables_enable_persistence_if_possible
  echo "Mode test confirmé: le rollback automatique au reboot est désactivé."
}

show_status() {
  print_header "État pare-feu"
  echo "Backend utilisé : $FIREWALL_BACKEND"
  if [[ "$FIREWALL_BACKEND" == "ufw" ]]; then
    ufw status verbose || true
    echo
    ufw status numbered || true
  else
    iptables -S || true
  fi
}

add_inbound_port() {
  local port proto src_choice src confirm local_mode
  print_header "Ajout de port entrant"
  echo "Pour un port lié au réseau WG, on utilisera l'interface sélectionnée."
  echo "Pour un port lié à un réseau local/ZeroTier, on peut l'ajouter globalement."
  choose_interface
  echo "Interface WG choisie : $SELECTED_IFACE"
  read -r -p "Port entrant à autoriser (port simple ou plage ex. 10000:10010) : " port
  [[ "$port" =~ ^[0-9]{1,5}(:[0-9]{1,5})?$ ]] || { echo "Port ou plage invalide." >&2; exit 1; }

  echo "Protocole :"
  echo "1) tcp"
  echo "2) udp"
  echo "3) les deux"
  read -r -p "Choix [Entrée=tcp] : " proto
  proto="${proto:-1}"

  echo "Source autorisée :"
  echo "1) any"
  echo "2) $WG_RANGE (lié à l'interface WG)"
  echo "3) réseau local/ZeroTier (global, sans interface)"
  echo "4) saisie manuelle"
  read -r -p "Choix [Entrée=1] : " src_choice
  src_choice="${src_choice:-1}"

  case "$src_choice" in
    1) src="any"; local_mode="global" ;;
    2) src="$WG_RANGE"; local_mode="wg" ;;
    3)
      choose_local_networks
      if [[ ${#LOCAL_NETS[@]} -gt 1 ]]; then
        echo "Pour l'ajout de port, une seule source est prise à la fois. Choisis ensuite ce menu à nouveau si nécessaire." >&2
      fi
      src="${LOCAL_NETS[0]}"
      local_mode="global"
      ;;
    4)
      read -r -p "Entrer la source (IP ou CIDR) : " src
      read -r -p "Lier cette source à l'interface WG choisie ? [y/N] : " confirm
      if [[ "$confirm" =~ ^[Yy]$ ]]; then local_mode="wg"; else local_mode="global"; fi
      ;;
    *) echo "Choix invalide." >&2; exit 1 ;;
  esac

  print_header "Prévisualisation"
  case "$proto" in
    1) echo "$FIREWALL_BACKEND: $port/tcp depuis $src mode=$local_mode" ;;
    2) echo "$FIREWALL_BACKEND: $port/udp depuis $src mode=$local_mode" ;;
    3)
      echo "$FIREWALL_BACKEND: $port/tcp depuis $src mode=$local_mode"
      echo "$FIREWALL_BACKEND: $port/udp depuis $src mode=$local_mode"
      ;;
    *) echo "Choix invalide." >&2; exit 1 ;;
  esac

  read -r -p "Appliquer cette/ces règle(s) ? [y/N] : " confirm
  [[ "$confirm" =~ ^[Yy]$ ]] || { echo "Annulé."; return; }

  if [[ "$FIREWALL_BACKEND" == "ufw" ]]; then
    case "$proto" in
      1)
        if [[ "$local_mode" == "wg" ]]; then
          apply_rule_safe_ufw "ufw allow in on $SELECTED_IFACE proto tcp from $src to any port $port" "$port/tcp"
        else
          apply_rule_safe_ufw "ufw allow proto tcp from $src to any port $port" "$port/tcp"
        fi
        ;;
      2)
        if [[ "$local_mode" == "wg" ]]; then
          apply_rule_safe_ufw "ufw allow in on $SELECTED_IFACE proto udp from $src to any port $port" "$port/udp"
        else
          apply_rule_safe_ufw "ufw allow proto udp from $src to any port $port" "$port/udp"
        fi
        ;;
      3)
        if [[ "$local_mode" == "wg" ]]; then
          apply_rule_safe_ufw "ufw allow in on $SELECTED_IFACE proto tcp from $src to any port $port" "$port/tcp"
          apply_rule_safe_ufw "ufw allow in on $SELECTED_IFACE proto udp from $src to any port $port" "$port/udp"
        else
          apply_rule_safe_ufw "ufw allow proto tcp from $src to any port $port" "$port/tcp"
          apply_rule_safe_ufw "ufw allow proto udp from $src to any port $port" "$port/udp"
        fi
        ;;
    esac
  else
    case "$proto" in
      1)
        if [[ "$src" == "any" ]]; then
          if [[ "$local_mode" == "wg" ]]; then
            iptables_rule_exists INPUT -i "$SELECTED_IFACE" -p tcp --dport "$port" -j ACCEPT || iptables -A INPUT -i "$SELECTED_IFACE" -p tcp --dport "$port" -j ACCEPT
          else
            iptables_rule_exists INPUT -p tcp --dport "$port" -j ACCEPT || iptables -A INPUT -p tcp --dport "$port" -j ACCEPT
          fi
        else
          if [[ "$local_mode" == "wg" ]]; then
            iptables_rule_exists INPUT -i "$SELECTED_IFACE" -p tcp -s "$src" --dport "$port" -j ACCEPT || iptables -A INPUT -i "$SELECTED_IFACE" -p tcp -s "$src" --dport "$port" -j ACCEPT
          else
            iptables_rule_exists INPUT -p tcp -s "$src" --dport "$port" -j ACCEPT || iptables -A INPUT -p tcp -s "$src" --dport "$port" -j ACCEPT
          fi
        fi
        ;;
      2)
        if [[ "$src" == "any" ]]; then
          if [[ "$local_mode" == "wg" ]]; then
            iptables_rule_exists INPUT -i "$SELECTED_IFACE" -p udp --dport "$port" -j ACCEPT || iptables -A INPUT -i "$SELECTED_IFACE" -p udp --dport "$port" -j ACCEPT
          else
            iptables_rule_exists INPUT -p udp --dport "$port" -j ACCEPT || iptables -A INPUT -p udp --dport "$port" -j ACCEPT
          fi
        else
          if [[ "$local_mode" == "wg" ]]; then
            iptables_rule_exists INPUT -i "$SELECTED_IFACE" -p udp -s "$src" --dport "$port" -j ACCEPT || iptables -A INPUT -i "$SELECTED_IFACE" -p udp -s "$src" --dport "$port" -j ACCEPT
          else
            iptables_rule_exists INPUT -p udp -s "$src" --dport "$port" -j ACCEPT || iptables -A INPUT -p udp -s "$src" --dport "$port" -j ACCEPT
          fi
        fi
        ;;
      3)
        for oneproto in tcp udp; do
          if [[ "$src" == "any" ]]; then
            if [[ "$local_mode" == "wg" ]]; then
              iptables_rule_exists INPUT -i "$SELECTED_IFACE" -p "$oneproto" --dport "$port" -j ACCEPT || iptables -A INPUT -i "$SELECTED_IFACE" -p "$oneproto" --dport "$port" -j ACCEPT
            else
              iptables_rule_exists INPUT -p "$oneproto" --dport "$port" -j ACCEPT || iptables -A INPUT -p "$oneproto" --dport "$port" -j ACCEPT
            fi
          else
            if [[ "$local_mode" == "wg" ]]; then
              iptables_rule_exists INPUT -i "$SELECTED_IFACE" -p "$oneproto" -s "$src" --dport "$port" -j ACCEPT || iptables -A INPUT -i "$SELECTED_IFACE" -p "$oneproto" -s "$src" --dport "$port" -j ACCEPT
            else
              iptables_rule_exists INPUT -p "$oneproto" -s "$src" --dport "$port" -j ACCEPT || iptables -A INPUT -p "$oneproto" -s "$src" --dport "$port" -j ACCEPT
            fi
          fi
        done
        ;;
    esac
    iptables_enable_persistence_if_possible
  fi

  show_status
}

show_summary() {
  print_header "Résumé"
  echo "Backend : $FIREWALL_BACKEND"
  echo "Interface WG : $SELECTED_IFACE"
  echo "Ports SSH : ${SSH_PORTS[*]}"
  echo "Plage WireGuard autorisée SSH : $WG_RANGE (sur $SELECTED_IFACE)"
  echo "Réseaux locaux autorisés SSH : ${LOCAL_NETS[*]} (globaux, sans interface)"
  echo "EchoLink UDP : ${ECHO_UDP_PORTS[*]} sur $SELECTED_IFACE"
  echo "EchoLink TCP : $ECHO_TCP_PORT sur $SELECTED_IFACE"
  echo "Mode : $1"
}

initial_or_rebuild_config() {
  local mode p net confirm
  choose_interface
  choose_ssh_ports
  choose_local_networks
  print_header "Mode d'application"
  echo "1) Mode test (rollback automatique au reboot si non confirmé)"
  echo "2) Mode statique (permanent)"
  read -r -p "Choisir le mode [Entrée=1] : " mode
  mode="${mode:-1}"
  [[ "$mode" == "1" || "$mode" == "2" ]] || { echo "Choix invalide." >&2; exit 1; }

  show_summary "$([[ "$mode" == "1" ]] && echo 'test' || echo 'statique')"
  echo
  echo "Commandes principales qui seront appliquées :"
  if [[ "$FIREWALL_BACKEND" == "ufw" ]]; then
    echo "  ufw --force reset"
    echo "  ufw default deny incoming"
    echo "  ufw default allow outgoing"
    for p in "${SSH_PORTS[@]}"; do
      echo "  ufw allow in on $SELECTED_IFACE proto tcp from $WG_RANGE to any port $p"
      for net in "${LOCAL_NETS[@]}"; do echo "  ufw allow proto tcp from $net to any port $p"; done
    done
    echo "  ufw allow in on $SELECTED_IFACE proto udp from any to any port ${ECHO_UDP_PORTS[0]}"
    echo "  ufw allow in on $SELECTED_IFACE proto udp from any to any port ${ECHO_UDP_PORTS[1]}"
    echo "  ufw allow in on $SELECTED_IFACE proto tcp from any to any port $ECHO_TCP_PORT"
  else
    echo "  iptables -P INPUT DROP"
    echo "  iptables -P OUTPUT ACCEPT"
    for p in "${SSH_PORTS[@]}"; do
      echo "  iptables -A INPUT -i $SELECTED_IFACE -p tcp -s $WG_RANGE --dport $p -j ACCEPT"
      for net in "${LOCAL_NETS[@]}"; do echo "  iptables -A INPUT -p tcp -s $net --dport $p -j ACCEPT"; done
    done
    echo "  iptables -A INPUT -i $SELECTED_IFACE -p udp --dport ${ECHO_UDP_PORTS[0]} -j ACCEPT"
    echo "  iptables -A INPUT -i $SELECTED_IFACE -p udp --dport ${ECHO_UDP_PORTS[1]} -j ACCEPT"
    echo "  iptables -A INPUT -i $SELECTED_IFACE -p tcp --dport $ECHO_TCP_PORT -j ACCEPT"
  fi
  [[ "$mode" == "1" ]] && echo "  rollback automatique au reboot si non confirmé"

  read -r -p "Appliquer cette configuration ? [y/N] : " confirm
  [[ "$confirm" =~ ^[Yy]$ ]] || { echo "Annulé."; return; }

  if [[ "$FIREWALL_BACKEND" == "ufw" ]]; then
    setup_defaults_ufw
    apply_base_rules_ufw
    ufw --force enable
    if [[ "$mode" == "1" ]]; then
      install_test_rollback_ufw
      echo "Mode test UFW activé. Si tu perds l'accès, redémarre la machine."
    else
      rm -f "$TEST_FLAG"
      systemctl disable node-ufw-rollback.service >/dev/null 2>&1 || true
      echo "Mode statique UFW appliqué."
    fi
  else
    setup_defaults_iptables
    apply_base_rules_iptables
    if [[ "$mode" == "1" ]]; then
      install_test_rollback_iptables
      echo "Mode test iptables activé. Si tu perds l'accès, redémarre la machine."
    else
      rm -f "$TEST_FLAG"
      systemctl disable node-ufw-rollback.service >/dev/null 2>&1 || true
      iptables_enable_persistence_if_possible
      echo "Mode statique iptables appliqué."
    fi
  fi
  show_status
}

main_menu() {
  local choice status_line
  print_header "Gestionnaire pare-feu pour node"
  echo "Backend détecté/privilégié : $FIREWALL_BACKEND"
  if [[ "$FIREWALL_BACKEND" == "ufw" ]]; then
    status_line="$(ufw status | head -n1 || true)"
    echo "État actuel : ${status_line:-inconnu}"
  else
    echo "iptables détecté comme backend principal pour ce script."
  fi
  [[ -f "$TEST_FLAG" ]] && echo "Un mode test est actuellement en attente de confirmation."
  echo
  echo "1) Initialiser / refaire la configuration complète"
  echo "2) Ajouter un port entrant"
  echo "3) Afficher l'état du pare-feu"
  echo "4) Confirmer un mode test déjà appliqué"
  echo "5) Quitter"
  read -r -p "Choix [Entrée=1] : " choice
  case "${choice:-1}" in
    1) initial_or_rebuild_config ;;
    2) add_inbound_port ;;
    3) show_status ;;
    4) confirm_test_mode ;;
    5) exit 0 ;;
    *) echo "Choix invalide." >&2; exit 1 ;;
  esac
}

need_root
detect_firewall_backend
ensure_backend_available
has_cmd ip || { echo "Commande requise introuvable: ip" >&2; exit 1; }
has_cmd systemctl || { echo "Commande requise introuvable: systemctl" >&2; exit 1; }
mkdir -p "$STATE_DIR"
main_menu
