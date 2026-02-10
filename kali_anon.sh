#!/bin/bash


# Features:
# - Transparent Tor Proxying (IPTables)
# - IPv6 Leak Protection (Disables IPv6)
# - MAC Address Spoofing (macchanger)
# - Hostname Rotation
# - RAM/Cache Cleaning (BleachBit)
# - Process Killing (Modern apps)
# - By nylar357 - www.linkedin.com/in/brycezg
# --- CONFIGURATION ---

# Destinations to bypass Tor (Local Network)
NON_TOR="192.168.0.0/16 172.16.0.0/12 10.0.0.0/8"

# Tor User and Ports
TOR_UID="debian-tor"
TRANS_PORT="9040"
DNS_PORT="5353" # Using 5353 to avoid conflict with local systemd-resolved if active

# Processes to kill to prevent leaks
TO_KILL="chrome chromium firefox-esr discord telegram-desktop slack code code-oss skype zoom teams dropbox transmission qbittorrent thunderbird"

# BleachBit Cleaners
BLEACHBIT_CLEANERS="bash.history system.cache system.clipboard system.recent_documents system.rotated_logs system.tmp system.trash firefox.vacuum firefox.history firefox.cookies"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# --- FUNCTIONS ---

# Check if running as root
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${RED}[!] This script must run as root.${NC}" >&2
        exit 1
    fi
}

# Check for required tools
check_deps() {
    local deps="tor macchanger bleachbit curl"
    for dep in $deps; do
        if ! command -v $dep &> /dev/null; then
            echo -e "${RED}[!] Error: $dep is not installed.${NC}"
            echo -e "    Run: apt update && apt install $dep"
            exit 1
        fi
    done
}

# Configure Tor (Auto-update torrc if needed)
configure_tor() {
    TORRC="/etc/tor/torrc"
    echo -e "${BLUE}[*] Checking Tor configuration...${NC}"
    
    # Check for TransPort
    if ! grep -q "TransPort $TRANS_PORT" "$TORRC"; then
        echo -e "${YELLOW}[+] Adding TransPort $TRANS_PORT to $TORRC${NC}"
        echo "TransPort $TRANS_PORT" >> "$TORRC"
    fi
    
    # Check for DNSPort
    if ! grep -q "DNSPort $DNS_PORT" "$TORRC"; then
        echo -e "${YELLOW}[+] Adding DNSPort $DNS_PORT to $TORRC${NC}"
        echo "DNSPort $DNS_PORT" >> "$TORRC"
    fi
    
    # Check for VirtualAddrNetwork
    if ! grep -q "VirtualAddrNetwork 10.192.0.0/10" "$TORRC"; then
        echo "VirtualAddrNetwork 10.192.0.0/10" >> "$TORRC"
        echo "AutomapHostsOnResolve 1" >> "$TORRC"
    fi
}

kill_process() {
    echo -e "${BLUE}[*] Killing dangerous processes...${NC}"
    for proc in $TO_KILL; do
        if pgrep -x "$proc" > /dev/null; then
            killall -q "$proc"
            echo -e "    - Killed $proc"
        fi
    done
}

disable_ipv6() {
    echo -e "${BLUE}[*] Disabling IPv6 to prevent leaks...${NC}"
    sysctl -w net.ipv6.conf.all.disable_ipv6=1 > /dev/null
    sysctl -w net.ipv6.conf.default.disable_ipv6=1 > /dev/null
    sysctl -w net.ipv6.conf.lo.disable_ipv6=1 > /dev/null
}

enable_ipv6() {
    echo -e "${BLUE}[*] Re-enabling IPv6...${NC}"
    sysctl -w net.ipv6.conf.all.disable_ipv6=0 > /dev/null
    sysctl -w net.ipv6.conf.default.disable_ipv6=0 > /dev/null
    sysctl -w net.ipv6.conf.lo.disable_ipv6=0 > /dev/null
}

change_mac() {
    echo -e "${BLUE}[*] Changing MAC Address...${NC}"
    
    # Get active interface that isn't lo or tun/tap
    IFACE=$(ip -o -4 route show to default | awk '{print $5}' | head -n1)
    
    if [ -z "$IFACE" ]; then
        echo -e "${YELLOW}[!] No default interface found. Listing all non-loopback:${NC}"
        ip -o link show | grep -v "lo:" | awk -F': ' '{print $2}'
        read -p "Select Interface > " IFACE
    fi

    echo -e "    Target Interface: ${GREEN}$IFACE${NC}"
    
    ip link set dev "$IFACE" down
    
    if [ "$1" == "restore" ]; then
        macchanger -p "$IFACE"
    else
        macchanger -r "$IFACE"
    fi
    
    ip link set dev "$IFACE" up
    echo -e "    Interface $IFACE is up."
}

change_hostname() {
    if [ "$1" == "restore" ]; then
        hostnamectl set-hostname "kali" # Or your default
        echo -e "${BLUE}[*] Hostname restored to 'kali'${NC}"
    else
        NEW_HOSTNAME=$(shuf -n 1 /usr/share/dict/words 2>/dev/null | tr -dc 'a-zA-Z' | tr '[:upper:]' '[:lower:]' | head -c 10)
        [ -z "$NEW_HOSTNAME" ] && NEW_HOSTNAME="node$(shuf -i 100-999 -n 1)"
        
        hostnamectl set-hostname "$NEW_HOSTNAME"
        sed -i "s/127.0.1.1.*/127.0.1.1\t$NEW_HOSTNAME/g" /etc/hosts
        echo -e "${BLUE}[*] Hostname changed to: ${GREEN}$NEW_HOSTNAME${NC}"
    fi
}

start_tor_iptables() {
    echo -e "${BLUE}[*] Applying IPTables rules for Transparent Tor...${NC}"
    
    # Flush existing rules
    iptables -F
    iptables -t nat -F

    # Set up DNS Redirection
    # Use 127.0.0.1 for DNS in resolv.conf
    echo "nameserver 127.0.0.1" > /etc/resolv.conf
    # Prevent NetworkManager from overwriting it immediately (Optional: chattr +i /etc/resolv.conf)

    # Allow Tor User Logic
    iptables -t nat -A OUTPUT -m owner --uid-owner $TOR_UID -j RETURN
    
    # Redirect DNS
    iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-ports $DNS_PORT
    iptables -t nat -A OUTPUT -p tcp --dport 53 -j REDIRECT --to-ports $DNS_PORT

    # Allow Local Network
    for NET in $NON_TOR 127.0.0.0/8; do
        iptables -t nat -A OUTPUT -d "$NET" -j RETURN
        iptables -A OUTPUT -d "$NET" -j ACCEPT
    done

    # Redirect TCP to Tor TransPort
    iptables -t nat -A OUTPUT -p tcp --syn -j REDIRECT --to-ports $TRANS_PORT
    
    # Allow Established
    iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    # Allow Tor User Out
    iptables -A OUTPUT -m owner --uid-owner $TOR_UID -j ACCEPT
    
    # Reject Everything Else (Panic Mode)
    iptables -A OUTPUT -j REJECT --reject-with icmp-port-unreachable
    
    echo -e "${GREEN}[+] Rules applied.${NC}"
}

flush_iptables() {
    echo -e "${BLUE}[*] Flushing IPTables rules...${NC}"
    iptables -F
    iptables -t nat -F
    iptables -P INPUT ACCEPT
    iptables -P OUTPUT ACCEPT
    iptables -P FORWARD ACCEPT
}

do_clean() {
    if [ "$1" == "overwrite" ]; then
        echo -e "${BLUE}[*] Securely cleaning system (Overwrite Mode)...${NC}"
        bleachbit -o -c $BLEACHBIT_CLEANERS > /dev/null 2>&1
    else
        echo -e "${BLUE}[*] Cleaning system logs and cache...${NC}"
        bleachbit -c $BLEACHBIT_CLEANERS > /dev/null 2>&1
    fi
}

# --- MAIN LOGIC ---

do_start() {
    check_root
    check_deps
    configure_tor
    
    echo -e "${GREEN}=== Starting Anonymization Sequence ===${NC}"
    
    # 1. Kill dangerous apps
    kill_process
    
    # 2. Stop Networking for setup
    echo -e "${BLUE}[*] Stopping NetworkManager...${NC}"
    systemctl stop NetworkManager
    
    # 3. Spoofing
    change_mac
    change_hostname
    
    # 4. Disable IPv6
    disable_ipv6
    
    # 5. Start Networking & Tor
    echo -e "${BLUE}[*] Starting NetworkManager...${NC}"
    systemctl start NetworkManager
    echo -e "${BLUE}[*] Waiting for network...${NC}"
    sleep 5 # Wait for NM to grab DHCP
    
    echo -e "${BLUE}[*] Restarting Tor Service...${NC}"
    systemctl restart tor
    
    # 6. Apply Rules
    start_tor_iptables
    
    echo -e "${GREEN}[SUCCESS] System is now Anonymized.${NC}"
    echo -e "You are essentially a ghost. Do not log into personal accounts."
    
    # Verify IP
    echo -e "${YELLOW}Checking external IP...${NC}"
    curl -s --socks5 127.0.0.1:9050 https://check.torproject.org/api/ip
}

do_stop() {
    check_root
    
    echo -e "${RED}=== Stopping Anonymization ===${NC}"
    
    flush_iptables
    enable_ipv6
    
    echo -e "${BLUE}[*] Restoring Networking...${NC}"
    systemctl stop NetworkManager
    change_mac restore
    change_hostname restore
    systemctl start NetworkManager
    
    # Restore DNS (NetworkManager usually handles this on restart, but forcing it is good)
    # No custom command needed, NM update trigger:
    nmcli networking off && nmcli networking on
    
    read -p "Do you want to run BleachBit cleanup? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        do_clean
    fi
    
    echo -e "${GREEN}[DONE] System returned to normal state.${NC}"
}

do_status() {
    echo -e "${YELLOW}=== Anonymity Status ===${NC}"
    
    # Check IP
    echo -n "Current External IP: "
    curl -s --connect-timeout 5 https://ifconfig.me
    echo
    
    # Check Tor Check
    echo -n "Tor Status: "
    curl -s --connect-timeout 5 https://check.torproject.org | grep -q "Congratulations" && echo -e "${GREEN}SECURE (Tor Active)${NC}" || echo -e "${RED}INSECURE (Not using Tor)${NC}"
    
    # Hostname
    echo -e "Hostname: $(hostname)"
    
    # Mac
    IFACE=$(ip -o -4 route show to default | awk '{print $5}' | head -n1)
    if [ ! -z "$IFACE" ]; then
        macchanger -s "$IFACE" | grep "Current"
    fi
    
    # IPv6
    IPV6_STATUS=$(sysctl net.ipv6.conf.all.disable_ipv6 | awk '{print $3}')
    if [ "$IPV6_STATUS" == "1" ]; then
        echo -e "IPv6: ${GREEN}Disabled (Safe)${NC}"
    else
        echo -e "IPv6: ${RED}Enabled (Potential Leak)${NC}"
    fi
}

case "$1" in
    start)
        do_start
    ;;
    stop)
        do_stop
    ;;
    status)
        do_status
    ;;
    *)
        echo -e "Usage: $0 {start|stop|status}" >&2
        exit 3
    ;;
esac
