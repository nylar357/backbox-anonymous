# Kali Anonymous Script (Modernized)

A robust, all-in-one bash script adapted for Kali Linux 2024+ (and Debian-based systems) to automate system anonymization. This script acts as a "panic button" for privacy, instantly routing traffic through Tor, spoofing hardware identifiers, and scrubbing system artifacts.

Note: This is a modernized adaptation of the classic BackBox Linux anonymous script, updated to use systemd, ip commands, and protection against modern leakage vectors like IPv6.

## 🚀 Features

Transparent Tor Proxy: Routes all TCP traffic through the Tor network using iptables rules. You don't need to configure individual applications to use a proxy.

IPv6 Leak Protection: Completely disables the IPv6 stack while active to prevent de-anonymization via IPv6 leaks (a common vulnerability in Tor setups).

Identity Rotation:

MAC Spoofing: Randomizes the MAC address of your default interface to bypass Layer 2 tracking.

Hostname Rotation: Changes your system hostname to a random word or generic node ID to prevent local network enumeration.

Leak Prevention: Automatically kills "chatterbox" applications (Discord, Telegram, Browsers, VS Code) that might leak data before the Tor tunnel is established.

Forensic Cleanup: Uses bleachbit to scrub bash history, cache, temporary files, and cookies upon shutdown.

DNS Protection: Forces DNS requests through Tor's DNSPort to prevent DNS leaks.

## 📋 Prerequisites

Ensure you have the necessary tools installed on your Kali machine:

```
sudo apt update
sudo apt install tor macchanger bleachbit curl

```

## 🛠️ Usage

Download: Save the script as kali_anonymous.sh.

Permissions: Make the script executable.

```

chmod +x kali_anonymous.sh

```

Run: The script must be run as root.



### Start Anonymization

Initiates the lockdown sequence. Kills apps, rotates ID, disables IPv6, and establishes the Transparent Proxy.

```

sudo ./kali_anonymous.sh start

```

### Check Status

Verifies your current external IP, Tor connection status, current MAC address, and IPv6 status.

```

sudo ./kali_anonymous.sh status

```


### Stop Anonymization

Restores standard networking, reverts your MAC address and Hostname to defaults, re-enables IPv6, and offers to run a system cleaner.

```

sudo ./kali_anonymous.sh stop

```

## ⚙️ Configuration

You can customize the script by editing the variables at the top of the file:

NON_TOR: Add local subnets (e.g., 192.168.1.0/24) that you want to access directly without going through Tor.

TO_KILL: Add or remove application names that should be terminated when the script starts (e.g., slack, discord).

BLEACHBIT_CLEANERS: Customize which logs and cache files are scrubbed during the shutdown phase.

## 🛡️ Benefits of Use

Force-Multiplier for OpSec: Instead of manually configuring proxies chains, MAC changers, and firewall rules, this script handles the entire "identity shift" in seconds.

Prevents Accidental Leaks: By killing background processes like Discord or Dropbox immediately, it prevents these apps from "phoning home" with your real IP address the moment you connect to a network.

Forensic Anti-Analysis: Rotating the hostname and scrubbing logs makes it significantly harder for network administrators to correlate your device's activity over time or across different sessions.

### ⚠️ Disclaimer

This tool is for educational purposes and legitimate privacy protection.

Not a Silver Bullet: While this script significantly hardens privacy, OpSec is a mindset, not just a tool. Do not log into personal accounts (Google, Facebook) while using this script, as that will de-anonymize you regardless of your IP address.

Tor Limitations: Transparent proxying does not scrub protocol-specific headers (like User-Agents in HTTP). For web browsing, always use the Tor Browser Bundle in conjunction with this script for maximum safety.
