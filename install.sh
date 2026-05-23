#!/bin/bash
# Chromecast Security Blocker - Installation Script

echo "=== Chromecast Security Blocker Installation ==="

# Check for root privileges
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

# Detect OS
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    OS=$ID
fi

echo "Detected OS: $OS"

# Install dependencies based on OS
if [[ "$OS" == "ubuntu" || "$OS" == "debian" ]]; then
    echo "Installing dependencies for Debian/Ubuntu..."
    apt-get update
    apt-get install -y python3 python3-pip python3-venv python3-full iptables nmap avahi-utils tcpdump arptables
    
elif [[ "$OS" == "fedora" || "$OS" == "centos" || "$OS" == "rhel" ]]; then
    echo "Installing dependencies for Fedora/CentOS/RHEL..."
    yum install -y python3 python3-pip iptables nmap avahi-tools tcpdump arptables
    
elif [[ "$OS" == "arch" ]]; then
    echo "Installing dependencies for Arch..."
    pacman -S --noconfirm python python-pip iptables nmap avahi tcpdump arptables
    
else
    echo "Unsupported OS. Please install manually:"
    echo "  - python3 && python3-pip"
    echo "  - iptables"
    echo "  - nmap"
    echo "  - avahi-utils or avahi-tools"
    echo "  - tcpdump"
    echo "  - arptables"
    exit 1
fi

# Install Python dependencies into a virtual environment
echo "Installing Python dependencies..."
VENV_DIR="$(pwd)/venv"
python3 -m venv "$VENV_DIR"
"$VENV_DIR/bin/pip" install --upgrade pip
"$VENV_DIR/bin/pip" install -r requirements.txt

# Make scripts executable
chmod +x chromecast_blocker.py advanced_blocker.py ui_server.py

# Create log directory
mkdir -p logs
chmod 755 logs

# Setup systemd services (optional)
read -p "Install as systemd services (blocker + Web UI)? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    WORK_DIR="$(pwd)"

    cat > /etc/systemd/system/chromecast-blocker.service <<EOF
[Unit]
Description=Chromecast Security Blocker — Protection Daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=${WORK_DIR}
ExecStart=${WORK_DIR}/venv/bin/python3 ${WORK_DIR}/advanced_blocker.py monitor --interval 60
Restart=on-failure
RestartSec=10
StandardOutput=append:${WORK_DIR}/logs/blocker.log
StandardError=append:${WORK_DIR}/logs/blocker.log

[Install]
WantedBy=multi-user.target
EOF

    cat > /etc/systemd/system/chromecast-ui.service <<EOF
[Unit]
Description=Chromecast Blocker Web UI
After=network-online.target chromecast-blocker.service

[Service]
Type=simple
User=root
WorkingDirectory=${WORK_DIR}
ExecStart=${WORK_DIR}/venv/bin/python3 ${WORK_DIR}/ui_server.py --host 0.0.0.0 --port 8080
Restart=on-failure
RestartSec=5
StandardOutput=append:${WORK_DIR}/logs/ui_server.log
StandardError=append:${WORK_DIR}/logs/ui_server.log
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    echo "Services installed."
    echo "Enable:  systemctl enable chromecast-blocker chromecast-ui"
    echo "Start:   systemctl start  chromecast-blocker chromecast-ui"
fi

# Setup desktop autostart (shows terminal window at Pi login)
chmod +x startup_protect.sh

read -p "Install desktop autostart (terminal window on Pi login)? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    # Detect the real user (the one who invoked sudo, not root itself)
    REAL_USER="${SUDO_USER:-$USER}"
    REAL_HOME=$(getent passwd "$REAL_USER" | cut -d: -f6)
    AUTOSTART_DIR="$REAL_HOME/.config/autostart"

    mkdir -p "$AUTOSTART_DIR"

    # Rewrite the .desktop Exec path to the actual install location
    sed "s|/home/jorgen-larsen/block_chromecast|$(pwd)|g" \
        chromecast-autostart.desktop > "$AUTOSTART_DIR/chromecast-autostart.desktop"

    chown "$REAL_USER:$REAL_USER" "$AUTOSTART_DIR/chromecast-autostart.desktop"
    echo "Autostart installed → $AUTOSTART_DIR/chromecast-autostart.desktop"
    echo "The terminal window will open automatically at next desktop login."
fi

echo "=== Installation Complete ==="
echo ""
echo "Quick start (CLI):"
echo "  1. Discover:    sudo venv/bin/python3 chromecast_blocker.py discover"
echo "  2. Protect:     sudo venv/bin/python3 chromecast_blocker.py full-protect --ip <IP>"
echo "  3. Status:      sudo venv/bin/python3 chromecast_blocker.py status --ip <IP>"
echo ""
echo "Quick start (Web UI):"
echo "  venv/bin/python3 ui_server.py"
echo "  Then open: http://localhost:8080"
echo ""
echo "Raspberry Pi 4 gateway setup:"
echo "  sudo bash pi4_gateway.sh"
echo "  See PI4_SETUP.md for full instructions."
