#!/data/data/com.termux/files/usr/bin/bash
# ============================================================================
#  ███████╗██╗██████╗  ██████╗ ███████╗
#  ╚══███╔╝██║██╔══██╗██╔═══██╗██╔════╝
#    ███╔╝ ██║██████╔╝██║   ██║███████╗
#   ███╔╝  ██║██╔═══╝ ██║   ██║╚════██║
#  ███████╗██║██║     ╚██████╔╝███████║
#  ╚══════╝╚═╝╚═╝      ╚═════╝ ╚══════╝
#
#  ZYLON FUSION - Termux Non-Root Installer
#  Fused from omino + wizard + Zylon custom techniques
#
# ============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
RESET='\033[0m'

echo -e "${RED}"
echo "    ███████╗██╗██████╗  ██████╗ ███████╗"
echo "    ╚══███╔╝██║██╔══██╗██╔═══██╗██╔════╝"
echo "      ███╔╝ ██║██████╔╝██║   ██║███████╗"
echo "     ███╔╝  ██║██╔═══╝ ██║   ██║╚════██║"
echo "    ███████╗██║██║     ╚██████╔╝███████║"
echo "    ╚══════╝╚═╝╚═╝      ╚═════╝ ╚══════╝"
echo -e "${RESET}"
echo -e "${CYAN}    ZYLON FUSION - Termux Non-Root Installer${RESET}"
echo -e "${YELLOW}    omino + wizard + Zylon Custom Techniques${RESET}"
echo ""

# Detect Termux
if [ -d "/data/data/com.termux" ]; then
    echo -e "${GREEN}[+] Termux environment detected${RESET}"
    IS_TERMUX=1
    PKG_CMD="pkg"
    PIP_CMD="pip"
else
    echo -e "${YELLOW}[!] Non-Termux environment detected (Linux/macOS)${RESET}"
    IS_TERMUX=0
    PKG_CMD="apt-get"
    PIP_CMD="pip3"
fi

# ============================================================================
# STEP 1: Update packages
# ============================================================================
echo -e "${CYAN}[*] Step 1/6: Updating package repositories...${RESET}"
if [ "$IS_TERMUX" = "1" ]; then
    pkg update -y 2>/dev/null || true
    pkg upgrade -y 2>/dev/null || true
else
    sudo apt-get update -y 2>/dev/null || true
fi
echo -e "${GREEN}[+] Package repositories updated${RESET}"

# ============================================================================
# STEP 2: Install system dependencies
# ============================================================================
echo -e "${CYAN}[*] Step 2/6: Installing system dependencies...${RESET}"

if [ "$IS_TERMUX" = "1" ]; then
    # Termux packages
    PACKAGES="python python-pip git curl wget nmap openssl whois"
    for pkg in $PACKAGES; do
        if ! pkg list-installed 2>/dev/null | grep -q "^$pkg"; then
            echo -e "  ${YELLOW}Installing $pkg...${RESET}"
            pkg install -y "$pkg" 2>/dev/null || true
        fi
    done
else
    # Linux packages
    PACKAGES="python3 python3-pip git curl wget nmap openssl whois"
    for pkg in $PACKAGES; do
        if ! command -v "$pkg" &> /dev/null; then
            echo -e "  ${YELLOW}Installing $pkg...${RESET}"
            sudo apt-get install -y "$pkg" 2>/dev/null || true
        fi
    done
fi

echo -e "${GREEN}[+] System dependencies installed${RESET}"

# ============================================================================
# STEP 3: Install Python dependencies
# ============================================================================
echo -e "${CYAN}[*] Step 3/6: Installing Python dependencies...${RESET}"

PIP_PACKAGES="requests rich colorama beautifulsoup4 dnspython python-whois lxml cryptography aiohttp pyfiglet"

for pkg in $PIP_PACKAGES; do
    echo -e "  ${YELLOW}Installing $pkg...${RESET}"
    $PIP_CMD install "$pkg" --quiet 2>/dev/null || true
done

echo -e "${GREEN}[+] Python dependencies installed${RESET}"

# ============================================================================
# STEP 4: Install ZYLON FUSION
# ============================================================================
echo -e "${CYAN}[*] Step 4/6: Installing ZYLON FUSION...${RESET}"

# Determine install directory
if [ "$IS_TERMUX" = "1" ]; then
    INSTALL_DIR="$HOME/zylon-fusion"
else
    INSTALL_DIR="$HOME/zylon-fusion"
fi

# Clone or update
if [ -d "$INSTALL_DIR" ]; then
    echo -e "${YELLOW}[*] Updating existing installation...${RESET}"
    cd "$INSTALL_DIR"
    git pull 2>/dev/null || true
else
    echo -e "${YELLOW}[*] Cloning ZYLON FUSION...${RESET}"
    # If running from local source, just copy
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if [ -f "$SCRIPT_DIR/zylon.py" ]; then
        mkdir -p "$INSTALL_DIR"
        cp -r "$SCRIPT_DIR"/* "$INSTALL_DIR/"
    else
        git clone https://github.com/zylon/zylon-fusion "$INSTALL_DIR" 2>/dev/null || true
    fi
fi

echo -e "${GREEN}[+] ZYLON FUSION installed to $INSTALL_DIR${RESET}"

# ============================================================================
# STEP 5: Setup directories and config
# ============================================================================
echo -e "${CYAN}[*] Step 5/6: Setting up directories...${RESET}"

mkdir -p "$HOME/.zylon"
mkdir -p "$HOME/.zylon/reports"
mkdir -p "$HOME/.zylon/logs"
mkdir -p "$HOME/.zylon/wordlists"

# Create default config if not exists
if [ ! -f "$HOME/.zylon/config.json" ]; then
    cat > "$HOME/.zylon/config.json" << 'EOF'
{
    "shodan_api_key": "",
    "virustotal_api_key": "",
    "hunter_api_key": "",
    "securitytrails_api_key": "",
    "censys_api_id": "",
    "censys_api_secret": "",
    "ai_api_key": "",
    "ai_endpoint": "https://api.openai.com/v1"
}
EOF
fi

echo -e "${GREEN}[+] Directories and config created${RESET}"

# ============================================================================
# STEP 6: Create launcher alias
# ============================================================================
echo -e "${CYAN}[*] Step 6/6: Creating launcher...${RESET}"

# Create launcher script
LAUNCHER="$INSTALL_DIR/zylon"
cat > "$LAUNCHER" << EOF
#!/data/data/com.termux/files/usr/bin/env bash
cd "$INSTALL_DIR"
python3 zylon.py "\$@"
EOF
chmod +x "$LAUNCHER"

# Add to PATH
SHELL_RC="$HOME/.bashrc"
if [ "$IS_TERMUX" = "1" ]; then
    SHELL_RC="$HOME/.bashrc"
fi

if ! grep -q "zylon-fusion" "$SHELL_RC" 2>/dev/null; then
    echo "" >> "$SHELL_RC"
    echo "# ZYLON FUSION" >> "$SHELL_RC"
    echo "alias zylon='$LAUNCHER'" >> "$SHELL_RC"
    echo "alias zylon-fusion='$LAUNCHER'" >> "$SHELL_RC"
fi

echo -e "${GREEN}[+] Launcher created${RESET}"

# ============================================================================
# COMPLETE
# ============================================================================
echo ""
echo -e "${RED}╔══════════════════════════════════════════════════════════╗${RESET}"
echo -e "${RED}║                  INSTALLATION COMPLETE                   ║${RESET}"
echo -e "${RED}╚══════════════════════════════════════════════════════════╝${RESET}"
echo ""
echo -e "${GREEN}[+] ZYLON FUSION is ready!${RESET}"
echo ""
echo -e "${CYAN}Quick Start:${RESET}"
echo -e "  ${YELLOW}source ~/.bashrc${RESET}"
echo -e "  ${YELLOW}zylon${RESET}"
echo ""
echo -e "${CYAN}Or run directly:${RESET}"
echo -e "  ${YELLOW}cd $INSTALL_DIR && python3 zylon.py${RESET}"
echo ""
echo -e "${CYAN}Configure API keys:${RESET}"
echo -e "  ${YELLOW}nano ~/.zylon/config.json${RESET}"
echo ""
echo -e "${MAGENTA}  Built by Zylon | omino + wizard + Custom Techniques${RESET}"
echo -e "${MAGENTA}  For authorized security testing only${RESET}"
echo ""
