#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║       ReconX - Automated Installation Script v2.1           ║
# ║       Kali Linux 2023+ / Debian 12+ / Ubuntu 22+            ║
# ╚══════════════════════════════════════════════════════════════╝

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'; BOLD='\033[1m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"
LOG_FILE="$SCRIPT_DIR/install.log"
ERRORS=0
GLOBAL_BIN="/usr/local/bin"   # Tek global hedef — her yerden erişilir

info()    { echo -e "${GREEN}[+]${NC} $1" | tee -a "$LOG_FILE"; }
warn()    { echo -e "${YELLOW}[!]${NC} $1" | tee -a "$LOG_FILE"; }
err()     { echo -e "${RED}[✗]${NC} $1" | tee -a "$LOG_FILE"; ((ERRORS++)) || true; }
ok()      { echo -e "${GREEN}[✓]${NC} $1" | tee -a "$LOG_FILE"; }
section() { echo -e "\n${CYAN}${BOLD}╔══ $1 ══╗${NC}" | tee -a "$LOG_FILE"; }

# ── Banner ────────────────────────────────────────────────────
echo -e "${BLUE}${BOLD}"
cat << 'EOF'
 ____                       __  __
|  _ \ ___  ___ ___  _ __ \ \/ /
| |_) / _ \/ __/ _ \| '_ \ \  /
|  _ <  __/ (_| (_) | | | |/  \
|_| \_\___|\___\___/|_| |_/_/\_\
  Bug Bounty Recon Framework - Installer v2.1
EOF
echo -e "${NC}"
echo "Log: $LOG_FILE"
date > "$LOG_FILE"

# ── Root kontrolü ─────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
  echo -e "${RED}[✗] Bu script root olarak çalıştırılmalı!${NC}"
  echo -e "    ${YELLOW}sudo bash install.sh${NC}"
  exit 1
fi

# ── OS tespiti ────────────────────────────────────────────────
section "OS Tespiti"
if   [[ -f /etc/kali_version ]];   then OS="kali";   info "Kali Linux tespit edildi"
elif [[ -f /etc/debian_version ]]; then OS="debian"; info "Debian/Ubuntu tespit edildi"
elif [[ -f /etc/arch-release ]];   then OS="arch";   info "Arch Linux tespit edildi"
else OS="debian"; warn "Bilinmeyen OS — Debian varsayılıyor"; fi

# ── APT güncelleme ────────────────────────────────────────────
section "APT Güncelleme"
info "apt-get update çalıştırılıyor..."
apt-get update -qq 2>&1 | tail -3 | tee -a "$LOG_FILE"

# ── Sistem paketleri ──────────────────────────────────────────
section "Sistem Paketleri"

apt_pkgs=(
  git curl wget unzip p7zip-full
  python3 python3-pip python3-venv python3-dev python3-setuptools
  ruby ruby-dev rubygems
  nmap masscan dirb whois dnsutils
  libpcap-dev build-essential libssl-dev libffi-dev
  libxml2-dev libxslt1-dev zlib1g-dev
  chromium
  golang-go
  amass theharvester
  seclists wordlists
)

info "Paketler kuruluyor (bu birkaç dakika sürebilir)..."
for pkg in "${apt_pkgs[@]}"; do
  if dpkg -l "$pkg" &>/dev/null 2>&1; then
    true  # zaten kurulu
  else
    if apt-get install -y -q "$pkg" >> "$LOG_FILE" 2>&1; then
      ok "  $pkg"
    else
      warn "  $pkg kurulamadı — devam ediliyor"
    fi
  fi
done

# chromium fallback (eski Kali)
if ! command -v chromium &>/dev/null && ! command -v chromium-browser &>/dev/null; then
  apt-get install -y -q chromium-browser >> "$LOG_FILE" 2>&1 \
    || warn "chromium bulunamadı — EyeWitness çalışmayabilir"
fi

# ── Go kurulumu / güncelleme ──────────────────────────────────
section "Go Kurulumu"

# GOPATH'i root için sabitle
export GOPATH="/root/go"
export PATH="$PATH:/usr/local/go/bin:$GOPATH/bin"

install_go_latest() {
  local GO_VER="1.22.4"
  info "Go $GO_VER indiriliyor..."
  wget -q "https://go.dev/dl/go${GO_VER}.linux-amd64.tar.gz" -O /tmp/go.tar.gz >> "$LOG_FILE" 2>&1 || {
    err "Go indirilemedi — internet bağlantısını kontrol edin"
    return 1
  }
  rm -rf /usr/local/go
  tar -C /usr/local -xzf /tmp/go.tar.gz >> "$LOG_FILE" 2>&1
  rm -f /tmp/go.tar.gz
  export PATH="$PATH:/usr/local/go/bin"
  ok "Go $(go version) kuruldu → /usr/local/go"
}

if command -v go &>/dev/null; then
  GO_MAJOR=$(go version | grep -oP 'go\K\d+\.\d+' | cut -d. -f1)
  GO_MINOR=$(go version | grep -oP 'go\K\d+\.\d+' | cut -d. -f2)
  info "Mevcut Go: $(go version)"
  if [[ "$GO_MAJOR" -lt 1 ]] || ( [[ "$GO_MAJOR" -eq 1 ]] && [[ "$GO_MINOR" -lt 19 ]] ); then
    warn "Go çok eski (v$GO_MAJOR.$GO_MINOR < 1.19) — güncelleniyor..."
    install_go_latest
  fi
else
  warn "Go bulunamadı — indiriliyor..."
  install_go_latest
fi

# ── Python venv ───────────────────────────────────────────────
section "Python Virtual Environment"

if [[ ! -d "$VENV_DIR" ]]; then
  info "Venv oluşturuluyor: $VENV_DIR"
  python3 -m venv "$VENV_DIR" >> "$LOG_FILE" 2>&1 || { err "python3-venv başarısız!"; exit 1; }
fi

PIP="$VENV_DIR/bin/pip"
PYTHON="$VENV_DIR/bin/python3"

"$PIP" install --upgrade pip setuptools wheel --quiet >> "$LOG_FILE" 2>&1
ok "Venv hazır: $VENV_DIR"

pip_install() {
  if [[ "$1" == "-r" ]]; then
    "$PIP" install -r "$2" --quiet >> "$LOG_FILE" 2>&1 \
      && ok "  requirements: $2" || warn "  Bazı requirements başarısız: $2"
  else
    "$PIP" install "$1" --quiet >> "$LOG_FILE" 2>&1 \
      && ok "  python: $1" || warn "  python: $1 başarısız"
  fi
}

# ── Python paketleri ──────────────────────────────────────────
section "Python Paketleri (venv)"
py_pkgs=(
  requests urllib3 dnspython colorama pyyaml tqdm
  shodan censys rich tabulate jinja2
  truffleHog sublist3r
)
for pkg in "${py_pkgs[@]}"; do
  pip_install "$pkg"
done

# ── Go araçları ───────────────────────────────────────────────
section "Go Araçları"
# Tüm go araçları GOPATH/bin'e iner → sonra /usr/local/bin'e symlink

go_install() {
  local pkg="$1"
  local name
  name=$(basename "${pkg%%@*}")   # @latest vs. şeridi at, sadece binary adını al

  # Zaten global'de varsa atla
  if command -v "$name" &>/dev/null; then
    ok "  $name (zaten global erişilebilir)"
    return 0
  fi

  info "  Kuruluyor: $name  ($pkg)"
  if GOPATH="$GOPATH" go install "$pkg" >> "$LOG_FILE" 2>&1; then
    # Binary nerede? GOPATH/bin altında olmalı
    local bin_path="$GOPATH/bin/$name"
    if [[ -f "$bin_path" ]]; then
      # /usr/local/bin'e kopyala (symlink yerine cp — bazı sistemlerde symlink PATH sorunu çıkarır)
      cp -f "$bin_path" "$GLOBAL_BIN/$name"
      chmod +x "$GLOBAL_BIN/$name"
      ok "  $name → $GLOBAL_BIN/$name"
    else
      # İsim farklı olabilir (örn. "cmd/subfinder" → binary adı "subfinder")
      # GOPATH/bin altındaki en yeni binary'i bul
      local newest
      newest=$(find "$GOPATH/bin" -maxdepth 1 -newer "$LOG_FILE" -type f -executable 2>/dev/null | head -1)
      if [[ -n "$newest" ]]; then
        local real_name; real_name=$(basename "$newest")
        cp -f "$newest" "$GLOBAL_BIN/$real_name"
        chmod +x "$GLOBAL_BIN/$real_name"
        ok "  $real_name → $GLOBAL_BIN/$real_name  (otomatik tespit)"
      else
        err "  $name binary bulunamadı — log'u kontrol et"
      fi
    fi
  else
    err "  $name go install başarısız (detay: tail -50 $LOG_FILE)"
  fi
}

go_install "github.com/OJ/gobuster/v3@latest"
go_install "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
go_install "github.com/projectdiscovery/httpx/cmd/httpx@latest"
go_install "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
go_install "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
go_install "github.com/projectdiscovery/katana/cmd/katana@latest"
go_install "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
go_install "github.com/tomnomnom/waybackurls@latest"
go_install "github.com/tomnomnom/assetfinder@latest"
go_install "github.com/tomnomnom/gf@latest"
go_install "github.com/hakluke/hakrawler@latest"
go_install "github.com/lc/gau/v2/cmd/gau@latest"
go_install "github.com/ffuf/ffuf/v2@latest"
go_install "github.com/hahwul/dalfox/v2@latest"
go_install "github.com/zricethezav/gitleaks/v8@latest"
go_install "github.com/0xsha/cloudbrute@latest"

# ── GOPATH/bin → global: artık eklenmeyen kaldıysa toplu kopyala ─────────────
section "Go Binary'leri Global'e Kopyalama"
info "GOPATH/bin altındaki tüm binary'ler $GLOBAL_BIN'e kopyalanıyor..."
copied=0
if [[ -d "$GOPATH/bin" ]]; then
  for bin in "$GOPATH/bin"/*; do
    [[ -f "$bin" && -x "$bin" ]] || continue
    local_name=$(basename "$bin")
    # Zaten varsa üzerine yaz (yeni sürüm olabilir)
    cp -f "$bin" "$GLOBAL_BIN/$local_name"
    chmod +x "$GLOBAL_BIN/$local_name"
    ((copied++)) || true
  done
  ok "Toplam $copied binary → $GLOBAL_BIN"
else
  warn "GOPATH/bin dizini bulunamadı: $GOPATH/bin"
fi

# ── Git araçları ──────────────────────────────────────────────
section "Git Araçları"

clone_or_update() {
  local dir="$1" url="$2"
  local name; name=$(basename "$dir")
  if [[ -d "$dir/.git" ]]; then
    info "  $name güncel mi kontrol ediliyor..."
    git -C "$dir" pull --quiet >> "$LOG_FILE" 2>&1 && ok "  $name güncellendi" || warn "  $name pull başarısız"
  else
    info "  Klonlanıyor: $name"
    if git clone --depth 1 "$url" "$dir" >> "$LOG_FILE" 2>&1; then
      ok "  $name ✓"
    else
      err "  $name klonlanamadı"
      return 1
    fi
  fi
  # requirements varsa venv'e kur
  [[ -f "$dir/requirements.txt" ]] && pip_install -r "$dir/requirements.txt"
}

mkdir -p /opt/{Sublist3r,dirsearch,altdns,EyeWitness,GoogD0rker,parameth,dnscan,knockpy}

clone_or_update /opt/Sublist3r   "https://github.com/aboul3la/Sublist3r"
clone_or_update /opt/dirsearch   "https://github.com/maurosoria/dirsearch"
clone_or_update /opt/altdns      "https://github.com/infosec-au/altdns"
clone_or_update /opt/EyeWitness  "https://github.com/FortyNorthSecurity/EyeWitness"
clone_or_update /opt/GoogD0rker  "https://github.com/ZephrFish/GoogD0rker"
clone_or_update /opt/parameth    "https://github.com/mak-/parameth"
clone_or_update /opt/dnscan      "https://github.com/rbsec/dnscan"
clone_or_update /opt/knockpy     "https://github.com/guelfoweb/knock"

# EyeWitness setup
if [[ -f /opt/EyeWitness/Python/setup/setup.sh ]]; then
  info "EyeWitness setup çalıştırılıyor..."
  bash /opt/EyeWitness/Python/setup/setup.sh >> "$LOG_FILE" 2>&1 \
    || warn "EyeWitness setup başarısız"
fi

# ── Wrapper'lar — global erişim ───────────────────────────────
section "Wrapper Script'ler (global)"

# dirsearch
if [[ -f /opt/dirsearch/dirsearch.py ]]; then
  cat > "$GLOBAL_BIN/dirsearch" << DS
#!/usr/bin/env bash
"$VENV_DIR/bin/python3" /opt/dirsearch/dirsearch.py "\$@"
DS
  chmod +x "$GLOBAL_BIN/dirsearch"
  ok "dirsearch → $GLOBAL_BIN/dirsearch"
fi

# sublist3r
if [[ -f /opt/Sublist3r/sublist3r.py ]]; then
  cat > "$GLOBAL_BIN/sublist3r" << SL
#!/usr/bin/env bash
"$VENV_DIR/bin/python3" /opt/Sublist3r/sublist3r.py "\$@"
SL
  chmod +x "$GLOBAL_BIN/sublist3r"
  ok "sublist3r → $GLOBAL_BIN/sublist3r"
fi

# theHarvester — genelde apt'den geliyor ama fallback
if ! command -v theHarvester &>/dev/null 2>&1; then
  clone_or_update /opt/theHarvester "https://github.com/laramies/theHarvester"
  if [[ -f /opt/theHarvester/theHarvester.py ]]; then
    cat > "$GLOBAL_BIN/theHarvester" << TH
#!/usr/bin/env bash
"$VENV_DIR/bin/python3" /opt/theHarvester/theHarvester.py "\$@"
TH
    chmod +x "$GLOBAL_BIN/theHarvester"
    pip_install -r /opt/theHarvester/requirements.txt
    ok "theHarvester → $GLOBAL_BIN/theHarvester"
  fi
fi

# ReconX ana wrapper
cat > "$SCRIPT_DIR/reconx" << WRAPPER
#!/usr/bin/env bash
SCRIPT_DIR="\$(cd "\$(dirname "\${BASH_SOURCE[0]}")" && pwd)"
export PATH="\$PATH:$GLOBAL_BIN:/usr/local/go/bin:$GOPATH/bin"
export GOPATH="$GOPATH"
"\$SCRIPT_DIR/.venv/bin/python3" "\$SCRIPT_DIR/scanner.py" "\$@"
WRAPPER
chmod +x "$SCRIPT_DIR/reconx"
ok "ReconX wrapper → $SCRIPT_DIR/reconx"

# ── masscan ────────────────────────────────────────────────────
section "masscan"
if command -v masscan &>/dev/null; then
  ok "masscan: $(masscan --version 2>/dev/null | head -1)"
else
  warn "masscan apt'den kurulamadı — kaynaktan derleniyor..."
  clone_or_update /opt/masscan_src "https://github.com/robertdavidgraham/masscan"
  make -C /opt/masscan_src -j"$(nproc)" >> "$LOG_FILE" 2>&1 \
    && cp -f /opt/masscan_src/bin/masscan "$GLOBAL_BIN/masscan" \
    && chmod +x "$GLOBAL_BIN/masscan" \
    && ok "masscan → $GLOBAL_BIN/masscan" \
    || err "masscan derleme başarısız"
fi

# ── Nuclei templates ──────────────────────────────────────────
section "Nuclei Templates"
if command -v nuclei &>/dev/null; then
  info "Nuclei templates güncelleniyor (bu biraz sürer)..."
  nuclei -update-templates >> "$LOG_FILE" 2>&1 && ok "Nuclei templates ✓" \
    || warn "Nuclei templates güncellenemedi"
fi

# ── Ruby gems ─────────────────────────────────────────────────
section "Ruby Gems"
if command -v gem &>/dev/null; then
  gem install bucket_finder >> "$LOG_FILE" 2>&1 && ok "bucket_finder ✓" \
    || warn "bucket_finder gem başarısız"
else
  warn "Ruby gem bulunamadı"
fi

# ── Wordlistler ───────────────────────────────────────────────
section "Wordlistler"
WL_FOUND=""
for wl in \
  "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt" \
  "/usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt" \
  "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt" \
  "/usr/share/wordlists/dirb/common.txt"; do
  if [[ -f "$wl" ]]; then
    WL_FOUND="$wl"
    ok "Wordlist bulundu: $wl"
    sed -i "s|wordlist:.*|wordlist: \"$wl\"|" "$SCRIPT_DIR/config.yaml" 2>/dev/null || true
    break
  fi
done

if [[ -z "$WL_FOUND" ]]; then
  warn "Hiç wordlist bulunamadı — minimal fallback oluşturuluyor..."
  mkdir -p "$SCRIPT_DIR/wordlists"
  cat > "$SCRIPT_DIR/wordlists/common.txt" << 'WL'
admin login api backup config dashboard upload uploads static assets
js css img images files data db database test dev staging beta old
archive wp-admin phpmyadmin .env .git robots.txt sitemap.xml
WL
  sed -i "s|wordlist:.*|wordlist: \"$SCRIPT_DIR/wordlists/common.txt\"|" \
    "$SCRIPT_DIR/config.yaml" 2>/dev/null || true
  ok "Minimal fallback wordlist → $SCRIPT_DIR/wordlists/common.txt"
fi

# ── Shell PATH ────────────────────────────────────────────────
section "Shell PATH"
SHELL_RC="/root/.bashrc"
[[ -f "/root/.zshrc" ]] && SHELL_RC="/root/.zshrc"

PATH_LINES=(
  'export GOPATH="/root/go"'
  'export PATH="$PATH:/root/go/bin:/usr/local/go/bin:/usr/local/bin"'
)
for line in "${PATH_LINES[@]}"; do
  grep -qF "$line" "$SHELL_RC" 2>/dev/null || echo "$line" >> "$SHELL_RC"
done
ok "PATH → $SHELL_RC"

# ── Çıktı klasörleri ─────────────────────────────────────────
mkdir -p "$SCRIPT_DIR/output" "$SCRIPT_DIR/logs" "$SCRIPT_DIR/wordlists"

# ── FINAL: Kurulum özeti & eksik araç raporu ──────────────────
section "Kurulum Özeti"
echo ""

declare -A TOOLS=(
  [nmap]="nmap"
  [masscan]="masscan"
  [gobuster]="gobuster"
  [subfinder]="subfinder"
  [httpx]="httpx"
  [nuclei]="nuclei"
  [ffuf]="ffuf"
  [amass]="amass"
  [waybackurls]="waybackurls"
  [assetfinder]="assetfinder"
  [hakrawler]="hakrawler"
  [gau]="gau"
  [katana]="katana"
  [dnsx]="dnsx"
  [dalfox]="dalfox"
  [theHarvester]="theHarvester"
  [dirb]="dirb"
  [gitleaks]="gitleaks"
  [sublist3r]="sublist3r"
  [dirsearch]="dirsearch"
  [naabu]="naabu"
)

ok_count=0; fail_count=0; fail_list=()

for name in $(echo "${!TOOLS[@]}" | tr ' ' '\n' | sort); do
  cmd="${TOOLS[$name]}"
  # PATH'te mi? GOPATH/bin'de mi? /usr/local/bin'de mi? hepsini kontrol et
  if command -v "$cmd" &>/dev/null \
     || [[ -x "$GOPATH/bin/$cmd" ]] \
     || [[ -x "$GLOBAL_BIN/$cmd" ]]; then
    # Konumunu bul ve göster
    loc=$(command -v "$cmd" 2>/dev/null \
          || ([[ -x "$GLOBAL_BIN/$cmd" ]] && echo "$GLOBAL_BIN/$cmd") \
          || echo "$GOPATH/bin/$cmd")
    echo -e "  ${GREEN}✓${NC} ${BOLD}$name${NC}  ${CYAN}→ $loc${NC}"
    ((ok_count++)) || true
  else
    echo -e "  ${RED}✗${NC} ${BOLD}$name${NC}  ${YELLOW}(bulunamadı)${NC}"
    fail_list+=("$name")
    ((fail_count++)) || true
  fi
done

echo ""
echo -e "  Python venv : ${CYAN}$VENV_DIR${NC}"
echo -e "  GOPATH      : ${CYAN}$GOPATH${NC}"
echo -e "  Global bin  : ${CYAN}$GLOBAL_BIN${NC}"
echo -e "  Log dosyası : ${CYAN}$LOG_FILE${NC}"
echo ""
echo -e "  ${GREEN}✓ Hazır: $ok_count${NC} / ${#TOOLS[@]}   ${RED}✗ Eksik: $fail_count${NC}"

if [[ ${#fail_list[@]} -gt 0 ]]; then
  echo ""
  echo -e "  ${YELLOW}Eksik araçlar:${NC} ${fail_list[*]}"
  echo -e "  ${YELLOW}Detaylı log:${NC}  tail -100 $LOG_FILE"
fi

[[ $ERRORS -gt 0 ]] && echo -e "\n  ${YELLOW}⚠ Toplam $ERRORS hata oluştu — log: $LOG_FILE${NC}"

echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════╗"
echo -e "║   ✅  ReconX Kurulumu Tamamlandı!            ║"
echo -e "╚══════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${BOLD}Çalıştır:${NC}  ${YELLOW}cd $SCRIPT_DIR && ./reconx -d hedef.com${NC}"
echo -e "  ${BOLD}Log:${NC}       ${YELLOW}cat $LOG_FILE${NC}"
echo ""
