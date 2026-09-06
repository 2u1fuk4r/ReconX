#!/usr/bin/env bash
# =============================================================================
#  ReconX — Single-command installer for Kali / Debian-based distros
#  Run:   bash install.sh
#  Detects already-installed tools and skips them (or re-tags them).
#  Installs only what is missing. Safe to re-run anytime (idempotent).
# =============================================================================
set -u

R='\033[31m'; G='\033[32m'; Y='\033[33m'; C='\033[36m'; B='\033[1m'; N='\033[0m'
ok(){   printf "${G}${B}[ OK ]${N} %s\n" "$1"; }
skip(){ printf "${Y}${B}[HAS ]${N} %s — zaten kurulu, atlaniyor\n" "$1"; }
warn(){ printf "${R}${B}[WARN]${N} %s\n" "$1"; }
info(){ printf "${C}${B}[INFO]${N} %s\n" "$1"; }

cd "$(dirname "$0")"

# --------------------------------------------------------------------------
need(){ # need <cmd> <install-cmds...>
  local cmd="$1"; shift
  if command -v "$cmd" >/dev/null 2>&1; then
    skip "$cmd"
    return 0
  fi
  info "Kuruluyor: $cmd"
  "$@" || warn "$cmd kurulamadi — devam ediliyor"
}

pipx_need(){ # pipx_need <executable> <pip-package>
  local cmd="$1"
  if command -v "$cmd" >/dev/null 2>&1; then
    skip "$cmd"; return 0
  fi
  info "Kuruluyor (pip): $2"
  python3 -m pip install --break-system-packages "$2" >/dev/null 2>&1 \
    || pip install "$2" >/dev/null 2>&1 \
    || warn "$2 kurulamadi"
}

go_need(){ # go_need <executable> <go-import>
  local cmd="$1"
  if command -v "$cmd" >/dev/null 2>&1; then
    skip "$cmd"; return 0
  fi
  info "Kuruluyor (go): $2"
  ( export PATH="$PATH:$(go env GOPATH 2>/dev/null)/bin"
    go install "$2"@latest >/dev/null 2>&1 ) \
    || warn "$2 (go) kurulamadi"
}

# --------------------------------------------------------------------------
info "${B}ReconX kurulum basliyor — sistem guncelleniyor...${N}"
sudo apt-get update -y >/dev/null 2>&1
sudo apt-get install -y git curl wget unzip python3-pip python3-venv \
    nmap whatweb golang-go >/dev/null 2>&1

# Python bagimliliklari
python3 -m pip install --break-system-packages pyyaml curl-cffi 2>/dev/null \
  || python3 -m pip install pyyaml >/dev/null 2>&1

# Nuclei templates (cfg: "nuclei_templates" bos kalirsa otomatik)
export PATH="$PATH:$(go env GOPATH 2>/dev/null)/bin:${HOME}/go/bin"

# --------------------------------------------------------------------------
# Go tabanli araclar
info "${B}\n== Go araclari ==${N}"
go_need httpx        "github.com/projectdiscovery/httpx/cmd/httpx"
go_need subfinder    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
go_need nuclei       "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"
go_need katana       "github.com/projectdiscovery/katana/cmd/katana"
go_need gau          "github.com/lc/gau/v2/cmd/gau"
go_need waybackurls  "github.com/tomnomnom/waybackurls"
go_need dalfox       "github.com/hahwul/dalfox/v2"
go_need trufflehog   "github.com/trufflesecurity/trufflehog"
go_need findomain    "github.com/Findomain/Findomain"
go_need assetfinder  "github.com/tomnomnom/assetfinder"

# --------------------------------------------------------------------------
# Python / pip araclari
info "${B}\n== Python araclari ==${N}"
pipx_need theHarvester "theHarvester"
pipx_need wafw00f      "wafw00f"
pipx_need arjun        "arjun"
pipx_need shodan       "shodan"

# sqlmap — Stage 14 (SQL injection). apt paketi Kali'de mevcut; degilse pip.
if ! command -v sqlmap >/dev/null 2>&1; then
  info "Kuruluyor: sqlmap"
  sudo apt-get install -y sqlmap >/dev/null 2>&1 \
    || python3 -m pip install --break-system-packages sqlmap >/dev/null 2>&1 \
    || warn "sqlmap kurulamadi — Stage 14 (SQLi) devre disi kalir"
else
  skip "sqlmap"
fi

# interactsh-client — blind XSS OOB callback (Stage 6). Opsiyonel ama onerilir.
go_need interactsh-client "github.com/projectdiscovery/interactsh/cmd/interactsh-client"

# ParamSpider (git clone + pip)
if ! command -v paramspider >/dev/null 2>&1; then
  info "Kuruluyor: paramspider"
  rm -rf /tmp/ParamSpider
  git clone -q --depth 1 https://github.com/devanshbatham/ParamSpider /tmp/ParamSpider
  pip install /tmp/ParamSpider >/dev/null 2>&1 \
    || (cd /tmp/ParamSpider && pip install -r requirements.txt >/dev/null 2>&1 \
        && pip install . >/dev/null 2>&1) \
    || warn "paramspider kurulamadi"
else
  skip "paramspider"
fi

# Sublist3r (git clone + pip)
if ! command -v sublist3r >/dev/null 2>&1; then
  info "Kuruluyor: sublist3r"
  rm -rf /tmp/Sublist3r
  git clone -q --depth 1 https://github.com/aboul3la/Sublist3r /tmp/Sublist3r
  pip install /tmp/Sublist3r >/dev/null 2>&1 || warn "sublist3r kurulamadi"
else
  skip "sublist3r"
fi

# LinkFinder (git clone + pip)
if ! command -v linkfinder >/dev/null 2>&1; then
  info "Kuruluyor: linkfinder"
  rm -rf /tmp/LinkFinder
  git clone -q --depth 1 https://github.com/GerbenJavado/LinkFinder /tmp/LinkFinder
  ( cd /tmp/LinkFinder && python3 setup.py install >/dev/null 2>&1 ) \
    || warn "linkfinder kurulamadi"
else
  skip "linkfinder"
fi

# Hakrawler (go alt diziniyle kurulur)
go_need hakrawler "github.com/hakluke/hakrawler"

# --------------------------------------------------------------------------
# Nuclei template guncellemesi
if command -v nuclei >/dev/null 2>&1; then
  info "${B}\nNuclei template'leri guncelleniyor...${N}"
  nuclei -update-templates -silent >/dev/null 2>&1 \
    && ok "Nuclei templates guncellendi" \
    || warn "nuclei template guncelleme basarisiz (sonra nuclei -update-templates dene)"
fi

# --------------------------------------------------------------------------
echo
info "${B}Kurulum tamamlandi. Kurulu araclarin ozeti:${N}"
for c in httpx subfinder nuclei katana gau waybackurls dalfox trufflehog \
         findomain assetfinder shodan hakrawler theHarvester wafw00f arjun \
         paramspider sublist3r linkfinder nmap whatweb sqlmap interactsh-client; do
  if command -v "$c" >/dev/null 2>&1; then ok "$c"; else warn "$c — YOK"; fi
done

echo
info "Opsiyonel: XSS 'alert' dogrulama ekran goruntuleri icin Playwright:"
echo "  python3 -m pip install --break-system-packages playwright && playwright install chromium"

echo
info "${B}Ornek kullanim:${N}"
echo "  python3 reconX.py -d example.com"
echo "  python3 reconX.py -u https://example.com  (tek URL)"
echo "  python3 reconx_web.py                    (web arayuz: http://127.0.0.1:8711)"
echo "  python3 reconX.py -d example.com --auto   (tam otomatik, tum 14 stage)"
echo "  python3 reconX.py --help                 (tum secenekler)"
