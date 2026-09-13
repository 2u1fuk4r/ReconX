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
info "ReconX kurulum basliyor — sistem guncelleniyor..."
sudo apt-get update -y >/dev/null 2>&1
sudo apt-get install -y git curl wget unzip python3-pip python3-venv \
    nmap whatweb golang-go tor >/dev/null 2>&1

# Python bagimliliklari
python3 -m pip install --break-system-packages pyyaml curl-cffi stem 2>/dev/null \
  || python3 -m pip install pyyaml stem >/dev/null 2>&1

# Tor — engellenme ALGILANDIGINDA otomatik IP/devre rotasyonu icin (bkz.
# config.yaml: settings.auto_tor). ReconX kendi izole SOCKS/Control portlarini
# (.tor_data/) kullanarak KENDI Tor surecini baslatir — buradaki sistem
# paketi/binary'yi calistirmaz, sadece PATH'te bulunmasini saglar. Eksikse
# rotasyon ozelligi sessizce devre disi kalir, tarama normal calismaya devam eder.
if ! command -v tor >/dev/null 2>&1; then
  warn "tor kurulamadi — Ctrl+C menusu ve diger tum ozellikler calisir, "
  warn "sadece otomatik IP rotasyonu (settings.auto_tor) devre disi kalir"
else
  skip "tor"
fi

# Nuclei templates (cfg: "nuclei_templates" bos kalirsa otomatik)
export PATH="$PATH:$(go env GOPATH 2>/dev/null)/bin:${HOME}/go/bin"

# --------------------------------------------------------------------------
# Go tabanli araclar
echo
info "== Go araclari =="
go_need httpx        "github.com/projectdiscovery/httpx/cmd/httpx"
go_need subfinder    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
go_need nuclei       "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"
go_need katana       "github.com/projectdiscovery/katana/cmd/katana"
go_need gau          "github.com/lc/gau/v2/cmd/gau"
go_need waybackurls  "github.com/tomnomnom/waybackurls"
go_need dalfox       "github.com/hahwul/dalfox/v2"
go_need findomain    "github.com/Findomain/Findomain"
go_need assetfinder  "github.com/tomnomnom/assetfinder"

# trufflehog — "go install .../v3@latest" currently FAILS (exit 1): the
# module's own go.mod carries replace directives, which `go install pkg@ver`
# refuses to honor (a Go toolchain restriction, not a ReconX bug — verified
# directly against the real v3.97.4 module). apt's build is unaffected and
# is what Kali itself ships, so it's the primary path; go install is kept
# only as a last-resort fallback for non-Kali Debian systems without the
# apt package (may still fail for the reason above).
if ! command -v trufflehog >/dev/null 2>&1; then
  info "Kuruluyor: trufflehog"
  sudo apt-get install -y trufflehog >/dev/null 2>&1 \
    || ( export PATH="$PATH:$(go env GOPATH 2>/dev/null)/bin"
         go install github.com/trufflesecurity/trufflehog/v3@latest >/dev/null 2>&1 ) \
    || warn "trufflehog kurulamadi"
else
  skip "trufflehog"
fi

# --------------------------------------------------------------------------
# Python / pip araclari
echo
info "== Python araclari =="
pipx_need theHarvester "theHarvester"
pipx_need wafw00f      "wafw00f"
pipx_need arjun        "arjun"

# interactsh-client — blind XSS OOB callback (Stage 6). Opsiyonel ama onerilir.
go_need interactsh-client "github.com/projectdiscovery/interactsh/cmd/interactsh-client"

# v8.8-fix: these three used a BARE "pip install" (no "python3 -m" / no
# --break-system-packages). On Kali (and any PEP 668 "externally-managed-
# environment" system) that fails INSTANTLY with "error: externally-managed-
# environment" — verified directly on a real Kali box — which is exactly why
# all three silently showed "kurulamadi" for every user on a stock Kali
# install. pip_install() below matches the same --break-system-packages-
# then-plain-pip fallback chain already used elsewhere in this script (see
# pipx_need / the pyyaml+curl-cffi+stem line above).
pip_install(){
  python3 -m pip install --break-system-packages "$@" >/dev/null 2>&1 \
    || python3 -m pip install "$@" >/dev/null 2>&1
}

# ParamSpider (git clone + pip)
if ! command -v paramspider >/dev/null 2>&1; then
  info "Kuruluyor: paramspider"
  rm -rf /tmp/ParamSpider
  git clone -q --depth 1 https://github.com/devanshbatham/ParamSpider /tmp/ParamSpider
  pip_install /tmp/ParamSpider \
    || (cd /tmp/ParamSpider && pip_install -r requirements.txt && pip_install .) \
    || warn "paramspider kurulamadi"
else
  skip "paramspider"
fi

# Sublist3r (git clone + pip)
if ! command -v sublist3r >/dev/null 2>&1; then
  info "Kuruluyor: sublist3r"
  rm -rf /tmp/Sublist3r
  git clone -q --depth 1 https://github.com/aboul3la/Sublist3r /tmp/Sublist3r
  pip_install /tmp/Sublist3r || warn "sublist3r kurulamadi"
else
  skip "sublist3r"
fi

# LinkFinder (git clone + pip). "python setup.py install" is REMOVED — recent
# setuptools no longer supports it at all (and Python 3.12+ dropped distutils
# from the stdlib that old setup.py scripts implicitly relied on), so it
# always failed on any current system. "pip install ." is the modern
# equivalent and goes through the same PEP 668 handling as everything else.
if ! command -v linkfinder >/dev/null 2>&1; then
  info "Kuruluyor: linkfinder"
  rm -rf /tmp/LinkFinder
  git clone -q --depth 1 https://github.com/GerbenJavado/LinkFinder /tmp/LinkFinder
  pip_install /tmp/LinkFinder || warn "linkfinder kurulamadi"
else
  skip "linkfinder"
fi

# Hakrawler (go alt diziniyle kurulur)
go_need hakrawler "github.com/hakluke/hakrawler"

# --------------------------------------------------------------------------
# Nuclei template guncellemesi
if command -v nuclei >/dev/null 2>&1; then
  echo
  info "Nuclei template'leri guncelleniyor..."
  nuclei -update-templates -silent >/dev/null 2>&1 \
    && ok "Nuclei templates guncellendi" \
    || warn "nuclei template guncelleme basarisiz (sonra nuclei -update-templates dene)"
fi

# --------------------------------------------------------------------------
echo
info "Kurulum tamamlandi. Kurulu araclarin ozeti:"
for c in httpx subfinder nuclei katana gau waybackurls dalfox trufflehog \
         findomain assetfinder hakrawler theHarvester wafw00f arjun \
         paramspider sublist3r linkfinder nmap whatweb interactsh-client; do
  if command -v "$c" >/dev/null 2>&1; then ok "$c"; else warn "$c — YOK"; fi
done

echo
info "Opsiyonel: XSS 'alert' dogrulama ekran goruntuleri icin Playwright:"
echo "  python3 -m pip install --break-system-packages playwright && playwright install chromium"

echo
info "Ornek kullanim:"
echo "  python3 reconX.py -d example.com"
echo "  python3 reconX.py -u https://example.com  (tek URL)"
echo "  python3 reconx_web.py                    (web arayuz: http://127.0.0.1:8711)"
echo "  python3 reconX.py -d example.com --auto   (tam otomatik, tum 13 stage)"
echo "  python3 reconX.py --help                 (tum secenekler)"
