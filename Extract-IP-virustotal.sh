#!/usr/bin/env bash
set -euo pipefail

# ---------------------------
# vt-collect-ips.sh
# - Prompts for Virustotal API key on first run and saves it in this script.
# - Takes root domain as argument or prompts user.
# - Asks user whether to save all IPs in one file or per-subdomain in a folder.
# ---------------------------

APIKEY="APIKEY_PLACEHOLDER"
DELAY=16   # seconds between requests (Adjust per Virustotal tier)

sanitize_filename() {
  local name="$1"
  echo "${name}" | sed 's/[^A-Za-z0-9._-]/_/g'
}

ensure_apikey_stored() {
  if [ -n "${VT_APIKEY-}" ]; then
    APIKEY_VAL="${VT_APIKEY}"
  else
    APIKEY_VAL="${APIKEY}"
  fi

  if [ -z "${APIKEY_VAL}" ] || [ "${APIKEY_VAL}" = "APIKEY_PLACEHOLDER" ]; then
    read -rsp "Enter VirusTotal API key (hidden): " input_key
    echo
    if [ -z "${input_key}" ]; then
      echo "[!] No API key provided. Exiting."
      exit 1
    fi
    APIKEY_VAL="${input_key}"
    script_path="$(realpath "$0")"
    esc_key=$(printf '%s\n' "$APIKEY_VAL" | sed -e 's/[\/&]/\\&/g')
    perl -0777 -pe "s/APIKEY\\s*=\\s*\"[^\"]*\"/APIKEY=\"${esc_key}\"/" -i "$script_path"
    echo "[*] API key saved into script for future use."
    APIKEY="${APIKEY_VAL}"
  else
    APIKEY="${APIKEY_VAL}"
  fi
}

# --- Get domain ---
if [ "${#}" -ge 1 ] && [ -n "${1-}" ]; then
  ROOT="$1"
else
  read -rp "Enter root domain (e.g. google.com): " ROOT
fi
if [[ -z "${ROOT// }" ]]; then
  echo "[!] No domain provided. Exiting."
  exit 1
fi

ensure_apikey_stored

DOMAIN_SAFE=$(sanitize_filename "${ROOT}")
TMP_SUBS="${DOMAIN_SAFE}_sub.tmp"
OUT_SUBS="${DOMAIN_SAFE}_sub.txt"

echo "[*] Fetching subdomains for ${ROOT}..."
curl -s "https://www.virustotal.com/vtapi/v2/domain/report?apikey=${APIKEY}&domain=${ROOT}" \
  | jq -r '.subdomains[]? // empty' | sort -u > "${TMP_SUBS}" || true

grep -qxF "${ROOT}" "${TMP_SUBS}" || echo "${ROOT}" >> "${TMP_SUBS}"

echo "[*] Found $(wc -l < "${TMP_SUBS}") subdomains/domains."

# --- Ask user for output style ---
echo
echo "How do you want to save IPs?"
echo "1) All IPs in a single file: ${DOMAIN_SAFE}_ip.txt"
echo "2) Create folder ${DOMAIN_SAFE}-ip/ with per-subdomain files"
read -rp "Choose option [1/2]: " SAVE_OPTION
SAVE_OPTION="${SAVE_OPTION:-1}"

> "${OUT_SUBS}"
ALL_IPS=""

if [ "$SAVE_OPTION" = "2" ]; then
  mkdir -p "${DOMAIN_SAFE}-ip"
fi

# --- Process each subdomain ---
while IFS= read -r domain; do
  domain="${domain//[$'\t\r\n ']}"
  [ -z "$domain" ] && continue
  echo "[*] Querying: $domain"
  echo "$domain" >> "${OUT_SUBS}"

  ips=$(curl -s "https://www.virustotal.com/vtapi/v2/domain/report?apikey=${APIKEY}&domain=${domain}" \
    | jq -r '.. | .ip_address? // empty' | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u || true)

  if [ "$SAVE_OPTION" = "1" ]; then
    ALL_IPS+="$ips"$'\n'
  else
    file="${DOMAIN_SAFE}-ip/${domain}_ip.txt"
    echo "$ips" | sort -u > "$file"
    echo "    -> Saved $(wc -l < "$file") IP(s) into $file"
  fi

  sleep "${DELAY}"
done < "${TMP_SUBS}"

if [ "$SAVE_OPTION" = "1" ]; then
  echo "$ALL_IPS" | sort -u > "${DOMAIN_SAFE}_ip.txt"
  echo "[+] Saved all unique IPs into ${DOMAIN_SAFE}_ip.txt"
else
  echo "[+] Per-subdomain IP files saved in folder: ${DOMAIN_SAFE}-ip/"
fi

sort -u "${OUT_SUBS}" -o "${OUT_SUBS}"
echo "[+] Subdomains saved into ${OUT_SUBS}"
rm -f "${TMP_SUBS}"
