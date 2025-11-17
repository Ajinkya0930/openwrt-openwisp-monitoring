#!/bin/sh
# Minimal modem1.info -> NetJSON (mobile) generator
# Outputs ONLY the fields required by your schema (+ signal as 5g or lte)

set -eu

infile="${1:-}"
outfile="${2:-}"

if [ -z "$infile" ] || [ -z "$outfile" ]; then
  echo "Usage: $0 /path/to/modem1.info /path/to/output.json" >&2
  exit 1
fi

[ -f "$infile" ] || { echo "Input file not found: $infile" >&2; exit 1; }

trim(){ printf "%s" "$1" | awk '{$1=$1;print}'; }
digits(){ printf "%s" "$1" | tr -cd '0-9'; }
firstnum(){ printf "%s" "$1" | awk 'match($0,/[-+]?[0-9]+(\.[0-9]+)?/){print substr($0,RSTART,RLENGTH)}'; }
csq_to_rssi(){ 
  [ -n "${1:-}" ] || return 1
  c=$(printf "%s" "$1" | awk '{print int($1)}')
  [ "$c" -lt 0 ] && c=0
  [ "$c" -gt 31 ] && c=31
  awk -v c="$c" 'BEGIN{printf "%.0f", 2*c - 113}'
}
json_s(){ # safe string -> JSON string
  printf "%s" "$1" | python3 - <<'PY' 2>/dev/null || { printf '"%s"' "$(printf "%s" "$1" | sed 's/"/\\"/g')"; exit 0; }
import sys, json
print(json.dumps(sys.stdin.read()))
PY
}
num_or_null(){
  v="${1:-}"
  if [ -n "$v" ]; then printf "%s" "$v"; else printf "null"; fi
}

# Vars we actually need (schema required)
IMEI=""; OPERATOR_NAME=""; OPERATOR_CODE=""
CONNECTION_STATUS="disconnected"; POWER_STATUS="off"
MANUFACTURER=""; MODEL=""

# For signal block
RSSI=""; RSRP=""; RSRQ=""; SNR=""; SINR=""; CSQ=""; NETTYPE=""
MODULE_VERSION=""; IMSI=""

# ----------------------------
# Improved parsing + normalization
# ----------------------------
while IFS= read -r line || [ -n "$line" ]; do
  case "$line" in ''|'#'*) continue;; esac

  # normalize key: lowercase, trim, collapse spaces -> underscore
  key_raw=$(printf "%s" "$line" | awk -F':' '{print $1}')
  key=$(printf "%s" "$key_raw" | tr '[:upper:]' '[:lower:]' | awk '{$1=$1;print}' | sed -E 's/[[:space:]]+/_/g')

  # value = everything after first colon, left-trimmed
  val=$(printf "%s" "$line" | cut -d':' -f2- | sed 's/^[[:space:]]*//')

  case "$key" in
    imei) IMEI="$(digits "$val" | cut -c1-17)";;
    operator|operator_name) OPERATOR_NAME="$val";;
    imsi|sim_imsi) IMSI="$(digits "$val")";;
    network_type|nettype) NETTYPE="$val";;
    up_time|uptime) [ -n "$val" ] && POWER_STATUS="on";;
    module_version) MODULE_VERSION="$val";;
    module_model) MODEL="$val";;
    rssi) RSSI="$(firstnum "$val")";;
    csq|signal) CSQ="$(firstnum "$val")";;   # map "Signal:" -> CSQ
    rsrp) RSRP="$(firstnum "$val")";;
    rsrq) RSRQ="$(firstnum "$val")";;
    snr) SNR="$(firstnum "$val")";;
    sinr) SINR="$(firstnum "$val")";;
    *) ;; # ignore other keys for now
  esac
done < "$infile"

# ----------------------------
# Small post-processing / derived fields
# ----------------------------

# If MODULE_VERSION exists but MODEL is empty, try to pull manufacturer/model from it
if [ -n "$MODULE_VERSION" ] && [ -z "$MODEL" ]; then
  # same heuristic as before: first token manufacturer, then look for token that mixes letters+digits
  set -- $MODULE_VERSION
  MANUFACTURER="${1:-}"
  shift || true
  while [ $# -gt 0 ]; do
    tok="$1"; shift || true
    printf "%s" "$tok" | grep -Eq '([A-Za-z].*[0-9]|[0-9].*[A-Za-z]|-)' && { MODEL="$tok"; break; }
  done
fi

# If MODULE_MODEL provided set MODEL (prefer explicit model)
[ -n "$MODEL" ] && MODEL="$MODEL" || MODEL="$MODEL"

# RSSI from CSQ if not present
[ -z "$RSSI" ] && [ -n "$CSQ" ] && RSSI="$(csq_to_rssi "$CSQ" || true)"

# Map SINR -> SNR if SNR missing
[ -z "$SNR" ] && [ -n "$SINR" ] && SNR="$SINR"

# Derive operator_code from IMSI (MCC+first2 of MNC = 5 digits)
if [ -n "$IMSI" ]; then
  OPERATOR_CODE=$(printf "%s" "$IMSI" | cut -c1-5)
else
  OPERATOR_CODE=""
fi

# Connection status heuristic (use normalized NETTYPE)
nt_up=$(printf "%s" "$NETTYPE" | tr '[:lower:]' '[:upper:]' | awk '{$1=$1;print}')
if [ -n "$nt_up" ] && [ "$nt_up" != "NONE" ] && [ "$nt_up" != "NO SERVICE" ]; then
  CONNECTION_STATUS="connected"
else
  CONNECTION_STATUS="disconnected"
fi

# Decide 5G vs LTE
is_5g=false
case "$nt_up" in
  *NR*|*5G*) is_5g=true ;;
esac


# Start writing minimal JSON
{
  echo "{"
  echo "  \"mobile\": {"
  echo "    \"imei\": \"${IMEI}\","
  echo "    \"operator_code\": \"${OPERATOR_CODE}\","
  echo "    \"operator_name\": $(json_s "$OPERATOR_NAME"),"
  echo "    \"connection_status\": \"${CONNECTION_STATUS}\","
  echo "    \"power_status\": \"${POWER_STATUS}\","
  echo "    \"manufacturer\": $(json_s "$MANUFACTURER"),"
  echo "    \"model\": $(json_s "$MODEL")"

  # Prefer 5G if NETTYPE suggests it and the required 3 fields are present
  if $is_5g && [ -n "$RSRP" ] && [ -n "$RSRQ" ] && [ -n "$SNR" ]; then
    echo "    ,\"signal\": {"
    echo "      \"5g\": {"
    echo "        \"csq\": $(num_or_null "$CSQ"),"
    echo "        \"rsrp\": $(num_or_null "$RSRP"),"
    echo "        \"rsrq\": $(num_or_null "$RSRQ"),"
    echo "        \"snr\":  $(num_or_null "$SNR")"
    echo "      }"
    echo "    }"
  # Else fall back to LTE if all 4 required are present
  elif [ -n "$RSSI" ] && [ -n "$RSRP" ] && [ -n "$RSRQ" ] && [ -n "$SNR" ]; then
    echo "    ,\"signal\": {"
    echo "      \"lte\": {"
    echo "        \"csq\": $(num_or_null "$CSQ"),"
    echo "        \"rssi\": $(num_or_null "$RSSI"),"
    echo "        \"rsrp\": $(num_or_null "$RSRP"),"
    echo "        \"rsrq\": $(num_or_null "$RSRQ"),"
    echo "        \"snr\":  $(num_or_null "$SNR")"
    echo "      }"
    echo "    }"
  fi

  echo "  }"
  echo "}"
} > "$outfile"

echo "Wrote minimal NetJSON to: $outfile"



