#!/bin/sh
# ping_combined_bytes.sh  -- run once (cron-friendly)
# Usage: /usr/sbin/ping_combined_bytes.sh [DEST] [PING_COUNT] [SAMPLE_SECONDS]
# Example (cron): /usr/sbin/ping_combined_bytes.sh 8.8.8.8 5 5

DEST=${1:-8.8.8.8}
COUNT=${2:-5}
SAMPLE=${3:-5}
OUT=${OUT:-/tmp/ping_results.json}
LOCKDIR=/tmp/ping_combined.lock
TMPPREFIX="/tmp/ping_tmp.$$.$RANDOM"

# try to acquire lock (atomic). If exists, exit.
if ! mkdir "$LOCKDIR" 2>/dev/null; then
  # already running
  exit 0
fi
# ensure lock removal on exit
_cleanup() { rm -rf "$LOCKDIR" 2>/dev/null || true; }
trap _cleanup EXIT INT TERM HUP

# portable temp helper
tmpfile_create() {
  i=0
  while :; do
    t="${TMPPREFIX}.$i"
    if [ ! -e "$t" ]; then
      printf "%s" "$t"
      return 0
    fi
    i=$((i+1))
  done
}

# get rx/tx bytes for interface from /proc/net/dev
get_bytes() {
  iface="$1"
  awk -v IF="$iface" '
    $1 ~ IF":" {
      gsub(/:/,"",$1);
      print $2 " " $10;
      exit
    }
  ' /proc/net/dev 2>/dev/null || echo "0 0"
}

num_or_null(){
  v="${1:-}"
  if [ -n "$v" ]; then printf "%s" "$v"; else printf "null"; fi
}

# single-measure run
measure_once() {
  tmp=$(tmpfile_create) || tmp="/tmp/ping_results.$$.$RANDOM"
  echo "[" > "$tmp"
  first=1

  # iterate IPv4 interfaces (exclude lo and br0)
  ip -o -4 addr show | awk '!/127.0.0.1/ && $2 != "br0" {print $2, $4}' | while read -r iface cidr; do
    [ -z "$cidr" ] && continue
    srcip=${cidr%/*}

    # snapshot before
    b1=$(get_bytes "$iface"); rx1=$(echo "$b1" | awk '{print $1}'); tx1=$(echo "$b1" | awk '{print $2}')

    # create ping output temp file
    pf=$(tmpfile_create) || pf="/tmp/ping_pf.$$.$RANDOM"
    # start ping in background (bind to src ip)
    ping -I "$srcip" -c "$COUNT" "$DEST" >"$pf" 2>&1 &
    pid=$!

    # wait SAMPLE seconds while ping runs (throughput window)
    sleep "$SAMPLE"

    # snapshot after
    b2=$(get_bytes "$iface"); rx2=$(echo "$b2" | awk '{print $1}'); tx2=$(echo "$b2" | awk '{print $2}')

    # wait for ping to finish (if still running)
    wait "$pid" 2>/dev/null || true

    # compute deltas (bytes) and sanitize
    drx=$((rx2 - rx1)); dtx=$((tx2 - tx1))
    [ "$drx" -lt 0 ] && drx=0
    [ "$dtx" -lt 0 ] && dtx=0
    dt=${SAMPLE:-1}; [ "$dt" -le 0 ] && dt=1

    # bytes/sec formatted
    rx_bps=$(awk -v b="$drx" -v s="$dt" 'BEGIN{ printf "%.3f", (b/s) }')
    tx_bps=$(awk -v b="$dtx" -v s="$dt" 'BEGIN{ printf "%.3f", (b/s) }')
    tot_bps=$(awk -v r="$rx_bps" -v t="$tx_bps" 'BEGIN{ printf "%.3f", (r + t) }')

    # parse ping output for loss and rtt
    ping_out=$(cat "$pf" 2>/dev/null || true)
    loss=$(printf "%s" "$ping_out" | grep -oE '[0-9]+% packet loss' | awk '{print $1}')
    [ -z "$loss" ] && loss="100%"

    rtt_line=$(printf "%s" "$ping_out" | grep -E 'rtt|round-trip' || true)
    if [ -n "$rtt_line" ]; then
      vals=$(printf "%s" "$rtt_line" | sed -n 's/.*= //;s/ ms//p')
      avg=$(printf "%s" "$vals" | awk -F'/' '{print $2}')
      mdev=$(printf "%s" "$vals" | awk -F'/' '{print $4}')
      avg_out=$(printf "%.3f" "$avg" 2>/dev/null || printf "%s" "$avg")
      mdev_out=$(printf "%.3f" "$mdev" 2>/dev/null || printf "%s" "$mdev")
    else
      avg_out=null
      mdev_out=null
    fi

    ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    if [ "$first" -eq 0 ]; then
      echo "," >> "$tmp"
    fi
    first=0

    cat >> "$tmp" <<EOF
  {
    "interface": "$iface",
    "src ip": "$srcip",
    "dest ip": "$DEST",
    "timestamp": "$ts",
    "latency_ms": ${avg_out},
    "jitter_ms": ${mdev_out},
    "packet_loss": "$loss",
    "throughput_rx_bytes_per_s": $rx_bps,
    "throughput_tx_bytes_per_s": $tx_bps,
    "throughput_total_bytes_per_s": $tot_bps
  }
EOF

    rm -f "$pf" 2>/dev/null || true
  done

  echo "]" >> "$tmp"
  # atomic move into place
  mv "$tmp" "$OUT" 2>/dev/null || cp -f "$tmp" "$OUT" 2>/dev/null
  chmod 644 "$OUT" 2>/dev/null || true
  rm -f ${TMPPREFIX}* 2>/dev/null || true
}

# run once
measure_once
# lock removed by trap/_cleanup
exit 0


