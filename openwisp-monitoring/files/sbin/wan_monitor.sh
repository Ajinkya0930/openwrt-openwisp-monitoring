#!/bin/sh

MON_DIR="/tmp/monitoring_agent/wan_stat"
STATUS_FILE="$MON_DIR/wan_status.json"
CURRENT_STATUS="$MON_DIR/wan_status.current"
LOG_TAG="wan_status_Script"
MAX_RETRIES=3

# Ensure monitoring directory exists
[ ! -d "$MON_DIR" ] && mkdir -p "$MON_DIR"

# JSON validation helper
check_json() {
    echo "$1" | jq empty 2>/dev/null
    return $?
}

IP=$(uci get openwisp.http.url 2>/dev/null)
UUID=$(uci get openwisp.http.uuid 2>/dev/null)
KEY=$(uci get openwisp.http.key 2>/dev/null)
VERBOSE_MODE=$(uci get openwisp-monitoring.monitoring.verbose_mode 2>/dev/null)
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

if [ -z "$IP" ] || [ -z "$UUID" ] || [ -z "$KEY" ]; then
    [ "$VERBOSE_MODE" = "1" ] && logger -t "$LOG_TAG" "Missing OpenWISP configuration!"
    exit 1
else
    URL="$IP/api/v1/monitoring/device/$UUID/wan_status/?key=$KEY&time=$TIMESTAMP"
fi

# Build current JSON (as string for validation)
current_json='{"wan_status":['
first=1
for iface in $(uci show network | grep "=interface" | cut -d'.' -f2 | cut -d'=' -f1); do
    [ "$iface" = "lan" ] && continue
    [ "$iface" = "loopback" ] && continue
    status_json=$(ifstatus $iface)
    dev=$(echo "$status_json" | jsonfilter -e '@["l3_device"]')
    [ -z "$dev" ] && dev=$(echo "$status_json" | jsonfilter -e '@["device"]')
    case "$dev" in
        eth*) ;;
        *) continue ;;
    esac
    up=$(echo "$status_json" | jsonfilter -e '@["up"]')
    pending=$(echo "$status_json" | jsonfilter -e '@["pending"]')
    if [ "$up" = "true" ]; then
        state="CONNECTED"
    elif [ "$pending" = "true" ]; then
        state="CONNECTING"
    else
        state="DISCONNECTED"
    fi
    [ $first -eq 0 ] && current_json="${current_json},"
    first=0
    current_json="${current_json}{\"iface\":\"$iface\",\"device\":\"$dev\",\"status\":\"$state\"}"
done
current_json="${current_json}]}"

# Validate JSON
check_json "$current_json" || {
    [ "$VERBOSE_MODE" = "1" ] && logger -t "$LOG_TAG" "Generated WAN status JSON is invalid."
    exit 1
}

# Write temp .current file for comparison and possible retry
echo -n "$current_json" > "$CURRENT_STATUS"

if ! cmp -s "$CURRENT_STATUS" "$STATUS_FILE"; then
    echo "[$(date)] WAN status changed:"
    cat "$CURRENT_STATUS"
    cp "$CURRENT_STATUS" "$STATUS_FILE"

    # POST to controller with retries
    retry=0
    success=0
    while [ "$retry" -lt "$MAX_RETRIES" ]; do
        # http_code=$(curl -k -s -o /dev/null -w "%{http_code}" --max-time 15 \
        #     -H "Content-Type: application/json" -X POST "$URL" --data-binary "@$CURRENT_STATUS") || {
        #         [ "$VERBOSE_MODE" = "1" ] && logger -t "$LOG_TAG" "Curl request failed on attempt $((retry+1))"
        #         http_code=0
        #     }

        http_code=$(curl -k -s -o /dev/null -w "%{http_code}" \
            --connect-timeout 5 --max-time 10 \
            -H "Content-Type: application/json" \
            -X POST "$URL" --data-binary "@$CURRENT_STATUS") || http_code=0

        if [ "$http_code" -eq 200 ]; then
            [ "$VERBOSE_MODE" = "1" ] && logger -t "$LOG_TAG" "Response Code:- $http_code, wan status data successfully sent to controller (attempt $((retry+1)))"
            success=1
            break
        else
            [ "$VERBOSE_MODE" = "1" ] && logger -t "$LOG_TAG" "Response Code:- $http_code, wan status send failed (attempt $((retry+1)))"
            sleep 2
        fi
        retry=$((retry+1))
    done
    if [ "$success" -ne 1 ]; then
        [ "$VERBOSE_MODE" = "1" ] && logger -t "$LOG_TAG" "All retries failed, WAN status data saved in $STATUS_FILE for later troubleshooting."
    fi
else
    [ "$VERBOSE_MODE" = "1" ] && logger -t "$LOG_TAG" "No WAN status change; not sending."
fi

rm -f "$CURRENT_STATUS"

