#!/bin/sh

MON_DIR="/tmp/monitoring_agent/ipsec_stat"
STATUS_FILE="$MON_DIR/ipsec_status.json"
LOG_TAG="ipsec_monitor_Script"
MAX_RETRIES=3

# ============== Main Script ==============
IP=$(uci get openwisp.http.url 2>/dev/null)
UUID=$(uci get openwisp.http.uuid 2>/dev/null)
KEY=$(uci get openwisp.http.key 2>/dev/null)
VERBOSE_MODE=$(uci get openwisp-monitoring.monitoring.verbose_mode 2>/dev/null)
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Ensure monitoring directory exists
[ ! -d "$MON_DIR" ] && mkdir -p "$MON_DIR"

if [ -z "$IP" ] || [ -z "$UUID" ] || [ -z "$KEY" ]; then
    [ "$VERBOSE_MODE" = "1" ] && logger -t "$LOG_TAG" "Missing OpenWISP configuration!"
    exit 1
else
    URL="$IP/api/v1/monitoring/device/$UUID/ipsectunnel_list/?key=$KEY&time=$TIMESTAMP"
fi

# ============== JSON Validation Helper ==============
check_json() {
    echo "$1" | jq empty 2>/dev/null
    return $?
}

# ============== Fetch Tunnel Data ==============
current_json=$(ubus call ns.ipsectunnel list-tunnels 2>/dev/null)
if [ $? -ne 0 ]; then
    [ "$VERBOSE_MODE" = "1" ] && logger -t "$LOG_TAG" "Failed to fetch tunnel status from ubus."
    exit 1
fi

[ -z "$current_json" ] && exit 0
check_json "$current_json" || {
    [ "$VERBOSE_MODE" = "1" ] && logger -t "$LOG_TAG" "Invalid tunnel status JSON."
    exit 1
}

id=$(echo "$current_json" | jsonfilter -e '@.tunnels[0].id' 2>/dev/null)
name=$(echo "$current_json" | jsonfilter -e '@.tunnels[0].name' 2>/dev/null)
enabled=$(echo "$current_json" | jsonfilter -e '@.tunnels[0].enabled' 2>/dev/null)
connected=$(echo "$current_json" | jsonfilter -e '@.tunnels[0].connected' 2>/dev/null)
local=$(echo "$current_json" | jsonfilter -e '@.tunnels[0].local' 2>/dev/null)
remote=$(echo "$current_json" | jsonfilter -e '@.tunnels[0].remote' 2>/dev/null)

[ -z "$id" ] && id="unknown"
[ -z "$name" ] && name="unknown"
[ -z "$enabled" ] && enabled="0"
[ -z "$connected" ] && connected="false"
[ -z "$local" ] && local="[]"
[ -z "$remote" ] && remote="[]"

remote_count=$(echo "$remote" | grep -o "/" | wc -l)
if [ "$remote_count" -gt 0 ]; then
    role="hub"
else
    role="spoke"
fi

new_json=$(cat <<EOF
{
  "tunnels": [
    {
      "id": "$id",
      "name": "$name",
      "enabled": "$enabled",
      "connected": $connected,
      "role": "$role",
      "local": $local,
      "remote": $remote
    }
  ]
}
EOF
)

check_json "$new_json" || {
    [ "$VERBOSE_MODE" = "1" ] && logger -t "$LOG_TAG" "Generated tunnel JSON is invalid."
    exit 1
}

if [ ! -f "$STATUS_FILE" ] || [ "$new_json" != "$(cat "$STATUS_FILE")" ]; then
    echo "$new_json" > "$STATUS_FILE"
    [ "$VERBOSE_MODE" = "1" ] && logger -t "$LOG_TAG" "Updated status written to $STATUS_FILE"

    retry=0
    success=0
    while [ "$retry" -lt "$MAX_RETRIES" ]; do
        http_code=$(curl -k -s -o /dev/null -w "%{http_code}" --max-time 15 \
            -H "Content-Type: application/json" -X POST "$URL" --data-binary "@$STATUS_FILE") || {
                [ "$VERBOSE_MODE" = "1" ] && logger -t "$LOG_TAG" "Curl request failed on attempt $((retry+1))"
                http_code=0
            }

        if [ "$http_code" -eq 200 ]; then
            [ "$VERBOSE_MODE" = "1" ] && logger -t "$LOG_TAG" "Response Code:- $http_code, ipsec_monitor data successfully sent to controller (attempt $((retry+1)))"
            echo "Send data successfully......."
            success=1
            break
        else
            logger -t "$LOG_TAG" "Response Code:- $http_code, send failed (attempt $((retry+1)))"
            [ "$VERBOSE_MODE" = "1" ] && echo "Failed to send data to server......"
            sleep 2
        fi
        retry=$((retry+1))
    done

    if [ "$success" -ne 1 ]; then
        [ "$VERBOSE_MODE" = "1" ] && logger -t "$LOG_TAG" "All retries failed, data saved in $STATUS_FILE for later troubleshooting."
    fi
fi

