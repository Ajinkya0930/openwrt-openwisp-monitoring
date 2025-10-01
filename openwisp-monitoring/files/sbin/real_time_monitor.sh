#!/bin/sh

# This is a common script to read data and send through the API with retry, memory check, gzip compression,
# pruning of files older than 12 hours during offline/unregistered mode,and throttled sending to avoid overload.

#Explanation of new additions:
#1. offline_mode flag file at $FILE_DIR/.offline_mode signals offline/unregistered state.
#2. When offline mode active, files older than 12 hours get pruned on each save.
#3. On HTTP 404 response during send (device unregister), offline mode flag is set and affected file discarded to prevent infinite retries.
#4. On successful send, offline mode flag is removed.
#5. Added throttle pause after every 10 files successfully sent to reduce load.

FILE_DIR="/tmp/monitoring_agent/realtime_monitor"
FILE="common_data"
LOG_TAG="common_data_send"
MAX_RETRIES=5
REQUIRED_PERCENT=0.1
PRUNE_HOURS=12
THROTTLE_BATCH=10
THROTTLE_PAUSE=5

OFFLINE_FLAG="$FILE_DIR/.offline_mode"

#this is dpi client summary data file which is saved data from another script which is collect_dpi_client_data.sh
dpi_summary_client="/tmp/monitoring_agent/realtime_monitor/dpi_summary_by_client.json"

IP=$(uci get openwisp.http.url 2>/dev/null)
UUID=$(uci get openwisp.http.uuid 2>/dev/null)
KEY=$(uci get openwisp.http.key 2>/dev/null)
VERBOSE_MODE=$(uci get openwisp-monitoring.monitoring.verbose_mode 2>/dev/null)
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
FILENAME="${FILE_DIR}/${FILE}_${TIMESTAMP}.json"

if [ -z "$IP" ] || [ -z "$UUID" ] || [ -z "$KEY" ]; then
  logger -t "$LOG_TAG" "Missing OpenWISP configuration!"
  exit 1
else
  URL="$IP/api/v1/monitoring/device/$UUID/real_time_monitor_data/?key=$KEY&time=$TIMESTAMP"
fi

mkdir -p "$FILE_DIR"

check_available_memory() {
  total=$(ubus call system info | jsonfilter -e '@.memory.total')
  available=$(ubus call system info | jsonfilter -e '@.memory.available')
  required=$(echo "$total $REQUIRED_PERCENT" | awk '{printf("%.f",$1*$2)}')

  if [ "$available" -ge "$required" ]; then
    return 0
  else
    file=$(ls -1t "$FILE_DIR"/*.json.gz 2>/dev/null | tail -1)
    if [ -n "$file" ] && [ -f "$file" ]; then
      rm -f "$file"
      [ "$VERBOSE_MODE" -eq 1 ] && logger -t "$LOG_TAG" "Deleted oldest compressed file to free memory: $(basename "$file")"
      return 0
    else
      [ "$VERBOSE_MODE" -eq 1 ] && logger -t "$LOG_TAG" "Insufficient memory and no compressed files to delete"
      return 1
    fi
  fi
}

check_json() {
  echo "$1" | jq empty 2>/dev/null
  return $?
}

prune_old_files() {
  find "$FILE_DIR" -maxdepth 1 -name '*.json.gz' -type f -mmin +$((PRUNE_HOURS * 60)) -exec rm -f {} \;
  [ "$VERBOSE_MODE" -eq 1 ] && logger -t "$LOG_TAG" "Pruned files older than $PRUNE_HOURS hours"
}

collect_data() {
  dpi_sumV2=$(ubus call ns.dpireport summary-v2 2>/dev/null) || dpi_sumV2="{}"
  check_json "$dpi_sumV2" || dpi_sumV2="{}"

  if /usr/bin/python3 /usr/sbin/collect_dpi_client_data.py >/dev/null 2>&1; then
    if [ -f "$dpi_summary_client" ]; then
      dpi_client_data=$(cat "$dpi_summary_client")
      rm -f "$dpi_summary_client"
      check_json "$dpi_client_data" || dpi_client_data="{}"
    else
      logger -t "$LOG_TAG" "dpi_summary_by_client.json not found"
      dpi_client_data="{}"
    fi
  else
    logger -t "$LOG_TAG" "Failed to run collect_dpi_client_data.py"
    dpi_client_data="{}"
  fi

  malware_report=$(ubus call ns.report tsip-malware-report 2>/dev/null) || malware_report="{}"
  check_json "$malware_report" || malware_report="{}"

  attack_report=$(ubus call ns.report tsip-attack-report 2>/dev/null) || attack_report="{}"
  check_json "$attack_report" || attack_report="{}"

  real_time_traffic=$(ubus call ns.talkers list 2>/dev/null) || real_time_traffic="{}"
  check_json "$real_time_traffic" || real_time_traffic="{}"

  wan_events=$(ubus call ns.report mwan-report 2>/dev/null | sed 's/^[[:space:]]*//') || wan_events="{}"
  check_json "$wan_events" || wan_events="{}"

  wan_traffic=$(
    {
      echo "{"
      devices=$(ubus call ns.dashboard list-wans | jsonfilter -e '@.result[*].device')
      count=0
      for dev in $devices; do
        if [ $count -ne 0 ]; then
          echo ","
        fi
        echo -n "  \"$dev\":"
        ubus call ns.dashboard interface-traffic "{\"interface\":\"$dev\"}" || echo "{}"
        count=$((count + 1))
      done
      echo
      echo "}"
    }
  )

  check_json "$wan_traffic" || wan_traffic="{}"

  wan_lat_quality=$(ubus call ns.report latency-and-quality-report 2>/dev/null)
  # Fix case: {{ ... }}
  if echo "$wan_lat_quality" | grep -q '^{[[:space:]]*{'; then
      wan_lat_quality=$(echo "$wan_lat_quality" | sed 's/^{[[:space:]]*{//; s/}[[:space:]]*}$/}/')
  fi
  # If empty or "{}", keep as empty object
  if [ -z "$wan_lat_quality" ] || [ "$wan_lat_quality" = "{}" ]; then
      wan_lat_quality="{}"
  fi
  check_json "$wan_lat_quality" || wan_lat_quality="{}"


  cat <<EOF
{
  "traffic": {
    "dpi_summery_v2": $dpi_sumV2,
    "dpi_client_data": $dpi_client_data
  },
  "security": {
    "blocklist": $malware_report,
    "brute_force_attack": $attack_report
  },
  "real_time_traffic": {
    "data": $real_time_traffic
  },
  "wan_uplink": {
    "wan_events": $wan_events,
    "wan_traffic": $wan_traffic,
    "wan_lat_qua": $wan_lat_quality
  }
}
EOF


}

save_data() {
  [ -f "$OFFLINE_FLAG" ] && prune_old_files

  if check_available_memory; then
    data=$(collect_data)
    echo "$data" > "$FILENAME"
    gzip -f "$FILENAME"
    [ "$VERBOSE_MODE" -eq 1 ] && logger -t "$LOG_TAG" "Data saved and compressed to $(basename "$FILENAME.gz")"
    return 0
  else
    logger -t "$LOG_TAG" "Not enough available memory to save data"
    return 1
  fi
}

send_data() {
  success=0
  for file in "$FILE_DIR"/*.json.gz; do
    [ ! -f "$file" ] && {
      [ "$VERBOSE_MODE" -eq 1 ] && logger -t "$LOG_TAG" "No data file found to send."
      return 0
    }
    retries=0
    while [ "$retries" -lt "$MAX_RETRIES" ]; do
      tmpfile="${file%.gz}"
      gzip -dfc "$file" > "$tmpfile"
      if [ ! -f "$tmpfile" ]; then
        logger -t "$LOG_TAG" "Failed to decompress $file; skipping"
        break
      fi

      http_code=$(curl -k -s -o /dev/null -w "%{http_code}" --max-time 15 -H "Content-Type: application/json" -X POST "$URL" --data-binary "@$tmpfile") || {
        logger -t "$LOG_TAG" "Curl request failed for $file"
        rm -f "$tmpfile"
        break
      }
      rm -f "$tmpfile"

      if [ "$http_code" -eq 200 ]; then
        [ -f "$OFFLINE_FLAG" ] && rm -f "$OFFLINE_FLAG"
        [ "$VERBOSE_MODE" -eq 1 ] && logger -t "$LOG_TAG" "Successfully sent $file with response $http_code"
        rm -f "$file"
        success=$((success + 1))
        break
      elif [ "$http_code" -eq 400 ]; then
        logger -t "$LOG_TAG" "Bad request (400) for $file, discarding file"
        rm -f "$file"
        break
      elif [ "$http_code" -eq 404 ]; then
        logger -t "$LOG_TAG" "Device unregistered (404), enabling offline mode and pruning"
        touch "$OFFLINE_FLAG"
        rm -f "$file"
        break
      else
        logger -t "$LOG_TAG" "Failed to send $file, response code $http_code, attempt $((retries + 1))/$MAX_RETRIES"
        retries=$((retries + 1))
        sleep $(( ( RANDOM % 5 ) + 1 ))
      fi
    done

    [ "$retries" -ge "$MAX_RETRIES" ] && logger -t "$LOG_TAG" "Giving up on $file after $MAX_RETRIES retries"

    if [ $((success % THROTTLE_BATCH)) -eq 0 ] && [ "$success" -ne 0 ]; then
      [ "$VERBOSE_MODE" -eq 1 ] && logger -t "$LOG_TAG" "Throttling: sleeping $THROTTLE_PAUSE seconds after $success successful sends"
      sleep "$THROTTLE_PAUSE"
    fi
  done
}

if ! save_data; then
  exit 1
fi

if ! send_data; then
  exit 1
fi

exit 0


