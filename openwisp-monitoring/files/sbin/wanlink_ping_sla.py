#!/usr/bin/env python3
import subprocess
import time
import json
import os
import sys
import re
import csv
import signal
import socket
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ==========================
# CONFIGURATION
# ==========================

INTERVAL_SECONDS = 60          # measurement period (1 min)
SAMPLES_PER_SEND = 1           # send every 3 samples (3 min)
PING_COUNT = 10                # number of ping packets per run
PING_INTERVAL = 0.2            # interval between ping packets (sec)
PING_TIMEOUT = 2               # max wait per packet reply (sec) — covers satellite links
SUBPROCESS_TIMEOUT = 15        # hard kill if ping hangs beyond this (sec)
TCP_CHECK_TIMEOUT = 3          # TCP connect fallback timeout (sec)
INTERVAL = 60

# Internet targets (tried in order, stop on first success)
INTERNET_TARGETS = ["8.8.8.8", "1.1.1.1"]
TCP_FALLBACK = ("8.8.8.8", 53)  # DNS port — almost never blocked

# Storage: prefer /mnt/storage (disk, no flash wear), fall back to /tmp (RAM)
if os.path.ismount("/mnt/storage"):
    CSV_DIR = "/mnt/storage/sla"
else:
    CSV_DIR = "/tmp/sla"

STATE_DIR = CSV_DIR

# Graceful shutdown flag
running = True

def handle_signal(signum, frame):
    global running
    running = False

signal.signal(signal.SIGTERM, handle_signal)
signal.signal(signal.SIGINT, handle_signal)

# ==========================
# HELPER FUNCTIONS
# ==========================

def run_cmd(cmd, timeout=None):
    if timeout is None:
        timeout = SUBPROCESS_TIMEOUT
    try:
        proc = subprocess.Popen(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        out, err = proc.communicate(timeout=timeout)
        return out.strip(), err.strip(), proc.returncode
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        return "", "timeout", 1
    except Exception as e:
        return "", str(e), 1


def get_eth_interfaces():
    """
    Discover eth* interfaces from UCI (NOT IP-dependent).
    Returns list of device names: ['eth0', 'eth1', ...]
    """
    device_name = []

    out, err, rc = run_cmd("uci show network | grep '=interface'")
    if rc != 0:
        print(f"Failed to read UCI network: {err}", file=sys.stderr)
        return device_name

    for line in out.splitlines():
        iface = line.split('.')[1].split('=')[0]

        dev_out, _, _ = run_cmd(f"uci get network.{iface}.device")
        dev = dev_out.strip()

        if not dev.startswith("eth"):
            continue

        if dev not in device_name:
            device_name.append(dev)

    return device_name


def get_iface_ip(iface):
    """Get IPv4 address for an interface."""
    ip_out, _, _ = run_cmd(f"ip -o -4 addr show dev {iface} scope global")
    if ip_out:
        parts = ip_out.split()
        if len(parts) >= 4:
            return parts[3].split("/")[0]
    return None


def get_gateway(iface):
    """Auto-detect gateway IP for an interface from routing table."""
    out, _, _ = run_cmd(f"ip -4 route show dev {iface} default")
    if out:
        parts = out.split()
        if "via" in parts:
            idx = parts.index("via")
            if idx + 1 < len(parts):
                return parts[idx + 1]
    return None


def tcp_check(target, port, timeout=None):
    """TCP connect test — works even when ALL ICMP is blocked."""
    if timeout is None:
        timeout = TCP_CHECK_TIMEOUT
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target, port))
        sock.close()
        return result == 0
    except Exception:
        return False


# ==========================
# PING + SMART STATUS
# ==========================

def ping_target(source_ip, target):
    """Ping target from a specific source IP. Returns metrics dict."""
    result = {
        "latency_ms_min": None,
        "latency_ms_avg": None,
        "latency_ms_max": None,
        "jitter_ms": None,
        "loss_percent": 100.0,
        "status": "down",
    }

    if not source_ip or not target:
        return result

    cmd = f"ping -q -I {source_ip} -c {PING_COUNT} -i {PING_INTERVAL} -W {PING_TIMEOUT} {target}"
    out, err, rc = run_cmd(cmd)

    text = out + "\n" + err

    m_loss = re.search(
        r"(\d+)\s+packets transmitted,\s+(\d+)\s+received.*?(\d+)% packet loss",
        text
    )
    if m_loss:
        rx = int(m_loss.group(2))
        loss = float(m_loss.group(3))
        result["loss_percent"] = loss
        if rx > 0 and loss < 100.0:
            result["status"] = "up"
        else:
            result["status"] = "down"
    else:
        return result

    if result["loss_percent"] == 100.0:
        return result

    m_rtt = re.search(
        r"rtt min/avg/max/(?:mdev|stddev) = ([\d\.]+)/([\d\.]+)/([\d\.]+)/([\d\.]+) ms",
        text
    )
    if m_rtt:
        result["latency_ms_min"] = float(m_rtt.group(1))
        result["latency_ms_avg"] = float(m_rtt.group(2))
        result["latency_ms_max"] = float(m_rtt.group(3))
        result["jitter_ms"] = float(m_rtt.group(4))

    return result


def check_interface(iface):
    """
    Smart SLA check for one interface using fallback chain.
    Stops at first success — no unnecessary checks.

    Chain:
      1. Ping gateway        → proves link health
      2. Ping 8.8.8.8        → proves internet (if gateway ICMP disabled)
      3. Ping 1.1.1.1        → backup internet check
      4. TCP connect 8.8.8.8:53 → last resort (all ICMP blocked)

    Returns: (ip_addr, gateway, link_metrics, internet_metrics)
    """
    ip_addr = get_iface_ip(iface)
    gateway = get_gateway(iface)

    link_result = None
    internet_result = None
    checked_target = None

    # Step 1: Ping gateway (fastest, tests physical link)
    if gateway and ip_addr:
        gw_ping = ping_target(ip_addr, gateway)
        if gw_ping["status"] == "up":
            link_result = gw_ping
            checked_target = gateway

    # Step 2+3: Ping internet targets (only if gateway failed or absent)
    if not link_result and ip_addr:
        for target in INTERNET_TARGETS:
            inet_ping = ping_target(ip_addr, target)
            if inet_ping["status"] == "up":
                link_result = inet_ping      # link proven UP via internet
                internet_result = inet_ping
                checked_target = target
                break

    # Step 4: TCP fallback (only if ALL pings failed)
    if not link_result:
        if tcp_check(TCP_FALLBACK[0], TCP_FALLBACK[1]):
            link_result = {
                "latency_ms_min": None, "latency_ms_avg": None,
                "latency_ms_max": None, "jitter_ms": None,
                "loss_percent": 0.0, "status": "up",
            }
            internet_result = link_result
            checked_target = f"{TCP_FALLBACK[0]}:{TCP_FALLBACK[1]}"

    # Step 5: All failed — link is genuinely down
    if not link_result:
        link_result = {
            "latency_ms_min": None, "latency_ms_avg": None,
            "latency_ms_max": None, "jitter_ms": None,
            "loss_percent": 100.0, "status": "down",
        }
        checked_target = gateway or INTERNET_TARGETS[0]

    # If link came up via gateway, optionally check internet too
    # (only adds one ping when gateway succeeded — lightweight)
    if link_result["status"] == "up" and internet_result is None and ip_addr:
        inet_ping = ping_target(ip_addr, INTERNET_TARGETS[0])
        internet_result = inet_ping

    if internet_result is None:
        internet_result = {
            "latency_ms_avg": None, "loss_percent": 100.0, "status": "down",
        }

    return ip_addr, gateway, checked_target, link_result, internet_result


def check_all_interfaces(interfaces):
    """Check all interfaces in parallel."""
    results = {}

    with ThreadPoolExecutor(max_workers=min(len(interfaces), 10)) as pool:
        futures = {
            pool.submit(check_interface, iface): iface
            for iface in interfaces
        }
        for future in as_completed(futures, timeout=SUBPROCESS_TIMEOUT * 2):
            iface = futures[future]
            try:
                results[iface] = future.result()
            except Exception:
                results[iface] = (None, None, None,
                    {"latency_ms_min": None, "latency_ms_avg": None,
                     "latency_ms_max": None, "jitter_ms": None,
                     "loss_percent": 100.0, "status": "error"},
                    {"latency_ms_avg": None, "loss_percent": 100.0, "status": "error"})

    return results


# ==========================
# STATE FILE (fast boot recovery)
# ==========================

def read_state(iface_name):
    """Read uptime/downtime counters from small state file."""
    state_file = f"{STATE_DIR}/{iface_name}_state.json"
    try:
        with open(state_file) as f:
            state = json.load(f)
        return (
            int(state.get("downtime", 0)),
            int(state.get("uptime", 0)),
            int(state.get("start_time", 0))
        )
    except (FileNotFoundError, json.JSONDecodeError, ValueError):
        return 0, 0, 0


def write_state(iface_name, downtime, uptime, start_time):
    """Write uptime/downtime counters to small state file (~50 bytes)."""
    state_file = f"{STATE_DIR}/{iface_name}_state.json"
    try:
        with open(state_file, "w") as f:
            json.dump({
                "downtime": downtime,
                "uptime": uptime,
                "start_time": start_time
            }, f)
    except Exception as e:
        print(f"Error writing state for {iface_name}: {e}", file=sys.stderr)


# ==========================
# CSV + JSON OUTPUT
# ==========================

def save_json_to_tmp(payload):
    """Save the final 3-minute JSON bundle to /tmp."""
    try:
        path = "/tmp/ping_metrics.json"
        with open(path, "w") as f:
            json.dump(payload, f, indent=2)
    except Exception as e:
        print(f"Error saving JSON: {e}", file=sys.stderr)


def save_data_into_csv(sample, interface_name):
    """Append one row per interface to its CSV file."""
    fieldnames = [
        "timestamp", "interface", "target", "destination",
        "latency_ms", "jitter_ms", "loss_percent", "status",
        "internet_status", "internet_latency_ms", "internet_loss_percent",
        "uptime", "downtime"
    ]

    filename = f"{CSV_DIR}/{interface_name}.csv"
    file_exists = os.path.exists(filename)

    with open(filename, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        if not file_exists:
            writer.writeheader()

        ts = sample["timestamp"]
        for ifname, metrics in sample.get("ifaces", {}).items():
            row = {"timestamp": ts, "interface": ifname}
            row.update(metrics)
            writer.writerow(row)


def maybe_daily_reset(iface_name):
    """At 23:59, delete CSV + state for fresh next day."""
    now = datetime.now()
    if now.hour == 23 and now.minute == 59:
        csv_path = f"{CSV_DIR}/{iface_name}.csv"
        state_path = f"{STATE_DIR}/{iface_name}_state.json"
        if os.path.exists(csv_path):
            os.remove(csv_path)
        if os.path.exists(state_path):
            os.remove(state_path)
        return True
    return False


# ==========================
# MAIN LOOP
# ==========================

def main():
    data_capture_counter = 1

    interfaces = get_eth_interfaces()
    if not interfaces:
        print("No eth* interfaces found.", file=sys.stderr)
        return

    while running:
        try:
            loop_start = time.time()
            timestamp = int(loop_start)

            # Refresh interfaces each loop (in case iface added/removed)
            interfaces = get_eth_interfaces()
            if not interfaces:
                time.sleep(INTERVAL_SECONDS)
                continue

            # Check all WANs in parallel (smart fallback chain per interface)
            check_results = check_all_interfaces(interfaces)

            json_file_sample = []

            for iface in interfaces:
                ip_addr, gateway, checked_target, link_stats, inet_stats = \
                    check_results.get(iface, (None, None, None,
                        {"latency_ms_avg": None, "jitter_ms": None,
                         "loss_percent": 100.0, "status": "error"},
                        {"latency_ms_avg": None, "loss_percent": 100.0, "status": "error"}))

                # Daily reset check
                if maybe_daily_reset(iface):
                    down_time = 0
                    up_time = 0
                    start_time = 0
                else:
                    down_time, up_time, start_time = read_state(iface)

                # Set start_time on first measurement of the day
                if start_time == 0:
                    start_time = timestamp

                # Increment counters based on LINK status (not internet)
                if link_stats["status"] in ("up",):
                    up_time += INTERVAL
                else:
                    down_time += INTERVAL

                # Availability calculation
                total_time = up_time + down_time
                availability_percent = round((up_time / total_time * 100), 2) if total_time > 0 else 0.0

                # Save state
                write_state(iface, down_time, up_time, start_time)

                # Build CSV sample
                sample = {
                    "timestamp": timestamp,
                    "ifaces": {
                        iface: {
                            "target": ip_addr,
                            "destination": checked_target or gateway or INTERNET_TARGETS[0],
                            "latency_ms": link_stats.get("latency_ms_avg"),
                            "jitter_ms": link_stats.get("jitter_ms"),
                            "loss_percent": link_stats["loss_percent"],
                            "status": link_stats["status"],
                            "internet_status": inet_stats.get("status", "unknown"),
                            "internet_latency_ms": inet_stats.get("latency_ms_avg"),
                            "internet_loss_percent": inet_stats.get("loss_percent", 100.0),
                            "uptime": up_time,
                            "downtime": down_time
                        }
                    }
                }
                save_data_into_csv(sample, iface)

                # Build JSON entry for 3-minute bundle
                if datetime.now().minute % SAMPLES_PER_SEND == 0:
                    json_file_sample.append({
                        "device_name": iface,
                        "target": ip_addr,
                        "destination": checked_target or gateway or INTERNET_TARGETS[0],
                        "gateway": gateway,
                        "latency_ms": link_stats.get("latency_ms_avg"),
                        "jitter_ms": link_stats.get("jitter_ms"),
                        "packet_loss": link_stats["loss_percent"],
                        "status": link_stats["status"],
                        "internet_status": inet_stats.get("status", "unknown"),
                        "internet_latency_ms": inet_stats.get("latency_ms_avg"),
                        "internet_loss_percent": inet_stats.get("loss_percent", 100.0),
                        "start time": start_time,
                        "uptime_sec": up_time,
                        "downtime_sec": down_time,
                        "availability_percent": availability_percent
                    })

            # Send 3-minute bundle
            if datetime.now().minute % SAMPLES_PER_SEND == 0:
                save_json_to_tmp(json_file_sample)
                data_capture_counter = 0

            # Sleep until next tick
            elapsed = time.time() - loop_start
            next_tick = (int(time.time()) // INTERVAL_SECONDS + 1) * INTERVAL_SECONDS; sleep_time = next_tick - time.time()
            if sleep_time > 0:
                time.sleep(sleep_time)
            data_capture_counter += 1

        except Exception as e:
            print(f"Error in main loop: {e}", file=sys.stderr)
            time.sleep(5)


if __name__ == "__main__":
    os.makedirs(CSV_DIR, exist_ok=True)
    os.makedirs(STATE_DIR, exist_ok=True)
    main()

