#!/usr/bin/env python3
"""
neteventd — Network Event Daemon for OpenWisp Monitoring

Purpose:
  Monitors real-time network and config changes on the router and triggers
  an immediate device-statistics upload to the OpenWisp controller,
  instead of waiting for the default 5-minute polling interval.

Architecture:
  4 collector threads → shared event queue → 1 sender thread

  Collectors:
    - FIFO reader   : hotplug interface up/down events
    - ip monitor    : kernel link state, route, address changes
    - ubus listen   : netifd interface/device events
    - config watcher: polls UCI config files for mtime changes

  Sender:
    - Batches events with a quiet period (related events arrive together)
    - Enforces minimum interval between uploads
    - Runs netjson-monitoring to collect device stats
    - Writes gzipped snapshot for openwisp-monitoring to upload
    - Signals openwisp-monitoring send process via SIGUSR1

  Protections:
    - Dedup: same source+key in same state → event dropped
    - Config cooldown: same file modified repeatedly → one event per cooldown
    - Min flush interval: hard cap on upload frequency
    - SIGUSR1 rate limit: hard cap on send signals
    - Queue cap: bounded memory usage
    - xfrmi-test filter: transient IPsec probe interfaces ignored
"""

import os
import time
import threading
import subprocess
import json
import socket
import signal
import logging
import logging.handlers

# ======================== CONFIGURATION ========================

FIFO = "/tmp/netevents.fifo"
NETJSON_DIR = "/tmp/openwisp/monitoring"

# Debug flags
DEBUG_UBUS_RAW = False
DEBUG_IPMON_RAW = False
DEBUG_FIFO_RAW  = False
DEBUG_EVENTS    = True

# --- Batching ---
# When a real change happens (e.g. cable pull), link-down + route-remove +
# interface-down all fire within 2-3 seconds. The quiet period batches
# these related events so one upload captures the full picture.
QUIET_SECONDS = 10

# If events never stop arriving, flush after this many seconds regardless.
MAX_FLUSH_SECONDS = 60

# Hard minimum between two uploads. Prevents flooding even under event storms.
# A real change reaches the controller within this interval.
MIN_FLUSH_INTERVAL = 60

# Hard minimum between two SIGUSR1 signals to the openwisp-monitoring sender.
SIGUSR1_MIN_INTERVAL = 60

# --- Config watcher ---
# Same config file modified repeatedly: emit at most one event per cooldown.
# Prevents repeated events when a service (e.g. bonding) writes config in a loop.
CONFIG_COOLDOWN = 60
CONFIG_POLL_INTERVAL = 5

# --- Queue safety ---
MAX_QUEUE_SIZE = 500

# --- Config files to watch ---
WATCH_FILES = {
    # Network
    "/etc/config/network":        "NETWORK",
    "/etc/config/dhcp":           "NETWORK",
    "/etc/config/mwan3":          "NETWORK",
    "/etc/config/ns-failover":    "NETWORK",
    "/etc/config/lldpd":          "NETWORK",
    "/etc/config/igmpproxy":      "NETWORK",
    "/etc/config/ddns":           "NETWORK",
    "/etc/config/jool":           "NETWORK",
    # Routing
    "/etc/config/frr":            "ROUTING",
    "/etc/config/pbr":            "ROUTING",
    "/etc/config/vrf":            "ROUTING",
    "/etc/config/ptl_route":      "ROUTING",
    # SD-WAN
    "/etc/config/ns-bonding":     "SDWAN",
    "/etc/config/nsbond":         "SDWAN",
    # Firewall
    "/etc/config/firewall":       "FIREWALL",
    # Security
    "/etc/config/banip":          "SECURITY",
    "/etc/config/adblock":        "SECURITY",
    "/etc/config/dpi":            "SECURITY",
    "/etc/config/dpi_rule":       "SECURITY",
    "/etc/config/snort":          "SECURITY",
    "/etc/config/clamav":         "SECURITY",
    "/etc/config/squid":          "SECURITY",
    "/etc/config/ns-webfilter":   "SECURITY",
    "/etc/config/dnsdist":        "DNS",
    # VPN
    "/etc/config/openvpn":        "VPN",
    "/etc/config/ipsec":          "VPN",
    "/etc/config/ipsecrw":        "VPN",
    "/etc/config/wgrw":           "VPN",
    "/etc/config/l2tp_server":    "VPN",
    "/etc/config/zerotier":       "VPN",
    "/etc/config/eoip":           "VPN",
    "/etc/config/vxlan":          "VPN",
    # QoS
    "/etc/config/qos":            "QOS",
    "/etc/config/qosify":         "QOS",
    "/etc/config/sqm":            "QOS",
    "/etc/config/trafficshaper":  "QOS",
    # HA
    "/etc/config/keepalived":     "HA",
    "/etc/config/vrrp":           "HA",
    # Monitoring / System
    "/etc/config/snmpd":          "SYSTEM",
}

# ======================== STATE ========================

LAST_EVENT_TS   = 0.0
LAST_FLUSH_TS   = 0.0
BATCH_START_TS  = 0.0
LAST_SIGUSR1_TS = 0.0

EVENT_QUEUE = []
QUEUE_LOCK  = threading.Lock()
HOSTNAME    = socket.gethostname()

# Dedup: last known state per source key
_last_ipmon_state      = {}   # dev -> event_name
_last_ubus_iface_state = {}   # iface -> event_name
_last_ubus_dev_state   = {}   # dev -> event_name
_last_iface_state      = {}   # (iface, dev) -> action  [FIFO]

# Config cooldown: path -> last event timestamp
_config_last_event_ts = {}

# ======================== LOGGING ========================

logger = logging.getLogger("neteventd")
logger.setLevel(logging.INFO)

try:
    _syslog = logging.handlers.SysLogHandler(address="/dev/log")
    _syslog.setFormatter(logging.Formatter("neteventd: %(levelname)s: %(message)s"))
    logger.addHandler(_syslog)
except Exception:
    _stderr = logging.StreamHandler()
    _stderr.setFormatter(logging.Formatter("neteventd: %(levelname)s: %(message)s"))
    logger.addHandler(_stderr)

# ======================== EVENT QUEUE ========================

def add_event(ev: dict):
    global LAST_EVENT_TS, BATCH_START_TS

    now = time.time()
    ev.setdefault("timestamp", int(now))

    with QUEUE_LOCK:
        if len(EVENT_QUEUE) >= MAX_QUEUE_SIZE:
            EVENT_QUEUE.pop(0)
        if not EVENT_QUEUE:
            BATCH_START_TS = now
        EVENT_QUEUE.append(ev)
        LAST_EVENT_TS = now

    if DEBUG_EVENTS:
        etype = ev.get("event") or ev.get("type")
        logger.info("[EVENT] src=%s type=%s iface=%s dev=%s",
                     ev.get("source"), etype, ev.get("iface"), ev.get("dev"))

# ======================== SENDER ========================

def trigger_openwisp_send():
    global LAST_SIGUSR1_TS

    now = time.time()
    elapsed = now - LAST_SIGUSR1_TS
    if elapsed < SIGUSR1_MIN_INTERVAL:
        logger.info("[SENDER] skipping SIGUSR1, last signal was %ds ago (min %ds)",
                     int(elapsed), SIGUSR1_MIN_INTERVAL)
        return

    try:
        out = subprocess.check_output(
            ["pgrep", "-f", "openwisp-monitoring.*--mode send"],
            text=True,
        )
        pid = int(out.strip().splitlines()[0])
        os.kill(pid, signal.SIGUSR1)
        LAST_SIGUSR1_TS = now
        logger.info("[SENDER] signalled openwisp-monitoring send pid=%d", pid)
    except subprocess.CalledProcessError:
        logger.warning("[SENDER] openwisp-monitoring --mode send not running")
    except Exception as e:
        logger.exception("[SENDER] error signalling openwisp-monitoring: %s", e)


def _restore_batch(batch):
    """On failure, put events back into queue (bounded)."""
    with QUEUE_LOCK:
        batch.extend(EVENT_QUEUE)
        EVENT_QUEUE[:] = batch[-MAX_QUEUE_SIZE:]


def netjson_sender():
    global EVENT_QUEUE, LAST_FLUSH_TS

    while True:
        time.sleep(1)
        # Wall-clock alignment: only consider flushing at :00 second boundaries
        if int(time.time()) % MIN_FLUSH_INTERVAL != 0:
            continue

        with QUEUE_LOCK:
            if not EVENT_QUEUE:
                continue

            now = time.time()

            # Hard minimum between flushes
            if now - LAST_FLUSH_TS < MIN_FLUSH_INTERVAL:
                continue

            # Batch: wait for quiet period or max age
            if (now - LAST_EVENT_TS < QUIET_SECONDS and
                    now - BATCH_START_TS < MAX_FLUSH_SECONDS):
                continue

            # Lock flush time before releasing lock (prevents re-entry)
            LAST_FLUSH_TS = now
            batch = EVENT_QUEUE
            EVENT_QUEUE = []

        # --- Outside lock: run netjson-monitoring and upload ---
        try:
            logger.info("[SENDER] flushing %d events, running netjson-monitoring...",
                         len(batch))

            result = subprocess.run(
                ["/usr/sbin/netjson-monitoring", "--dump", "*"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            if result.returncode != 0:
                logger.error("[SENDER] netjson-monitoring failed (rc=%d): %s",
                             result.returncode, result.stderr.strip())
                _restore_batch(batch)
                continue

            data = result.stdout.strip()
            if not data:
                logger.error("[SENDER] netjson-monitoring returned empty output")
                _restore_batch(batch)
                continue

            try:
                json.loads(data)
            except Exception as je:
                logger.error("[SENDER] invalid JSON: %s", je)
                _restore_batch(batch)
                continue

            # Write snapshot
            os.makedirs(NETJSON_DIR, exist_ok=True)
            filename = time.strftime("%d-%m-%Y_%H:%M:%S", time.gmtime())
            path = os.path.join(NETJSON_DIR, filename)

            with open(path, "w") as f:
                f.write(data)

            try:
                subprocess.run(["gzip", path], check=False)
                logger.info("[SENDER] wrote snapshot %s.gz", path)
            except Exception as gz_e:
                logger.warning("[SENDER] gzip failed: %s", gz_e)
                logger.info("[SENDER] wrote snapshot %s (uncompressed)", path)

            # Signal openwisp-monitoring to send
            trigger_openwisp_send()

        except Exception as e:
            logger.exception("[SENDER] flush error: %s", e)
            _restore_batch(batch)

# ======================== PARSERS ========================

def process_fifo_line(line: str):
    """Parse hotplug FIFO lines. Dedup by (iface, dev) → action."""
    line = line.strip()
    if not line:
        return

    if not line.startswith("[IFACE]"):
        if DEBUG_FIFO_RAW:
            logger.debug("[FIFO-RAW] %s", line)
        return

    fields = {}
    for tok in line.split()[1:]:
        if "=" in tok:
            k, v = tok.split("=", 1)
            fields[k] = v

    action = fields.get("ACTION")
    iface = fields.get("INTERFACE")
    dev = fields.get("DEVICE")

    if not action or not iface:
        return

    # Dedup
    key = (iface, dev or "")
    if _last_iface_state.get(key) == action:
        return
    _last_iface_state[key] = action

    add_event({
        "source": "IFACE", "category": "interface",
        "event": action, "iface": iface, "dev": dev,
    })


def process_ubus_line(line: str):
    """Parse ubus JSON events. Dedup by iface/dev → state."""
    try:
        data = json.loads(line)
    except Exception:
        if DEBUG_UBUS_RAW:
            logger.debug("[UBUS-RAW] %s", line)
        return

    if "network.interface" in data:
        d = data["network.interface"]
        action = d.get("action")
        iface = d.get("interface") or d.get("name")
        if action and iface:
            event_name = f"interface-{action}"
            if _last_ubus_iface_state.get(iface) == event_name:
                return
            _last_ubus_iface_state[iface] = event_name
            add_event({
                "source": "UBUS", "category": "interface",
                "event": event_name, "iface": iface,
            })
        return

    if "network.device" in data:
        d = data["network.device"]
        action = d.get("action")
        dev = d.get("name") or d.get("device")
        if action and dev:
            event_name = f"device-{action}"
            if _last_ubus_dev_state.get(dev) == event_name:
                return
            _last_ubus_dev_state[dev] = event_name
            add_event({
                "source": "UBUS", "category": "device",
                "event": event_name, "dev": dev,
            })
        return


def process_ipmon_line(line: str):
    """Parse 'ip monitor' output. Dedup by dev → state."""
    if DEBUG_IPMON_RAW:
        logger.debug("[IPMON-RAW] %s", line)

    # Default route add/remove
    if "default via " in line:
        removed = line.startswith("Deleted ")
        text = line[len("Deleted "):] if removed else line
        tokens = text.split()
        gw = dev = None
        try:
            gw = tokens[tokens.index("via") + 1]
        except (ValueError, IndexError):
            pass
        try:
            dev = tokens[tokens.index("dev") + 1]
        except (ValueError, IndexError):
            pass

        if gw and dev:
            event_name = "default-route-removed" if removed else "default-route-added"
            key = f"route-{dev}"
            if _last_ipmon_state.get(key) == event_name:
                return
            _last_ipmon_state[key] = event_name
            add_event({
                "source": "IPMON", "category": "route",
                "event": event_name, "gateway": gw, "dev": dev,
            })
        return

    # Link state change
    if " state " in line and ":" in line:
        parts = line.split(":", 2)
        if len(parts) >= 3:
            dev = parts[1].strip()

            # Skip transient xfrmi-test interfaces (short-lived IPsec probes)
            if dev.startswith("xfrmi-test-"):
                return

            event_name = None
            if " state DOWN" in line:
                event_name = "link-down"
            elif " state UP" in line:
                event_name = "link-up"

            if event_name:
                if _last_ipmon_state.get(dev) == event_name:
                    return
                _last_ipmon_state[dev] = event_name
                add_event({
                    "source": "IPMON", "category": "link",
                    "event": event_name, "dev": dev,
                })
                return

# ======================== READERS ========================

def ensure_fifo():
    if not os.path.exists(FIFO):
        logger.info("[CORE] FIFO missing, creating %s", FIFO)
        os.mkfifo(FIFO)


def reader_fifo():
    ensure_fifo()
    logger.info("[CORE] FIFO reader started")
    while True:
        try:
            with open(FIFO, "r") as f:
                for line in f:
                    process_fifo_line(line)
        except Exception as e:
            logger.exception("[CORE] FIFO reader error, reopening: %s", e)
            time.sleep(1)


def reader_cmd(name, cmd):
    while True:
        try:
            logger.info("[CORE] starting %s: %s", name, " ".join(cmd))
            p = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1,
            )
            for line in p.stdout:
                line = line.strip()
                if not line:
                    continue
                if name == "UBUS":
                    process_ubus_line(line)
                elif name == "IPMON":
                    process_ipmon_line(line)
            rc = p.wait()
            logger.warning("[CORE] %s exited (rc=%d), restarting in 1s", name, rc)
        except Exception as e:
            logger.exception("[CORE] %s crashed: %s", name, e)
        time.sleep(1)


def watcher_configs():
    """Poll config files for mtime changes. Per-file cooldown prevents storms."""
    logger.info("[CORE] config watcher started")
    last_mtime = {}
    for p in WATCH_FILES:
        try:
            last_mtime[p] = os.stat(p).st_mtime
        except FileNotFoundError:
            last_mtime[p] = None

    while True:
        time.sleep(CONFIG_POLL_INTERVAL)
        for path, component in WATCH_FILES.items():
            try:
                cur = os.stat(path).st_mtime
            except FileNotFoundError:
                cur = None

            if cur == last_mtime.get(path):
                continue

            last_mtime[path] = cur
            now = time.time()

            # Per-file cooldown
            if now - _config_last_event_ts.get(path, 0) < CONFIG_COOLDOWN:
                continue
            _config_last_event_ts[path] = now

            if cur is None:
                ev_type = "config-deleted"
            elif last_mtime.get(path) is None:
                ev_type = "config-created"
            else:
                ev_type = "config-modified"

            add_event({
                "source": "CONFIG", "category": "config",
                "event": ev_type, "component": component,
                "file": path, "timestamp": int(now),
            })

# ======================== MAIN ========================

def main():
    logger.info("=== neteventd v2.0: starting monitors + sender ===")

    threads = [
        threading.Thread(target=reader_fifo, daemon=True),
        threading.Thread(target=reader_cmd,
                         args=("IPMON", ["ip", "monitor", "link", "addr", "route"]),
                         daemon=True),
        threading.Thread(target=reader_cmd,
                         args=("UBUS", ["ubus", "listen",
                               "network.interface", "network.device"]),
                         daemon=True),
        threading.Thread(target=watcher_configs, daemon=True),
        threading.Thread(target=netjson_sender, daemon=True),
    ]
    for t in threads:
        t.start()

    while True:
        time.sleep(60)


if __name__ == "__main__":
    main()

