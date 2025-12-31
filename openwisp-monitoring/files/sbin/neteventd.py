#!/usr/bin/env python3
import os
import time
import threading
import subprocess
import json
import socket
import signal  # make sure this import is at the top
import logging
import logging.handlers


FIFO = "/tmp/netevents.fifo"

# Debug flags
DEBUG_UBUS_RAW = False
DEBUG_IPMON_RAW = False
DEBUG_FIFO_RAW = False   # show raw FIFO lines (non-IFACE)
DEBUG_EVENTS   = True    # print one line when we add an event

# Where to drop NetJSON so openwisp-monitoring can send it
NETJSON_DIR = "/tmp/openwisp/monitoring"


LAST_EVENT_TS = 0.0          # last time we added an event
LAST_FLUSH_TS = time.time()  # last time we sent
BATCH_START_TS = 0.0         # time when the current batch started


# Batching behaviour
QUIET_SECONDS      = 5    # wait this long with no new events before sending
MAX_FLUSH_SECONDS  = 30   # maximum wait even if events keep coming

# -------- CONFIG FILE MAP --------
WATCH_FILES = {
    # Core network
    "/etc/config/network":        "NETWORK",
    "/etc/config/dhcp":           "NETWORK_DHCP",
    "/etc/config/mwan3":          "NETWORK_MWAN",
    "/etc/config/frr":            "ROUTING",
    "/etc/config/pbr":            "ROUTING",
    "/etc/config/sla":            "SLA",

    # Firewall / security
    "/etc/config/firewall":       "FIREWALL",
    "/etc/config/banip":          "SECURITY",
    "/etc/config/adblock":        "SECURITY",
    "/etc/config/dpi":            "SECURITY",
    "/etc/config/dpi_rule":       "SECURITY",
    "/etc/config/dnsdist":        "DNS",

    # VPN / tunnels
    "/etc/config/openvpn":        "VPN",
    "/etc/config/ipsec":          "VPN",
    "/etc/config/pptpd":          "VPN",
    "/etc/config/zerotier":       "VPN",
    "/etc/config/eoip":           "VPN",

    # QoS / shaping
    "/etc/config/qos":            "QOS",
    "/etc/config/advance_qos":    "QOS",
    "/etc/config/qosify":         "QOS",
    "/etc/config/sqm":            "QOS",
    "/etc/config/trafficshaper":  "QOS",
}

# -------- EVENT QUEUE (for NetJSON) --------
EVENT_QUEUE = []
QUEUE_LOCK = threading.Lock()
HOSTNAME = socket.gethostname()

LAST_EVENT_TS = 0.0    # last time we added an event
LAST_FLUSH_TS = time.time()  # last time we sent to controller/file


# -------- LOGGING (syslog) --------
logger = logging.getLogger("neteventd")
logger.setLevel(logging.INFO)  # change to DEBUG if needed

try:
    # OpenWrt uses /dev/log for syslog
    _syslog = logging.handlers.SysLogHandler(address="/dev/log")
    _formatter = logging.Formatter("neteventd: %(levelname)s: %(message)s")
    _syslog.setFormatter(_formatter)
    logger.addHandler(_syslog)
except Exception:
    # Fallback: stderr logging (still better than lots of prints)
    _stderr = logging.StreamHandler()
    _formatter = logging.Formatter("neteventd: %(levelname)s: %(message)s")
    _stderr.setFormatter(_formatter)
    logger.addHandler(_stderr)


def add_event(ev: dict):
    """
    Add a high-level event to the in-memory queue.
    ev is a plain dict; we'll trigger netjson-monitoring later.
    """
    global LAST_EVENT_TS, BATCH_START_TS

    now = time.time()
    ev.setdefault("timestamp", int(now))

    with QUEUE_LOCK:
        # If queue was empty, this is the first event of a new batch
        if not EVENT_QUEUE:
            BATCH_START_TS = now
        EVENT_QUEUE.append(ev)
        LAST_EVENT_TS = now

    if DEBUG_EVENTS:
        etype = ev.get("event") or ev.get("type")
        # print(f"[EVENT] src={ev.get('source')} type={etype} iface={ev.get('iface')} dev={ev.get('dev')}")
        logger.info("[EVENT] src=%s type=%s iface=%s dev=%s", ev.get("source"), etype, ev.get("iface"), ev.get("dev"))


def trigger_openwisp_send():
    """
    Find the openwisp-monitoring send process and send it SIGUSR1,
    so it immediately tries to send pending data.
    """
    try:
        # Equivalent of: pgrep -f 'openwisp-monitoring.*--mode send'
        out = subprocess.check_output(
            ["pgrep", "-f", "openwisp-monitoring.*--mode send"],
            text=True,
        )
        pid_str = out.strip().splitlines()[0]
        pid = int(pid_str)
        os.kill(pid, signal.SIGUSR1)
        # print(f"[SENDER] signalled openwisp-monitoring send pid={pid}")
        logger.info("[SENDER] signalled openwisp-monitoring send pid=%d", pid)
    except subprocess.CalledProcessError:
        # print("[SENDER] openwisp-monitoring --mode send not running")
        logger.warning("[SENDER] openwisp-monitoring --mode send not running")
    except Exception as e:
        # print(f"[SENDER] error signalling openwisp-monitoring: {e}")
        logger.exception("[SENDER] error signalling openwisp-monitoring: %s", e)


def netjson_sender():
    """
    Periodically check the queue; when conditions are met,
    trigger a NetJSON DeviceMonitoring dump and store it
    where openwisp-monitoring can pick it up.

    Conditions:
      - there are pending events AND
      - (quiet period passed) OR (max flush time reached)
    """
    global EVENT_QUEUE, LAST_FLUSH_TS

    while True:
        time.sleep(1)  # check every second

        with QUEUE_LOCK:
            if not EVENT_QUEUE:
                # No events -> nothing to trigger
                continue

            now = time.time()
            time_since_last_event = now - LAST_EVENT_TS
            batch_age = now - BATCH_START_TS if BATCH_START_TS else 0

            # Still within quiet period and batch not too old -> keep batching
            if time_since_last_event < QUIET_SECONDS and batch_age < MAX_FLUSH_SECONDS:
                continue

            # It's time to trigger a NetJSON dump for this batch
            batch = EVENT_QUEUE
            EVENT_QUEUE = []

        # At this point we decided to collect a monitoring snapshot.
        # The controller expects the output of:
        #   /usr/sbin/netjson-monitoring --dump '*'
        try:
             # print(f"[SENDER] flushing after {len(batch)} events, running netjson-monitoring...")
            logger.info("[SENDER] flushing after %d events, running netjson-monitoring...", len(batch))
            # This call blocks until netjson-monitoring finishes and returns JSON
            result = subprocess.run(
                ["/usr/sbin/netjson-monitoring", "--dump", "*"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            if result.returncode != 0:
                #print(f"[SENDER] netjson-monitoring failed (rc={result.returncode}): {result.stderr.strip()}")
                logger.error("[SENDER] netjson-monitoring failed (rc=%d): %s",result.returncode, result.stderr.strip())
                # Put events back so we can try again next time
                with QUEUE_LOCK:
                    batch.extend(EVENT_QUEUE)
                    EVENT_QUEUE = batch
                continue

            data = result.stdout.strip()
            if not data:
                #print("[SENDER] netjson-monitoring returned empty output")
                logger.error("[SENDER] netjson-monitoring returned empty output")
                with QUEUE_LOCK:
                    batch.extend(EVENT_QUEUE)
                    EVENT_QUEUE = batch
                continue

            # Optional: validate JSON once (will raise if invalid)
            try:
                json.loads(data)
            except Exception as je:
                #print(f"[SENDER] invalid JSON from netjson-monitoring: {je}")
                logger.error("[SENDER] invalid JSON from netjson-monitoring: %s", je)
                with QUEUE_LOCK:
                    batch.extend(EVENT_QUEUE)
                    EVENT_QUEUE = batch
                continue

            # Write to /tmp/openwisp/monitoring with same filename style as openwisp-monitoring
            os.makedirs(NETJSON_DIR, exist_ok=True)

            # Use UTC timestamp, format: DD-MM-YYYY_HH:MM:SS
            ts = time.gmtime()
            filename = time.strftime("%d-%m-%Y_%H:%M:%S", ts)
            path = os.path.join(NETJSON_DIR, filename)

            with open(path, "w") as f:
                f.write(data)

            # gzip, like the official agent does
            try:
                subprocess.run(["gzip", path], check=False)
                gz_path = path + ".gz"
                #print(f"[SENDER] wrote monitoring snapshot to {gz_path}")
                logger.info("[SENDER] wrote monitoring snapshot to %s", gz_path)
            except Exception as gz_e:
                #print(f"[SENDER] gzip failed: {gz_e}")
                logger.warning("[SENDER] gzip failed: %s", gz_e)
                #print(f"[SENDER] wrote monitoring snapshot to {path}")
                logger.info("[SENDER] wrote monitoring snapshot to %s", gz_path)

            LAST_FLUSH_TS = time.time()

            # Ask openwisp-monitoring --mode send to upload immediately
            trigger_openwisp_send()

        except Exception as e:
            #print(f"[SENDER] error during flush: {e}")
            logger.exception("[SENDER] error during flush: %s", e)
            # On any error, restore events back into queue so we don't lose them
            with QUEUE_LOCK:
                batch.extend(EVENT_QUEUE)
                EVENT_QUEUE = batch

# -------- helpers --------

def ensure_fifo():
    if not os.path.exists(FIFO):
        #print(f"[CORE] FIFO missing, creating {FIFO}")
        logger.info("[CORE] FIFO missing, creating %s", FIFO)
        os.mkfifo(FIFO)

# ---------- FIFO parser (state-based IFACE events) ----------

_last_iface_state = {}  # key: (iface, dev) -> action


def process_fifo_line(line: str):
    """
    Handle lines coming from hotplug via FIFO.
    - [IFACE] lines -> parsed into high-level events,
      but ONLY when the ACTION changes compared to last state.
    - other lines -> optional raw print for debugging.
    """
    line = line.strip()
    if not line:
        return

    if line.startswith("[IFACE]"):
        parts = line.split()
        fields = {}
        for tok in parts[1:]:
            if "=" in tok:
                k, v = tok.split("=", 1)
                fields[k] = v

        action = fields.get("ACTION")
        iface = fields.get("INTERFACE")
        dev = fields.get("DEVICE")

        if not action or not iface:
            if DEBUG_FIFO_RAW:
                #print(f"[FIFO-RAW] {line}")
                logger.debug("[FIFO-RAW] %s", line)
            return

        key = (iface, dev or "")

        # If we already saw same ACTION for this iface/dev, ignore
        prev = _last_iface_state.get(key)
        if prev == action:
            return

        _last_iface_state[key] = action

        ev = {
            "source": "IFACE",
            "category": "interface",
            "event": action,  # "ifup" / "ifdown"
            "iface": iface,
            "dev": dev,
        }
        add_event(ev)

    else:
        if DEBUG_FIFO_RAW:
            #print(f"[FIFO-RAW] {line}")
            logger.debug("[FIFO-RAW] %s", line)


# ---------- UBUS & IPMON parsers ----------

def process_ubus_line(line: str):
    """Parse UBUS JSON and emit high-level events."""
    try:
        data = json.loads(line)
    except Exception:
        if DEBUG_UBUS_RAW:
            #print(f"[UBUS-RAW] {line}")
            logger.debug("[UBUS-RAW] %s", line)
        return

    # network.interface events
    if "network.interface" in data:
        iface_data = data["network.interface"]
        action = iface_data.get("action")
        iface = iface_data.get("interface") or iface_data.get("name")
        if action and iface:
            ev = {
                "source": "UBUS",
                "category": "interface",
                "event": f"interface-{action}",  # "interface-ifup"/"interface-ifdown"
                "iface": iface,
            }
            add_event(ev)
        else:
            if DEBUG_UBUS_RAW:
                #print(f"[UBUS-RAW] {line}")
                logger.debug("[UBUS-RAW] %s", line)
        return

    # network.device events
    if "network.device" in data:
        dev_data = data["network.device"]
        action = dev_data.get("action")
        dev = dev_data.get("name") or dev_data.get("device")
        if action and dev:
            ev = {
                "source": "UBUS",
                "category": "device",
                "event": f"device-{action}",
                "dev": dev,
            }
            add_event(ev)
        else:
            if DEBUG_UBUS_RAW:
                #print(f"[UBUS-RAW] {line}")
                logger.debug("[UBUS-RAW] %s", line)
        return

    if DEBUG_UBUS_RAW:
        #print(f"[UBUS-RAW] {line}")
        logger.debug("[UBUS-RAW] %s", line)


def process_ipmon_line(line: str):
    """Parse 'ip monitor' output into link/route events."""
    if DEBUG_IPMON_RAW:
        #print(f"[IPMON-RAW] {line}")
        logger.debug("[IPMON-RAW] %s", line)

    # Default route add/remove
    if "default via " in line:
        removed = False
        text = line
        if text.startswith("Deleted "):
            removed = True
            text = text[len("Deleted "):]

        tokens = text.split()
        gw = None
        dev = None
        try:
            via_idx = tokens.index("via")
            gw = tokens[via_idx + 1]
        except Exception:
            pass
        try:
            dev_idx = tokens.index("dev")
            dev = tokens[dev_idx + 1]
        except Exception:
            pass

        if gw and dev:
            ev = {
                "source": "IPMON",
                "category": "route",
                "event": "default-route-removed" if removed else "default-route-added",
                "gateway": gw,
                "dev": dev,
            }
            add_event(ev)
        return

    # Link state change: "3: eth1: ... state DOWN/UP ..."
    if " state " in line and ":" in line:
        parts = line.split(":", 2)
        if len(parts) >= 3:
            dev = parts[1].strip()
            ev = None
            if " state DOWN" in line:
                ev = {
                    "source": "IPMON",
                    "category": "link",
                    "event": "link-down",
                    "dev": dev,
                }
            elif " state UP" in line:
                ev = {
                    "source": "IPMON",
                    "category": "link",
                    "event": "link-up",
                    "dev": dev,
                }
            if ev:
                add_event(ev)
                return

    # IP address add/del messages can be added later if needed.


# ---------- readers ----------

def reader_fifo():
    """Read messages sent by hotplug scripts."""
    ensure_fifo()
    #print("[CORE] FIFO reader started")
    logger.info("[CORE] FIFO reader started")
    while True:
        try:
            with open(FIFO, "r") as f:
                for line in f:
                    process_fifo_line(line)
        except Exception as e:
            #print("[CORE] FIFO reader error, reopening:", e)
            logger.exception("[CORE] FIFO reader error, reopening: %s", e)
            time.sleep(1)


def reader_cmd(name, cmd):
    """Run command (ip monitor / ubus listen) and feed into parsers."""
    while True:
        try:
            # print(f"[CORE] starting {name}: {' '.join(cmd)}")
            logger.info("[CORE] starting %s: %s", name, " ".join(cmd))
            p = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            for line in p.stdout:
                line = line.strip()
                if not line:
                    continue
                if name == "UBUS":
                    process_ubus_line(line)
                elif name == "IPMON":
                    process_ipmon_line(line)
                else:
                    print(f"[{name}] {line}")
            rc = p.wait()
            #print(f"[CORE] {name} exited with code {rc}, restarting in 1s")
            logger.warning("[CORE] %s exited with code %d, restarting in 1s", name, rc)
        except Exception as e:
            #print(f"[CORE] {name} crashed: {e}")
            logger.exception("[CORE] %s crashed: %s", name, e)
        time.sleep(1)


def get_mtime(path):
    try:
        st = os.stat(path)
        return st.st_mtime
    except FileNotFoundError:
        return None


def watcher_configs(interval=5):
    """Poll important config files and emit events when they change."""
    #print("[CORE] config watcher started")
    logger.info("[CORE] config watcher started")
    last = {p: get_mtime(p) for p in WATCH_FILES.keys()}
    while True:
        time.sleep(interval)
        for path, comp in WATCH_FILES.items():
            cur = get_mtime(path)
            if cur != last.get(path):
                ts = int(time.time())
                if last.get(path) is None and cur is not None:
                    ev_type = "config-created"
                elif cur is None:
                    ev_type = "config-deleted"
                else:
                    ev_type = "config-modified"
                last[path] = cur

                ev = {
                    "source": "CONFIG",
                    "category": "config",
                    "event": ev_type,
                    "component": comp,
                    "file": path,
                    "timestamp": ts,
                }
                add_event(ev)


# -------- main --------

def main():
    #print("=== neteventd: starting monitors + NetJSON sender ===")

    threads = []

    # FIFO reader (hotplug)
    t_fifo = threading.Thread(target=reader_fifo, daemon=True)
    threads.append(t_fifo)

    # ip monitor
    t_ip = threading.Thread(
        target=reader_cmd,
        args=("IPMON", ["ip", "monitor", "link", "addr", "route"]),
        daemon=True,
    )
    threads.append(t_ip)

    # ubus listener
    t_ubus = threading.Thread(
        target=reader_cmd,
        args=("UBUS", ["ubus", "listen", "network.interface", "network.device"]),
        daemon=True,
    )
    threads.append(t_ubus)

    # config watcher
    t_cfg = threading.Thread(target=watcher_configs, daemon=True)
    threads.append(t_cfg)

    # NetJSON sender
    t_sender = threading.Thread(target=netjson_sender, daemon=True)
    threads.append(t_sender)

    for t in threads:
        t.start()

    while True:
        time.sleep(60)


if __name__ == "__main__":
    main()


