#!/usr/bin/env python3
import subprocess
import time
import json
import os
import sys
import re
import csv
from datetime import datetime

# ==========================
# CONFIGURATION
# ==========================

INTERVAL_SECONDS = 60          # measurement period (1 min)
SAMPLES_PER_SEND = 3           # send every 3 samples (3 min)
PING_COUNT = 10                # number of ping packets per run
PING_INTERVAL = 0.2            # interval between ping packets (sec)
DEFAULT_PING_FALLBACK = "8.8.8.8"  # fallback if no gateway found
CSV_DIR = "/overlay/sla"

#down time variable to calculate sla percentage.
DownTime = 0
UpTime = 0
Availability_Percent = 0
prev_downtime = 0

DataCapture_Counter = 1
TOTAL_TIME = 86400
INTERVAL = 60

# ==========================
# HELPER FUNCTIONS
# ==========================
def run_cmd(cmd):
    try:
        proc = subprocess.Popen(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        out, err = proc.communicate()
        return out.strip(), err.strip(), proc.returncode
    except Exception as e:
        return "", str(e), 1


def get_eth_interfaces():
    """
    Discover eth* interfaces from UCI (NOT IP-dependent).
    Returns dict: {iface: ip_or_None}
    """
    interfaces = {}
    device_name = []

    # 1. Get all logical network interfaces
    out, err, rc = run_cmd("uci show network | grep '=interface'")
    if rc != 0:
        print(f"Failed to read UCI network: {err}", file=sys.stderr)
        return interfaces

    for line in out.splitlines():
        # network.WAN1=interface
        iface = line.split('.')[1].split('=')[0]

        # 2. Get device name (ethX)
        dev_out, _, _ = run_cmd(f"uci get network.{iface}.device")
        dev = dev_out.strip()

        if not dev.startswith("eth"):
            continue
        else:
            device_name.append(dev)

        #print(f"device names --> {device_name}")

        # 3. Get IP if present (optional)
        ip_out, _, _ = run_cmd(f"ip -o -4 addr show dev {dev} scope global")
        ip = None
        if ip_out:
            parts = ip_out.split()
            if len(parts) >= 4:
                ip = parts[3].split("/")[0]

        interfaces[dev] = ip

    return device_name #interfaces


def ping_target(iface, target):
    result = {
        "latency_ms_min": None,
        "latency_ms_avg": None,
        "latency_ms_max": None,
        "jitter_ms": None,
        "loss_percent": 100.0,
        "status": "down",
    }

    cmd = f"ping -q -I {iface} -c {PING_COUNT} -i {PING_INTERVAL} {target}"
    out, err, rc = run_cmd(cmd)

    # We can still parse output even if rc != 0 (e.g. some packets lost)
    text = out + "\n" + err

    # Parse loss line:
    # "10 packets transmitted, 10 received, 0% packet loss, time ..."
    m_loss = re.search(
        r"(\d+)\s+packets transmitted,\s+(\d+)\s+received.*?(\d+)% packet loss",
        text
    )
    if m_loss:
        tx = int(m_loss.group(1))
        rx = int(m_loss.group(2))
        loss = float(m_loss.group(3))
        result["loss_percent"] = loss
        if rx > 0 and loss < 100.0:
            result["status"] = "up"
        else:
            result["status"] = "down"
    else:
        # If we can't parse, assume 100% loss / down
        return result

    # If 100% loss, we won't have RTT stats
    if result["loss_percent"] == 100.0:
        return result

    # Parse RTT line:
    # Linux: "rtt min/avg/max/mdev = 13.813/15.219/18.594/1.428 ms"
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

def save_json_to_tmp(payload):
    """Save the final 3-minute JSON bundle to /tmp."""
    #print("Inside the save to file....")
    try:
        path = "/tmp/ping_metrics.json"     # final json data append into this file.
        with open(path, "w") as f:
            json.dump(payload, f, indent=2)
        #print(f"Saved JSON to {path}")
    except Exception as e:
        #print(f"Error saving JSON: {e}", file=sys.stderr)

#===========================
# SAVE DATA INTO CSV FILE
#===========================
def save_data_into_csv(sample, interface_name):
    #------- This part store the 1min interval data into csv file.---------
    fieldnames = [
        "timestamp", "interface", "target", "destination",
        "latency_ms", "jitter_ms", "loss_percent", "status", "uptime", "downtime"
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

#===========================
# Read Downtime From CSV
#===========================
def read_downtime_from_csv(iface_name):
    filename = f"{CSV_DIR}/{iface_name}.csv"

    if not os.path.exists(filename):
        return 0, 0, 0
    
    last_row = None
    first_row = None

    with open(filename, newline="") as f:
        reader = csv.DictReader(f)
        first_row = next(reader, None)   # get first data row
        for row in reader:
            last_row = row
    
    if not first_row:
        return 0, 0, 0
    
    start_time = int(first_row.get("timestamp", 0) or 0)

    if last_row is not None:
        downtime = int(last_row.get("downtime") or 0)
        uptime = int(last_row.get("uptime") or 0)
        #print("Last downtime:", downtime)
    else:
        #print("CSV is empty")
        downtime = 0
        uptime = 0
        start_time = 0
    return downtime,uptime,start_time


#=================================
# on day change delete the file.
#=================================
def maybe_daily_reset(csv_path):
    now = datetime.now()
    hour = now.hour
    minute = now.minute

    if hour == 23 and minute == 59:
        if os.path.exists(csv_path):
            os.remove(csv_path)   # delete yesterday file

        return 0  # downtime reset to zero

    return None  # no reset

# ==========================
# MAIN LOOP
# ==========================    
def main():
    global DownTime,UpTime,Availability_Percent,prev_downtime,DataCapture_Counter

    interfaces = get_eth_interfaces()
    if not interfaces:
        print("No eth* interfaces with IPv4 found.", file=sys.stderr)
        return

    # print(f"Monitoring interfaces:- {interfaces}")
    # print(f"Sample interval: {INTERVAL_SECONDS} seconds")
    # print(f"Bundle size: {SAMPLES_PER_SEND} samples (3 minutes total)")

    samples_buffer = []

    while True:
        loop_start = time.time()
        timestamp = int(loop_start)

        # refresh interfaces list each loop (in case iface added/removed)
        interfaces = get_eth_interfaces()

        #---- below array and dict used to save sample json data.-----------
        json_file_sample = []
        sample = {
            "timestamp": timestamp,
            "ifaces": {}
        }

        for iface in interfaces:
            sample["ifaces"].clear()               # reset for next interval
            sample["timestamp"] = timestamp

            # 3. Get IP if present (optional)
            ip_out, _, _ = run_cmd(f"ip -o -4 addr |grep -i {iface}")
            ip_addr = None
            if ip_out:
                parts = ip_out.split()
                if len(parts) >= 4:
                    ip_addr = parts[3].split("/")[0]

            #print(f"ip address of {iface} ---> {ip_addr}")
            #---- this will bring the ping stats --------------
            ping_stats = ping_target(ip_addr, DEFAULT_PING_FALLBACK)

            #---- check end of the day time to reset the variable values and check the down time from file and read it then calculate---------
            csv_file = f"{CSV_DIR}/{iface}.csv"
            reset_dt = maybe_daily_reset(csv_file)
            if reset_dt is not None:
                DownTime = 0
                UpTime = 0
                Start_Time = 0
            else:
                DownTime, UpTime, Start_Time = read_downtime_from_csv(iface)

            # Increment only on 100% loss
            if ping_stats["loss_percent"] == 100:
                DownTime += INTERVAL
            else:
                UpTime += INTERVAL

            # Availability calculation
            #print(f"uptime --> {UpTime} and downtime ==> {DownTime}")
            Availability_Percent = UpTime / (UpTime + DownTime) * 100
            Availability_Percent = round(Availability_Percent, 2)       #this will save two decimal value.
            #print(f"--- Time and percentage --> {Availability_Time},{Availability_Percent}")

            # Build iface JSON exactly in your desired format
            iface_entry = {
                "target": ip_addr,
                "destination": DEFAULT_PING_FALLBACK, 
                "latency_ms": ping_stats["latency_ms_avg"], # average latency in ms
                "jitter_ms": ping_stats["jitter_ms"],
                "loss_percent": ping_stats["loss_percent"],
                "status": ping_stats["status"],  # "up" or "down"
                "uptime": UpTime,
                "downtime": DownTime
            }

            # Build iface JSON exactly in your desired format
            json_file_entry = {
                "device_name": iface,
                "target": ip_addr,
                "destination": DEFAULT_PING_FALLBACK, 
                "latency_ms": ping_stats["latency_ms_avg"], # average latency in ms
                "jitter_ms": ping_stats["jitter_ms"],
                "packet_loss": ping_stats["loss_percent"],
                "status": ping_stats["status"],  # "up" or "down"
                "start time": Start_Time,
                "uptime_sec": UpTime,
                "downtime_sec": DownTime,
                "availability_percent":Availability_Percent
            }

            sample["ifaces"][iface] = iface_entry

            #--- call this function to save the data into file. -------
            save_data_into_csv(sample, iface)

            #--- capture data after SAMPLES_PER_SEND reach ------------
            if DataCapture_Counter == SAMPLES_PER_SEND:
                #print(f" to capture the json data counter ---> {DataCapture_Counter}")
                json_file_sample.append(json_file_entry)

        # If buffer full, send 3-minute window
        if DataCapture_Counter == SAMPLES_PER_SEND:
            # Save JSON bundle in /tmp/
            save_json_to_tmp(json_file_sample)

            # After sending, clear buffer to avoid resending same samples.
            json_file_sample = []
            DataCapture_Counter = 0

        # Sleep until next 1-minute tick
        loop_end = time.time()
        elapsed = loop_end - loop_start
        sleep_time = INTERVAL_SECONDS - elapsed
        if sleep_time > 0:
            time.sleep(sleep_time)
            DataCapture_Counter += 1



if __name__ == "__main__":
    try:
        os.makedirs(CSV_DIR, exist_ok=True)
        main()
    except KeyboardInterrupt:
        print("Exiting on Ctrl+C")

