#!/usr/bin/env python3
import json
from pathlib import Path
from datetime import datetime
import logging

logging.basicConfig(filename='/tmp/openwisp_monitoring.log', level=logging.INFO)
logging.info(f'Script run at {datetime.now()}')

# Paths
base_dir = Path("/var/run/dpireport")
output_dir = Path("/tmp/monitoring_agent/realtime_monitor")
output_dir.mkdir(parents=True, exist_ok=True)

# Get current hour timestamp for file naming and existence check
hour_timestamp = datetime.now().strftime("%Y%m%d_%H")

# Output file path (aggregated JSON for this hour)
out_path = output_dir / f"dpi_summary_by_client.json"

# If the file already exists for this hour, skip to avoid duplicates
if out_path.exists():
    print(f"JSON file for this hour already exists: {out_path}")
    exit(0)

# Find the latest year/month/day directories
years = sorted([d for d in base_dir.iterdir() if d.is_dir() and d.name.isdigit()], reverse=True)
if not years:
    print("No year directories found.")
    exit(1)
latest_year = years[0]

months = sorted([d for d in latest_year.iterdir() if d.is_dir() and d.name.isdigit()], reverse=True)
if not months:
    print("No month directories found.")
    exit(1)
latest_month = months[0]

days = sorted([d for d in latest_month.iterdir() if d.is_dir() and d.name.isdigit()], reverse=True)
if not days:
    print("No day directories found.")
    exit(1)
latest_day = days[0]

dpi_dir = latest_day
results = []

for client_dir in dpi_dir.iterdir():
    if not client_dir.is_dir():
        continue
    client_ip = client_dir.name

    # Get all .json files and pick the latest (highest hour)
    json_files = sorted(client_dir.glob("*.json"), reverse=True)
    if not json_files:
        continue

    latest_file = json_files[0]  # latest hour file
    try:
        with open(latest_file) as f:
            data = json.load(f)
            results.append({
                "client": client_ip,
                "hour": latest_file.stem,
                "data": data
            })
    except json.JSONDecodeError:
        print(f"Error decoding JSON in: {latest_file}")

if results:
    # Save all collected data to plain JSON file
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f)
    print(f"Saved aggregated DPI data to {out_path}")
else:
    print("No valid DPI data found to save.")


