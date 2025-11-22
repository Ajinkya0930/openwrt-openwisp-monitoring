#!/usr/bin/env lua
-- sample_netjson.lua  (fixed unmatched 'end' issue)
package.path = package.path .. ";../files/lib/?.lua"

local cjson = require('cjson')
local io = require('io')

local ubus_lib = require('ubus')
local ubus = ubus_lib.connect()
if not ubus then error('Failed to connect to ubusd') end

local monitoring = require('openwisp-monitoring.monitoring')

----------------------------------------------------------------
-- Helpers (safe ubus, fs/shell, parsing)
----------------------------------------------------------------
local function safe_ubus_call(obj, meth, args, timeout_ms)
  if not ubus then return nil end
  local ok, res = pcall(function()
    return ubus:call(obj, meth, args or {}, timeout_ms or 1000)
  end)
  if ok then return res end
  return nil
end

local function file_exists(path)
  local f = io.open(path, "r")
  if f then f:close() return true end
  return false
end

local function read_first_line(path)
  local f = io.open(path, "r")
  if not f then return nil end
  local l = f:read("*l"); f:close()
  return l
end

local function read_all(path)
  local f = io.open(path, "r"); if not f then return nil end
  local d = f:read("*a"); f:close(); return d
end

local function sh(cmd)
  local p = io.popen(cmd .. " 2>/dev/null")
  if not p then return "" end
  local out = p:read("*a"); p:close()
  return out or ""
end

local function dedup_array(arr)
  local seen, out = {}, {}
  for _, v in ipairs(arr or {}) do
    if v and v ~= "" and not seen[v] then
      seen[v] = true
      table.insert(out, v)
    end
  end
  return out
end

local function safe_get_interface_info(name, iface_tbl)
  local ok, res = pcall(function()
    return monitoring.interfaces.get_interface_info(name, iface_tbl)
  end)
  if ok and type(res) == "table" then
    return res
  end
  return {}
end

----------------------------------------------------------------
-- Single robust JSON reader used everywhere
-- returns table or nil,err
----------------------------------------------------------------
local function read_json_file(path)
  if type(path) ~= "string" then return nil, "path must be string" end
  local f, err = io.open(path, "rb")
  if not f then return nil, ("failed to open %s: %s"):format(path, tostring(err)) end
  local content = f:read("*a")
  f:close()
  if not content or content == "" then return nil, ("empty file: %s"):format(path) end
  local ok, decoded = pcall(cjson.decode, content)
  if not ok then return nil, ("json decode error: %s"):format(tostring(decoded)) end
  return decoded
end

----------------------------------------------------------------
-- Normalizers & validators
----------------------------------------------------------------
local function normalize_family(fam)
  if fam == "inet"  then return "ipv4" end
  if fam == "inet6" then return "ipv6" end
  return fam
end

local function sanitize_mac(mac)
  if not mac or mac == "" then return nil end
  mac = mac:lower()
  if mac == "00:00:00:00" or mac == "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00" then
    return nil
  end
  if not mac:match("^%x%x:%x%x:%x%x:%x%x:%x%x:%x%x$") then
    return nil
  end
  if mac == "00:00:00:00:00:00" then
    return nil
  end
  return mac
end

local function is_bad_iface_name(name)
  if not name then return true end
  if name == "lo" then return true end
  if name == "gre0" or name == "gretap0" or name == "sit0"
     or name == "ip6tnl0" or name == "ip6_vti0" or name == "teql0"
     or name == "tunl0" then
    return true
  end
  if name:match("^tun%d+") or name:match("^tap%d+") then
    return true
  end
  return false
end

local function map_iface_name_to_eth(name)
  if not name then return name end
  local n = name:match("^lan(%d+)$")
  if n then return "eth" .. n end
  if name == "inter-lan" then return "eth0" end
  return name
end

----------------------------------------------------------------
-- Interface enumeration helpers
----------------------------------------------------------------
local function list_ifaces()
  local out = sh("ls -1 /sys/class/net")
  local ifs = {}
  for name in out:gmatch("([^\n]+)") do
    if not is_bad_iface_name(name) and not monitoring.utils.is_excluded(name) then
      table.insert(ifs, name)
    end
  end
  return ifs
end

local function read_netdev_counters()
  local map = {}
  local txt = read_all("/proc/net/dev") or ""
  for line in txt:gmatch("[^\n]+") do
    local ifname, rest = line:match("^%s*([^:]+):%s*(.+)$")
    if ifname and rest then
      local rx_bytes, rx_packets, rx_errs, rx_drop,
            tx_bytes, tx_packets, tx_errs, tx_drop =
        rest:match("(%d+)%s+(%d+)%s+(%d+)%s+(%d+)%s+%d+%s+%d+%s+%d+%s+%d+%s+(%d+)%s+(%d+)%s+(%d+)%s+(%d+)")
      if rx_bytes and tx_bytes then
        map[ifname] = {
          rx_bytes = tonumber(rx_bytes),
          rx_packets = tonumber(rx_packets),
          rx_errors = tonumber(rx_errs),
          rx_dropped = tonumber(rx_drop),
          tx_bytes = tonumber(tx_bytes),
          tx_packets = tonumber(tx_packets),
          tx_errors = tonumber(tx_errs),
          tx_dropped = tonumber(tx_drop)
        }
      end
    end
  end
  return map
end

local function iface_basic_info(name)
  local info = {}
  info.mtu = tonumber(read_first_line("/sys/class/net/"..name.."/mtu"))
  info.mac = read_first_line("/sys/class/net/"..name.."/address")
  if file_exists("/sys/class/net/"..name.."/wireless") then
    info.type = "wireless"
  elseif file_exists("/sys/class/net/"..name.."/bridge") then
    info.type = "bridge"
  elseif file_exists("/sys/class/net/"..name.."/tun_flags") or name:match("^tun") or name:match("^tap") or name:match("^wg") then
    info.type = "virtual"
  elseif name == "modem" or name == "modem2" then
    info.type = "mobile"
  else
    info.type = "ethernet"
  end
  info.up = (read_first_line("/sys/class/net/"..name.."/operstate") == "up")
  local speed = read_first_line("/sys/class/net/"..name.."/speed")
  info.speed = speed and speed:gsub("%s+$", "") or nil
  return info
end

local function iface_addresses()
  local map = {}
  local out = sh("ip -o addr show")
  for line in out:gmatch("[^\n]+") do
    local ifname, fam, addr = line:match("^%d+:%s*([^%s]+)%s+([^%s]+)%s+([^%s]+)")
    if ifname and fam and addr and (fam == "inet" or fam == "inet6") then
      local ip, mask = addr:match("^([^/]+)/(%d+)$")
      ip   = ip or addr
      mask = tonumber(mask)
      local family = (fam == "inet") and "ipv4" or "ipv6"
      if family == "ipv6" then ip = ip:gsub("%%[%w._-]+$", "") end
      map[ifname] = map[ifname] or {}
      local entry = { family = family, address = ip }
      if mask then entry.mask = mask end
      table.insert(map[ifname], entry)
    end
  end
  return map
end

local function bridge_members(name)
  local dir = "/sys/class/net/"..name.."/brif"
  local out = sh("[ -d "..dir.." ] && ls -1 "..dir.." || true")
  local members = {}
  for m in out:gmatch("([^\n]+)") do table.insert(members, m) end
  return (#members > 0) and members or nil
end

----------------------------------------------------------------
-- Wireless helpers via ubus (guarded)
----------------------------------------------------------------
local function iwinfo_via_ubus(dev)
  return safe_ubus_call("iwinfo", "info", { device = dev }, 1000)
end

local function iwinfo_assoclist(dev)
  local res = safe_ubus_call("iwinfo", "assoclist", { device = dev }, 1000)
  return res and res.results or nil
end

local function hostapd_clients(dev)
  local res = safe_ubus_call("hostapd."..dev, "get_clients", {}, 1000)
  return res and res.clients or nil
end

----------------------------------------------------------------
-- DNS helpers
----------------------------------------------------------------
local function read_dns()
  local servers, search = {}, {}
  local path = "/tmp/resolv.conf.d/resolv.conf.auto"
  if not file_exists(path) then path = "/etc/resolv.conf" end
  local data = read_all(path) or ""
  for line in data:gmatch("[^\n]+") do
    local k, v = line:match("^(%S+)%s+(.+)$")
    if k == "nameserver" then
      table.insert(servers, v)
    elseif k == "search" or k == "domain" then
      for s in v:gmatch("(%S+)") do table.insert(search, s) end
    end
  end
  return dedup_array(servers), dedup_array(search)
end

----------------------------------------------------------------
-- read the eth interfaces file
----------------------------------------------------------------
local function read_iface_zone_mode(name)
  local path = "/tmp/" .. name .. ".info"
  local f = io.open(path, "r")
  if not f then return nil end
  local zone, mode
  for line in f:lines() do
    line = line:match("^%s*(.-)%s*$")
    if line ~= "" then
      local k, v = line:match("^(%S+)%s*:%s*(.-)%s*$")
      if k and v then
        k = k:lower()
        if k == "zone" then zone = v end
        if k == "mode" then mode = v end
      end
    end
  end
  f:close()
  return { zone = zone, mode = mode }
end

----------------------------------------------------------------
-- Collect system info (fast ubus)
----------------------------------------------------------------
local system_info = ubus:call('system', 'info', {})
local board       = ubus:call('system', 'board', {})

local loadavg_file = io.popen('cat /proc/loadavg')
local loadavg_output = loadavg_file:read()
loadavg_file:close()
local load_average = monitoring.utils.split(loadavg_output or "", ' ')
load_average = {
  tonumber(load_average[1]) or 0,
  tonumber(load_average[2]) or 0,
  tonumber(load_average[3]) or 0
}

local serial_num = ""
if file_exists("/tmp/device.info") then
  local s = read_all("/tmp/device.info") or ""
  serial_num = s:match("devsn%s*[:=]%s*(%S+)") or ""
end
----------------------------------------------------------------
-- Init NetJSON
----------------------------------------------------------------
local netjson = {
  type = 'DeviceMonitoring',
  device_type = '4g_5g_router',
  general = {
    hostname   = board.hostname,
    local_time = system_info.localtime,
    uptime     = system_info.uptime,
    serialnumber = serial_num
  },
  resources = {
    load   = load_average,
    memory = system_info.memory,
    swap   = system_info.swap,
    cpus   = monitoring.resources.get_cpus(),
    disk   = monitoring.resources.parse_disk_usage()
  }
}

----------------------------------------------------------------
-- DHCP leases and neighbors
----------------------------------------------------------------
local dhcp_leases = monitoring.dhcp.get_dhcp_leases()
if not monitoring.utils.is_table_empty(dhcp_leases) then
  netjson.dhcp_leases = dhcp_leases
end

local host_neighbors = monitoring.neighbors.get_neighbors()
if not monitoring.utils.is_table_empty(host_neighbors) then
  netjson.neighbors = host_neighbors
end

----------------------------------------------------------------
-- Determine interfaces to monitor (argument: "*" or space-separated list)
----------------------------------------------------------------
local arg = {...}
local traffic_monitored = arg[1]
local include_stats = {}
local monitor_all = (traffic_monitored == '*')
if traffic_monitored and not monitor_all then
  traffic_monitored = monitoring.utils.split(traffic_monitored, ' ')
  for _, name in pairs(traffic_monitored) do include_stats[name] = true end
end

----------------------------------------------------------------
-- Collect device data (without slow ubus calls to network.device/wireless)
----------------------------------------------------------------
local vpn_interfaces  = monitoring.interfaces.get_vpn_interfaces() or {}
local host_interfaces = {}
local dns_servers     = {}
local dns_search      = {}

-- Interfaces
local ifs       = list_ifaces()
local counters  = read_netdev_counters()
local addr_map  = iface_addresses()

for _, name in ipairs(ifs) do
  if not monitoring.utils.is_excluded(name) then
    local b = iface_basic_info(name)
    local mac = sanitize_mac(b.mac)
    local mapped_name = map_iface_name_to_eth(name)

    local netjson_interface = {
      name  = mapped_name,
      type  = b.type,
      up    = b.up,
      mtu   = b.mtu,
      speed = b.speed
    }
    if mac then netjson_interface.mac = mac end

    local file_info = read_iface_zone_mode(name)
    if file_info then
      if file_info.zone and not netjson_interface.zone then
        netjson_interface.role = string.lower(file_info.zone)
      end

      local zone_l = file_info.zone and string.lower(file_info.zone) or nil
      local mode_l = file_info.mode and string.lower(file_info.mode) or nil
      if (zone_l == "wan" or (mode_l and mode_l:match("^wan"))) and not netjson_interface.is_wan then
        netjson_interface.is_wan = true
      end
    end

    if b.type == "bridge" then
      local members = bridge_members(name)
      if members then
        for i,m in ipairs(members) do members[i] = map_iface_name_to_eth(m) end
        netjson_interface.bridge_members = members
      end
    end

    if b.type == "wireless" then
      local iw --= iwinfo_via_ubus(name)
      if iw then
        netjson_interface.wireless = {
          ssid      = iw.ssid,
          mode      = monitoring.wifi.iwinfo_modes[iw.mode] or iw.mode,
          channel   = iw.channel,
          frequency = iw.frequency,
          tx_power  = iw.txpower,
          signal    = iw.signal,
          noise     = iw.noise,
          country   = iw.country
        }
        local clients, is_mesh = nil, false
        if iw.mode == "Ad-Hoc" or iw.mode == "Mesh Point" then
          clients = iwinfo_assoclist(name)
          is_mesh = true
        else
          clients = hostapd_clients(name) or iwinfo_assoclist(name)
        end
        if clients and not monitoring.utils.is_table_empty(clients) then
          netjson_interface.wireless.clients = monitoring.wifi.netjson_clients(clients, is_mesh)
        end
      end
    elseif vpn_interfaces[name] then
      netjson_interface.type = "virtual"
    end

    if monitor_all or include_stats[name] then
      local st = counters[name]
      if st then
        local rx_bytes = st.rx_bytes
        local rx_packets = st.rx_packets
        local rx_errors = st.rx_errors
        local rx_dropped = st.rx_dropped

        local tx_bytes = st.tx_bytes
        local tx_packets = st.tx_packets
        local tx_errors = st.tx_errors
        local tx_dropped = st.tx_dropped

        if monitoring.wifi.needs_inversion(netjson_interface) then
          rx_bytes, tx_bytes = tx_bytes, rx_bytes
          rx_packets, tx_packets = tx_packets, rx_packets
          rx_errors, tx_errors = tx_errors, rx_errors
          rx_dropped, tx_dropped = tx_dropped, rx_dropped
        end

        local stats = {}
        if rx_bytes    ~= nil then stats.rx_bytes    = rx_bytes    end
        if rx_packets  ~= nil then stats.rx_packets  = rx_packets  end
        if rx_errors   ~= nil then stats.rx_errors   = rx_errors   end
        if rx_dropped  ~= nil then stats.rx_dropped  = rx_dropped  end

        if tx_bytes    ~= nil then stats.tx_bytes    = tx_bytes    end
        if tx_packets  ~= nil then stats.tx_packets  = tx_packets  end
        if tx_errors   ~= nil then stats.tx_errors   = tx_errors   end
        if tx_dropped  ~= nil then stats.tx_dropped  = tx_dropped  end

        netjson_interface.statistics = stats
      end
    end

    local addrs = addr_map[name]
    if addrs and next(addrs) then
      netjson_interface.addresses = addrs
    end

    local info = safe_get_interface_info(name, netjson_interface)
    if info.stp ~= nil then netjson_interface.stp = info.stp end
    if type(info.specialized) == "table" then
      for k, v in pairs(info.specialized) do netjson_interface[k] = v end
    end
    if type(info.dns_servers) == "table" then
      monitoring.utils.array_concat(info.dns_servers, dns_servers)
    end
    if type(info.dns_search) == "table" then
      monitoring.utils.array_concat(info.dns_search, dns_search)
    end

    table.insert(host_interfaces, netjson_interface)
  end
end

----------------------------------------------------------------
-- NEW: attach mobile JSON files safely (mobile1 -> modem, mobile2 -> modem2)
----------------------------------------------------------------
local function read_kv_file(path)
  local t = {}
  local fh, err = io.open(path, "r")
  if not fh then
    return nil, ("failed to open %s: %s"):format(path, tostring(err))
  end
  for line in fh:lines() do
    local k, v = line:match("^%s*(.-)%s*:%s*(.*)$")
    if k then t[k] = v end
  end
  fh:close()
  return t
end

local function find_host_iface_by_name(name)
  for _, iface in ipairs(host_interfaces) do
    if iface.name == name then return iface end
  end
  return nil
end

local function mobile_obj_to_mobile_table(mobj)
  if type(mobj) ~= "table" then return nil end
  return {
    imei              = mobj.imei,
    operator_code     = mobj.operator_code,
    operator_name     = mobj.operator_name,
    connection_status = mobj.connection_status,
    power_status      = mobj.power_status,
    manufacturer      = mobj.manufacturer,
    model             = mobj.model,
    signal            = mobj.signal
  }
end

local function attach_mobile_file_to_iface(json_path, ifname)
  local parsed, perr = read_json_file(json_path)
  if not parsed then return false, ("no json at %s: %s"):format(json_path, tostring(perr)) end
  local mtable = mobile_obj_to_mobile_table(parsed.mobile or parsed)
  if not mtable then return false, "mobile table missing or invalid" end
  local existing = find_host_iface_by_name(ifname)
  if existing then
    existing.mobile = existing.mobile or {}
    for k,v in pairs(mtable) do existing.mobile[k] = v end
    if mtable.connection_status then existing.up = (mtable.connection_status == "connected") end
  else
    local new_iface = {
      name = ifname,
      type = "mobile",
      up   = (mtable.connection_status == "connected"),
      mobile = mtable
    }
    table.insert(host_interfaces, new_iface)
  end
  return true
end

attach_mobile_file_to_iface("/tmp/mobile1.json", "modem")
attach_mobile_file_to_iface("/tmp/mobile2.json", "modem2")

----------------------------------------------------------------
-- Attach ping measurements from /tmp/ping_metrics.json to matching interfaces
----------------------------------------------------------------
local function iface_matches_srcip(iface, srcip)
  if not srcip then return false end
  if not iface.addresses then return false end
  for _, a in pairs(iface.addresses) do
    if type(a) == "string" then
      if a == srcip then return true end
    elseif type(a) == "table" then
      if a.address == srcip or a.ip == srcip or a.addr == srcip then return true end
      for _, v in pairs(a) do
        if type(v) == "string" and v == srcip then return true end
      end
    end
  end
  return false
end

local function find_host_interface(name, srcip)
  local mapped_name = name and map_iface_name_to_eth(name) or nil
  for _, iface in ipairs(host_interfaces) do
    if name and (iface.name == name or iface.name == mapped_name) then return iface end
    if srcip and iface_matches_srcip(iface, srcip) then return iface end
  end
  return nil
end

local function extract_throughput_from_record(rec)
  if type(rec) ~= "table" then return nil end
  local thr = {}
  local any = false
  for k, v in pairs(rec) do
    if type(k) == "string" and k:match("^throughput") then
      local nk = k:gsub("^throughput_", "")
      if type(v) == "string" then
        local n = tonumber(v)
        if n ~= nil then thr[nk] = n else thr[nk] = v end
      else
        thr[nk] = v
      end
      any = true
    end
  end
  if any then return thr end
  return nil
end

do
  local ping_file = "/tmp/ping_metrics.json"
  local pings, perr = read_json_file(ping_file)
  if pings and type(pings) == "table" then
    for _, rec in ipairs(pings) do
      local ifname = rec["device_name"] or rec.device_name or rec["interface"] or rec.interface
      local srcip  = rec["source_ip"]   or rec.source_ip   or rec["src ip"] or rec["src_ip"] or rec.src_ip or rec["src"] or rec.src

      local target_iface = find_host_interface(ifname, srcip)
      if target_iface then
  local dest_ip = rec["destination_ip"] or rec.destination_ip or rec["destination"] or rec.destination or rec["dest ip"] or rec.dest_ip or rec.dest
        local pkt_loss = rec.packet_loss or rec.packet_loss_percent or rec.loss
        if type(pkt_loss) == "number" then pkt_loss = tostring(pkt_loss) .. "%" end

        local ping_obj = {
          dest_ip     = dest_ip,
          timestamp   = rec.timestamp,
          latency_ms  = (rec.latency_ms ~= nil) and tonumber(rec.latency_ms) or rec.latency_ms,
          jitter_ms   = (rec.jitter_ms  ~= nil) and tonumber(rec.jitter_ms)  or rec.jitter_ms,
          packet_loss = pkt_loss
        }

        local thr = extract_throughput_from_record(rec)
        if thr then ping_obj.throughput = thr end

        target_iface.ping = ping_obj
      else
        if not monitoring._orphan_pings then monitoring._orphan_pings = {} end
        table.insert(monitoring._orphan_pings, rec)
      end
    end
  end
end

-- System-level DNS
local sys_dns_servers, sys_dns_search = read_dns()
for _, v in ipairs(sys_dns_servers or {}) do table.insert(dns_servers, v) end
for _, v in ipairs(sys_dns_search or {}) do table.insert(dns_search, v) end
dns_servers = dedup_array(dns_servers)
dns_search  = dedup_array(dns_search)

----------------------------------------------------------------
-- Finalize NetJSON
----------------------------------------------------------------
if next(host_interfaces) ~= nil then netjson.interfaces = host_interfaces end
if next(dns_servers)   ~= nil then netjson.dns_servers = dns_servers end
if next(dns_search)    ~= nil then netjson.dns_search  = dns_search  end

----------------------------------------------------------------
-- Legacy KV readers for modem etc.
----------------------------------------------------------------
netjson.cellular = {
  modem = (read_kv_file("/tmp/modem_data.info")),
  modem2 = (read_kv_file("/tmp/modem_data2.info"))
}

netjson.wlan = {
  wlan_data = read_kv_file("/tmp/wlan.info")
}

netjson.device = {
  device_info = read_kv_file("/tmp/device.info")
}

netjson.ethernet = {
  eth1_data = read_kv_file("/tmp/eth1.info"),
  eth2_data = read_kv_file("/tmp/eth2.info"),
  eth3_data = read_kv_file("/tmp/eth3.info"),
  eth4_data = read_kv_file("/tmp/eth4.info"),
  eth5_data = read_kv_file("/tmp/eth5.info")
}

netjson.performance_sla = {
  data = read_kv_file("/tmp/performance_sla.info")
}

netjson.zone_firewall = {
  data = read_kv_file("/tmp/zone_firewall.info")
}

-- Collect Real Time Monitor Data.
local dpi_summary_client = "/tmp/monitoring_agent/realtime_monitor/dpi_summary_by_client.json"
local python_status = os.execute("/usr/bin/python3 /usr/sbin/collect_dpi_client_data.py >/dev/null 2>&1")
local dpiclient_data = {}
if python_status == 0 then
  local file = io.open(dpi_summary_client, "r")
  if file then
    local content = file:read("*a")
    file:close()
    os.remove(dpi_summary_client)
    local ok, decoded = pcall(cjson.decode, content)
    if ok then dpiclient_data = decoded else dpiclient_data = {} end
  else
    dpiclient_data = {}
  end
else
  dpiclient_data = {}
end

local traffic_data, terr = read_json_file("/tmp/top_traffic.info")
if not traffic_data then traffic_data = {} end

netjson.realtimemonitor = {
  traffic = { dpi_client_data = dpiclient_data },
  real_time_traffic = { data = traffic_data }
}

-- final output
local ok, out = pcall(cjson.encode, netjson)
if not ok then
  io.stderr:write("error encoding output JSON: "..tostring(out).."\n")
  os.exit(1)
end
io.write(out)


