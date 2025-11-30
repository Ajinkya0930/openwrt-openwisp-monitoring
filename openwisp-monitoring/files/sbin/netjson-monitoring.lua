#!/usr/bin/env lua
-- sample_netjson.lua  (updated: only include modem/modem2 if /sys/class/net/<name> exists)
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
-- JSON reader
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

----------------------------------------------------------------
-- Map interface names -> canonical ethN where appropriate
-- Handles: eth-1, eth_1, eth01, lan1, Lan1 -> eth1
----------------------------------------------------------------
local function map_iface_name_to_eth(name)
  if not name then return name end
  local nm = name:lower()
  local ethdash = nm:match("^eth%-0*(%d+)$") or nm:match("^eth%-([0-9]+)$")
  if ethdash then return "eth" .. tonumber(ethdash) end
  local eth_ = nm:match("^eth_0*(%d+)$") or nm:match("^eth_([0-9]+)$")
  if eth_ then return "eth" .. tonumber(eth_) end
  local ethplain = nm:match("^eth0*(%d+)$")
  if ethplain then return "eth" .. tonumber(ethplain) end
  local lan = nm:match("^lan0*(%d+)$") or nm:match("^lan([0-9]+)$")
  if lan then return "eth" .. tonumber(lan) end
  if nm == "inter-lan" then return "eth0" end
  return nm
end

----------------------------------------------------------------
-- Merge helpers: merge new iface data into existing to avoid duplicates
----------------------------------------------------------------
local function merge_tables(dest, src)
  for k, v in pairs(src) do
    if dest[k] == nil then
      dest[k] = v
    else
      if type(dest[k]) == "table" and type(v) == "table" then
        local function is_array(t)
          local n = 0
          for kk in pairs(t) do
            if type(kk) == "number" then n = n + 1 end
          end
          return n > 0
        end
        local dest_arr = is_array(dest[k])
        local v_arr = is_array(v)
        if dest_arr and v_arr then
          local seen = {}
          for _, item in ipairs(dest[k]) do seen[tostring(item)] = true end
          for _, item in ipairs(v) do
            if not seen[tostring(item)] then table.insert(dest[k], item); seen[tostring(item)] = true end
          end
        else
          for kk, vv in pairs(v) do
            if dest[k][kk] == nil then dest[k][kk] = vv end
          end
        end
      else
        -- keep dest's scalar value (safer)
      end
    end
  end
end

local function merge_iface_into_list(iface_tbl, list)
  local name = iface_tbl.name
  if not name then
    table.insert(list, iface_tbl)
    return iface_tbl
  end

  local mapped_name = map_iface_name_to_eth(name)

  for _, existing in ipairs(list) do
    local existing_mapped = map_iface_name_to_eth(existing.name or existing)
    if existing.name == name or existing.name == mapped_name or existing_mapped == mapped_name then
      merge_tables(existing, iface_tbl)
      return existing
    end
  end

  iface_tbl.name = mapped_name
  table.insert(list, iface_tbl)
  return iface_tbl
end

----------------------------------------------------------------
-- Interface existence / operstate helpers
----------------------------------------------------------------
local function iface_is_present(ifname)
  if not ifname then return false end
  return file_exists("/sys/class/net/" .. ifname)
end

-- robust: read operstate preferring lanN for any ethN canonical name
local function sys_iface_operstate(ifname)
  if not ifname then return nil end

  local function read_oper(ifn)
    if not ifn then return nil end
    local path = "/sys/class/net/" .. ifn .. "/operstate"
    local f = io.open(path, "r")
    if not f then return nil end
    local s = f:read("*l")
    f:close()
    return s and s:match("^%s*(.-)%s*$") or nil
  end

  -- canonicalize (handles eth-0, eth_0, lan1, eth01, etc.)
  local canonical = ifname
  if type(map_iface_name_to_eth) == "function" then
    canonical = map_iface_name_to_eth(ifname) or canonical
  end

  -- if canonical is ethN => try lanN first
  local eth_index = canonical:match("^eth(%d+)$")
  if eth_index then
    local s = read_oper("lan" .. eth_index)
    if s then return s end
    -- try canonical (ethN) next
    s = read_oper(canonical)
    if s then return s end
  end

  -- try original raw name
  local s = read_oper(ifname)
  if s then return s end

  -- try mapped/canonical name (if not already tried)
  if canonical and canonical ~= ifname then
    s = read_oper(canonical)
    if s then return s end
  end

  return nil
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

-- improved iface_basic_info: reads MTU/MAC/speed from the actual kernel iface when present,
-- and uses sys_iface_operstate() (which prefers lanN for ethN)
local function iface_basic_info(name)
  local info = {}

  -- Prefer an existing kernel name: try original, then mapped canonical
  local actual = name
  if not iface_is_present(actual) and type(map_iface_name_to_eth) == "function" then
    local mapped = map_iface_name_to_eth(name)
    if mapped and iface_is_present(mapped) then actual = mapped end
  end

  -- read MTU/MAC from the actual (present) interface when possible
  local mtu_raw = read_first_line("/sys/class/net/"..actual.."/mtu")
  info.mtu = tonumber(mtu_raw)
  info.mac = read_first_line("/sys/class/net/"..actual.."/address")

  -- determine type using the actual interface (safer)
  if file_exists("/sys/class/net/"..actual.."/wireless") then
    info.type = "wireless"
  elseif file_exists("/sys/class/net/"..actual.."/bridge") then
    info.type = "bridge"
  elseif file_exists("/sys/class/net/"..actual.."/tun_flags") or name:match("^tun") or name:match("^tap") or name:match("^wg") then
    info.type = "virtual"
  elseif name == "modem" or name == "modem2" then
    info.type = "mobile"
  else
    info.type = "ethernet"
  end

  -- use sys_iface_operstate (which prefers lanN for any ethN canonical name)
  info.up = (sys_iface_operstate(name) == "up")

  -- read speed from actual iface if possible
  local speed = read_first_line("/sys/class/net/"..actual.."/speed")
  info.speed = speed and speed:gsub("%s+$", "") or nil

  return info
end


-- Lua 5.1 safe: robust iface_addresses + cached get_addresses
local cached_map = nil

local function iface_addresses()
  local map = {}
  local out = sh("ip -o addr show") or ""
  if out == "" then return map end

  for line in out:gmatch("[^\n]+") do
    -- tokenize by whitespace
    local fields = {}
    for f in line:gmatch("%S+") do table.insert(fields, f) end
    if #fields == 0 then
      -- nothing to do for this line
    else
      -- find 'inet' or 'inet6'
      local fam_idx, fam_token = nil, nil
      for i = 1, #fields do
        if fields[i] == "inet" or fields[i] == "inet6" then
          fam_idx = i
          fam_token = fields[i]
          break
        end
      end

      if fam_idx then
        local addr_tok = fields[fam_idx + 1]
        local peer_tok = nil

        -- find peer token if present
        for i = fam_idx + 1, math.min(#fields, fam_idx + 8) do
          if fields[i] == "peer" and fields[i + 1] then
            peer_tok = fields[i + 1]
            break
          end
        end

        if addr_tok == "peer" then addr_tok = fields[fam_idx + 2] end

        -- helper to detect IP-like token
        local function looks_like_ip_token(s)
          if not s then return false end
          if s:match("^%d+%.%d+%.%d+%.%d+/%d+$") then return true end
          if s:match("^%d+%.%d+%.%d+%.%d+$") then return true end
          if s:match("^[%x:]+/[%d]+$") then return true end
          if s:match("^[%x:]+%%[%w._-]+/[%d]+$") then return true end
          if s:match("^[%x:]+%%[%w._-]+$") then return true end
          if s:match("^[%x:]+$") then return true end
          return false
        end

        if not looks_like_ip_token(addr_tok) then
          for j = fam_idx + 1, math.min(#fields, fam_idx + 8) do
            if looks_like_ip_token(fields[j]) then
              addr_tok = fields[j]
              break
            end
          end
        end

        if addr_tok then
          local ip, mask = addr_tok:match("^([^/]+)/(%d+)$")
          ip = ip or addr_tok
          mask = tonumber(mask)

          -- try to get mask from peer token (peer x.x.x.x/NN)
          if not mask and peer_tok then
            local _, pmask = peer_tok:match("^([^/]+)/(%d+)$")
            mask = pmask and tonumber(pmask) or nil
          end

          local family = (fam_token == "inet") and "ipv4" or "ipv6"
          if family == "ipv6" then ip = ip:gsub("%%[%w._-]+$", "") end

          -- infer p2p mask if still missing and 'peer' present
          if not mask and line:find("%speer%s") then
            mask = (family == "ipv4") and 32 or 128
          end

          -- interface name normally fields[2]
          local ifname = fields[2] and fields[2]:gsub(":$", "") or nil
          if ifname and ip then
            map[ifname] = map[ifname] or {}
            local entry = { family = family, address = ip }
            if mask then entry.mask = mask end
            table.insert(map[ifname], entry)
          end
        end
      end
    end
  end

  return map
end

-- cache builder (call once per collect cycle)
local function build_address_cache()
  cached_map = iface_addresses() or {}
  return cached_map
end

-- safe accessor: always returns a table (never nil)
local function get_addresses(name)
  if not cached_map then build_address_cache() end
  return cached_map[name] or {}
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
-- read the eth interfaces file (zone, mode)
----------------------------------------------------------------
-- read the eth interfaces file (zone, mode)
local function read_iface_zone_mode(name)
  if not name then return nil end

  local function parse_file(path)
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
    if zone == nil and mode == nil then return nil end
    return { zone = zone, mode = mode }
  end

  -- check exact name first
  local p1 = "/tmp/" .. name .. ".info"
  local res = parse_file(p1)
  if res then return res end

  -- if not found, try canonical mapped name (eth-1 -> eth1, lan1 -> eth1)
  local mapped = map_iface_name_to_eth(name)
  if mapped and mapped ~= name then
    local p2 = "/tmp/" .. mapped .. ".info"
    res = parse_file(p2)
    if res then return res end
  end

  return nil
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
local f = io.open("/tmp/device_data.info","r")
if f then
  local s = f:read("*a"); f:close()
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
--local addr_map  = iface_addresses()
build_address_cache()


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

    -- statistics: take counters by original sys name, but attach to canonical mapped interface
    if monitor_all or include_stats[name] or include_stats[mapped_name] then
      local st = counters[name] or counters[mapped_name]
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

    -- addresses: prefer addr_map[original] or addr_map[mapped]
  -- per-interface (inside loop that builds netjson_interface)
  local addresses = get_addresses(name)
  if addresses and next(addresses) then
      netjson_interface.addresses = addresses
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

    -- MERGE into host_interfaces (this prevents eth-1 + eth1 duplicates)
    merge_iface_into_list(netjson_interface, host_interfaces)
  end
end

----------------------------------------------------------------
-- NEW: attach mobile JSON files safely (only if kernel exposes the interface)
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
  if not name then return nil end
  local mapped = map_iface_name_to_eth(name)
  for _, iface in ipairs(host_interfaces) do
    local existing_mapped = map_iface_name_to_eth(iface.name or iface)
    if iface.name == name or iface.name == mapped or existing_mapped == mapped then
      return iface
    end
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

  -- only act if kernel exposes the interface
  if not iface_is_present(ifname) and not iface_is_present(map_iface_name_to_eth(ifname)) then
    -- do not create any entry or set up flags for non-existing kernel interface
    -- keep orphan mobile info elsewhere if you want:
    monitoring._orphan_modems = monitoring._orphan_modems or {}
    table.insert(monitoring._orphan_modems, { name = ifname, mobile = mtable })
    return true
  end

  local existing = find_host_iface_by_name(ifname)
  local kernel_exists = iface_is_present(ifname) or iface_is_present(map_iface_name_to_eth(ifname))
  local mapped_name = map_iface_name_to_eth(ifname)

  -- prefer kernel operstate if present
  local oper = sys_iface_operstate(ifname) or sys_iface_operstate(mapped_name)
  local desired_up = false
  if oper == "up" then
    desired_up = true
  else
    if mtable.connection_status == "connected" and (not mtable.power_status or mtable.power_status ~= "off") and kernel_exists then
      desired_up = true
    else
      desired_up = false
    end
  end

  if existing then
    existing.mobile = existing.mobile or {}
    for k,v in pairs(mtable) do existing.mobile[k] = v end
    existing.up = desired_up
  else
    local new_iface = {
      name = mapped_name,
      type = "mobile",
      up   = desired_up,
      mobile = mtable
    }
    merge_iface_into_list(new_iface, host_interfaces)
  end
  return true
end

-- attach only when kernel interface exists
attach_mobile_file_to_iface("/tmp/mobile1.json", "modem")
attach_mobile_file_to_iface("/tmp/mobile2.json", "modem2")


-- Attach ping measurements from /tmp/ping_metrics.json to matching interfaces
local function normalize_ping_ifname(raw)
  if not raw then return nil end
  return map_iface_name_to_eth(tostring(raw))
end

-- helper: check if a ping srcip matches an iface.addresses
local function iface_matches_srcip(iface, srcip)
  if not srcip or not iface then return false end
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

-- find interface by name (canonicalized) or by source IP
local function find_host_interface(name, srcip)
  local mapped_name = name and map_iface_name_to_eth(name) or nil
  for _, iface in ipairs(host_interfaces) do
    -- match by passed name or canonicalized name
    if name and (iface.name == name or iface.name == mapped_name) then
      return iface
    end
    -- match by source ip if provided
    if srcip and iface_matches_srcip(iface, srcip) then
      return iface
    end
  end
  return nil
end

-- Extract throughput { tx_bytes = ..., rx_bytes = ... } from a ping record
local function extract_throughput_from_record(rec)
  if not rec then return nil end

  -- accept multiple naming styles
  local tx = rec.throughput_tx_bytes or rec.tx_bytes or rec.tx or rec["tx-bytes"]
  local rx = rec.throughput_rx_bytes or rec.rx_bytes or rec.rx or rec["rx-bytes"]

  if tx or rx then
    return {
      tx_bytes = tonumber(tx) or 0,
      rx_bytes = tonumber(rx) or 0
    }
  end

  return nil
end



do
  local ping_file = "/tmp/ping_metrics.json"
  local pings, perr = read_json_file(ping_file)
  if not pings or type(pings) ~= "table" then
    -- nothing to do
  else
    for _, rec in ipairs(pings) do
      local raw_ifname = rec["device_name"] or rec.device_name or rec["interface"] or rec.interface
      local srcip = rec["source_ip"]   or rec.source_ip   or rec["src ip"] or rec["src_ip"] or rec.src_ip or rec["src"] or rec.src

      local canonical_ifname = normalize_ping_ifname(raw_ifname)

      local target_iface = nil
      if canonical_ifname then
        target_iface = find_host_interface(canonical_ifname, nil)
      end
      if not target_iface and srcip then
        target_iface = find_host_interface(nil, srcip)
      end

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
        monitoring._orphan_pings = monitoring._orphan_pings or {}
        table.insert(monitoring._orphan_pings, rec)
      end
    end
  end
end



----------------------------------------------------------------
-- System-level DNS
----------------------------------------------------------------
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
-- Legacy KV readers for modem etc.  (only include if kernel interface exists)
----------------------------------------------------------------
local cellular_modem, cellular_modem2 = nil, nil
if iface_is_present("modem") or iface_is_present(map_iface_name_to_eth("modem")) then
  cellular_modem = read_kv_file("/tmp/modem_data.info")
end
if iface_is_present("modem2") or iface_is_present(map_iface_name_to_eth("modem2")) then
  cellular_modem2 = read_kv_file("/tmp/modem_data2.info")
end

if cellular_modem or cellular_modem2 then
  netjson.cellular = {}
  if cellular_modem then netjson.cellular.modem = cellular_modem end
  if cellular_modem2 then netjson.cellular.modem2 = cellular_modem2 end
end

netjson.wlan = {}
local wlan_kv = read_kv_file("/tmp/wlan.info")
if wlan_kv then netjson.wlan.wlan_data = wlan_kv end

netjson.device = {}
local device_kv = read_kv_file("/tmp/device.info")
if device_kv then netjson.device.device_info = device_kv end

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

-- === Read /tmp/ipsec.info and merge tunnels into netjson.ipsec.data.tunnels ===
do
  local ipsec_path = "/tmp/ipsec.info"
  local ipsec_data, perr = read_json_file(ipsec_path)

  -- ensure netjson.ipsec structure exists
  netjson.ipsec = netjson.ipsec or {}
  netjson.ipsec.data = netjson.ipsec.data or {}
  netjson.ipsec.data.tunnels = netjson.ipsec.data.tunnels or {}

  if not ipsec_data then
    -- nothing to merge, optionally log perr (if you have logging)
  else
    -- possible shapes:
    -- 1) { "tunnels": { "tunnels": [ ... ] } }
    -- 2) { "tunnels": [ ... ] }
    -- 3) { ... } (maybe already the expected object)
    local incoming = nil
    if type(ipsec_data) == "table" then
      if ipsec_data.tunnels and type(ipsec_data.tunnels) == "table" and ipsec_data.tunnels.tunnels then
        incoming = ipsec_data.tunnels.tunnels
      elseif ipsec_data.tunnels and type(ipsec_data.tunnels) == "table" then
        incoming = ipsec_data.tunnels
      elseif ipsec_data.tunnels == nil and ipsec_data.tunnels == nil and next(ipsec_data) ~= nil then
        -- fallback: if file already contains the exact data object we expect
        -- (e.g. ipsec_data = { data = { tunnels = {...} } }) try to find it:
        if ipsec_data.data and ipsec_data.data.tunnels then
          incoming = ipsec_data.data.tunnels
        end
      end
    end

    -- Build existing id map for dedupe
    local existing_ids = {}
    for _, t in ipairs(netjson.ipsec.data.tunnels) do
      if type(t) == "table" and t.id then existing_ids[t.id] = true end
    end

    -- If incoming is a table/array, append deduped entries
    if type(incoming) == "table" then
      for _, t in ipairs(incoming) do
        if type(t) == "table" then
          local id = t.id
          if id and not existing_ids[id] then
            table.insert(netjson.ipsec.data.tunnels, t)
            existing_ids[id] = true
          elseif not id then
            -- no id: append anyway (can't dedupe)
            table.insert(netjson.ipsec.data.tunnels, t)
          end
        end
      end
    else
      -- No tunnels array found; if ipsec_data looks like a full data object, merge it in
      -- Only set netjson.ipsec.data.raw if needed for debugging/inspection
      netjson.ipsec.data.raw = netjson.ipsec.data.raw or ipsec_data
    end
  end
end


local ipsec_data, terr = read_json_file("/tmp/ipsec.info")
if not ipsec_data then ipsec_data = {} end

netjson.ipsec = {
  data = ipsec_data
}

-- final output
local ok, out = pcall(cjson.encode, netjson)
if not ok then
  io.stderr:write("error encoding output JSON: "..tostring(out).."\n")
  os.exit(1)
end
io.write(out)

