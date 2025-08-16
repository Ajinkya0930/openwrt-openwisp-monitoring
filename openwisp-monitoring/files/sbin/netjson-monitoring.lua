#!/usr/bin/env lua

-- retrieve monitoring information
-- and return it as NetJSON Output
package.path = package.path .. ";../files/lib/?.lua"

local nixio = require("nixio")
local uci = require("uci").cursor()
local cjson = require('cjson')
local io = require('io')

local ubus_lib = require('ubus')
local ubus = ubus_lib.connect()
if not ubus then error('Failed to connect to ubusd') end

local monitoring = require('openwisp-monitoring.monitoring')

-- collect system info
local system_info = ubus:call('system', 'info', {})
local board = ubus:call('system', 'board', {})
local loadavg_file = io.popen('cat /proc/loadavg')
local loadavg_output = loadavg_file:read()
loadavg_file:close()
loadavg_output = monitoring.utils.split(loadavg_output, ' ')
local load_average = {
  tonumber(loadavg_output[1]), tonumber(loadavg_output[2]),
  tonumber(loadavg_output[3])
}

local sernum_file = io.popen('cat /sys/class/dmi/id/board_serial')
local serial_number = sernum_file:read()
sernum_file:close()


-- init netjson data structure
local netjson = {
  type = 'DeviceMonitoring',
  general = {
    hostname = board.hostname,
    local_time = system_info.localtime,
    uptime = system_info.uptime,
    serialnumber = serial_number
  },
  resources = {
    load = load_average,
    memory = system_info.memory,
    swap = system_info.swap,
    cpus = monitoring.resources.get_cpus(),
    disk = monitoring.resources.parse_disk_usage()
  }
}

local dhcp_leases = monitoring.dhcp.get_dhcp_leases()
if not monitoring.utils.is_table_empty(dhcp_leases) then
  netjson.dhcp_leases = dhcp_leases
end

local host_neighbors = monitoring.neighbors.get_neighbors()
if not monitoring.utils.is_table_empty(host_neighbors) then
  netjson.neighbors = host_neighbors
end

-- determine the interfaces to monitor
local arg = {...}
local traffic_monitored = arg[1]
local include_stats = {}
if traffic_monitored and traffic_monitored ~= '*' then
  traffic_monitored = monitoring.utils.split(traffic_monitored, ' ')
  for _, name in pairs(traffic_monitored) do include_stats[name] = true end
end

-- collect device data
local network_status = ubus:call('network.device', 'status', {})
local wireless_status = ubus:call('network.wireless', 'status', {})
local vpn_interfaces = monitoring.interfaces.get_vpn_interfaces()
local wireless_interfaces = {}
local host_interfaces = {}
local dns_servers = {}
local dns_search = {}

-- collect relevant wireless interface stats
for _, radio in pairs(wireless_status) do
  for _, interface in ipairs(radio.interfaces) do
    local name = interface.ifname
    local is_mesh = false
    local clients = nil
    if name and not monitoring.utils.is_excluded(name) then
      local iwinfo = ubus:call('iwinfo', 'info', {device = name})
      local netjson_interface = {
        name = name,
        type = 'wireless',
        wireless = {
          ssid = iwinfo.ssid,
          mode = monitoring.wifi.iwinfo_modes[iwinfo.mode] or iwinfo.mode,
          channel = iwinfo.channel,
          frequency = iwinfo.frequency,
          tx_power = iwinfo.txpower,
          signal = iwinfo.signal,
          noise = iwinfo.noise,
          country = iwinfo.country
        }
      }
      if iwinfo.mode == 'Ad-Hoc' or iwinfo.mode == 'Mesh Point' then
        clients = ubus:call('iwinfo', 'assoclist', {device = name}).results
        is_mesh = true
      else
        local hostapd_output = ubus:call('hostapd.' .. name, 'get_clients', {})
        if hostapd_output then clients = hostapd_output.clients end
      end
      if not monitoring.utils.is_table_empty(clients) then
        netjson_interface.wireless.clients =
          monitoring.wifi.netjson_clients(clients, is_mesh)
      end
      wireless_interfaces[name] = netjson_interface
    end
  end
end

-- collect interface stats
for name, interface in pairs(network_status) do
  if not monitoring.utils.is_excluded(name) then
    local netjson_interface = {
      name = name,
      type = string.lower(interface.type),
      up = interface.up,
      mac = interface.macaddr,
      txqueuelen = interface.txqueuelen,
      mtu = interface.mtu,
      speed = interface.speed,
      bridge_members = interface['bridge-members'],
      multicast = interface.multicast
    }

    if interface['bridge-members'] ~= nil then
      local bridge_members = {}
      for _, bridge_member in ipairs(interface['bridge-members']) do
        if network_status[bridge_member] then
          local network_interface = network_status[bridge_member]
          if network_interface.up and network_interface.present then
            table.insert(bridge_members, bridge_member)
          end
        end
      end
      netjson_interface['bridge_members'] = bridge_members
    end
    if wireless_interfaces[name] then
      monitoring.utils.dict_merge(wireless_interfaces[name], netjson_interface)
      interface.type = netjson_interface.type
    end
    if interface.type == 'Network device' then
      local link_supported = interface['link-supported']
      if link_supported and next(link_supported) then
        netjson_interface.type = 'ethernet'
        netjson_interface.link_supported = link_supported
      elseif vpn_interfaces[name] then
        netjson_interface.type = 'virtual'
      else
        netjson_interface.type = 'other'
      end
    end
    if include_stats[name] or traffic_monitored == '*' then
      if monitoring.wifi.needs_inversion(netjson_interface) then
        interface.statistics = monitoring.wifi.invert_rx_tx(interface.statistics)
      end
      netjson_interface.statistics = interface.statistics
    end
    local addresses = monitoring.interfaces.get_addresses(name)
    if next(addresses) then netjson_interface.addresses = addresses end
    local info = monitoring.interfaces.get_interface_info(name, netjson_interface)
    if info.stp ~= nil then netjson_interface.stp = info.stp end
    if info.specialized then
      for key, value in pairs(info.specialized) do netjson_interface[key] = value end
    end
    table.insert(host_interfaces, netjson_interface)
    if info.dns_servers then
      monitoring.utils.array_concat(info.dns_servers, dns_servers)
    end
    if info.dns_search then
      monitoring.utils.array_concat(info.dns_search, dns_search)
    end
  end
end

if next(host_interfaces) ~= nil then netjson.interfaces = host_interfaces end
if next(dns_servers) ~= nil then netjson.dns_servers = dns_servers end
if next(dns_search) ~= nil then netjson.dns_search = dns_search end


-- This function is common to all when we read the data from the /etc/config file..................................                                               
local function read_config(config_name)
    local result = {}

    -- Check if config file exists
    if not nixio.fs.access("/etc/config/" .. config_name) then
        return result  -- return empty table if missing
    end

    -- Function to rename keys starting with "."
    local function remove_dot_prefix(tbl)
        local cleaned = {}
        for k, v in pairs(tbl) do
            if string.sub(k, 1, 1) == "." then
                cleaned[string.sub(k, 2)] = v  -- remove first character "."
            else
                cleaned[k] = v
            end
        end
        return cleaned
    end

    -- Read all sections and clean key names
    uci:foreach(config_name, nil, function(s)
        result[#result+1] = remove_dot_prefix(s)
    end)

    return result
end

-- This function for /etc/frr/ read config from this files.......................................................
local function read_frr_config(filename)
    local result = {}
    local full_path = "/etc/frr/" .. filename
    if not nixio.fs.access(full_path) then
        return result
    end
    local file = io.open(full_path, "r")
    if file then
        result.content = file:read("*all")
        file:close()
    end
    return result
end
 
-- Collect data of System ......taking data of snmp,tr069,icmp check, schedule
netjson.system = {
	snmp      = read_config("snmp"),
	tr069     = read_config("tr069"),
	icmpcheck = read_config("icmpcheck"),
	schedule  = read_config("schedule")
}

-- Add firewall information
netjson.firewall = {
    port_forward = {
	ubus:call('ns.redirects', 'list-redirects', {}) or {}
    },
    nat = {
	rules = ubus:call('ns.nat', 'list-rules', {}) or {},
	netmap = ubus:call('ns.netmap', 'list-rules', {}) or {},
	nat_helper = ubus:call('ns.nathelpers', 'list-nat-helpers', {}) or {}
    },
    rules = {
 	zones = ubus:call('ns.firewall', 'list_zones', {}) or {},
 	forwardings = ubus:call('ns.firewall', 'list_forwardings', {}) or {},
 	input_rules = ubus:call('ns.firewall', 'list-input-rules', {}) or {},
	output_rules = ubus:call('ns.firewall', 'list-output-rules', {}) or {},
	forward_rules = ubus:call('ns.firewall', 'list-forward-rules', {}) or {},
	redirects = ubus:call('ns.firewall', 'list_redirects', {}) or {}
    },
    connections = {
	ubus:call('ns.conntrack', 'list', {}) or {}
    }
}


-- Collect data of Network --> DNS and DHCP tab.
netjson.network = {
    DNS_DHCP = {
	DHCP_MAC = ubus:call('ns.dhcp', 'list-interfaces', {}) or {} ,
	Static_Lease = ubus:call('ns.dhcp', 'list-static-leases', {}) or {} ,
	Dynamic_Lease = ubus:call('ns.dhcp', 'list-active-leases', {}) or {} ,
	DNS = ubus:call('ns.dns', 'get-config', {}) or {} ,
	DNS_Records = ubus:call('ns.dns', 'list-records', {}) or {} ,
 	Scan_Network = ubus:call('ns.scan', 'list-interfaces', {}) or {} 
    },
    Routes = {
	IPV4_Routes = ubus:call('ns.routes', 'list-routes', {protocol = 'ipv4'}) or {},
	IPV4_Maintable = ubus:call('ns.routes', 'main-table', {protocol = 'ipv4'}) or {},
	IPV6_Routes = ubus:call('ns.routes', 'list-routes', {protocol = 'ipv6'}) or {},
	IPV6_Maintable = ubus:call('ns.routes', 'main-table', {protocol = 'ipv6'}) or {}
    },
    VxLan = read_config("vxlan"), 
    FlowEdge_Multiwan = {
	Multiwan_Manager = { Manager_Policy = ubus:call('ns.mwan', 'index_policies', {}) or {},
	Manager_Rules = ubus:call('ns.mwan', 'index_rules', {}) or {} },
	General_Settings = { ubus:call('ns.mwan', 'get_default_config', {}) or {}}
    },
    LoadBalance = read_config("loadbalance"),
    Reverse_Proxy = { ubus:call('ns.reverseproxy', 'list-proxies', {}) or {} },
    QoS = { ubus:call('ns.qos', 'list', {}) or {} },
    Advanced_QoS = read_config("advance_qos"),
    RIP = read_frr_config("ripd.conf"),
    OSPF = read_frr_config("ospfd.conf"),
    BGP = read_frr_config("bgpd.conf"),
    VRF = read_config("vrf")
    
}

-- Collect data of VPN tab 
netjson.vpn = {
	OpenVPN_Tunnel = { ubus:call('ns.ovpntunnel', 'list-tunnels', {}) or {} },
	IPSec_Tunnel = { server_tunnel = read_config("ipsec"),
	Static_Lease = ubus:call('ns.ipsectunnel', 'list-tunnels', {}) or {} },
	L2TP = { server = read_config("l2tp_server") }, 
	VRRP = read_config("vrrp"),
	ZeroTier = read_config("zerotier"),
	Wireguard = { server = read_config("wireguard") },
	OpenVPN = {
		Instance = ubus:call('ns.ovpnrw', 'list-instances', {}) or {},
		Configuration = ubus:call('ns.ovpnrw', 'get-configuration', { instance = "ns_roadwarrior1" }) or {}
    }
}

-- Collect Security data from tab
netjson.security = {
     InstaShield_Field = {
	blocklist_feeds = ubus:call('ns.threatshield', 'list-blocklist', {}) or {},
	local_allowlist = ubus:call('ns.threatshield', 'list-allowed', {}) or {},
	local_blocklist = ubus:call('ns.threatshield', 'list-blocked', {}) or {},
	settings = ubus:call('ns.threatshield', 'list-settings', {}) or {}
     },
     Instashield_DNS = {
	blocklist_sources = ubus:call('ns.threatshield', 'dns-list-blocklist', {}) or {},
	Filter_bypass = ubus:call('ns.threatshield', 'dns-list-bypass', {}) or {},
	local_blocklist = ubus:call('ns.threatshield', 'dns-list-blocked', {}) or {},
	settings = ubus:call('ns.threatshield', 'dns-list-settings', {}) or {}
     },
     DPI = {
	rules = ubus:call('ns.dpi', 'list-rules', {}) or {},
	exceptions = ubus:call('ns.dpi', 'list-exemptions', {}) or {}
     },
     IPS = {
	today_event_list = ubus:call('ns.snort', 'list-events', {}) or {},
        filter_bypass = ubus:call('ns.snort', 'list-bypasses', {}) or {},
        disabled_rules = ubus:call('ns.snort', 'list-disabled-rules', {}) or {},
        suppressed_alerts = ubus:call('ns.snort', 'list-suppressed-alerts', {}) or {},
        settings = ubus:call('ns.snort', 'settings', {}) or {}
     },
     Antivirus = read_config("clamv"),
     Antispam = read_config("rspamd")

}


io.write(cjson.encode(netjson))
return cjson.encode(netjson)



