package.path = package.path .. ";../files/lib/?.lua"

local monitoring = {}

monitoring.dhcp = require('nexapp-monitoring.dhcp')
monitoring.interfaces = require('nexapp-monitoring.interfaces')
monitoring.neighbors = require('nexapp-monitoring.neighbors')
monitoring.resources = require('nexapp-monitoring.resources')
monitoring.utils = require('nexapp-monitoring.utils')
monitoring.wifi = require('nexapp-monitoring.wifi')

local success, iwinfo = pcall(require, 'nexapp-monitoring.iwinfo')
if success then
  monitoring.iwinfo = iwinfo
else
  monitoring.iwinfo = {
    enabled = false
  }
end

return monitoring
