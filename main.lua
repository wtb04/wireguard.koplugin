local DataStorage = require("datastorage")
local Dispatcher = require("dispatcher")
local Font = require("ui/font")
local InfoMessage = require("ui/widget/infomessage")
local UIManager = require("ui/uimanager")
local WidgetContainer = require("ui/widget/container/widgetcontainer")
local logger = require("logger")
local _ = require("gettext")

local WG_BIN     = "/usr/bin/wg"
local WG_GO_BIN  = "/usr/bin/wireguard-go"
local TUN_DEV    = "/dev/net/tun"
local STATE_FILE = "/tmp/wireguard_state"
local DNS_BACKUP = "/tmp/resolv.wg.bak"

local WireGuard = WidgetContainer:extend{
    name = "wireguard",
    is_doc_only = false,
}

local function fileExists(path)
    local f = io.open(path, "r")
    if f then f:close(); return true end
    return false
end

local function exec(cmd)
    logger.dbg("WireGuard:", cmd)
    local h = io.popen(cmd .. " 2>&1")
    if not h then return false, "popen failed" end
    local out = h:read("*a") or ""
    local ok = h:close()
    return ok, out
end

-- Everything from a .conf file reaches a root shell, so values are whitelisted
-- on load and quoted at the point of use.
local function shquote(s)
    return "'" .. (tostring(s):gsub("'", "'\\''")) .. "'"
end

local function isIPv4(s)
    local octets = { s:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$") }
    if #octets ~= 4 then return false end
    for _, o in ipairs(octets) do
        if #o > 3 or tonumber(o) > 255 then return false end
    end
    return true
end

local function isIPv6(s)
    return s:match("^[%x:]+$") ~= nil and s:find(":") ~= nil
end

local function isIP(s)
    return isIPv4(s) or isIPv6(s)
end

local function isHostname(s)
    return #s <= 253 and s:match("^%w[%w%.%-]*$") ~= nil
end

local function isCIDR(s)
    local addr, prefix = s:match("^(.+)/(%d+)$")
    if not addr then return false end
    if isIPv4(addr) then return tonumber(prefix) <= 32 end
    if isIPv6(addr) then return tonumber(prefix) <= 128 end
    return false
end

-- Interface names are interpolated into Lua patterns as well as shell
-- commands, and a config may legitimately be named "home-vpn".
local function patternEscape(s)
    return (s:gsub("[%^%$%(%)%%%.%[%]%*%+%-%?]", "%%%0"))
end

local function info(text, timeout)
    UIManager:show(InfoMessage:new{ text = text, timeout = timeout or 4 })
end

function WireGuard:init()
    self.conf_dir = DataStorage:getFullDataDir() .. "/plugins/wireguard.koplugin/configs"
    os.execute("mkdir -p '" .. self.conf_dir .. "'")

    -- Load version (and other metadata) from the plugin's own _meta.lua so
    -- we don't have to keep it in sync in two places.
    local meta_path = debug.getinfo(1, "S").source:sub(2):gsub("main%.lua$", "_meta.lua")
    local ok, meta = pcall(dofile, meta_path)
    self.meta = ok and meta or {}

    self:onDispatcherRegisterActions()

    if self.ui and self.ui.menu then
        self.ui.menu:registerToMainMenu(self)
    end
end

function WireGuard:onDispatcherRegisterActions()
    Dispatcher:registerAction("wireguard_connect",    { category="none", event="WireguardConnect",    title=_("WireGuard connect"),    general=true,})
    Dispatcher:registerAction("wireguard_disconnect", { category="none", event="WireguardDisconnect", title=_("WireGuard disconnect"), general=true,})
    Dispatcher:registerAction("wireguard_toggle",     { category="none", event="WireguardToggle",     title=_("WireGuard toggle"),     general=true,})
    Dispatcher:registerAction("wireguard_status",     { category="none", event="WireguardStatus",     title=_("WireGuard status"),     general=true, separator=true,})
end

function WireGuard:onWireguardConnect()
    self:connect()
end

function WireGuard:onWireguardDisconnect()
    self:disconnect()
end

function WireGuard:onWireguardToggle()
    if self:isUp() then
        self:disconnect()
    else
        self:connect()
    end
end

function WireGuard:onWireguardStatus()
    self:showStatus()
end

function WireGuard:missingRequirements()
    local missing = {}
    if not fileExists(WG_BIN)    then table.insert(missing, WG_BIN) end
    if not fileExists(WG_GO_BIN) then table.insert(missing, WG_GO_BIN) end
    if not fileExists(TUN_DEV)   then table.insert(missing, TUN_DEV) end
    return missing
end

function WireGuard:hasRequirements()
    return #self:missingRequirements() == 0
end

-- Parse a wg-quick style .conf into:
--   wg_conf: pure [Interface]/[Peer] text suitable for `wg setconf`
--   iface:   { addresses, dns, mtu, endpoint, allowed_ips }
--   raw:     the original file contents
function WireGuard:parseConfig(path)
    local f = io.open(path, "r")
    if not f then return nil, "Cannot open " .. path end
    local text = f:read("*a")
    f:close()

    local iface = { addresses = {}, dns = {}, mtu = nil, endpoint = nil, allowed_ips = {} }
    local wg_lines = {}
    local quick_keys = {
        address = true, dns = true, mtu = true, table = true,
        preup = true, postup = true, predown = true, postdown = true,
        saveconfig = true,
    }

    local in_interface = false
    for line in text:gmatch("[^\r\n]+") do
        local trimmed = line:match("^%s*(.-)%s*$")
        if trimmed == "" or trimmed:sub(1, 1) == "#" then
            table.insert(wg_lines, line)
        elseif trimmed:lower():match("^%[interface%]") then
            in_interface = true
            table.insert(wg_lines, line)
        elseif trimmed:lower():match("^%[peer%]") then
            in_interface = false
            table.insert(wg_lines, line)
        else
            local key, val = trimmed:match("^(%S+)%s*=%s*(.+)$")
            local lk = key and key:lower()
            if in_interface and lk and quick_keys[lk] then
                if lk == "address" then
                    for addr in val:gmatch("[^,%s]+") do table.insert(iface.addresses, addr) end
                elseif lk == "dns" then
                    for dns in val:gmatch("[^,%s]+") do table.insert(iface.dns, dns) end
                elseif lk == "mtu" then
                    iface.mtu = val:match("^%d+")
                end
            else
                if lk == "endpoint" and not iface.endpoint then
                    iface.endpoint = val
                elseif lk == "allowedips" then
                    for cidr in val:gmatch("[^,%s]+") do
                        table.insert(iface.allowed_ips, cidr)
                    end
                end
                table.insert(wg_lines, line)
            end
        end
    end

    return table.concat(wg_lines, "\n") .. "\n", iface, text
end

function WireGuard:getEndpointHost(endpoint)
    if not endpoint then return nil end
    return endpoint:match("^%[(.+)%]:%d+$") or endpoint:match("^(.+):%d+$")
end

function WireGuard:resolveHost(host)
    if isIP(host) then return host end
    local _ok, out = exec("getent hosts " .. shquote(host))
    local first = (out or ""):match("^(%S+)")
    if first and isIP(first) then return first end
    return nil
end

function WireGuard:getDefaultGateway()
    local ok, out = exec("ip route show default")
    if ok and out then
        return out:match("via%s+(%S+)"), out:match("dev%s+(%S+)")
    end
end

function WireGuard:saveState(iface_name, routes)
    local f = io.open(STATE_FILE, "w")
    if not f then return end
    f:write(iface_name .. "\n")
    for _, r in ipairs(routes) do f:write(r .. "\n") end
    f:close()
end

-- Routes are stored as "<dest> dev <iface>" or "<dest> via <gw> dev <iface>".
local function parseStoredRoute(line)
    local dest, gw, dev = line:match("^(%S+) via (%S+) dev (%S+)$")
    if dest then
        if not (isCIDR(dest) or isIP(dest)) then return nil end
        if not isIP(gw) or not dev:match("^[%w_%-]+$") then return nil end
        return "ip route del " .. shquote(dest) .. " via " .. shquote(gw) .. " dev " .. shquote(dev)
    end
    dest, dev = line:match("^(%S+) dev (%S+)$")
    if dest and (isCIDR(dest) or isIP(dest)) and dev:match("^[%w_%-]+$") then
        return "ip route del " .. shquote(dest) .. " dev " .. shquote(dev)
    end
    return nil
end

function WireGuard:loadState()
    local f = io.open(STATE_FILE, "r")
    if not f then return nil, {} end
    local iface_name = f:read("*l")
    local routes = {}
    for line in f:lines() do
        if line ~= "" then table.insert(routes, line) end
    end
    f:close()
    if iface_name and not iface_name:match("^[%w_%-]+$") then return nil, {} end
    return iface_name, routes
end

function WireGuard:getConfigs()
    local configs = {}
    local h = io.popen("ls -1 '" .. self.conf_dir .. "/' 2>/dev/null")
    if h then
        for line in h:lines() do
            local name = line:match("^(.+)%.conf$")
            if name then
                table.insert(configs, { name = name, path = self.conf_dir .. "/" .. line })
            end
        end
        h:close()
    end
    return configs
end

function WireGuard:isUp()
    local ok, out = exec(WG_BIN .. " show interfaces")
    return ok and (out or ""):gsub("%s+", "") ~= ""
end

function WireGuard:getActiveInterface()
    local ok, out = exec(WG_BIN .. " show interfaces")
    if ok and out then return out:match("^(%S+)") end
end

function WireGuard:killProcess(iface_name)
    local pf = io.open("/var/run/wireguard/" .. iface_name .. ".pid", "r")
    if not pf then return end
    local pid = pf:read("*l")
    pf:close()
    if pid and pid:match("^%d+$") then exec("kill " .. pid) end
end

function WireGuard:waitForInterface(iface_name, attempts)
    for _ = 1, attempts or 6 do
        os.execute("sleep 0.5")
        local _ok, out = exec("ip link show " .. shquote(iface_name))
        if (out or ""):find(iface_name, 1, true) then return true end
    end
    return false
end

function WireGuard:connectConfig(config)
    info(_("Connecting ") .. config.name .. "…", 1)
    UIManager:forceRePaint()

    local ok, err = pcall(self._doConnect, self, config)
    if not ok then
        logger.warn("WireGuard: connect error:", err)
        info(_("WireGuard error:\n") .. tostring(err):sub(1, 800), 6)
    end
end

-- Returns wg_conf, iface, raw on success; nil, error_message on failure.
function WireGuard:_loadAndValidateConfig(config)
    local iface_name = config.name
    if not iface_name:match("^[%w_%-]+$") then
        return nil, _("Invalid config name. Use only letters, digits, '_' and '-'.")
    end

    local wg_conf, iface, raw = self:parseConfig(config.path)
    if not wg_conf then
        return nil, _("Failed to parse config:\n") .. (iface or "")
    end

    if #iface.addresses == 0 then
        return nil, _("Config is missing an 'Address = ...' line in [Interface].\n\nAdd e.g.\n  Address = 10.0.0.2/32")
    end
    if not raw:match("[Pp]eer") or not raw:match("[Pp]ublic[Kk]ey") then
        return nil, _("Config has no valid [Peer] section.")
    end

    for _i, addr in ipairs(iface.addresses) do
        if not addr:match("/%d+$") then
            return nil, _("Address '") .. addr .. _("' has no /prefix (e.g. /32 or /24).")
        end
        if not isCIDR(addr) then
            return nil, _("Address '") .. addr .. _("' is not a valid IP address.")
        end
    end

    for _i, dns in ipairs(iface.dns) do
        if not isIP(dns) then
            return nil, _("DNS '") .. dns .. _("' is not a valid IP address.")
        end
    end

    for _i, cidr in ipairs(iface.allowed_ips) do
        if not isCIDR(cidr) then
            return nil, _("AllowedIPs entry '") .. cidr .. _("' is not a valid network.")
        end
    end

    if iface.endpoint then
        local host = self:getEndpointHost(iface.endpoint)
        if not host or not (isIP(host) or isHostname(host)) then
            return nil, _("Endpoint '") .. iface.endpoint .. _("' is not a valid host:port.")
        end
    end

    return wg_conf, iface, raw
end

function WireGuard:_writeTempConfig(iface_name, wg_conf)
    local tmp_conf = "/tmp/wg_" .. iface_name .. ".conf"
    local f = io.open(tmp_conf, "w")
    if not f then return nil, _("Cannot write temp config to /tmp") end
    f:write(wg_conf); f:close()
    os.execute("chmod 600 '" .. tmp_conf .. "'")
    return tmp_conf
end

function WireGuard:_isInterfacePresent(iface_name)
    local _ok, out = exec("ip link show " .. shquote(iface_name))
    return (out or ""):match("%d+:%s+" .. patternEscape(iface_name) .. ":") ~= nil
end

-- Starts wireguard-go and loads the config. Returns ok, err.
function WireGuard:_spawnInterface(iface_name, tmp_conf)
    os.execute(WG_GO_BIN .. " " .. shquote(iface_name) .. " >/dev/null 2>&1 &")
    if not self:waitForInterface(iface_name) then
        return false, _("wireguard-go did not create interface '") .. iface_name
            .. _("'.\n\nCheck that /dev/net/tun exists and ") .. WG_GO_BIN .. _(" is executable.")
    end

    local ok, out = exec(WG_BIN .. " setconf " .. shquote(iface_name) .. " " .. shquote(tmp_conf))
    if not ok then return false, _("wg setconf failed:\n") .. (out or "") end
    return true
end

-- Assigns addresses, sets MTU, brings link up. Returns ok, err; appends MTU
-- failures to warnings.
function WireGuard:_configureInterface(iface_name, iface, warnings)
    for _i, addr in ipairs(iface.addresses) do
        local ok, out = exec("ip addr add " .. shquote(addr) .. " dev " .. shquote(iface_name))
        if not ok and not (out or ""):match("File exists") then
            return false, _("Failed to add address ") .. addr .. ":\n" .. (out or "")
        end
    end

    local _v, addr_out = exec("ip addr show " .. shquote(iface_name))
    if not (addr_out or ""):match("inet ") then
        return false, _("Address assignment silently failed (no IPv4 on interface).\n\n") .. (addr_out or "")
    end

    if iface.mtu then
        local ok, out = exec("ip link set mtu " .. shquote(iface.mtu) .. " dev " .. shquote(iface_name))
        if not ok then table.insert(warnings, "MTU: " .. (out or "")) end
    end

    local ok, out = exec("ip link set " .. shquote(iface_name) .. " up")
    if not ok then return false, _("Failed to bring up interface:\n") .. (out or "") end
    return true
end

-- Pin the endpoint to the original default route so handshake packets
-- don't try to traverse the tunnel they're trying to establish.
function WireGuard:_pinEndpointRoute(iface, tracked, warnings)
    local host = self:getEndpointHost(iface.endpoint)
    if not host then return end

    local endpoint_ip = self:resolveHost(host)
    if not endpoint_ip then
        table.insert(warnings, "Could not resolve endpoint host '" .. host .. "'")
        return
    end

    local gw, gw_dev = self:getDefaultGateway()
    if not (gw and gw_dev) then
        table.insert(warnings, "No default route, endpoint exception not added")
        return
    end

    local route = endpoint_ip .. " via " .. gw .. " dev " .. gw_dev
    local ok, out = exec("ip route add " .. shquote(endpoint_ip)
        .. " via " .. shquote(gw) .. " dev " .. shquote(gw_dev))
    if ok then
        table.insert(tracked, route)
    elseif not (out or ""):match("File exists") then
        table.insert(warnings, "Endpoint route: " .. (out or ""))
    end
end

-- Installs routes for every AllowedIPs entry. Returns ok, err; err is set
-- only if at least one route was attempted and they all failed.
function WireGuard:_installAllowedIPs(iface, iface_name, tracked, warnings)
    local attempted, added = 0, 0
    local function addRoute(cmd, label)
        attempted = attempted + 1
        local rok, rout = exec(cmd)
        if rok then
            table.insert(tracked, label)
            added = added + 1
        elseif not (rout or ""):match("File exists") then
            table.insert(warnings, "route '" .. label .. "': " .. (rout or ""))
        end
    end

    local dev = " dev " .. shquote(iface_name)
    for _, cidr in ipairs(iface.allowed_ips) do
        if cidr == "0.0.0.0/0" then
            -- Two /1 routes beat the existing default without replacing it.
            addRoute("ip route add 0.0.0.0/1" .. dev, "0.0.0.0/1 dev " .. iface_name)
            addRoute("ip route add 128.0.0.0/1" .. dev, "128.0.0.0/1 dev " .. iface_name)
        elseif cidr:match(":") then
            addRoute("ip -6 route add " .. shquote(cidr) .. dev, cidr .. " dev " .. iface_name)
        else
            addRoute("ip route add " .. shquote(cidr) .. dev, cidr .. " dev " .. iface_name)
        end
    end

    if attempted > 0 and added == 0 then
        return false, _("All routes failed to install:\n") .. table.concat(warnings, "\n")
    end
    return true
end

function WireGuard:_writeResolvConf(dns, warnings)
    if #dns == 0 then return end
    if not exec("cp /etc/resolv.conf " .. DNS_BACKUP) then
        table.insert(warnings, "Could not back up /etc/resolv.conf")
    end
    local r = io.open("/etc/resolv.conf", "w")
    if r then
        for _, d in ipairs(dns) do r:write("nameserver " .. d .. "\n") end
        r:close()
    else
        table.insert(warnings, "Could not write /etc/resolv.conf")
    end
end

function WireGuard:_doConnect(config)
    local wg_conf, iface, raw = self:_loadAndValidateConfig(config)
    if not wg_conf then info(iface, 8); return end

    local iface_name = config.name

    if self:_isInterfacePresent(iface_name) then
        info(_("Interface '") .. iface_name .. _("' already exists. Disconnect first."), 6)
        return
    end

    local tmp_conf, terr = self:_writeTempConfig(iface_name, wg_conf)
    if not tmp_conf then info(terr, 6); return end

    local tracked = {}
    local warnings = {}

    local function abort(msg)
        exec("ip link del dev " .. shquote(iface_name))
        self:killProcess(iface_name)
        os.remove(tmp_conf)
        info(msg, 8)
    end

    local ok, err = self:_spawnInterface(iface_name, tmp_conf)
    if not ok then abort(err); return end

    ok, err = self:_configureInterface(iface_name, iface, warnings)
    if not ok then abort(err); return end

    self:_pinEndpointRoute(iface, tracked, warnings)

    ok, err = self:_installAllowedIPs(iface, iface_name, tracked, warnings)
    if not ok then abort(err); return end

    self:_writeResolvConf(iface.dns, warnings)

    self:saveState(iface_name, tracked)
    os.remove(tmp_conf)

    local msg = _("WireGuard connected: ") .. iface_name
    if #warnings > 0 then
        info(msg .. "\n\n" .. _("Warnings:\n  ") .. table.concat(warnings, "\n  "), 8)
    else
        info(msg, 3)
    end
end

function WireGuard:connect(touchmenu_instance)
    if not self:hasRequirements() then
        info(_("Missing requirements:\n  ") .. table.concat(self:missingRequirements(), "\n  "), 8)
        return
    end

    local configs = self:getConfigs()
    if #configs == 0 then
        info(_("No .conf files found.\n\nPlace WireGuard configs in:\n") .. self.conf_dir .. "/", 6)
        return
    end

    if #configs == 1 then
        self:connectConfig(configs[1])
        if touchmenu_instance then touchmenu_instance:updateItems() end
        return
    end

    local ButtonDialog = require("ui/widget/buttondialog")
    local buttons, dlg = {}, nil
    for _, cfg in ipairs(configs) do
        table.insert(buttons, {{
            text = cfg.name,
            callback = function()
                UIManager:close(dlg)
                self:connectConfig(cfg)
                if touchmenu_instance then touchmenu_instance:updateItems() end
            end,
        }})
    end
    table.insert(buttons, {{
        text = _("Cancel"),
        callback = function() UIManager:close(dlg) end,
    }})

    dlg = ButtonDialog:new{ title = _("Choose WireGuard config"), buttons = buttons }
    UIManager:show(dlg)
end

function WireGuard:disconnect(touchmenu_instance)
    local iface_name, routes = self:loadState()
    if not iface_name or iface_name == "" then
        iface_name = self:getActiveInterface()
        if not iface_name then
            info(_("No active WireGuard tunnel."), 3)
            return
        end
        routes = {}
    end

    info(_("Disconnecting WireGuard…"), 1)
    UIManager:forceRePaint()

    for _, route in ipairs(routes) do
        local cmd = parseStoredRoute(route)
        if cmd then exec(cmd) end
    end
    exec("ip link del dev " .. shquote(iface_name))
    self:killProcess(iface_name)

    if fileExists(DNS_BACKUP) then
        exec("cp " .. DNS_BACKUP .. " /etc/resolv.conf")
    end

    os.remove(STATE_FILE)
    os.remove(DNS_BACKUP)

    if touchmenu_instance then touchmenu_instance:updateItems() end
    info(_("WireGuard disconnected."), 3)
end

function WireGuard:showStatus()
    local lines = {}

    -- Header
    local title = (self.meta and self.meta.fullname) or "WireGuard VPN"
    if self.meta and self.meta.version then
        title = title .. " v" .. self.meta.version
    end
    table.insert(lines, title)
    table.insert(lines, "")

    -- Requirements
    local missing = self:missingRequirements()
    if #missing > 0 then
        table.insert(lines, _("Missing requirements:"))
        if not fileExists(WG_BIN)    then table.insert(lines, "  \u{2717} wg (" .. WG_BIN .. ")") end
        if not fileExists(WG_GO_BIN) then table.insert(lines, "  \u{2717} wireguard-go (" .. WG_GO_BIN .. ")") end
        if not fileExists(TUN_DEV)   then table.insert(lines, "  \u{2717} " .. TUN_DEV) end
    else
        table.insert(lines, _("\u{2713} All requirements installed."))
    end

    -- Active tunnel.
    if fileExists(WG_BIN) then
        local _ok, out = exec(WG_BIN .. " show")
        out = (out or ""):gsub("%s+$", "")
        table.insert(lines, "")
        if out == "" then
            table.insert(lines, _("No active WireGuard interfaces."))
        else
            table.insert(lines, _("Active tunnel:"))
            table.insert(lines, out)
        end
    end

    -- Configs
    local configs = self:getConfigs()
    table.insert(lines, "")
    if #configs == 0 then
        table.insert(lines, _("No configs found in:"))
        table.insert(lines, "  " .. self.conf_dir)
    else
        table.insert(lines, _("Configs:"))
        for _, c in ipairs(configs) do
            table.insert(lines, "  \u{2022} " .. c.name)
        end
    end

    -- Footer
    table.insert(lines, "")
    table.insert(lines, _("Made by Wouter ten Brinke"))
    table.insert(lines, "https://woutertenbrinke.nl")
    table.insert(lines, "")
    table.insert(lines, _("\"WireGuard\" is a registered trademark of Jason A. Donenfeld. This plugin is not affiliated with or endorsed by the WireGuard project."))
    table.insert(lines, "https://www.wireguard.com/")

    UIManager:show(InfoMessage:new{
        text = table.concat(lines, "\n"),
        face = Font:getFace("infofont", 18),
    })
end

function WireGuard:addToMainMenu(menu_items)
    menu_items.wireguard = {
        sorting_hint = "network",
        text = _("WireGuard VPN"),
        sub_item_table = {
            {
                text_func = function()
                    if not self:hasRequirements() then return _("WireGuard not available") end
                    if self:isUp() then return _("Disconnect WireGuard") end
                    return _("Connect WireGuard")
                end,
                keep_menu_open = true,
                callback = function(touchmenu_instance)
                    if self:isUp() then
                        self:disconnect(touchmenu_instance)
                    else
                        self:connect(touchmenu_instance)
                    end
                end,
            },
            {
                text = _("Status"),
                callback = function() self:showStatus() end,
            },
        },
    }
end

-- Exposed for tests/run.lua.
WireGuard._shquote          = shquote
WireGuard._isIP             = isIP
WireGuard._isCIDR           = isCIDR
WireGuard._isHostname       = isHostname
WireGuard._patternEscape    = patternEscape
WireGuard._parseStoredRoute = parseStoredRoute

return WireGuard
