-- Run with: lua tests/run.lua
-- Loads main.lua with the KOReader modules stubbed out, so no device and no
-- KOReader install is needed. If main.lua starts requiring another KOReader
-- module, add a stub below.

package.loaded["datastorage"] = { getFullDataDir = function() return "/tmp" end }
package.loaded["dispatcher"] = { registerAction = function() end }
package.loaded["ui/font"] = {}
package.loaded["ui/widget/infomessage"] = { new = function() return {} end }
package.loaded["ui/uimanager"] = { show = function() end, forceRePaint = function() end }
package.loaded["ui/widget/container/widgetcontainer"] = { extend = function(_, t) return t end }
package.loaded["logger"] = { dbg = function() end, warn = function() end }
package.loaded["gettext"] = function(s) return s end

local root = debug.getinfo(1, "S").source:sub(2):gsub("tests[/\\][^/\\]*$", "")
local loaded, WG = pcall(dofile, root .. "main.lua")
if not loaded then
    io.stderr:write("could not load main.lua. If it now requires a KOReader module\n"
        .. "that is not stubbed at the top of this file, add it.\n\n" .. tostring(WG) .. "\n")
    os.exit(1)
end

local failed = 0

local function check(name, got, want)
    local ok, result = pcall(function() return got end)
    if not ok then
        failed = failed + 1
        print(string.format("FAIL %s\n  threw: %s", name, tostring(result)))
    elseif result ~= want then
        failed = failed + 1
        print(string.format("FAIL %s\n  want %s\n  got  %s", name, tostring(want), tostring(result)))
    else
        print("ok   " .. name)
    end
end

local function tmpconf(body)
    local path = os.tmpname()
    local f = assert(io.open(path, "w"))
    f:write(body)
    f:close()
    return path
end

-- A payload that would run a command if it ever reached a shell unquoted.
local PAYLOAD = "$(id>/tmp/pwned)"

print("shquote")
check("neutralises substitution", WG._shquote(PAYLOAD), "'" .. PAYLOAD .. "'")
check("escapes a single quote", WG._shquote("a'b"), [['a'\''b']])
check("leaves a plain value usable", WG._shquote("10.0.0.1"), "'10.0.0.1'")

print("\nvalue whitelists")
check("plain ipv4", WG._isIP("192.168.1.1"), true)
check("octet over 255", WG._isIP("192.168.1.256"), false)
check("payload is not an ip", WG._isIP(PAYLOAD), false)
check("ipv6", WG._isIP("2001:db8::1"), true)
check("cidr", WG._isCIDR("10.0.0.0/24"), true)
check("cidr prefix too large", WG._isCIDR("10.0.0.0/33"), false)
check("payload is not a cidr", WG._isCIDR(PAYLOAD .. "/32"), false)
check("hostname", WG._isHostname("vpn.example.com"), true)
check("payload is not a hostname", WG._isHostname(PAYLOAD), false)
check("hostname with a space", WG._isHostname("a b"), false)

print("\nconfig parsing ignores comments")
local commented = tmpconf([[
[Interface]
PrivateKey = aaaa
Address = 10.0.0.2/32

[Peer]
PublicKey = bbbb
# Endpoint = ]] .. PAYLOAD .. [[:1
Endpoint = vpn.example.com:51820
#AllowedIPs = 0.0.0.0/0
AllowedIPs = 10.20.30.0/24
]])
local _conf, iface = WG:parseConfig(commented)
os.remove(commented)
check("live endpoint wins over commented", iface.endpoint, "vpn.example.com:51820")
check("commented AllowedIPs ignored", #iface.allowed_ips, 1)
check("only the real network is kept", iface.allowed_ips[1], "10.20.30.0/24")

print("\nhostile config is rejected on load")
local hostile = tmpconf([[
[Interface]
PrivateKey = aaaa
Address = 10.0.0.2/32

[Peer]
PublicKey = bbbb
Endpoint = ]] .. PAYLOAD .. [[:51820
AllowedIPs = 0.0.0.0/0
]])
local conf, err = WG:_loadAndValidateConfig({ name = "test", path = hostile })
os.remove(hostile)
check("config is refused", conf, nil)
check("error names the endpoint", (tostring(err):find("Endpoint", 1, true) ~= nil), true)

local bad_allowed = tmpconf([[
[Interface]
PrivateKey = aaaa
Address = 10.0.0.2/32

[Peer]
PublicKey = bbbb
AllowedIPs = ]] .. PAYLOAD .. [[

]])
local conf2, err2 = WG:_loadAndValidateConfig({ name = "test", path = bad_allowed })
os.remove(bad_allowed)
check("bad AllowedIPs is refused", conf2, nil)
check("error names AllowedIPs", (tostring(err2):find("AllowedIPs", 1, true) ~= nil), true)

print("\ninterface names used as patterns")
local link = "6: home-vpn: <POINTOPOINT,NOARP> mtu 1420 state UNKNOWN"
check("hyphen name matches itself",
    link:match("%d+:%s+" .. WG._patternEscape("home-vpn") .. ":") ~= nil, true)
check("unescaped hyphen name does not",
    link:match("%d+:%s+home-vpn:") ~= nil, false)

print("\nstored routes")
check("via form", WG._parseStoredRoute("1.2.3.4 via 192.168.1.1 dev wlan0"),
    "ip route del '1.2.3.4' via '192.168.1.1' dev 'wlan0'")
check("on-link form", WG._parseStoredRoute("10.0.0.0/24 dev wg0"),
    "ip route del '10.0.0.0/24' dev 'wg0'")
check("payload is refused", WG._parseStoredRoute(PAYLOAD .. " dev wg0"), nil)
check("junk is refused", WG._parseStoredRoute("nonsense"), nil)

if failed > 0 then
    print("\n" .. failed .. " failed")
    os.exit(1)
end
print("\nall passed")
