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

-- `got` is a thunk so a validator that throws is reported as one failed
-- check rather than aborting the run.
local function check(name, got, want)
    local ok, result = pcall(got)
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
check("neutralises substitution", function() return WG._shquote(PAYLOAD) end, "'" .. PAYLOAD .. "'")
check("escapes a single quote", function() return WG._shquote("a'b") end, [['a'\''b']])
check("leaves a plain value usable", function() return WG._shquote("10.0.0.1") end, "'10.0.0.1'")

print("\nvalue whitelists")
check("plain ipv4", function() return WG._isIP("192.168.1.1") end, true)
check("octet over 255", function() return WG._isIP("192.168.1.256") end, false)
check("payload is not an ip", function() return WG._isIP(PAYLOAD) end, false)
check("ipv6", function() return WG._isIP("2001:db8::1") end, true)
check("cidr", function() return WG._isCIDR("10.0.0.0/24") end, true)
check("cidr prefix too large", function() return WG._isCIDR("10.0.0.0/33") end, false)
check("payload is not a cidr", function() return WG._isCIDR(PAYLOAD .. "/32") end, false)
check("hostname", function() return WG._isHostname("vpn.example.com") end, true)
check("payload is not a hostname", function() return WG._isHostname(PAYLOAD) end, false)
check("hostname with a space", function() return WG._isHostname("a b") end, false)

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
check("live endpoint wins over commented", function() return iface.endpoint end, "vpn.example.com:51820")
check("commented AllowedIPs ignored", function() return #iface.allowed_ips end, 1)
check("only the real network is kept", function() return iface.allowed_ips[1] end, "10.20.30.0/24")

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
check("config is refused", function() return conf end, nil)
check("error names the endpoint", function() return (tostring(err):find("Endpoint", 1, true) ~= nil) end, true)

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
check("bad AllowedIPs is refused", function() return conf2 end, nil)
check("error names AllowedIPs", function() return (tostring(err2):find("AllowedIPs", 1, true) ~= nil) end, true)

print("\nconfig name limits")
local okconf = tmpconf("[Interface]\nPrivateKey = aaaa\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = bbbb\nAllowedIPs = 10.0.0.0/24\n")
check("a name the kernel cannot use is refused",
    function() return (WG:_loadAndValidateConfig({ name = "a-name-that-is-too-long", path = okconf })) end, nil)
check("a normal name is accepted",
    function() return (WG:_loadAndValidateConfig({ name = "my-vpn", path = okconf })) ~= nil end, true)
os.remove(okconf)

print("\ninterface names used as patterns")
local link = "6: my-vpn: <POINTOPOINT,NOARP> mtu 1420 state UNKNOWN"
check("hyphen name matches itself", function() return link:match("%d+:%s+" .. WG._patternEscape("my-vpn") .. ":") ~= nil end, true)
check("unescaped hyphen name does not", function() return link:match("%d+:%s+my-vpn:") ~= nil end, false)

print("\nstored routes")
check("via form", function() return WG._parseStoredRoute("1.2.3.4 via 192.168.1.1 dev wlan0") end, "ip route del '1.2.3.4' via '192.168.1.1' dev 'wlan0'")
check("on-link form", function() return WG._parseStoredRoute("10.0.0.0/24 dev wg0") end, "ip route del '10.0.0.0/24' dev 'wg0'")
check("payload is refused", function() return WG._parseStoredRoute(PAYLOAD .. " dev wg0") end, nil)
check("junk is refused", function() return WG._parseStoredRoute("nonsense") end, nil)

print("\nconfigs that are valid for wg are still accepted")
check("bare address in AllowedIPs (wg reads it as /32)",
    function() return WG._isCIDR("10.0.0.5") or WG._isIP("10.0.0.5") end, true)
check("hostname with an underscore", function() return WG._isHostname("vpn_gw.example.com") end, true)
check("vlan device in a stored route",
    function() return WG._parseStoredRoute("1.2.3.4 via 192.168.1.1 dev eth0.100") ~= nil end, true)
check("aliased device in a stored route",
    function() return WG._parseStoredRoute("10.0.0.0/24 dev wlan0:1") ~= nil end, true)

print("\ninterface presence is not fooled by an error message")
local missing = 'Device "wg0" does not exist.'
check("strict pattern rejects the error text",
    function() return missing:match("%d+:%s+" .. WG._patternEscape("wg0") .. ":") ~= nil end, false)
check("strict pattern accepts a real link line",
    function() return ("6: wg0: <POINTOPOINT> mtu 1420"):match("%d+:%s+" .. WG._patternEscape("wg0") .. ":") ~= nil end, true)

print("\nendpoint is read back from wg, not resolved again")
local two_peers = tmpconf([[
[Interface]
PrivateKey = aaaa
Address = 10.0.0.2/32

[Peer]
PublicKey = lan+peer/key=
AllowedIPs = 10.0.0.3/32

[Peer]
Endpoint = vpn.example.com:51820
PublicKey = server+key/abc=
AllowedIPs = 0.0.0.0/0
]])
local _c, ep_iface = WG:parseConfig(two_peers)
os.remove(two_peers)
check("endpoint is tied to its own peer, even when listed before PublicKey",
    function() return ep_iface.endpoint_key end, "server+key/abc=")
local endpoints = "lan+peer/key=\t(none)\nserver+key/abc=\t1.2.3.4:51820\n"
check("address is taken from the matching peer",
    function() return WG._endpointIPFor(endpoints, "server+key/abc=") end, "1.2.3.4")
check("peer without an endpoint gives nothing",
    function() return WG._endpointIPFor(endpoints, "lan+peer/key=") end, nil)
check("unknown peer gives nothing",
    function() return WG._endpointIPFor(endpoints, "other=") end, nil)
check("bracketed ipv6 endpoint",
    function() return WG._endpointIPFor("k=\t[2001:db8::1]:51820\n", "k=") end, "2001:db8::1")
check("no wg output gives nothing", function() return WG._endpointIPFor(nil, "k=") end, nil)

print("\nexec reports the real exit status")
-- Run through a real shell: this is what close() got wrong on the device.
check("a failing command is a failure", function() return (WG._exec("false")) end, false)
check("a succeeding command is a success", function() return (WG._exec("true")) end, true)
check("output comes back without the marker",
    function() return select(2, WG._exec("echo hello")) end, "hello\n")
check("output without a trailing newline is kept as is",
    function() return select(2, WG._exec("printf abc")) end, "abc")
check("stderr is captured", function() return select(2, WG._exec("echo oops >&2; false")) end, "oops\n")
check("a missing command is a failure",
    function() return (WG._exec("/nonexistent/getent hosts x")) end, false)
check("missing marker counts as failure", function() return (WG._parseExecOutput("partial")) end, false)
check("nonzero code", function() return (WG._parseExecOutput("x\n\n__wg_exit=2\n")) end, false)
check("marker text inside the output does not confuse it",
    function() return select(2, WG._parseExecOutput("a\n__wg_exit=1\n\n__wg_exit=0\n")) end, "a\n__wg_exit=1\n")

-- Replaces io.popen so connect steps can be driven with scripted output.
-- `script` maps a substring of the command to { output, exit code }.
local function withFakeShell(script, fn)
    local real = io.popen
    io.popen = function(cmd)
        for needle, res in pairs(script) do
            if cmd:find(needle, 1, true) then
                return { read = function() return res[1] .. "\n__wg_exit=" .. res[2] .. "\n" end,
                         close = function() return true end }
            end
        end
        return { read = function() return "\n__wg_exit=0\n" end, close = function() return true end }
    end
    local ok, a, b = pcall(fn)
    io.popen = real
    if not ok then error(a, 0) end
    return a, b
end

print("\nroutes that already exist")
check("a route the kernel already added does not abort the connect", function()
    local tracked, warnings = {}, {}
    local ok = withFakeShell({ ["ip route add"] = { "RTNETLINK answers: File exists", 2 } }, function()
        return WG:_installAllowedIPs({ allowed_ips = { "10.0.0.0/24" } }, "wg0", tracked, warnings)
    end)
    return ok == true and #tracked == 0 and #warnings == 0
end, true)
check("a route that really fails is not tracked", function()
    local tracked, warnings = {}, {}
    local ok = withFakeShell({ ["ip route add"] = { "RTNETLINK answers: Network is down", 2 } }, function()
        return WG:_installAllowedIPs({ allowed_ips = { "10.0.0.0/24" } }, "wg0", tracked, warnings)
    end)
    return ok == false and #tracked == 0
end, true)

if failed > 0 then
    print("\n" .. failed .. " failed")
    os.exit(1)
end
print("\nall passed")
