local M = {}

local function contains_plain(haystack, needle)
    if type(haystack) ~= "string" or type(needle) ~= "string" then
        return false
    end
    return string.find(string.lower(haystack), string.lower(needle), 1, true) ~= nil
end

local function normalize_headers(raw_headers)
    local lowered = {}
    if raw_headers == nil then
        return lowered
    end
    for k, v in pairs(raw_headers) do
        if type(k) == "string" then
            lowered[string.lower(k)] = tostring(v)
        end
    end
    return lowered
end

function M.evaluate_l7(ctx)
    local out = {
        tls_profile = "NO_TLS_CONTEXT",
        findings = {}
    }

    if ctx == nil then
        return out
    end

    local claimed_ua = tostring(ctx.claimed_ua or "")
    local is_websocket = ctx.is_websocket == true
    local webgl_renderer = tostring(ctx.webgl_renderer or "")
    local headers = normalize_headers(ctx.headers)
    local upgrade_hdr = headers["upgrade"] or ""
    local is_ws_upgrade = is_websocket or contains_plain(upgrade_hdr, "websocket")
    local sig_module = rawget(_G, "SignatureModule")

    if ctx.tls ~= nil and sig_module ~= nil then
        local tls_payload = {
            ja3 = ctx.tls.ja3,
            ja4 = ctx.tls.ja4,
            claimed_ua = claimed_ua,
            is_grease_present = ctx.tls.is_grease_present,
            cipher_count = ctx.tls.cipher_count,
            extension_count = ctx.tls.extension_count,
            has_h2_alpn = ctx.tls.has_h2_alpn,
            is_websocket = is_ws_upgrade
        }
        local tls_res = sig_module.classify_tls(tls_payload)
        out.tls_profile = tostring(tls_res.profile or "UNKNOWN")
        if tls_res.findings ~= nil then
            for _, item in ipairs(tls_res.findings) do
                table.insert(out.findings, item)
            end
        end
    end

    local bot_ua_tokens = {
        "python-requests",
        "python-urllib",
        "httpx",
        "aiohttp",
        "go-http-client",
        "curl/",
        "scrapy"
    }

    for _, token in ipairs(bot_ua_tokens) do
        if contains_plain(claimed_ua, token) then
            table.insert(out.findings, {
                rule_id = "LUA_PYTHON_CLIENT_HEADERS",
                detail = "Explicit automation library signature in User-Agent: " .. token
            })
            break
        end
    end

    local claims_chrome = contains_plain(claimed_ua, "chrome/") and not contains_plain(claimed_ua, "edg/")

    if claims_chrome and not is_ws_upgrade then
        local sec_ch_ua = headers["sec-ch-ua"]
        local sec_fetch_mode = headers["sec-fetch-mode"]
        local accept_hdr = headers["accept"] or ""

        if sec_ch_ua == nil and sec_fetch_mode == nil then
            table.insert(out.findings, {
                rule_id = "LUA_MISSING_CLIENT_HINTS",
                detail = "Chrome UA missing mandatory Sec-CH-UA and Sec-Fetch-Mode HTTP headers"
            })
        end

        if accept_hdr == "*/*" and headers["accept-language"] == nil then
            table.insert(out.findings, {
                rule_id = "LUA_PYTHON_CLIENT_HEADERS",
                detail = "Default programmatic HTTP client headers (Accept: */* without Accept-Language)"
            })
        end
    end

    if webgl_renderer ~= "" then
        local claims_macos = contains_plain(claimed_ua, "macintosh") or contains_plain(claimed_ua, "mac os x")
        local claims_windows = contains_plain(claimed_ua, "windows nt")

        local gpu_is_direct3d = contains_plain(webgl_renderer, "direct3d") or contains_plain(webgl_renderer, "d3d11")
        local gpu_is_apple = contains_plain(webgl_renderer, "apple m") or contains_plain(webgl_renderer, "apple gpu")

        if claims_macos and gpu_is_direct3d then
            table.insert(out.findings, {
                rule_id = "LUA_USER_AGENT_WEBGL_OS_MISMATCH",
                detail = "User-Agent claims macOS, but WebGL reports Windows-exclusive Direct3D renderer"
            })
        elseif claims_windows and gpu_is_apple then
            table.insert(out.findings, {
                rule_id = "LUA_USER_AGENT_WEBGL_OS_MISMATCH",
                detail = "User-Agent claims Windows, but WebGL reports Apple Silicon GPU renderer"
            })
        end
    end

    return out
end

return M