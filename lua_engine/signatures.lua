local M = {}

local KNOWN_PYTHON_JA3 = {
    ["87e2668215f385b4ea50bcc9cbe4279d"] = "Python Standard OpenSSL / Curl Without Impersonation"
}

local KNOWN_CHROME_JA3 = {
    ["9304e3aa198a88b489cf8f746d01802f"] = "Chrome 124 / BoringSSL Impersonation",
    ["ba212f99ff217fd39f5aa1bb85465fe6"] = "Chrome 124 / BoringSSL Impersonation"
}

local function contains_plain(haystack, needle)
    if type(haystack) ~= "string" or type(needle) ~= "string" then
        return false
    end
    return string.find(string.lower(haystack), string.lower(needle), 1, true) ~= nil
end

function M.classify_tls(tls_ctx)
    local result = {
        profile = "UNKNOWN_CLIENT",
        confidence = "LOW",
        findings = {}
    }

    if tls_ctx == nil then
        return result
    end

    local ja3 = tostring(tls_ctx.ja3 or "")
    local ja4 = tostring(tls_ctx.ja4 or "")
    local claimed_ua = tostring(tls_ctx.claimed_ua or "")
    local is_grease = tls_ctx.is_grease_present == true
    local cipher_count = tonumber(tls_ctx.cipher_count) or 0
    local extension_count = tonumber(tls_ctx.extension_count) or 0
    local has_h2_alpn = tls_ctx.has_h2_alpn == true
    local is_websocket = tls_ctx.is_websocket == true

    if KNOWN_PYTHON_JA3[ja3] ~= nil then
        result.profile = "PYTHON_OR_LIBCURL_DEFAULT"
        result.confidence = "HIGH"
    elseif KNOWN_CHROME_JA3[ja3] ~= nil then
        result.profile = "CHROMIUM_BORINGSSL"
        result.confidence = "HIGH"
    end

    local claims_chrome = contains_plain(claimed_ua, "chrome/") and not contains_plain(claimed_ua, "edg/")
    local claims_modern_browser = claims_chrome or contains_plain(claimed_ua, "firefox/")

    if claims_chrome and not is_grease then
        table.insert(result.findings, {
            rule_id = "LUA_TLS_NON_BROWSER_PROFILE",
            detail = "Lua signature engine confirmed Chrome UA paired with non-GREASE TLS stack (" .. ja4 .. ")"
        })
        result.profile = "NON_BROWSER_TLS_STACK"
        result.confidence = "HIGH"
    end

    if claims_modern_browser and not has_h2_alpn and not is_websocket and extension_count > 0 then
        table.insert(result.findings, {
            rule_id = "LUA_TLS_NON_BROWSER_PROFILE",
            detail = "Missing HTTP/2 (h2) ALPN negotiation expected from modern browser engines"
        })
    end

    if cipher_count > 0 and cipher_count < 6 and claims_modern_browser then
        table.insert(result.findings, {
            rule_id = "LUA_TLS_NON_BROWSER_PROFILE",
            detail = "Abnormally narrow TLS cipher suite count (" .. tostring(cipher_count) .. ") for claimed browser"
        })
    end

    if result.profile == "UNKNOWN_CLIENT" and is_grease and (has_h2_alpn or is_websocket) then
        result.profile = "CHROMIUM_BORINGSSL_STACK"
        result.confidence = "HIGH"
    end

    return result
end

return M