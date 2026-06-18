require 'config'
local match = string.match
local ngxmatch = ngx.re.match
local unescape = ngx.unescape_uri
local get_headers = ngx.req.get_headers
local optionIsOn = function(options) return options == "on" and true or false end

logpath = logdir
rulepath = RulePath
UrlDeny = optionIsOn(UrlDeny)
PostCheck = optionIsOn(postMatch)
CookieCheck = optionIsOn(CookieMatch)
WhiteCheck = optionIsOn(whiteModule)
attacklog = optionIsOn(attacklog)
CCDeny = optionIsOn(CCDeny)
Redirect = optionIsOn(Redirect)

-- 获取客户端真实IP
function getClientIp()
    local IP = ngx.var.remote_addr
    if IP == nil then
        IP = "unknown"
    end
    return IP
end

-- 写入日志文件
function write(logfile, msg)
    local fd = io.open(logfile, "ab")
    if fd == nil then return end
    fd:write(msg)
    fd:flush()
    fd:close()
end

-- 记录攻击日志（JSON格式，便于前端解析）
function log(method, url, data, ruletag, attack_type)
    if attacklog then
        local realIp = getClientIp()
        local ua = ngx.var.http_user_agent or "-"
        local servername = ngx.var.server_name or "unknown"
        local time = ngx.localtime()
        attack_type = attack_type or "unknown"
        
        -- JSON格式日志
        local log_entry = string.format(
            '{"time":"%s","ip":"%s","server":"%s","method":"%s","url":"%s","data":"%s","ua":"%s","rule":"%s","type":"%s"}\n',
            time, realIp, servername, method, url, data or "-", ua, ruletag or "-", attack_type
        )
        
        local filename = logpath .. '/' .. servername .. "_" .. ngx.today() .. "_sec.log"
        write(filename, log_entry)
        
        -- 同时记录到访问日志（用于实时统计）
        local access_filename = logpath .. '/' .. servername .. "_access.log"
        local access_entry = string.format(
            '{"time":"%s","ip":"%s","url":"%s","ua":"%s","status":"blocked","type":"%s"}\n',
            time, realIp, url, ua, attack_type
        )
        write(access_filename, access_entry)
    end
end

-- 记录正常访问日志
function log_access()
    local realIp = getClientIp()
    local ua = ngx.var.http_user_agent or "-"
    local servername = ngx.var.server_name or "unknown"
    local time = ngx.localtime()
    local url = ngx.var.request_uri or "-"
    
    local access_filename = logpath .. '/' .. servername .. "_access.log"
    local access_entry = string.format(
        '{"time":"%s","ip":"%s","url":"%s","ua":"%s","status":"normal","type":"access"}\n',
        time, realIp, url, ua
    )
    write(access_filename, access_entry)
end

-- 读取规则文件
function read_rule(var)
    file = io.open(rulepath .. '/' .. var, "r")
    if file == nil then
        return {}
    end
    t = {}
    for line in file:lines() do
        if line and line ~= "" then
            table.insert(t, line)
        end
    end
    file:close()
    return t
end

-- 加载规则
urlrules = read_rule('url')
argsrules = read_rule('args')
uarules = read_rule('user-agent')
wturlrules = read_rule('whiteurl')
postrules = read_rule('post')
ckrules = read_rule('cookie')

-- 返回拦截页面
function say_html()
    if Redirect then
        ngx.header.content_type = "text/html"
        ngx.status = ngx.HTTP_FORBIDDEN
        ngx.say(html)
        ngx.exit(ngx.status)
    end
end

-- URL白名单检查
function whiteurl()
    if WhiteCheck and SITE_RULES.whiteurl then
        if wturlrules ~= nil then
            for _, rule in pairs(wturlrules) do
                if rule ~= "" and ngxmatch(ngx.var.uri, rule, "isjo") then
                    return true
                end
            end
        end
    end
    return false
end

-- 文件扩展名检查
function fileExtCheck(ext)
    local items = Set(black_fileExt)
    ext = string.lower(ext)
    if ext then
        for rule in pairs(items) do
            if ngx.re.match(ext, rule, "isjo") then
                log('POST', ngx.var.request_uri, "-", "file attack with ext " .. ext, "file_upload")
                say_html()
            end
        end
    end
    return false
end

function Set(list)
    local set = {}
    for _, l in ipairs(list) do set[l] = true end
    return set
end

-- GET参数检查
function args()
    if not SITE_RULES.args then return false end
    for _, rule in pairs(argsrules) do
        local args = ngx.req.get_uri_args()
        for key, val in pairs(args) do
            if type(val) == 'table' then
                local t = {}
                for k, v in pairs(val) do
                    if v == true then v = "" end
                    table.insert(t, v)
                end
                data = table.concat(t, " ")
            else
                data = val
            end
            if data and type(data) ~= "boolean" and rule ~= "" and ngxmatch(unescape(data), rule, "isjo") then
                log('GET', ngx.var.request_uri, "-", rule, "args_attack")
                say_html()
                return true
            end
        end
    end
    return false
end

-- URL检查
function url()
    if not SITE_RULES.url then return false end
    if UrlDeny then
        for _, rule in pairs(urlrules) do
            if rule ~= "" and ngxmatch(ngx.var.request_uri, rule, "isjo") then
                log('GET', ngx.var.request_uri, "-", rule, "url_attack")
                say_html()
                return true
            end
        end
    end
    return false
end

-- User-Agent检查
function ua()
    if not SITE_RULES.useragent then return false end
    local ua = ngx.var.http_user_agent
    if ua ~= nil then
        for _, rule in pairs(uarules) do
            if rule ~= "" and ngxmatch(ua, rule, "isjo") then
                log('UA', ngx.var.request_uri, "-", rule, "ua_attack")
                say_html()
                return true
            end
        end
    end
    return false
end

-- POST内容检查
function body(data)
    if not SITE_RULES.post then return false end
    for _, rule in pairs(postrules) do
        if rule ~= "" and data ~= "" and ngxmatch(unescape(data), rule, "isjo") then
            log('POST', ngx.var.request_uri, data, rule, "post_attack")
            say_html()
            return true
        end
    end
    return false
end

-- Cookie检查
function cookie()
    if not SITE_RULES.cookie then return false end
    local ck = ngx.var.http_cookie
    if CookieCheck and ck then
        for _, rule in pairs(ckrules) do
            if rule ~= "" and ngxmatch(ck, rule, "isjo") then
                log('Cookie', ngx.var.request_uri, "-", rule, "cookie_attack")
                say_html()
                return true
            end
        end
    end
    return false
end

-- CC防御
function denycc()
    if CCDeny then
        local uri = ngx.var.uri
        CCcount = tonumber(string.match(CCrate, '(.*)/'))
        CCseconds = tonumber(string.match(CCrate, '/(.*)'))
        local token = getClientIp() .. uri
        local limit = ngx.shared.bt_waf_limit
        local req, _ = limit:get(token)
        if req then
            if req > CCcount then
                log('CC', ngx.var.request_uri, "-", "CC attack", "cc_attack")
                ngx.exit(503)
                return true
            else
                limit:incr(token, 1)
            end
        else
            limit:set(token, 1, CCseconds)
        end
    end
    return false
end

-- 获取multipart boundary
function get_boundary()
    local header = get_headers()["content-type"]
    if not header then
        return nil
    end
    if type(header) == "table" then
        header = header[1]
    end
    local m = match(header, ";%s*boundary=\"([^\"]+)\"")
    if m then
        return m
    end
    return match(header, ";%s*boundary=([^\",;]+)")
end

-- IP白名单检查
function whiteip()
    if next(ipWhitelist) ~= nil then
        for _, ip in pairs(ipWhitelist) do
            if getClientIp() == ip then
                return true
            end
        end
    end
    return false
end

-- IP黑名单检查
function blockip()
    if next(ipBlocklist) ~= nil then
        for _, ip in pairs(ipBlocklist) do
            if getClientIp() == ip then
                ngx.exit(403)
                return true
            end
        end
    end
    return false
end