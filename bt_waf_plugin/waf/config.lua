-- BT-WAF 配置文件
-- 支持按站点独立配置

local json = require "cjson"
local io = require "io"

-- 获取当前站点配置
local function get_site_config()
    local server_name = ngx.var.server_name or "default"
    local config_file = "/www/server/panel/plugin/bt_waf/waf/sites/" .. server_name .. ".json"
    
    -- 读取站点配置
    local file = io.open(config_file, "r")
    if file then
        local content = file:read("*a")
        file:close()
        local ok, config = pcall(json.decode, content)
        if ok and config then
            return config
        end
    end
    
    -- 返回默认配置
    return {
        attacklog = "on",
        logdir = "/www/server/panel/plugin/bt_waf/waf/logs/",
        UrlDeny = "on",
        Redirect = "on",
        CookieMatch = "on",
        postMatch = "on",
        whiteModule = "on",
        CCDeny = "on",
        CCrate = "100/60",
        ipWhitelist = {},
        ipBlocklist = {},
        black_fileExt = {"php", "jsp"},
        rules = {
            args = true,
            url = true,
            post = true,
            cookie = true,
            useragent = true,
            whiteurl = true
        }
    }
end

-- 全局配置（向后兼容）
RulePath = "/www/server/panel/plugin/bt_waf/waf/wafconf/"
attacklog = "on"
logdir = "/www/server/panel/plugin/bt_waf/waf/logs/"
UrlDeny = "on"
Redirect = "on"
CookieMatch = "on"
postMatch = "on"
whiteModule = "on"
CCDeny = "on"
CCrate = "100/60"
ipWhitelist = {}
ipBlocklist = {}
black_fileExt = {"php", "jsp"}

-- 获取站点配置
local site_config = get_site_config()

-- 应用站点配置
if site_config.attacklog then attacklog = site_config.attacklog end
if site_config.logdir then logdir = site_config.logdir end
if site_config.UrlDeny then UrlDeny = site_config.UrlDeny end
if site_config.Redirect then Redirect = site_config.Redirect end
if site_config.CookieMatch then CookieMatch = site_config.CookieMatch end
if site_config.postMatch then postMatch = site_config.postMatch end
if site_config.whiteModule then whiteModule = site_config.whiteModule end
if site_config.CCDeny then CCDeny = site_config.CCDeny end
if site_config.CCrate then CCrate = site_config.CCrate end
if site_config.ipWhitelist then ipWhitelist = site_config.ipWhitelist end
if site_config.ipBlocklist then ipBlocklist = site_config.ipBlocklist end
if site_config.black_fileExt then black_fileExt = site_config.black_fileExt end

-- 站点规则开关
SITE_RULES = site_config.rules or {
    args = true,
    url = true,
    post = true,
    cookie = true,
    useragent = true,
    whiteurl = true
}

-- 拦截页面
html = [[
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>BT-WAF | 访问拦截</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Noto Sans SC", "PingFang SC", "Microsoft YaHei", sans-serif;
    background: linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #0f172a 100%);
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    color: #e2e8f0;
}
.container {
    text-align: center;
    padding: 40px;
    max-width: 600px;
}
.shield {
    width: 120px;
    height: 120px;
    margin: 0 auto 30px;
    background: linear-gradient(135deg, #2563eb, #1d4ed8);
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 60px;
    box-shadow: 0 0 40px rgba(37, 99, 235, 0.4);
    animation: pulse 2s ease-in-out infinite;
}
@keyframes pulse {
    0%, 100% { transform: scale(1); box-shadow: 0 0 40px rgba(37, 99, 235, 0.4); }
    50% { transform: scale(1.05); box-shadow: 0 0 60px rgba(37, 99, 235, 0.6); }
}
.title {
    font-size: 28px;
    font-weight: 700;
    margin-bottom: 16px;
    background: linear-gradient(135deg, #38bdf8, #2563eb);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
}
.subtitle {
    font-size: 16px;
    color: #94a3b8;
    margin-bottom: 30px;
    line-height: 1.6;
}
.info-box {
    background: rgba(30, 41, 59, 0.8);
    border: 1px solid rgba(37, 99, 235, 0.3);
    border-radius: 12px;
    padding: 24px;
    margin-bottom: 24px;
    text-align: left;
}
.info-box h3 {
    font-size: 14px;
    color: #38bdf8;
    margin-bottom: 12px;
    text-transform: uppercase;
    letter-spacing: 0.1em;
}
.info-box p {
    font-size: 14px;
    color: #cbd5e1;
    line-height: 1.8;
}
.info-box .code {
    background: rgba(15, 23, 42, 0.8);
    padding: 8px 12px;
    border-radius: 6px;
    font-family: "SF Mono", "Fira Code", monospace;
    font-size: 12px;
    color: #38bdf8;
    margin-top: 8px;
}
.footer {
    font-size: 12px;
    color: #64748b;
    margin-top: 30px;
}
.footer a {
    color: #38bdf8;
    text-decoration: none;
}
</style>
</head>
<body>
<div class="container">
    <div class="shield">&#128737;</div>
    <h1 class="title">BT-WAF 访问拦截</h1>
    <p class="subtitle">您的请求触发了网站防火墙规则，已被安全系统拦截</p>
    
    <div class="info-box">
        <h3>可能原因</h3>
        <p>1. 请求中包含恶意参数或攻击特征</p>
        <p>2. 请求频率过高，触发 CC 防护</p>
        <p>3. IP 地址被列入黑名单</p>
        <p>4. 请求内容包含敏感关键词</p>
    </div>
    
    <div class="info-box">
        <h3>您的访问信息</h3>
        <p>IP 地址：<span class="code">]] .. (ngx.var.remote_addr or "unknown") .. [[</span></p>
        <p>请求时间：<span class="code">]] .. (ngx.localtime() or "") .. [[</span></p>
        <p>请求 URL：<span class="code">]] .. (ngx.var.request_uri or "") .. [[</span></p>
    </div>
    
    <div class="footer">
        <p>如有疑问，请联系网站管理员</p>
        <p>Powered by <a href="#">BT-WAF 网站防火墙</a></p>
    </div>
</div>
</body>
</html>
]]