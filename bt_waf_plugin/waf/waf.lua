require 'init'

local content_length = tonumber(ngx.req.get_headers()['content-length'])
local method = ngx.req.get_method()
local ngxmatch = ngx.re.match

-- 检查顺序：白IP -> 黑IP -> CC -> 扫描器特征 -> URL白名单 -> UA -> URL -> ARGS -> Cookie -> POST

if whiteip() then
    -- IP白名单，直接放行
    log_access()
    return
elseif blockip() then
    -- IP黑名单，已拦截
    return
elseif denycc() then
    -- CC攻击，已拦截
    return
elseif ngx.var.http_Acunetix_Aspect then
    -- Acunetix扫描器
    log('SCAN', ngx.var.request_uri, "-", "Acunetix Scanner", "scanner")
    ngx.exit(444)
elseif ngx.var.http_X_Scan_Memo then
    -- 其他扫描器
    log('SCAN', ngx.var.request_uri, "-", "X-Scan", "scanner")
    ngx.exit(444)
elseif whiteurl() then
    -- URL白名单，放行
    log_access()
    return
elseif ua() then
    -- User-Agent拦截
    return
elseif url() then
    -- URL拦截
    return
elseif args() then
    -- GET参数拦截
    return
elseif cookie() then
    -- Cookie拦截
    return
elseif PostCheck then
    -- POST请求检查
    if method == "POST" then
        local boundary = get_boundary()
        if boundary then
            -- 文件上传检查
            local len = string.len
            local sock, err = ngx.req.socket()
            if not sock then
                return
            end
            ngx.req.init_body(128 * 1024)
            sock:settimeout(0)
            local content_length = nil
            content_length = tonumber(ngx.req.get_headers()['content-length'])
            local chunk_size = 4096
            if content_length < chunk_size then
                chunk_size = content_length
            end
            local size = 0
            local filetranslate = false
            while size < content_length do
                local data, err, partial = sock:receive(chunk_size)
                data = data or partial
                if not data then
                    return
                end
                ngx.req.append_body(data)
                if body(data) then
                    return true
                end
                size = size + len(data)
                local m = ngxmatch(data, [[Content-Disposition: form-data;(.+)filename="(.+)\.(.*)"]], 'ijo')
                if m then
                    fileExtCheck(m[3])
                    filetranslate = true
                else
                    if ngxmatch(data, "Content-Disposition:", 'isjo') then
                        filetranslate = false
                    end
                    if filetranslate == false then
                        if body(data) then
                            return true
                        end
                    end
                end
                local less = content_length - size
                if less < chunk_size then
                    chunk_size = less
                end
            end
            ngx.req.finish_body()
        else
            -- 普通POST数据检查
            ngx.req.read_body()
            local args = ngx.req.get_post_args()
            if not args then
                return
            end
            for key, val in pairs(args) do
                if type(val) == "table" then
                    if type(val[1]) == "boolean" then
                        return
                    end
                    data = table.concat(val, ", ")
                else
                    data = val
                end
                if data and type(data) ~= "boolean" and body(data) then
                    body(key)
                end
            end
        end
    end
else
    -- 所有检查通过，记录正常访问
    log_access()
    return
end

-- 所有检查通过，记录正常访问
log_access()