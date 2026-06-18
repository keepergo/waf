#!/bin/bash
# BT-WAF 插件安装脚本

plugin_dir=/www/server/panel/plugin/bt_waf
waf_dir=/www/server/panel/plugin/bt_waf/waf
nginx_conf=/www/server/nginx/conf

# 安装
Install() {
    echo '==========================================='
    echo '  BT-WAF 网站防火墙 安装开始'
    echo '==========================================='
    
    # 创建插件目录
    mkdir -p ${plugin_dir}
    mkdir -p ${waf_dir}
    mkdir -p ${waf_dir}/wafconf
    mkdir -p ${waf_dir}/logs
    
    # 复制WAF核心文件
    cp -r ${plugin_dir}/waf/* ${waf_dir}/ 2>/dev/null || true
    
    # 创建默认规则文件
    touch ${waf_dir}/wafconf/args
    touch ${waf_dir}/wafconf/url
    touch ${waf_dir}/wafconf/post
    touch ${waf_dir}/wafconf/cookie
    touch ${waf_dir}/wafconf/user-agent
    touch ${waf_dir}/wafconf/whiteurl
    
    # 写入默认规则
    cat > ${waf_dir}/wafconf/args << 'EOF'
\.(bak|inc|old|mdb|sql|backup|java|class)$
(vhost|bbs|host|wwwroot|www|site|root|backup|data|uploads|upload|static|ftp|ftpdata|ftproot|ftpfile).*(\.|\/)
\.(git|svn|hg|bzr|cvs)
\.(sql|bak|backup|old|swp|swo|swn|save|tmp|temp|log|err|out|pid|sock|lock|db|mdb|accdb|sqlite|sqlite3|frm|myd|myi|ibd|dbf|mdb|accdb)$
EOF

    cat > ${waf_dir}/wafconf/url << 'EOF'
\.(bak|inc|old|mdb|sql|backup|java|class)$
(vhost|bbs|host|wwwroot|www|site|root|backup|data|uploads|upload|static|ftp|ftpdata|ftproot|ftpfile).*(\.|\/)
\.(git|svn|hg|bzr|cvs)
EOF

    cat > ${waf_dir}/wafconf/post << 'EOF'
basename|phpinfo|eval|assert|exec|system|passthru|shell_exec|popen|proc_open|pcntl_exec|base64_decode|gzinflate|gzuncompress
EOF

    cat > ${waf_dir}/wafconf/cookie << 'EOF'
eval\(|assert\(|\+\+|\-\-|base64_decode|gzinflate|gzuncompress
EOF

    cat > ${waf_dir}/wafconf/user-agent << 'EOF'
(HTTrack|harvest|audit|dirbuster|pangolin|nmap|sqln|-scan|hydra|Parser|libwww|BBBike|sqlmap|w3af|owasp|nikto|fimap|havij|PycURL|zmeu|BabyKrokodil|netsparker|httperf|bench|dirbuster)
EOF

    cat > ${waf_dir}/wafconf/whiteurl << 'EOF'
EOF

    # 创建站点配置文件目录
    mkdir -p ${waf_dir}/sites
    
    # 创建数据库
    python3 ${plugin_dir}/bt_waf_main.py init_db
    
    # 安装Nginx配置
    if [ -d "${nginx_conf}" ]; then
        # 备份原配置
        if [ ! -f "${nginx_conf}/nginx.conf.bt_waf.bak" ]; then
            cp ${nginx_conf}/nginx.conf ${nginx_conf}/nginx.conf.bt_waf.bak 2>/dev/null || true
        fi
        
        # 检查是否已经包含waf配置
        if ! grep -q "bt_waf" ${nginx_conf}/nginx.conf 2>/dev/null; then
            echo "请手动在 nginx.conf 的 http 段添加以下配置："
            echo ""
            echo "    lua_package_path \"/www/server/panel/plugin/bt_waf/waf/?.lua;;\";"
            echo "    lua_shared_dict bt_waf_limit 50m;"
            echo "    lua_shared_dict bt_waf_cache 10m;"
            echo "    init_by_lua_file /www/server/panel/plugin/bt_waf/waf/init.lua;"
            echo "    access_by_lua_file /www/server/panel/plugin/bt_waf/waf/waf.lua;"
            echo ""
            echo "添加后请重启Nginx: /www/server/nginx/sbin/nginx -s reload"
        fi
    fi
    
    # 设置权限
    chown -R www:www ${waf_dir}
    chmod -R 755 ${waf_dir}
    
    echo '==========================================='
    echo '  BT-WAF 网站防火墙 安装完成'
    echo '==========================================='
    echo '请手动配置Nginx并重启'
}

# 卸载
Uninstall() {
    echo '==========================================='
    echo '  BT-WAF 网站防火墙 卸载开始'
    echo '==========================================='
    
    # 恢复Nginx配置
    if [ -f "${nginx_conf}/nginx.conf.bt_waf.bak" ]; then
        cp ${nginx_conf}/nginx.conf.bt_waf.bak ${nginx_conf}/nginx.conf
        echo "Nginx配置已恢复"
    fi
    
    # 删除插件目录
    rm -rf ${plugin_dir}
    
    echo '==========================================='
    echo '  BT-WAF 网站防火墙 卸载完成'
    echo '==========================================='
    echo '请重启Nginx: /www/server/nginx/sbin/nginx -s reload'
}

action=${1}
if [ "${1}" == 'install' ]; then
    Install
elif [ "${1}" == 'uninstall' ]; then
    Uninstall
else
    echo "Usage: $0 {install|uninstall}"
fi