# BT-WAF 网站防火墙

基于 ngx_lua_waf 开发的宝塔面板插件，提供多站点管理、可视化面板、Nginx Lua 核心引擎、实时访问监控等功能。

---

## 目录

- [功能特性](#功能特性)
- [安装要求](#安装要求)
- [安装方法](#安装方法)
- [Nginx 配置](#nginx-配置)
- [目录结构](#目录结构)
- [使用说明](#使用说明)
  - [多站点管理](#多站点管理)
  - [规则配置](#规则配置)
  - [IP / UA 黑白名单](#ip--ua-黑白名单)
  - [CC 防御](#cc-防御)
  - [实时访问监控](#实时访问监控)
  - [日志查看](#日志查看)
- [配置文件说明](#配置文件说明)
- [卸载](#卸载)
- [常见问题](#常见问题)

---

## 功能特性

- **多站点管理** — 每个站点可独立开启/关闭 WAF、独立配置规则
- **可视化面板** — 科技风格深色界面，直观查看拦截统计、访问趋势
- **Nginx Lua 核心引擎** — 基于 ngx_lua_waf 的高性能检测引擎
- **规则配置** — 支持 args、url、post、cookie、user-agent、whiteurl 六类规则在线配置
- **IP / UA 黑白名单** — 支持 IP 段和 User-Agent 关键词的黑白名单管理
- **CC 防御** — 可配置请求频率阈值，自动拦截高频攻击
- **实时访问监控** — 实时刷新展示被拦截请求和正常访问记录
- **攻击日志** — 记录每次拦截的时间、IP、站点、攻击类型、触发规则

---

## 安装要求

- 宝塔面板 7.x 或更高版本
- Nginx 1.12+ 且已编译安装 `ngx_http_lua_module`（LuaJIT + lua-nginx-module）
- Python 3.6+
- 服务器内存建议 ≥ 1GB

### 检查 Nginx 是否支持 Lua

```bash
nginx -V 2>&1 | grep -o 'http_lua_module'
```

如果有输出 `http_lua_module`，说明已支持。如果没有，需要在宝塔面板的 **Nginx 设置 → 编译安装** 中勾选 `Lua` 模块后重新编译安装。

---

## 安装方法

### 方式一：宝塔插件导入（推荐）

1. 将本插件目录打包为 zip：
   ```bash
   cd /path/to/bt_waf_plugin
   zip -r bt_waf_plugin.zip .
   ```

2. 登录宝塔面板 → **软件商店 → 第三方应用 → 导入插件**

3. 选择 `bt_waf_plugin.zip` 上传，点击安装

4. 安装完成后，按提示配置 Nginx（见下方 [Nginx 配置](#nginx-配置)）

### 方式二：手动安装

1. 上传插件文件到服务器：
   ```bash
   mkdir -p /www/server/panel/plugin/bt_waf
   cp -r ./* /www/server/panel/plugin/bt_waf/
   ```

2. 执行安装脚本：
   ```bash
   cd /www/server/panel/plugin/bt_waf
   bash install.sh install
   ```

3. 按提示配置 Nginx（见下方 [Nginx 配置](#nginx-配置)）

---

## Nginx 配置

安装完成后，需要手动在 Nginx 配置文件的 `http` 段添加以下配置：

```nginx
http {
    # ... 其他配置 ...

    # BT-WAF 配置
    lua_package_path "/www/server/panel/plugin/bt_waf/waf/?.lua;;";
    lua_shared_dict bt_waf_limit 50m;
    lua_shared_dict bt_waf_cache 10m;
    init_by_lua_file /www/server/panel/plugin/bt_waf/waf/init.lua;
    access_by_lua_file /www/server/panel/plugin/bt_waf/waf/waf.lua;

    # ... 其他配置 ...
}
```

配置文件路径：`/www/server/nginx/conf/nginx.conf`

添加后重启 Nginx：

```bash
/www/server/nginx/sbin/nginx -t
/www/server/nginx/sbin/nginx -s reload
```

---

## 目录结构

```
/www/server/panel/plugin/bt_waf/
├── info.json              # 插件元数据（名称、版本、作者等）
├── install.sh             # 安装/卸载脚本
├── bt_waf_main.py         # Python 后端 API（SQLite 数据库、接口服务）
├── index.html             # 前端可视化面板（主界面）
├── README.md              # 本说明文件
└── waf/                   # WAF 核心引擎目录
    ├── config.lua         # 多站点配置加载
    ├── init.lua           # 引擎初始化（检测函数、CC 计数器）
    ├── waf.lua            # 请求处理主逻辑
    ├── wafconf/           # 规则文件目录
    │   ├── args           # URL 参数过滤规则
    │   ├── url            # URL 路径过滤规则
    │   ├── post           # POST 数据过滤规则
    │   ├── cookie         # Cookie 过滤规则
    │   ├── user-agent     # User-Agent 过滤规则
    │   └── whiteurl       # URL 白名单规则
    ├── sites/             # 站点独立配置目录
    └── logs/              # 日志目录
```

---

## 使用说明

安装完成后，在宝塔面板左侧菜单点击 **BT-WAF** 即可进入管理界面。

### 多站点管理

- 插件会自动识别宝塔面板中已创建的网站
- 每个站点可独立 **开启/关闭** WAF 防护
- 点击站点名称进入该站点的独立配置页面
- 支持批量操作

### 规则配置

进入 **规则管理** 页面，可在线编辑六类防护规则：

| 规则类型 | 说明 | 示例 |
|---------|------|------|
| args | URL 参数过滤 | `\.sql$`、`eval\(` |
| url | URL 路径过滤 | `\.git`、`\.bak$` |
| post | POST 数据过滤 | `phpinfo`、`base64_decode` |
| cookie | Cookie 过滤 | `eval\(`、`assert\(` |
| user-agent | UA 过滤 | `sqlmap`、`nmap` |
| whiteurl | URL 白名单 | `/api/whitelist` |

- 每行一条规则，支持正则表达式
- 修改后点击 **保存** 即时生效
- 支持为不同站点配置不同规则集

### IP / UA 黑白名单

进入 **IP 黑白名单** 页面：

- **IP 黑名单** — 被拦截的 IP 无法访问网站
  - 支持单个 IP：`192.168.1.100`
  - 支持 IP 段：`192.168.1.0/24`
- **IP 白名单** — 跳过后续所有检测
- **UA 黑名单** — 匹配 User-Agent 关键词即拦截

### CC 防御

进入 **CC 防御** 页面配置：

- **请求阈值**：单位时间内的最大请求次数（默认 100 次/60 秒）
- **封禁时长**：触发阈值后的封禁时间（默认 600 秒）
- **检测模式**：全站统一 / 按站点独立

### 实时访问监控

进入 **实时监控** 页面：

- 点击右上角开关启用实时刷新
- 左侧展示 **被拦截请求**（红色标记）
- 右侧展示 **正常访问**（绿色标记）
- 每 3 秒自动刷新一次
- 显示信息：时间、IP、访问 URL、攻击类型/状态

### 日志查看

进入 **日志审计** 页面：

- 查看所有被拦截的攻击记录
- 支持按时间、站点、攻击类型筛选
- 显示字段：时间、IP、站点、攻击类型、URL、触发规则
- 支持清理 7 天前的历史日志

---

## 配置文件说明

### 站点配置文件

每个站点的独立配置存储在 `waf/sites/{domain}.json`，示例：

```json
{
  "domain": "example.com",
  "waf_enabled": true,
  "cc_rate": 100,
  "cc_duration": 600,
  "rules": {
    "args": true,
    "url": true,
    "post": true,
    "cookie": true,
    "user_agent": true,
    "whiteurl": true
  }
}
```

### 数据库文件

SQLite 数据库路径：`/www/server/panel/plugin/bt_waf/waf/bt_waf.db`

包含以下数据表：

- `site_configs` — 站点配置
- `block_logs` — 拦截日志
- `access_stats` — 访问统计
- `ip_blacklist` — IP 黑名单
- `ip_whitelist` — IP 白名单

---

## 卸载

### 通过宝塔面板

**软件商店 → 已安装 → BT-WAF → 卸载**

### 手动卸载

```bash
cd /www/server/panel/plugin/bt_waf
bash install.sh uninstall
```

卸载后会：
- 自动恢复 Nginx 配置备份
- 删除插件目录 `/www/server/panel/plugin/bt_waf`
- 请手动重启 Nginx 使配置生效

---

## 常见问题

**Q: 安装后界面显示空白？**
A: 检查 `index.html` 是否存在于 `/www/server/panel/plugin/bt_waf/index.html`，并确认文件权限为 `644`。

**Q: WAF 规则不生效？**
A: 检查 Nginx 配置中是否正确添加了 `init_by_lua_file` 和 `access_by_lua_file`，并确认 Nginx 已重启。

**Q: 如何查看 WAF 是否在工作？**
A: 进入插件的 **实时监控** 页面，访问网站后观察是否有访问记录产生。或查看日志目录 `waf/logs/` 下的文件。

**Q: 误拦截了正常用户怎么办？**
A: 将该用户的 IP 添加到 **IP 白名单**，或将访问的 URL 添加到 **whiteurl** 规则白名单。

**Q: 支持 HTTPS 站点吗？**
A: 支持。WAF 工作在 Nginx 的 access 阶段，在 SSL 握手之后，因此同时支持 HTTP 和 HTTPS。

**Q: 对网站访问速度影响大吗？**
A: 本地部署的 Nginx Lua WAF 延迟开销通常在 1ms 以内，吞吐量损失 < 3%，对大多数网站影响可忽略。

---

## 技术栈

- **后端**：Python 3 + Flask（内置在 `bt_waf_main.py`）+ SQLite
- **前端**：原生 HTML/CSS/JavaScript + ECharts（数据可视化）
- **WAF 引擎**：OpenResty / ngx_http_lua_module + LuaJIT
- **规则来源**：基于 [loveshell/ngx_lua_waf](https://github.com/loveshell/ngx_lua_waf)

---

## 开源协议

本项目基于 [ngx_lua_waf](https://github.com/loveshell/ngx_lua_waf) 开发，遵循其开源协议。

---

## 更新日志

### v1.0.0
- 多站点独立管理
- 六类规则在线配置（args/url/post/cookie/user-agent/whiteurl）
- IP / UA 黑白名单
- CC 攻击防御
- 实时访问监控
- 攻击日志审计
- 科技风格可视化面板
