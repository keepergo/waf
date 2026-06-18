#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BT-WAF 网站防火墙 - 宝塔插件主程序
提供后端API接口，供前端面板调用
"""

import os
import sys
import json
import time
import sqlite3
import re
import glob
from datetime import datetime, timedelta

# 插件目录
PLUGIN_DIR = "/www/server/panel/plugin/bt_waf"
WAF_DIR = os.path.join(PLUGIN_DIR, "waf")
LOG_DIR = os.path.join(WAF_DIR, "logs")
SITES_DIR = os.path.join(WAF_DIR, "sites")
RULES_DIR = os.path.join(WAF_DIR, "wafconf")
DB_PATH = os.path.join(PLUGIN_DIR, "bt_waf.db")

# 确保目录存在
for d in [LOG_DIR, SITES_DIR, RULES_DIR]:
    if not os.path.exists(d):
        os.makedirs(d)


class bt_waf_main:
    """BT-WAF 主类"""

    def __init__(self):
        self.init_db()

    def init_db(self):
        """初始化数据库"""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # 站点配置表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS site_configs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                server_name TEXT UNIQUE NOT NULL,
                config TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # 拦截日志表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS block_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                time TEXT NOT NULL,
                ip TEXT NOT NULL,
                server_name TEXT NOT NULL,
                method TEXT,
                url TEXT,
                ua TEXT,
                rule TEXT,
                attack_type TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # 访问统计表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS access_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date TEXT NOT NULL,
                server_name TEXT NOT NULL,
                total_requests INTEGER DEFAULT 0,
                blocked_requests INTEGER DEFAULT 0,
                unique_ips INTEGER DEFAULT 0,
                UNIQUE(date, server_name)
            )
        ''')

        # IP黑名单表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ip_blacklist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                server_name TEXT NOT NULL,
                reason TEXT,
                expire_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(ip, server_name)
            )
        ''')

        # IP白名单表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ip_whitelist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                server_name TEXT NOT NULL,
                reason TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(ip, server_name)
            )
        ''')

        conn.commit()
        conn.close()

    # ==================== 站点管理 ====================

    def get_sites(self, get):
        """获取所有站点列表"""
        try:
            # 从Nginx配置读取站点列表
            nginx_vhost = "/www/server/panel/vhost/nginx"
            sites = []

            if os.path.exists(nginx_vhost):
                for conf_file in os.listdir(nginx_vhost):
                    if conf_file.endswith('.conf'):
                        server_name = conf_file.replace('.conf', '')
                        site_config = self._get_site_config(server_name)
                        sites.append({
                            'name': server_name,
                            'waf_enabled': site_config.get('waf_enabled', True),
                            'rules': site_config.get('rules', {}),
                            'cc_enabled': site_config.get('CCDeny', 'off') == 'on',
                            'cc_rate': site_config.get('CCrate', '100/60')
                        })

            return {'success': True, 'data': sites}
        except Exception as e:
            return {'success': False, 'message': str(e)}

    def get_site_detail(self, get):
        """获取单个站点详情"""
        try:
            server_name = get.server_name
            config = self._get_site_config(server_name)
            return {'success': True, 'data': config}
        except Exception as e:
            return {'success': False, 'message': str(e)}

    def save_site_config(self, get):
        """保存站点配置"""
        try:
            server_name = get.server_name
            config = json.loads(get.config)

            # 保存到JSON文件
            config_file = os.path.join(SITES_DIR, f"{server_name}.json")
            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, ensure_ascii=False, indent=2)

            # 同步到数据库
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO site_configs (server_name, config, updated_at)
                VALUES (?, ?, datetime('now'))
            ''', (server_name, json.dumps(config)))
            conn.commit()
            conn.close()

            return {'success': True, 'message': '配置保存成功'}
        except Exception as e:
            return {'success': False, 'message': str(e)}

    def toggle_site_waf(self, get):
        """开关站点WAF"""
        try:
            server_name = get.server_name
            enabled = get.enabled == 'true'

            config = self._get_site_config(server_name)
            config['waf_enabled'] = enabled

            return self.save_site_config(type('obj', (object,), {
                'server_name': server_name,
                'config': json.dumps(config)
            })())
        except Exception as e:
            return {'success': False, 'message': str(e)}

    # ==================== 规则管理 ====================

    def get_rules(self, get):
        """获取规则列表"""
        try:
            rule_type = get.rule_type  # args, url, post, cookie, user-agent, whiteurl
            rule_file = os.path.join(RULES_DIR, rule_type)

            rules = []
            if os.path.exists(rule_file):
                with open(rule_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            rules.append(line)

            return {'success': True, 'data': rules}
        except Exception as e:
            return {'success': False, 'message': str(e)}

    def save_rules(self, get):
        """保存规则"""
        try:
            rule_type = get.rule_type
            rules = json.loads(get.rules)

            rule_file = os.path.join(RULES_DIR, rule_type)
            with open(rule_file, 'w', encoding='utf-8') as f:
                for rule in rules:
                    if rule.strip():
                        f.write(rule.strip() + '\n')

            return {'success': True, 'message': '规则保存成功'}
        except Exception as e:
            return {'success': False, 'message': str(e)}

    def add_rule(self, get):
        """添加单条规则"""
        try:
            rule_type = get.rule_type
            rule = get.rule

            rule_file = os.path.join(RULES_DIR, rule_type)
            with open(rule_file, 'a', encoding='utf-8') as f:
                f.write(rule + '\n')

            return {'success': True, 'message': '规则添加成功'}
        except Exception as e:
            return {'success': False, 'message': str(e)}

    def delete_rule(self, get):
        """删除规则"""
        try:
            rule_type = get.rule_type
            rule = get.rule

            rule_file = os.path.join(RULES_DIR, rule_type)
            rules = []
            if os.path.exists(rule_file):
                with open(rule_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        if line.strip() != rule:
                            rules.append(line)

            with open(rule_file, 'w', encoding='utf-8') as f:
                f.writelines(rules)

            return {'success': True, 'message': '规则删除成功'}
        except Exception as e:
            return {'success': False, 'message': str(e)}

    # ==================== IP管理 ====================

    def get_ip_list(self, get):
        """获取IP列表"""
        try:
            list_type = get.list_type  # whitelist, blacklist
            server_name = get.get('server_name', 'global')

            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()

            if list_type == 'blacklist':
                cursor.execute('''
                    SELECT ip, reason, expire_at, created_at FROM ip_blacklist
                    WHERE server_name = ? ORDER BY created_at DESC
                ''', (server_name,))
            else:
                cursor.execute('''
                    SELECT ip, reason, created_at FROM ip_whitelist
                    WHERE server_name = ? ORDER BY created_at DESC
                ''', (server_name,))

            rows = cursor.fetchall()
            conn.close()

            data = []
            for row in rows:
                if list_type == 'blacklist':
                    data.append({
                        'ip': row[0],
                        'reason': row[1],
                        'expire_at': row[2],
                        'created_at': row[3]
                    })
                else:
                    data.append({
                        'ip': row[0],
                        'reason': row[1],
                        'created_at': row[2]
                    })

            return {'success': True, 'data': data}
        except Exception as e:
            return {'success': False, 'message': str(e)}

    def add_ip(self, get):
        """添加IP"""
        try:
            list_type = get.list_type
            ip = get.ip
            server_name = get.get('server_name', 'global')
            reason = get.get('reason', '')

            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()

            if list_type == 'blacklist':
                expire_at = get.get('expire_at', None)
                cursor.execute('''
                    INSERT OR REPLACE INTO ip_blacklist (ip, server_name, reason, expire_at)
                    VALUES (?, ?, ?, ?)
                ''', (ip, server_name, reason, expire_at))
            else:
                cursor.execute('''
                    INSERT OR REPLACE INTO ip_whitelist (ip, server_name, reason)
                    VALUES (?, ?, ?)
                ''', (ip, server_name, reason))

            conn.commit()
            conn.close()

            # 同步到站点配置
            self._sync_ip_to_config(server_name)

            return {'success': True, 'message': 'IP添加成功'}
        except Exception as e:
            return {'success': False, 'message': str(e)}

    def delete_ip(self, get):
        """删除IP"""
        try:
            list_type = get.list_type
            ip = get.ip
            server_name = get.get('server_name', 'global')

            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()

            if list_type == 'blacklist':
                cursor.execute('DELETE FROM ip_blacklist WHERE ip = ? AND server_name = ?',
                               (ip, server_name))
            else:
                cursor.execute('DELETE FROM ip_whitelist WHERE ip = ? AND server_name = ?',
                               (ip, server_name))

            conn.commit()
            conn.close()

            # 同步到站点配置
            self._sync_ip_to_config(server_name)

            return {'success': True, 'message': 'IP删除成功'}
        except Exception as e:
            return {'success': False, 'message': str(e)}

    # ==================== 日志与统计 ====================

    def get_logs(self, get):
        """获取拦截日志"""
        try:
            server_name = get.get('server_name', '')
            page = int(get.get('page', 1))
            limit = int(get.get('limit', 20))
            attack_type = get.get('attack_type', '')

            # 从日志文件读取
            logs = []
            log_files = []

            if server_name:
                pattern = os.path.join(LOG_DIR, f"{server_name}_*_sec.log")
                log_files = glob.glob(pattern)
            else:
                pattern = os.path.join(LOG_DIR, "*_sec.log")
                log_files = glob.glob(pattern)

            # 读取最近7天的日志
            for log_file in sorted(log_files, reverse=True)[:7]:
                if os.path.exists(log_file):
                    with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                log_entry = json.loads(line)
                                if attack_type and log_entry.get('type') != attack_type:
                                    continue
                                logs.append(log_entry)
                            except:
                                continue

            # 按时间倒序
            logs.sort(key=lambda x: x.get('time', ''), reverse=True)

            # 分页
            total = len(logs)
            start = (page - 1) * limit
            end = start + limit
            page_logs = logs[start:end]

            return {
                'success': True,
                'data': page_logs,
                'total': total,
                'page': page,
                'limit': limit
            }
        except Exception as e:
            return {'success': False, 'message': str(e)}

    def get_access_logs(self, get):
        """获取访问日志（用于实时展示）"""
        try:
            server_name = get.get('server_name', '')
            limit = int(get.get('limit', 50))

            logs = []
            log_files = []

            if server_name:
                pattern = os.path.join(LOG_DIR, f"{server_name}_access.log")
                if os.path.exists(pattern):
                    log_files = [pattern]
            else:
                pattern = os.path.join(LOG_DIR, "*_access.log")
                log_files = glob.glob(pattern)

            for log_file in log_files:
                if os.path.exists(log_file):
                    with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()
                        for line in lines[-limit:]:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                log_entry = json.loads(line)
                                logs.append(log_entry)
                            except:
                                continue

            # 按时间倒序
            logs.sort(key=lambda x: x.get('time', ''), reverse=True)

            return {'success': True, 'data': logs[:limit]}
        except Exception as e:
            return {'success': False, 'message': str(e)}

    def get_stats(self, get):
        """获取统计数据"""
        try:
            server_name = get.get('server_name', '')

            # 统计今日数据
            today = datetime.now().strftime('%Y-%m-%d')

            # 从日志文件统计
            total_blocked = 0
            total_access = 0
            cc_blocked = 0
            unique_ips = set()
            attack_types = {}
            site_stats = {}

            log_files = glob.glob(os.path.join(LOG_DIR, "*_sec.log"))
            access_files = glob.glob(os.path.join(LOG_DIR, "*_access.log"))

            # 统计拦截日志
            for log_file in log_files:
                if today not in log_file:
                    continue
                if server_name and server_name not in log_file:
                    continue

                with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        try:
                            entry = json.loads(line.strip())
                            total_blocked += 1
                            unique_ips.add(entry.get('ip', ''))

                            atype = entry.get('type', 'unknown')
                            attack_types[atype] = attack_types.get(atype, 0) + 1

                            site = entry.get('server', 'unknown')
                            if site not in site_stats:
                                site_stats[site] = {'blocked': 0, 'access': 0}
                            site_stats[site]['blocked'] += 1
                        except:
                            continue

            # 统计访问日志
            for log_file in access_files:
                if today not in log_file:
                    continue
                if server_name and server_name not in log_file:
                    continue

                with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        try:
                            entry = json.loads(line.strip())
                            total_access += 1
                            unique_ips.add(entry.get('ip', ''))

                            site = entry.get('server', 'unknown')
                            if site not in site_stats:
                                site_stats[site] = {'blocked': 0, 'access': 0}
                            site_stats[site]['access'] += 1
                        except:
                            continue

            # 获取7天趋势
            trend = []
            for i in range(6, -1, -1):
                date = (datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d')
                day_blocked = 0
                day_access = 0

                for log_file in log_files:
                    if date in log_file:
                        with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                            day_blocked += sum(1 for _ in f)

                for log_file in access_files:
                    if date in log_file:
                        with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                            day_access += sum(1 for _ in f)

                trend.append({
                    'date': date,
                    'blocked': day_blocked,
                    'access': day_access
                })

            # TOP 攻击IP
            ip_stats = {}
            for log_file in log_files:
                if today not in log_file:
                    continue
                with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        try:
                            entry = json.loads(line.strip())
                            ip = entry.get('ip', '')
                            ip_stats[ip] = ip_stats.get(ip, 0) + 1
                        except:
                            continue

            top_ips = sorted(ip_stats.items(), key=lambda x: x[1], reverse=True)[:10]

            # TOP 被攻击站点
            top_sites = sorted(site_stats.items(), key=lambda x: x[1]['blocked'], reverse=True)[:5]

            return {
                'success': True,
                'data': {
                    'total_blocked': total_blocked,
                    'total_access': total_access,
                    'cc_blocked': cc_blocked,
                    'unique_ips': len(unique_ips),
                    'attack_types': attack_types,
                    'trend': trend,
                    'top_ips': [{'ip': ip, 'count': count} for ip, count in top_ips],
                    'top_sites': [{'site': site, 'blocked': stats['blocked'], 'access': stats['access']} for site, stats in top_sites]
                }
            }
        except Exception as e:
            return {'success': False, 'message': str(e)}

    def get_realtime_logs(self, get):
        """获取实时日志（用于WebSocket轮询）"""
        try:
            server_name = get.get('server_name', '')
            last_time = get.get('last_time', '')
            limit = int(get.get('limit', 20))

            logs = []
            log_files = []

            if server_name:
                pattern = os.path.join(LOG_DIR, f"{server_name}_access.log")
                if os.path.exists(pattern):
                    log_files = [pattern]
            else:
                pattern = os.path.join(LOG_DIR, "*_access.log")
                log_files = glob.glob(pattern)

            for log_file in log_files:
                if not os.path.exists(log_file):
                    continue
                with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
                    for line in lines:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entry = json.loads(line)
                            if last_time and entry.get('time', '') <= last_time:
                                continue
                            logs.append(entry)
                        except:
                            continue

            logs.sort(key=lambda x: x.get('time', ''), reverse=True)

            return {
                'success': True,
                'data': logs[:limit],
                'latest_time': logs[0].get('time', '') if logs else last_time
            }
        except Exception as e:
            return {'success': False, 'message': str(e)}

    # ==================== CC防御 ====================

    def get_cc_config(self, get):
        """获取CC防御配置"""
        try:
            server_name = get.server_name
            config = self._get_site_config(server_name)
            return {
                'success': True,
                'data': {
                    'enabled': config.get('CCDeny', 'off') == 'on',
                    'rate': config.get('CCrate', '100/60'),
                    'count': config.get('CCrate', '100/60').split('/')[0],
                    'seconds': config.get('CCrate', '100/60').split('/')[1]
                }
            }
        except Exception as e:
            return {'success': False, 'message': str(e)}

    def save_cc_config(self, get):
        """保存CC防御配置"""
        try:
            server_name = get.server_name
            enabled = get.enabled == 'true'
            count = get.count
            seconds = get.seconds

            config = self._get_site_config(server_name)
            config['CCDeny'] = 'on' if enabled else 'off'
            config['CCrate'] = f"{count}/{seconds}"

            return self.save_site_config(type('obj', (object,), {
                'server_name': server_name,
                'config': json.dumps(config)
            })())
        except Exception as e:
            return {'success': False, 'message': str(e)}

    # ==================== 工具方法 ====================

    def _get_site_config(self, server_name):
        """获取站点配置"""
        config_file = os.path.join(SITES_DIR, f"{server_name}.json")
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except:
                pass

        # 返回默认配置
        return {
            'waf_enabled': True,
            'attacklog': 'on',
            'logdir': LOG_DIR,
            'UrlDeny': 'on',
            'Redirect': 'on',
            'CookieMatch': 'on',
            'postMatch': 'on',
            'whiteModule': 'on',
            'CCDeny': 'on',
            'CCrate': '100/60',
            'ipWhitelist': [],
            'ipBlocklist': [],
            'black_fileExt': ['php', 'jsp'],
            'rules': {
                'args': True,
                'url': True,
                'post': True,
                'cookie': True,
                'useragent': True,
                'whiteurl': True
            }
        }

    def _sync_ip_to_config(self, server_name):
        """同步IP列表到站点配置"""
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()

            # 获取白名单
            cursor.execute('SELECT ip FROM ip_whitelist WHERE server_name = ?', (server_name,))
            whitelist = [row[0] for row in cursor.fetchall()]

            # 获取黑名单
            cursor.execute('SELECT ip FROM ip_blacklist WHERE server_name = ?', (server_name,))
            blacklist = [row[0] for row in cursor.fetchall()]

            conn.close()

            # 更新配置
            config = self._get_site_config(server_name)
            config['ipWhitelist'] = whitelist
            config['ipBlocklist'] = blacklist

            config_file = os.path.join(SITES_DIR, f"{server_name}.json")
            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, ensure_ascii=False, indent=2)

        except Exception as e:
            print(f"Sync IP error: {e}")

    def clear_logs(self, get):
        """清理日志"""
        try:
            days = int(get.get('days', 7))
            cutoff = datetime.now() - timedelta(days=days)

            deleted = 0
            for log_file in glob.glob(os.path.join(LOG_DIR, "*.log")):
                try:
                    # 从文件名提取日期
                    basename = os.path.basename(log_file)
                    date_match = re.search(r'(\d{4}-\d{2}-\d{2})', basename)
                    if date_match:
                        file_date = datetime.strptime(date_match.group(1), '%Y-%m-%d')
                        if file_date < cutoff:
                            os.remove(log_file)
                            deleted += 1
                except:
                    continue

            return {'success': True, 'message': f'已清理 {deleted} 个日志文件'}
        except Exception as e:
            return {'success': False, 'message': str(e)}

    def reload_nginx(self, get):
        """重载Nginx配置"""
        try:
            import subprocess
            result = subprocess.run(
                ['/www/server/nginx/sbin/nginx', '-t'],
                capture_output=True,
                text=True
            )
            if result.returncode != 0:
                return {'success': False, 'message': f'Nginx配置测试失败: {result.stderr}'}

            result = subprocess.run(
                ['/www/server/nginx/sbin/nginx', '-s', 'reload'],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                return {'success': True, 'message': 'Nginx重载成功'}
            else:
                return {'success': False, 'message': f'Nginx重载失败: {result.stderr}'}
        except Exception as e:
            return {'success': False, 'message': str(e)}