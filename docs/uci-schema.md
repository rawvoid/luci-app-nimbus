# UCI Configuration Schema — `/etc/config/nimbus`

本文档是 `/etc/config/nimbus` 的唯一事实来源（Single Source of Truth）。`uci-defaults`、后端 `ucode` 与前端 LuCI 表单均以本文件定义的 Section 名称、Option 键名、数据类型、默认值与校验规则为准。

---

## 1. 通用约定

- **布尔值**：统一使用 OpenWrt UCI 标准字符串 `'0'`（关）与 `'1'`（开）。
- **命名规范**：全部使用 `snake_case`。
- **数据边界**：
  - `/etc/config/nimbus` 仅保存用户配置。
  - 运行期上下文（状态机阶段、生效端口/网卡、探测到的 API 入口摘要、`warnings` 与 `last_error`）统一存于 `/var/run/nimbus/state.json`（权限 `0600`，严禁存储明文 API `secret`）；真实 `sing-box` 进程号由 `supervisor.uc` 维护于 `/var/run/nimbus/sing-box.pid`。
  - 实时进程状态、内存占用与防火墙计数器通过 `ubus`、`/proc` 与 `nft` 按需实时查询。白名单计数须区分“各源文本解析条目数”与“经 `nftables` `auto-merge` 合并后的加载元素数”。
  - 远程白名单与订阅的上次更新时间直接读取对应文件的 `mtime`，HTTP 增量同步使用 `curl -z`，仅在 `SHA256` 变化时覆盖本地缓存。
- **运行时路径**：
  - `sing-box` 以 `-D /var/run/nimbus` 为工作目录启动，配置中的相对路径文件（如 `cache.db`、`dashboard/`）默认位于 `tmpfs`；显式绝对路径原样保留。`/var/run/nimbus/config.json` 权限固定设为 `0600`。
  - 运行日志由 `sing-box` 以原生 `O_APPEND` 方式写入 `/var/log/nimbus.log`，由 `supervisor.uc` 定时器实施滞回截断（超过 512KB 时就地截断保留尾部 256KB）。
- **路径安全**：
  - `profile.filename` 仅允许纯文件名（匹配 `^[A-Za-z0-9._-]+\.json$`），固定拼接至 `/etc/nimbus/profiles/`。
  - `list_source.filename` 仅允许纯文件名（匹配 `^[A-Za-z0-9._-]+\.txt$`），固定拼接至 `/etc/nimbus/lists/local/`。
  - 远程白名单缓存固定存于 `/etc/nimbus/lists/cache/<section_id>.txt`。

---

## 2. Section 详细定义

### 2.1 `config main 'global'`（命名单例：全局设置）

| Option | 类型 | 默认值 | 合法值 / 校验规则 | 说明 |
| :--- | :--- | :--- | :--- | :--- |
| `enabled` | `bool` | `'0'` | `'0'`, `'1'` | 全局启用开关 |
| `active_profile` | `string` | `''` | 已存在的 `config profile` Section 名 | 当前激活的 `sing-box` 配置 ID |
| `topology` | `enum` | `'main'` | `'main'`, `'side'` | `main`=主路由；`side`=旁路由（自动关闭 LAN 口 `send_redirects`，不依赖 `wan` 接口） |
| `proxy_mode` | `enum` | `'tproxy_redirect'` | `'tproxy_redirect'`（v1.1+ 预留 `'tun'`） | 透明代理模式（v1.0 仅实现 `tproxy_redirect`） |
| `fail_open` | `bool` | `'0'` | `'0'`, `'1'` | `'0'`=内核异常/崩溃时切入 Lockdown 阻断非白名单 LAN 转发（始终放行路由器管理流量）；`'1'`=异常时清表回落直连 |
| `lan_interfaces` | `list(string)` | `['lan']` | OpenWrt `network` 逻辑接口名列表 | 代理覆盖的 LAN 接口 |
| `wan_interfaces` | `list(string)` | `['wan', 'wan6']` | OpenWrt `network` 逻辑接口名列表 | `topology='main'` 时使用，提取公网 IPv4/IPv6 加入 `wan_v4`/`wan_v6` 绕行 |
| `ipv4_enable` | `bool` | `'1'` | `'0'`, `'1'` | 启用 IPv4 透明代理 |
| `ipv6_enable` | `bool` | `'1'` | `'0'`, `'1'` | 启用 IPv6 透明代理 |
| `proxy_local` | `bool` | `'0'` | `'0'`, `'1'` | 是否代理路由器本机出站流量（`output` 链） |
| `log_level` | `enum` | `'warn'` | `'trace'`, `'debug'`, `'info'`, `'warn'`, `'error'`, `'fatal'`, `'panic'` | 覆写运行期 `sing-box` 日志级别 |
| `gomemlimit` | `string` | `'auto'` | `'auto'` 或 Go 内存格式（如 `'128MiB'`） | 注入 `GOMEMLIMIT`；`'auto'` 按 `min(MemTotal * 0.4, 256MiB)` 计算 |

---

### 2.2 `config proxy 'proxy'`（命名单例：数据面与入站补齐参数）

> Fake-IP 网段（IPv4/IPv6）由 `config_builder.uc` 从用户 `sing-box` 配置中自动提取并排除出保留段绕行。（`tun_iface` 留待 v1.1 引入 `tun` 模式时补充。）

| Option | 类型 | 默认值 | 合法值 / 校验规则 | 说明 |
| :--- | :--- | :--- | :--- | :--- |
| `redirect_port` | `port` | `'7891'` | `1024`–`65535` | 配置缺少 `redirect` 入站时自动补齐的监听端口 |
| `tproxy_port` | `port` | `'7892'` | `1024`–`65535`（不得与 `redirect_port` 相同） | 配置缺少 UDP `tproxy` 入站时自动补齐的监听端口 |
| `outbound_mark` | `hex_u32` | `'0xff'` | `0x1`–`0xffffffff`（不得与 `proxy_mark` 相同） | 防环路标记；原配置未设 `route.default_mark` 时注入此值 |
| `proxy_mark` | `hex_u32` | `'0x1'` | `0x1`–`0xffffffff` | UDP TPROXY 策略路由 fwmark |
| `route_table` | `uint` | `'100'` | `1`–`252` | IPv4/IPv6 策略路由表 ID |
| `port_filter_mode` | `enum` | `'all'` | `'all'`, `'include'`, `'exclude'` | 目标端口过滤：`all`=全端口；`include`=仅代理指定端口；`exclude`=排除指定端口 |
| `proxy_tcp_ports` | `list(portrange)` | `[]` | 端口或范围（如 `'80'`, `'443'`, `'8000-8999'`） | 非 `'all'` 模式下生效的 TCP 端口集合 |
| `proxy_udp_ports` | `list(portrange)` | `[]` | 端口或范围（如 `'53'`, `'443'`） | 非 `'all'` 模式下生效的 UDP 端口集合 |
| `sniff` | `bool` | `'0'` | `'0'`, `'1'` | `'1'` 时在 `sing-box` 路由表头部为生效透明代理入站注入 `{ "action": "sniff" }` 规则（若尚未被全局或对应 `inbound` 嗅探规则覆盖） |
| `block_quic` | `bool` | `'0'` | `'0'`, `'1'` | `'1'` 时在 `sing-box` 路由表注入 `protocol: quic -> action: reject` |
| `lan_device_mode` | `enum` | `'default_proxy'` | `'default_proxy'`, `'default_bypass'`（兼容旧值 `'all'` / `'bypass_listed'` / `'except_listed'` -> `'default_proxy'`，`'proxy_listed'` -> `'default_bypass'`） | 未命中下方 `lan_device` 规则的局域网设备默认策略：`default_proxy`=默认走代理；`default_bypass`=默认直连绕行。下方 `lan_device` 规则按顺序**优先于**本默认策略生效 |

---

### 2.3 `config dns 'dns'`（命名单例：`dnsmasq` 托管）

接管前备份原始 `dhcp.@dnsmasq[0]` 配置至 `/etc/nimbus/dns_backup.json`，停用或切回 `'none'` 时按快照还原。`mode='singbox'` 时同时设置 `noresolv='1'`、`cachesize='0'`、`dnssec='0'`。

| Option | 类型 | 默认值 | 合法值 / 校验规则 | 说明 |
| :--- | :--- | :--- | :--- | :--- |
| `mode` | `enum` | `'none'` | `'none'`, `'singbox'`, `'custom'` | `'none'`=不接管；`'singbox'`=转发至本机 `sing-box` DNS 入站；`'custom'`=转发至自定义上游 |
| `singbox_dns_port` | `port` | `'5353'` | `1024`–`65535` | `mode='singbox'` 且配置中无本地 DNS 入站时自动补齐的端口 |
| `custom_servers` | `list(string)` | `[]` | `dnsmasq` 上游格式（如 `'127.0.0.1#5335'`、`'192.168.1.2#5353'`） | `mode='custom'` 时写入 `dhcp.@dnsmasq[0].server` |
| `local_dns_policy` | `enum` | `'auto'` | `'auto'`, `'fallback'`, `'reject'` | `mode='singbox'` 时对 `dns.servers` 中 `type='local'` 条目的防死循环处理：`auto`=自动探测 WAN 非回环 DNS 运行期改写为 `udp` 上游（取不到时回退至 `local_fallback_server`）；`fallback`=始终使用 `local_fallback_server`；`reject`=直接报错拒绝 |
| `local_fallback_server` | `ipaddr` | `'223.5.5.5'` | 合法单播非回环 IPv4/IPv6 或空串 | 当 `local_dns_policy='fallback'` 时或 `'auto'` 暂未取到安全 WAN DNS 时，用于替换 `type='local'` 的直连 DNS；留空则无可用 WAN DNS 时报错 |
| `hijack_lan_dns` | `bool` | `'0'` | `'0'`, `'1'` | 在 `table inet nimbus` 中将 LAN 发往外部的 `TCP/UDP 53` 重定向至路由器本机 `53` |

---

### 2.4 `config core 'core'`（命名单例：`sing-box` 内核管理）

| Option | 类型 | 默认值 | 合法值 / 校验规则 | 说明 |
| :--- | :--- | :--- | :--- | :--- |
| `bin_path` | `string` | `'/etc/nimbus/bin/sing-box'` | 合法绝对文件路径（可指向外挂盘或 `/tmp/nimbus/sing-box`） | `sing-box` 二进制存放路径 |
| `repo` | `string` | `'SagerNet/sing-box'` | `^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$` | GitHub Releases 仓库 |
| `channel` | `enum` | `'stable'` | `'stable'`, `'prerelease'` | 版本通道 |
| `mirror_prefix` | `string` | `''` | 空或 `http(s)://` 前缀 | GitHub 下载加速镜像前缀 |
| `download_via_proxy` | `bool` | `'0'` | `'0'`, `'1'` | 代理运行中检查/下载内核更新时经当前代理拉取 |

---

### 2.5 `config whitelist 'whitelist'`（命名单例：白名单全局策略）

| Option | 类型 | 默认值 | 合法值 / 校验规则 | 说明 |
| :--- | :--- | :--- | :--- | :--- |
| `enabled` | `bool` | `'1'` | `'0'`, `'1'` | 启用白名单绕行（关闭时仍保留系统内置局域网/保留段绕行） |
| `auto_update` | `bool` | `'1'` | `'0'`, `'1'` | 通过 `crond` 自动更新所有已启用的 `type='url'` 白名单源并原子热刷新 `nftables` Set |
| `update_cron` | `string` | `'30 4 * * *'` | 标准 5 段 Cron 表达式 | 定时更新计划 |

---

### 2.6 `config list_source`（多实例：白名单列表，支持远程源与多个手动列表）

每个列表可独立命名、开关与编辑。本地列表通过 `rpcd` 直接读写对应 `.txt` 文件并触发 `nft -f` 原子热刷新；所有列表共用同一解析器，支持 IPv4/IPv6/CIDR 混排、空行、`#`/`//`/`;` 注释行与行尾注释。

| Option | 类型 | 默认值 | 合法值 / 校验规则 | 说明 |
| :--- | :--- | :--- | :--- | :--- |
| `name` | `string` | 必填 | 非空显示名称 | 前端展示名（如 `'China IPv4'`、`'Custom Direct'`） |
| `type` | `enum` | `'url'` | `'url'`, `'local'` | `'url'`=远程订阅源；`'local'`=本地手动编辑/导入列表 |
| `enabled` | `bool` | `'1'` | `'0'`, `'1'` | 是否启用该列表 |
| `family` | `enum` | `'auto'` | `'auto'`, `'ipv4'`, `'ipv6'` | 解析族过滤；`'auto'` 自动分拣至 `bypass_v4` / `bypass_v6` |
| `filename` | `string` | `''` | `type='local'` 时必填，`^[A-Za-z0-9._-]+\.txt$` | 本地列表文件名，存储于 `/etc/nimbus/lists/local/` |
| `url` | `string` | `''` | `type='url'` 时必填合法 `http(s)://` URL | 远程白名单下载地址 |
| `via_proxy` | `bool` | `'0'` | `'0'`, `'1'` | `type='url'` 时生效，拉取该源时是否经当前代理请求 |

---

### 2.7 `config profile`（多实例：`sing-box` 配置文件与订阅）

| Option | 类型 | 默认值 | 合法值 / 校验规则 | 说明 |
| :--- | :--- | :--- | :--- | :--- |
| `name` | `string` | 必填 | 非空显示名称 | 前端展示名 |
| `type` | `enum` | `'local'` | `'local'`, `'subscription'` | `'local'`=本地上传/编辑；`'subscription'`=远程订阅 |
| `filename` | `string` | 必填 | `^[A-Za-z0-9._-]+\.json$` | 位于 `/etc/nimbus/profiles/` 下的原始只读文件名 |
| `url` | `string` | `''` | `type='subscription'` 时必填 `http(s)://` URL | 远程订阅地址 |
| `user_agent` | `string` | `'sing-box/nimbus'` | 非空字符串 | 订阅拉取 `User-Agent` |
| `via_proxy` | `bool` | `'0'` | `'0'`, `'1'` | 拉取订阅时是否经当前代理请求 |
| `auto_update` | `bool` | `'0'` | `'0'`, `'1'` | `type='subscription'` 时启用定时自动更新 |
| `update_interval_hours` | `uint` | `'24'` | `1`–`720` | 自动更新周期（小时） |

---

### 2.8 `config lan_device`（多实例：局域网设备分流）

| Option | 类型 | 默认值 | 合法值 / 校验规则 | 说明 |
| :--- | :--- | :--- | :--- | :--- |
| `name` | `string` | `''` | 可选备注名 | 前端展示备注 |
| `enabled` | `bool` | `'1'` | `'0'`, `'1'` | 是否生效 |
| `mac` | `macaddr` | `''` | `XX:XX:XX:XX:XX:XX`（与 `ip` 至少填一项） | 按源 MAC 匹配（双栈生效） |
| `ip` | `ipaddr/cidr` | `''` | 合法 IPv4 或 IPv6 地址/网段（与 `mac` 至少填一项） | 按源 IP 匹配 |
| `policy` | `enum` | `'bypass'` | `'bypass'`, `'proxy'` | `'bypass'`=命中该规则的设备直连绕行；`'proxy'`=命中该规则的设备进入代理链路。启用规则按配置顺序自上而下**优先于** `proxy.lan_device_mode` 匹配（先命中者生效） |

---

## 3. 默认 `/etc/config/nimbus` 模板

```uci
config main 'global'
	option enabled '0'
	option active_profile ''
	option topology 'main'
	option proxy_mode 'tproxy_redirect'
	option fail_open '0'
	list lan_interfaces 'lan'
	list wan_interfaces 'wan'
	list wan_interfaces 'wan6'
	option ipv4_enable '1'
	option ipv6_enable '1'
	option proxy_local '0'
	option log_level 'warn'
	option gomemlimit 'auto'

config proxy 'proxy'
	option redirect_port '7891'
	option tproxy_port '7892'
	option outbound_mark '0xff'
	option proxy_mark '0x1'
	option route_table '100'
	option port_filter_mode 'all'
	option sniff '0'
	option block_quic '0'
	option lan_device_mode 'default_proxy'

config dns 'dns'
	option mode 'none'
	option singbox_dns_port '5353'
	option local_dns_policy 'auto'
	option local_fallback_server '223.5.5.5'
	option hijack_lan_dns '0'

config core 'core'
	option bin_path '/etc/nimbus/bin/sing-box'
	option repo 'SagerNet/sing-box'
	option channel 'stable'
	option mirror_prefix ''
	option download_via_proxy '0'

config whitelist 'whitelist'
	option enabled '1'
	option auto_update '1'
	option update_cron '30 4 * * *'

config list_source 'cn_ipv4'
	option name 'China IPv4'
	option type 'url'
	option enabled '1'
	option family 'ipv4'
	option url 'https://raw.githubusercontent.com/misakaio/chnroutes2/master/chnroutes.txt'
	option via_proxy '0'

config list_source 'cn_ipv6'
	option name 'China IPv6'
	option type 'url'
	option enabled '1'
	option family 'ipv6'
	option url 'https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/china6.txt'
	option via_proxy '0'

config list_source 'custom_direct'
	option name 'Custom Direct'
	option type 'local'
	option enabled '1'
	option family 'auto'
	option filename 'custom_direct.txt'
```

---

## 4. 跨字段校验约束

1. **双栈至少启用一项**：`global.ipv4_enable` 与 `global.ipv6_enable` 不可同时为 `'0'`。
2. **端口不冲突**：`proxy.redirect_port`、`proxy.tproxy_port`（以及 `dns.mode='singbox'` 时的 `dns.singbox_dns_port`）两两不可相同。
3. **标记不冲突**：`proxy.outbound_mark` 与 `proxy.proxy_mark` 必须为不同的非零 32 位整数。
4. **自定义 DNS 非空**：`dns.mode='custom'` 时，`dns.custom_servers` 至少包含 1 条合法上游；`dns.mode='singbox'` 且 `dns.local_dns_policy='fallback'` 时，`dns.local_fallback_server` 须为合法非回环单播 IP。
5. **白名单源完整性**：`list_source.type='url'` 时 `url` 必填；`type='local'` 时 `filename` 必填且各本地列表 `filename` 不可重复。
6. **配置源完整性**：`profile.type='subscription'` 时 `url` 必填；各 `profile.filename` 不可重复。
7. **设备条目完整**：启用的 `lan_device` 必须至少填写 `mac` 或 `ip` 之一。
8. **启动前置校验**：`global.enabled='1'` 时，`active_profile` 对应文件与 `core.bin_path` 必须有效；不满足则按 `fail_open` 策略处理并写入错误原因至 `/var/run/nimbus/state.json`。
9. **运行期合成碰撞校验**：`config_builder.uc` 合成配置时校验 `effective_outbound_mark != proxy.proxy_mark`，并检测自动注入入站端口与用户配置中已有入站监听端口之间不存在碰撞冲突。