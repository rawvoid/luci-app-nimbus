# Dataplane & sing-box Specification

本文档是 `nft_manager.uc`、`route_manager.uc`、`config_builder.uc`、`dns_manager.uc`、`list_updater.uc`、`profile_updater.uc`、`core_manager.uc` 与 `supervisor.uc` 的底层实现契约。所有防火墙规则、策略路由、配置合成、监督轮转与版本兼容逻辑必须严格按本规范实现。

---

## 1. 全局常量与标记分配

### 1.1 防火墙与路由常量

| 常量名 | 来源 / 固定值 | 用途 |
| :--- | :--- | :--- |
| `TABLE_NAME` | `inet nimbus` | 独立 `nftables` 表名（固定） |
| `OUTBOUND_MARK` | UCI `proxy.outbound_mark`（默认 `0xff`） | 防环路标记，对应 `sing-box` 的 `route.default_mark` |
| `PROXY_MARK` | UCI `proxy.proxy_mark`（默认 `0x1`） | UDP TPROXY 策略路由 `fwmark` |
| `CT_BYPASS_BIT` | `0x10`（掩码 `0x30`） | Conntrack 首包直连决策缓存位（写入前先清掩码 `ct mark & 0xffffffcf | 0x10`，不覆盖其他工具的高低位标记） |
| `CT_PROXY_BIT` | `0x20`（掩码 `0x30`） | Conntrack 首包代理决策缓存位（写入前先清掩码 `ct mark & 0xffffffcf | 0x20`） |
| `ROUTE_TABLE` | UCI `proxy.route_table`（默认 `100`） | IPv4/IPv6 策略路由表 ID |
| `RULE_PRIO_PROXY` | `1000` | `ip -4/-6 rule` 优先级 |

### 1.2 自动补齐入站保留 Tag

当用户配置文件缺少所需入站时，使用以下固定 `tag`（`nimbus-tun-in` 预留至 v1.1）：

| 场景 | 自动注入 Tag |
| :--- | :--- |
| 自动补齐 TCP `redirect` 入站 | `nimbus-redirect-in` |
| 自动补齐 UDP `tproxy` 入站 | `nimbus-tproxy-in` |
| 自动补齐本地 DNS `direct` 入站 | `nimbus-dns-in` |

### 1.3 内置系统保留地址段

以下 CIDR 固定写入 `reserved_v4` / `reserved_v6` Set（注意：**不包含** `198.18.0.0/15`；IPv6 的 Fake-IP 网段如 `fc00::/18` 虽处于 `fc00::/7` 内部，但因 Fake-IP Set 优先级高于 `reserved_v6`，不会被误绕行）：

- **`reserved_v4`**：
  `0.0.0.0/8`, `10.0.0.0/8`, `100.64.0.0/10`, `127.0.0.0/8`, `169.254.0.0/16`, `172.16.0.0/12`, `192.0.0.0/24`, `192.0.2.0/24`, `192.88.99.0/24`, `192.168.0.0/16`, `198.51.100.0/24`, `203.0.113.0/24`, `224.0.0.0/4`, `240.0.0.0/4`
- **`reserved_v6`**：
  `::/128`, `::1/128`, `::ffff:0:0/96`, `64:ff9b::/96`, `100::/64`, `2001::/32`, `2001:db8::/32`, `fc00::/7`, `fe80::/10`, `ff00::/8`

---

## 2. `table inet nimbus` 防火墙规则规范 (`nft_manager.uc`)

### 2.1 生成铁律（防 `nft -f` 语法错误）

1. **空集合禁写 `elements`**：`nftables` 不允许 `elements = { }` 语法。当某 Set（如 `wan_v6`、`fakeip_v4`、`bypass_v4`、`lan_bypass_mac`）为空时，必须省略 `elements = { ... }` 行，仅声明集合定义。
2. **原子替换主表与幂等删表**：每次全量加载规则文件 `/var/run/nimbus/rules.nft` 时，文件顶部必须使用两行幂等原子重建写法；`delete_table()` 同样采用该两行事务批处理执行，确保表不存在时天然幂等返回 `0`，而二进制缺失、权限不足或超时等真实故障准确返回错误：
   ```nft
   table inet nimbus
   delete table inet nimbus
   table inet nimbus { ... }
   ```
3. **Hook 优先级与 Netfilter 执行序**：
   - `mangle`（`-150`）早于 `dstnat`（`-100`）执行。当启用 `dns.hijack_lan_dns='1'` 时，`prerouting_udp` 必须显式跳过发往外部的 `UDP 53`，让数据包继续流向 `prerouting_dns`（`dstnat + 1`）重定向至本机 `53`。
   - `prerouting_dns` 位于 `dstnat + 1`（`-99`），`prerouting_tcp` 位于 `dstnat + 2`（`-98`），且均在链首执行 `meta mark $OUTBOUND_MARK return` 与 `ct status dnat return`，确保 `fw4` 中用户自定义的端口转发（`-100`）始终优先。
4. **`inet` 表中的 `redirect` / `tproxy` 单条规则语法**：`nftables` 要求每条含 `redirect to :<port>` 或 `tproxy ... to :<port>` 的规则**自身必须显式携带传输层协议匹配**（链首的 `meta l4proto != tcp/udp return` 不能替代）；在 `table inet` 内必须写为 `meta l4proto tcp ... redirect to :$REDIRECT_PORT`，以及区分协议族写成 `meta nfproto ipv4 meta l4proto udp ... tproxy ip to :$TPROXY_PORT accept` 与 `meta nfproto ipv6 meta l4proto udp ... tproxy ip6 to :$TPROXY_PORT accept`。所有统计规则统一引用表级具名计数器（`counter name "..."`），不重复叠加匿名 `counter`。
5. **本机目的地、入站回包与续约保护**：
   - 所有 `prerouting` 代理链均需包含 `fib daddr type local return`，确保访问路由器任意本地地址（含动态 IPv6 GUA/ULA/Link-Local）的流量绝不被劫持。
   - 逐包遍历的 `prerouting_udp`、`output_udp` 与阻断链 `forward_lockdown` 必须包含 `ct status dnat return` 与 `ct direction reply return`，防止 WAN 端口转发、IPv6 GUA 无 NAT 入站服务及本机 UDP VPN 服务端回包被误劫持或阻断。
   - `output_udp` 必须显式放行单播 DHCPv4（`meta nfproto ipv4 udp sport 68 udp dport 67 return`）与 DHCPv6（`meta nfproto ipv6 udp sport 546 udp dport 547 return`）续约报文。
6. **单栈裁剪与链首协议族守卫**：当 `ipv6_enable='0'` 时在全部主链顶部注入 `meta nfproto != ipv4 return` 并省略 IPv6 匹配与导流规则；当 `ipv4_enable='0'` 时注入 `meta nfproto != ipv6 return` 并省略 IPv4 匹配与导流规则。
7. **接口集合与 CIDR 安全边界**：
   - 写入 `set lan_ifaces`（`type ifname`）的设备名必须校验长度 `1..15`（`IFNAMSIZ - 1`）、排除 `.` 与 `..`，且匹配 `^[A-Za-z0-9_.+-]+$`（严禁混入引号、空白、`@` 别名或 `:` 地址标签）；`ubus` 已解析接口时不叠加静态 UCI 旧值，回退读 UCI 时对 `@alias` 执行有限深度解引用。
   - 所有 IP/CIDR 集合严禁混入 `/0` 默认路由（前缀长度须满足 IPv4 `1–32`、IPv6 `1–128`），并统一规范化消除前导零。

### 2.2 公共 Set 定义（双态共享）

```nft
    set lan_ifaces {
        type ifname
        elements = { "br-lan" }          # 动态解析 global.lan_interfaces 填充
    }
    set reserved_v4 { type ipv4_addr; flags interval; auto-merge; elements = { ... } }
    set reserved_v6 { type ipv6_addr; flags interval; auto-merge; elements = { ... } }
    set lan_v4      { type ipv4_addr; flags interval; auto-merge; }  # 动态解析 lan_interfaces 全部 IPv4 前缀
    set lan_v6      { type ipv6_addr; flags interval; auto-merge; }  # 动态解析 lan_interfaces 全部 IPv6 前缀（含 GUA/ULA）
    set wan_v4      { type ipv4_addr; flags interval; auto-merge; }
    set wan_v6      { type ipv6_addr; flags interval; auto-merge; }
    set fakeip_v4   { type ipv4_addr; flags interval; auto-merge; }
    set fakeip_v6   { type ipv6_addr; flags interval; auto-merge; }
    set bypass_v4   { type ipv4_addr; flags interval; auto-merge; }
    set bypass_v6   { type ipv6_addr; flags interval; auto-merge; }

    # 设备分流不再使用无序集合（按 lan_device 列表顺序逐条优先匹配，First-Match Wins）

    # 端口过滤集合（仅在 port_filter_mode != 'all' 且非空时填充）
    set filter_tcp_ports { type inet_service; flags interval; auto-merge; }
    set filter_udp_ports { type inet_service; flags interval; auto-merge; }

    # 表级具名统计计数器
    counter tcp_proxied {}
    counter udp_proxied {}
    counter lockdown_dropped {}
```

### 2.3 状态一：`tproxy_redirect` 模式规则骨架

```nft
table inet nimbus
delete table inet nimbus

table inet nimbus {
    # [插入 2.2 节公共 Set 与具名计数器定义]

    # 可选链：仅当 dns.hijack_lan_dns == '1' 时生成（按与代理链一致的单栈、设备规则与默认策略边界劫持外部 53）
    chain prerouting_dns {
        type nat hook prerouting priority dstnat + 1; policy accept;
        iifname != @lan_ifaces return
        # [单栈守卫：!ipv6_enable -> meta nfproto != ipv4 return；!ipv4_enable -> meta nfproto != ipv6 return]
        meta l4proto != { tcp, udp } return
        th dport != 53 return
        meta mark $OUTBOUND_MARK return
        ct status dnat return
        fib daddr type local return
        # [设备分流过滤：policy='bypass' -> return；policy='proxy' -> goto prerouting_dns_hijack]
        # 均未命中回退：default_bypass -> return；default_proxy -> 进入 prerouting_dns_hijack（或内联 redirect to :53）
    }

    # LAN TCP 透明代理（REDIRECT）
    chain prerouting_tcp {
        type nat hook prerouting priority dstnat + 2; policy accept;
        iifname != @lan_ifaces return
        # [单栈守卫：!ipv6_enable -> meta nfproto != ipv4 return；!ipv4_enable -> meta nfproto != ipv6 return]
        meta l4proto != tcp return
        meta mark $OUTBOUND_MARK return
        ct status dnat return
        fib daddr type local return

        # [设备分流过滤：按 lan_device 规则自上而下顺序匹配（First-Match Wins），先于默认策略生效]
        # 每条启用规则依序匹配 ether saddr / ip saddr / ip6 saddr：
        #   policy='bypass' -> return
        #   policy='proxy'  -> goto prerouting_tcp_proxy（Fake-IP/端口过滤/白名单/redirect 位于尾部子链）
        # 均未命中时回退至 lan_device_mode 默认策略：
        #   default_bypass ('proxy_listed')：return
        #   default_proxy ('all'/'bypass_listed')：goto prerouting_tcp_proxy（无 proxy 规则时直接内联后续规则）

        # Fake-IP 优先通道（先于端口过滤与保留段/白名单，防止不可路由的 198.18.0.0/15 或 fc00::/18 漏出 WAN 黑洞）
        ip daddr @fakeip_v4 meta l4proto tcp counter name "tcp_proxied" redirect to :$REDIRECT_PORT
        ip6 daddr @fakeip_v6 meta l4proto tcp counter name "tcp_proxied" redirect to :$REDIRECT_PORT

        # [端口过滤：按 port_filter_mode 条件生成，见注3]
        # include: tcp dport != @filter_tcp_ports return（若 filter_tcp_ports 为空则直接 return）
        # exclude: tcp dport @filter_tcp_ports return

        # 白名单与保留段放行（命中后留在 forward 链吃满 Flow Offloading）
        ip daddr @reserved_v4 return
        ip6 daddr @reserved_v6 return
        ip daddr @lan_v4 return
        ip6 daddr @lan_v6 return
        ip daddr @wan_v4 return
        ip6 daddr @wan_v6 return
        ip daddr @bypass_v4 return
        ip6 daddr @bypass_v6 return

        meta nfproto ipv4 meta l4proto tcp counter name "tcp_proxied" redirect to :$REDIRECT_PORT
        meta nfproto ipv6 meta l4proto tcp counter name "tcp_proxied" redirect to :$REDIRECT_PORT
    }

    # LAN（及可选本机回流）UDP 透明代理（TPROXY）
    chain prerouting_udp {
        type filter hook prerouting priority mangle; policy accept;

        # 仅当 proxy_local == '1' 时按已启用协议族生成：承接 output_udp 经 lo 重路由的本机 UDP
        iifname "lo" meta mark $PROXY_MARK meta l4proto udp meta nfproto ipv4 counter name "udp_proxied" tproxy ip to :$TPROXY_PORT accept
        iifname "lo" meta mark $PROXY_MARK meta l4proto udp meta nfproto ipv6 counter name "udp_proxied" tproxy ip6 to :$TPROXY_PORT accept

        iifname != @lan_ifaces return
        # [单栈守卫：!ipv6_enable -> meta nfproto != ipv4 return；!ipv4_enable -> meta nfproto != ipv6 return]
        meta l4proto != udp return
        meta mark $OUTBOUND_MARK return
        fib daddr type local return
        ct status dnat return
        ct direction reply return

        # 仅当 dns.hijack_lan_dns == '1' 时生成：放行外部 53 给 dstnat 链劫持至本地 dnsmasq
        udp dport 53 return

        # Conntrack 首包决策快速路径（避免逐包查大体积白名单 Set；short_circuit_bypass 时省略 0x20 分支防止存量流粘滞）
        ct mark & 0x30 == 0x10 return
        ct mark & 0x30 == 0x20 meta nfproto ipv4 meta l4proto udp meta mark set $PROXY_MARK counter name "udp_proxied" tproxy ip to :$TPROXY_PORT accept
        ct mark & 0x30 == 0x20 meta nfproto ipv6 meta l4proto udp meta mark set $PROXY_MARK counter name "udp_proxied" tproxy ip6 to :$TPROXY_PORT accept

        # [设备分流过滤：按 lan_device 规则自上而下顺序匹配（First-Match Wins）]
        #   policy='bypass' -> ct mark set ct mark & 0xffffffcf | 0x10 return
        #   policy='proxy'  -> goto prerouting_udp_proxy
        # 均未命中回退默认策略：default_bypass 时 ct mark set ct mark & 0xffffffcf | 0x10 return；default_proxy 时进入 prerouting_udp_proxy，见注1/注2

        # Fake-IP 优先通道
        ip daddr @fakeip_v4 ct mark set ct mark & 0xffffffcf | 0x20 meta l4proto udp meta mark set $PROXY_MARK counter name "udp_proxied" tproxy ip to :$TPROXY_PORT accept
        ip6 daddr @fakeip_v6 ct mark set ct mark & 0xffffffcf | 0x20 meta l4proto udp meta mark set $PROXY_MARK counter name "udp_proxied" tproxy ip6 to :$TPROXY_PORT accept

        # [端口过滤：命中直连时写 ct mark set ct mark & 0xffffffcf | 0x10 return，见注3]

        # 白名单与保留段放行并缓存直连标记
        ip daddr @reserved_v4 ct mark set ct mark & 0xffffffcf | 0x10 return
        ip6 daddr @reserved_v6 ct mark set ct mark & 0xffffffcf | 0x10 return
        ip daddr @lan_v4 ct mark set ct mark & 0xffffffcf | 0x10 return
        ip6 daddr @lan_v6 ct mark set ct mark & 0xffffffcf | 0x10 return
        ip daddr @wan_v4 ct mark set ct mark & 0xffffffcf | 0x10 return
        ip6 daddr @wan_v6 ct mark set ct mark & 0xffffffcf | 0x10 return
        ip daddr @bypass_v4 ct mark set ct mark & 0xffffffcf | 0x10 return
        ip6 daddr @bypass_v6 ct mark set ct mark & 0xffffffcf | 0x10 return

        # 首包命中代理并缓存代理标记
        meta nfproto ipv4 ct mark set ct mark & 0xffffffcf | 0x20 meta l4proto udp meta mark set $PROXY_MARK counter name "udp_proxied" tproxy ip to :$TPROXY_PORT accept
        meta nfproto ipv6 ct mark set ct mark & 0xffffffcf | 0x20 meta l4proto udp meta mark set $PROXY_MARK counter name "udp_proxied" tproxy ip6 to :$TPROXY_PORT accept
    }

    # 可选链：仅当 global.proxy_local == '1' 时生成（不应用 port_filter_mode，见注3）
    chain output_tcp {
        type nat hook output priority -100; policy accept;
        oifname "lo" return
        # [单栈守卫：!ipv6_enable -> meta nfproto != ipv4 return；!ipv4_enable -> meta nfproto != ipv6 return]
        meta l4proto != tcp return
        meta mark $OUTBOUND_MARK return
        fib daddr type local return
        ip daddr @fakeip_v4 meta l4proto tcp counter name "tcp_proxied" redirect to :$REDIRECT_PORT
        ip6 daddr @fakeip_v6 meta l4proto tcp counter name "tcp_proxied" redirect to :$REDIRECT_PORT
        ip daddr @reserved_v4 return
        ip6 daddr @reserved_v6 return
        ip daddr @lan_v4 return
        ip6 daddr @lan_v6 return
        ip daddr @wan_v4 return
        ip6 daddr @wan_v6 return
        ip daddr @bypass_v4 return
        ip6 daddr @bypass_v6 return
        meta nfproto ipv4 meta l4proto tcp counter name "tcp_proxied" redirect to :$REDIRECT_PORT
        meta nfproto ipv6 meta l4proto tcp counter name "tcp_proxied" redirect to :$REDIRECT_PORT
    }

    chain output_udp {
        type route hook output priority mangle; policy accept;
        oifname "lo" return
        # [单栈守卫：!ipv6_enable -> meta nfproto != ipv4 return；!ipv4_enable -> meta nfproto != ipv6 return]
        meta l4proto != udp return
        meta mark $OUTBOUND_MARK return
        fib daddr type local return
        ct status dnat return
        ct direction reply return
        meta nfproto ipv4 udp sport 68 udp dport 67 return
        meta nfproto ipv6 udp sport 546 udp dport 547 return
        ip daddr @fakeip_v4 meta mark set $PROXY_MARK accept
        ip6 daddr @fakeip_v6 meta mark set $PROXY_MARK accept
        ip daddr @reserved_v4 return
        ip6 daddr @reserved_v6 return
        ip daddr @lan_v4 return
        ip6 daddr @lan_v6 return
        ip daddr @wan_v4 return
        ip6 daddr @wan_v6 return
        ip daddr @bypass_v4 return
        ip6 daddr @bypass_v6 return
        meta nfproto ipv4 meta mark set $PROXY_MARK accept
        meta nfproto ipv6 meta mark set $PROXY_MARK accept
    }
}
```

> **注 1（设备分流优先顺序与 `goto` 尾子链）**：`lan_device` 规则优先级严格高于全局 `lan_device_mode` 默认策略，并按 UCI 节序号（`.index` / 列表自上而下）顺序匹配、先命中者生效，从而支持如“大网段 `bypass` + 单设备 `proxy`”或“大网段 `proxy` + 单设备 `bypass`”等任意交错规则。当存在有效 `policy='proxy'` 规则时，生成常规尾部子链 `prerouting_dns_hijack` / `prerouting_tcp_proxy` / `prerouting_udp_proxy` / `forward_lockdown_enforce` 并通过 `goto` 跳转，使命中 `proxy` 的设备跳过后续 `bypass` 规则且不额外占用 `ct mark` 位；当不存在 `policy='proxy'` 规则时，后续规则可直接内联在主链中。（`output_udp` 不挂具名 `udp_proxied` 计数器，因为打标包经 `lo` 进入 `prerouting_udp` 的 `iifname "lo"` 规则时统一计数，避免双倍累加。）
>
> **注 2（默认直连 `default_bypass` 下无 `proxy` 规则时的语义）**：当 `lan_device_mode` 归一化为 `'default_bypass'`（含旧值 `'proxy_listed'`）且无任何启用的有效 `policy='proxy'` 规则时，禁止跳过设备过滤而误放开代理或 DNS 劫持！应在保留表级命名计数器声明的同时，于对应链内（`prerouting_dns`、`prerouting_tcp`、`prerouting_udp`、`forward_lockdown`）直接输出单条短路放行（`prerouting_dns`、`prerouting_tcp` 与 `forward_lockdown` 中为 `return`；`prerouting_udp` 中省略 `ct mark & 0x30 == 0x20` 快速路径并直接输出 `ct mark set ct mark & 0xffffffcf | 0x10 return`，使存量代理 UDP 流在下一包立即自愈回直连）并省略不可达的尾部规则。
>
> **注 3（Fake-IP 与端口过滤 / 直连设备的协同边界）**：`@fakeip_v4` / `@fakeip_v6` 必须位于 `port_filter_mode` 之前，确保任何已分配虚拟地址 `198.18.0.0/15` / `fc00::/18` 的连接均进入 `sing-box` 还原真实域名，绝不因端口不匹配而漏出 WAN 造成 100% 黑洞；当 `port_filter_mode == 'include'` 且 `proxy_udp_ports`（或 `proxy_tcp_ports`）为空时，在 Fake-IP 规则之后输出 `ct mark set ct mark & 0xffffffcf | 0x10 return`（或 `return`），使全部真实 IP 流量直连绕行。路由器本机出站链（`output_tcp`、`output_udp`）不应用 `port_filter_mode`。同时，若检测到 Fake-IP 与 `port_filter_mode != 'all'` 共存，或 `dns.mode == 'singbox'` + Fake-IP 与直连设备策略（`lan_device` `bypass` / `default_bypass`）共存，或 `dns.hijack_lan_dns == '1'` 搭配 `dns.mode == 'none'`，须在 `warnings` 中写入明确诊断提示。

### 2.4 状态二：`lockdown` 阻断态规则骨架（`fail_open == '0'` 异常时）

仅 Hook `forward` 链（**不拦截 `input` 链**），确保 LAN 管理路由器的 SSH、LuCI、DHCP、ICMP/ICMPv6 始终可达，同时阻断原本受代理范围内的非白名单 LAN 转发流量防止 IP 泄漏（若常规 `apply_lockdown()` 因异常输入执行失败，Fail Handler 必须自动回退加载零外部输入依赖的静态最小 `forward` 阻断表，严禁在内核无阻断规则时静默写入 `lockdown` 状态）：

```nft
table inet nimbus
delete table inet nimbus

table inet nimbus {
    # [保留公共 Set 与具名计数器声明]

    chain forward_lockdown {
        type filter hook forward priority filter - 1; policy accept;
        iifname != @lan_ifaces return
        # [单栈守卫：!ipv6_enable -> meta nfproto != ipv4 return；!ipv4_enable -> meta nfproto != ipv6 return]
        ct status dnat return
        ct direction reply return
        # 仅当 ipv6_enable == '1' 时前置放行差错与邻居发现报文（1..4, 133..137），阻断对非白名单境外地址的 ping6 防止暴露真实 GUA
        meta l4proto icmpv6 icmpv6 type { 1, 2, 3, 4, 133, 134, 135, 136, 137 } return

        # [设备策略过滤：按 lan_device 顺序匹配与默认策略回退，保持与运行态完全一致的代理范围边界]
        # policy='bypass' -> return；policy='proxy' -> goto forward_lockdown_enforce
        # 未命中回退：default_bypass -> return；default_proxy -> 进入 forward_lockdown_enforce（或内联下方阻断规则）

        ip daddr @reserved_v4 return
        ip6 daddr @reserved_v6 return
        ip daddr @lan_v4 return
        ip6 daddr @lan_v6 return
        ip daddr @wan_v4 return
        ip6 daddr @wan_v6 return
        ip daddr @bypass_v4 return
        ip6 daddr @bypass_v6 return

        counter name "lockdown_dropped" reject with icmpx type admin-prohibited
    }
}
```

### 2.5 Set 原子热更新事务格式

#### 白名单热更新 (`/var/run/nimbus/bypass_sets.nft`)
```nft
flush set inet nimbus bypass_v4
add element inet nimbus bypass_v4 { 1.0.1.0/24, 1.0.2.0/23 }
flush set inet nimbus bypass_v6
add element inet nimbus bypass_v6 { 2400:3200::/32 }
```
> 若某族合并结果为空，仅输出 `flush set`，不输出 `add element`。

#### 接口与设备集合热更新 (`/var/run/nimbus/wan_sets.nft`)
由 `hotplug.d/iface/90-nimbus` 触发，格式与白名单事务一致，原子刷新 `lan_ifaces`（经 `is_valid_ifname()` 校验并加引号）、`lan_v4`、`lan_v6`（全部模式）与 `wan_v4`、`wan_v6`（`topology == 'main'`，UCI `ip6addr` 回退时剥离前缀仅保留接口本机 `/128`）。若因外部清空规则集导致刷新失败，`hotplug` 自动重放 `/var/run/nimbus/rules.nft`（及更新的 `/var/run/nimbus/bypass_sets.nft`）完成表自愈。

### 2.6 计数器读取规范（供 `rpcd` 状态页）
优先执行轻量级 `nft -j list counters table inet nimbus` 直接读取表级具名计数器（`tcp_proxied` / `udp_proxied` / `lockdown_dropped`），避免状态轮询序列化大体积白名单元素；若表不存在则直接返回零值不二次调用，仅在旧表无具名计数器时以 `nft -j -t list table inet nimbus`（`--terse` 省略 Set 元素）回退解析。

### 2.7 `fw4` `input` 放行边界检测
`nimbus` 严禁向 `table inet fw4` 注入代理链或白名单 Set，也严禁修改 `/etc/config/firewall`。在 `tproxy_redirect` 模式下，被 TCP `REDIRECT`、UDP `TPROXY` 或 `:53` DNS 劫持投递至本机的流量均会经过 `fw4` 的 `input` 链（若某 Zone 未在 `/etc/config/firewall` 定义 `fw4` 自身 DNAT 规则，`fw4` 甚至不会在该 Zone 生成 `ct status dnat accept`）；若检测到 LAN 接口所属 Zone 的 `input` 策略非 `ACCEPT`，或某 LAN 接口未归属任何 `fw4` Zone 且全局 `defaults.input` 非 `ACCEPT`，在 `state.json` 的 `warnings` 中写入明确诊断提示。

---

## 3. 策略路由与内核参数规范 (`route_manager.uc`)

### 3.1 `tproxy_redirect` 模式路由

- **IPv4**（`ipv4_enable == '1'`）：
  ```sh
  ip -4 rule add fwmark $PROXY_MARK lookup $ROUTE_TABLE pref 1000
  ip -4 route replace local 0.0.0.0/0 dev lo table $ROUTE_TABLE
  ```
- **IPv6**（`ipv6_enable == '1'`）：
  ```sh
  ip -6 rule add fwmark $PROXY_MARK lookup $ROUTE_TABLE pref 1000
  ip -6 route replace local ::/0 dev lo table $ROUTE_TABLE
  ```

### 3.2 内核 `sysctl` 调优

执行均为尽力而为（写入失败记录警告但不阻塞启动）：

- **UDP 缓冲区优化**（通用）：仅在当前值小于 `4194304` 时提升 `net.core.rmem_max=4194304` 与 `net.core.wmem_max=4194304`。
- **旁路由模式**（`topology == 'side'`）：设置 `net.ipv4.conf.all.send_redirects=0` 与各 LAN 物理设备 `net.ipv4.conf.<dev>.send_redirects=0`。

### 3.3 清理与自愈

- **幂等清理**：循环执行 `ip -4/-6 rule del lookup $ROUTE_TABLE` 直至无匹配记录，并执行 `ip -4/-6 route flush table $ROUTE_TABLE`。
- **热插拔自愈**：`hotplug.d/iface/90-nimbus` 触发时，若 `state.json` 处于 `running` 态，校验 `ip -4/-6 rule show` 中是否存在 `lookup $ROUTE_TABLE` 及对应路由，缺失则自动补回。

---

## 4. `sing-box` 配置合成与双 API 探测规范 (`config_builder.uc`)

### 4.1 输入与输出

- **输入**：只读原始配置 `/etc/nimbus/profiles/<filename>`、当前 UCI 配置、`sing-box` 二进制路径。
- **输出**：
  - 经 `sing-box check` 校验通过后原子替换的 `/var/run/nimbus/config.json`（权限 `0600`）；
  - 返回供 `nft_manager.uc`、`route_manager.uc`、`dns_manager.uc` 及 `/var/run/nimbus/state.json` 使用的构建上下文对象（注意：`effective_outbound_mark` 在上下文内部为整数如 `255`，落盘 `state.json` 与返回 `status` 时格式化为十六进制字符串如 `"0xff"`；且 `state.json` 中 `apis` 严禁写入明文 `secret`，仅保留 `has_secret`）：
    ```json
    {
      "core_version": "1.14.4",
      "effective_outbound_mark": 255,
      "effective_redirect_port": 7891,
      "effective_tproxy_port": 7892,
      "effective_tun_iface": null,
      "effective_dns_port": 5353,
      "inbound_sources": { "redirect": "auto", "tproxy": "user", "tun": null },
      "fakeip": { "ipv4": ["198.18.0.0/15"], "ipv6": ["fc00::/18"] },
      "apis": {
        "singbox_api": { ... },
        "clash_api": { ... }
      },
      "warnings": []
    }
    ```

### 4.2 确定性合成流水线（按序执行）

#### Step 1：探测内核版本与解析源 JSON
执行 `<bin_path> version`，正则提取主次版本号 `major.minor.patch`；读取源 JSON 并校验顶层为合法对象。

#### Step 2：日志与防环路标记
- **日志覆写**：设置 `cfg.log = { ...(cfg.log || {}), disabled: false, level: uci.global.log_level, output: "/var/log/nimbus.log", timestamp: true }`（显式确保 `disabled: false`）。
- **防环路标记**：
  - 使用 `ucode` 内置函数 `int(uci.proxy.outbound_mark, 16)` 解析 UCI `outbound_mark` 与 `proxy_mark`（严禁使用不存在的 `parseInt()`，并校验 `!isnan(...)`）。
  - 若 `cfg.route.default_mark` 已有非零整数值，校验其不得等于 `proxy_mark`（碰撞时立即中止并报校验错）；否则尊重原值作为 `effective_outbound_mark` 同步给 `nft_manager.uc`；若未设则写入 `cfg.route.default_mark = int(uci.proxy.outbound_mark, 16)`。（注意：若启用 `proxy_local='1'`，不建议在单个出站上覆盖与 `default_mark` 不同的 `routing_mark`。）

#### Step 3：透明代理入站复用、补齐与冲突隔离（`tproxy_redirect`）
确保 `cfg.inbounds` 为数组。定义当前协议族通配监听地址 `default_listen = (uci.global.ipv6_enable == '1') ? "::" : "0.0.0.0"`（防止关闭 IPv6 或无 IPv6 内核模块时绑定 `::` 失败）。

1. **剥离冲突 `tun`**：移除 `inbounds` 中所有 `type == "tun"` 的项，将其 `tag` 收集至 `stripped_tags`。
2. **处理 `redirect` 入站**：
   - 查找首个 `type == "redirect"` 入站：
     - 若存在：复用之，读取 `listen_port`；若 `listen` 仅绑定 `127.0.0.1` 或 `::1`，在运行期改为 `default_listen` 并记录 warning；若开启 `ipv6_enable == '1'` 且用户仅配置 `"0.0.0.0"`（且无独立 IPv6 `redirect` 入站），写入明确 warning 提示而保留用户原意；标记来源为 `"user"`。
     - 若不存在：校验 `uci.proxy.redirect_port` 未被已有入站占用后，追加 `{ "type": "redirect", "tag": "nimbus-redirect-in", "listen": default_listen, "listen_port": <uci.proxy.redirect_port> }`，标记来源为 `"auto"`，记入 `injected_tags`。
3. **处理 `tproxy` 入站**：
   - 查找首个 `type == "tproxy"` 且承载 UDP（未设 `network`，或 `network == "udp"`，或数组含 `"udp"`）的入站：
     - 若存在：复用之，读取 `listen_port`（同上检查回环绑定并记录 `0.0.0.0` 双栈 warning）；标记来源为 `"user"`。
     - 若不存在：校验 `uci.proxy.tproxy_port` 未被已有入站占用后，追加 `{ "type": "tproxy", "tag": "nimbus-tproxy-in", "listen": default_listen, "listen_port": <uci.proxy.tproxy_port>, "network": "udp" }`，标记来源为 `"auto"`，记入 `injected_tags`。
4. **Tag 重映射**：若 `stripped_tags` 非空，**递归遍历** `cfg.route.rules` 与 `cfg.dns.rules`（包含嵌套在 `type == "logical"` 规则 `rules` 子数组内的规则），将 `inbound` 字段（支持字符串或字符串数组）内命中的旧 `tun` tag 替换为当前生效的 `[redirect_tag, tproxy_tag]` 并去重。

#### Step 4：本地 DNS 入站与死循环防护（`dns.mode == 'singbox'` 或 `global.proxy_local == '1'`）
1. **仅当 `dns.mode == 'singbox'` 时**：校验 `cfg.dns.servers` 非空，并查找是否已有可通过 IPv4 回环访问（`listen` 为 `127.0.0.1` / `0.0.0.0` / `::`）、支持 UDP（未设 `network`、`network == "udp"` 或含 `"udp"`）且在 `route.rules` 中被 `action: "hijack-dns"` 引用的 `type == "direct"` 入站：
   - 若存在：复用其 `listen_port` 作为 `effective_dns_port`。
   - 若不存在：校验 `uci.dns.singbox_dns_port` 未与已有入站端口冲突后，追加 `{ "type": "direct", "tag": "nimbus-dns-in", "listen": "127.0.0.1", "listen_port": <uci.dns.singbox_dns_port> }`，并在 `cfg.route.rules` 最前端插入 `{ "inbound": ["nimbus-dns-in"], "action": "hijack-dns" }`。
2. **DNS 死循环防护与 `type: "local"` 自动适配（`dns.mode == 'singbox'`，或 `global.proxy_local == '1'` 且 `cfg.dns.servers` 非空时）**：
   - 检查 `cfg.dns.servers` 中是否包含 `type == "local"`（或旧格式 `address == "local"`）条目：`dns.mode == 'singbox'` 时 `dnsmasq` 转发至 `sing-box` 而 `local` 反向查询 `127.0.0.1` 会形成 DNS 环路；`dns.mode != 'singbox'` 但开启 `proxy_local == '1'` 时，`sing-box` 解析节点域名经 `local` 请求 `dnsmasq`（无 `0xff` 标记）亦会被 `output_udp`/`output_tcp` 环回至 `sing-box` 引发冷启动死锁。因此上述两种场景均不可保留原始 `local` 上游。
   - 按 `uci.dns.local_dns_policy`（默认 `'auto'`）处理：
     - **`'reject'`**：保持严格模式，直接中止合成并返回明确校验错误。
     - **`'fallback'`**：直接使用 `uci.dns.local_fallback_server`（须为合法非回环单播 IP，若开启 IPv6 关闭则不可为 IPv6）运行期改写为 `{ "type": "udp", "server": <ip> }`（保留原 `tag`/`detour` 等字段，剥离 `prefer_go`/`address`）。
     - **`'auto'`（默认）**：从 `ubus network.interface.dump`（`wan_interfaces` 及非环回 `up` 接口 `dns-server`）与 `/tmp/resolv.conf.d/resolv.conf.auto` 读取上游 DNS，严格过滤回环（`127.0.0.0/8`、`::1`）、未指定（`0.0.0.0`、`::`）、链路本地、路由器自身全部接口 IP 以及关闭 `ipv6_enable` 时的 IPv6 地址，优先选用首个安全 IPv4（否则安全 IPv6）：
       - **旁路由风险提示**：当 `global.topology == 'side'` 且选中的上游 DNS 位于当前 LAN 子网内时，在 `warnings` 中提示存在主旁路由相互转发 DNS 死循环风险（若不适用可在 Settings 改为 `fallback` 并指定直连 DNS）。
       - **兜底与错误边界**：若暂未检测到安全的非回环 WAN DNS，且 `uci.dns.local_fallback_server` 非空合法，则先使用该兜底 IP 改写并在 `warnings` 中标注（`hotplug` 在 WAN 上线/DNS 变更后自动热重载为最新 WAN DNS）；若 `local_fallback_server` 为空，则中止合成并返回明确校验错误。

#### Step 5：现代路由动作注入（嗅探与 QUIC 拒绝）
- **嗅探（Sniff）**：严禁向任何自动生成的入站写入已移除的入站级 `sniff` 字段。检查 `cfg.route.rules` 是否已存在无 `inbound` 限制的全局 `{ "action": "sniff" }` 规则：
  - 当 `injected_tags` 非空，或 `uci.proxy.sniff == '1'` / `uci.proxy.block_quic == '1'`（以及存在从旧版入站级 `sniff` 迁移而来的 tag）且目标生效透明代理入站尚无嗅探覆盖时，在 `cfg.route.rules` 头部（`hijack-dns` 之后）按需插入 `{ "inbound": ["<target_tags...>"], "action": "sniff" }`。
- **QUIC 拒绝**：若 `uci.proxy.block_quic == '1'` 且现有规则中尚无 `protocol: "quic"` 的 `reject` 规则，紧跟在 `sniff` 规则之后插入：
  ```json
  { "protocol": "quic", "action": "reject" }
  ```

#### Step 6：Fake-IP 网段自动探测
遍历 `cfg.dns.servers`（现代 `sing-box` 1.12+ 规范格式），筛选 `type == "fakeip"` 的条目，收集 `inet4_range` 与 `inet6_range`，校验格式合法后输出至 `fakeip.ipv4` / `fakeip.ipv6`，交由 `nft_manager.uc` 写入 `fakeip_v4` / `fakeip_v6` Set。

#### Step 7：双 API 与 Dashboard 自动探测
1. **原生 sing-box API**：遍历顶层 `cfg.services`（数组），筛选 `type == "api"` 的条目：
   - 解析 `listen`、`listen_port`、`secret`、`tls`（`tls && tls.enabled === true` 则 `scheme = "https"`，否则 `"http"`）。
   - 解析 `dashboard` 三种官方合法形态：
     - `dashboard === true` -> `dashboard_enabled = true`, `dashboard_path = "/dashboard/"`
     - `type(dashboard) == "string" && length(dashboard) > 0` -> `dashboard_enabled = true`, `dashboard_path = "/dashboard/"`
     - `type(dashboard) == "object" && dashboard.enabled === true` -> `dashboard_enabled = true`, `dashboard_path = "/dashboard/"`（对象形态下 `enabled` 缺省值为 `false`）
     - 其他 -> `dashboard_enabled = false`
   - 安全与可达性标注：
     - `listen` 为 `127.0.0.1` 或 `::1` 时标记 `loopback_only: true`；
     - 非回环监听且 `secret` 为空时标记 `no_secret: true`。
2. **Clash API**：检查 `cfg.experimental.clash_api`：
   - 若存在且 `external_controller` 非空，兼容解析 `:9090`、`0.0.0.0:9090`、`[::]:9090`、`127.0.0.1:9090`、`[::1]:9090` 等格式提取 `listen` 与 `port`，解析 `secret`、`external_ui` 是否配置，并同步标注 `loopback_only` 与 `no_secret`。
   - **密钥隔离**：返回上下文可携带 `has_secret` 及仅供校验的摘要；写入 `/var/run/nimbus/state.json` 时剥离明文 `secret`，前端仅在用户点击复制控制面板配置时通过写权限 `api_secret` RPC 按需从 `/var/run/nimbus/config.json`（`0600`）读取。

#### Step 8：配置预校验与原子发布
1. 序列化写入 `/var/run/nimbus/config.json.tmp`（权限 `0600`）。
2. 执行 `<bin_path> check -c /var/run/nimbus/config.json.tmp -D /tmp/nimbus-check-dir`（使用独立临时工作目录，避免触碰在线运行进程持锁的 `/var/run/nimbus/cache.db`）并捕获标准错误输出。
3. 退出码为 `0` 时 `rename()` 原子替换 `/var/run/nimbus/config.json`（保持 `0600`）；非 `0` 时清理临时文件并保留错误文本供上层 Fail Handler 处理及记录至 `state.json`。

---

## 5. 白名单解析与热更新规范 (`list_updater.uc`)

### 5.1 统一文本解析器（`url` 与 `local` 共用）

逐行按以下顺序清洗并校验：
1. 去除行尾 `\r`，裁剪首尾空白字符（空格、Tab）。
2. 剥离注释：截断首个 `#`、`//` 或 `;` 及其之后的全部内容，再次裁剪首尾空白。
3. 空行跳过。
4. 校验格式：
   - **IPv4**：合法 IPv4 地址（`a.b.c.d`，每段 `0–255`）或 CIDR（前缀长度 `1–32`，严禁 `/0` 默认路由）。
   - **IPv6**：合法 IPv6 地址（含 `::` 压缩格式）或 CIDR（前缀长度 `1–128`，严禁 `/0` 默认路由）。
   - **异常内容拒收**：若文本包含 HTML 特征（如 `<html`、`<!doctype`）或存在非法行：
     - `local` 保存接口：直接拒绝保存，返回首个/前 10 个错误行号与内容，不覆盖原文件。
     - `url` 拉取任务：丢弃临时文件，保留原缓存与当前 `nftables` Set，记录错误日志。
5. 按 `list_source.family`（`auto` / `ipv4` / `ipv6`）分别归入 `v4_entries` 与 `v6_entries`。

### 5.2 远程白名单拉取、热更新与 `crond` 同步

1. 对每个已启用的 `type='url'` 源：
   - 缓存路径固定为 `/etc/nimbus/lists/cache/<section_id>.txt`。
   - 使用 `curl -fsSL --connect-timeout 15 --max-time 60` 下载至 `/tmp/nimbus-list-<id>.tmp`；若缓存已存在，附加 `-z <cache_path>` 利用 HTTP `If-Modified-Since` 避免无效传输（304 跳过）。
   - 当 `via_proxy == '1'` 且运行期配置中存在可用本地代理入站（`mixed`/`http`/`socks`）时，附加 `--proxy` 参数经本地代理拉取。
   - 对下载结果执行 5.1 解析校验，确保有效条目数 `>= 1`。
   - 计算临时文件与原缓存文件的 `SHA256`：仅哈希不同时原子 `rename()` 更新缓存文件。
2. 合并全部已启用 `list_source`（`url` 缓存 + `local` 文件）的合法条目，生成 `/var/run/nimbus/bypass_sets.nft` 并执行 `nft -f /var/run/nimbus/bypass_sets.nft` 完成无感热刷新（若 `nft -f` 执行失败必须准确向上层返回错误码与错误信息，禁止吞掉失败结果）；随后在后台通过 `nft -j list set inet nimbus bypass_v4/v6` 读取经 `auto-merge` 合并后的实际加载元素数同步更新 `/var/run/nimbus/state.json`，供只读 RPC `list_status` 无阻塞直接读取（服务处于 `stopped` 态时 `nft_loaded` 返回 `0`）。
3. **定时同步管理**：根据 `whitelist.auto_update` 与 `whitelist.update_cron` 原子同步 `/etc/crontabs/root` 中带 `# nimbus-whitelist` 标记的行，变更时重载 `cron`。

---

## 6. `dnsmasq` 托管规范 (`dns_manager.uc`)

快照文件固定位于 `/etc/nimbus/dns_backup.json`，记录 `dhcp.@dnsmasq[0]` 的原始字段：`noresolv`、`resolvfile`、`server`、`cachesize`、`dnssec`。

1. **首次接管（`mode` 为 `'singbox'` 或 `'custom'`）**：
   - 若 `/etc/nimbus/dns_backup.json` 不存在，先读取当前 `dhcp.@dnsmasq[0]` 并原子写入备份快照（已有快照时绝不覆写，防止多次重载冲掉最初备份）。
   - **`mode == 'singbox'`**：设置 `noresolv='1'`、`server=['127.0.0.1#' + effective_dns_port]`（如 `'127.0.0.1#5353'`）、`cachesize='0'`、`dnssec='0'`。
   - **`mode == 'custom'`**：设置 `noresolv='1'`、`server=uci.dns.custom_servers`（保留原有 `cachesize`/`dnssec`）。
   - 执行 `uci commit dhcp` 并调用 `/etc/init.d/dnsmasq reload`。
2. **无损还原（`mode == 'none'`、服务停止、`fail_open='1'` 回落直连或包卸载 `prerm`）**：
   - 若 `/etc/nimbus/dns_backup.json` 存在，按快照逐项恢复 `dhcp.@dnsmasq[0]`（原值为 `null` 的字段执行 `uci delete`），提交 `dhcp` 并重载 `dnsmasq`，随后删除备份文件。

---

## 7. `sing-box` 内核管理与架构映射规范 (`core_manager.uc`)

### 7.1 OpenWrt 架构精准映射表

读取 `/etc/openwrt_release` 的 `DISTRIB_ARCH`（回退结合 `uname -m`）并检测 `/lib/ld-musl-*.so.1` 判定 `libc` 与浮点 ABI：
- 对 32 位 ARM（`armv7`/`armv6`/`armv5`），前置检测 `/lib/ld-musl-armhf.so.1` 是否存在：若存在（硬浮点）优先匹配 `-musl.tar.gz`，若为软浮点（仅 `/lib/ld-musl-arm.so.1`）则直接选用纯 Go 静态非 `-musl` 资产 `sing-box-<ver>-linux-<target>.tar.gz`；
- 其余架构在检测到 `musl` 时优先匹配 `sing-box-<ver>-linux-<target>-musl.tar.gz`，若目标仓库资产无 `-musl` 后缀则回退匹配 `sing-box-<ver>-linux-<target>.tar.gz`（安装前均须通过可执行测试验证）。

| OpenWrt `DISTRIB_ARCH` 匹配前缀 | `sing-box` Release `<target>` |
| :--- | :--- |
| `x86_64` | `amd64` |
| `i386_*` | `386` |
| `aarch64_*` | `arm64` |
| `arm_cortex-a7*`, `arm_cortex-a9*`, `arm_cortex-a15*`, `arm_cortex-a5*`, `arm_cortex-a8*` | `armv7` |
| `arm_arm1176*`, `arm_mpcore*` | `armv6` |
| `arm_arm926*`, `arm_xscale*` | `armv5` |
| `mipsel_*` | `mipsle-softfloat` |
| `mips_*` | `mips-softfloat` |
| `mips64el_*` | `mips64le` |
| `mips64_*` | `mips64` |
| `riscv64_*` | `riscv64` |
| `loongarch64*` | `loong64` |

### 7.2 GitHub Release 查询与下载安全流水线

1. **版本查询**：
   - `channel == 'stable'`：`GET https://api.github.com/repos/<repo>/releases/latest`
   - `channel == 'prerelease'`：`GET https://api.github.com/repos/<repo>/releases?per_page=10`，选取首条 `draft == false` 的 Release。
   - 若 `core.download_via_proxy == '1'` 且本地代理入站可用，版本查询与资产下载均附加 `--proxy`；若配置了 `core.mirror_prefix`，对资产下载 URL 拼接镜像前缀。API 失败时直接返回明确 `E_NETWORK` 错误。
2. **两阶段空间检查**：
   - **下载前预检**：检查 `/tmp` 可用空间 `>= max(asset_size * 3.5, 55MB)`，且 `dirname(core.bin_path)` 可用空间 `>= max(asset_size * 3.0, 40MB)`（若 `/tmp` 与目标目录位于同一文件系统，则合并按总量校验；不足则中止下载并报 `E_DISK_SPACE`）。
   - **解压后复检**：解压出 `sing-box` 裸二进制后，获取实际解压体积 `bin_size`，再次校验 `dirname(core.bin_path)` 可用空间 `>= bin_size * 1.2`（避免 `.tar.gz` 高压缩比导致误判 `ENOSPC`）。
3. **下载、校验与可执行验证**：
   - 下载至独立临时目录 `/tmp/nimbus-core-dl/`。
   - 若 Release 资产包含校验文件（如 `SHA256SUMS` / `checksums.txt` / `.sha256`）或 GitHub API 资产对象提供 `digest`（`sha256:...`），强制校验压缩包 `SHA256`，不匹配立即中止。
   - 解压提取 `sing-box` 可执行文件，赋予 `0755` 权限，执行 `<tmp_bin> version` 验证退出码为 `0` 且输出包含 `sing-box version`。
4. **原子替换**：
   - 确保目标父目录存在；将新二进制写入同目录临时文件 `<bin_path>.new` 并 `rename()` 原子替换 `<bin_path>`，清理 `/tmp/nimbus-core-dl/`。
   - 若更新前服务处于 `running` 态，立即触发服务重载。

---

## 8. 订阅配置管理与定时同步规范 (`profile_updater.uc`)

负责处理所有 `type == 'subscription'` 的 `config profile` 远程拉取、预校验与定时更新：

1. **拉取与预校验**：
   - 使用 `curl -fsSL --connect-timeout 15 --max-time 60 -A <profile.user_agent>` 下载至 `/tmp/nimbus-sub-<id>.tmp`；当 `profile.via_proxy == '1'` 且本地代理入站可用时附加 `--proxy`。
   - 解析为 JSON 并调用 `config_builder.uc` 在隔离临时目录 `/tmp/nimbus-check-dir` 执行完整合成与 `sing-box check -c ... -D /tmp/nimbus-check-dir`；任何失败均直接丢弃临时文件，**严禁覆写** `/etc/nimbus/profiles/<filename>`。
2. **哈希比对与原子替换**：
   - 计算临时文件与现有 `/etc/nimbus/profiles/<filename>` 的 `SHA256`：哈希一致则记为 `"unchanged"` 不触发写盘；仅当变化时写入同目录临时文件并 `rename()` 原子替换，确保闪存零无效磨损。
   - 若本次更新的是当前 `global.active_profile` 且服务处于 `running` 态，在互斥锁保护下自动触发运行期配置重建与平滑重载。
3. **定时调度（每小时分发器）**：
   - 因标准 5 段 Cron 无法精确表达任意小时周期（UCI `update_interval_hours` 为 `1`–`720`），当存在至少 1 个启用 `auto_update == '1'` 的订阅时，在 `/etc/crontabs/root` 注册一条每小时整点触发的任务（`0 * * * * ... # nimbus-profile`）。
   - 分发器遍历所有 `type == 'subscription'` 且 `auto_update == '1'` 的配置，检查 `(now - stat(file).mtime) >= update_interval_hours * 3600`（文件不存在视作立即到期），到期则执行 1–2 步更新流程。

---

## 9. 进程监督器与日志轮转规范 (`supervisor.uc`)

由 `/etc/init.d/nimbus` 通过 `procd` 直接启动（**不开启 `procd_set_param respawn`**），采用纯 `ucode` + `uloop` 实现：

1. **进程托管与 PID**：注入 `GOMEMLIMIT` 与 `GOGC=50`，拉起 `sing-box run -c /var/run/nimbus/config.json -D /var/run/nimbus`，将真实子进程 PID 写入 `/var/run/nimbus/sing-box.pid`。
2. **主动停机 vs 异常崩溃区分**：
   - 捕获 `SIGTERM` / `SIGINT`（OpenWrt 24.10+ 优先使用 `uloop.signal`，在 OpenWrt 23.05 等未导出 `uloop.signal` 的 `ucode` 版本上回退至内建 `signal()` 配合 `uc_vm_signal_notifyfd` 唤醒 `uloop`）：置 `stopping = true`，向 `sing-box` 发送 `SIGTERM`（最多等待 5 秒后发送 `SIGKILL`），清理 `sing-box.pid` 后干净退出，**不触发** Fail Handler。
3. **崩溃重试窗口与 Fail Handler**：
   - 若非 `stopping` 下 `sing-box` 异常退出，内部维护重试窗口（默认阈值 `3600s`、退避 `3s`、最多重试 `5` 次）：窗口内瞬时崩溃直接拉起并更新 `sing-box.pid`，期间防火墙表与路由保持在线零泄漏。
   - 连续崩溃耗尽重试上限时，清理 `sing-box.pid`，获取锁并调用统一 Fail Handler（`fail_open='0'` 切换为 `LOCKDOWN`；`fail_open='1'` 删表清路由并还原 `dnsmasq`）后主动退出，由 `procd` 保持停止态不再拉起。
4. **日志滞回截断轮转**：
   - 注册 `30s` 周期 `uloop.timer` 检查 `/var/log/nimbus.log` 大小：当体积超过 `524288` 字节（`512KB`）时，就地截取末尾 `262144` 字节（`256KB`，并对齐至首个 `\n` 完整行首），通过原地回写 + `f.truncate()` 完成截断；利用 `sing-box` 原生 `O_APPEND` 打开日志文件的特性，杜绝管道转发开销、空洞文件及删除 inode 导致的内存泄漏。