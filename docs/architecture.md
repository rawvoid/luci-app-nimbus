# System Architecture — luci-app-nimbus

本文档定义 `nimbus`（核心包）与 `luci-app-nimbus`（前端包）的系统分层架构、拓扑适配矩阵、完整生命周期状态机、存储分层模型以及双格式（`opkg` / `apk`）CI/CD 发布架构。

---

## 1. 分层架构总览

系统划分为**控制面（Control Plane）**、**数据面（Data Plane）**与**分层存储面（Storage Plane）**，核心逻辑全部运行在 OpenWrt 原生 `ucode` 运行时上。

```text
+-----------------------------------------------------------------------+
|  Browser (LuCI Client-side JS: /www/luci-static/resources/view/nimbus)|
+-----------------------------------+-----------------------------------+
                                    | ubus (HTTP/JSON-RPC, ACL protected)
                                    v
+-----------------------------------------------------------------------+
|  Control Plane                                                        |
|  +-----------------------------+   +-------------------------------+  |
|  | rpcd-mod-ucode              |   | procd (/etc/init.d/nimbus)    |  |
|  | /usr/share/rpcd/ucode/      |   | -> supervisor.uc (ucode)      |  |
|  | luci.nimbus.uc (非阻塞)     |   | hotplug.d | crond (list/sub)  |  |
|  +--------------+--------------+   +---------------+---------------+  |
|                 |                                  |                  |
|                 v                                  v                  |
|  +-----------------------------------------------------------------+  |
|  | /usr/share/nimbus/*.uc  (受 /var/run/nimbus/nimbus.lock 串行保护) |  |
|  |  config_builder | nft_manager | route_manager | dns_manager     |  |
|  |  core_manager   | list_updater| profile_updater| supervisor/common| |
|  +--------+---------------+---------------+---------------+--------+  |
+-----------|---------------|---------------|---------------|-----------+
            |               |               |               |
            v               v               v               v
+-----------------------------------------------------------------------+
|  Data Plane (内核态 + sing-box)                                        |
|  +-------------------+  +-------------------+  +-------------------+  |
|  | table inet nimbus |  | Policy Routing    |  | dnsmasq (UCI)     |  |
|  | (完全独立于 fw4)  |  | ip -4/-6 rule     |  | 备份/接管/无损还原 |  |
|  | 双栈白名单 Set    |  | table 100 (TPROXY)|  |                   |  |
|  +---------+---------+  +---------+---------+  +---------+---------+  |
|            |                      |                      |            |
|            +----------+-----------+----------------------+            |
|                       v                                               |
|            +---------------------+                                    |
|            | sing-box (由        |  <-- -D /var/run/nimbus            |
|            | supervisor.uc 托管) |      GOMEMLIMIT / RLIMIT_NOFILE    |
|            | REDIRECT + TPROXY   |      sing-box.pid                  |
|            +---------------------+                                    |
+-----------------------------------------------------------------------+
```

---

## 2. 单仓库多包（Monorepo Feed）边界设计

仓库根目录符合 OpenWrt Feed 规范，对外产出全架构通用包（`PKGARCH:=all`）：

### 2.1 `nimbus`（核心服务包）
- **职责**：UCI 默认配置、服务生命周期管理、防火墙独立表、策略路由、DNS 托管、多源白名单与订阅热更新、内核下载与校验、`rpcd` ucode 接口。
- **独立性**：不依赖任何 LuCI 组件，可在无 Web 界面的 OpenWrt 固件上通过 UCI 与 `ubus` 完整运行。
- **包依赖声明**：
  - **运行时依赖**：`ucode`、`ucode-mod-fs`、`ucode-mod-uci`、`ucode-mod-ubus`、`ucode-mod-uloop`、`rpcd-mod-ucode`、`nftables-json`（强依赖，用于 `nft -j`；不兼容 `nftables-nojson`）、`ip-full`（通过 OpenWrt `ALTERNATIVES` 优先级 `300` 与 `ip-tiny` 无冲突共存，规避 OpenWrt 25.12 `apk` 虚拟 `+ip` 解析歧义）、`ca-bundle`、`curl`。
  - **内核模块依赖**：`kmod-nft-core`、`kmod-nft-fib`（支持 `fib daddr type local`）、`kmod-nft-nat`、`kmod-nft-tproxy`。
- **卸载清理钩子（`Package/nimbus/prerm`）**：包卸载/移除前停止 `nimbus` 服务，删除 `table inet nimbus`、清空策略路由、从快照无损还原 `dnsmasq`，并移除 `/etc/crontabs/root` 中所有 `nimbus` 定时任务。

### 2.2 `luci-app-nimbus`（前端交互包）
- **职责**：LuCI 客户端 JS 视图、菜单路由（`menu.d`）、最小权限 ACL（`acl.d`）及多语言包（`luci-i18n-nimbus-zh-cn` 等）。
- **包依赖声明**：`+nimbus`、`+luci-base`。

---

## 3. 运行组合矩阵与主/旁路由适配

`nimbus` v1.0 聚焦于稳定完备的 **`proxy_mode = 'tproxy_redirect'`**，通过正交维度定义运行行为：**`{main, side}` × `{fail_open=0, fail_open=1}`**（`proxy_mode` 保留枚举扩展位，于 v1.1+ 引入 `tun` 模式）。

### 3.1 主路由模式 (`topology = 'main'`) vs 旁路由模式 (`topology = 'side'`)

| 适配项 | 主路由模式 (`main`) | 旁路由模式 (`side`) |
| :--- | :--- | :--- |
| **入站监听接口** | 用户选定的 LAN 逻辑接口（默认 `lan`，解析为 `br-lan`） | 同左（通常仅有一个 `lan` 接口） |
| **LAN 子网动态绕行** | 提取 `lan_interfaces` 的全部 IPv4/IPv6 前缀写入 `lan_v4` / `lan_v6` Set，防止 LAN 内 IPv6 GUA 互访及 `proxy_local='1'` 场景被劫持或形成环路 | 同左（尤其针对旁路由无 `wan6`、IPv6 GUA 无法经 `wan_v6` 覆盖的场景） |
| **出口公网 IP 动态绕行** | 监听 `wan` / `wan6` 的 `hotplug.d/iface` 事件，自动提取公网 IPv4、IPv6 及 PD 前缀写入 `wan_v4` / `wan_v6` Set | 无 `wan`/`wan6` 时静默跳过，不报错、不阻塞启动；保留段、`lan_v4`/`lan_v6` 与 `fib daddr type local` 自动覆盖局域网与本机通信 |
| **Flow Offloading 协同** | 白名单流量在 `prerouting` 直接 `return` 进入 `forward`，完整保留 `fw4` 软/硬件加速；代理 TCP/UDP 流量进入本机处理 | 单臂转发流量走 `lan -> lan`；白名单直接回送上级主路由 |
| **ICMP Redirect 处理** | 保持系统默认 | 启动时自动设置 `net.ipv4.conf.all.send_redirects=0` 与各 LAN 物理设备 `send_redirects=0`，防止旁路由发送 ICMP Redirect 导致客户端绕过代理 |
| **防火墙边界检测** | 不改写 `/etc/config/firewall`：检测 LAN Zone `input` 策略，若非 `ACCEPT` 在 `state.json` 的 `warnings` 中给出诊断提示 | 同左 |

### 3.2 `tproxy_redirect` 数据面处理流水线（v1.1 预留 `tun` 扩展位）

在 `table inet nimbus` 中按以下统一前段筛选流量：
1. 防环路标记 `meta mark $OUTBOUND_MARK return`
2. Fake-IP 自动识别优先通道（跳过保留段与白名单，直进代理）
3. 保留段 / 局域网子网（`lan_v4`/`lan_v6`） / WAN 公网 IP / LAN 设备白名单 `return`
4. 端口过滤（`port_filter_mode`: `all` / `include` / `exclude`）
5. 远程 + 多手动白名单 `bypass_v4` / `bypass_v6` 命中 `return`
6. `ct mark`（`0x10`/`0x20`，掩码 `0x30`）按位首包决策缓存（UDP TPROXY 链）

末尾导流动作：
- **`tproxy_redirect`**：优先复用配置中已有的 `redirect`/`tproxy` 入站（缺失自动补齐，运行期剥离冲突 `tun` 并递归重映射 tag）；TCP 走 `dstnat` 链 `redirect`，UDP 走 `mangle` 链 `tproxy` + 策略路由指向 `local default dev lo`。
- **v1.1+ 扩展预留**：保留 `proxy_mode` 枚举及 `status.effective.tun_iface` / `counters.tun_*` 字段位，后续按需扩展 `tun` 导流分支。

---

## 4. 服务生命周期与状态机

状态机运行态上下文记录于 `/var/run/nimbus/state.json`。

```text
                      [用户启用 / 系统开机]
     +---------+  ---------------------------->  +-----------+
     | STOPPED |                                 | PREPARING |
     +---------+  <----------------------------  +-----+-----+
          ^           (fail_open=1 失败)               |
          |                                           | 1. 合成运行期 config.json
          |                                           | 2. 执行 sing-box check
          |                                           | 3. 校验通过 -> procd 拉起
          |                                           |    supervisor.uc
          |                                           |    校验失败 ----+
          |                                           v                 |
          | [用户手动停止 (SIGTERM)]            +-----------+           |
          +-------------------------------------|  RUNNING  |           |
          |  (停进程、删表、清路由、            +-----+-----+           |
          |   还原 dnsmasq)                           |  ^              |
          |                                           |  | 重载成功       |
          |              白名单原子热更新 (无状态切换)  |  | (配置/内核)    |
          |              [nft -f 事务刷新 Set]         |  |              |
          |                                           |  |              |
          |          supervisor.uc 内核重启耗尽 /      |  |              |
          |          配置重载校验失败                  v  |              v
          |                                     +-----------------------+
          +-------------------------------------|     FAIL HANDLER      |
           (fail_open = 1: 删表、清路由、直连)   +-----------+-----------+
                                                            |
                                              (fail_open = 0, 默认)
                                                            v
                                                   +-----------------+
                                                   |    LOCKDOWN     |
                                                   | (Kill Switch)   |
                                                   +-----------------+
                                                     仅 Hook forward 链,
                                                     阻断非白名单 LAN 转发,
                                                     始终放行路由器管理
```

### 4.1 状态转换与原子动作

| 转换场景 | `sing-box` 进程（经 `supervisor.uc`） | `table inet nimbus` | 策略路由 | `dnsmasq` |
| :--- | :--- | :--- | :--- | :--- |
| **`STOPPED -> PREPARING -> RUNNING`** | 合成 `/var/run/nimbus/config.json` 并执行 `sing-box check`；校验通过后由 `procd` 拉起 `supervisor.uc`（不开 `procd respawn`），写入真实 PID 至 `sing-box.pid` | 原子加载 `running` 规则表（`nft -f`） | 加载表 `100` 双栈 `local` 路由指向 `lo` | 备份原 UCI 后写入托管配置并 `reload` |
| **`RUNNING` 白名单更新** | 不重启、无感知 | 单事务 `nft -f` 仅 `flush` + `add element` 更新 `bypass_v4/v6` | 不变 | 不变 |
| **`RUNNING` 期间内核瞬时崩溃（`supervisor.uc` 重试窗口内）** | `supervisor.uc` 按退避策略自动重新拉起并更新 `sing-box.pid` | 维持 `running` 规则不撤除（流量指向无监听本机端口，零泄漏窗口） | 维持 | 维持 |
| **进入 `LOCKDOWN`（`fail_open=0`，启动失败 / 崩溃耗尽 / 重载校验失败）** | `supervisor.uc` 清理 `sing-box.pid`、调用 Fail Handler 后退出（不触发 `procd respawn`） | 原子切换为 `lockdown` 表（在 `forward` 链对非白名单流量执行 `reject`；不拦截 `input`，LAN 管理流量始终可达） | 清理代理策略路由 | 维持现状，不回退至 ISP DNS（见下述自救说明） |
| **故障回落直连（`fail_open=1`）** | 已退出或停止，`sing-box.pid` 已清理 | 执行 `nft delete table inet nimbus` | 清理表 `100` 及对应 `ip rule` | 从快照无损还原 `dnsmasq` UCI 并 `reload` |
| **用户手动停止** | `procd` 向 `supervisor.uc` 发送 `SIGTERM`；`supervisor.uc` 标记主动停机并转发 `SIGTERM` 给 `sing-box`，不触发 Fail Handler | 执行 `nft delete table inet nimbus` | 清理表 `100` 及对应 `ip rule` | 从快照无损还原 `dnsmasq` UCI 并 `reload` |

> **关于 `LOCKDOWN` + `dns.mode='singbox'` 的本机 DNS 说明**：`LOCKDOWN` 期间保持 `dnsmasq` 指向本机 `sing-box`（`noresolv='1'`）可彻底防止 LAN 侧 DNS 泄漏至运营商。其副作用是路由器本机 `/etc/resolv.conf` 同样指向 `127.0.0.1` (`dnsmasq`)，因此在 `LOCKDOWN` 状态下路由器自身无法解析外部域名（无法直接从 GitHub 拉取新内核或订阅）。前端 `overview` 页的 `LOCKDOWN` 告警横幅必须明确提示：如需通过网络修复或切换直连，请先点击“停止服务”还原 `dnsmasq`。

---

## 5. 存储分层与运行时路径

| 路径 | 介质 | 内容 | 读写策略 |
| :--- | :--- | :--- | :--- |
| `/etc/config/nimbus` | Flash | UCI 用户配置 | 仅用户修改配置时写入；不存放动态状态 |
| `/etc/nimbus/profiles/` | Flash | 本地上传与订阅原始 JSON（只读源） | 订阅更新在 `/tmp` 校验 `sing-box check` 通过且 `SHA256` 变化时原子替换 |
| `/etc/nimbus/lists/local/` | Flash | 多个独立手动白名单 `.txt` 文件 | 用户保存并通过格式校验后原子写入 |
| `/etc/nimbus/lists/cache/` | Flash | 远程白名单源离线缓存 `<section_id>.txt` | `curl -z` 增量拉取，校验通过且 `SHA256` 变化时原子替换；上次更新时间直接读 `mtime` |
| `/etc/nimbus/bin/` | Flash（可自定义外挂盘或 `/tmp`） | `sing-box` 二进制文件 | 仅在用户安装/升级内核时写入；操作前执行两阶段空间检查 |
| `/etc/nimbus/dns_backup.json` | Flash | `dnsmasq` 接管前原始 UCI 快照 | 首次接管写入，还原后删除 |
| `/var/run/nimbus/` | **RAM (`tmpfs`)** | `sing-box -D /var/run/nimbus` 工作目录（承接相对路径 `cache.db` 与 `dashboard/`）、`config.json`（`0600`）、`state.json`（`0600`，不含明文密钥）、`sing-box.pid`、`*.nft`、`core_task.json`、`nimbus.lock` | 全部驻留内存；用户 JSON 中显式绝对路径原样保留 |
| `/var/log/nimbus.log` | **RAM (`tmpfs`)** | 独立运行日志（默认级别 `warn`） | `sing-box` 原生 `O_APPEND` 写入；`supervisor.uc` 定时器实施滞回截断（超过 512KB 时就地截断保留尾部 256KB） |

**固件升级保留（`sysupgrade`）**：`/lib/upgrade/keep.d/nimbus` 注册 `/etc/config/nimbus`、`/etc/nimbus/profiles/`、`/etc/nimbus/lists/` 与 `/etc/nimbus/dns_backup.json`；不包含 `/etc/nimbus/bin/` 下的大体积内核二进制。

---

## 6. 并发控制、进程托管与事件自愈

### 6.1 统一互斥锁与 `rpcd` 非阻塞约定
- CLI（`init.d`、`hotplug.d`、`crond`、Fail Handler）写操作通过 `/var/run/nimbus/nimbus.lock` 串行化，采用带有限超时重试的互斥锁保护。
- `rpcd-mod-ucode` 运行在 `rpcd` 单线程 `uloop` 主循环内：**严禁阻塞等锁或同步执行长耗时 `system()`**。所有写 RPC 入口必须通过 `f.lock('xn')` 非阻塞抢锁（占锁立即返回 `E_LOCKED`），耗时操作通过 `uloop.process` + 延迟 `req.reply()` 异步派发或独立后台进程执行，杜绝冻结全路由器 LuCI / `ubus`。

### 6.2 `procd`、`supervisor.uc` 托管与差异化重载
- **工作目录与权限**：`sing-box run -c /var/run/nimbus/config.json -D /var/run/nimbus`，`config.json` 与 `state.json` 权限固定为 `0600`。
- **动态 `GOMEMLIMIT`**：若 UCI `global.gomemlimit == 'auto'`，读取 `/proc/meminfo` 的 `MemTotal`，按 `min(MemTotal * 0.4, 256MiB)` 注入环境变量 `GOMEMLIMIT` 与 `GOGC=50`；否则注入用户指定值。
- **系统限制与内核缓冲**：`procd_set_param limits nofile="65535 65535"`（由 `supervisor.uc` 子进程继承）；启动时若当前值小于 `4194304`，自动提升 `net.core.rmem_max` 与 `net.core.wmem_max` 至 4MB。
- **为什么用 `supervisor.uc` 而不对主进程开 `procd respawn`**：
  1. `procd` 会在进程任何退出（包括 `exit 0`）后强制拉起，且崩溃耗尽 `respawn` 后**不提供脚本回调**，既无法触发 `LOCKDOWN` 也无法在进入 `LOCKDOWN` 后阻止 `procd` 把服务再次拉起。
  2. 因此 `procd` 仅直接托管 `/usr/share/nimbus/supervisor.uc`（**不配置 `procd_set_param respawn`**）。`supervisor.uc`（纯 `ucode` + `uloop`）负责：
     - 拉起 `sing-box` 并将其真实 PID 写入 `/var/run/nimbus/sing-box.pid`；
     - 捕获 `SIGTERM`/`SIGINT` 标记主动停机，转发 `SIGTERM` 给 `sing-box`（5s 宽限后 `SIGKILL`），清理 PID 文件后干净退出（**不触发** Fail Handler）；
     - 内部维护崩溃重试窗口（如 3600s 窗口 / 3s 退避 / 最多 5 次）；瞬时崩溃期间保留防火墙表与路由；耗尽重试次数后删除 PID 文件、执行统一 Fail Handler（按 `fail_open` 切入 `LOCKDOWN` 或回落直连）并自身退出；
     - 每 30s 通过 `uloop.timer` 检查 `/var/log/nimbus.log`：超过 512KB 时就地截断保留尾部 256KB（对齐换行边界），配合 `sing-box` 原生 `O_APPEND` 打开模式避免管道转发开销与空洞文件。
- **异常回调**：启动校验失败或 `supervisor.uc` 重试耗尽时，统一调用 Fail Handler 按 `fail_open` 执行切入 `LOCKDOWN` 或回落直连。
- **智能差异化重载（`reload_service`）**：`init.d` 通过 `procd_add_reload_trigger "nimbus"` 响应 UCI 变更；`reload_service` 先合成临时配置 `/var/run/nimbus/config.json.tmp` 并将其 `SHA256` 与在线 `/var/run/nimbus/config.json` 比对，同时刷新规则表、路由及 `dnsmasq` 与 `crond`；若 `config.json` 哈希未变化（例如仅修改 `core.mirror_prefix` 或 `whitelist.*`），则**跳过重启 `sing-box` 进程**（仍确保双态规则/Set 与定时任务同步）。

### 6.3 `hotplug.d/iface/90-nimbus` 事件自愈
监听网络接口的 `ifup` / `ifupdate` / `ifdown` 事件：
- **WAN/WAN6 与 LAN 前缀变更**：主路由模式提取最新公网 `wan_v4` / `wan_v6`；所有模式均刷新 `lan_interfaces` 的最新 `lan_v4` / `lan_v6` 前缀，执行单事务 `nft -f` 原子刷新对应 Set，不重启 `sing-box`。
- **策略路由自愈**：当 `state.json` 处于 `running` 态时，检查 `ip -4/-6 rule` 与表 `100` 路由是否被 `netifd` 重载清除，缺失则自动补回。

---

## 7. GitHub Actions CI/CD 与 GitHub Pages 双格式软件源架构

项目为纯 `PKGARCH:=all` 包，所有校验、打包与双格式软件源签名托管均由 GitHub Actions 自动完成。

### 7.1 CI 三阶段流水线

```text
[Push / PR / Tag]
       │
       ▼
Stage 1: Lint & Unit Tests (每次提交运行: .github/workflows/ci.yml，M1 交付)
  ├── Job A [openwrt/rootfs:x86-64-openwrt-24.10 容器]:
  │     ├── ucode -S -c -o /dev/null（独立脚本）与 ucode -S -L ... -e "import ..."（ES 模块全量语法校验）
  │     └── tests/run_tests.sh (config_builder / nft_manager / list_updater / profile_updater / core_manager / dns_manager / supervisor / rpc 单测)
  └── Job B [Ubuntu Runner 宿主机]:
        ├── shellcheck -s sh (init.d / hotplug.d / uci-defaults / scripts / tests)
        ├── JSON 合法性校验 (menu.d / acl.d / fixtures)
        ├── 下载真实 sing-box (linux-amd64-musl) 对合成配置执行 `sing-box check -c <out> -D /tmp/nimbus-check-dir`
        ├── 执行 `sudo nft -c -f` 校验双态 nftables 规则语法
        └── ESLint / Node (`node --check`) 校验 LuCI JS 代码规范
       │
       ▼
Stage 2: Dual-Format SDK Build Matrix (打 Tag 或 workflow_dispatch dry_run 触发: .github/workflows/release.yml，M1 交付骨架并于 M6 终验)
  ├── Job A [opkg]: openwrt/sdk:x86-64-openwrt-24.10
  │     ├── 若为按需初始化镜像先执行 `[ ! -d ./scripts ] && ./setup.sh`
  │     ├── 挂载仓库为本地 feed: `src-link nimbus $GITHUB_WORKSPACE`，执行 `feeds update luci nimbus && feeds install -a -p luci -p nimbus`（`luci-app-nimbus` 通过 `include $(TOPDIR)/feeds/luci/luci.mk` 构建）
  │     ├── 编译 nimbus + luci-app-nimbus + luci-i18n-nimbus-zh-cn -> *_all.ipk
  │     └── 使用仓库 Secrets 中的 `USIGN_PRIVATE_KEY` 生成签名索引 Packages / Packages.gz / Packages.sig
  └── Job B [apk]:  openwrt/sdk:x86-64-openwrt-25.12
        ├── 同方式初始化并挂载本地 feed 编译产出 *.apk
        └── 使用仓库 Secrets 中的 `APK_PRIVATE_KEY`（EC P-256）通过 `apk mkndx` 生成内嵌签名索引 packages.adb
       │
       ▼
Stage 3: Release & GitHub Pages Deploy (仅非 dry_run 的正式 Tag 触发)
  ├── 发布 GitHub Release（附带全部 .ipk / .apk 与 SHA256SUMS）
  └── 合并 opkg/ 与 apk/ 产物目录并部署至 GitHub Pages（`index.html` 中 `apk` 安装指引须提示将 `/etc/apk/keys/nimbus-apk.pem` 单文件路径追加至 `/etc/sysupgrade.conf`，切勿保留整个 `/etc/apk/keys/` 目录）
```

### 7.2 GitHub Pages 软件源目录结构

```text
https://<owner>.github.io/luci-app-nimbus/
├── index.html                  # 安装指引页（opkg / apk 源配置命令）
├── keys/
│   ├── nimbus-usign.pub        # opkg 校验公钥 (usign)
│   └── nimbus-apk.pem          # apk 校验公钥 (EC P-256)
├── opkg/
│   └── all/
│       ├── Packages
│       ├── Packages.gz
│       ├── Packages.sig
│       ├── nimbus_<ver>_all.ipk
│       ├── luci-app-nimbus_<ver>_all.ipk
│       └── luci-i18n-nimbus-zh-cn_<ver>_all.ipk
└── apk/
    └── all/
        ├── packages.adb        # 含签名的 apk 索引
        ├── nimbus-<ver>.apk
        ├── luci-app-nimbus-<ver>.apk
        └── luci-i18n-nimbus-zh-cn-<ver>.apk
```