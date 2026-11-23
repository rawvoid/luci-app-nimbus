# Development Milestones & Acceptance Criteria — luci-app-nimbus

本文档定义 `luci-app-nimbus` 的六阶段递进式开发计划与验收门禁。开发必须严格按阶段顺序推进：**当前阶段的全部交付物与自动化验收项全部通过后，方可进入下一阶段**。

---

## 执行规则

1. **单阶段闭环**：每个里程碑对应独立的提交集合（Conventional Commits），不跨阶段提前堆砌未验证代码。
2. **契约优先**：实现前对照 `AGENTS.md` 及对应 `docs/*.md` 契约文档；若发现必须修改字段或接口，先更新文档再改代码。
3. **测试伴随**：M2–M5 的每个核心 `ucode` 模块必须附带可独立运行的单元测试与 Fixture（置于 `tests/unit/` 与 `tests/fixtures/`）。
4. **零漂移检查**：每个阶段结束前必须执行 `AGENTS.md` 第 7 节的全部静态与单元校验。

---

## M1：工程骨架、OpenWrt Feed 打包与 CI/双轨 SDK 流水线

**目标**：建立合规的单仓库多包 OpenWrt Feed 结构，打通自动化静态检查与 `.ipk` + `.apk` 双轨 SDK 编译签名流水线（通过 `dry_run` 验证构建与索引，正式发布留待 M6 完成全部功能后触发）。

### 交付物
- 顶层及双包目录与构建文件：
  - `nimbus/Makefile`（`PKGARCH:=all`，声明完整运行时含 `+ucode-mod-uloop`、`+ip-full`、`+nftables-json` 与内核模块 `+kmod-nft-core`、`+kmod-nft-fib`、`+kmod-nft-nat`、`+kmod-nft-tproxy` 依赖，提供 `Package/nimbus/prerm` 卸载还原钩子）
  - `luci-app-nimbus/Makefile`（`PKGARCH:=all`，通过 `include $(TOPDIR)/feeds/luci/luci.mk` 构建，依赖 `+nimbus +luci-base`，自动生成 `luci-i18n-nimbus-zh-cn`）
- 软件源公钥（严禁提交私钥进仓库）：
  - `keys/nimbus-usign.pub` 与 `keys/nimbus-apk.pem`
- 基础系统文件：
  - `nimbus/files/etc/config/nimbus`（与 `docs/uci-schema.md` 第 3 节完全一致）
  - `nimbus/files/etc/uci-defaults/99-nimbus`（初始化 `/etc/nimbus/{profiles,lists/local,lists/cache,bin}` 目录与默认 `custom_direct.txt`）
  - `nimbus/files/lib/upgrade/keep.d/nimbus`（保留 `/etc/config/nimbus`、`/etc/nimbus/profiles/`、`/etc/nimbus/lists/`、`/etc/nimbus/dns_backup.json`，不包含内核二进制）
  - `nimbus/files/usr/share/nimbus/common.uc`（常量定义、UCI 读取封装、`/var/run/nimbus/nimbus.lock` 互斥锁、`/var/run/nimbus/state.json` `0600` 原子读写、日志工具函数）
- 测试基础设施：
  - `tests/run_tests.sh`（统一测试入口）
- GitHub Actions 工作流：
  - `.github/workflows/ci.yml`（Push/PR 触发：拆分 `openwrt/rootfs:x86-64-openwrt-24.10` 容器运行 `ucode -S -c -o /dev/null` / 模块 `import` 语法校验与单元测试，以及 Ubuntu 宿主机运行 `shellcheck -s sh`、JSON 校验、`sing-box check -D /tmp/nimbus-check-dir`、`sudo nft -c -f` 与 ESLint/Node 检查）
  - `.github/workflows/release.yml`（`v*` Tag 或 `workflow_dispatch` 触发，支持 `dry_run` 输入：`openwrt/sdk:x86-64-openwrt-24.10` 编译 `.ipk` + `USIGN_PRIVATE_KEY` 签名索引，`openwrt/sdk:x86-64-openwrt-25.12` 编译 `.apk` + `APK_PRIVATE_KEY` EC P-256 签名 `packages.adb`，兼容 `[ ! -d ./scripts ] && ./setup.sh` 初始化与 `feeds update/install luci nimbus`；`dry_run=true` 时仅产出并上传 `nimbus-repo` Artifact，跳过正式 Release 与 Pages 部署）

### 验收标准
- [ ] `ucode -S -L nimbus/files/usr/share/nimbus -e "import * as _m from 'common';"` 通过，且工作目录不残留 `./uc.out`
- [ ] `shellcheck -s sh` 校验所有 Shell 脚本无错误
- [ ] `release.yml`（`dry_run=true`）双轨 SDK 均能成功将本仓库挂载为 `src-link nimbus` feed 并产出 `nimbus`、`luci-app-nimbus`、`luci-i18n-nimbus-zh-cn` 的 `.ipk` 与 `.apk` 及签名索引
- [ ] 解包检查产物内容路径、文件权限（可执行位）、`prerm` 钩子、`Depends` 字段及签名索引完全符合预期

---

## M2：`sing-box` 运行期配置引擎 (`config_builder.uc`)

**目标**：完整实现只读源配置解析、透明代理入站复用/补齐、冲突隔离、现代路由动作注入、Fake-IP 自动识别与双 API 探测。

### 交付物
- `nimbus/files/usr/share/nimbus/config_builder.uc`
- `tests/fixtures/` 配置样本集：
  - `minimal_1.12.json`（无透明入站、新版 `dns.servers[type=fakeip]`）
  - `with_tun_and_rules.json`（含 `tun` 入站及 `route.rules`/`dns.rules` 引用 `tun-in`）
  - `with_user_tproxy_redirect.json`（已有用户自定义端口的 `redirect` 与 `tproxy`、自定义 `route.default_mark`）
  - `with_singbox_api_dashboard.json`（含 `services[].type == "api"`，覆盖 `dashboard` 为 `true`/字符串/对象三种形态与 `tls`）
  - `with_clash_api.json`（含 `experimental.clash_api` 与现代 `dns.servers[type=fakeip]`）
- `tests/unit/test_config_builder.uc`

### 验收标准
- [ ] `tproxy_redirect` 模式：已有 `redirect`/`tproxy` 时准确复用端口（纯回环 `listen` 自动修正为 `::`/`0.0.0.0`，`ipv6_enable='1'` 时仅绑定 `0.0.0.0` 记录 warning），缺失时按 UCI 与 `ipv6_enable` 选用 `::` 或 `0.0.0.0` 补齐（校验端口不与已有入站碰撞）；原有 `tun` 被剥离且 `route.rules` / `dns.rules`（含递归嵌套 `type: "logical"` 子规则）中的 `inbound` 引用正确重映射
- [ ] 自动生成的入站不写入入站级 `sniff`；正确按需向 `route.rules` 头部注入 `{ "action": "sniff" }`（含仅开启 `block_quic='1'` 而未自动注入入站的场景）、`hijack-dns`（`dns.mode='singbox'`，复用 IPv4 可达本地 `direct` 入站并拦截 `local` 上游死循环）与 `protocol: quic -> action: reject`（`block_quic='1'`）
- [ ] 拦截 `default_mark == proxy_mark` 碰撞；Fake-IP IPv4/IPv6 网段自动探测准确（现代 `dns.servers[type=fakeip]`）
- [ ] `services[].type == "api"`（三种 `dashboard` 形态且对象默认 `enabled: false` + `loopback_only`/`no_secret` 标志）与 `experimental.clash_api`（含 `:port`/`[::]:port` 与 `loopback_only`/`no_secret`）探测准确；写入 `state.json` 时不含明文 `secret`
- [ ] 原始 `/etc/nimbus/profiles/*.json` 在任何测试中字节级未修改，`/var/run/nimbus/config.json` 权限为 `0600`
- [ ] CI 中使用真实 `sing-box`（`linux-amd64`）对全部合成输出在独立临时目录执行 `sing-box check -c <out> -D /tmp/nimbus-check-dir` 全部返回退出码 `0`

---

## M3：数据面引擎、服务监督器与热插拔 (`nft_manager.uc` / `route_manager.uc` / `supervisor.uc` / `init.d` / `hotplug.d`)

**目标**：打通独立防火墙表 `table inet nimbus` 双态生成、双栈策略路由、`procd` + `supervisor.uc` 托管、Fail-Closed 状态机与接口事件自愈。

### 交付物
- `nimbus/files/usr/share/nimbus/nft_manager.uc`（双态规则生成、`lan_v4`/`lan_v6` 绕行、`port_filter_mode` 含空集 `include` 安全放行、`ct mark` 首包按位缓存、设备分流规则优先于 `lan_device_mode` 默认策略按序匹配、`lockdown` 下 `default_bypass` 范围隔离、`bypass_sets.nft` / `wan_sets.nft` 原子热更新、计数器 JSON 解析、LAN Zone `input` 诊断检测）
- `nimbus/files/usr/share/nimbus/route_manager.uc`（IPv4/IPv6 `tproxy_redirect` 策略路由、`sysctl` 调优、幂等清理与自愈）
- `nimbus/files/usr/share/nimbus/supervisor.uc`（纯 `ucode` + `uloop` 监督器：管理 `sing-box.pid`、区分 `SIGTERM` 主动停机与异常崩溃重试窗口、耗尽触发 Fail Handler、`30s` 定时器对 `/var/log/nimbus.log` 实施 512KB->256KB 滞回截断）
- `nimbus/files/etc/init.d/nimbus`（`USE_PROCD=1`、托管 `supervisor.uc` 且不开 `procd respawn`、自动计算 `GOMEMLIMIT`、`-D /var/run/nimbus`、`RLIMIT_NOFILE=65535`、校验失败 Fail Handler、比对 `config.json` `SHA256` 的差异化 `reload_service` 与 `procd_add_reload_trigger`）
- `nimbus/files/etc/hotplug.d/iface/90-nimbus`（WAN/WAN6 与 LAN 前缀变更热刷 `wan_v4`/`wan_v6`/`lan_v4`/`lan_v6` Set 与策略路由自愈，受互斥锁保护）
- `tests/unit/test_nft_manager.uc`、`tests/unit/test_supervisor.uc`

### 验收标准
- [ ] 生成的 `tproxy_redirect`、`lockdown` 双态 `nftables` 规则在各类边界组合（空 Set、单栈 IPv4/IPv6、`proxy_local=0/1`、`hijack_lan_dns=0/1`、`lan_device_mode=default_proxy/default_bypass` 及旧值兼容与空/交错/排序规则、`port_filter_mode=all/include/exclude` 空/非空）下均不输出非法 `elements = { }` 且无范围泄漏
- [ ] 所有生成的规则文件通过真实 `sudo nft -c -f` 语法校验
- [ ] `prerouting_dns`（`dstnat + 1`）与 `prerouting_tcp`（`dstnat + 2`）均含 `ct status dnat return` 与 `fib daddr type local return`
- [ ] `prerouting_udp` 正确实现 `ct mark & 0x30` 按位缓存及 `port_filter_mode='include'` 空集安全放行
- [ ] `lockdown` 规则仅 Hook `forward` 链，不拦截 `input`，无条件放行 `icmpv6`，并正确保留直连规则与 `default_bypass` 未命中直连设备通路
- [ ] `supervisor.uc` 单元测试验证 `SIGTERM` 退出不触发 Fail Handler，崩溃耗尽后触发 `LOCKDOWN`/`fail_open=1` 且不重新拉起，超过 512KB 日志滞回截断为 256KB
- [ ] `init.d` `reload_service` 在仅变更不影响 `config.json` 的配置时跳过重启 `sing-box`
- [ ] `topology='side'` 且无 `wan`/`wan6` 接口时不报错、自动绕行 `lan_v4`/`lan_v6` 并关闭 LAN 口 `send_redirects`
- [ ] `init.d` 与 `hotplug.d` 脚本零 bashism，`shellcheck -s sh` 全绿

---

## M4：外围子系统 (`dns_manager.uc` / `list_updater.uc` / `profile_updater.uc` / `core_manager.uc`)

**目标**：实现 `dnsmasq` 无损备份接管与还原、多源白名单与订阅配置清洗校验热更新、无系统依赖的 `sing-box` 内核自动拉取校验安装。

### 交付物
- `nimbus/files/usr/share/nimbus/dns_manager.uc`（`/etc/nimbus/dns_backup.json` 幂等备份、`'singbox'` `127.0.0.1#<port>` 接管、`'custom'` 接管、`'none'`/停机/卸载还原）
- `nimbus/files/usr/share/nimbus/list_updater.uc`（统一 IPv4/IPv6/CIDR/注释解析器、`curl -z` 增量拉取、`SHA256` 变化写盘、多本地文件与远程缓存合并后触发 `nft -f` 热刷新与 `state.json` 计数同步、`# nimbus-whitelist` `crond` 定时任务同步）
- `nimbus/files/usr/share/nimbus/profile_updater.uc`（订阅配置拉取、隔离 `-D /tmp/nimbus-check-dir` `sing-box check` 预校验、`SHA256` 差异写盘、激活配置平滑重载、`# nimbus-profile` 每小时 `crond` 分发器）
- `nimbus/files/usr/share/nimbus/core_manager.uc`（`DISTRIB_ARCH` + `musl` 软/硬浮点 ABI 前置选包、GitHub Release API 查询与 `mirror_prefix`/`download_via_proxy`、下载前与解压后两阶段空间检查、SHA256 校验、`<tmp_bin> version` 可执行验证、原子替换、本地上传安装与异步任务状态 `/var/run/nimbus/core_task.json` 写入）
- `tests/fixtures/` 白名单、订阅与 Release JSON 样本（含 `#`/`//`/`;` 注释、行尾注释、CRLF、混排 IPv4/IPv6、HTML 错误页、非法 CIDR 行）
- `tests/unit/test_list_updater.uc`、`tests/unit/test_profile_updater.uc`、`tests/unit/test_core_manager.uc`、`tests/unit/test_dns_manager.uc`

### 验收标准
- [ ] 白名单解析器能准确解析带多行 `#` 头部注释的 Chnroutes/BGP 导出文件，正确分拣 IPv4/IPv6；遇到 HTML 错误页或非法 CIDR 时拒绝覆写并返回准确行号
- [ ] 远程白名单与订阅内容未变化（`SHA256` 一致）时不触发缓存/配置文件写盘；订阅校验失败不覆盖原文件
- [ ] `dns_manager.uc` 连续多次重载不覆写已有 `/etc/nimbus/dns_backup.json`，还原后 `dhcp.@dnsmasq[0]` 恢复至接管前状态并删除快照文件
- [ ] `core_manager.uc` 覆盖 `x86_64`、`aarch64_*`、`arm_cortex-a7*`（含软/硬浮点 ABI 前置区分）、`mipsel_*`、`riscv64_*` 全部架构映射单测，以及下载前/解压后两阶段空间不足和校验失败中止安装测试
- [ ] 所有外部进程调用均使用参数数组，无命令拼接注入风险

---

## M5：`rpcd` 接口层与权限收口 (`luci.nimbus.uc` / `acl.d` / `menu.d`)

**目标**：按 `docs/rpc-contract.md` 完整暴露 `luci.nimbus` ubus 对象（原 v1.0 为 9 只读 + 14 写 = 23 个方法，Composer 扩展后共 13 只读 + 16 写 = 29 个方法），并收口最小权限声明与菜单配置。

### 交付物
- `nimbus/files/usr/share/rpcd/ucode/luci.nimbus.uc`（实现全部 23 个读写 RPC 方法）
- `luci-app-nimbus/root/usr/share/rpcd/acl.d/luci-app-nimbus.json`
- `luci-app-nimbus/root/usr/share/luci/menu.d/luci-app-nimbus.json`
- `tests/unit/test_rpc_contract.uc`（契约级单测：校验全部接口返回结构、错误码、文件名路径穿越拦截、`256KB` 直传上限、`profile_delete`/`list_delete` 原子删除与 `E_CONFLICT`、非阻塞抢锁 `E_LOCKED`、`api_secret` 权限隔离）

### 验收标准
- [ ] 全部 23 个 RPC 方法名称、入参与返回 JSON 结构与 `docs/rpc-contract.md` 100% 一致
- [ ] 恶意文件名（`../etc/shadow`、`a/b.json`、`test.sh`）在 `profile_*` 与 `list_*` 接口中被严格拦截并返回 `E_INVALID_ARG`
- [ ] 写方法使用非阻塞 `f.lock('xn')` 抢锁，长耗时 RPC 通过 `uloop.process` 异步派发，不阻塞 `rpcd` 主循环；`core_install` 脱离主请求并干净收割，无僵尸进程
- [ ] `status` 实时聚合 `state.json`、`sing-box.pid`、`ubus`、`/proc/<pid>/status`、`nft -j` 计数器及双 API 探测结果，且不泄露明文 `secret`（仅通过写权限 `api_secret` 按需读取）
- [ ] `acl.d` 与 `menu.d` 通过 JSON 合法性校验，仅开放文档列出的最小 `ubus`/`uci`/`cgi-io`/`file` 权限

---

## M6：LuCI 前端视图、双格式发布流水线与实机联调

**目标**：交付全部 6 个纯客户端 JS LuCI 页面、中英双语翻译、`.ipk` + `.apk` 双轨签名发布与 GitHub Pages 源流水线，并在真实 OpenWrt 环境中完成全链路功能与安全验收。

### 交付物
- `luci-app-nimbus/htdocs/luci-static/resources/nimbus/api.js`（统一 `rpc.declare` 封装与错误处理）
- 6 个 LuCI 页面视图（`luci-app-nimbus/htdocs/luci-static/resources/view/nimbus/`）：
  - `overview.js`：运行状态卡片（含 `lockdown` 醒目告警与 `dns.mode='singbox'` 本机解析恢复提示）、启停/重载按钮、真实进程 PID/运行时长/RSS 内存、生效模式与入站来源、双栈白名单条目与实时流量计数器、**原生 `sing-box API` Dashboard/Remote Control 卡片与 `clash_api` 快捷入口**（点击复制配置时按需调用 `api_secret`）、诊断警告区
  - `settings.js`：全局设置、数据面参数（含 `port_filter_mode` 端口规则）、DNS 托管、局域网设备分流表（带 `getHostHints` 主机/MAC 自动联想）
  - `profiles.js`：纯 RPC 驱动的配置/订阅列表与元数据增删改、在线 JSON 编辑器弹窗（保存即校验）、文件上传导入、订阅立即更新、一键激活切换
  - `whitelists.js`：纯 RPC 驱动的全局定时开关、多源列表（远程 URL 源 + 多个独立本地列表）增删改、本地列表弹窗文本编辑与导入（校验失败高亮展示具体错误行号与原因）、保存后提示“已原子热更新”、远程源一键刷新
  - `core.js`：本机架构/磁盘空间/已安装版本卡片、GitHub 仓库/通道/镜像设置、检查更新、GitHub 一键下载安装与本地上传安装、轮询进度条
  - `logs.js`：内存日志查看器（支持行数选择、自动刷新、清空日志）
- 国际化文件：`luci-app-nimbus/po/templates/nimbus.pot` 与 `luci-app-nimbus/po/zh_Hans/nimbus.po`
- 发布流水线校验：`.github/workflows/release.yml`（`dry_run=true` 验证完整终产 `.ipk` + `.apk` 双轨产物、签名索引与带 `apk` 单文件密钥持久化至 `/etc/sysupgrade.conf` 指引的 `index.html`）

### 验收标准
- [ ] 全部 JS 文件通过 ESLint 语法与规范检查；所有用户可见字符串均使用 `_('...')` 包裹，中英文翻译无遗漏
- [ ] 双轨 SDK 发布流水线成功产出已签名的 `opkg`（`Packages.sig`）与 `apk`（`packages.adb`）双格式软件源并部署至 GitHub Pages
- [ ] **实机 / VM 端到端验证清单**（覆盖至少一套 `opkg` 环境 OpenWrt 23.05/24.10 与一套 `apk` 环境 OpenWrt 25.12+）：
  1. 通过 GitHub Pages 软件源直接 `opkg install luci-app-nimbus` / `apk add luci-app-nimbus` 安装成功
  2. 在 `Core` 页无代理冷启动（或经镜像）一键拉取并安装 `sing-box` 二进制成功
  3. 上传只读 JSON 配置跑通 `tproxy_redirect` 模式，验证 IPv4 + IPv6 代理正常、`port_filter_mode` + `ct mark` 按位缓存生效、白名单直连命中且保留 Flow Offloading、Fake-IP 正常走代理
  4. 在 `Whitelists` 页新建多个本地手动列表粘贴带 `#` 注释的 CIDR 保存，验证不断流原子热更新生效；故意输入错误 CIDR 验证弹窗精准报行号且不破坏原规则
  5. 验证 `dnsmasq` 接管至 `sing-box`、切回 `none` 后以及通过 `opkg remove` / `apk del` 卸载 `nimbus` 时 `/etc/config/dhcp` 原样无损还原
  6. 模拟强杀 `sing-box` 进程耗尽重试窗口或载入错误配置：验证 `fail_open='0'` 时自动切入 `lockdown`，LAN 设备非白名单外网立即被阻断（零真实 IP 泄漏），同时 SSH 与 LuCI 仍可正常登录管理
  7. 验证 `Overview` 页正确识别并一键打开新版 `sing-box API` 内置 Dashboard 与 `clash_api` 面板（点击复制配置时再拉取 `api_secret`）
  8. 连续运行、高频写日志并重载多次后检查 `/etc/nimbus/`、`/var/run/nimbus/` 与 `/var/log/nimbus.log`，确认运行期配置、`cache.db`、`dashboard/` 均驻留内存、日志体积极限控制在 `<= 512KB` 内，且无异常闪存写入