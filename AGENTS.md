# AGENTS.md — luci-app-nimbus 工程规范与开发约束

本文档是 `luci-app-nimbus`（含核心包 `nimbus` 与前端包 `luci-app-nimbus`）的最高级别开发约束。所有代码生成、重构、脚本编写与测试提交都必须严格遵守本文件。

---

## 1. 项目定位与目标平台

- **项目名称**：`nimbus`（后端核心包）+ `luci-app-nimbus`（LuCI 前端包）
- **仓库形态**：单仓库多包（Monorepo），仓库根目录本身即是一个合法的 OpenWrt Feed，并通过 GitHub Actions + GitHub Pages 同时发布 `opkg` 与 `apk` 双格式软件源。
- **目标系统**：**OpenWrt 23.05 及以上版本**（覆盖 23.05、24.10 的 `opkg`，以及 25.12+ 的 `apk`）。
- **架构要求**：应用本体为全架构通用（`PKGARCH:=all`），**不含任何需要交叉编译的 C/Go/Rust 源码**。
- **内核来源**：不依赖系统软件源中的 `sing-box` 包；由 `nimbus` 内置的内核管理模块直接从 `sing-box` GitHub Releases 拉取、校验并安装对应架构的 `musl` 发行包。
- **支持拓扑**：原生支持**主路由模式**与**旁路由模式**。
- **支持代理模式**：
  - **v1.0 核心模式**：`tproxy_redirect`（TCP REDIRECT + UDP TPROXY）
  - **v1.1+ 扩展预留**：`tun`（`auto_route: false`，UCI 保留 `proxy_mode` 扩展枚举位）

---

## 2. 强制技术栈（必须使用）

| 模块 | 强制选型 | 说明 |
| :--- | :--- | :--- |
| 后端业务逻辑 | **`ucode`**（OpenWrt 23.05+ 原生内置） | 含 `ucode-mod-uloop`，处理配置构建、JSON 操作、白名单清洗、nft 规则生成、内核与订阅管理 |
| RPC 服务层 | **`rpcd-mod-ucode`** | 编写 `/usr/share/rpcd/ucode/luci.nimbus.uc`，进程内非阻塞 `uloop` 异步执行 |
| 服务管理 | **`procd`** (`/etc/init.d/nimbus`) | `USE_PROCD=1`、`procd_add_reload_trigger`、`GOMEMLIMIT`、`-D /var/run/nimbus`；托管 `/usr/share/nimbus/supervisor.uc`（不对 supervisor 开启 `procd respawn`，由其内部维护重试窗口、Fail Handler、真实 PID 文件与日志轮转） |
| 数据面防火墙 | **独立表 `table inet nimbus`**（`nftables`） | 原生 IPv4/IPv6 双栈，完全独立于 `table inet fw4` |
| 路由与策略 | **`ip-full`**（`ip -4` / `ip -6`） | 同时管理 IPv4 与 IPv6 策略路由（通过 OpenWrt `ALTERNATIVES` 优先级 `300` 与 `ip-tiny` 无冲突共存） |
| Web 前端 | **LuCI Client-side JavaScript**（`luci-base`） | 纯 JS 视图（`view.extend` / `form.Map` / `rpc.declare`） |
| 权限与菜单 | 声明式 JSON | `/usr/share/luci/menu.d/` 与 `/usr/share/rpcd/acl.d/` |
| DNS 托管 | OpenWrt 原生 **UCI (`dhcp`)** | 仅通过 UCI 操作 `dnsmasq`，并在接管前备份、停用或经 `Package/nimbus/prerm` 卸载时无损还原 |
| 打包发布 | OpenWrt SDK（CI Matrix） | 24.10 SDK 产 `.ipk` + `usign` 索引；25.12+ SDK 产 `.apk` + EC P-256 内嵌签名 `packages.adb` |

---

## 3. 红线禁令（严禁违反）

1. **严禁使用历史淘汰栈**：
   - 禁止任何 Lua 代码、LuCI CBI、旧版 Shell RPC（`/usr/libexec/rpcd/` 下的 sh 脚本）。
   - 禁止调用 `iptables`、`ip6tables`、`ipset`、`fw3`。
   - 禁止依赖 `jq`、`python`、`bash`、`coreutils` 等非最小化外部工具（JSON 处理一律用 `ucode` 原生 `json()`，Shell 脚本一律严格 POSIX `ash`/`sh`）。
2. **严禁篡改系统主防火墙表**：
   - 禁止向 `table inet fw4` 注入代理链、白名单 Set 或修改 `/etc/config/firewall`。
   - 所有代理规则、白名单 Set、Lockdown 阻断规则必须且只能位于独立表 `table inet nimbus`。
   - 例外边界：不自动改写用户 `fw4` UCI 策略；仅在检测到 LAN Zone 的 `input` 策略可能拦截 TPROXY 时写入 `state.json` 的 `warnings` 中提示。
3. **严禁直接修改用户原始配置文件**：
   - `/etc/nimbus/profiles/` 中的本地上传配置与订阅拉取配置为**只读源**。
   - 运行期配置必须动态合成并输出到 `/var/run/nimbus/config.json`（`tmpfs`）。
4. **入站处理原则（优先复用，缺失补齐，隔离冲突）**：
   - **v1.0 (`tproxy_redirect` 模式)**：优先复用用户配置中已有的 `redirect` 与 `tproxy` 入站（读取其 `listen_port` 交给 `nftables`；若缺失其一或 `tproxy` 未包含 `udp`，则仅自动补齐缺失部分）。运行期必须剥离冲突的 `tun` 入站，并将 `route.rules`/`dns.rules` 中指向被剥离 `tun` tag 的引用递归重映射到生效的透明代理入站（`tun` 运行模式留待 v1.1+ 扩展）。
   - 所有其他非冲突入站（`mixed`、`socks`、`http`、`direct` 等）一律原样保留。
5. **存储边界与闪存保护**：
   - `sing-box` 固定以 `-D /var/run/nimbus` 为工作目录启动，相对路径的 `cache.db` 与 `dashboard/` 驻留 `tmpfs`；用户 JSON 中的显式绝对路径原样保留。
   - 运行期配置、nft 临时脚本、下载解压临时文件存于 `/var/run/nimbus/` 或 `/tmp/`；`/var/run/nimbus/config.json` 与 `/var/run/nimbus/state.json` 文件权限固定设为 `0600`，且 `state.json` 严禁存储明文 API `secret`。
   - 运行日志由 `sing-box` 原生 `O_APPEND` 方式写入 `/var/log/nimbus.log`（`tmpfs`），由 `supervisor.uc` 定时器实施滞回截断轮转（超过 512KB 时就地截断保留尾部 256KB）。
   - 远程白名单或订阅更新必须先在 `/tmp` 完成合法性校验并比对 `SHA256`，内容无变化严禁覆写 `/etc/nimbus/`；运行态元数据严禁回写 UCI。
6. **严禁引入已废弃的 `sing-box` 字段**：
   - 禁止在自动生成的 `inbounds` 中写入入站级 `sniff`、`sniff_override_destination`、`domain_strategy`（1.11 废弃、1.13 移除）。嗅探一律通过 `route.rules` 中的 `{ "action": "sniff" }` 实现。
   - 禁止生成旧版 `dns.servers` 与 `dns.fakeip` 格式（1.12 废弃、1.14 移除）。
   - 后续 v1.1 引入 `tun` 模式时，亦禁止写入已废弃的 `inet4_address` / `inet6_address`（1.10 废弃、1.12 移除）、`gso`（1.11 废弃、1.13 移除）及 `stack`（1.15 废弃、预计 1.17 移除；省略 `stack` 在 1.11–1.15+ 均合法），且必须强制 `auto_route: false`。
   - Fake-IP 网段由 `config_builder.uc` 自动识别并优先导流，禁止误将其纳入绕行集合。
7. **安全默认基线（默认 Fail-Closed）**：
   - `fail_open` 默认为 `'0'`。服务异常、内核崩溃耗尽重启、配置校验失败或重载失败时，严禁静默清空规则导致非白名单流量直连泄漏真实 IP，必须切入 `lockdown` 阻断态。
   - `lockdown` 仅 Hook `forward` 链，**必须始终放行 LAN 侧访问路由器的 `input` 管理流量**（SSH、LuCI、DHCP、ICMP/ICMPv6）。
   - 用户手动停止服务时，干净卸载防火墙表、清理策略路由、还原 `dnsmasq` 并转入 `stopped`。

---

## 4. 目录结构约定

```text
luci-app-nimbus/                         # Git 仓库根目录（OpenWrt Feed 根）
├── AGENTS.md                            # 本文件
├── docs/                                # 架构与契约文档（开发前必读）
│   ├── architecture.md                  # 架构、Feed/Pages 发布流与状态机
│   ├── uci-schema.md                    # /etc/config/nimbus 唯一事实来源
│   ├── dataplane-and-singbox-spec.md    # nftables 双态模板与 sing-box 注入规范
│   ├── rpc-contract.md                  # ubus RPC 接口与 ACL 契约
│   └── milestones.md                    # 分阶段开发与验收清单
├── nimbus/                              # 后端核心包
│   ├── Makefile
│   └── files/
│       ├── etc/config/nimbus
│       ├── etc/init.d/nimbus
│       ├── etc/uci-defaults/99-nimbus
│       ├── etc/hotplug.d/iface/90-nimbus
│       ├── lib/upgrade/keep.d/nimbus
│       ├── usr/share/rpcd/ucode/luci.nimbus.uc
│       └── usr/share/nimbus/
│           ├── common.uc                # 常量、UCI 读取、互斥锁、state.json 与日志工具
│           ├── supervisor.uc            # procd 托管的 ucode 监督器：PID 管理、崩溃重试与 Fail Handler、日志滞回轮转
│           ├── config_builder.uc        # 配置合成、入站复用/补齐、Fake-IP 与双 API 探测
│           ├── nft_manager.uc           # 独立表生成、双态切换、Set 原子热更新与计数器解析
│           ├── route_manager.uc         # IPv4/IPv6 策略路由与 sysctl 调优
│           ├── dns_manager.uc           # dnsmasq UCI 备份/接管/还原
│           ├── core_manager.uc          # GitHub Release 拉取、架构映射与校验替换
│           ├── list_updater.uc          # 白名单源下载、清洗、校验与触发热更新
│           └── profile_updater.uc       # 订阅配置拉取、校验、原子替换、重载与定时调度
├── luci-app-nimbus/                     # LuCI 前端包
│   ├── Makefile
│   ├── htdocs/luci-static/resources/
│   │   ├── nimbus/api.js                # 统一 ubus RPC 客户端封装
│   │   └── view/nimbus/                 # LuCI 页面视图
│   ├── po/                              # 国际化翻译（templates / zh_Hans）
│   └── root/usr/share/
│       ├── luci/menu.d/luci-app-nimbus.json
│       └── rpcd/acl.d/luci-app-nimbus.json
├── tests/                               # 单元测试与 Fixture
│   ├── run_tests.sh                     # 统一测试入口
│   ├── fixtures/                        # 多版本 sing-box 配置样本、白名单与 Release 样本
│   └── unit/                            # ucode 单元测试脚本
└── .github/workflows/                   # CI 校验、SDK 双轨打包与 GitHub Pages 发布
```

---

## 5. 文档查阅优先级与工作流

在编写或修改任何代码前，必须先查阅对应契约文档，确保字段名、常量、状态转换与接口格式 100% 对齐：

1. 修改配置项、默认值或前端表单 -> 先查 `docs/uci-schema.md`
2. 修改防火墙规则、策略路由、`config_builder.uc`、白名单或内核下载 -> 先查 `docs/dataplane-and-singbox-spec.md`
3. 修改后端 RPC 或前端交互调用 -> 先查 `docs/rpc-contract.md`
4. 修改状态转换、旁路由逻辑、CI 或发布流程 -> 先查 `docs/architecture.md`
5. 确认当前阶段交付范围与验收标准 -> 先查 `docs/milestones.md`

**契约变更原则**：若实现中必须调整 UCI 字段、RPC 签名或防火墙常量，**必须先同步更新对应 `docs/*.md` 文档，再修改前后端代码**，严禁代码与文档漂移。

---

## 6. 编码规范

- **`ucode`**：
  - 所有模块采用严格模式（`'use strict';` 并通过 `ucode -S` 校验），显式 `import`/`export`，避免全局污染；注意 OpenWrt `ucode` 模块导出语法为 `export { ... };` 或 `export default { ... };`（严禁写 `export function foo()`）。
  - 数值进制解析一律使用内置 `int(str, base)` 并校验 `!isnan(...)`，严禁误写 JavaScript 的 `parseInt()`。
  - 所有外部命令执行必须通过参数数组形式（如 `system(['nft', '-f', path])`），**严禁拼接 Shell 字符串防范命令注入**。
  - 在 `rpcd-mod-ucode`（`luci.nimbus.uc`）内禁止执行同步阻塞 `system()` 或阻塞抢锁：所有写接口须用非阻塞 `f.lock('xn')`（占锁立即返回 `E_LOCKED`），耗时操作一律通过 `uloop.process` + 延迟 `req.reply()` 异步派发或交由独立后台任务执行。
  - 涉及文件替换（配置、内核、白名单缓存、`state.json`）必须采用“写同目录临时文件 -> 校验 -> `rename()` 原子替换”。
  - 所有网络请求与外部进程调用必须带超时限制与清晰错误码返回。
- **Shell（`init.d` / `hotplug.d` / `uci-defaults`）**：
  - Shebang 固定使用 `#!/bin/sh`（`init.d` 使用 `#!/bin/sh /etc/rc.common`），严禁出现 bashism（如 `[[ ]]`、数组、`local -a`）。
  - 保持薄壳原则：复杂逻辑全部下沉给 `/usr/share/nimbus/*.uc` 执行，Shell 脚本只负责 `procd` 声明与触发调用。
- **LuCI JS**：
  - 遵循官方 LuCI 客户端模块风格（`'use strict'; 'require view'; 'require form'; 'require rpc';`）。
  - 所有用户可见文本必须用 `_('...')` 包裹以支持 i18n。
  - 状态页自动识别并展示 `services[].type == "api"`（sing-box 原生 API 与内置 Dashboard）以及 `experimental.clash_api` 快捷入口。
- **Git 提交规范**：
  - 遵循 Conventional Commits（如 `feat(config): reuse existing transparent inbounds and auto-fill missing ones`、`fix(nft): preserve icmpv6 ndp in lockdown mode`）。

---

## 7. 变更后的强制验证清单

每次完成代码修改后，必须按实际环境执行对应校验，全部通过方可结束任务：

1. **ucode 语法校验**：独立可执行脚本与 `rpcd` 插件（`supervisor.uc`、`luci.nimbus.uc`、`tests/unit/*.uc`）执行 `ucode -S -c -o /dev/null <file>`；带 `export` 的 ES 模块（`/usr/share/nimbus/*.uc`）通过 `ucode -S -L <dir> -e "import * as _m from '<module>';"` 编译校验，严禁遗留 `./uc.out`。
2. **Shell 静态检查**：对所有变更的 Shell 脚本执行 `shellcheck -s sh <file>`（OpenWrt init 脚本可按需忽略标准 `rc.common` 预定义变量提示）。
3. **JSON 语法检查**：校验所有 `menu.d`、`acl.d` 及测试 Fixture 的 JSON 合法性。
4. **核心逻辑单测**：运行 `tests/run_tests.sh` 覆盖 `tests/unit/` 下的全部单元测试，确保：
   - 配置构建输出通过真实 `sing-box check -c`（若环境中存在 `sing-box` 二进制）；
   - 生成的 `nftables` 双态规则（`tproxy_redirect` / `lockdown`）语法无误（若环境支持则执行 `nft -c -f`）。
5. **前端 JS 语法检查**：执行配置的 linter（如 `eslint` / `node --check`）验证无语法错误。
6. **最小改动审计**：确认未向 `/etc/nimbus/` 引入任何高频写盘逻辑，未修改 `table inet fw4`，未破坏 `fail_open='0'` 默认行为。