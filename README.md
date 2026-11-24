# luci-app-nimbus

面向 **OpenWrt 23.05+**（同时支持 `opkg` 与 OpenWrt 25.12+ `apk`）的现代 `sing-box` 透明代理控制器，包含后端核心包 `nimbus` 与 LuCI 前端包 `luci-app-nimbus`（全架构通用 `PKGARCH:=all`）。

---

## 核心特性

- **纯原生现代技术栈**：后端基于 OpenWrt 原生 `ucode` + `rpcd-mod-ucode`（进程内 `uloop` 非阻塞异步 RPC），前端为纯 LuCI Client-side JavaScript；零 Lua、零 `iptables`/`fw3`、零 `jq`/`python`/`bash` 依赖。
- **独立防火墙表（零污染 `fw4`）**：全部透明代理规则、白名单 Set 与阻断规则均位于独立 `table inet nimbus`，不修改 `/etc/config/firewall` 与 `table inet fw4`，白名单流量完整保留 `fw4` 软/硬件 Flow Offloading 加速。
- **双栈透明代理与主/旁路由原生适配**：采用 `tproxy_redirect`（TCP REDIRECT + UDP TPROXY）与 IPv4/IPv6 策略路由；自动提取 LAN/WAN 动态前缀，旁路由自动关闭 `send_redirects`，`hotplug.d` 自动响应接口变更与表/路由自愈。
- **默认 Fail-Closed 安全基线（Lockdown）**：`fail_open` 默认为 `0`。启动校验失败、配置重载失败或内核崩溃耗尽重试窗口时自动切入 `lockdown` 阻断态（仅拦截 `forward` 链非白名单转发，始终放行 LAN 访问路由器的 SSH / LuCI / DHCP / NDP 管理流量）。
- **双模式配置管理与共享订阅（`sing-box` 1.14 标准）**：
  - **编排模式（Composer，新装默认）**：通过 `/etc/nimbus/composer.json` 自主管理入站、手动出站、多订阅节点筛选提取、出站组（`selector`/`urltest`）挂载、DNS、路由规则、规则集与 RFC 7396 顶层复写 JSON，内置官方 Schema 片段模板与实时合成预览；
  - **完整配置模式（Profile）**：直接选用 `/etc/nimbus/profiles/` 下的整份只读本地或远程订阅 JSON，两种模式共享同一套订阅源，无需重复维护；
  - **智能透明代理合成**：两种模式统一经运行期合成至 `tmpfs`（`/var/run/nimbus/config.json`），优先复用已有 `redirect`/`tproxy` 入站、缺失自动补齐、剥离冲突 `tun` 并重映射规则、自动识别 Fake-IP 网段优先导流，自动探测 `sing-box` 原生 API 与 `clash_api` Dashboard 入口。
- **无损 `dnsmasq` 托管**：通过 OpenWrt UCI 备份与接管 `dnsmasq`，服务停止或包卸载（`prerm`）时自动无损还原。
- **多源白名单原子热更新**：支持多个远程 CIDR 列表与本地手动白名单，`curl -z` 增量拉取、自动清洗校验并通过单事务 `nft -f` 原子刷新 Set，无需重启 `sing-box`。
- **内置 `sing-box` 内核管理**：直接从 `sing-box` GitHub Releases（支持自定义镜像前缀）拉取对应架构的 `musl` 发行包，校验 `SHA256` 后原子替换安装。
- **闪存保护**：运行期配置、状态、`cache.db` 与滞回轮转日志（`/var/log/nimbus.log`）均驻留 `tmpfs`；远程订阅与白名单内容无变更时不写闪存。

---

## 系统要求

- **OpenWrt 23.05 / 24.10**（`opkg`）或 **OpenWrt 25.12+**（`apk`）
- 包管理器会自动解析安装所需依赖：`ucode`、`ucode-mod-*`、`rpcd-mod-ucode`、`nftables-json`、`ip-full`、`curl`、`ca-bundle`、`kmod-nft-core`、`kmod-nft-fib`、`kmod-nft-nat`、`kmod-nft-tproxy` 等。
  > 注意：`nimbus` 强依赖 `nftables-json`（用于 `nft -j`），若固件预装了精简版 `nftables-nojson`，请先替换为 `nftables-json`。

---

## 安装指南

推荐直接添加本项目的 GitHub Pages 签名软件源（`https://rawvoid.github.io/luci-app-nimbus/`），也可从 [GitHub Releases](https://github.com/rawvoid/luci-app-nimbus/releases) 手动下载 `.ipk` / `.apk` 安装。

### OpenWrt 23.05 / 24.10（`opkg`）

```sh
wget -O /tmp/nimbus-usign.pub https://rawvoid.github.io/luci-app-nimbus/keys/nimbus-usign.pub
mv /tmp/nimbus-usign.pub "/etc/opkg/keys/$(usign -F -p /tmp/nimbus-usign.pub)"
grep -qxF 'src/gz nimbus https://rawvoid.github.io/luci-app-nimbus/opkg/all' /etc/opkg/customfeeds.conf || \
  echo 'src/gz nimbus https://rawvoid.github.io/luci-app-nimbus/opkg/all' >> /etc/opkg/customfeeds.conf
opkg update
opkg install luci-app-nimbus luci-i18n-nimbus-zh-cn
```

后续升级（将 `nimbus` 放最后，避免 `opkg` 逐包升级时先停代理影响后续包下载）：

```sh
opkg update
opkg upgrade luci-i18n-nimbus-zh-cn luci-app-nimbus nimbus
```

### OpenWrt 25.12+（`apk`）

> 请仅将单个公钥文件路径 `/etc/apk/keys/nimbus-apk.pem` 追加到 `/etc/sysupgrade.conf`，**切勿**保留整个 `/etc/apk/keys/` 目录。

```sh
mkdir -p /etc/apk/keys /etc/apk/repositories.d
wget -O /etc/apk/keys/nimbus-apk.pem https://rawvoid.github.io/luci-app-nimbus/keys/nimbus-apk.pem
grep -qxF '/etc/apk/keys/nimbus-apk.pem' /etc/sysupgrade.conf || \
  echo '/etc/apk/keys/nimbus-apk.pem' >> /etc/sysupgrade.conf
echo 'https://rawvoid.github.io/luci-app-nimbus/apk/all/packages.adb' > /etc/apk/repositories.d/nimbus.list
apk update
apk add luci-app-nimbus luci-i18n-nimbus-zh-cn
```

后续升级：

```sh
apk update
apk upgrade nimbus luci-app-nimbus luci-i18n-nimbus-zh-cn
```

---

## 快速上手

安装完成后，刷新 LuCI 页面并进入 **服务 -> Nimbus**：

1. **Core（内核管理）**：点击拉取并安装与当前路由器架构匹配的 `sing-box` 内核（网络受限时可配置镜像前缀）。
2. **Config（配置管理）**：按需选择 **编排模式（Composer）**（共享订阅只提取出站节点、自由编排出站组/DNS/路由/复写 JSON 并支持实时预览校验）或 **完整配置模式（Profile）**（上传/订阅并激活整份 `sing-box` JSON）。从 `v0.1.0-beta.1` 升级且已配置旧 Profile 的路由器会自动保持在 Profile 模式，可随时无痛切换体验编排模式。
3. **Settings（基础设置）**：按实际拓扑选择 **主路由 / 旁路由**、LAN 接口、DNS 托管模式与设备/端口策略，勾选启用并保存应用。
4. **Overview / Whitelists / Logs**：在总览页查看运行状态、流量计数与 Dashboard 快捷入口；在白名单页按需添加或热更新直连列表；在日志页查看 `sing-box` 实时输出。

### 关于 `LOCKDOWN` 状态下的本机 DNS

当 `fail_open = 0`（默认）且 `dns.mode = singbox` 时，若服务因配置错误或内核故障进入 `LOCKDOWN` 阻断态，`nimbus` 会保持 `dnsmasq` 指向本机 `sing-box` 以防止局域网 DNS 泄漏至运营商。此时路由器本机也无法解析外部域名（无法联网下载新内核或拉取订阅）：**请先在 Overview 页面点击“停止服务”以还原 `dnsmasq`**，修复配置或内核后再重新启动。

### 卸载与无损还原

卸载 `nimbus` 时，包内 `prerm` 钩子会自动停止服务、删除 `table inet nimbus`、清理策略路由、从备份快照无损还原 `dnsmasq` 并移除相关定时任务：

```sh
# opkg
opkg remove luci-i18n-nimbus-zh-cn luci-app-nimbus nimbus

# apk
apk del luci-i18n-nimbus-zh-cn luci-app-nimbus nimbus
```

---

## 文档与开发测试

- [系统架构与状态机](docs/architecture.md)
- [UCI 配置规范](docs/uci-schema.md)
- [数据面与 sing-box 合成规范](docs/dataplane-and-singbox-spec.md)
- [ubus RPC 接口与 ACL 契约](docs/rpc-contract.md)

本地全量校验（需安装 Docker 与 `shellcheck`/`node`）：

```sh
./scripts/verify-local.sh
```

---

## License

本项目基于 [GNU General Public License v3.0 or later](LICENSE) 开源发布。
