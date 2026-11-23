# RPC & ACL Contract — `luci.nimbus`

本文档定义后端 `/usr/share/rpcd/ucode/luci.nimbus.uc` 暴露的 `ubus` 对象契约，以及前端包 `luci-app-nimbus` 的最小权限声明（`acl.d`）与菜单路由（`menu.d`）。前后端交互严格以本文件为准。

---

## 1. 通用约定

- **ubus 对象名**：`luci.nimbus`
- **实现位置**：`/usr/share/rpcd/ucode/luci.nimbus.uc`（由 `rpcd-mod-ucode` 进程内加载）
- **非阻塞与并发安全**：
  - `rpcd-mod-ucode` 运行在 `rpcd` 单线程 `uloop` 主循环内，**严禁阻塞等锁或同步执行长耗时外部命令**。
  - 所有写方法均须先以非阻塞 `f.lock('xn')` 获取 `/var/run/nimbus/nimbus.lock`；若锁被占用，立即返回 `code: "E_LOCKED"`。
  - 长耗时操作（`service_action`、`profile_activate(reload=true)`、`profile_update`、`list_update`、`core_check_update`、`composer_preview`、`composer_save`、`composer_mode_set(reload=true)`）通过 `uloop.process` + 延迟 `req.reply()` 异步派发子进程执行；`core_install` 派发脱离主请求的后台任务（由 `uloop.process` 回调收割或双 fork/`start-stop-daemon -b` 避免僵尸进程）并通过 `core_task_status` 轮询。
- **文件名安全校验**：
  - Profile 文件名必须匹配 `^[A-Za-z0-9._-]+\.json$`，固定映射至 `/etc/nimbus/profiles/`。
  - 本地白名单文件名必须匹配 `^[A-Za-z0-9._-]+\.txt$`，固定映射至 `/etc/nimbus/lists/local/`。
- **响应结构**：所有方法返回 JSON 对象，统一包含 `ok`（布尔值）；失败时必含 `code` 与 `error` 字段：
  ```json
  {
    "ok": false,
    "code": "E_VALIDATE_FAILED",
    "error": "line 14: invalid CIDR '1.2.3.999/24'"
  }
  ```
- **标准错误码**：
  - `E_INVALID_ARG`：参数缺失、类型错误或非法文件名
  - `E_NOT_FOUND`：目标文件或 UCI Section 不存在
  - `E_CONFLICT`：目标正在使用（如删除当前激活 Profile）或文件名已存在
  - `E_VALIDATE_FAILED`：JSON 语法错误、`sing-box check` 失败或白名单格式校验失败
  - `E_LOCKED`：后台已有写操作正在执行
  - `E_NETWORK`：上游拉取失败、超时或 HTTP 状态码异常
  - `E_DISK_SPACE`：`/tmp` 或目标目录剩余空间不足
  - `E_INTERNAL`：未预期系统错误
- **大文件传输边界**：文本直接通过 `ubus` 参数传输上限为 `256KB`；超过该体积或文件上传场景通过 LuCI 原生 `/cgi-bin/cgi-upload` 写入 ACL 授权的固定临时路径后，由对应 RPC 方法校验目标为普通文件（非符号链接）后接管并原子落盘。

---

## 2. 服务状态与控制接口

### 2.1 `status`（只读）
聚合 `/var/run/nimbus/state.json`（`0600`，不含明文密钥）、`/var/run/nimbus/sing-box.pid`、`ubus service list`、`/proc/<pid>/status`、`nft -j list table inet nimbus` 与内核二进制状态。

- **请求**：`{}`
- **响应**：
```json
{
  "ok": true,
  "state": "running",
  "enabled": true,
  "config_mode": "composer",
  "topology": "main",
  "proxy_mode": "tproxy_redirect",
  "fail_open": false,
  "active_profile": "main_sub",
  "composer": {
    "initialized": true,
    "enabled_sources": 1,
    "extracted_nodes": 12,
    "groups": 3,
    "manual_outbounds": 1,
    "inbounds": 0,
    "dns_servers": 3,
    "route_rules": 6,
    "rule_sets": 2
  },
  "process": {
    "running": true,
    "pid": 4312,
    "uptime": 86420,
    "rss_kb": 42180
  },
  "core": {
    "installed": true,
    "bin_path": "/etc/nimbus/bin/sing-box",
    "version": "1.14.4"
  },
  "effective": {
    "outbound_mark": "0xff",
    "redirect_port": 7891,
    "tproxy_port": 7892,
    "tun_iface": null,
    "dns_mode": "singbox",
    "dns_port": 5353,
    "inbound_sources": {
      "redirect": "auto",
      "tproxy": "user",
      "tun": null
    },
    "fakeip": {
      "ipv4": ["198.18.0.0/15"],
      "ipv6": ["fc00::/18"]
    }
  },
  "whitelist": {
    "enabled": true,
    "v4_count": 3912,
    "v6_count": 1420
  },
  "counters": {
    "tcp_packets": 152410,
    "tcp_bytes": 184291020,
    "udp_packets": 48920,
    "udp_bytes": 32910440,
    "tun_packets": 0,
    "tun_bytes": 0,
    "lockdown_rejected_packets": 0
  },
  "apis": {
    "singbox_api": {
      "detected": true,
      "scheme": "http",
      "listen": "::",
      "port": 9091,
      "has_secret": true,
      "dashboard_enabled": true,
      "dashboard_path": "/dashboard/",
      "loopback_only": false,
      "no_secret": false
    },
    "clash_api": {
      "detected": false,
      "listen": null,
      "port": null,
      "has_secret": false,
      "external_ui": false,
      "loopback_only": false,
      "no_secret": false
    }
  },
  "last_error": null,
  "warnings": []
}
```
> `state` 枚举值：`"stopped"` | `"preparing"` | `"running"` | `"lockdown"`。`config_mode` 枚举值：`"composer"` | `"profile"`（`profile` 模式下 `composer` 字段为 `null`；`composer` 模式下返回编排摘要，文件未初始化时从当前 UCI/磁盘实时估算）。`status`（只读）不返回明文 API `secret`。v1.0 中 `proxy_mode` 固定为 `"tproxy_redirect"`，`effective.tun_iface`、`effective.inbound_sources.tun` 与 `counters.tun_packets`/`tun_bytes` 保持 `null`/`0`（预留供 v1.1 扩展）。

### 2.2 `api_secret`（写）
仅在前端用户点击“打开 / 复制控制面板连接配置”时按需调用，从 `/var/run/nimbus/config.json`（`0600`）实时读取探测到的明文 API `secret`。

- **请求**：`{}`
- **响应**：
```json
{
  "ok": true,
  "singbox_api_secret": "your-secret",
  "clash_api_secret": null
}
```

### 2.3 `service_action`（写，异步非阻塞派发）
通过 `uloop.process` 异步控制 `/etc/init.d/nimbus` 生命周期动作，完成后延迟 `req.reply()` 返回。

- **请求**：
```json
{
  "action": "start"
}
```
> `action` 枚举值：`"start"` | `"stop"` | `"restart"` | `"reload"`。
- **响应**：`{ "ok": true, "state": "running" }`（若因配置或内核失败切入 `lockdown`，返回 `ok: false, code: "E_VALIDATE_FAILED", state: "lockdown", error: "..."`）。

### 2.4 `log_read`（只读）
读取 `/var/log/nimbus.log` 尾部日志。

- **请求**：
```json
{
  "lines": 200
}
```
> `lines` 可选，默认 `200`，范围 `1`–`2000`。
- **响应**：
```json
{
  "ok": true,
  "content": "...",
  "size_bytes": 18432,
  "truncated": false
}
```

### 2.5 `log_clear`（写）
清空 `/var/log/nimbus.log`（保留文件节点，截断为 0 字节）。

- **请求**：`{}`
- **响应**：`{ "ok": true }`

---

## 3. 配置与订阅管理接口（纯 RPC 驱动，无 `form.Map` 脏状态）

### 3.1 `profile_list`（只读）
返回所有 UCI `profile` Section 的完整元数据及对应原始文件状态（`mtime` 与文件体积直接由 `stat()` 获取）。

- **请求**：`{}`
- **响应**：
```json
{
  "ok": true,
  "active_profile": "main_sub",
  "profiles": [
    {
      "id": "main_sub",
      "name": "Main Subscription",
      "type": "subscription",
      "filename": "main_sub.json",
      "url": "https://example.com/sub.json",
      "user_agent": "sing-box/nimbus",
      "via_proxy": false,
      "auto_update": true,
      "update_interval_hours": 24,
      "exists": true,
      "size_bytes": 24510,
      "mtime": 1795185600,
      "active": true
    }
  ]
}
```

### 3.2 `profile_read`（只读）
读取原始只读配置文件内容供前端编辑器展示。

- **请求**：`{ "filename": "local_cfg.json" }`
- **响应**：
```json
{
  "ok": true,
  "filename": "local_cfg.json",
  "content": "{ ... }",
  "size_bytes": 8420,
  "mtime": 1795185600
}
```

### 3.3 `profile_save`（写）
保存或导入原始 JSON 配置文件。支持直接传文本 `content`（上限 `256KB`），或由 LuCI 上传至 `/tmp/nimbus-upload.json` 后传 `from_upload: true`（校验为普通文件，拒绝符号链接）。

- **请求**：
```json
{
  "filename": "local_cfg.json",
  "content": "{ ... }",
  "from_upload": false,
  "validate": true
}
```
- **行为**：
  1. 校验 JSON 语法；
  2. 当 `validate != false` 且 `sing-box` 二进制存在时，走 `config_builder.uc` 临时合成并在独立临时工作目录 `-D /tmp/nimbus-check-dir` 执行 `sing-box check`，失败时拒绝落盘并返回详细报错；
  3. 原子写入 `/etc/nimbus/profiles/<filename>`（若 `from_upload=true`，完成后清理临时上传文件）；
  4. 若该文件正是当前激活配置（或 Composer 模式下被启用的源配置）且服务处于 `running` 或 `lockdown` 态，返回 `reload_required: true`（由前端或调用方按需触发重载）。
- **响应**：
```json
{
  "ok": true,
  "filename": "local_cfg.json",
  "size_bytes": 8420,
  "mtime": 1795189200,
  "checked": true,
  "reload_required": true
}
```

### 3.4 `profile_meta_save`（写）
新建或更新 UCI `config profile` 元数据（供 `profiles.js` 纯 RPC CRUD 调用）。

- **请求**：
```json
{
  "section_id": "",
  "name": "Main Subscription",
  "type": "subscription",
  "filename": "main_sub.json",
  "url": "https://example.com/sub.json",
  "user_agent": "sing-box/nimbus",
  "via_proxy": false,
  "auto_update": true,
  "update_interval_hours": 24
}
```
> `section_id` 为空时自动生成合法 UCI Section 名新建；编辑时不可与其它 Section 的 `filename` 重复；若修改了 `auto_update` / `update_interval_hours`，同步更新 `/etc/crontabs/root` 中的 `# nimbus-profile` 定时项。
- **响应**：`{ "ok": true, "section_id": "main_sub" }`

### 3.5 `profile_activate`（写，可选异步重载）
切换 `global.active_profile`；若 `reload == true` 且服务处于运行或 `lockdown` 态，通过 `uloop.process` 异步触发重载。

- **请求**：`{ "section_id": "main_sub", "reload": true }`
- **响应**：`{ "ok": true, "active_profile": "main_sub", "reloaded": true }`

### 3.6 `profile_delete`（写）
原子删除未处于使用状态的配置对应的 **UCI `config profile` Section 与 `/etc/nimbus/profiles/<filename>` 文件**，并同步 `# nimbus-profile` 定时项。

- **请求**：`{ "section_id": "old_cfg" }`
- **响应**：`{ "ok": true, "section_id": "old_cfg" }`（在 `profile` 模式下为当前 `global.active_profile`，或在 `composer` 模式下已被 `/etc/nimbus/composer.json` 的 `sources` 启用时，返回 `E_CONFLICT`）。

### 3.7 `profile_update`（写，异步非阻塞派发）
通过 `uloop.process` 调用 `profile_updater.uc` 立即拉取指定或全部 `type='subscription'` 订阅配置，仅在 `sing-box check -D /tmp/nimbus-check-dir` 通过且 `SHA256` 变化时原子替换；若更新了当前激活配置且服务在运行，自动平滑重载。

- **请求**：
```json
{
  "section_id": "main_sub"
}
```
> `section_id` 省略或为空字符串时更新全部已配置订阅。
- **响应**：
```json
{
  "ok": true,
  "reloaded": true,
  "results": [
    {
      "id": "main_sub",
      "status": "updated",
      "changed": true,
      "size_bytes": 25120,
      "mtime": 1795190000,
      "error": null
    }
  ]
}
```
> `status` 枚举：`"updated"` | `"unchanged"` | `"failed"`。

---

## 3B. 编排配置管理接口（`composer`，`sing-box` 1.14 蓝图）

### 3.8 `composer_get`（只读）
读取 `/etc/nimbus/composer.json`（若尚未创建则返回默认骨架），并附带全部共享 `config profile` 摘要与当前数据面自动托管的入站信息。

- **请求**：`{}`
- **响应**：
```json
{
  "ok": true,
  "config_mode": "composer",
  "exists": true,
  "mtime": 1795191000,
  "composer": {
    "schema_version": 1,
    "sources": {},
    "inbounds": [],
    "outbound_groups": [],
    "outbounds": [],
    "dns": {},
    "rule_sets": [],
    "route": {},
    "override": {}
  },
  "profiles": [],
  "auto_inbounds": {
    "proxy_mode": "tproxy_redirect",
    "redirect_port": 7891,
    "tproxy_port": 7892,
    "dns_mode": "none",
    "singbox_dns_port": 5353
  }
}
```

### 3.9 `composer_nodes`（只读）
使用后端 `ucode` 正则引擎（POSIX ERE 不区分大小写）解析共享订阅源并返回提取节点与预览列表，不写盘。

- **请求**：
```json
{
  "profile_id": "main_sub",
  "composer_json": "",
  "include_regex": "HK|香港",
  "exclude_regex": "倍率|过期"
}
```
> `profile_id` 省略或为空时汇总全部启用源；传入临时 `composer` 对象或 `composer_json` 字符串（上限 `256KB`，优先使用 `composer_json` 以确保 `override` / `node_override` 中的 RFC 7396 `null` 删除标记完整穿透 OpenWrt `rpcd` `blobmsg`）可实时预览未保存的提取策略效果；当通过 `ubus` 传入 `composer_json` 时，调用方应省略 `"composer"` 键（严禁发送 `"composer": null`）；传入 `include_regex`/`exclude_regex` 时按组筛选语义再过滤一遍。
- **响应**：
```json
{
  "ok": true,
  "nodes": [
    {
      "profile_id": "main_sub",
      "original_tag": "HK-01",
      "tag": "[A] HK-01",
      "type": "vless",
      "server": "example.com",
      "server_port": 443
    }
  ],
  "per_source_counts": {
    "main_sub": 12
  },
  "warnings": []
}
```

### 3.10 `composer_preview`（只读，异步非阻塞派发）
通过 `uloop.process` 对当前已保存或请求传入的 `composer` / `composer_json` 草稿执行 Stage A 编排与 Stage B 数据面合成，并在 `validate != false` 且内核存在时执行隔离目录 `sing-box check`，不写正式配置。

- **请求**：`{ "composer": { ... }, "composer_json": "", "validate": true }`
> 支持以 `composer_json`（JSON 字符串，上限 `256KB`）传入草稿，确保 RFC 7396 `null` 键在 `rpcd` `blobmsg` 传输中不被丢失；响应除对象 `composed` / `effective` 外，亦会同步返回对应 JSON 字符串 `composed_json` / `effective_json`。
- **响应**：
```json
{
  "ok": true,
  "composed": { ... },
  "effective": { ... },
  "composed_json": "{ ... }",
  "effective_json": "{ ... }",
  "warnings": [],
  "checked": true,
  "check_ok": true,
  "check_error": null,
  "summary": {
    "enabled_sources": 1,
    "extracted_nodes": 12,
    "groups": 3,
    "manual_outbounds": 1,
    "inbounds": 0,
    "dns_servers": 3,
    "route_rules": 6,
    "rule_sets": 2
  }
}
```

### 3.11 `composer_save`（写，异步非阻塞派发）
校验并原子保存 `/etc/nimbus/composer.json`（权限 `0600`，`composer` 序列化后体积上限 `256KB`）；当 `validate != false` 且内核存在时先走 Stage A + Stage B 与 `sing-box check`；`SHA256` 一致时不写盘；可选触发平滑重载。

- **请求**：`{ "composer": { ... }, "composer_json": "", "validate": true, "reload": false }`
> 请求支持传入 `composer` 对象或 `composer_json`（JSON 字符串，上限 `256KB`）；优先解析 `composer_json`，确保 RFC 7396 `null` 字段完整穿透 OpenWrt `rpcd` `blobmsg`；响应亦按需附带规范化后的 `composer_json` 字符串。
- **响应**：
```json
{
  "ok": true,
  "checked": true,
  "changed": true,
  "mtime": 1795192000,
  "reload_required": true,
  "reloaded": false,
  "composer_json": "{ ... }",
  "warnings": []
}
```

### 3.12 `composer_mode_set`（写，可选异步重载）
切换 UCI `global.config_mode`（`"composer"` 或 `"profile"`）并提交；当 `reload == true` 且服务处于运行或 `lockdown` 态时通过 `uloop.process` 异步触发重载。

- **请求**：`{ "mode": "composer", "reload": true }`
- **响应**：`{ "ok": true, "config_mode": "composer", "reload_required": true, "reloaded": true }`

### 3.13 `composer_import`（只读）
将指定 `profile_id` 对应文件或传入的原始 `sing-box` JSON 文本（上限 `256KB`）逆向拆解为 `composer` 结构草稿（未归类顶层块自动放入 `override`），不写盘。

- **请求**：`{ "source": "profile", "profile_id": "main_sub", "content": "" }`
> `source` 枚举：`"profile"` | `"json"`。
- **响应**：`{ "ok": true, "composer": { ... }, "warnings": [] }`

---

## 4. 白名单管理接口（纯 RPC 驱动，无 `form.Map` 脏状态）

### 4.1 `list_status`（只读）
返回全局 `whitelist` 策略、所有 UCI `list_source`（含远程源与多手动列表）的完整元数据与源文件解析条目统计，以及经 `auto-merge` 合并后当前 `nftables` Set 实际加载元素总条数。

- **请求**：`{}`
- **响应**：
```json
{
  "ok": true,
  "whitelist": {
    "enabled": true,
    "auto_update": true,
    "update_cron": "30 4 * * *"
  },
  "nft_loaded": {
    "v4_count": 3912,
    "v6_count": 1420
  },
  "sources": [
    {
      "id": "cn_ipv4",
      "name": "China IPv4",
      "type": "url",
      "enabled": true,
      "family": "ipv4",
      "url": "https://raw.githubusercontent.com/misakaio/chnroutes2/master/chnroutes.txt",
      "via_proxy": false,
      "exists": true,
      "size_bytes": 62140,
      "mtime": 1795140000,
      "v4_count": 3903,
      "v6_count": 0
    },
    {
      "id": "custom_direct",
      "name": "Custom Direct",
      "type": "local",
      "enabled": true,
      "family": "auto",
      "filename": "custom_direct.txt",
      "exists": true,
      "size_bytes": 420,
      "mtime": 1795150000,
      "v4_count": 9,
      "v6_count": 2
    }
  ]
}
```

### 4.2 `whitelist_config_save`（写）
保存 UCI `config whitelist 'whitelist'` 全局策略（`enabled`、`auto_update`、`update_cron`），同步 `/etc/crontabs/root` 中的 `# nimbus-whitelist` 定时任务；若服务运行中立即执行 `nft -f` 原子热刷新（不重启 `sing-box`）。

- **请求**：
```json
{
  "enabled": true,
  "auto_update": true,
  "update_cron": "30 4 * * *"
}
```
- **响应**：`{ "ok": true, "hot_reloaded": true }`

### 4.3 `list_source_save`（写）
新建或更新 UCI `config list_source` 元数据；新建 `type='local'` 源时自动创建空 `.txt` 文件；若服务运行中且影响了生效集合则立即 `nft -f` 原子热刷新（不重启 `sing-box`）。

- **请求**：
```json
{
  "section_id": "",
  "name": "Custom Direct",
  "type": "local",
  "enabled": true,
  "family": "auto",
  "filename": "custom_direct.txt",
  "url": "",
  "via_proxy": false
}
```
- **响应**：`{ "ok": true, "section_id": "custom_direct", "hot_reloaded": true }`

### 4.4 `list_read`（只读）
读取指定本地白名单文本文件内容。

- **请求**：`{ "filename": "custom_direct.txt" }`
- **响应**：
```json
{
  "ok": true,
  "filename": "custom_direct.txt",
  "content": "# custom\n1.1.8.0/24\n",
  "size_bytes": 20,
  "mtime": 1795150000
}
```

### 4.5 `list_save`（写）
校验并保存本地白名单文件（支持直接传 `content` 上限 `256KB`，或 `from_upload: true` 从 `/tmp/nimbus-upload.txt` 导入并校验非符号链接）。通过后原子落盘，并在服务运行中立即执行 `nft -f` 原子热刷新。

- **请求**：
```json
{
  "filename": "custom_direct.txt",
  "content": "# comment\n1.1.8.0/24\n2400:3200::/32\n",
  "from_upload": false
}
```
- **成功响应**：
```json
{
  "ok": true,
  "filename": "custom_direct.txt",
  "v4_count": 1,
  "v6_count": 1,
  "hot_reloaded": true
}
```
- **校验失败响应**（不覆盖原文件）：
```json
{
  "ok": false,
  "code": "E_VALIDATE_FAILED",
  "error": "invalid entries found",
  "invalid_lines": [
    { "line": 4, "text": "1.2.3.999/24", "reason": "invalid IPv4/CIDR" }
  ]
}
```
> `invalid_lines` 最多返回前 10 条。

### 4.6 `list_delete`（写）
原子删除 UCI `config list_source` Section 及其对应本地 `.txt` 文件或远程缓存文件，并在服务运行中自动触发 `nft -f` 热刷新。

- **请求**：`{ "section_id": "unused_list" }`
- **响应**：`{ "ok": true, "section_id": "unused_list", "hot_reloaded": true }`

### 4.7 `list_update`（写，异步非阻塞派发）
通过 `uloop.process` 调用 `list_updater.uc` 立即拉取指定或全部已启用的 `type='url'` 远程白名单源，校验通过后仅在 `SHA256` 变化时更新缓存，并统一执行一次 `nft -f` 原子热刷新。

- **请求**：
```json
{
  "section_id": "cn_ipv4"
}
```
> `section_id` 省略或为空字符串时更新全部已启用远程源。
- **响应**：
```json
{
  "ok": true,
  "hot_reloaded": true,
  "nft_loaded": {
    "v4_count": 3912,
    "v6_count": 1420
  },
  "results": [
    {
      "id": "cn_ipv4",
      "status": "updated",
      "changed": true,
      "v4_count": 3903,
      "v6_count": 0,
      "error": null
    }
  ]
}
```

---

## 5. `sing-box` 内核管理接口

因跨网络下载大体积二进制可能超过 `uhttpd`/`ubus` 单次请求超时，`core_install` 采用**后台异步任务 + 轮询状态文件（`/var/run/nimbus/core_task.json`）**模式。

### 5.1 `core_info`（只读）
返回本机架构映射、已安装内核信息与关键挂载点可用空间。

- **请求**：`{}`
- **响应**：
```json
{
  "ok": true,
  "arch": {
    "openwrt_arch": "aarch64_cortex-a53",
    "target": "arm64",
    "libc": "musl",
    "preferred_suffix": "linux-arm64-musl.tar.gz"
  },
  "installed": {
    "exists": true,
    "executable": true,
    "bin_path": "/etc/nimbus/bin/sing-box",
    "version": "1.14.4",
    "size_bytes": 24812032,
    "mtime": 1795100000
  },
  "disk": {
    "tmp_free_kb": 198400,
    "target_free_kb": 84200
  }
}
```

### 5.2 `core_check_update`（只读，异步非阻塞派发）
通过 `uloop.process` 异步按 UCI `core.repo`、`core.channel`、`core.mirror_prefix`、`core.download_via_proxy` 查询 GitHub Release 并匹配本机架构资产，完成后延迟 `req.reply()` 返回。

- **请求**：`{}`
- **响应**：
```json
{
  "ok": true,
  "latest_version": "1.14.5",
  "prerelease": false,
  "published_at": "2026-11-18T10:00:00Z",
  "release_url": "https://github.com/SagerNet/sing-box/releases/tag/v1.14.5",
  "asset": {
    "name": "sing-box-1.14.5-linux-arm64-musl.tar.gz",
    "size_bytes": 11842900,
    "download_url": "https://github.com/SagerNet/sing-box/releases/download/v1.14.5/sing-box-1.14.5-linux-arm64-musl.tar.gz",
    "digest": "sha256:..."
  },
  "update_available": true
}
```

### 5.3 `core_install`（写，异步触发）
触发后台内核安装/升级任务（通过 `uloop.process` 回调收割或双 fork/`start-stop-daemon -b` 脱离主请求，不残留僵尸进程），立即返回，进度由 `core_task_status` 轮询。

- **请求**（v1.0 支持二选一来源模式；`"custom_url"` 与 `"rollback"` 留待 v1.1+ 扩展）：
```json
{
  "source": "github",
  "download_url": "",
  "digest": ""
}
```
> `source` 枚举值（v1.0）：
> - `"github"`：自动按 `core_check_update` 规则拉取最新匹配资产（若显式传入 `download_url` 与可选 `digest` 则直接下载该资产）
> - `"upload"`：安装已通过 LuCI 上传至 `/tmp/nimbus-upload.bin` 的压缩包或裸二进制（校验目标为普通文件、非符号链接）
- **响应**：`{ "ok": true, "started": true }`（若已有任务在执行返回 `E_LOCKED`）。

### 5.4 `core_task_status`（只读）
轮询后台内核安装任务状态。

- **请求**：`{}`
- **响应**：
```json
{
  "ok": true,
  "state": "downloading",
  "progress": 64,
  "message": "Downloading sing-box-1.14.5-linux-arm64-musl.tar.gz",
  "installed_version": null,
  "error": null,
  "updated_at": 1795190512
}
```
> `state` 枚举值：`"idle"` | `"checking_space"` | `"downloading"` | `"verifying"` | `"installing"` | `"reloading"` | `"done"` | `"failed"`。

---

## 6. 最小权限声明 (`acl.d`) 与菜单路由 (`menu.d`)

### 6.1 `/usr/share/rpcd/acl.d/luci-app-nimbus.json`

严格分离只读与写入权限，仅放开必需的 `ubus` 方法、UCI 配置与固定临时上传路径：

```json
{
	"luci-app-nimbus": {
		"description": "Grant access to Nimbus transparent proxy management",
		"read": {
			"ubus": {
				"luci.nimbus": [
					"status",
					"log_read",
					"profile_list",
					"profile_read",
					"list_status",
					"list_read",
					"core_info",
					"core_check_update",
					"core_task_status",
					"composer_get",
					"composer_nodes",
					"composer_preview",
					"composer_import"
				],
				"network.interface": [ "dump" ],
				"luci-rpc": [ "getHostHints" ]
			},
			"uci": [ "nimbus", "network", "firewall" ]
		},
		"write": {
			"cgi-io": [ "upload" ],
			"ubus": {
				"luci.nimbus": [
					"api_secret",
					"service_action",
					"log_clear",
					"profile_save",
					"profile_meta_save",
					"profile_activate",
					"profile_delete",
					"profile_update",
					"whitelist_config_save",
					"list_source_save",
					"list_save",
					"list_delete",
					"list_update",
					"core_install",
					"composer_save",
					"composer_mode_set"
				]
			},
			"uci": [ "nimbus" ],
			"file": {
				"/tmp/nimbus-upload.json": [ "write" ],
				"/tmp/nimbus-upload.txt": [ "write" ],
				"/tmp/nimbus-upload.bin": [ "write" ]
			}
		}
	}
}
```

### 6.2 `/usr/share/luci/menu.d/luci-app-nimbus.json`

```json
{
	"admin/services/nimbus": {
		"title": "Nimbus",
		"order": 30,
		"action": {
			"type": "firstchild"
		},
		"depends": {
			"acl": [ "luci-app-nimbus" ],
			"uci": { "nimbus": true }
		}
	},
	"admin/services/nimbus/overview": {
		"title": "Overview",
		"order": 10,
		"action": {
			"type": "view",
			"path": "nimbus/overview"
		}
	},
	"admin/services/nimbus/settings": {
		"title": "Settings",
		"order": 20,
		"action": {
			"type": "view",
			"path": "nimbus/settings"
		}
	},
	"admin/services/nimbus/profiles": {
		"title": "Config",
		"order": 30,
		"action": {
			"type": "view",
			"path": "nimbus/profiles"
		}
	},
	"admin/services/nimbus/whitelists": {
		"title": "Whitelists",
		"order": 40,
		"action": {
			"type": "view",
			"path": "nimbus/whitelists"
		}
	},
	"admin/services/nimbus/core": {
		"title": "Core",
		"order": 50,
		"action": {
			"type": "view",
			"path": "nimbus/core"
		}
	},
	"admin/services/nimbus/logs": {
		"title": "Logs",
		"order": 60,
		"action": {
			"type": "view",
			"path": "nimbus/logs"
		}
	}
}
```