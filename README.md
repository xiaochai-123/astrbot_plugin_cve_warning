# astrbot_plugin_cve_warning

基于 **AstrBot** 框架的 **QQ群聊/会话 CVE 漏洞推送插件**：定时拉取 **CISA KEV（Known Exploited Vulnerabilities）** 漏洞目录，并结合 **NVD** 查询到的 **CVSS 严重等级**进行分级展示与推送。

- 数据源：CISA KEV JSON Feed
- 严重等级：默认仅推送 **Critical / High**（可选开启 Medium / Low）
- 去重：默认只推送“从未推送过”的 CVE，避免刷屏
- 支持手动刷新、运行状态查询（管理员）

## 功能特性

- ⏱️ **定时任务**：启动后立即刷新一次，之后按 `push_interval_hours` 定时刷新
- 🧾 **CISA KEV 拉取**：支持失败重试与间隔配置
- 📊 **NVD CVSS 查询**：支持可选 `NVD API Key`，并带本地缓存（TTL 可配）
- 🧹 **去重机制**：记录已推送 CVE，支持限制状态文件最大条目数
- 🧩 **消息分级**：
  - Critical/High：可配置为**详细格式**
  - Medium/Low：默认简略（且默认不推送，需手动开启）

## 依赖

见 `requirements.txt`：

- `aiohttp>=3.8.0`
- `python-dateutil>=2.8.0`

## 安装方式

> 以下为 AstrBot 插件的一般安装方式，请按你当前 AstrBot 的插件加载方式选择其一。

### 方式 1：从仓库安装（推荐）
1. 将本项目放入 AstrBot 的插件目录（或通过 AstrBot 插件管理安装）
2. 重启/重载 AstrBot

### 方式 2：手动拷贝
把 `astrbot_plugin_cve_warning` 插件目录复制到 AstrBot 插件目录下，然后重启 AstrBot。

## 配置说明（WebUI）

插件提供 `_conf_schema.json`，可在 AstrBot WebUI 中配置。下面是常用配置项说明：

### 基础配置

- `enabled`：是否启用插件（关闭后不会启动定时服务）
- `admin_users`：插件管理员列表（QQ号等）。用于执行“状态/手动刷新”等管理命令
- `target_sessions`：推送目标会话列表（UMO）
  - 格式：`{platform_name}:{message_type}:{session_id}`
  - 示例：`aiocqhttp:GroupMessage:123456789`

### 拉取与推送

- `kev_feed_url`：CISA KEV 数据源（默认指向 cisa.gov，通常无需修改）
- `push_interval_hours`：刷新间隔（小时），默认 `6`
- `max_push_per_run`：单次最多推送条目数，默认 `30`

### 严重等级与展示

- `enable_low_medium`：是否推送 Medium/Low（默认 `false`，只推 Critical/High）
- `display_timezone`：显示用时区（仅影响展示，不影响逻辑），默认 `UTC+8`
- `message_format.critical_high_detailed`：Critical/High 是否使用详细格式（默认 `true`）
- `message_format.short_description_max_len`：描述截断长度（默认 `220`）
- `message_format.include_cwe`：详细格式是否包含 CWE（默认 `true`）

### NVD / 缓存

- `nvd_api_key`：NVD API Key（可选，建议配置以减少限流风险）
- `nvd_timeout_seconds`：NVD 请求超时（默认 `12` 秒）
- `cvss_cache_ttl_days`：CVSS 缓存过期天数（默认 `30`）

### 去重策略

- `dedup.push_only_new`：只推送未推送过的 CVE（默认 `true`）
- `dedup.state_max_entries`：状态文件最大去重条目数（默认 `5000`）

### 失败通知（可选）

- `failure_notify_sessions`：初始化/手动刷新失败时通知的会话列表（留空则仅写日志）

## 指令（聊天命令）

插件提供以下命令：

- `/CVE漏洞推送`  
  显示帮助

- `/CVE漏洞推送状态`（管理员）  
  查看服务状态（是否运行、上次拉取/推送时间、下次运行时间、已推送数量等）

- `/CVE漏洞推送手动刷新`（管理员）  
  立即触发一次拉取并推送（用于测试配置是否正确）

> 管理员判定逻辑：  
> 1) AstrBot 平台本身的 `event.is_admin()` 为真；或  
> 2) 发送者 ID 在 `admin_users` 配置列表中。

## 推送消息示例（说明）

插件会根据 CVSS 严重程度输出不同风格的消息：

- Critical/High（详细，可包含：影响范围、CISA 建议操作、DueDate、DateAdded、CVSS 向量、CWE、NVD/KEV 链接）
- Medium/Low（简略：CVE、严重等级、描述、到期时间、NVD 链接；默认不推送）

## 状态文件与数据存储

插件会在 AstrBot 的插件数据目录下写入 `state.json`，用于：

- 去重：记录已推送过的 CVE
- 缓存：记录 CVSS 查询结果并按 TTL 过期

> 注意：如果你清空该状态文件，插件会把历史 CVE 视为“未推送”，可能导致重新推送。

## 版本与兼容性

- `astrbot_version: ">=4.11.2"`
- 当前插件版本：`v1.0.0`（见 `metadata.yaml`）

## 开发者

- Author: `xiaochai_123`

## License

GPL
