# Cloudflare DDNS（直连检测公网 IP）

一个无需 Docker、无需第三方 Python 包的 Cloudflare 动态 DNS 客户端。程序定时获取本机公网 IPv4/IPv6，只在地址或记录设置发生变化时更新 Cloudflare。

公网 IP 检测默认显式忽略 `HTTP_PROXY`、`HTTPS_PROXY`、`ALL_PROXY` 以及操作系统 HTTP 代理，避免把代理服务器的出口 IP 写入 DNS。Cloudflare API 的网络策略与 IP 检测相互独立，默认仍可使用本机代理。

## macOS 图形应用

已经提供原生 SwiftUI 图形界面，支持：

- 侧边栏分区（概览 / Cloudflare / DNS 记录 / 网络与调度 / 运行日志）与状态徽章
- Token 保存到 macOS 钥匙串，不写入 JSON 配置；后台助手由 App 显式授权，定时同步不会反复询问系统密码
- 编辑区域、Zone ID、多个域名、A/AAAA、TTL、Cloudflare 代理状态、是否自动创建缺失记录
- 自定义 IPv4/IPv6 查询来源列表，共识票数上限随来源数量自动收敛
- 分别控制 IP 查询与 Cloudflare API 是否绕过本机代理
- 检测公网 IP、演练、立即同步，可随时停止正在运行的任务
- 概览页展示当前公网 IPv4/IPv6（可一键复制）、上次同步时间与倒计时
- 按级别着色的流式运行日志，支持复制与清空
- 应用内定时同步、菜单栏图标快捷操作和登录时启动
- 独立后台同步助手：退出主 App 后仍可持续运行，网络恢复和睡眠唤醒后立即检查
- 首次设置向导、Token/权限测试、区域发现和 Cloudflare 现有记录导入
- 本机、Webhook、Bark、Gotify、Telegram 变化/失败/恢复通知（密钥存入钥匙串）
- 最近 100 次同步历史、运行状态持久化、配置迁移与最近 5 份配置备份
- 日志按应用/信息/警告/错误/调试分类，支持数量统计与关键词组合筛选

预构建应用位于：

```text
build/DirectCloudflareDDNS.app
build/DirectCloudflareDDNS-macOS-universal2.zip
build/DirectCloudflareDDNS-macOS-universal2.zip.sha256
```

将 App 拖入“应用程序”目录后双击运行。首次启动请填写一个**新建的** Cloudflare API Token；不要继续使用曾经粘贴到聊天、日志或其他公开位置的 Token。

这是本机临时签名、未经过 Apple 公证的构建。如果 Finder 阻止首次打开，请右键 App 选择“打开”，不要全局关闭 Gatekeeper。登录时启动功能建议在 App 移入“应用程序”目录后启用。

图形应用要求 macOS 13+。正式发布时可将可重定位的 Universal Python 3.9+ 运行时一同打包，形成无外部依赖的 App；开发构建未提供 `EMBEDDED_PYTHON_PREFIX` 时，会依次查找系统、Homebrew 或 Python.org 的 Python。开启定时同步后，内嵌 LaunchAgent 助手独立于主窗口运行；主 App 退出或意外崩溃不会中断后续同步。

重新构建：

```bash
./scripts/build-macos-app.sh
```

生产构建示例：

```bash
EMBEDDED_PYTHON_PREFIX=/path/to/universal-python \
SIGNING_IDENTITY='Developer ID Application: Example (TEAMID)' \
NOTARY_PROFILE='notarytool-profile' \
UPDATE_FEED_URL='https://example.com/ddns/update-manifest.json' \
./scripts/build-macos-app.sh
```

构建默认生成 Universal 2、SHA-256 校验文件，并在提供签名身份和 notarytool 钥匙串配置后启用 Hardened Runtime、公证与装订。单架构开发构建可设置 `BUILD_ARCHS=arm64`。如果本机 Swift 工具链和默认 SDK 不匹配，可用 `MACOS_SDK_OVERRIDE=/path/to/MacOSX.sdk` 指定 SDK。发布后使用 `scripts/make-release-manifest.sh` 生成应用内更新检查所需的 JSON 清单。

App 图标由 `scripts/make-icon.swift` 用 Core Graphics 从源码渲染，构建脚本会自动生成 `AppIcon.icns`，无需提交二进制图片。

## 特性

- Python 3.9+ 标准库即可运行，无 Docker、无 `pip install`
- IPv4（A）和 IPv6（AAAA），支持一个区域内的多个域名；两种地址并行检测
- 三个直连 IP 服务并发查询，默认至少两个结果一致才采用
- IPv4/IPv6 分别设置共识票数；拒绝重复来源，默认禁止不安全 HTTP，最多各 10 个来源
- 自动查找 Cloudflare Zone ID，也可直接配置 Zone ID
- 记录不存在时可自动创建；已一致时不发更新请求
- IP 查询失败、返回内网地址或结果冲突时，保留 Cloudflare 现有记录；同一地址族连续 3 次检测失败会额外告警，提示记录可能已失效
- Cloudflare 请求遇到网络错误或 408/429/5xx 时自动重试（尊重 `Retry-After`，1/2/4 秒指数退避）；写请求重试前会重新查询记录，避免重复创建
- 每种记录类型一次性拉取全区域列表并建立本地索引，记录多时不再逐条请求
- 同一配置文件同时只允许一个写入实例运行（GUI、launchd/systemd、手动命令重复启动时，后启动的实例提示后退出；`--dry-run` 与 `--check-ip` 不受限制）
- 域名在本地即校验空格、非法连字符等问题；配置中出现未知字段（例如把 `proxied` 拼成 `proxy`）会输出警告
- `--check-ip`、`--dry-run`、单次运行和内置定时循环
- Linux systemd 与 macOS launchd 模板

## 快速开始

要求 Python 3.9 或更高版本。

```bash
cp config.example.json config.json
```

编辑 `config.json`：

1. 把 `cloudflare.zone_name` 改为 Cloudflare 中的区域，例如 `example.com`。
2. 把 `records[].name` 改为要更新的完整域名，例如 `home.example.com`。
3. 默认只更新 IPv4 A 记录；如需原生公网 IPv6，把 `types` 改为 `["A", "AAAA"]`。

在 Cloudflare 创建 API Token，推荐使用 **Edit zone DNS** 模板，并把资源范围限制到目标区域。若配置了 `zone_name` 让程序自动查询 Zone ID，Token 还需 Zone Read 权限；也可以直接填写控制台中的 `zone_id`。

令牌建议只放在环境变量，不要写入配置文件：

```bash
export CLOUDFLARE_API_TOKEN='你的 API Token'
```

先确认直连查询到的地址：

```bash
python3 cloudflare_ddns.py --config config.json --check-ip
```

预览 Cloudflare 变更：

```bash
python3 cloudflare_ddns.py --config config.json --once --dry-run
```

执行一次：

```bash
python3 cloudflare_ddns.py --config config.json --once
```

持续运行（默认每 300 秒检查）：

```bash
python3 cloudflare_ddns.py --config config.json
```

## 配置说明

### `cloudflare`

| 字段 | 默认值 | 说明 |
|---|---:|---|
| `api_token_env` | `CLOUDFLARE_API_TOKEN` | 读取 Token 的环境变量名 |
| `api_token_file` | `null` | 环境变量为空时，从该文件读取 Token；服务部署推荐使用绝对路径 |
| `zone_name` | — | Cloudflare 区域名，用于自动查找 Zone ID |
| `zone_id` | `null` | 可选；填写后跳过 Zone ID 查询 |
| `bypass_proxy` | `false` | Cloudflare API 是否也强制绕过 HTTP 代理 |
| `create_missing_records` | `true` | 目标 A/AAAA 不存在时是否创建 |

相对的 `api_token_file` 路径以 `config.json` 所在目录为基准解析。

### `ip_detection`

| 字段 | 默认值 | 说明 |
|---|---:|---|
| `bypass_proxy` | `true` | 公网 IP 查询是否显式禁用 HTTP/HTTPS/SOCKS 环境代理和系统 HTTP 代理 |
| `allow_insecure_http` | `false` | 是否显式允许明文 HTTP 查询来源；开启时会持续警告 |
| `source_diagnostics` | `false` | 是否输出每个来源的耗时与进程内成功率 |
| `minimum_agreement.ipv4` | `2` | 至少多少个 IPv4 查询服务返回同一地址才采用 |
| `minimum_agreement.ipv6` | `2` | 至少多少个 IPv6 查询服务返回同一地址才采用 |
| `services.ipv4` | 见示例 | 只返回纯 IPv4 文本的 URL 列表 |
| `services.ipv6` | 见示例 | 只返回纯 IPv6 文本的 URL 列表 |

为了防止单个第三方服务异常污染 DNS，建议保持三个服务、两票共识。自建 IP 查询接口时，响应正文必须只含一个公网 IP 地址。

### `records`

每项支持：

- `name`：完整域名，支持中文域名（自动转换 Punycode）。
- `types`：`["A"]`、`["AAAA"]` 或 `["A", "AAAA"]`。
- `ttl`：`1` 表示 Cloudflare 自动 TTL，也可设置 `60` 到 `86400`；`proxied: true` 时必须为 `1`。
- `proxied`：是否启用 Cloudflare 橙云代理。远程访问 SSH、VPN 等非 Cloudflare 代理端口时通常设为 `false`。
- `comment`：可选。配置后会同步记录备注；省略则保留已有备注。

## “绕过代理”的边界

`ip_detection.bypass_proxy: true` 使用空代理处理器发起 HTTPS 请求，因此不会采用 shell 里的 `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY`，也不会采用 macOS/Windows 的系统 HTTP 代理。可通过下面的方式验证：

```bash
HTTPS_PROXY=http://127.0.0.1:1 python3 cloudflare_ddns.py -c config.json --check-ip
```

如果仍然能查到 IP，说明请求没有经过该代理。

透明网关代理、VPN、TUN 模式或路由器层面的代理发生在 HTTP 客户端之外，程序无法仅靠“禁用 HTTP 代理”绕过。此时需要在代理软件中为三个查询域名设置 `DIRECT` 规则，或在 `services` 中填写一个明确走物理 WAN 的自建接口。

Cloudflare API 默认 `bypass_proxy: false`，所以它仍可借助本机代理连接。若希望所有流量都直连，将其改为 `true`。

## Linux systemd 部署

下面以系统服务账户部署，不需要 Docker：

```bash
sudo useradd --system --home /nonexistent --shell /usr/sbin/nologin cloudflare-ddns
sudo install -d -o root -g root -m 755 /opt/cloudflare-ddns
sudo install -m 755 cloudflare_ddns.py /opt/cloudflare-ddns/cloudflare_ddns.py
sudo install -d -o root -g cloudflare-ddns -m 750 /etc/cloudflare-ddns
sudo install -o root -g cloudflare-ddns -m 640 config.json /etc/cloudflare-ddns/config.json
printf '%s\n' '你的 API Token' | sudo tee /etc/cloudflare-ddns/token >/dev/null
sudo chown root:cloudflare-ddns /etc/cloudflare-ddns/token
sudo chmod 640 /etc/cloudflare-ddns/token
sudo install -m 644 deploy/cloudflare-ddns.service /etc/systemd/system/cloudflare-ddns.service
```

把 `/etc/cloudflare-ddns/config.json` 中的 `api_token_file` 设为 `/etc/cloudflare-ddns/token`，然后启动：

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now cloudflare-ddns
sudo journalctl -u cloudflare-ddns -f
```

## macOS launchd 部署

模板路径固定为 `/usr/local`：

```bash
sudo install -d -m 755 /usr/local/libexec/cloudflare-ddns /usr/local/etc/cloudflare-ddns /usr/local/var/log
sudo install -m 755 cloudflare_ddns.py /usr/local/libexec/cloudflare-ddns/cloudflare_ddns.py
sudo install -m 600 config.json /usr/local/etc/cloudflare-ddns/config.json
sudo install -m 644 deploy/com.direct-cloudflare-ddns.plist /Library/LaunchDaemons/com.direct-cloudflare-ddns.plist
sudo install -m 644 deploy/cloudflare-ddns.newsyslog.conf /etc/newsyslog.d/cloudflare-ddns.conf
```

将 Token 保存为仅 root 可读文件，并在配置中填写其绝对路径：

```bash
printf '%s\n' '你的 API Token' | sudo tee /usr/local/etc/cloudflare-ddns/token >/dev/null
sudo chmod 600 /usr/local/etc/cloudflare-ddns/token
sudo launchctl bootstrap system /Library/LaunchDaemons/com.direct-cloudflare-ddns.plist
tail -f /usr/local/var/log/cloudflare-ddns.log
```

卸载 launchd 任务：

```bash
sudo launchctl bootout system /Library/LaunchDaemons/com.direct-cloudflare-ddns.plist
```

## 测试

测试全部使用本地模拟响应，不访问公网或 Cloudflare：

```bash
python3 -m unittest discover -s tests -v
swift test --package-path macos
```

CI 会在 Python 3.9–3.13 上运行后端测试，并在 macOS 上运行 XCTest、构建 App 和验证代码签名。详见 `CHANGELOG.md`、`PRIVACY.md` 与 `LICENSE`。

## API 依据

- [Cloudflare：创建 API Token](https://developers.cloudflare.com/fundamentals/api/get-started/create-token/)
- [Cloudflare：列出 DNS 记录](https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/list/)
- [Cloudflare：创建 DNS 记录](https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/create/)
- [Cloudflare：更新 DNS 记录](https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/edit/)

本项目受 `timothymiller/cloudflare-ddns` 的功能思路启发，但为满足无 Docker、Python 标准库和独立代理策略的需求而重新实现。
