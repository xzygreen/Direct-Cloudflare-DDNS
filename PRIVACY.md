# 隐私说明

Cloudflare DDNS 不收集遥测、分析数据或设备标识，也不运营任何中转服务器。

- Cloudflare API Token 与通知渠道密钥保存在当前用户的 macOS 钥匙串中。
- 区域、DNS 记录和网络设置保存在当前用户的 Application Support 目录。
- 公网 IP 查询会访问用户配置的查询服务；同步会直接访问 Cloudflare API。
- 只有用户启用通知渠道后，事件标题、IP 变化或错误摘要才会发送到相应的 Bark、Gotify、Telegram 或 Webhook 服务。
- 运行历史默认仅在本机保留最近 100 条；配置仅保留最近 5 份本地备份。

用户可删除 `~/Library/Application Support/DirectCloudflareDDNS` 并在“钥匙串访问”中删除服务名为 `io.github.xzygreen.direct-cloudflare-ddns` 的条目，以清除应用数据。
