# ZoogCNBypass for macOS

> **Windows 用户**：请看 [windows/README.md](windows/README.md)（命令行工具，与 macOS 版共用 `data/` 数据）。

让 ZoogVPN 或 Clash Pro（增强模式 TUN）与公司内网 VPN（如 UniVPN）共存，同时让中国大陆网站和 IP 通过本地物理网络直连。分流依据是目标域名和 IP，不区分 App。

## 工作方式

- **公司内网（UniVPN 等）**：通过 `config/corp-dns.conf` 注册 macOS 专属域名解析器，内网域名直连公司内网 DNS，内网子网流量走公司 VPN 网卡。
- **中国大陆 IPv4/IPv6**：通过 Wi‑Fi 或以太网物理网关直连；国内域名由本机 `dnsmasq` 转发至 AliDNS `223.5.5.5`，获得国内 CDN 地址。
- **国外公网流量（支持 ZoogVPN 与 Clash Pro 自动切换）**：
  - **ZoogVPN 与 Clash Pro 同时连接**：国外流量优先走 **ZoogVPN**（自动下发 16 条更细前缀覆盖路由压过 Clash TUN，并将 `dnsmasq` 国外上游切至 `1.1.1.1`/`8.8.8.8`）。
  - **仅连接 Clash Pro（增强模式 TUN）**：国外流量走 **Clash Pro**（`dnsmasq` 国外上游自动切至 Clash TUN 内置 DNS `198.18.0.2`）。
  - **仅连接 ZoogVPN**：国外流量走 **ZoogVPN**。
  - **两者均未连接**：自动撤销分流 DNS 接管与覆盖路由，恢复曾被压制的 Clash 系统代理；若公司 VPN 仍在线，内网域名解析继续保持可用。
- **系统代理防冲突**：当 ZoogVPN 或 Clash TUN 分流生效时，自动检测并关闭 Clash 本机系统代理端口（如 `127.0.0.1:7890`/`7891`），防止浏览器流量绕过内核路由表与内网 DNS（不影响 Charles / Proxyman 等其他调试抓包端口）。
- 本地 DNS 仅绑定 `lo0`（`127.0.0.1` 和 `::1`），不会开放给局域网；绑定端口后自动降权至 `nobody` 运行，并启用 `stop-dns-rebind`、`domain-needed`、`bogus-priv` 防御 DNS 重绑定攻击与内网信息泄漏。

它不会读取或修改 ZoogVPN / Clash Pro 的账号、密码、订阅规则和应用文件。

## 要求

- macOS。
- 使用以下任一（或同时安装）：
  - ZoogVPN（存在名为 `ZoogVPN` 的网络服务，并使用 OpenVPN 连接）；
  - ClashX Pro / Clash 增强模式（Enhanced Mode TUN，`198.18.0.1`）。
- 如需公司内网域名分流（如 UniVPN），可在 `config/corp-dns.conf` 配置 `<内网域名> <内网DNS_IPv4>` 后执行 `./install.sh`。
- 已安装 [Homebrew](https://brew.sh)。安装器会在需要时自动执行 `brew install dnsmasq`，但不会自动安装 Homebrew。

当前版本在 Apple Silicon、macOS 26.3+ 和 ZoogVPN OpenVPN 连接上验证通过。Intel Homebrew 路径也受安装器支持。

## 本地安全安装

为杜绝远程脚本供应链风险，`install.sh` 仅从本地已审计仓库目录安装，不会联网下载远程代码包：

```bash
git clone https://github.com/turing747/zoog-cn-bypass-macos.git
cd zoog-cn-bypass-macos
./install.sh
```

macOS 会弹出管理员授权框。安装完成后会立即启用；如果 ZoogVPN 尚未连接，则会在下次连接时自动生效。重复运行 `./install.sh` 即可升级，并会尽量保留当前已生效的路由，减少网络中断。

## 启用、停用与状态

安装后使用统一命令：

```bash
# 查看实时状态（无需管理员权限）
zoog-cn-bypass status

# 持久启用；重启后仍会自动运行
zoog-cn-bypass enable

# 持久停用；不会断开 ZoogVPN 本身
zoog-cn-bypass disable

# 完整卸载
zoog-cn-bypass uninstall
```

`enable`、`disable` 和 `uninstall` 会触发 macOS 管理员授权。停用后，ZoogVPN 恢复为原本的全局 VPN 路由。

正常启用时，状态应类似：

```text
ZoogVPN: Connected
Route service: loaded
Local DNS service: loaded
Split DNS override: active
China-direct routing: active
Route check — China 223.5.5.5: en0
Route check — foreign 1.1.1.1: utun7
DNS check — www.baidu.com: <国内 IP> via en0
DNS check — www.cloudflare.com: <境外 IP> via utun
```

## 安装内容与安全加固

安装器只写入以下位置（全部归属 `root:wheel`）：

- `/Library/Application Support/ZoogCNBypass/`（包含独立拷贝并由 `root:wheel` 持有的 `dnsmasq` 可执行文件、受保护的 `zoog-cn-bypass` 与 `daemon.sh`，不指向用户可写的 Homebrew 软链接）
- `/Library/LaunchDaemons/com.local.zoog-cn-bypass.plist`
- `/Library/LaunchDaemons/com.local.zoog-cn-dns.plist`
- `/usr/local/bin/zoog-cn-bypass`（归属 `root:wheel` 且附加 `uchg` 不可变标志，防止非特权进程替换）
- `/var/run/com.local.zoog-cn-bypass/`（`0755` `root:wheel` 独立运行时状态目录）

卸载器会删除这些文件以及本工具记录的路由和 DNS 状态。Homebrew 的 `dnsmasq` 会保留，避免影响其他配置；确认不再使用后可自行运行 `brew uninstall dnsmasq`。

## 数据来源

- IP 前缀：[APNIC delegated statistics](https://ftp.apnic.net/stats/apnic/delegated-apnic-latest)，仓库快照为 2026-09-12，共 5,494 条 IPv4 和 2,015 条 IPv6 前缀。
- 国内域名：[felixonmars/dnsmasq-china-list](https://github.com/felixonmars/dnsmasq-china-list)，快照提交为 `c55bc322c2ebcb0e0d78614ef44951be629862ed`。
- `scripts/update-data.sh` 可重新下载数据，`scripts/generate-routes.py` 会按 APNIC 原始分配边界生成精确网段。

APNIC 数据表示最初的资源分配地区，并不是实时地理位置数据库；CDN、跨境网络和地址转让可能产生少量例外。

## 隐私与风险

启用本工具意味着国内直连流量不再受到 VPN 隧道保护：本地网络和运营商可能看到连接目标，国内 DNS 查询也会直接发送给 AliDNS。国外流量和国外 DNS 上游会继续通过 ZoogVPN。

路由守护进程仅删除自己成功添加并记录的路由。若本地 DNS 不健康，或国外默认路由不再指向 `utun`，它会撤销 DNS 接管以避免系统断网或 DNS 直连泄漏。

不要同时启用会接管默认路由或本机 53 端口的其他 VPN/DNS 工具，除非你了解它们的优先级和冲突方式。

## 排查

先运行：

```bash
zoog-cn-bypass status
```

常见情况：

- `ZoogVPN: Disconnected`：先在 ZoogVPN 中连接 OpenVPN。
- `foreign 1.1.1.1` 不是 `utun`：Zoog 的 VPN 默认路由未建立，DNS 分流会保持关闭。
- DNS 服务无法启动：检查是否有其他程序占用本机 53 端口。
- 升级 Homebrew 的 `dnsmasq` 后：重新运行 `./install.sh` 即可同步更新受保护的 `dnsmasq` 副本。

查看最近日志：

```bash
log show --last 10m --style compact \
  --predicate 'process == "dnsmasq" OR eventMessage CONTAINS[c] "ZoogCNBypass"'
```

## 开发验证

```bash
./tests/validate.sh
```

## License

项目代码使用 [MIT License](LICENSE)。随仓库分发的数据来源和许可说明见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
