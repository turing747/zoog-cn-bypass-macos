# ZoogCNBypass for Windows

在 Windows 上让 ZoogVPN 保持全局连接，同时让中国大陆网站和 IP 通过本地物理网卡直连。分流依据是目标域名和 IP，不区分 App。原理与 macOS 版相同，数据（`../data`）共用。

## 工作方式

| 部分 | 做法 |
|---|---|
| IP 分流 | 把中国大陆 IPv4（及有物理 IPv6 网关时的 IPv6）网段以**更具体的路由**指向物理网关（IP Helper API，非持久，重启自动消失）。其余流量沿 ZoogVPN 隧道（OpenVPN/Wintun 的 `0.0.0.0/1`+`128.0.0.0/1`，或 WireGuard 的 `0.0.0.0/0`）。 |
| DNS 分流 | 内置本地 DNS 代理 `127.0.0.1:53`：国内域名 → AliDNS `223.5.5.5`/`223.6.6.6`（直连），其余 → `1.1.1.1`/`8.8.8.8`（走隧道）。带 `domain-needed`、`bogus-priv`、`stop-dns-rebind`、缓存与并发上限。 |
| 系统 DNS 接管 | 一条 NRPT 全局规则（命名空间 `.` → `127.0.0.1`，注释 `ZoogCNBypass`），不修改任何网卡 DNS。Tailscale 等自带更具体 NRPT 规则的程序不受影响。 |
| 常驻 | 计划任务 `ZoogCNBypass`（SYSTEM、开机启动、失败自动重启），每 3 秒检查 VPN 状态，连接时自动应用、断开时撤销 DNS 接管。 |
| 安全回滚 | 添加路由后用 `GetBestRoute2` 验证，失败整体回滚；只删除自己记录的路由；本地 DNS 不健康或国外流量没走隧道时撤销 DNS 接管。 |

它不会读取或修改 ZoogVPN 的账号、配置和程序文件。

## 要求

- Windows 10/11，管理员权限（安装与启用时会弹出 UAC）。
- Python 3.9+（建议系统级安装，如 `C:\Python312`；仅用标准库，无需 pip 安装任何包）。
  - 或使用 `build-exe.ps1` 打成单文件 exe，运行时无需 Python。
- 已安装 ZoogVPN 客户端（OpenVPN/Wintun 或 WireGuard 均可，自动识别）。

## 安装与使用

在仓库的 `windows` 目录：

```powershell
.\zoog-cn-bypass.cmd install      # 复制到 %ProgramData%\ZoogCNBypass、收紧权限、注册并启动计划任务
.\zoog-cn-bypass.cmd status       # 无需管理员；查看实时状态
.\zoog-cn-bypass.cmd disable      # 停止并清理（不会断开 ZoogVPN）
.\zoog-cn-bypass.cmd enable       # 重新启用
.\zoog-cn-bypass.cmd uninstall    # 完整卸载
```

其他命令：

```powershell
.\zoog-cn-bypass.cmd reconcile --dry-run   # 只打印将要做什么（无需管理员）
.\zoog-cn-bypass.cmd reconcile             # 手动应用一次（需要守护进程的 DNS 代理在运行才会接管 DNS）
.\zoog-cn-bypass.cmd cleanup               # 救援：强制清除本工具添加的路由与 NRPT 规则
.\zoog-cn-bypass.cmd update-data           # 重新下载 APNIC / dnsmasq-china-list（仅仓库检出时可用）
```

需要管理员权限的命令会自动弹出 UAC 并把输出回显到当前终端。

正常启用时，连接 ZoogVPN 后状态应类似：

```text
ZoogVPN: Connected (ZoogVPN TUN, ifIndex 87)
Scheduled task: Running
Local DNS service: listening on 127.0.0.1:53
Split DNS override (NRPT): active
China-direct routing: active
Installed IPv4 routes: 5494
Installed IPv6 routes: 0
Route check - China 223.5.5.5: <以太网/WLAN>
Route check - foreign 1.1.1.1: ZoogVPN TUN
DNS check - www.baidu.com: <国内 IP> via <以太网/WLAN>
DNS check - www.cloudflare.com: <境外 IP> via ZoogVPN TUN
```

## 兼容模式：VPN 的 DNS 泄漏防护会拦截本地 DNS

在开发机（ZoogVPN OpenVPN/Wintun 已连接）上实测：连接后，除隧道接口（如 `10.20.136.22`）外，**回环 `127.0.0.1` 与物理网卡 IP 的 UDP/TCP 53 端口都被系统层拦截**（TCP 返回 `WSAEACCES`），经物理网卡发往 AliDNS 的 53 端口也不通；其他端口（含 HTTPS 443）不受影响。这是 ZoogVPN 客户端的 DNS 泄漏防护（类似 OpenVPN 的 `block-outside-dns`）。

默认模式下的表现：本地 DNS 代理收不到查询，守护进程出于安全**不会**启用 NRPT 接管；**IP 路由分流仍然生效**，但国内域名由 VPN 的 DNS 解析，常会得到境外 IP（例如 `www.baidu.com` → `103.x`），于是仍走隧道。

两种解决办法：

1. 在 ZoogVPN 客户端里关闭 DNS 泄漏防护/Kill Switch 类选项（若提供），然后使用默认模式。
2. **兼容模式**（需要你明确同意，默认关闭）：

   ```powershell
   .\zoog-cn-bypass.cmd compat on     # 写入 config.json 并重启守护进程
   .\zoog-cn-bypass.cmd compat off    # 还原
   ```

   - 本地 DNS 代理改为监听**隧道地址**的 53 端口（VPN 客户端放行 DNS 的位置，随每次连接变化，守护进程自动跟随并更新 NRPT），且只接受本机来源的查询；
   - 国内域名改用 **DoH（HTTPS 443）** 直连 AliDNS（`https://223.5.5.5/dns-query`、`223.6.6.6`），国外域名仍经隧道解析。

   **这等于绕开了 ZoogVPN 客户端为国内域名设置的 DNS 泄漏防护**：国内域名的 DNS 查询会走物理网卡（加密的 HTTPS，但运营商可见你在连接 AliDNS）。国外域名不受影响。
## 配置


`%ProgramData%\ZoogCNBypass\config.json`（安装时生成，可选修改后重启任务）：

- `vpn_adapter_patterns`：识别 VPN 适配器的名称/描述子串（默认 `ZoogVPN`、`Wintun`、`Amnezia`、`WireGuard`、`OpenVPN`、`TAP-Windows`）。
- `virtual_adapter_patterns`：不当作「物理网卡」的子串（Tailscale、Hyper-V、VMware、Sangfor 等）。
- `poll_seconds`：检查间隔，默认 3 秒。

识别判据：`1.1.1.1` 的最佳路由必须落在匹配的 VPN 适配器上，否则视为未连接（`status` 会说明原因），不会加路由也不会接管 DNS。

## 安装内容与安全加固

- `%ProgramData%\ZoogCNBypass\`：仅 SYSTEM 与 Administrators 可写（`icacls` 去除继承），普通用户只读（`status` 需要读状态）。
- 计划任务以 SYSTEM 运行 `python -I -E -s ...\app\run_daemon.py daemon`（隔离模式，忽略 `PYTHON*` 环境变量与用户 site-packages）。**请使用系统级 Python**；安装器检测到 Python 位于用户目录会给出警告。
- 本地 DNS 仅绑定 `127.0.0.1`，不对局域网开放。域名列表加载时逐行严格校验，出现非 `server=/域名/223.5.5.5` 的指令会拒绝加载。
- 路由列表同样校验：拒绝私网/CGNAT/保留地址，并排除 `1.1.1.1`、`8.8.8.8`。

## 隐私与风险

- 国内直连流量不再受 VPN 保护：本地网络和运营商可能看到连接目标，国内 DNS 查询会直接发送给 AliDNS。国外流量和国外 DNS 上游继续通过 ZoogVPN。
- 浏览器内置 DoH（如 Chrome 的「安全 DNS」）会绕过系统 DNS 分流；需要国内外分流请关闭它。
- NRPT `.` 规则会覆盖没有更具体 NRPT 规则的内网/公司 DNS。
- NRPT 规则写入注册表。如果守护进程被强杀，规则会指向已停止的本地 DNS 导致无法解析：守护进程启动时会先清理，也可随时运行 `cleanup` 恢复。
- 不要同时运行其他占用本机 53 端口的 DNS 工具。ICS/Hyper-V 默认交换机占用的是 `0.0.0.0:53`，已验证不会与绑定在 `127.0.0.1:53` 的本代理冲突。
- 本版本只做 IPv4 的国内直连；仅当物理网卡存在 IPv6 默认网关（`fe80::`）时才会为国内 IPv6 网段加直连路由，否则 IPv6 继续走隧道（不泄漏）。

## 排查

先运行 `status`。常见情况：

- `ZoogVPN: Disconnected`，备注 `VPN adapter ... is up, but foreign traffic is not routed through it`：隧道已建立但默认流量没走它（例如客户端未启用全局路由）；此时工具保持关闭状态。
- `Local DNS service: not responding`：查看 `%ProgramData%\ZoogCNBypass\logs\daemon.log`；检查是否有程序占用 `127.0.0.1:53`。
- 用 `Get-DnsClientNrptRule | ? Comment -eq ZoogCNBypass` 检查规则，`route print -4` 查看路由。
- 网络异常且怀疑残留规则：以管理员运行 `.\zoog-cn-bypass.cmd cleanup`。

## 开发验证

```powershell
cd windows
python -m unittest discover -s tests -v
```

测试无需管理员：覆盖 CIDR/数据校验、DNS 报文与分流（本地假上游）、reconcile 逻辑（模拟路由表）、真实 Windows API 的只读检查。

## License

同仓库的 MIT License。
