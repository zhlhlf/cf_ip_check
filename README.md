# cf-ip-select-go

Go 版 Cloudflare IP 优选工具，迁移自 `a.c`。

功能：

- 拉取 Cloudflare CIDR 列表，失败时使用内置备用网段。
- 随机抽样候选 IP，并发 TCP 连接测试延迟。
- 输出最快的 32 个结果。
- 可选更新 mihomo/clash 配置中 `CF官方优选1` 到 `CF官方优选32` 的 `server`、`port`、`password`、`sni`、`Host`。

## 使用

```bash
cfip [config文件] [端口] [password] [sni]
```

示例：

```bash
cfip
cfip config.yaml
cfip config.yaml 2096
cfip config.yaml 2096 YOUR_PASSWORD
cfip config.yaml 2096 YOUR_PASSWORD YOUR_SNI_DOMAIN
```

不传配置文件时只打印优选结果。传入配置文件时会按最快结果更新配置。

## 本地构建

在仓库根目录直接执行：

```bash
go build
```

Windows 下会生成 `cf-ip-select-go.exe`，Linux/macOS 下会生成 `cf-ip-select-go`。

Windows PowerShell：

```powershell
.\scripts\build.ps1
```

Linux/macOS：

```bash
sh ./scripts/build.sh
```

构建产物在 `dist/`：

- `cfip-windows-amd64.exe`
- `cfip-linux-amd64`
- `cfip-darwin-amd64`
- `cfip-android-amd64`

注意：`android/amd64` 目标需要 Android NDK 外部链接。本机打包前设置 `ANDROID_NDK_HOME`，或设置 `ANDROID_CC` 指向 `x86_64-linux-android21-clang`。没有 NDK 时可临时跳过 Android：

```powershell
.\scripts\build.ps1 -SkipAndroid
```

```bash
SKIP_ANDROID=1 sh ./scripts/build.sh
```

## GitHub Actions

推送 `v*` tag 或手动运行 `Release` workflow，会自动构建 Windows、Linux、macOS、Android 的 x64 产物。
