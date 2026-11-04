# cfip — Cloudflare 优选 IP 批量筛选

改造自 [zhlhlf/cf_ip_check](https://github.com/zhlhlf/cf_ip_check)。

**所有配置都在 `cf.env` 里**，不读、也不改 xray 的 `config.json`。

## 两种模式

`PASSWORD` 是模式开关，不需要额外的 flag：

| PASSWORD | 模式 | 探测方式 | 能证明什么 |
|---|---|---|---|
| 留空（默认） | **纯 TCP** | TCP 三次握手 | 只筛掉完全不可达的 IP，零配置可跑 |
| 填了 | **TLS+WS** | TCP → TLS1.3 → WS 101，可选隧道测速 | 真正承载该域名的 IP + 真实吞吐 |

纯 TCP 模式是给"还没配好节点、只想先看看通不通"用的。它测不出质量，原因见下节。

## 为什么需要 TLS+WS 模式

上游工具只测 **TCP connect**（`main.go:396` 的 `tcpConnectTimeout`）。这个指标在 Cloudflare 上是无效的：

- Cloudflare 是 anycast，本机到某条边缘路由的 TCP 握手几乎恒定在 **70ms**，254 个 IP 测出来全是 70–83ms
- 单次 TCP 握手根本不经过回源链路，测不出节点真实转发能力

实测证据（同一节点、同一 /24）：

| IP | 工具握手排名 | xray 真实延迟 | 真实下载 |
|---|---|---|---|
| 172.64.229.184 | 第 1 名 / 287ms | 608ms | 1.38 MB/s |
| 172.64.229.118 | 并列第 1 / 232ms | 667ms | 4.93 MB/s |
| 直接用节点域名 | 未进榜 | 2406ms | 0.68 MB/s |

握手最快的那个下载只有别人的 1/4，域名解析反而最差。**握手延迟和真实体验没有相关性。**

## 三个阶段

| 阶段 | 测什么 | 能证明什么 | 需要什么 |
|---|---|---|---|
| 1 快筛 | WS 握手是否返回 101 | IP 是否承载该域名、接受 WS 升级 | HOST + 端口 |
| 2 精测 | 上述握手 × N 轮取中位数 | 同上，排序更稳 | 同上 |
| 3 测速 | 带密码走完隧道下载 | **真实吞吐**，这才是用户体感 | 再加 PASSWORD + XRAY_BIN |

> ⚠️ **101 不等于可用**。Cloudflare 全站 anycast，10000 个候选里有 8561 个能返回 101。密码或 HOST 填错时它们照样全部返回 101，但一个都用不了。只有阶段 3 能证明节点真的通。
>
> ⚠️ **握手延迟不能用来选 IP**。它是"连上 CF 边缘"的耗时，不包含回源链路。同一 /24 内 35ms 的差距纯属网络抖动。

## 用法

`cf.env.example` 已内嵌进二进制：默认路径 `cf.env` 不存在时会自动生成一份模板，
改完再跑即可，不需要手动 `cp`。（显式指定的 `-env` 路径不存在仍会报错，避免路径写错时悄悄生成模板。）

```bash
# 默认读当前目录的 cf.env, 不存在则自动从内置模板生成
./cfip

# 完整筛选 + 测速, 并按 cf.env 的 CLASH_YML 写回 clash 配置
./cfip

# 限定网段穷举
./cfip -cidr 172.64.229.0/24

# 换个配置文件
./cfip -env /path/to/prod.env
```

| 参数 | 默认 | 说明 |
|---|---|---|
| `-env` | `cf.env` | 配置文件路径 |
| `-cidr` | | 限定网段，逗号分隔，覆盖在线列表 |
| `-n` | 4096 | 抽样候选数 |
| `-rounds` | 3 | 精测轮数 |
| `-refine` | 200 | 进入精测的候选数 |
| `-c` / `-rc` | 200 / 8 | 阶段 1 / 阶段 2 并发数 |
| `-timeout` | 0 | 单次探测超时（毫秒）；0 = 按模式取默认，纯 TCP 1s / TLS+WS 2.2s |
| `-verify` | false | 校验 TLS 证书（仅 TLS+WS 模式；默认跳过，系统 CA 过旧会误判） |

写回目标由 `cf.env` 的 `CLASH_YML` 决定，没有对应的命令行参数。

## cf.env

```ini
# ---- 连接信息 ----
HOST=example.com            # 配了 PASSWORD 才必填；同时作为 TLS SNI 和 HTTP Host
PORT=2096
WS_PATH=/                   # 键名是 WS_PATH，避免和 shell 的 PATH 撞车
PROTOCOL=trojan             # trojan / vless / vmess
PASSWORD=...                # 留空 = 纯 TCP 模式；填了 = TLS+WS 模式
XRAY_BIN=/path/to/xray      # 测速用的 xray 可执行文件

# ---- 写回 clash 配置 (可选) ----
CLASH_YML=                  # 填了就改该文件 proxies 段前 16 个节点的 server

# ---- 测速 (可选) ----
SPEED_URL=https://proof.ovh.net/files/10Mb.dat   # 留空 = 完全不测速
SPEED_TOP=5        # 参与测速的候选数
SPEED_REPEATS=3    # 每个 IP 重复几次取中位数
SPEED_TIMEOUT=40   # 单次下载超时（秒）
```

## 写回 clash 配置

`CLASH_YML` 填了路径就启用，程序结束后按最终排名改写该文件 `proxies:` 段里
**前 16 个**节点的 `server` IP：

```yaml
proxies:
  - {name: CF官方优选1, server: 104.17.148.141, port: 2096, type: trojan, ...}
  #                                              ↑ 只改这里
```

- 最终顺序：测速成功的按吞吐从高到低排前面，其余按握手排名补齐
- **`server` 和 `port` 一起改**，都写成 `cf.env` 里的值。只换 IP 会很危险：探测是按
  `cf.env` 的 `PORT` 做的，保留 yaml 里的旧端口等于把没验证过的 IP 塞进配置
- `name`/`password`/`sni`/`ws-opts`/引号/注释全部原样保留
- 只动 `proxies:` 段；`dns` 里同样叫 `server` 的字段不会被误改
- 条目少于 16 个时全改并打印警告，不会静默跳过
- 写文件是「写临时文件 + rename」，中途失败不会留下半个配置文件

改完不会自动重启 clash，需要的话自己 reload。

**不测速的三种情况**（都会在启动时明确提示原因）：

- `SPEED_URL` 为空
- 没配 `PASSWORD`（纯 TCP 模式）
- `XRAY_BIN` 没配或文件不存在

只有 `SPEED_*` 这组可以被同名环境变量覆盖（文件优先级更高的是环境变量），连接参数必须写在文件里 —— 否则会和 shell 的同名变量撞车。

**测速源的坑**：不要用 `speed.cloudflare.com` —— 代理本身就走 Cloudflare，测它等于绕回自家边缘，实测直接 0 字节。用 `proof.ovh.net` 之类第三方源。

## 构建

```bash
go build -o cfip .
```

本机没有 Go 时用临时工具链：

```bash
export PATH=/tmp/goroot/go/bin:$PATH GOCACHE=/tmp/gocache HOME=/tmp \
       GOPROXY=https://goproxy.cn GOFLAGS=-mod=mod
go build -o cfip .
```

## 实现要点

- **TLS 强制 1.3** —— 本机 curl 7.29+NSS 不支持 1.3，回落 1.2 会让握手看起来要 1.1–1.7 秒，那是假象。Go 的 `tls.Conn` 直接锁 1.3。
- **轮次在外层做屏障** —— 每轮把所有 IP 各测一遍，网络抖动被均匀分摊，避免"某几个 IP 恰好赶上拥堵"。
- **阶段 2 降并发** —— 100 并发下 TCP 测出 176ms，单独测只有 78ms，纯粹是本地排队。
- **阶段 3 串行 + 重复取中位数** —— 多个 xray 实例同时下载会互相抢带宽；单次测速受丢包影响噪声极大（实测同一 IP 两次能差 2 倍）。
- **综合评分** —— `下载 × 10 - 首字节延迟/100`，让吞吐主导。实测过握手相同的 IP 下载差 4 倍，而延迟差通常只有 100ms 量级。
