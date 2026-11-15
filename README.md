# rlproxy — 限流反向代理 + rlreplay 流量回放压测工具

C11 实现，单线程事件循环（macOS `kqueue` / Linux `epoll`，编译期自动选择），
专为"网关被刷到雪崩"的场景设计：超限请求在**建立上游连接之前**就被 429 拒绝，
拒绝路径不碰上游、几乎零成本。

## 构建

```sh
make          # 产出 rlproxy 和 rlreplay
```

## rlproxy

```sh
./rlproxy -c conf/proxy.conf
kill -HUP <pid>     # 配置热加载：限流参数/路由/上游/监听地址全部生效，不断任何连接
```

### 分层限流

一个请求要依次通过所有适用层，任一层拒绝即返回 429：

| 层 | 键 | 说明 |
|---|---|---|
| `limit ip` | 客户端 IP | 建议令牌桶，容忍 NAT 突发 |
| `limit token` | `Authorization: Bearer` / `X-Api-Key` | 建议滑动窗口，严格配额 |
| `route <前缀>` | 路由前缀（全局限流） | 最长前缀匹配，保护贵接口 |

### 两种算法

- **令牌桶** `token_bucket`：`rate`（令牌/秒）+ `burst`（桶容量）。平滑限流，
  允许不超过 burst 的突发。新键满桶启动。
- **滑动窗口日志** `sliding_window`：`limit` + `window_ms`。窗口内精确计数，
  不容忍任何突发，超限的 `Retry-After` 精确到最早一条日志滑出窗口的时间。

429 响应示例：

```
HTTP/1.1 429 Too Many Requests
Retry-After: 1
X-RateLimit-Layer: ip

{"error":"rate_limited","layer":"ip","retry_after":1}
```

### 其他特性

- HTTP/1.1 keep-alive（客户端与上游各自独立维持），响应流式转发，
  支持 Content-Length / chunked / EOF 三种分帧，写缓冲 256KB 高水位回压
- 慢连接攻击防护：请求头必须在 `header_timeout_ms` 内发完（按请求计时，
  不被单字节心跳重置），空闲连接 `idle_timeout_ms` 回收
- 限流状态按键哈希存储，空闲条目定期清扫；SIGHUP 热加载保留未超期键的状态
- 上游不可达返回 502；`max_conns` 超限返回 503
- 每 5s 向 stderr 输出 `allowed/denied/conns/keys` 统计

已知取舍：请求体仅支持 Content-Length（chunked 请求体返回 501）；
不支持客户端管线化（pipeline）请求。

## rlreplay

```sh
# 模式 1：当一个极简上游（keep-alive，200 "hello world!"）
./rlreplay --serve 127.0.0.1:9000

# 模式 2：负载发生 / 流量回放
./rlreplay --target 127.0.0.1:8080 --duration 30 --rps 500 --conns 100 \
           --burst-rps 3000 --burst-start 10 --burst-dur 3 \
           --paths /api/list,/api/heavy --tokens 1000 \
           --slow 300 --slow-ms 500
./rlreplay --target ... --model conf/model.csv     # 按录制模型回放（offset_ms METHOD /path token）
```

输出：每 2s 一行实时统计，结束输出延迟分位（p50/p90/p99/p99.9/max/mean）、
2xx/429 分布、放行率、慢连接存活/被杀数。

## 压测调参记录（本机实测，Darwin arm64）

| 场景 | 配置 | 结果 |
|---|---|---|
| 基线 | 50 rps，IP 层 100/s | 100% 放行，p99 1ms |
| 超限精度 | 500 rps × 5s，桶 100/s+200 | 放行 699 ≈ 200+100×5 |
| 令牌层 | 3 token × 100 rps，窗 100/10s | 放行 300 = 3×100，精确 |
| 路由层 | 100 rps 打 20/s+40 | 放行 239 ≈ 40+20×10 |
| 突发吸收 | 基线 10 rps + 1s 200 rps 突发，桶 20/s+40 | 突发秒吸收 ~57%（40 桶容+20 补充），滑动窗口同场景硬顶 |
| 慢连接攻击 | 300 slowloris + 正常 50 rps | 慢连接 10s 内全部掐死，正常流量 100% 放行 |
| 雪崩 | 5000 rps 冲击 100/s+200 | 放行 1699 ≈ 理论值，97.7% 快速 429，代理 CPU 3.9%，RSS 5.8MB，p99.9 0ms，0 连接错误 |
| 热加载 | 200 rps 持续打，中途两次 SIGHUP 改限流值 | 新参数立即生效（100→744/5s→收紧归零），全程 0 连接错误 |

**调参结论**（已写入 `conf/proxy.conf` 默认值）：

1. IP 层用令牌桶、`burst = 2×rate`：共享 IP 的正常用户突发被桶吸收，
   持续超限才被压到均值；滑动窗口在这里误伤明显。
2. 令牌层用滑动窗口：配额语义严格，超限后 `Retry-After` 有明确含义
   （最早日志滑出窗口的时间），客户端退避行为可预期。
3. `header_timeout_ms 10000` 足够：正常请求头毫秒级完成，
   慢连接攻击 10s 掐断，资源占用可忽略。
4. 429 路径成本极低（不建上游连接、不回读请求体以外的字节），
   雪崩时代理自身不会成为瓶颈——限流要"宁可误杀"。

## 文件布局

```
src/evloop.c    kqueue/epoll 事件循环抽象
src/http.c      增量 HTTP 头解析 + chunked 分帧跟踪
src/limiter.c   令牌桶 / 滑动窗口日志，哈希表 + 空闲清扫
src/config.c    配置解析（自定义文本格式，# 注释）
src/proxy.c     连接状态机、分层限流、热加载、超时清扫
tools/replay.c  回放/压测/慢连接模拟/极简上游
conf/proxy.conf 调优后的默认配置
conf/model.csv  录制流量模型样例
```
