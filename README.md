# rlproxy — 事件驱动的分层限流反向代理

用 C 写的单线程、事件循环反向代理，在网关前做 IP / 用户令牌 / 路由三层限流，
保护后端不被突发流量和慢速连接攻击打垮。macOS 用 kqueue，Linux 用 epoll，
同一份事件循环抽象下两个后端可互换。

## 组件

| 二进制 | 作用 |
|---|---|
| `rlproxy` | 限流反向代理本体 |
| `replay` | 流量回放 / 攻击发生器，输出延迟分位与放行率 |
| `upstream_echo` | 事件驱动的测试上游，单进程承载数千连接 |
| `test_unit` | 两种限流算法的确定性单元测试（假时钟） |

## 目录结构

```
include/            公共头文件（事件循环、缓冲、HTTP、限流、配置）
src/
  event_loop.c            计时器堆 + 信号自管道 + 主循环
  event_loop_kqueue.c     macOS/BSD 后端
  event_loop_epoll.c      Linux 后端
  ratelimit.c             令牌桶 + 滑动窗口日志
  http.c                  增量 HTTP/1.x 请求/响应解析
  proxy.c request.c upstream.c   连接状态机、分层限流、双向中继、热加载
  hashmap.c sbuf.c util.c config.c main.c
tools/
  replay.c                回放 / burst / slow / mix 四种模式
  upstream_echo.c         测试上游
tests/
  rlproxy.conf            示例配置
  rlproxy.load.conf       压测调优后的配置
  model.conf              流量模型
  test_ratelimit.c        单元测试
  e2e.sh                  端到端测试
```

## 构建

```sh
make            # 自动按平台选 kqueue/epoll
make test_unit  # 跑限流算法单元测试
./tests/e2e.sh  # 端到端：转发、429、Retry-After、热加载、坏配置拒绝
```

依赖只有 libc 和 libm，无第三方库。C11，零警告编译
（`-Wall -Wextra -Wshadow -Wstrict-prototypes ...`）。

## 运行

```sh
./upstream_echo 127.0.0.1:19000      # 测试上游，可选 [delay_ms] [body_bytes]
./rlproxy -f tests/rlproxy.conf -p rlproxy.pid -v
```

信号：

- `SIGHUP`  重新加载配置
- `SIGUSR1` 打印各 zone 的 key 数、放行/拒绝计数
- `SIGINT`/`SIGTERM` 优雅退出

不发信号也会每秒检测配置文件 mtime，文件被替换即自动热加载。

## 配置

文本格式，`#` 注释，未知指令是硬错误（防止拼写错误静默关掉一条限流）。

```
listen    127.0.0.1:18080
upstream  127.0.0.1:19000
token_header X-User-Token
trust_xff on            # 从 X-Forwarded-For 取客户端 IP
max_conns 20000         # 连接级兜底，超出回 503 + Retry-After
head_timeout_ms 8000    # 请求头超时，挡 slowloris
idle_timeout_ms 30000

# zone <名字> type=ip|token|route key=... alg=token_bucket|sliding_log \
#            rate=<n>/s|/m [burst=<n>]
zone ip_fast  type=ip    key=$ip    alg=token_bucket rate=30/s  burst=60
zone user_q   type=token key=$token alg=sliding_log  rate=600/m
zone admin    type=route key=/admin alg=sliding_log  rate=10/s
```

### 三层如何叠加

每个请求按配置顺序经过所有匹配的 zone，**任意一层拒绝即返回 429**：

1. **IP 层** — 按来源 IP（信任 XFF 时取其首个地址）限流，挡单源洪水。
2. **令牌层** — 按 `token_header` 里的用户令牌限流；无令牌归入 `anon`。
   注意匿名配额要按 IP 维度配（`type=ip`），不要用一个全局 `anon` key，
   否则所有匿名调用者共用一个桶，该 zone 会成为整体瓶颈（见
   `docs/tuning.md` 的复盘）。
3. **路由层** — 按路径前缀匹配，保护昂贵接口（如 `/admin`）和聚合总量。

## 两种算法

- **令牌桶 `token_bucket`**：容量 `burst`，按 `rate/window` 持续补充。
  适合吸收短时突发、维持长期吞吐，用在 IP 层和路由聚合层。
- **滑动窗口日志 `sliding_log`**：保留窗口内最多 `rate` 个时间戳，
  半开区间 `(now-window, now]`，边界精确、无桶额度囤积，适合需要硬上限的
  用户配额和敏感路由。

拒绝时统一返回：

```
HTTP/1.1 429 Too Many Requests
Retry-After: 1
Content-Type: application/json
Connection: close

{"error":"rate_limited"}
```

`Retry-After` 由算法算出（令牌桶按补足 1 个令牌的时间，窗口日志按最老
时间戳滑出窗口的时间），向上取整到整秒，至少 1。

## 热加载为什么不断连接

连接对象不持有任何指向配置的指针；zone 按名字存放在独立哈希表中。
reload 时解析新配置 → 同名 zone 就地 `rl_zone_reconfigure`（令牌桶/窗口
计数保留，仅换参数；算法切换才清空该 zone）→ 新增的建 zone、消失的销毁。
监听端口变更时先绑定新监听成功再关旧的。进行中的 socket 完全不参与
reload，因此连接不中断。坏配置解析失败时整体回退，旧配置继续服务。

## 回放工具

```sh
# 突发攻击：800 个虚拟客户端全速打 8 秒
./replay -t 127.0.0.1:18080 -m tests/model.conf -M burst -d 8 -c 1500 --attack 800

# 攻击 + 正常基线，分开统计两组的放行率和延迟分位
./replay -t 127.0.0.1:18080 -m tests/model.conf -M mix -d 8 \
         --attack 400 --benign 30

# slowloris：每 2s 滴一个字节，占住连接 12s，验证 head_timeout 回收
./replay -t 127.0.0.1:18080 -m tests/model.conf -M slow \
         --attack 150 --drip-ms 2000 --hold-ms 12000

# 固定 rps 回放，JSON 输出
./replay -t 127.0.0.1:18080 -m tests/model.conf -M replay -r 200 -j
```

流量模型 `model.conf` 每行 `METHOD /path [weight=N] [token=...]`。
输出每组的 `sent / allowed / 放行率 / 429 / IO 错误` 与
`p50 p90 p95 p99 max` 延迟分位。虚拟客户端各自带独立源 IP（攻击与正常
流量用不相交网段），正常客户端带稳定用户令牌，从而在三层都有稳定身份。

## 设计取舍

- **单线程事件循环**：限流逻辑无需加锁，热点路径只有几次哈希查找；
  水平触发 + 非阻塞 IO，背压靠在 socket interest 上反映缓冲压力。
- **首版每请求一条上游连接（Connection: close）**：状态机最直接、
  语义最稳；keep-alive 复用可在同一状态机上后续开启，不影响限流层。
- **OOM 时 fail-open**：分配失败优先放行而非整体拒绝，避免内存抖动
  演变成全站故障；连接级 `max_conns` 仍是硬兜底。
- **Linux 说明**：epoll 后端与 kqueue 后端实现同一套接口，本机（macOS）
  无法编译验证 Linux 头文件，代码已按 `EPOLLIN/OUT/RDHUP` 水平触发语义
  编写，上 Linux 后 `make` 自动选用。
