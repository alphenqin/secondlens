# secondlens

`secondlens` 是供应商侧受控外联情报二次研判桶处理程序，需求见 [RD.md](RD.md)。

它不是 Web API 服务。当前主流程是：

```text
只读桶 secon_analysis_{任务ID}.json
        |
        | 读取 id / ioc
        v
IntelLens IOC 研判核心
        |
        | 生成 evidence
        v
secondlens WFY v2 查询
        |
        | 回填非 evidence 字段
        v
assessment_results_{任务ID}_{时间戳}.json
        |
        v
写入只写桶 日期/任务ID/
```

当前供应商侧自动流程只消费 `secon_analysis_{任务ID}.json`。`alert_message/` 告警文件和 `rejection_result/` 拒绝反馈文件不进入自动处理流程。

## 目录结构

```text
README.md
requirements.txt
config.yaml
main.py
app/
  config.py              # YAML/env 配置加载、桶名称生成
  worker.py              # 本地/桶单次处理
  scheduler.py           # APScheduler 长轮询桶监听
  clients/
    api_client.py        # S3 兼容对象存储读写
    http_client.py       # httpx 封装
  intellens/             # 从 IntelLens 迁移的 IOC 研判核心，不含 Excel/API/DB 层
    clients/
  services/
    intellens_service.py # IntelLens 产物到 RD evidence 的映射
    task_service.py      # 结果 JSON 组装、IOC 解析、处理状态
    wfy_service.py      # secondlens 自有 WFY v2 字段适配层，后续可替换 v3
  models/
    task.py              # 任务、研判结果模型
  utils/
    logger.py            # loguru 日志配置
deploy/
  secondlens.service     # systemd 服务模板
tests/
```

`app/intellens/` 需要和上游 IntelLens 研判核心 `docs/webapi2/py3/apps/intellens/` 保持一致。修改或同步前先看 [.codex/intellens-sync.md](.codex/intellens-sync.md)。

## 运行方式

安装依赖：

```bash
python3 -m pip install -r requirements.txt
```

默认启动后会自动轮询只读桶：发现 `secon_analysis_{任务ID}.json` 后自动读取、研判、写本地结果，并按 `config.yaml` 的 `runtime.upload` 配置上传到只写桶。当前默认配置已开启上传。

```bash
python3 main.py
```

如果项目已安装命令行入口，也可以使用：

```bash
secondlens
```

配置默认读取 `config.yaml`，也可以通过 `--config` 指定其他配置文件。轮询间隔、是否上传、最大任务数等默认行为都放在配置文件里：

```yaml
runtime:
  poll_interval_seconds: 60
  upload: true
```

### 调试命令

本地 dry run：先把只读桶文件放到 `data/input/YYYYMMDD/{任务ID}/`，再执行：

```bash
python3 main.py local
```

从只读桶读取指定前缀的任务，只处理一次：

```bash
python3 main.py bucket --prefix 20260707/ --max-tasks 10
```

临时覆盖配置并持续监听：

```bash
python3 main.py watch --interval 60 --upload
```

## 生产部署

建议使用 systemd：

先把 `deploy/secondlens.service` 里的 `WorkingDirectory` 改成服务器上的实际项目目录。例如项目放到 `/opt/secondlens` 时保持默认即可；如果放到 `/data/apps/secondlens`，就改成：

```ini
WorkingDirectory=/data/apps/secondlens
```

```bash
sudo cp deploy/secondlens.service /etc/systemd/system/secondlens.service
sudo systemctl daemon-reload
sudo systemctl enable --now secondlens
sudo systemctl status secondlens
```

日志默认写入：

```text
logs/secondlens.log
```

systemd 自身的 stdout/stderr 日志通过 `journalctl -u secondlens -f` 查看。

临时前台/后台测试可以用：

```bash
nohup python3 main.py >> logs/secondlens.log 2>&1 &
```

## 去重和上传

监听模式会把已处理的只读桶任务 key 记录到：

```text
data/work/processed_tasks.json
```

程序重启后不会重复提交同一个 `secon_analysis` 任务。

生成结果会先写本地：

```text
data/output/日期/任务ID/assessment_results_任务ID_时间戳.json
```

只有启用 `--upload` 或配置 `runtime.upload: true` 时，才会上传到只写桶；默认 `config.yaml` 已设置为 `true`。

## 研判和 evidence

IOC 研判逻辑来自 IntelLens 核心流水线，保留：

- WFY
- XMON
- SC
- hash
- WD
- external
- AI
- LLM evidence_chain 总结
- decision 规则

已故意移除：

- Excel 读写
- Web API 路由和响应模型
- MongoDB 请求日志
- Excel 失败重跑

`app/services/intellens_service.py` 只负责把 IntelLens 产物映射到 RD `evidence`。除 `evidence` 外，其他回传字段不从 IntelLens 取值。

以下字段由 secondlens 自己通过 `app/services/wfy_service.py` 单独请求 WFY v2 回填：

```text
ops          <- WFY v2 judge，black -> +，非 black 或空值 -> -
malicious_stamp <- 需求未明确，当前固定回填 ""
base         <- WFY v2 base，字符串原样回填
tpd          <- WFY v2 tpd，0/false -> false，1/true -> true
category_v8  <- WFY v2 category_v8 数组的第一个整数
category_v9  <- WFY v2 category_v9 数组的第一个整数
category_new <- WFY v2 category_new 数组的第一个整数
first_seen   <- WFY v2 first_seen，UTC ISO 8601 字符串原样回填
confidence   <- WFY v2 confidence，整数
risk_level   <- WFY v2 risk_level，整数
status       <- WFY v2 status，按下列枚举映射：
                ACTIVE   -> active
                OVER     -> inactive
                SINKHOLE -> sinkhole
                UNKNOWN  -> unknown
control_type <- 非必填，当前固定回填 ""
file_hash    <- 非必填，当前固定回填 []
last_seen    <- 非必填，当前固定回填 ""
created_time <- 非必填，当前固定回填 null
modified_time <- 非必填，当前固定回填 null
campaign     <- 非必填，当前固定回填 null
malicious_family <- 非必填，当前固定回填 []
platform     <- 非必填，当前固定回填 []
tags         <- 非必填，当前固定回填 []
ttps         <- 非必填，当前固定回填 []
scene        <- WFY v2 scene，整数，缺失为 null
whois        <- WFY v2 whois，对象原样回填，缺失为 null
icp          <- WFY v2 icp，原样回填，缺失为 null
dns          <- WFY v2 dns，非空值组成数组，缺失为 null
open_port    <- WFY v2 open_port，非空整数值组成数组，缺失为 null
geo          <- WFY v2 geo，非空值组成数组
dynamic_domain <- WFY v2 dynamic_domain，布尔值，缺失为 null
certificate  <- WFY v2 certificate，字符串原样回填，缺失为 null
```

`generation_method` 需求未明确，当前固定回填 `""`。

以后 secondlens 如果切到 WFY v3，只替换 `app/services/wfy_service.py`，不要改 `app/intellens/clients/wfy.py`，后者要继续和 IntelLens v2 保持一致。

## 校验

上传前会做本地字段校验。当前校验重点包括：

- `id` 必须是数字字符串。
- `ops` 必须是 `+` 或 `-`。
- `ioc_host`、`ioc_port`、`ioc_uri`、`protocol`、`ioc_type` 由 IOC 解析生成。
- 枚举字段如果非空，必须符合 RD 枚举。
- `source_links` 如果非空，必须是合法 `http/https` URL。
- `traffic_fragments` 如果非空，必须包含 `traffic_type`、`traffic_pattern`、`description`。
- `sample_behavior` 如果非空，必须至少包含 `hash_md5` 或 `hash_sha256`。

如果校验失败，结果仍会写本地，但不会上传。

## 时效

桶任务的 `LastModified` 会作为任务接收时间。处理耗时超过 `runtime.task_deadline_seconds` 时，会在日志里标记 `overdue=true`。默认阈值是一小时。
