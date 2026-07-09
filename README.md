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
        | 生成研判结论和 evidence
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
    intellens_service.py # IntelLens 结果到 RD 回传字段/evidence 的映射
    task_service.py      # 结果 JSON 组装、IOC 解析、处理状态
    wfy_status_service.py # secondlens 自有 WFY status 适配层，当前兼容 v2
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

本地 dry run：先把只读桶文件放到 `data/input/YYYYMMDD/{任务ID}/`，再执行：

```bash
python3 main.py local
```

从只读桶读取任务，只写本地结果：

```bash
python3 main.py bucket --prefix 20260707/ --max-tasks 10
```

从只读桶读取任务，并上传结果到只写桶：

```bash
python3 main.py bucket --prefix 20260707/ --upload
```

持续监听只读桶：

```bash
python3 main.py watch --interval 60 --upload
```

如果项目已安装命令行入口，也可以使用：

```bash
secondlens watch --interval 60 --upload
```

配置默认读取 `config.yaml`，也可以通过 `--config` 指定其他配置文件。

## 生产部署

建议使用 systemd：

```bash
sudo cp deploy/secondlens.service /etc/systemd/system/secondlens.service
sudo systemctl daemon-reload
sudo systemctl enable --now secondlens
sudo systemctl status secondlens
```

日志默认写入：

```text
logs/secondlens.log
logs/systemd.log
logs/systemd.err.log
```

临时前台/后台测试可以用：

```bash
nohup python3 main.py watch --interval 60 --upload >> logs/secondlens.log 2>&1 &
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

只有启用 `--upload` 或配置 `runtime.upload: true` 时，才会上传到只写桶。

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

`app/services/intellens_service.py` 负责把 IntelLens 产物映射到 RD 回传 JSON，包括：

- `ops`
- `malicious_stamp`
- `status`
- `base`
- `generation_method`
- `category_v8`
- `category_v9`
- `category_new`
- `confidence`
- `risk_level`
- `file_hash`
- `tags`
- `evidence`

`status` 当前使用 `WfyStatusService` 从 WFY v2 的 `status` 字段回填：

```text
ACTIVE   -> active
OVER     -> inactive
SINKHOLE -> sinkhole
UNKNOWN  -> unknown
```

以后 secondlens 如果切到 WFY v3，只替换 `app/services/wfy_status_service.py`，不要改 `app/intellens/clients/wfy.py`，后者要继续和 IntelLens v2 保持一致。

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
