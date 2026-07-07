# 供应商受控外联情报二次研判需求文档

## 1. 文档说明

本文档根据 `doc/供应商受控外联情报二次研判标准.docx` 整理，用于指导供应商侧实现受控外联情报二次研判任务的接收、处理、结果回传与整改重提。

## 2. 背景与目标

当前供应商基于海量情报的回扫周期较长，部分线索在流转到处置环节时已经失效，或缺少完整证据链，导致客户侧排查处置时误报率高、响应效率低。

本需求要求通过对象存储桶机制，将网防云侧每小时产生的网络威胁情报推送给供应商。供应商需要在规定时间内完成二次研判，判断情报是否误报，并补充符合要求的证据链信息，再将研判结果回传至指定存储桶。

核心目标：

- 按小时接收网防云侧下发的待研判任务。
- 在本小时内完成二次研判并回传结果。
- 判断情报是否误报。
- 补充完整、合规的证据链信息。
- 支持审核拒绝后的整改重提。
- 为月度时效与质量考核提供数据基础。

## 3. 角色与职责

### 3.1 网防云侧

- 每小时整点触发任务整合。
- 在每小时前 10 分钟内完成待研判任务推送。
- 将任务写入供应商只读桶。
- 读取供应商只写桶中的研判结果。
- 审核研判结果格式、字段和证据链完整性。
- 对审核不通过的结果生成拒绝原因，并写回只读桶的 `rejection_result/` 目录。

### 3.2 供应商侧

- 持续监控只读桶文件更新。
- 下载待研判情报和关联告警。
- 在当前小时内完成研判。
- 判断情报是非误报还是误报。
- 按字段标准和证据链必填要求补充结果。
- 将结果文件写入只写桶指定任务目录。
- 对被拒绝结果按拒绝原因整改并重新提交。

## 4. 整体业务流程

1. 任务下发：网防云侧每小时整点触发，例如 `01:00`，并在 `01:00-01:10` 内完成任务整合和写桶。
2. 任务获取：供应商监控只读桶，发现新任务后下载待研判情报和关联告警。
3. 研判执行：供应商在本小时内完成二次研判，判断是否误报，并补充证据链。
4. 结果回传：供应商将研判结果写入只写桶中对应任务 ID 的目录。
5. 结果审核：网防云侧读取并审核研判结果。
6. 拒绝处理：审核不通过时，网防云侧将结果文件复制到只读桶 `rejection_result/`，并追加拒绝原因。
7. 整改重提：供应商查看拒绝原因，整改后重新提交。研判结果和研判时间以最后一次提交为准。

## 5. 时效要求

- 网防云侧每小时推送一次任务，全天 24 小时不间断运行。
- 每小时任务应在前 10 分钟内推送完成，例如 `01:10` 前完成 `01:00` 时段任务推送。
- 供应商必须在任务所属小时内完成研判和合格结果回传。
- 示例：`01:10` 推送的任务，需要在 `01:10-02:00` 内完成研判并回传合格结果。
- 超出规定时间提交的研判结果视为过期研判，后续会扣除相应分数。
- 若结果被拒绝并重新提交，最终研判结果和研判时间以最后一次提交为准。

## 6. 存储桶规范

每个供应商分配两个独立对象存储桶，沿用现有对象存储访问密钥 AK/SK。

| 存储桶 | 权限 | 正式桶名称格式 | 测试桶名称格式 | 用途 |
| --- | --- | --- | --- | --- |
| 只读桶 | 供应商仅可读取 | `second-analysis-inbox-{供应商编码}` | `second-analysis-inbox-{供应商编码}-dev` | 接收网防云侧推送的待研判任务及关联告警信息 |
| 只写桶 | 供应商仅可写入 | `second-analysis-outbox-{供应商编码}` | `second-analysis-outbox-{供应商编码}-dev` | 回传供应商研判结果 |

供应商编码如下：

| 序号 | 供应商 | 编码 |
| --- | --- | --- |
| 1 | 360 | `360` |
| 2 | 阿里 | `ali` |
| 3 | 华为 | `hw` |
| 4 | 绿盟 | `lm` |
| 5 | 奇安信 | `qax` |
| 6 | 腾讯 | `tx` |
| 7 | 知道创宇 | `zdcy` |

## 7. 任务生成规则

- 24 小时内，同一个 IOC 生成唯一任务 ID。
- 待研判情报以 JSON 文件形式下发。
- 关联告警以 JSON 文件形式下发，聚合该情报前 24 小时内的告警信息。
- 待研判情报默认 24 小时闭环。
- 同一条情报闭环后，如果仍有新告警产生，应重新触发新的研判流程，并生成新的任务 ID。

## 8. 只读桶目录结构

| 路径 | 文件名 | 说明 |
| --- | --- | --- |
| `/日期/{任务ID}/` | `secon_analysis_{任务ID}.json` | 待研判情报信息 |
| `/日期/{任务ID}/alert_message/` | `alert_message_{任务ID}_{时间戳}.json` | 对应情报的告警信息聚合，时间戳精确到毫秒 |
| `/日期/rejection_result/` | `assessment_results_{任务ID}_{时间戳}.json` | 存放被拒绝收录的结果文件和拒绝原因 |

### 8.1 待研判情报文件

文件名：

```text
secon_analysis_{任务ID}.json
```

内容格式：

```json
{
  "id": "纯数字任务ID",
  "ioc": "server-01.example.com"
}
```

### 8.2 关联告警文件

文件名：

```text
alert_message_{任务ID}_{时间戳}.json
```

内容格式：

```json
{
  "id": "纯数字任务ID",
  "alertdevCount": 100,
  "alertCount": 5
}
```

字段说明：

| 字段 | 说明 |
| --- | --- |
| `id` | 任务 ID |
| `alertdevCount` | 告警设备数量 |
| `alertCount` | 告警次数 |

## 9. 只写桶目录结构

| 路径 | 文件名 | 说明 |
| --- | --- | --- |
| `/日期/{任务ID}/` | `assessment_results_{任务ID}_{时间戳}.json` | 供应商研判结果回传文件，时间戳精确到毫秒 |

要求：

- 每次提交的结果文件名不得重名。
- 结果文件必须为 JSON 格式。
- 结果文件必须符合字段标准。
- 任意类型证据链数据的必填项必须填充完整。
- 证据链必填要求以附件《附件三：二次研判证据链必填要求》为准。

## 10. 研判结果文件要求

结果文件名：

```text
assessment_results_{任务ID}_{时间戳}.json
```

结果文件用于表达供应商对该任务的二次研判结论。

关键字段要求：

| 字段 | 要求 |
| --- | --- |
| `id` | 必须与任务 ID 一致 |
| `ops` | 研判操作标识，非误报填 `+`，误报填 `-` |
| `ioc_host` | IOC 主体，例如域名或 IP |
| `ioc_type` | IOC 类型，例如 `domain`、`ip` |
| `malicious_stamp` | 恶意标记 |
| `status` | 情报状态 |
| `base` | 情报来源类型 |
| `generation_method` | 生成方式 |
| `tpd` | 是否 TPD |
| `category_v8` | V8 分类 |
| `category_v9` | V9 分类 |
| `category_new` | 新分类 |
| `confidence` | 置信度 |
| `control_type` | 管控类型 |
| `evidence` | 证据链对象 |
| `modified_time` | 修改时间 |

研判结果还可能包含如下补充字段：

- `ioc_port`
- `ioc_uri`
- `protocol`
- `first_seen`
- `last_seen`
- `created_time`
- `campaign`
- `malicious_family`
- `platform`
- `tags`
- `ttps`
- `scene`
- `whois`
- `icp`
- `dns`
- `open_port`
- `geo`
- `dynamic_domain`
- `certificate`
- `file_hash`

## 11. 证据链要求

供应商必须根据研判结论补充证据链。证据链字段位于 `evidence` 对象中，典型结构如下：

```json
{
  "evidence": {
    "sample_behavior": {},
    "source_links": "",
    "related_vulnerabilities": "",
    "traffic_fragments": {},
    "phishing_details": null,
    "other_evidence": ""
  }
}
```

常见证据类型：

| 字段 | 说明 |
| --- | --- |
| `sample_behavior` | 样本行为证据 |
| `source_links` | 情报来源链接 |
| `related_vulnerabilities` | 关联漏洞 |
| `traffic_fragments` | 流量片段和检测特征 |
| `phishing_details` | 钓鱼相关证据 |
| `other_evidence` | 其他补充证据 |

`sample_behavior` 可包含：

- `hash_md5`
- `hash_sha256`
- `file_name`
- `file_size`
- `file_type`
- `platform`
- `processes_tree`
- `tcp_connections`
- `http_requests`
- `behavior_description`
- `persistence_mechanism`
- `files_written`

`traffic_fragments` 可包含：

- `traffic_type`
- `traffic_pattern`
- `description`

## 12. 非误报结果示例

非误报时，`ops` 应为 `+`。

```json
{
  "id": "任务id",
  "ops": "+",
  "ioc_host": "evil-malware.com",
  "ioc_port": 0,
  "ioc_uri": null,
  "protocol": null,
  "ioc_type": "domain",
  "malicious_stamp": "black",
  "status": "active",
  "base": "authority",
  "generation_method": "analyst",
  "tpd": true,
  "category_v8": 100,
  "category_v9": 10300,
  "category_new": 100005,
  "first_seen": "2025-12-01T00:00:00Z",
  "confidence": 3,
  "control_type": "c2",
  "file_hash": ["5d41402abc4b2a76b9719d911017c592"],
  "last_seen": "2026-03-26T23:59:59Z",
  "created_time": null,
  "modified_time": "2026-03-27T08:30:15.123Z",
  "campaign": "银狐",
  "malicious_family": ["银狐"],
  "platform": ["windows"],
  "tags": ["C2", "Mirai"],
  "ttps": ["T1059.001"],
  "evidence": {
    "sample_behavior": {
      "hash_md5": "5d41402abc4b2a76b9719d911017c592",
      "hash_sha256": "9f86d081884c7d659ea2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a8",
      "file_name": ["malware.exe"],
      "file_size": 1048576,
      "file_type": "PE32 executable (GUI) Intel 80386, for MS Windows",
      "platform": ["windows"],
      "behavior_description": "银狐木马样本：高频心跳包，User-Agent混淆，非常规端口HTTPS隧道"
    },
    "source_links": "https://threatintel.com/report/123",
    "related_vulnerabilities": "CVE-2026-1234",
    "traffic_fragments": {
      "traffic_type": "tls",
      "traffic_pattern": "tls.sni: evil-malware.com",
      "description": "TLS SNI特征，用于检测C2加密流量"
    },
    "phishing_details": null,
    "other_evidence": "{\"ip\":\"45.33.22.11\"}"
  },
  "scene": 200001,
  "whois": {
    "domain_names": ["evil-malware.com", "evil-malware.net"],
    "registrar": "GoDaddy.com, LLC",
    "nameservers": ["ns1.cloudflare.com", "ns2.cloudflare.com"],
    "sources": ["virustotal"]
  },
  "dns": ["45.33.22.11", "45.33.22.12"],
  "geo": ["美国", "加利福尼亚", "洛杉矶"],
  "dynamic_domain": false
}
```

## 13. 误报结果示例

误报时，`ops` 应为 `-`。

```json
{
  "id": "任务id",
  "ops": "-",
  "ioc_host": "185.130.5.253",
  "ioc_port": 4444,
  "ioc_uri": null,
  "protocol": null,
  "ioc_type": "ip",
  "malicious_stamp": "black",
  "status": "active",
  "base": "public",
  "generation_method": "machine",
  "tpd": false,
  "category_v8": 200,
  "category_v9": 10500,
  "category_new": 200010,
  "first_seen": "2026-02-10T12:00:00Z",
  "confidence": 2,
  "control_type": "download",
  "file_hash": ["e99a18c428cb38d5f260853678922e03"],
  "last_seen": "2026-03-26T23:59:59Z",
  "created_time": "2026-02-10T12:00:00Z",
  "modified_time": "2026-03-27T10:15:22.456Z",
  "campaign": null,
  "malicious_family": ["Dridex"],
  "platform": ["windows"],
  "tags": ["Downloader", "MalwareDistribution"],
  "ttps": ["T1105"],
  "evidence": {
    "sample_behavior": null,
    "source_links": "https://openioc.org/feed/2026/03/dridex-ip",
    "related_vulnerabilities": null,
    "traffic_fragments": {
      "traffic_type": "http",
      "traffic_pattern": "GET /update.exe HTTP/1.1\\r\\nHost: 185.130.5.253\\r\\nUser-Agent: Mozilla/5.0",
      "description": "恶意程序下载请求特征"
    },
    "phishing_details": null,
    "other_evidence": "{\"asn\":\"AS12345\",\"org\":\"Some Hosting Ltd\"}"
  },
  "scene": 300001,
  "whois": null,
  "icp": null,
  "dns": null,
  "open_port": [80, 443, 4444],
  "geo": ["俄罗斯", "莫斯科"],
  "dynamic_domain": false,
  "certificate": null
}
```

## 14. 被拒绝结果处理

当网防云侧审核不通过时，会将结果文件复制到只读桶：

```text
/日期/rejection_result/assessment_results_{任务ID}_{时间戳}.json
```

拒绝文件会在原结果基础上增加拒绝原因对象，包含：

| 字段 | 说明 |
| --- | --- |
| `id` | 任务 ID |
| `issue_field` | 不合格字段列表 |
| `detailed_reason` | 每个字段对应的具体拒绝原因 |

示例：

```json
{
  "id": "任务id",
  "issue_field": ["ops", "ioc_host"],
  "detailed_reason": ["ops字段为空", "ioc_host字段为空"]
}
```

供应商应根据拒绝原因修正结果，并重新写入只写桶对应任务目录。

## 15. 验收要求

供应商侧实现应满足以下要求：

- 能持续发现只读桶中新下发的任务目录。
- 能下载 `secon_analysis_{任务ID}.json`。
- 能下载对应 `alert_message/` 下的告警聚合文件。
- 能在规定时间内生成 `assessment_results_{任务ID}_{时间戳}.json`。
- 能区分非误报和误报，并正确填写 `ops`。
- 能按字段标准生成合法 JSON。
- 能按证据链必填要求补充必填信息。
- 能将结果上传到只写桶 `/日期/{任务ID}/` 路径下。
- 能识别只读桶 `rejection_result/` 中的拒绝结果。
- 能根据拒绝原因整改并重新提交。
- 每次提交文件名不得重复。

## 16. 质量考核

供应商二次研判服务评估主要覆盖两个维度：

- 时效：是否在规定小时内完成合格结果回传。
- 质量：字段、结论、证据链是否满足标准。

考核结果将严格对照《情报排名规则_专题库建设补充》进行评分，并以月度报告形式通过邮件通知。

## 17. 依赖附件

完整字段口径和证据链必填规则依赖以下附件：

- 《附件一：受控外联情报字段标准-二次研判包》
- 《附件二：受控外联情报字段标准-子字段标准》
- 《附件三：二次研判证据链必填要求》

