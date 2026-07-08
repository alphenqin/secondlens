# 供应商受控外联情报二次研判需求文档

## 1. 文档说明

本文档根据 `doc/供应商受控外联情报二次研判标准/供应商受控外联情报二次研判标准.docx` 整理，用于指导供应商侧实现受控外联情报二次研判任务的接收、处理、结果回传与整改重提。

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

结果文件用于表达供应商对该任务的二次研判结论。文件必须是合法 JSON，必须包含任务 ID、研判结论、IOC 标识、分类、置信度、时效字段和证据链字段。

核心判定规则：

- `id` 必须与只读桶任务文件中的任务 ID 一致。
- `ops` 表示供应商研判结论：`+` 表示非误报，`-` 表示误报。
- `ioc_host`、`ioc_port`、`ioc_uri`、`protocol`、`ioc_type` 共同描述 IOC。其中无端口时 `ioc_port` 填 `0`；`ioc_type=url` 时 `ioc_uri` 和 `protocol` 必填。
- `malicious_stamp`、`status`、`base`、`generation_method`、`category_v8`、`category_v9`、`category_new` 必须使用附件定义的枚举值。
- `first_seen`、`last_seen`、`created_time`、`modified_time` 使用 UTC ISO 8601 时间格式；与 `first_seen` 或 `last_seen` 相同的创建/修改时间可置空。
- `confidence` 和 `risk_level` 使用 `3` 高、`2` 中、`1` 低。
- `evidence` 是审核重点，至少需要满足一种证据链必填组合，具体见第 11 节。

### 10.1 研判结果字段标准

#### 10.1.1 常规增量包

| 序号 | 分类 |   | 情报标签 | 字段说明 | 类型 | 是否必填 | 枚举值/参考详情 | 样例（非同一条数据） |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 二次研判 |   | id | 任务id | String | 必填 | 纯数字 | 暂无 |
| 2 | 操作标识 |   | ops | 增删改情况 | String | 必填 | "+"（非误报）\|"-"（误报） | "+" |
| 3 | 情报要素 |   | ioc_host | IOC的主机名或IP地址 | String | 必填 | 构成情报唯一标识符的核心部分 | "aqzmtyx.ru" |
|   |   |   | ioc_port | IOC的端口号 | Int | 必填 | 构成情报唯一标识符的一部分；若无端口则填0 | 443 |
|   |   |   | ioc_uri | IOC的URI路径 | String | 必填 | 构成情报唯一标识符的一部分；当ioc_type为url时必填 | "/abc" |
|   |   |   | protocol | 协议类型 | String | 必填 | 当ioc_type为url时必填 | "https" |
|   |   |   | ioc_type | 情报类型 | String | 必填 | 枚举值：ip（含ip:port）、domain（含domain:port）、url | "domain" |
|   |   |   | malicious_stamp | 情报状态 | String | 必填 | 枚举值：black、white、gray、suspicious | "black" |
|   |   |   | status | 存活状态 | String | 必填 | 当malicious_stamp为black时必填<br>数据标准定义详情见sheet“存活状态”<br>枚举值：active、inactive、sinkhole、unknown | "active" |
|   |   |   | base | 情报来源 | String | 必填 | 数据标准定义详情见sheet“情报来源”<br>枚举值：public（开源情报）、authority（权威厂商）、device（自有设备）、honeypot（蜜罐捕获）、sample（样本分析）、partner（合作共享） | "public" |
|   |   |   | generation_method | 情报生成方式 | String | 必填 | 数据标准定义详情见sheet“情报生成方式”<br>枚举值：direct（直接获取）、machine（机器生成）、analyst（人工研判）、pivot（关联扩线） | "analyst" |
|   |   |   | tpd | 是否全子域名匹配 | Boolean | 必填 | 当ioc_type为ip可置空<br>枚举值：True（子域名匹配）、False（精确匹配） | True |
|   |   |   | category_v8 | v8版本威胁分类 | Int | 必填 | 数据标准定义详情见sheet“category_v8”，其中枚举值需取自“编码”列 | 100 |
|   |   |   | category_v9 | V9版本威胁分类 | Int | 必填 | 数据标准定义详情见sheet“category_v9”，其中枚举值需取自“编码”列 | 10300 |
|   |   |   | category_new | 新版本威胁分类 | Int | 必填 | 数据标准定义详情见sheet“category_new”，其中枚举值需取自“编码”列 | 100005 |
|   |   |   | first_seen | 首次发现时间 | OffsetDateTime | 必填 | UTC时间，ISO 8601标准 | 2025-08-22T01:43:08.835Z |
|   |   |   | confidence | 置信度 | Int | 必填 | 枚举值：3（高）、2（中）、1（低） | 3 |
|   |   |   | risk_level | 排查优先级 | Int | 必填 | 枚举值：3（高）、2（中）、1（低） | 3 |
|   |   |   | control_type | 远控类型 | String |   | 枚举值：general（综合类型）、c2（c2通道）、data（数据窃取）、download（恶意程序下载） | "general" |
|   |   |   | file_hash | 关联恶意样本 | List[String] |   | 哈希值，小写 | ["3ca2e067f96df491f8301eccdfcff3a8", "fe2568619adaf7c906fa459a830f771c"] |
|   |   |   | last_seen | 最近发现时间 | OffsetDateTime |   | UTC时间，ISO 8601标准 | 2025-08-22T01:43:08.835Z |
|   |   |   | created_time | 该条情报在供应商库内的创建时间 | OffsetDateTime |   | UTC时间，ISO 8601标准；若与first_seen相同，可置空 | 2025-08-22T01:43:08.835Z |
|   |   |   | modified_time | 该条情报在供应商库内的修改时间 | OffsetDateTime |   | UTC时间，ISO 8601标准；若与last_seen相同，可置空 | 2025-08-22T01:43:08.835Z |
| 4 | 组织信息 |   | campaign | 攻击组织名称 | String |   | 关联到的攻击团伙，有则提供，没有关联的就不提供，但必须是能够关联到的攻击团伙/个人信息 | "摩诃草" |
| 5 | 威胁信息 |   | malicious_family | 恶意代码家族 | List[String] |   |   | ["Generic"] |
|   |   |   | platform | 影响平台 | List[String] |   | 枚举值：generic、windows、macOS、linux、android、ios、iot | ["windows"] |
|   |   |   | tags | 标签 | List[String] |   | 自定义 | ["Sinkhole"] |
|   |   |   | ttps | 技战术编号 | List[String] |   | 参考网站 https://attack.mitre.org/ | ["T1059.001"] |
| 6 | 证据链 | evidence | sample_behavior | 关联样本行为信息 | Map<String, Object> | 必填，至少选一个字段填写 | 当base为sample（样本分析）时必填<br>数据标准定义详情见sheet“关联样本行为信息” | {<br>  "hash_md5": "5d41402abc4b2a76b9719d911017c592",<br>  "hash_sha256": "9f86d081884c7d659ea2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a8",<br>  "file_name": ["a.exe"],<br>  "file_size": 1048576,<br>  "file_type": "PE32 executable (GUI) Intel 80386, for MS Windows",<br>  "platform": ["windows"],<br>  "processes_tree": "2396 - %CONHOST% \"-1411401420-365983208102190015515091439521954106109525264775-648316390-507561376\"\n2200 - %CONHOST% \"1461072400-2006535710-37283794-18918241111842884643820657457-693123434653510855\"\n3040 - %CONHOST% \"-1378535480-393077050-167384529714127882571193999822-1649521772-6375838871702255558\"\n2532 - %TEMP%\\1F4EJKUSJ6Y0MMVA.exe",<br>  "tcp_connections": "192.168.1.100:4444, 10.0.0.5:8080",<br>  "http_requests": "POST\nhttp://evil.com/gate.php?id=123",<br>  "behavior_description": "命中银狐流量特征: 高频心跳包, User-Agent混淆, 非常规端口HTTPS隧道",<br>  "persistence_mechanism": "添加注册表Run启动项：HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Malware",<br>  "files_written": "C:\\Program Files\\Your Product\\xcd\\xfa\\xc9\\xcc.exe\nC:\\Users\\<USER>\\AppData\\Local\\Local\\ziliao.jpg\nC:\\Users\\<USER>\\AppData\\Local\\Temp\\Your Product Setup Log.txt"<br>} |
|   |   |   | source_links | 参考链接 | String |   | 当base为public（开源情报）、authority（权威厂商）时必填<br>情报来源链接 | "http://a.com/a/a" |
|   |   |   | related_vulnerabilities | 相关漏洞/payload | List[String] |   | 该IOC相关漏洞，利用什么漏洞或方式植入样本 | ["CVE-2006-1114"] |
|   |   |   | traffic_fragments | 流量片段 | Map<String, Object> |   | 数据标准定义详情见sheet“流量片段” | {<br>  "traffic_type": "http",<br>  "traffic_pattern": "GET /malware.exe HTTP/1.1\r\nHost: evil.com\r\nUser-Agent: Mozilla/4.0",<br>  "description": "恶意软件下载请求特征，包含URI和Host头"<br>} 或<br>{<br>  "traffic_type": "dns",<br>  "traffic_pattern": "dns.qry.name: evil.com",<br>  "description": "DNS查询特征，用于检测C2域名解析"<br>} 或<br>{<br>  "traffic_type": "tls",<br>  "traffic_pattern": "tls.sni: evil.com",<br>  "description": "TLS SNI特征，识别加密流量中的C2"<br>} 或<br>{<br>  "traffic_type": "hex",<br>  "traffic_pattern": "ffd8ffe000104a4649460001",<br>  "description": "JPEG文件头，用于识别图片文件传输"<br>} |
|   |   |   | phishing_details | 社工钓鱼信息 | Map<String, Object> |   | 当category_new为社工钓鱼 - 木马投递类、社工钓鱼 - 凭据窃取类时必填<br>数据标准定义详情见sheet“社工钓鱼信息” | {<br>  "brand": ["腾讯"],<br>  "target_system": ["企业邮箱"],<br>  "website_title": ["登录 - 腾讯企业邮箱"],<br>  "backend_url": ["https://phish.com/capture"],<br>  "download_link": null,<br>  "download_name": null,<br>  "behavior_description": "仿冒WPS官网，通过SEO投毒诱导用户下载捆绑木马的安装包"<br>} |
|   |   |   | other_evidence | 其他证据信息 | String |   | 用于存放无法归类到其他证据字段的补充信息，若为文本内容请控制长度在2048 字符内 | "{\"ip\": \"8.8.8.8\", \"ports\": [{\"port\": 80, \"service\": \"http\", \"banner\": \"Apache/2.4.41\"}, {\"port\": 443, \"service\": \"https\", \"banner\": \"Apache/2.4.41\"}], \"geo\": {\"country\": \"US\", \"city\": \"Mountain View\"}, \"asn\": \"AS15169\", \"hostnames\": [\"dns.google\"]}" |
|   |   |   | manual_analysis | 人工研判 | Int |   | 1<br>填写该字段表示情报需要人工研判，只需要填写数字1即可 | 1 |
| 7 | 测绘信息 |   | scene | IP资产属性 | Int |   | 数据标准定义详情见sheet“IP资产属性”，其中枚举值需取自“编码”列 | 200001 |
|   |   |   | whois | 注册信息 | Map<String, Object> |   | 数据标准定义详情见sheet“whois” | {<br>  "domain_names": ["secure-payment-portal.com", "secure-payment-portal.net"],<br>  "registrar": "GoDaddy.com, LLC",<br>  "status": ["clientTransferProhibited", "serverDeleteProhibited"],<br>  "nameservers": ["ns1.cloudflare.com", "ns2.cloudflare.com"],<br>  "created_date": "2024-01-15T08:30:22Z",<br>  "expires_date": "2027-01-15T08:30:22Z",<br>  "sources": ["virustotal", "netlab"]<br>} |
|   |   |   | icp | 备案信息 | String |   |   | "京ICP证030173号" |
|   |   |   | dns | 域名解析信息 | List[String] |   |   | ["1.1.1.1","2.2.2.2"] |
|   |   |   | open_port | 开放端口 | Array[Int] |   |   | [8080,9090] |
|   |   |   | geo | 地理位置 | List[String]/String |   | ["国家", "省份", "城市"]或"中国北京北京" | ["中国", "北京", "北京"] |
|   |   |   | dynamic_domain | 动态域名 | Boolean |   | 枚举值：True、False | False |
|   |   |   | certificate | 数字证书 | String |   | PEM格式 | "-----BEGIN CERTIFICATE-----\nMIIDdzCCAl+gAwIBAgIEAgAAuTANBgkqhkiG9w0BAQUFADBaMQswCQYDVQQGEwJJ\nEESMBAGA1UEChMJQmFsdGltb3JlMRMwEQYDVQQLEwpDeWJlclRydXN0MSIwIAYD\n......\nTRUstIEYL8w6L9254i+lH7sOqP+e8=\n-----END CERTIFICATE-----" |

字段口径待确认：

- `base` 字段在附件一中出现 `authority`，附件二“情报来源”枚举中对应外部权威厂商的枚举值为 `vendor`。实现前需要与网防云侧确认最终接收值。

## 11. 证据链必填要求

### 11.1 二次研判以及专题库情报质量评价基线

| 分类 | 字段名名称 | 情报标签 | 字段说明 | 类型 | 是否必填 | 字段名 | 数据类型 | 填写规范与示例 | 置信度必填 | 业务含义 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 证据链 | evidence | sample_behavior | 关联样本行为信息 | Map<String, Object> | 多选一必填 | hash_md5 | String | "e99a18c428cb38d5f260853678922e03" | 必填，至少选一个字段填写 | 文件特征值，小写 |
|   |   |   |   |   |   | hash_sha256 | String | "9f86d081884c7d659ea2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a8" |   | 文件特征值，小写 |
|   |   |   |   |   |   | file_name | List[String] | ["a.exe"] | 10选5必填 | 文件名称 |
|   |   |   |   |   |   | file_size | Int | 1048576 |   | 文件大小（单位Bytes） |
|   |   |   |   |   |   | file_type | String | "PE32 executable (GUI) Intel 80386, for MS Windows" |   | 文件类型 |
|   |   |   |   |   |   | platform | List[String] | ["windows"] |   | 影响操作系统<br>枚举值：generic、windows、macOS、linux、android、ios、iot |
|   |   |   |   |   |   | persistence_mechanism | String | "添加注册表Run启动项：HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Malware" |   | 样本实现持久化的具体手段描述 |
|   |   |   |   |   |   | files_written | String | "C:\\Program Files\\Your Product\\xcd\\xfa\\xc9\\xcc.exe\nC:\\Users\\<USER>\\AppData\\Local\\Local\\ziliao.jpg\nC:\\Users\\<USER>\\AppData\\Local\\Temp\\Your Product Setup Log.txt" |   | 释放文件，当样本被执行时写入文件的绝对路径 |
|   |   |   |   |   |   | processes_tree | String | "2396 - C:\\Windows\\System32\\conhost.exe\n2200 - C:\\Windows\\System32\\conhost.exe\n3040 - C:\\Windows\\System32\\conhost.exe\n2532 - %TEMP%\\1F4EJKUSJ6Y0MMVA.exe" |   | 相关进程ID及文件名称（限制PID或文件名称的数量不超过100个） |
|   |   |   |   |   |   | tcp_connections | String | "192.168.1.100:4444" |   | TCP连接记录（限制10个地址信息内） |
|   |   |   |   |   |   | http_requests | String | "POST http://evil.com/gate.php?id=123" |   | Http访问记录（只要请求行） |
|   |   |   |   |   |   | behavior_description | String | "命中银狐流量特征: 高频心跳包, User-Agent混淆, 非常规端口HTTPS隧道" |   | 行为描述或流量特征描述（限制1000字符内） |
|   |   | traffic_fragments | 流量片段 | Map<String, Object> |   | traffic_type | String | "http" | 必填 | 标识流量特征的协议类型或编码方式，用于指导如何解析"traffic_pattern"字段<br>推荐枚举值：http、dns、tls、smtp、ftp、irc、hex。 |
|   |   |   |   |   |   | traffic_pattern | String | "GET /malware.exe HTTP/1.1" 或<br>"dns.qry.name: evil.com" 或<br>"tls.sni: evil.com" 或<br>"ffd8ffe000104a4649460001" | 必填 | 用于流量匹配的文本特征描述。应包含可被网络监控设备（如IDS/IPS、NTA）识别的协议字段、负载关键字、请求头信息等。如 HTTP 请求行、域名、特定负载关键字等。若为二进制特征，请用十六进制字符串表示。长度小于1024字符 |
|   |   |   |   |   |   | description | String | "C2通信心跳包特征" | 必填 | 对该流量特征的简要说明，帮助理解其用途或背景。限制1000字符内 |
|   |   | phishing_details | 社工钓鱼信息 | Map<String, Object> |   | brand | List[String] | ["腾讯","顺丰速运","Microsoft"] | 必填，至少选一个字段填写 | 被仿冒的品牌或机构名称 |
|   |   |   |   |   |   | target_system | List[String] | ["企业邮箱"、"快递单查询"、"Office 365 登录页"] |   | 被仿冒的具体系统、页面或服务名称 |
|   |   |   |   |   |   | website_title | List[String] | ["登录 - 腾讯企业邮箱"] | 必填 | 仿冒页面的网站标题 |
|   |   |   |   |   |   | backend_url | List[String] | ["https://fake.com/login/submit"] | / | 钓鱼网站接收数据的后端地址 |
|   |   |   |   |   |   | download_link | List[String] | ["https://fake.com/update.exe"] | / | 诱饵文件或恶意程序的下载链接 |
|   |   |   |   |   |   | download_name | List[String] | ["发票详情.exe"] | / | 下载链接对应的文件名或显示名称 |
|   |   |   |   |   |   | behavior_description | String | "仿冒WPS官网，通过SEO投毒诱导用户下载捆绑木马的安装包" | 必填 | 行为描述 |
|   |   | source_links | 参考链接 | String |   | source_links | String | "http://a.com/a/a" | 必填 | 参考链接 |
|   |   | other_evidence | 其他证据信息 | Map<String, Object> |   | parent_intelligence | List[String] | ["evil.com", "1.2.3.4"] | 必填 | 被扩线的父情报 |
|   |   |   |   |   |   | parent_evidence | String | "{\"brand\": \"腾讯\", \"behavior_description": \"仿冒WPS官网，通过SEO投毒诱导用户下载捆绑木马的安装包\"}" | 必填 | 父情报的判黑依据,关联样本行为信息中的hash_md5或hash_sha256、剩余10选5；流量片段中的traffic_type、traffic_pattern、description；社工钓鱼信息中的brand、target_system、website_title（三选一），和behavior_description |
|   |   |   |   |   |   | pivoting_feature | String | "同域名注册邮箱：admin@evil.com，关联发现该邮箱注册的其他恶意域名" | 必填 | 扩线特征 |
|   |   | manual_analysis | 人工研判 | String |   | int |   | 1 | 必填 | 表示该情报需要人工研判 |

## 12. 子字段与枚举标准

### 12.1 存活状态

| 序号 | 状态 | 定义 | 判定依据 | 情报用途和建议 |
| --- | --- | --- | --- | --- |
| 1 | 存活（active） | 情报当前仍处于正常解析状态，仍被攻击者掌控并可直接用于接收指令、下发载荷、建立控制通道或回传数据。 | 1、IP/域名在网络空间测绘结果中仍响应且解析未发生变更、Whois信息未变化；<br>2、IP当前端口开放；<br>3、当前最近一次域名解析时间/样本通信时间不超过3个月。 | 属于可直接防御与阻断级情报。 |
| 2 | 失活（inactive） | 当前攻击者失去对该基础设施的控制权，无法用于下发指令或回传数据，但不排除攻击者在后续重新接管或复用该资源的可能性。<br>当前IOC没有活跃迹象 | 1、域名当前无解析；<br>2、IP当前端口不开放；<br>3、当前最近一次域名解析时间/样本通信时间超过3个月。 | 属于历史威胁，主要用于威胁溯源、日志复核。<br>失活不代表失效。 |
| 3 | 安全机构接管（sinkhole） | 被权威安全机构、研究组织或厂商接管并用于监测、分析或阻断攻击活动的网络实体。 | 1、解析指向安全机构、CERT或厂商Sinkhole节点；<br>2、数据包流量显示为监测/拦截流。 | 属于无当前攻击行为，但具情报价值的IOC，可用于攻击面统计或威胁追踪。 |
| 4 | 未知（unknown） | 因信息不足、数据源冲突或无法完成有效验证，导致其当前真实状态无法被明确归类的网络实体。该状态是一种临时性的“待定”分类。 | 1、网络探测请求超时、无响应或被目标防火墙主动拦截；<br>2、不同情报来源对该实体的状态判定结果相互矛盾；<br>3、缺乏足够的数据点（如无Whois信息、无历史解析记录）以支持进行“存活”或“失活”的判断。 | 属于低置信度情报，需要通过更多渠道或人工方式进行二次验证，以明确其最终状态。 |

### 12.2 情报来源

| 枚举值 | 中文 | 定义 |
| --- | --- | --- |
| public | 开源情报 | 来自公开可获取的信息源，如博客、社区、GitHub、公开报告、公开 IOC 库 |
| vendor | 权威厂商 | 来自外部安全厂商、研究机构、商业安全团队发布的情报<br>【权威厂商名单】<br>微步在线、腾讯安全、奇安信、绿盟科技、安恒信息、360安全、深信服、知道创宇、CrowdStrike、IBM Security、Microsoft、Palo Alto Networks、FireEye/Mandiant、Kaspersky、Anomali、Recorded Future、AlienVault、Centripetal等 |
| device | 自有设备 | 来自自有安全设备、日志、流量、DNS、代理、EDR/NDR 等观测结果 |
| honeypot | 蜜罐捕获 | 来自自有蜜罐、诱捕系统、陷阱环境捕获 |
| sample | 样本分析 | 来自自有样本的静态、动态、沙箱分析直接提取 |
| partner | 合作共享 | 来自合作伙伴、客户共享、情报联盟、订阅源 |

### 12.3 情报生成方式

| 枚举值 | 中文含义 | 说明 |
| --- | --- | --- |
| direct | 直接获取 | IOC 未经过任何加工或重组，直接从原始来源（如公开报告、博客、GitHub、第三方情报库）中原样提取，不涉及自动化规则生成或设备自动产出。例如：手动复制公开报告中的IOC列表。 |
| machine | 机器生成 | IOC 由安全设备或沙箱分析直接产出，未经人工审核或修正。例如：EDR告警自动提取的恶意IP、沙箱动态解析出的C2域名、IDS规则命中后自动生成的IOC。 |
| analyst | 人工研判 | IOC 经过分析师人工补充、归纳、确认或修正后形成，可能融合了多源数据或上下文判断。例如：分析师对机器告警进行核实后添加的标签、手动扩线的关联IOC。 |
| pivot | 关联扩线 | 基于已有IOC通过资产测绘、同证书、同指纹、同基础设施等技术手段关联扩展得到的新IOC，通常属于自动化或半自动化扩线结果。 |

### 12.4 category_v8

| 编码 | 语义 | 备注 |
| --- | --- | --- |
| 100 | apt攻击类 | 对攻击者有明确归因（通常具有国家、政府、军队等背景），被攻击者目标较为明确且潜伏周期长，在攻击过程中所使用的网络基础设施地址和回连地址 |
| 200 | 勒索软件类 | 发现的勒索软件以及其所回连的地址或者下载地址 |
| 300 | 重点木马类 | 整体上用于窃密，控制系统等具有较高危害性木马的通用分类号 |
| 301 | 远控木马类 | 带有远控功能的木马或者未能识别具体恶意家族的恶意代码的回连地址或者下载地址 |
| 302 | 窃密木马类 | 专门用于窃取敏感数据的，包括但不限于密码凭据、隐私信息、重要文件、数字资产等，并会将收集到的数据回传至攻击者服务器 |
| 400 | 挖矿软件类 | 用于挖矿牟利的恶意代码样本所回连的地址以及矿池地址 |
| 500 | 僵尸网络类 | 攻击者下发指令或者僵尸主机回连控制端的地址 |
| 600 | 社工钓鱼类 | 互联网侧伪装成受信任的人或组织，以诱骗潜在受害者共享敏感信息或向他们汇款网站地址和样本回连地址 |
| 700 | 漏洞利用类 | 漏洞利用成功后，受害主机回连、回显的攻击者服务器地址 |
| 800 | 后门软件 | 能绕过系统安全设置，潜伏在电脑中，预置一种登录系统的方法 |
| 900 | 间谍软件 | 收集用户行为，系统指标等数据，在未经用户授权情况下传输给第三方的恶意软件 |
| 1000 | 恶意代码下载 | 专门用于进行下载其他恶意代码的恶意程序所回连的地址或者下载地址 |
| 1100 | 一般性恶意代码 | 带有感染文件行为的恶意代码样本所发起的回连地址或者下载地址 |
| 1101 | 蠕虫 | 蠕虫病毒 |
| 1102 | 恶意脚本 | 恶意的脚本，如js脚本，vb脚本等 |
| 1200 | 普通木马 | 分析后未有明确的特征倾向，无法具体划分重点木马中的木马 |
| 1300 | 流氓程序 | 有劫持流量、静默安装、锁定主页等流氓行为的程序所回连的地址或者下载地址 |
| 1400 | 黑客工具 | 以常见渗透工具/软件为主，具有扫描、漏洞利用、暴力破解等功能，类似Metasploit之类的攻击框架等生成的恶意代码样本的回连地址或者下载地址 |
| 9900 | 其它类型 | 不属于以上任何类型的恶意代码 |

### 12.5 category_v9

| 编码 | 语义 |
| --- | --- |
| 10100 | 病毒 |
| 10200 | 蠕虫 |
| 10300 | 木马 |
| 10400 | 勒索软件 |
| 10500 | 黑客工具 |
| 10600 | 灰色软件 |
| 10700 | 钓鱼网站 |
| 9900 | 其它类型 |

### 12.6 category_new

| 编码 | 威胁类型 | 攻击阶段 | 定义 | IOC用途 | 客户命中解释 |
| --- | --- | --- | --- | --- | --- |
| 100000 | 扫描探测 | 攻击投递与扫描探测类 | 该IP用于开展端口、服务、漏洞扫描的攻击源地址。 | 攻击前信息收集节点。 | / |
| 100001 | 漏洞利用 - 通用漏洞 |   | 用于测试或利用公开漏洞的攻击发起IP/域名。 | 攻击指令发送端或漏洞请求源。 | / |
| 100002 | 漏洞利用 - 产品漏洞 |   | 利用特定厂商产品漏洞（如WebLogic、Exchange）的攻击节点。 | 专针对某产品发起攻击。 | / |
| 100003 | 暴力破解 |   | 发起密码尝试/认证测试的IP | 登录爆破源 | / |
| 100004 | 带外交互回显地址 |   | 带外交互是指通过隐秘信道将敏感数据偷偷发送到外部服务器的行为，此类行为包含DnsLog、interactsh、IPFS等等，可用于匿名托管规避审查、盲注回显利用、隐蔽信道、存活检测等场景 | 盲注回显、隐蔽数据外泄与存活检测的地址 | 若出现在非授权业务通信中，可能为内网数据泄露通道 |
| 100005 | 社工钓鱼 - 木马投递类 |   | 通过伪造软件下载站、广告推广页、二维码引导页或假客服沟通渠道等方式，使用户误以为是正常软件下载或技术支持，从而引导其下载带有远控木马、广告投递器或勒索软件的恶意程序。 | 新注册的域名模仿知名软件（如 winrar-cn[.]com, notepadplus.download[.]xyz） | 若终端访问或解析此类 IOC，意味着用户可能通过非官方源下载软件，存在恶意程序感染或系统被远控的风险。应及时阻断访问、检查可疑安装包与变更文件 |
| 100006 | 社工钓鱼 - 凭据窃取类 |   | 伪造或篡改知名品牌、机构、银行、邮箱或云服务登录页，以获取用户敏感凭据（账号、口令、Token、银行卡号等） | 仿冒品牌拼写（如 micros0ft-login[.]com, office-cn[.]net） | 此类 IOC 表示用户浏览器或邮件客户端正在访问仿冒域名，存在凭证泄露风险；应立刻提醒用户、更换密码，开展邮箱攻击溯源 |
| 100007 | 社工钓鱼 - 网络探针类 |   | 内嵌于钓鱼页面或被入侵正常网站中的探针URL，用于记录访客浏览器指纹、IP地址、User-Agent 等信息，从而筛选目标访客进行精准攻击或社工跟进。 | 典型模式如短链形式的追踪器、JS-指纹采集脚本、统计跳转域名。 | 若终端命中此类 IOC，表示用户访问了被监控的网页，可能被列入钓鱼目标名单。应提醒用户警惕后续社工邮件或钓鱼行为，并协同 SOC 分析是否存在针对性后续攻击趋势 |
| 100008 | 远控木马 | 远控与植入后利用类 | 远控木马部署及运行过程中所访问的服务器地址，第三方公共服务需具体到URL级。 | 木马与恶意服务器通信的核心节点 | 表示感染主机与攻击者控制端存在连接，主机已被入侵 |
| 100009 | 勒索软件 |   | 勒索病毒的数据上报或密钥分发服务端地址 | 勒索控制/支付/加密指令服务器 | 若被访问，系统极可能被勒索程序入侵 |
| 100010 | 僵尸网络 |   | 僵尸主机与控制域名交互的C&C或命令节点 | Bot节点上报与命令下发控制端 | 命中代表主机可能为僵尸网络一员 |
| 100011 | 矿池 |   | 挖矿木马远控C2控制端地址或连接挖矿节点地址 | 命令下发通信渠道或计算结果上报与算力控制节点 | 命中表示终端设备被利用进行加密货币挖矿 |
| 100012 | 网络蠕虫 |   | 具有扩散与自感染能力的木马远控C2控制端地址 | 蠕虫的控制节点或者传播节点（类似下载节点） | 表示主机存在被蠕虫感染并传播的风险，可能在内网造成横向扩散，应立即隔离并处置。 |
| 100013 | 远程控制软件 | 可疑服务/灰色用途类 | 包括面向正常远程桌面/运维/协助用途的、可能被攻击者滥用的远程控制软件（商用/开源）的关键通信节点地址。 | 被入侵者利用进行控制的合法远控信道 | 若命中需判定该通信是否为企业正常运维行为 |
| 100014 | 内网穿透 / 远程接入软件 |   | 用于穿透防火墙、建立外部访问通道的地址。如：ZeroTier等软件 | 攻击者利用的隐蔽通信中继 | 若出现在非授权业务通信中，可能为内网数据泄露通道 |
| 100015 | 翻墙代理地址 |   | 被滥用的公共代理出口地址 | 数据中转或外联掩饰节点 | 若命中内部主机使用，可能存在规避防护与信息外流 |
| 100016 | 潜在有害应用程序 |   | 有广告推广、劫持流量、静默安装、锁定主页、数据收集等流氓行为的程序所回连的地址 | 检出内网存在劫持流量、静默安装、数据收集的应用程序运行时外联的地址 | 表明内网设备可能已感染流氓软件，需定位感染主机并清除恶意程序，以防止流量劫持、隐私窃取等进一步危害。 |
| 100017 | 潜在有害程序站点 |   | 托管含下载引流、恶意脚本的域名 | 潜在恶意内容分发源 | 需监控后续是否存在真实攻击传播行为 |

### 12.7 IP资产属性

| 序号 | 一级分类 | 一级分类定义 | 二级分类 | 编码 | 二级分类定义 |
| --- | --- | --- | --- | --- | --- |
| 1 | 数据中心 | 指分配给数据中心运营商、云服务提供商或主机托管商的IP地址段。 | 云计算基础设施 | 200001 | 由公有云或私有云厂商提供的，基于虚拟化技术的弹性计算资源IP。其特征是IP流转率高，常关联至特定的云厂商ASN。 |
|   |   |   | 传统IDC | 200002 | 位于物理机房内，用于托管物理服务器或机柜租赁的IP。通常用于承载不需要频繁变动的大型业务系统。 |
|   |   |   | 二级运营商 | 200003 | 该IP隶属某一IDC，但被分配给二级运营商使用，用户基数非常大 |
|   |   |   | 虚拟专用服务器 (VPS) | 200004 | 在物理服务器上通过轻量级虚拟化分割出的独立实例IP，常用于中小企业建站、个人开发或轻量级应用，成本低于独享云主机。 |
| 2 | 家庭带宽 | 指互联网服务提供商（ISP）分配给最终家庭用户的IP地址。 | 家庭带宽 | 200005 | / |
| 3 | 组织与专线 | 指分配给政府、企业、教育机构等实体组织的专用静态IP段。 | 企业专线 | 200006 | 商业公司用于办公网出口或自建机房的固定IP，通常具有反向DNS解析（rDNS）指向企业域名的特征。 |
|   |   |   | 教育科研网 | 200007 | 分配给大学、中小学及科研院所的专用IP段（如CERNET），用于学术研究和校园网接入。 |
|   |   |   | 政府机构 | 200008 | 分配给政府部门、行政机关及电子政务外网的专用IP。 |
|   |   |   | 组织机构 | 200009 | 分配给拥有自有AS号的非运营商机构使用的IP。 |
| 4 | 移动基站 | 指移动通信运营商（MNO）分配给蜂窝网络（3G/4G/5G）生态系统的IP地址。 | 移动基站 | 200010 | / |
| 5 | 网络基础设施 | 指构成互联网骨干架构的硬件设施IP,负责数据的路由、交换、分发和传输。 | 骨干路由设备 | 200011 | 核心网路由器、汇聚交换机、网关设备的接口IP，负责AS之间或AS内部的流量转发。 |
|   |   |   | 内容分发网络(CDN) | 200012 | 部署在网络边缘的缓存节点IP，用于静态资源加速。 |
|   |   |   | 网关 | 200013 | 网关是计算机网络中的一种设备或服务器，用于连接不同网络或协议之间进行数据转发和处理。 |
|   |   |   | VOIP | 200014 | 基于IP的语音传输是一种语音通话技术，经由网际协议来达成语音通话与多媒体会议，也就是经由互联网来进行通信。 |
|   |   |   | 卫星通信 | 200015 | 通过卫星（如Starlink）、微波等非传统光纤介质接入互联网的地面站或终端IP。 |
| 6 | 应用服务 | 指根据IP开放的端口、返回的Banner信息或运行的协议特征，识别出的具体应用服务层资产。 | Web应用服务 | 200016 | 运行HTTP/HTTPS协议，承载网站、API或Web管理后台的服务器IP |
|   |   |   | 数据存储服务 | 200017 |   |
|   |   |   | 邮件服务器 | 200018 | 运行邮件传输协议（SMTP/IMAP）或即时通讯服务的服务器。 |
|   |   |   | 远程管理服务 | 200019 | 开放了用于系统运维的远程控制端口（如SSH, RDP, Telnet）的资产。 |
|   |   |   | DNS服务 | 200020 | 提供DNS解析 |
| 7 | 物联网设备 | 指位于网络边缘的非服务器类设备。包括个人计算设备、办公外设以及广泛的物联网（IoT）和工业控制系统（ICS）设备。 | 视频监控系统 | 200021 | 专门用于视音频采集、编码和存储的网络设备IP。 |
|   |   |   | 工业控制 | 200022 | 用于工业生产环境的PLC、SCADA系统、DCS系统或工业网关，涉及物理世界控制。 |
|   |   |   | 其他 | 200023 | / |
| 8 | 代理与网络安全 | 指具有中间人属性（转发流量）或安全攻防属性（防御或攻击）的特殊用途IP。 | VPN与隧道 | 200024 | 提供加密隧道接入服务的网关设备或服务器，用于远程访问或隐私保护。 |
|   |   |   | 代理与匿名节点 | 200025 | 提供HTTP/SOCKS代理功能，或作为Tor等匿名网络的出口节点，用于隐藏真实IP。 |
|   |   |   | 内网穿透 | 200026 | 提供内网穿透服务的入口IP |
|   |   |   | 木马远控 | 200027 | shell和远控类 |
|   |   |   | 安全防御设施 | 200028 | 部署在网络边界的防火墙、WAF或安全网关，用于流量过滤和威胁阻断。 |
|   |   |   | 扫描器 | 200029 | 被识别为正在进行网络测绘、漏洞扫描或发起攻击的IP。 |
| 9 | 其他 | 暂时无法识别 | 保留地址 | 200030 | 国际互联网代理成员管理局(IANA)在IP地址范围内，将一部分地址保留作为备用IP地址空间或者专门用于内部局域网等特殊用途使用的IP地址 |
|   |   |   | 未分配 IP | 200031 | 该 IP 在区域性 IP 地址分配机构（如 APNIC）中，还未分配给特定的 机构 |
|   |   |   | 已分配-未路由 | 200032 | 该 IP 已经分配给特定的机构，但还没有在网络路由信息 |
|   |   |   | 已路由-未使用 | 200033 | 该 IP 已经分配给特定的机构且出现在网络路由信息中，但还没有在 网络中被使用 |
|   |   |   | 已使用 | 200034 | IP 在使用中，但是无法给出具体的应用场景 |
|   |   |   | 串口服务器 | 200035 |   |
|   |   |   | 企业办公设备 | 200036 | 用于企业办公的设备 |
|   |   |   | 视频会议 | 200037 | 各方透过网络与通信设备实时传输视频和声音频号来面对面沟通的会议方式。 |
|   |   |   | 台式机 | 200038 | 台式办公电脑 |
|   |   |   | 企业管理产品 | 200039 |   |
|   |   |   | 非web通用端口 | 200040 |   |
|   |   |   | 未知 | 200041 |   |

### 12.8 whois

| 序号 | 字段名 (Key) | 数据类型 | 填写规范与示例 | 是否必填 | 业务含义 |
| --- | --- | --- | --- | --- | --- |
| 1 | domainname | List[String] | ["example.com"] | 必填 | 核心查询域名 |
|   |   |   | 若有多个别名/变体：["a.com", "b.com"] |   |   |
| 2 | status | List[String] | ["ok", "serverDeleteProhibited"] | 必填 | 域名状态列表 |
| 3 | registrarname | List[String] | ["Spaceship, Inc."] | 必填 | 注册商名称 |
| 4 | nameservers | List[String] | ["ns1.a.com", "ns2.a.com"] | 必填 | DNS 服务器列表 |
| 5 | createddate | String | "2025-05-05 02:58:46" | 必填 | 域名注册时间，格式不限 |
| 6 | expiresdate | String | "2026-05-05 23:59:59" | 必填 | 域名过期时间，格式不限 |
| 7 | whoisserver | List[String] | ["whois.spaceship.com"] |   | 提供该条 WHOIS 信息的服务器地址 |
| 8 | source | List[String] | ["virustotal", "netlab"] |   | 数据来源标识 |
| 9 | registrant | String | "DATA REDACTED" |   | 注册者 |
| 10 | address | String | "DATA REDACTED,DATA REDACTED,CA,US" |   | 地址 |
| 11 | telephone | String | "+1.4153197517" |   | 电话 |

### 12.9 关联样本行为信息

| 序号 | 字段名 | 数据类型 | 填写规范与示例 | 必填 | 业务含义 |
| --- | --- | --- | --- | --- | --- |
| 1 | hash_md5 | String | "e99a18c428cb38d5f260853678922e03" | 必填，至少选一个字段填写 | 文件特征值，小写 |
| 2 | hash_sha256 | String | "9f86d081884c7d659ea2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a8" |   | 文件特征值，小写 |
| 3 | file_name | List[String] | ["a.exe"] |   | 文件名称 |
| 4 | file_size | Int | 1048576 |   | 文件大小（单位Bytes） |
| 5 | file_type | String | "PE32 executable (GUI) Intel 80386, for MS Windows" |   | 文件类型 |
| 6 | platform | List[String] | ["windows"] |   | 影响操作系统<br>枚举值：generic、windows、macOS、linux、android、ios、iot |
| 7 | persistence_mechanism | String | "添加注册表Run启动项：HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Malware" |   | 样本实现持久化的具体手段描述 |
| 8 | files_written | String | "C:\\Program Files\\Your Product\\xcd\\xfa\\xc9\\xcc.exe\nC:\\Users\\<USER>\\AppData\\Local\\Local\\ziliao.jpg\nC:\\Users\\<USER>\\AppData\\Local\\Temp\\Your Product Setup Log.txt" |   | 释放文件，当样本被执行时写入文件的绝对路径 |
| 9 | processes_tree | String | "2396 - C:\\Windows\\System32\\conhost.exe\n2200 - C:\\Windows\\System32\\conhost.exe\n3040 - C:\\Windows\\System32\\conhost.exe\n2532 - %TEMP%\\1F4EJKUSJ6Y0MMVA.exe" |   | 相关进程ID及文件名称（限制PID或文件名称的数量不超过100个） |
| 10 | tcp_connections | String | "192.168.1.100:4444" |   | TCP连接记录（限制10个地址信息内） |
| 11 | http_requests | String | "POST http://evil.com/gate.php?id=123" |   | Http访问记录（只要请求行） |
| 12 | behavior_description | String | "命中银狐流量特征: 高频心跳包, User-Agent混淆, 非常规端口HTTPS隧道" |   | 行为描述或流量特征描述（限制1000字符内） |

### 12.10 流量片段

| 序号 | 字段名 | 数据类型 | 填写规范与示例 | 必填 | 业务含义 |
| --- | --- | --- | --- | --- | --- |
| 1 | traffic_type | String | "http" | 必填，至少选一个字段填写 | 标识流量特征的协议类型或编码方式，用于指导如何解析"traffic_pattern"字段<br>推荐枚举值：http、dns、tls、smtp、ftp、irc、hex。 |
| 2 | traffic_pattern | String | "GET /malware.exe HTTP/1.1" 或<br>"dns.qry.name: evil.com" 或<br>"tls.sni: evil.com" 或<br>"ffd8ffe000104a4649460001" |   | 用于流量匹配的文本特征描述。应包含可被网络监控设备（如IDS/IPS、NTA）识别的协议字段、负载关键字、请求头信息等。如 HTTP 请求行、域名、特定负载关键字等。若为二进制特征，请用十六进制字符串表示。长度小于1024字符 |
| 3 | description | String | "C2通信心跳包特征" |   | 对该流量特征的简要说明，帮助理解其用途或背景。限制1000字符内 |

### 12.11 社工钓鱼信息

| 子字段名 | 说明 | 类型 | 必填 | 样例 |
| --- | --- | --- | --- | --- |
| brand | 被仿冒的品牌或机构名称 | List[String] | 必填，至少选一个字段填写 | ["腾讯","顺丰速运","Microsoft"] |
| target_system | 被仿冒的具体系统、页面或服务名称 | List[String] |   | ["企业邮箱"、"快递单查询"、"Office 365 登录页"] |
| website_title | 仿冒页面的网站标题 | List[String] |   | ["登录 - 腾讯企业邮箱"] |
| backend_url | 钓鱼网站接收数据的后端地址 | List[String] |   | ["https://fake.com/login/submit"] |
| download_link | 诱饵文件或恶意程序的下载链接 | List[String] |   | ["https://fake.com/update.exe"] |
| download_name | 下载链接对应的文件名或显示名称 | List[String] |   | ["发票详情.exe"] |
| behavior_description | 行为描述 | String |   | "仿冒WPS官网，通过SEO投毒诱导用户下载捆绑木马的安装包" |

### 12.12 其他证据信息-测绘扩线

| 子字段名 | 说明 | 类型 | 必填 | 样例 |
| --- | --- | --- | --- | --- |
| parent_intelligence | 被扩线的父情报 | List[String] | 必填 | ["evil.com", "1.2.3.4"] |
| parent_evidence | 父情报的判黑依据,关联样本行为信息中的hash_md5或hash_sha256、剩余10选5；流量片段中的traffic_type、traffic_pattern、description；社工钓鱼信息中的brand、target_system、website_title（三选一），和behavior_description | String |   | "{\"brand\": \"腾讯\", \"behavior_description": \"仿冒WPS官网，通过SEO投毒诱导用户下载捆绑木马的安装包\"}" |
| pivoting_feature | 扩线特征 | String |   | "同域名注册邮箱：admin@evil.com，关联发现该邮箱注册的其他恶意域名" |

## 13. 结果示例

### 13.1 非误报示例

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
  "risk_level": 3,
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
    "related_vulnerabilities": ["CVE-2026-1234"],
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
    "domainname": ["evil-malware.com", "evil-malware.net"],
    "registrarname": ["GoDaddy.com, LLC"],
    "status": ["clientTransferProhibited"],
    "nameservers": ["ns1.cloudflare.com", "ns2.cloudflare.com"],
    "createddate": "2025-01-15T08:30:22Z",
    "expiresdate": "2027-01-15T08:30:22Z",
    "source": ["virustotal"]
  },
  "dns": ["45.33.22.11", "45.33.22.12"],
  "geo": ["美国", "加利福尼亚", "洛杉矶"],
  "dynamic_domain": false
}
```

### 13.2 误报示例

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
  "category_new": 100010,
  "first_seen": "2026-02-10T12:00:00Z",
  "confidence": 2,
  "risk_level": 2,
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
- 能按枚举标准填写 `status`、`base`、`generation_method`、`category_v8`、`category_v9`、`category_new`、`scene` 等字段。
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

- `doc/供应商受控外联情报二次研判标准/供应商受控外联情报二次研判标准.docx`
- `doc/供应商受控外联情报二次研判标准/附件一：受控外联情报字段标准-二次研判包.xlsx`
- `doc/供应商受控外联情报二次研判标准/附件二：受控外联情报字段标准-子字段标准.xlsx`
- `doc/供应商受控外联情报二次研判标准/附件三：二次研判证据链必填要求.xlsx`
