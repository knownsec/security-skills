---
name: seebug-search-api
description: >
  Seebug 公开匿名漏洞搜索 API（https://www.seebug.org/api/search）的完整调用契约：
  参数宽容化语义、DRF 分页信封、编号直查/全文双查询路径、缓存与限流行为、
  13 个返回字段口径、行为怪癖、错误响应对照与集成建议。
  当用户要求调用、调试、联测、集成 Seebug 漏洞搜索接口、按 SSV/CVE/CNVD/CNNVD
  编号查询漏洞，或讨论该接口的分页/过滤/限流/缓存行为时使用。
---

# Seebug 公开搜索 API（/api/search）调用契约

一句话：`GET https://www.seebug.org/api/search` 是 Seebug 站点的公开匿名漏洞检索端点，
无需注册与 Token；查询口径与网页 `/search` 一致；限流仅计未命中。
本 skill 是调用方的唯一权威速查。

## 1. 定位与触发场景

**适用**：
- 编写调用该接口的集成代码、测试、脚本（curl/Python/Go）。
- 排查搜索结果"不符合预期"（编号查不到、过滤不生效、翻页 404、429 限流）。
- 评估接口公开口径：确认某信息是否会出现在搜索返回面（见 §5）。

**不适用**：
- Token 鉴权的漏洞明细/PoC 正文 API（`/api/get_vul_detail_by_id`、`/api/get_poc_detail_by_vul_id`）。
- 网页 `/search` 的 UI 行为（高亮、热词榜、空查询推荐位——仅网页有）。

## 2. 端点总览

| 项 | 值 |
| --- | --- |
| 方法与地址 | `GET https://www.seebug.org/api/search` |
| 认证 | 匿名，无需 Token |
| CORS | 开放（`Access-Control-Allow-Origin: *`），可浏览器直调 |
| 每页条数 | 固定 20，不可配 |
| 限流 | 30 次/分/IP 独立窗口，**仅缓存未命中计数**；超限 429 |
| 缓存 | 服务端结果页缓存，命中直接返回、不消耗限流额度 |
| 排序 | `submit_time` 降序，固定不可改 |
| 数据可见面 | 仅公开漏洞（编号直查例外，见 §6） |

## 3. 请求参数

| 参数 | 类型 | 必填 | 宽容化语义 |
| --- | --- | --- | --- |
| `keywords` | string | 是 | trim 后空 → 400；命中编号正则走直查（见 §6） |
| `page` | int | 否 | 缺失/非整数 → 回落第 1 页；整数 `<1` 或 `>总页数` → 404 |
| `has_poc` | bool | 否 | 仅 `on`/`true`/`1` 为真，其余一律 false |
| `has_detail` | bool | 否 | 接受值同上；**实际按 `has_poc` 过滤**（怪癖，见 §8） |
| `category` | string | 否 | 按分类名精确匹配；`all`（不分大小写）等价忽略 |
| `level` | string | 否 | 仅 `low`/`middle`/`high`；其余值静默忽略过滤 |
| `start_date` | date | 否 | `YYYY-MM-DD` / `YYYY-MM-DD HH:MM:SS` / RFC3339；非法值静默忽略 |
| `end_date` | date | 否 | 同上；闭区间 `<=`（`start_date` 为 `>=`） |

调用示例：

```bash
# 编号直查（无公开状态过滤，见 §6）
curl 'https://www.seebug.org/api/search?keywords=CVE-2020-24660'  # → SSV-98384
curl 'https://www.seebug.org/api/search?keywords=SSV-91395'

# 全文路径 + 过滤组合
curl 'https://www.seebug.org/api/search?keywords=redis&has_poc=1&level=high&page=2'
curl 'https://www.seebug.org/api/search?keywords=openssl&category=组件&start_date=2020-01-01&end_date=2024-12-31'

# 错误用法（验证 400/404）
curl -i 'https://www.seebug.org/api/search?keywords='          # 400
curl -i 'https://www.seebug.org/api/search?keywords=x&page=0'  # 404 Invalid page.
```

## 4. 响应契约

### 4.1 信封（DRF 遗留分页）

```json
{"count": 128,
 "next": "https://www.seebug.org/api/search?keywords=redis&page=2",
 "previous": null,
 "results": [ ... ]}
```

- `next`/`previous`：完整 URL 或 `null`（首页 `previous` 为 null，末页 `next` 为 null）。
- 翻页越界：`404 {"detail": "Invalid page."}`，不是软性空列表。

### 4.2 行字段（公开可见面，13 字段，**无正文内容**）

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `id` | int | 漏洞站内主键 |
| `ssvid` | string | `"SSV-" + id` 拼接 |
| `name` | string | 漏洞标题 |
| `summary` | string | 漏洞概要 |
| `cve_id` / `cnvd_id` / `cnnvd_id` | string | 编号，可为空串 |
| `level` | int | **原始 1-10 整数**（与入参 `level=low/middle/high` 是双语义，勿混淆） |
| `has_poc` | bool | 是否附有 PoC；仅布尔，正文不在此接口 |
| `category` | string | 分类名；无分类 → 空串 |
| `find_time` | string/null | `YYYY-MM-DD`；零值 → `null` |
| `submit_time` / `update_time` | string/null | `YYYY-MM-DDTHH:MM:SS`（无时区后缀）；零值 → `null` |

### 4.3 level 双语义对照

| 入参过滤 | 匹配的返回值 |
| --- | --- |
| `level=low` | 1-4 |
| `level=middle` | 5-7 |
| `level=high` | 8-10 |

## 5. 公开口径（返回面边界）

搜索返回的 13 字段是漏洞信息的公开子集，口径红线：

1. **漏洞详情正文、PoC 正文永不出现在本匿名接口**；需要正文走 Token 鉴权 API
   （`/api/get_vul_detail_by_id`、`/api/get_poc_detail_by_vul_id`）。
2. **待审核/未公开漏洞**不出现在全文路径；但可能被编号直查命中（§6 怪癖）。
   排查"提交后搜不到"属预期行为。
3. 不在返回面的信息：漏洞别名、0day 标记、参考链接、dork、解决方案、
   影响版本、发现者、组件列表等——本接口一律不返回。

## 6. 查询双路径（口径核心）

判定顺序：`keywords` 大写化后按序匹配编号正则；命中 → **编号直查**；
未命中 → 全文检索。

### 6.1 编号直查（正则严格）

| 正则 | 直查目标 | 备注 |
| --- | --- | --- |
| `^CVE-\d{4}-\d{4}$` | CVE 编号精确匹配 | 严格 4+4 位；`CVE-2020-123456` **不命中**，落回全文路径 |
| `^CNVD-\d{4}-\d{5}$` | CNVD 编号 | 5 位流水 |
| `^CNNVD-\d{6}-\d{3}$` | CNNVD 编号 | 6+3 位 |
| `^SSV-\d*$` | SSV 编号（按站内 id） | 允许空后缀：`SSV-` → 空结果集（不报错） |

直查怪癖：**不经过"仅公开漏洞"过滤**，待审核漏洞同样可能被编号命中。
这是口径设计，不是缺陷。

### 6.2 全文路径

- 匹配范围：漏洞标题与概要。
- 叠加过滤：`has_poc` / `category` / `level` / 时间区间；强制仅公开漏洞。
- 排序固定 `submit_time` 降序；`count` 与结果行同一口径。
- 全文引擎不可用时自动降级为子串匹配，对调用方透明，行为差异仅在
  分词粒度（整词匹配 vs 子串包含）。

## 7. 缓存与限流（调用方视角）

调用方可依赖的行为契约：

- **缓存命中不消耗限流额度**：限流仅计未命中（30 次/分/IP 独立窗口）。
- **空结果集同样缓存**：同参数重复探测不撞限流，也拿不到新数据。
- **缓存失效**：数据变更即失效，另有分钟级 TTL 兜底。
- 客户端无需自己做参数归一化，服务端已处理。

## 8. 行为怪癖与注意事项

| 怪癖 | 行为 |
| --- | --- |
| `has_detail` 名不副实 | 该过滤实际按 `has_poc` 生效，二者结果相同 |
| 编号直查无公开状态过滤 | 未公开漏洞可能被编号命中（§6.1） |
| 严格编号正则 | 年份/流水位数固定，多一位即落回全文路径 |
| 全文仅公开面 | 全文路径只返回公开漏洞（编号直查例外） |
| 不写热词 | API 搜索不影响网页热词榜（防爬虫污染） |
| 无高亮无推荐 | API 无高亮片段、无空查询推荐位（仅网页有） |

## 9. 错误响应对照

| 场景 | 状态码 | 响应体 |
| --- | --- | --- |
| `keywords` trim 后为空 | 400 | `{"detail": "missing keywords parameter"}` |
| `page` 为 `<1` 整数 | 404 | `{"detail": "Invalid page."}` |
| `page` 超过总页数 | 404 | `{"detail": "Invalid page."}` |
| 限流超限 | 429 | `{"detail": "Request was throttled."}` |
| 非法日期/category/level | 200 | 对应过滤被静默忽略，正常返回 |

注意：本接口错误体是 DRF 风格 `{"detail": ...}`，**不是**站内其他公开 API 的
`{"code": 0, ...}` 通用信封，解析时勿混用。

## 10. 集成建议

1. 翻页以 `next == null` 为终止条件，不要预设总页数。
2. 收到 429 按分钟级窗口退避重试；同参数重试大概率命中缓存，不再消耗限流额度。
3. 编号查询使用规范大写、位数正确的格式，确保命中直查路径；位数不齐可截断为
   规范格式或改用关键词检索。
4. 日期过滤统一用 `YYYY-MM-DD`。
5. 客户端缓存键按（规范化 keywords + 过滤参数 + page）设计，TTL 取分钟级以上。
6. `level` 返回值是 1-10 原始整数，展示端映射参考 §4.3；入参与返回值是两套语义。

## 11. 关联入口

- 网页搜索：`https://www.seebug.org/search`（同口径，另有高亮与热词榜）。
- Token 鉴权正文 API：`/api/get_vul_detail_by_id`、`/api/get_poc_detail_by_vul_id`。
- 匿名统计/分类族：`/api/get_vul_statistics`、`/api/get_vul_categories` 等。
