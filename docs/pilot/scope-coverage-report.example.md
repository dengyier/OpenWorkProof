# Scope Coverage Report 示例：Rich #4196

> 示例类型：OpenWorkProof 自有协议演示，不是客户案例。
>
> Issue 来源：<https://github.com/Textualize/rich/issues/4196>
>
> 上游采用：`not evidenced`；客户采用：`not evidenced`；客户验收：
> `not evidenced`；付款：`not evidenced`。

## 买方收到的结论

**VERIFIED within the signed Evaluation Scope: every observed arm matched the
declared population, required targets were covered, and registered negative
controls were caught.**

中文解释：只在签名 Evaluation Scope 内，声明人口与各臂观察人口一致，
必选目标全部覆盖，注册负控被捕获。因此该冻结主张可判为 `VERIFIED`。

## 范围与结果摘要

| 字段 | 演示值 |
|---|---|
| Source revision | `9d8f9a372cc5916fd4781fec207ced7ddac2f08f` |
| Candidate commit | `1d19af6229b67ca73227614521df1c221ae21b5c` |
| 声明成员数 | 2（候选源文件 + 必选 NBSP 回归测试） |
| 正臂观察成员数 | 2 |
| 负臂观察成员数 | 2 |
| 必选目标 | 2 declared / 0 missing |
| 跨臂人口 | consistent |
| 正臂 | required regression passed |
| 负臂 | mutant applied and caught |
| Scope status | `satisfied` |
| Decision | `VERIFIED` |
| Settlement readiness | `READY_FOR_ACCEPTANCE`，不是付款或验收证明 |

## 为什么旧绿灯不够

`legacy_check.py` 只检查普通 ASCII 空格；candidate 与错误 mutant 都能通过。
当 Observed Scope 漏掉必选 `required-test.py` 时，v0.3 输出：

```text
scope_status: indeterminate
decision: UNKNOWN
reason_code: SCOPE_REQUIRED_TARGET_MISSING
```

补齐必选测试后，正臂通过且负控失败，才形成上面的限定 `VERIFIED`。这说明
“测试为绿”与“验证范围足以支持交付主张”是两个不同问题。

## 三种交付视图

| 视图 | 买方可见内容 | 能否完整离线重放 |
|---|---|---|
| public | 聚合计数、Scope 摘要、Decision、边界声明 | 否 |
| diagnostic | public + 双臂状态、原因码、缺失目标诊断 | 否 |
| customer_private | 签名 Scope/Profile/Arm/Decision、成员、selector、证据、公钥、报告 | 是 |

客户私有包内含 `verify.sh`，也可运行：

```bash
env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY \
  ./.venv/bin/python tests/evidence-bundles/verify_evidence_bundle.py \
  tests/evidence-bundles/rich-4196-scope-v03-delivery-package.json
```

## 本报告不证明什么

本报告不证明 Rich 官方采纳 OpenWorkProof，不证明客户已经验收或付款，不
证明资金释放、自动结算、生产部署、普遍正确性、未编码的业务意图或法规
合规。它只证明冻结包中的签名对象、范围人口、必选目标、正负臂证据和决定
可被第三方重算，并在任一受保护字节被篡改时失败关闭。
