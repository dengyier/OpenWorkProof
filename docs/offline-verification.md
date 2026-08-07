# 离线验签说明(Offline Verification)

OpenWorkProof 的证据链设计允许**第三方不接入任何一方系统**、仅凭一份
复制的证据包离线复核全部事实。本文件说明验签的入口、输入与复现步骤。

## 1. 适用场景

- 纠纷复核:验收后,独立第三方拿证据包即可验证"这份 accepted/rejected
  结论是否由 WorkOrder 绑定的 Acceptor 真实签名、证据链是否完整";
- 交付审计:赛事评委或监管方无需运行任何一方服务,离线重放签名历史;
- 可复现性:证据包 + 本说明即构成可独立执行的验收证明。

## 2. 核心入口

### `verify_acceptance_bundle`(终态验收/拒绝)

位于 `src/openworkproof/acceptance.py`,接受**无活动账本**的完整证据快照:

```python
from openworkproof.acceptance import verify_acceptance_bundle

result = verify_acceptance_bundle(
    work_order=work_order,              # WorkOrder(含六角色绑定公钥)
    report=report,                      # CompositionReport(权威账本工件)
    effective_grants=grants,            # 规范化 Grant 前缀
    grant_attempts=attempts,            # 签发尝试
    receipts=receipts,                  # ActionReceipt 信封序列
    committed_evidence=evidence,        # (CommittedEvidence, ...)
    acceptance_receipt=signed,          # 终态验收收据(与 rejection 二选一)
    public_keys=public_keys,            # {key_id: Ed25519PublicKey}
    reports=reports,                    # 全部 CompositionReport(含 recomposition 链)
    rejection=rejection,                # 终态拒绝收据(与 acceptance 二选一)
)
```

**Exactly one** 终态决策(acceptance 或 rejection)必须绑定请求 tip;
`public_keys` 必须与 WorkOrder 绑定公钥一致。

### `verify_composition_bundle`(报告链复核)

位于 `src/openworkproof/acceptance.py`,复核报告一一对应与顺序唯一性,
并验证 composition/recomposition 链。

## 3. 输入如何收集(导出端)

证据包的导出由生产协调器完成(见 M2 演示 `test_delivery_m2.py` 的
step 9):从账本读 receipts/grants/attempts,从证据根读 committed
evidence 字节,从签名草稿取 AcceptanceReceipt。导出后:

1. 每个 EvidenceRef 的 `path` 指向证据根内文件,`sha256` 为文件内容摘要;
2. `CommittedEvidence(reference=ref, payload=bytes)` 保持原始字节;
3. receipts 按 sequence 排序,evidence 按 path 排序(可哈希稳定)。

## 4. 验证内容(验签器做什么)

1. **签名授权历史**:重建确定性索引,验证每条收据的 Ed25519 签名,
   父集精确匹配,genesis 唯一,active patch/rework/approval/
   composition/independent-result episode 语义正确;
2. **策略回放**:重算 Grant 衰减、余额、撤销、single-use、配额与拒绝
   优先级,验证证据引用与 publication 闭包;
3. **证据绑定**:逐字节重哈希 committed evidence,与 EvidenceRef.sha256
   和收据 output_digest 一致;
4. **报告绑定**:CompositionReport 与触发收据一一对应、顺序唯一;
   双报告链(recomposition)两段 signed report-to-trigger 绑定;
5. **终态互斥**:acceptance 与 rejection 二选一,与请求 tip 绑定,
   Acceptor 签名权威与 WorkOrder 绑定公钥一致;
6. **篡改拒绝**:报告/收据/关联因子/公钥/账本表任一字节被改即失败。

## 5. 快速复现(M2 演示)

```bash
./.venv/bin/python -m pytest tests/test_delivery_m2.py -q
```

`test_m2_full_chain_...` 的 step 9 演示完整导出 + `verify_acceptance_bundle`
离线验签通过;篡改测试验证任何单字节修改均被拒绝。

## 6. 边界与诚实声明

- 离线验签**证明证据链与签名的有效性**,不证明"外部真实人类复核过"——
  外部个人签署属线下事件,不由本仓库保证;
- `public_keys` 由验证者自行获取;若 WorkOrder 绑定公钥本身不可信,
  验签结果仅在"信任该 WorkOrder 绑定"前提下成立。
