# M4 赛事材料清单与质量检查(Delivery Materials Checklist)

> 对应交付验证计划环节 4(5.2 材料清单 + 5.3 质量检查标准)。
> 状态时间:2026-08-07;冻结 HEAD:`14fd7d6c4047a4a6d5782e23499180eab9ed7b07`。
> 第三轮独立审计(2026-08-16)闭环后复核:候选库存目录现有 **20** 份不可变
> 库存(含当前 `66d242e…` 最终候选与更早历史候选);required-live 全量
> fresh `3489 passed、0 failed、0 skip`。

## 1. 材料清单(8 类)核对结果

| # | 类别 | 材料 | 位置 | 状态 |
|---|---|---|---|---|
| 1 | 项目说明 | README / 30 秒理解 / 市场定位 | `README.md`(30 秒理解 §、为什么是现在 §、愿景 §) | ✅ 已审校更新 |
| 2 | 协议文档 | specs 设计(6)+ 实施计划(8)+ schema(6)+ 离线验签说明 | `docs/superpowers/specs/`、`docs/superpowers/plans/`、`specs/v0.1/`、`docs/offline-verification.md` | ✅ 齐备(离线验签说明本轮补齐) |
| 3 | 代码 | 源码(27)+ requirements-lock + 候选库存(20) | `src/openworkproof/`、`requirements-lock.txt`、`supply-chain/images/candidates/` | ✅ 齐备(含当前 HEAD 候选) |
| 4 | 验证 | 全量测试报告 + focused/candidate/full 计数 | `docs/status.md` §当前验证快照 | ✅ required-live 全量 fresh 3489 passed、0 failed、0 skip |
| 5 | 演示 | 环节 2 证据链 + 记录 | `tests/test_delivery_m2.py`、`docs/superpowers/2026-08-07-rich-4196-demo-log.md` | ✅ 已完成(M2) |
| 6 | 签署 | 环节 3 签名单 + 哈希 | `docs/delivery-signoff/`(MANIFEST/SHA256SUMS/owner+witness.signature) | ✅ 已完成(M3) |
| 7 | 法律 | Apache-2.0 LICENSE + 版权主体声明 | `LICENSE`、`README.md` §项目主体、`docs/status.md` §项目主体说明 | ✅ 齐备 |
| 8 | 补充 | 路线图 / 边界声明 / 已知限制 | `README.md` §路线图、`docs/status.md` §重要边界 + §尚未完成 | ✅ 已审校更新 |

## 2. 质量检查标准(Checklist)

- [x] **完整性**:8 类材料逐项存在且为最新版本(本表核对);
- [x] **规范性**:Markdown/JSON 格式校验通过(源码 `compileall`、`pip check`、
  候选 JSON 由 `test_image_supply_chain.py` 严格 schema 校验);
- [x] **无真实姓名泄漏**:材料中仅出现技术 Owner 标识 `dengyier` 与
  版权主体「成都星火领航科技有限公司」(项目要求披露项),无第三方
  个人真实姓名;独立见证人仅以 key_id 记录,不出现姓名;
- [x] **可复现性**:`git clone` + `pip install -r requirements-lock.txt` +
  `pytest -q`(required-live)可复跑;M2 演示 `test_delivery_m2.py` 本地闭环;
- [x] **一致性**:README/status 计数与 required-live 全量一致
  (第三轮 fresh 3489 passed、0 failed、0 skip);total 复审通过;
- [x] **边界诚实**:全材料不宣称"独立外部人类验收完成"——明确标注
  外部 Acceptor 人类签署属线下事件、交付验证签署与赛事结果不由本仓库保证。

## 3. 复核命令

```bash
# 证据链离线验签(M2)
./.venv/bin/python -m pytest tests/test_delivery_m2.py -q
# 交付验证签署锚点复核(M3)
./.venv/bin/python docs/delivery-signoff/verify_sha256sums.py
./.venv/bin/python docs/delivery-signoff/verify_signature.py --role owner   --public-key-hex a9ba87f3bef8e4f352a8f7dcdfdc5fff1d8d2de084be9dd475589fe97c9283f4
./.venv/bin/python docs/delivery-signoff/verify_signature.py --role witness --public-key-hex 41f7dc2483f18dc7897296d034acf0b9325e13b6dbe1eca10986a17744c68f96
```

## 4. 剩余边界(如实声明)

- **真实外部人类签署**:M3 已用协议工具完成 Owner/见证人 Ed25519 签署
  并离线验签通过,但外部真实个人复核属线下事件,不由本仓库保证;
- **赛事提交**:材料齐备不代表入围或获奖,正式提交由 Owner 执行。
- **required-live 最终门**:第三轮 fresh 3489 passed、0 failed、0 skip
  (零 warning),候选按最终修订 `66d242e…` 重建;total 复审通过后
  恢复一致性勾选。
