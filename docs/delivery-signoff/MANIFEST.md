# 交付验证签署冻结清单(FREEZE MANIFEST)

- 冻结日期(UTC):2026-08-07T04:58:49Z
- 冻结 HEAD:`14fd7d6c4047a4a6d5782e23499180eab9ed7b07`
  (`refactor: rename Day 0 to delivery signoff (交付验证签署)`)
- 冻结范围:HEAD 全部 112 个 git 跟踪文件(见 `SHA256SUMS`,排除本目录避免自引用)
- 不可变锚点:`SHA256SUMS`(逐文件 SHA-256,复核脚本 `verify_sha256sums.py` 重算比对)

## 1. 材料清单(对应交付验证计划 4.3)

| 类别 | 内容 | 说明 |
|---|---|---|
| 源码 | `src/openworkproof/**`(27 文件)+ `pyproject.toml` + `requirements-lock.txt` | HEAD 快照,由 git 提交 SHA 锚定 |
| 协议规格 | `specs/v0.1/*.schema.json`(6)+ `docs/superpowers/specs/**`(6 设计) | 协议四对象 + 双终态 + 供应链 schema |
| 实施计划 | `docs/superpowers/plans/**`(8 实施) | repo_read、run-tests 恢复、验收事务、独立 recomposition、Acceptor 拒绝、交付验证计划 |
| 项目说明 | `README.md`、`docs/status.md`、`llms.txt`、`LICENSE`(Apache-2.0) | 能力清单、状态、许可证 |
| 验证证据 | `tests/**`(28 文件) | 全量测试可复现 |
| 环节 1 记录 | `docs/superpowers/2026-08-07-acceptor-rejection-execution-log.md` | 外部 Acceptor 端到端验证 |
| 环节 2 记录 | `docs/superpowers/2026-08-07-rich-4196-demo-log.md` | 五角色 9 步演示证据链 |
| 候选库存 | `supply-chain/images/candidates/*.json`(10)+ `supply-chain/images/README.md` | 镜像候选清单(digest 绑定) |
| 补充 | `docs/superpowers/2026-08-07-execution-adapter-guide.md`、`team-network-client-guide.md` | 执行接入层与网络客户端指南 |

## 2. 全量测试计数(冻结时点)

- 本地全量(`pytest tests/ -q`,非 required-live):**2271 passed、2 failed、7 skipped**
- 2 个失败为既有环境问题:候选库存与当前 HEAD 定义不匹配
  (`test_current_candidate_inventory_binds_execution_runner` /
  `test_current_candidate_inventory_binds_fixed_test_source`),stash 对比确认与本次无关;
- required-live Docker 全量历史计数见 README(`2226 passed、0 failed、0 skip`),
  需在候选库存与当前 HEAD 对齐后重跑。

## 3. 签署记录

| 角色 | key_id | 签署时间(UTC) | 签名文件 |
|---|---|---|---|
| 技术 Owner(dengyier) | `ed25519:1d153afca0cde7d3eed2d5736afefd520e8a7cf7525119be352854ba865b39f9` | 2026-08-07T04:59:38Z | `owner.signature` |
| 独立见证人 | `ed25519:3ef752211ae092fb48c4f9a473b0bc4479178f9e01b74422cfb28dd1e970ff54` | 2026-08-07T04:59:38Z | `witness.signature` |

签署对象:`SHA256SUMS` 精确字节(Ed25519 明文签名,base64url)。
复核:`verify_signature.py --role <role> --public-key-hex <32-byte-hex>`。

验证者公钥(hex,32 字节):

| 角色 | public_key_hex |
|---|---|
| 技术 Owner(dengyier) | `a9ba87f3bef8e4f352a8f7dcdfdc5fff1d8d2de084be9dd475589fe97c9283f4` |
| 独立见证人 | `41f7dc2483f18dc7897296d034acf0b9325e13b6dbe1eca10986a17744c68f96` |

## 4. 存档机制

- `git tag delivery-signoff-2026-08-07` 冻结存档点;
- 存档目录只读约定:签署后本目录内容不再修改,如需变更走新冻结周期;
- 复核流程:重跑 `verify_sha256sums.py` + 两条 `verify_signature.py`,全部 OK 即锚点有效。
