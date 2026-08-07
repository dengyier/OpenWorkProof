# 交付验证签署冻结清单(FREEZE MANIFEST)

- 冻结日期(UTC):2026-08-07T05:59:35Z(第三轮:候选库存对齐 HEAD 后重签)
  - 首轮冻结 2026-08-07T04:58:49Z(HEAD `14fd7d6`),因 M4 材料审校
    更新 README/status/交付验证计划,SHA256SUMS 重生成并按
    「签署后变更走新冻结周期」规则重签(第二轮 05:05:30Z);
  - 第三轮:为当前 HEAD 重新生成候选库存(新增
    `supply-chain/images/candidates/21af516b….json`),required-live
    全量 2281 passed、0 failed、0 skip 首次全绿,SHA256SUMS 重生成并重签;
- 冻结 HEAD:`14fd7d6c4047a4a6d5782e23499180eab9ed7b07` + M4 材料审校
  + 候选库存对齐(README/status/交付验证计划/离线验签说明/材料清单/
  新候选库存)
- 冻结范围:HEAD 全部 git 跟踪文件(见 `SHA256SUMS`,排除本目录避免自引用)
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
| 候选库存 | `supply-chain/images/candidates/*.json`(11)+ `supply-chain/images/README.md` | 镜像候选清单(digest 绑定,含当前 HEAD) |
| 补充 | `docs/superpowers/2026-08-07-execution-adapter-guide.md`、`team-network-client-guide.md` | 执行接入层与网络客户端指南 |

## 2. 全量测试计数(冻结时点)

- required-live Docker 全量:**2281 passed、0 failed、0 skip**,退出码 0
  (候选库存已为当前 HEAD 重新生成,历史 2 个既有失败消除,首次全绿);
- 非 required-live 本地全量:2271 passed、7 skipped、0 failed。

## 3. 签署记录

| 角色 | key_id | 签署时间(UTC) | 签名文件 |
|---|---|---|---|
| 技术 Owner(dengyier) | `ed25519:1d153afca0cde7d3eed2d5736afefd520e8a7cf7525119be352854ba865b39f9` | 2026-08-07T05:59:35Z(第三轮重签) | `owner.signature` |
| 独立见证人 | `ed25519:3ef752211ae092fb48c4f9a473b0bc4479178f9e01b74422cfb28dd1e970ff54` | 2026-08-07T05:59:35Z(第三轮重签) | `witness.signature` |

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
