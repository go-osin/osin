---
date: 2026-09-17
topic: oauth21-enforcement
---

# OAuth 2.1 基线强制执行（EnforceOAuth21）

## Summary

为 osin 增加一个默认关闭的 `EnforceOAuth21` 开关。开启后按 OAuth 2.1 基线执行三件事：授权码流程强制 PKCE、redirect_uri 精确匹配、public client 可在令牌端点凭 client_id 免密钥换令牌。关闭时对外行为与当前版本一致。

---

## Problem Frame

osin 目前实现的是 OAuth 2.0 + 可选 PKCE。OAuth 2.1 草案（draft-ietf-oauth-v2-1-15）与 RFC 9700 把若干安全实践提升为规范要求，其中三处与当前实现直接冲突：

- 授权服务器必须拒绝未使用 PKCE 的授权码流程（§4.1.2.1、§7.5.1.1）。当前只有 opt-in 的 `RequirePKCEForPublicClients`，默认关闭；令牌端点对未关联 `code_challenge` 的授权码照常签发令牌。
- redirect_uri 必须按 RFC 3986 §6.2.1 的简单字符串比较精确匹配（§2.3.1、§4.1.2）。当前 URI 校验接受同 host 下的子路径前缀匹配，且不比较 query 部分。
- 未认证的客户端必须能凭 `client_id` 完成令牌请求（§4.1.3）。当前令牌端点的客户端认证要求非空 secret，表单回落路径默认关闭，未注册 secret 的客户端只能拿到 `invalid_request`。

影响面是下游部署：依赖子路径 redirect_uri 的客户端和未上 PKCE 的客户端在切换到严格行为时会中断，所以严格行为需要可开关，并保留迁移窗口。

---

## Actors

- A1. 下游部署方：把 osin 集成进授权服务器，决定是否开启 `EnforceOAuth21`，并负责客户端迁移。
- A2. confidential client：注册了 secret 的客户端，使用授权码流程换取令牌。
- A3. public client：未注册 secret 的客户端（SPA、原生 App），依赖 PKCE 与 `client_id` 完成令牌请求。

---

## Key Flows

- F1. 授权请求
  - **Trigger:** 客户端携带 `client_id`、`redirect_uri`、`response_type=code` 访问授权端点。
  - **Actors:** A1, A2, A3
  - **Steps:** 校验 redirect_uri 是否与注册值精确匹配；校验 PKCE 参数是否满足模式要求；授权决策通过后签发授权码并重定向。
  - **Outcome:** 授权码与 PKCE 状态（challenge 与 method）被一并保存；模式开启时不存在没有 challenge 的授权码。
  - **Covered by:** R3, R6, R7

- F2. 令牌兑换
  - **Trigger:** 客户端携带 `grant_type=authorization_code` 与 `code` 访问令牌端点。
  - **Actors:** A1, A2, A3
  - **Steps:** 识别客户端（凭据或 `client_id`）；加载授权码；校验 redirect_uri、`code_verifier` 与 challenge 的一致性；签发访问令牌与刷新令牌。
  - **Outcome:** 符合模式要求的请求拿到令牌，其余请求得到对应的 OAuth 错误码，不签发令牌。
  - **Covered by:** R4, R5, R6, R8, R9, R10

---

## Requirements

**模式开关**

- R1. `ServerConfig` 新增布尔配置 `EnforceOAuth21`，默认 false。false 时本库对外行为与当前版本完全一致。
- R2. `EnforceOAuth21` 为 true 时 R3–R10 同时生效；不提供逐项开关。

**PKCE 强制**

- R3. 授权端点收到授权码请求而未携带 `code_challenge` 时，返回 `invalid_request` 授权错误响应，不下发授权码。
- R4. 令牌端点拒绝兑换未关联 `code_challenge` 的授权码，返回 `invalid_grant`。
- R5. 令牌端点要求 `code_verifier` 与授权请求的 PKCE 状态严格同现：授权码关联了 challenge 时必填且必须匹配，缺失或不匹配返回 `invalid_grant`；未关联时不得携带，携带属于参数层面违规，返回 `invalid_request`。

**redirect_uri 精确匹配**

- R6. 授权请求与令牌请求中的 `redirect_uri` 必须与注册值按简单字符串比较完全相等，包含 query 部分；不再接受同 host 子路径前缀匹配。不相等时授权端点返回 `invalid_request` 错误响应，且不得重定向到未注册的 URI。
- R7. 注册值为 loopback 的客户端（`http://127.0.0.1` 或 `http://[::1]`）允许端口与注册值不同，其余部分仍需精确相等。

**public client 令牌端点认证**

- R8. secret 为空的客户端可仅凭请求体中的 `client_id` 在令牌端点完成识别，无需 `client_secret`，且不受 `AllowClientSecretInParams` 取值限制。
- R9. 注册了 secret 的客户端仍必须提供凭据；仅传 `client_id` 时返回 `invalid_client`。
- R10. 既无凭据也无 `client_id` 的令牌请求返回 `invalid_request`。

---

## Acceptance Examples

- AE1. **Covers R1.** 开关为 false 时，授权请求不带 `code_challenge` 仍签发授权码，该码可正常兑换令牌。
- AE2. **Covers R3.** 开关为 true 时，同样的请求返回 `invalid_request`，不签发授权码。
- AE3. **Covers R4.** 开关为 true 时，用未关联 challenge 的授权码兑换令牌，返回 `invalid_grant`。
- AE4. **Covers R5.** 开关为 true，授权请求带 `code_challenge_method=S256`：令牌请求不带 `code_verifier` 返回 `invalid_grant`，带不匹配的 `code_verifier` 返回 `invalid_grant`，带匹配的 `code_verifier` 签发令牌。
- AE5. **Covers R5.** 开关为 true，未关联 challenge 的授权码在令牌请求中携带 `code_verifier`，返回 `invalid_request`。
- AE6. **Covers R6.** 注册 `https://app.example.com/cb`，开关为 true 时，`https://app.example.com/cb/extra`、`https://app.example.com/cb?x=1`、`https://app.example.com/other/cb` 均返回 `invalid_request`；完全相同的 `https://app.example.com/cb` 通过。
- AE7. **Covers R7.** 注册 `http://127.0.0.1/cb`，请求 `http://127.0.0.1:49152/cb` 通过；`http://127.0.0.1:49152/cb/extra` 被拒绝。
- AE8. **Covers R8, R10.** 开关为 true 且 `AllowClientSecretInParams=false` 时，secret 为空的客户端以请求体 `client_id` 兑换授权码成功；无 `client_id` 且无凭据的请求返回 `invalid_request`。
- AE9. **Covers R9.** 开关为 true 时，secret 非空的客户端仅传 `client_id` 兑换授权码，返回 `invalid_client`；携带正确凭据时成功。

---

## Success Criteria

- 下游开启 `EnforceOAuth21` 后，符合 2.1 基线的客户端（带 PKCE 的授权码流程、精确注册的 redirect_uri、无 secret 的 public client）能完整跑通授权与令牌兑换。
- 未开启该开关的部署升级后行为无变化，现有测试全部保持通过。
- 规划阶段无需再决定开关语义、三处行为的触发条件与客户端可见的错误码。

---

## Scope Boundaries

- implicit 授权与 ROPC 的废弃处置不在本次范围，现状保持（默认均未在允许列表中启用）。
- `iss` 响应参数（RFC 9207）与授权服务器元数据不在本次范围。
- DPoP（RFC 9449）与 mTLS（RFC 8705）发件人约束不在本次范围。
- 刷新令牌的 reuse 检测与整条授权链的连带吊销不在本次范围。
- 授权码一次性使用的连带吊销不在本次范围。
- PKCE `plain` 方法的处理保持现状（草案允许 `plain`，RFC 9700 仅为 SHOULD 使用 S256）。
- 下游部署的客户端迁移与灰度方案不在本次范围。

---

## Key Decisions

- 单一开关、默认关闭：三处属于同一套 2.1 基线语义，独立开关允许出现只严格一半的组合；默认关闭使存量部署升级零风险。
- 开关命名 `EnforceOAuth21`：与现有 `Allow*`/`Require*` 命名风格一致，表达"强制执行基线"，不暗示完整 2.1 支持。
- PKCE 对所有客户端无条件强制，不实现草案 §7.5.1.1 中 confidential client 叠加 OIDC nonce 的例外：该例外要求授权服务器对客户端 nonce 实现有合理保证，本库无从验证。
- public client 的免密钥路径只在 `EnforceOAuth21` 为 true 时生效，范围与开关一致。
- 精确匹配保留 loopback 变端口例外：缺少该例外时原生 App 没有合规的注册路径。

---

## Dependencies / Assumptions

- 假设 `EnforceOAuth21` 关闭时 `RequirePKCEForPublicClients` 保持原义；开启时被 R3 覆盖。
- 本次不引入刷新令牌重用检测或发件人约束，因此 `Storage` 接口与现有存储实现无需改动。
- 本次为向后兼容变更（新增开关、默认关闭），可直接进入 minor 版本。

---

## Outstanding Questions

### Deferred to Planning

- [Affects R6, R7][Technical] loopback 例外的表达方式：是在现有 URI 校验工具内处理端口差异，还是在客户端注册信息层面标记 loopback。
- [Affects R8, R9][Technical] public client 的判定依据：沿用"secret 为空"的既有约定，还是引入显式的客户端类型标记。
- [Affects R3][Technical] 授权端点拒绝缺失 PKCE 时的错误码与描述文案。
- [Affects R5][Technical] `code_verifier` 在不该出现时出现，应返回 `invalid_request` 还是 `invalid_grant`。
