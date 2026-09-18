---
title: "feat: Enforce OAuth 2.1 baseline behind EnforceOAuth21"
type: feat
status: completed
date: 2026-09-18
origin: docs/brainstorms/2026-09-17-oauth21-enforcement-requirements.md
deepened: 2026-09-18
---

# feat: Enforce OAuth 2.1 baseline behind EnforceOAuth21

## Summary

在 `ServerConfig` 上增加默认关闭的 `EnforceOAuth21`，用它统一切换三处基线行为：授权码流程强制 PKCE、redirect_uri 精确匹配、public client 凭 client_id 免密钥换令牌。严格 URI 比较作为模式内的独立实现，既不改 `ValidateUri*` 的公共语义，也不触碰模式关闭时的任何代码路径。

---

## Problem Frame

osin 目前是 OAuth 2.0 + 可选 PKCE 的实现。OAuth 2.1 草案与 RFC 9700 把 PKCE 强制、redirect_uri 精确匹配、未认证客户端的令牌请求提升为规范要求，当前实现三处都不满足。下游部署在切换到严格行为时会打断依赖子路径注册的客户端和未上 PKCE 的客户端，因此严格行为需要一个显式开关作为迁移窗口。详见 [origin](docs/brainstorms/2026-09-17-oauth21-enforcement-requirements.md)。

---

## Requirements

- R1. `ServerConfig` 新增 `EnforceOAuth21`，默认 false；false 时对外行为与当前版本完全一致。
- R2. 为 true 时 R3–R10 同时生效，不提供逐项开关。
- R3. 授权端点收到无 `code_challenge` 的授权码请求时返回 `invalid_request`，不下发授权码。
- R4. 令牌端点拒绝兑换未关联 `code_challenge` 的授权码，返回 `invalid_grant`。
- R5. 令牌端点要求 `code_verifier` 与授权请求的 PKCE 状态严格同现，违反返回对应错误码。
- R6. 授权与令牌请求中的 `redirect_uri` 必须与注册值精确字符串比较相等（含 query），不再接受同 host 子路径前缀匹配。
- R7. loopback 注册值（`http://127.0.0.1`、`http://[::1]`）允许端口不同，其余部分精确相等。
- R8. secret 为空的客户端可仅凭请求体 `client_id` 在令牌端点完成识别，不受 `AllowClientSecretInParams` 限制。
- R9. 注册了 secret 的客户端仍必须提供凭据；仅传 `client_id` 返回 `invalid_client`。
- R10. 既无凭据也无 `client_id` 的令牌请求返回 `invalid_request`。

**Origin actors:** A1 (下游部署方), A2 (confidential client), A3 (public client)

**Origin flows:** F1 (授权请求), F2 (令牌兑换)

**Origin acceptance examples:** AE1–AE9 (覆盖 R1–R10 的开关两侧行为)

---

## Scope Boundaries

- implicit 授权与 ROPC 的处置不在本次范围，默认允许列表保持现状。
- `iss` 响应参数与授权服务器元数据不在本次范围。
- DPoP 与 mTLS 发件人约束不在本次范围。
- 刷新令牌 reuse 检测与授权链连带吊销不在本次范围。
- 授权码一次性使用的连带吊销不在本次范围。
- PKCE `plain` 方法的处理保持现状。
- 下游部署的客户端迁移与灰度方案不在本次范围，本次只提供开关与文档。
- `Storage` 接口与现有存储实现不改动。

---

## Context & Research

### Relevant Code and Patterns

- `config.go` — `ServerConfig` 字段与 `NewServerConfig()` 默认值，现有布尔开关（`RequirePKCEForPublicClients`、`RetainTokenAfterRefresh`、`AllowClientSecretInParams`）的写法与注释风格。
- `authorize.go` — 授权端点的 redirect_uri 校验与 PKCE 参数校验分支，含 `RequirePKCEForPublicClients` 的现有实现。
- `access.go` — 授权码换令牌路径：客户端认证、redirect_uri 比对（对照已保存的授权数据）、PKCE 校验块。
- `urivalidate.go` — `ValidateUri` / `ValidateUriList` / `FirstUri`，当前实现对同 host 子路径前缀放行、比较时忽略 query。
- `util.go` — `getClientAuth` 与 `CheckClientSecret`，public client 的既有判定方式（secret 为空）。
- 测试约定：每个源文件对应 `*_test.go`；`storage_test.go` 的 `NewTestingStorage()` 提供 `1234`（有 secret）与 `public-client`（无 secret）两个客户端；令牌生成器用 `TestingAccessTokenGen` / `TestingAuthorizeTokenGen` 桩。

### Institutional Learnings

- 仓库没有 `docs/solutions/`，无历史经验条目可循。

### External References

- draft-ietf-oauth-v2-1-15：§2.3.1 注册要求、§4.1.2 授权响应、§4.1.2.1 授权错误响应与 PKCE 拒绝规则、§4.1.3 令牌端点扩展、§7.5.1.1 PKCE 强制。
- draft-ietf-oauth-v2-1-15 §10.2：令牌请求中的 redirect_uri 已从 OAuth 2.1 移除；服务器为兼容 2.0 客户端仍必须接受该参数，并在出现时按 RFC 6749 强制校验。
- RFC 9700 §2.1.1 与 §4.8（PKCE 强制与降级攻击）。
- RFC 8252 §7.3（loopback 重定向的变端口例外）。

---

## Key Technical Decisions

- 严格 URI 比较新增独立实现，`ValidateUri` / `ValidateUriList` 的语义与导出行为不动：两者是公共 API，且 `urivalidate_test.go` 把子路径匹配、query 透传当作正确行为断言。
- public client 判定沿用"未注册 secret"（`CheckClientSecret(client, "")` 为真）：与 `RequirePKCEForPublicClients` 同源，不新增接口，存储实现零改动。
- 免密钥路径只认请求体 `client_id`；Basic 空密码继续被拒（origin R8 的措辞）。
- 模式内的免密钥路径不受 `AllowClientSecretInParams` 约束，但加载客户端后必须复核其确实没有 secret，否则返回 `invalid_client`。
- `code_verifier` 在不该出现时出现返回 `invalid_request`：属于参数层面违规，与既有分工一致（格式问题 → `invalid_request`，与 challenge 不匹配 → `invalid_grant`）。
- 授权端点缺 `code_challenge` 沿用 `invalid_request`，错误描述去掉 "for public clients" 限定。
- loopback 例外只覆盖 `127.0.0.1` 与 `[::1]` 两个主机，`localhost` 不参与端口放宽（origin R7）。
- 令牌端点保留 RFC 6749 的 redirect_uri 语义（草案 §10.2 要求服务器继续接受该参数）：携带时按注册值强校验，省略时沿用既有回落逻辑，因此只注册一个 URI 的 2.1 客户端可以直接省略该参数。
- 免密钥路径不做客户端认证，令牌与客户端的绑定由 PKCE 承载；这两件事必须同属一个模式，不能只开其中一个（见 System-Wide Impact）。

---

## Open Questions

### Resolved During Planning

- loopback 例外的表达方式：在 URI 比较内部处理主机与端口的差异，不在客户端注册信息上加标记。
- public client 判定依据：沿用 secret 为空的既有约定。
- 授权端点缺 PKCE 的错误码：`invalid_request`。
- `code_verifier` 在不该出现时的错误码：`invalid_request`。

### Deferred to Implementation

- 严格比较函数的最终命名与落点（`urivalidate.go` 内新增，或单独文件）。
- 新增错误描述的确切文案。
- 模式内客户端认证分支的具体组织方式（在 `getClientAuth` 内分支，或在调用点前置判定）。

---

## High-Level Technical Design

> *This illustrates the intended approach and is directional guidance for review, not implementation specification. The implementing agent should treat it as context, not code to reproduce.*

| 行为面 | `EnforceOAuth21 = false` | `EnforceOAuth21 = true` |
|---|---|---|
| 授权请求缺 `code_challenge` | 签发授权码 | `invalid_request`，不签发 |
| 授权码未关联 challenge | 可兑换 | `invalid_grant` |
| `code_verifier` 与 challenge 不同现 | 多余的 verifier 被忽略 | 缺失/不匹配 → `invalid_grant`；多余 → `invalid_request` |
| redirect_uri 比较 | 同 host 子路径前缀匹配，query 透传 | 精确字符串比较，loopback 主机放宽端口 |
| public client 令牌请求 | 依赖 `AllowClientSecretInParams` 才能用表单 `client_id` | 表单 `client_id` 直接生效，不受该字段约束 |

---

## Implementation Units

### U1. 新增 EnforceOAuth21 配置开关

**Goal:** 在 `ServerConfig` 上提供默认关闭的模式开关，作为三处行为的统一入口，并在 README 记录其覆盖范围。

**Requirements:** R1, R2

**Dependencies:** None

**Files:**
- Modify: `config.go`
- Modify: `README.md`
- Create: `config_test.go`

**Approach:**
- 在 `ServerConfig` 增加布尔字段，注释写明它管的三件事与它不覆盖的范围（`iss`、DPoP 等）。
- `NewServerConfig()` 中显式置为 false，与既有默认值列表风格一致。
- README 在 PKCE 段落之后补一段说明，指明开启后的行为差异与适用场景。

**Patterns to follow:**
- `config.go` 中 `RequirePKCEForPublicClients`、`RetainTokenAfterRefresh` 的字段定义与默认值写法。

**Test scenarios:**
- Happy path: `NewServerConfig()` 返回的配置 `EnforceOAuth21` 为 false。
- Edge case: 显式置 true 后读取该字段仍为 true，配置结构不引入其他副作用。

**Verification:**
- 默认配置下 `go test ./...` 全绿，且无任何行为变化。

---

### U2. redirect_uri 严格匹配与 loopback 例外

**Goal:** 模式开启时，授权端点和令牌端点按精确字符串比较校验 `redirect_uri`，并保留 loopback 主机的端口放宽；模式关闭时维持现状。

**Requirements:** R6, R7

**Dependencies:** U1

**Files:**
- Modify: `urivalidate.go`
- Modify: `authorize.go`
- Modify: `access.go`
- Test: `urivalidate_test.go`
- Test: `authorize_test.go`

**Approach:**
- 新增一个严格比较函数：解析注册值与请求值，要求 scheme、host、path、query 全部相等；当两侧主机同属 loopback（`127.0.0.1`、`[::1]`）时允许端口不同。
- 比较函数保持列表语义（注册值可以是分隔符拼接的多个 URI），与 `ValidateUriList` 的调用约定一致。
- 模式开关在两个调用点选择严格函数或既有函数；令牌端点对已保存授权数据的比对逻辑保持原有语义。

**Patterns to follow:**
- `urivalidate.go` 中 `ValidateUriList` 的列表切分与"返回真实 URI"约定。
- `authorize.go`、`access.go` 现有的 `ValidateUriList` 调用与错误处理分支。

**Test scenarios:**
- Happy path: 注册 `https://app.example.com/cb`，请求完全相同 → 通过（Covers AE6）。
- Edge case: 注册 `http://127.0.0.1/cb`，请求 `http://127.0.0.1:49152/cb` → 通过（Covers AE7）。
- Edge case: 注册值带 query，请求 query 不同 → 拒绝。
- Edge case: 非 loopback 主机的端口不同 → 拒绝。
- Edge case: 令牌请求省略 redirect_uri 且客户端只注册一个 URI → 维持现有回落行为并成功换取令牌（草案 §10.2 的兼容要求）。
- Error path: 子路径 `https://app.example.com/cb/extra`、后缀 `/other/cb`、追加 query `?x=1` → 授权端点返回 `invalid_request`（Covers AE6）。
- Error path: 令牌请求携带与授权请求不一致的 redirect_uri → 拒绝（Covers AE6）。
- Integration: 模式关闭时 `TestURIValidate`、`TestURIListValidate` 的既有断言全部保持通过，`ValidateUri` 返回值不变。

**Verification:**
- 模式关闭时 URI 校验的对外行为与改动前一致；模式开启时上表行为全部成立。

---

### U3. 授权端点强制 PKCE

**Goal:** 模式开启时，授权码请求必须携带 `code_challenge`，对所有客户端类型一致。

**Requirements:** R3

**Dependencies:** U1

**Files:**
- Modify: `authorize.go`
- Test: `authorize_test.go`

**Approach:**
- 现有 PKCE 校验分支已在 CODE 分支内，把模式作为独立的强制条件纳入，与 `RequirePKCEForPublicClients` 形成超集关系（模式开启时覆盖它）。
- 缺失 `code_challenge` 时返回 `invalid_request`，走 `SetErrorState` 的错误路径（不重定向）。
- 既有的 challenge 格式校验、`code_challenge_method` 取值校验与 challenge/method 存储行为保持不变。

**Patterns to follow:**
- `authorize.go` 中 `RequirePKCEForPublicClients` 的分支结构与 `E_INVALID_REQUEST` 错误设置方式。

**Test scenarios:**
- Happy path: 模式开启 + 携带 `code_challenge_method=S256` → 签发授权码，且 challenge 与 method 被保存（Covers AE4 的授权侧）。
- Error path: 模式开启 + 不带 `code_challenge`（有 secret 的客户端）→ `invalid_request`，不签发授权码（Covers AE2）。
- Error path: 模式开启 + 不带 `code_challenge`（无 secret 的客户端）→ `invalid_request`。
- Edge case: 模式关闭 + 不带 `code_challenge` → 照常签发授权码（Covers AE1）。
- Edge case: 模式开启 + 不支持的 `code_challenge_method` → `invalid_request`，行为与现状一致。
- Edge case: 模式开启 + `code_challenge` 格式非法 → `invalid_request`。

**Verification:**
- 模式开启后不存在未关联 challenge 的授权码；模式关闭时既有 `TestAuthorizeCodePKCE*` 与隐式流程测试保持通过。

---

### U4. 令牌端点 PKCE 一致性

**Goal:** 模式开启时，未关联 challenge 的授权码不可兑换，且 `code_verifier` 必须与 challenge 严格同现。

**Requirements:** R4, R5

**Dependencies:** U1

**Files:**
- Modify: `access.go`
- Test: `access_test.go`

**Approach:**
- 现有校验块以"授权码有 challenge"为前提，模式内改为三态判定：有 challenge → 必须提供且匹配；无 challenge → 拒绝兑换；无 challenge 却带了 verifier → `invalid_request`。
- 有 challenge 情形下的格式校验（`pkceMatcher`）与 `plain`/`S256` 转换逻辑保持不变。

**Patterns to follow:**
- `access.go` 中 `handleAuthorizationCodeRequest` 现有的 PKCE 校验块与错误码分工。

**Test scenarios:**
- Happy path: 模式开启 + S256 challenge + 正确 verifier → 签发访问令牌与刷新令牌（Covers AE4）。
- Error path: 模式开启 + 有 challenge + 缺 `code_verifier` → `invalid_grant`（Covers AE4）。
- Error path: 模式开启 + 有 challenge + 不匹配的 verifier → `invalid_grant`（Covers AE4）。
- Error path: 模式开启 + 无 challenge 的授权码 → `invalid_grant`（Covers AE3）。
- Error path: 模式开启 + 无 challenge + 携带 verifier → `invalid_request`（Covers AE5）。
- Edge case: 模式关闭 + 无 challenge + 携带 verifier → 维持现状（verifier 被忽略、成功签发），现有 `TestAccessAuthorizationCodePKCE` 的 "missing from storage" 用例语义不变。
- Edge case: 模式开启 + `plain` 与 `S256` 两种 method 各自按既有转换规则校验通过。

**Verification:**
- 模式开启时无 challenge 的授权码无法换到任何令牌；模式关闭时既有 PKCE 用例全绿。

---

### U5. public client 免密钥令牌认证

**Goal:** 模式开启时，未注册 secret 的客户端可仅凭请求体 `client_id` 完成令牌端点识别。

**Requirements:** R8, R9, R10

**Dependencies:** U1

**Files:**
- Modify: `util.go`
- Modify: `access.go`
- Test: `util_test.go`
- Test: `access_test.go`

**Approach:**
- 无 Basic 凭据时，模式内允许用请求体 `client_id` 进入客户端查询，不要求 `AllowClientSecretInParams` 为真。
- 加载客户端后复核其没有 secret（`CheckClientSecret(client, "")` 为真），否则返回 `invalid_client`；这样有 secret 的客户端无法退化为只报 `client_id`。
- 既无凭据也无 `client_id` → `invalid_request`，与现有"未发送客户端认证"的错误码保持一致。
- 模式关闭时 `getClientAuth` 的既有分支与错误码完全不变，`unauthorized_client` 的现有路径不动。

**Patterns to follow:**
- `util.go` 中 `getClientAuth` 的 Basic 与表单回落分支；`access.go` 中 `getClient` 的客户端加载与 secret 复核。

**Test scenarios:**
- Happy path: 模式开启 + `AllowClientSecretInParams=false` + 表单 `client_id`（无 secret 客户端）→ 成功换取令牌（Covers AE8）。
- Happy path: 模式开启 + 有 secret 的客户端携带正确 Basic 凭据 → 成功换取令牌（Covers AE9）。
- Error path: 模式开启 + 有 secret 的客户端只传表单 `client_id` → `invalid_client`（Covers AE9）。
- Error path: 模式开启 + 无凭据且无 `client_id` → `invalid_request`（Covers AE8）。
- Edge case: 模式开启 + Basic 空密码 → 仍被拒绝，免密钥路径只走请求体 `client_id`。
- Integration: 模式关闭时 `TestGetClientAuth` 的既有断言与 `AllowClientSecretInParams` 语义保持不变。

**Verification:**
- 模式开启时无 secret 的客户端能走完授权码换令牌；模式关闭时客户端认证行为与改动前一致。

---

## System-Wide Impact

- **Interaction graph:** 授权端点（`authorize.go`）与令牌端点（`access.go`）共用 URI 校验与客户端认证工具（`urivalidate.go`、`util.go`）；三处行为都从同一个配置字段读取，避免出现半严格组合。
- **Error propagation:** 授权端点的失败继续走 `SetErrorState`（不重定向到未注册 URI）；令牌端点的失败继续走 `setErrorAndLog`。新模式只新增 `invalid_client` 一条分支，`unauthorized_client` 的既有路径保持。
- **State lifecycle risks:** 无持久化结构变化；PKCE 状态继续由 `AuthorizeData` 的 challenge 与 method 字段承载，令牌端点据此判定。
- **API surface parity:** 新增一个公共配置字段；`ValidateUri` / `ValidateUriList` / `FirstUri` 作为导出 API 行为不变。
- **Integration coverage:** 授权到令牌的完整链路上 PKCE 状态的传递与校验必须一起验证，单端点单测桩覆盖不到。
- **Security boundary:** 免密钥路径本身不认证客户端，客户端绑定完全依赖 `code_verifier` 与 challenge 的匹配；该路径与 PKCE 强制必须由同一个开关同时开启，单独放开其一会形成任意调用方都能使用授权码的窗口。
- **Unchanged invariants:** 模式关闭时的 URI 宽松匹配、`AllowClientSecretInParams` 语义、既有错误码分工、implicit 与 ROPC 的默认允许列表均不变。

---

## Risks & Dependencies

| Risk | Mitigation |
|------|------------|
| 严格匹配打断依赖子路径注册的存量客户端 | 仅在显式开启开关后生效；文档写明 loopback 变端口是唯一放宽点 |
| 使用 Basic 空密码的 PKCE 客户端在模式内失败 | 文档标注免密钥路径需改用请求体 `client_id` |
| loopback 例外被扩大解释 | 例外只对 `127.0.0.1` 与 `[::1]` 生效，并配对应的拒绝用例 |
| 公共 URI 校验函数被无意改动导致下游漂移 | `ValidateUri*` 不动，严格比较走新函数，用既有测试作为回归基线 |
| 新模式路径被误用到默认配置 | 三处调用点都显式判读同一字段，配置默认值进入测试 |

---

## Documentation / Operational Notes

- README 增补 `EnforceOAuth21` 的行为差异说明与适用场景。
- 该开关是下游部署的迁移入口：本次只提供开关与说明，迁移节奏与灰度由下游决定。

---

## Sources & References

- **Origin document:** [docs/brainstorms/2026-09-17-oauth21-enforcement-requirements.md](docs/brainstorms/2026-09-17-oauth21-enforcement-requirements.md)
- Related code: `config.go`, `authorize.go`, `access.go`, `urivalidate.go`, `util.go`
- External docs: [draft-ietf-oauth-v2-1-15](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/), [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700), [RFC 8252 §7.3](https://www.rfc-editor.org/rfc/rfc8252#section-7.3)
