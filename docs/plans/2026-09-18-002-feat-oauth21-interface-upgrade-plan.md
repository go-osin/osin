---
title: "feat: OAuth 2.1 接口与结构升级（v1 兼容）"
type: feat
status: completed
date: 2026-09-18
origin: docs/brainstorms/2026-09-18-oauth21-interface-upgrade-requirements.md
---

# feat: OAuth 2.1 接口与结构升级（v1 兼容）

## Summary

在保持 `Client` 与 `Storage` 方法集不变的前提下，用新增可选接口承载客户端注册事实，用带显式能力握手的承载位承载令牌绑定事实，用 `ServerConfig` 承载服务器身份与策略。所有新增能力以附加方式表达，未实现新接口的既有代码路径行为不变。

---

## Problem Frame

`EnforceOAuth21` 覆盖了授权码流程的三处基线行为后，2.1 的其余部分在库的公共面上仍无处表达：客户端注册的是 URI 集合还是单值、以 `none` 还是非共享密钥方式认证、令牌是否被发件人约束、授权服务器是否有 issuer。下游因此派生自己的类型来承载差异，并在每次解析时做类型断言。库长期停留在 v1，没有破坏式变更窗口，因此升级只能用附加形式完成。详见 [origin](docs/brainstorms/2026-09-18-oauth21-interface-upgrade-requirements.md)。

---

## Requirements

- R1. `Client` 与 `Storage` 的方法集保持不变；所有新增能力以新的可选接口表达。
- R2. 库内通过类型断言探测可选接口，未实现时回退到现有访问器。
- R3. 承载只读事实的扩展，缺省行为与当前版本完全一致。
- R4. 承载读写事实的扩展，在下游不具备必要能力时报错终止，不得静默降级。
- R5. 现有导出类型新增字段时保持既有零值语义不变。
- R6. 新增单方法可选接口，暴露客户端注册的重定向 URI 集合。
- R7. 该接口返回非空集合时，授权与令牌端点按集合逐条精确比较，保留 loopback 端口例外，且不受 `RedirectUriSeparator` 与 `EnforceOAuth21` 影响。
- R8. 新增单方法可选接口，暴露客户端的令牌端点认证方式，取值来自 RFC 7591 的 `token_endpoint_auth_method`。
- R9. 认证方式为 `none` 的客户端，可在令牌端点仅凭 `client_id` 完成识别。
- R10. 认证方式为非共享密钥方式时，共享密钥比较必须不通过，且不得判定为公开客户端。
- R11. 未表达认证方式时沿用现有判定：共享密钥为空即视为公开客户端。
- R12. `AccessData` 增加绑定承载位，零值表示未绑定。
- R13. 启用发件人约束时，零值绑定的令牌数据一律校验失败。
- R14. 存储侧能力扩展同样以可选接口表达，`Storage` 方法集不变。
- R15. `ServerConfig` 增加 issuer；配置后授权响应携带 `iss`，未配置时不输出。
- R16. 是否拒绝 `plain` 作为独立策略开关，默认保持现状。
- R17. 逐客户端注册事实由接口承载，`EnforceOAuth21` 只保留部署策略语义。
- R18. 公共契约在 v1 内永久有效，不存在把可选接口合并进主接口的窗口。
- R19. 未来的能力扩展只能以新增可选接口、新增导出类型或常量、导出结构体新增字段、`ServerConfig` 新增字段四种形式表达。

**Origin actors:** A1 (下游部署方), A2 (现有 `Client` / `Storage` 实现者), A3 (2.1 形态的客户端), A4 (库的后续实现者)

**Origin flows:** F1 (客户端注册事实解析), F2 (令牌绑定事实的持久化与校验)

**Origin acceptance examples:** AE1–AE9

---

## Scope Boundaries

- 不实现 DPoP proof 与 mTLS 证书的密码学校验，本次只定承载位与失败语义。
- 不实现刷新令牌重用检测的判定逻辑，本次只定存储侧扩展点。
- `ValidateUri` / `ValidateUriList` / `FirstUri` 的导出语义不变。
- `RequirePKCEForPublicClients` 保持读取 `GetSecret()` 的既有语义，不改为读取认证方式接口。
- implicit 与 ROPC 的移除不在本次范围，`AllowedAuthorizeTypes` / `AllowedAccessTypes` 已覆盖该策略。
- 授权服务器元数据与动态客户端注册端点不在本次范围。
- 破坏式变更不在任何版本的范围内。

---

## Context & Research

### Relevant Code and Patterns

- `client.go` — `Client` 四个必选方法与可选接口 `ClientSecretMatcher`；`DefaultClient` 与其 `CopyFrom`。新可选接口沿用 `ClientSecretMatcher` 的单方法形态与注释风格。
- `util.go` — `CheckClientSecret` 的类型分支；`getClientAuth` 中与 `EnforceOAuth21` 相关的免密钥回落分支。
- `access.go` — `getClient` 的客户端加载与密钥复核；`handleAuthorizationCodeRequest` 的 redirect_uri 比对；`FirstUri` 在 refresh / password / client_credentials / assertion 四条路径上的使用。
- `authorize.go` — `HandleAuthorizeRequest` 的注册 URI 读取、`FirstUri` 调用、`validateRedirectUri` 选择与 PKCE 分支。
- `urivalidate.go` — `ValidateUriList`（宽松）与 `validateUriListExact` / `validateUriExact` / `loopbackUriVariant`（严格）。
- `config.go` — `ServerConfig` 字段与 `NewServerConfig()` 的显式默认值列表。
- `storage_test.go` — `TestingStorage` 与 `NewTestingStorage()`，含 `1234`（有密钥）与 `public-client`（无密钥）两个客户端。
- `access_test.go` — `clientWithMatcher` / `clientWithoutMatcher` 两个测试替身，是验证可选接口探测与回退的现成模式。
- `example/teststorage.go` — 面向下游的存储实现示例，接口零改动时它必须保持可编译。

### Institutional Learnings

- 仓库没有 `docs/solutions/`，无历史经验条目可循。

### External References

- RFC 9700 §2.1（redirect URI 精确匹配）、§2.1.1（PKCE 强制与 S256）、§2.2.2 与 §4.14（刷新令牌保护）。
- RFC 7636 §4.3（`plain` 与 `S256`，以及 `code_challenge_method` 缺省为 `plain`）。
- RFC 9207（授权响应中的 `iss` 参数）。
- RFC 8252 §7.3（loopback 重定向的端口例外）。
- RFC 7591 与 IANA `token_endpoint_auth_method` 注册表。
- draft-ietf-oauth-v2-1-16 §7.5.2（`plain` 方法）——未能逐字核对，见 Open Questions。

---

## Key Technical Decisions

- 事实分治：只读事实走"可选接口 + 回退"，读写事实走"能力握手 + 报错"。两者不能共用一套兼容策略。
- 新增独立可选接口，不依赖给具体类型加方法：避免下游嵌入 `DefaultClient` 后定义同名方法的编译风险。
- 认证方式用定义字符串类型而非整数枚举：值域来自 RFC 7591 注册表且会增长，未识别值应能透传。
- 客户端事实解析收敛到单一入口：授权端点与令牌端点（含 refresh / password / client_credentials / assertion 四条路径）共用同一解析结果，避免同一事实出现第二份真相。
- 令牌绑定单独落一个启用开关，使 R13 可被测试覆盖；开关默认关闭。
- 拒绝 `plain` 是部署策略而非协议要求，单独开关，默认不变。

---

## Open Questions

### Resolved During Planning

- 令牌绑定这条线的落地程度：落承载位、存储能力握手与启用开关，不实现校验算法本身。
- 现有公开客户端判定的归属：`RequirePKCEForPublicClients` 保持读 `GetSecret()`，新接口只作用于新增路径。
- 可选接口的形态：两个独立单方法接口，客户端可只实现其中一个。

### Deferred to Implementation

- 绑定承载位的具体类型（值类型、指针或接口）：受"零值表示未绑定"这一约束限制，随实现确定。
- 存储能力探测的触发时机（构造服务器时、启用策略时或首次签发时）。
- 可选接口与结构体字段的确切命名。
- draft-ietf-oauth-v2-1-16 §7.5.2 的规范用词：抓取受限未逐字核对，若其要求与"拒绝 `plain` 是部署策略"冲突，需回改 R16。

---

## High-Level Technical Design

> *This illustrates the intended approach and is directional guidance for review, not implementation specification. The implementing agent should treat it as context, not code to reproduce.*

| 事实 | 客户端表达了 | 客户端未表达 |
|---|---|---|
| 重定向 URI | 集合接口返回值，逐条精确比较，保留 loopback 端口例外；忽略 separator 与 `EnforceOAuth21` | `GetRedirectUri()` 加 separator 拆分，比较函数由 `EnforceOAuth21` 决定 |
| 认证方式 | 接口返回值决定 `none` / 共享密钥 / 非共享密钥 | 共享密钥为空即公开客户端 |
| 令牌绑定 | 承载位有值 | 承载位为零值：策略开启时失败，关闭时不介入 |

---

## Implementation Units

### U1. 扩展 ServerConfig 的策略与身份字段

**Goal:** 提供 issuer、拒绝 `plain`、启用发件人约束三个配置项，作为后续单元的行为入口。

**Requirements:** R5, R15, R16

**Dependencies:** None

**Files:**
- Modify: `config.go`
- Modify: `README.md`
- Create: `config_test.go`

**Approach:**
- 新增 issuer 字段，空值表示不输出 `iss`。
- 新增拒绝 `plain` 的策略开关，默认值保持现状。
- 新增发件人约束启用开关，默认关闭。
- `NewServerConfig()` 中沿用现有显式默认值列表风格逐项写出。

**Patterns to follow:**
- `config.go` 中 `EnforceOAuth21` 的字段注释与默认值写法。

**Test scenarios:**
- Happy path: `NewServerConfig()` 返回的三个字段均为零值或 false，现有默认配置行为不变。
- Edge case: 显式配置 issuer 与两个开关后读取值不变，配置结构不引入副作用。
- Integration: 现有 `go test ./...` 在默认配置下全部通过。

**Verification:**
- 默认配置下库的对外行为与改动前一致；三个字段可被后续单元读取。

---

### U2. 新增客户端注册事实的可选接口与 DefaultClient 字段

**Goal:** 定义重定向 URI 集合与认证方式两个单方法可选接口，并让 `DefaultClient` 能承载这两项事实。

**Requirements:** R1, R2, R6, R8, R11, R19

**Dependencies:** U1

**Files:**
- Modify: `client.go`
- Modify: `client_test.go`

**Approach:**
- 定义认证方式为字符串类型，常量覆盖 `none`、`client_secret_post`、`client_secret_basic`、`client_secret_jwt`、`private_key_jwt`、`tls_client_auth`，未识别的值原样使用。
- 两个接口各含一个方法，允许客户端只实现其中一个。
- `DefaultClient` 在末尾追加集合字段与认证方式字段，旧字段保留；`CopyFrom` 一并复制新字段。
- 认证方式为空字符串表示未表达，由解析方回退到既有判定。

**Patterns to follow:**
- `client.go` 中 `ClientSecretMatcher` 的单方法可选接口形态与注释位置。
- `DefaultClient.CopyFrom` 的字段复制写法。

**Test scenarios:**
- Happy path: `DefaultClient` 同时满足两个新接口与 `Client`，编译期断言通过。
- Edge case: 只实现集合接口的测试替身类型可被探测为实现了集合接口、未实现认证方式接口。
- Edge case: 现有 `clientWithoutMatcher` 与 `clientWithMatcher` 未实现任一新接口，行为不变。
- Edge case: 认证方式字段为空字符串时，解析方判定为"未表达"。
- Integration: `CopyFrom` 复制新字段，源对象为零值时目标仍为零值。

**Verification:**
- 新接口与字段可被 U3、U4 使用；未实现新接口的既有类型编译与行为都不变。

---

### U3. 重定向 URI 集合的解析与匹配接入

**Goal:** 客户端实现集合接口时，授权与令牌端点按集合逐条精确匹配，忽略 separator 与 `EnforceOAuth21`。

**Requirements:** R2, R3, R6, R7, R17

**Dependencies:** U2

**Files:**
- Modify: `urivalidate.go`
- Modify: `authorize.go`
- Modify: `access.go`
- Test: `urivalidate_test.go`
- Test: `authorize_test.go`
- Test: `access_test.go`

**Approach:**
- 新增一个解析入口，输入客户端对象，输出"注册值列表"与"应使用的比较函数"，把两项事实绑在一起返回，避免调用点分别判断。
- 集合接口存在且返回非空集合时使用集合与精确比较；其余情况返回 `GetRedirectUri()` 与由 `EnforceOAuth21` 决定的现有比较函数。
- 授权端点与令牌端点的全部 `FirstUri` 使用点改走该入口，覆盖 refresh、password、client_credentials、assertion 四条路径。
- 精确比较复用 `validateUriExact` 与 loopback 例外，不新增第二套比较逻辑。

**Patterns to follow:**
- `authorize.go` 与 `access.go` 现有的 `validateRedirectUri` 变量选择写法。
- `urivalidate.go` 中 `validateUriListExact` 的列表遍历与错误类型约定。

**Test scenarios:**
- Happy path: **Covers AE2.** 客户端返回两条 URI，`RedirectUriSeparator` 非空且 `EnforceOAuth21` 为 false 时，请求集合内任一条都通过。
- Error path: **Covers AE2.** 请求"集合内 URI 追加子路径"被拒绝。
- Edge case: **Covers AE3.** 集合内含 `http://127.0.0.1/cb` 时，`http://127.0.0.1:49152/cb` 通过，`http://127.0.0.1:49152/cb/extra` 被拒绝。
- Edge case: 集合接口返回空集合时回退到 `GetRedirectUri()` 路径，行为与现状一致。
- Edge case: 集合含带 query 的 URI，请求 query 不同即被拒绝。
- Integration: refresh / password / client_credentials / assertion 四条路径上，集合客户端的默认 `redirect_uri` 取集合第一条且后续比对使用精确比较。
- Integration: 模式关闭时 `TestURIValidate`、`TestURIListValidate` 的既有断言全部保持通过。

**Verification:**
- 集合客户端在所有涉及注册 URI 的端点上只有一处判定来源；未实现集合接口的客户端行为与改动前逐字一致。

---

### U4. 客户端认证方式的接入

**Goal:** 认证方式为 `none` 的客户端可仅凭 `client_id` 完成令牌端点识别；非共享密钥方式不被当作公开客户端。

**Requirements:** R2, R8, R9, R10, R11

**Dependencies:** U2

**Files:**
- Modify: `util.go`
- Modify: `access.go`
- Test: `util_test.go`
- Test: `access_test.go`

**Approach:**
- 新增认证方式解析入口，返回三种结果：`none`、共享密钥、非共享密钥。客户端未表达认证方式时按共享密钥为空即 `none` 回退。
- `none` 时允许仅凭请求体 `client_id` 进入客户端查询，不再要求 `AllowClientSecretInParams`。
- 非共享密钥方式下共享密钥比较一律不通过，返回 `invalid_client`，且不得进入免密钥路径。
- `RequirePKCEForPublicClients` 的判定保持读取 `GetSecret()`，不接入新接口。
- `ClientSecretMatcher` 仍单独负责共享密钥的比较语义，本次不改其调用位置。

**Patterns to follow:**
- `util.go` 中 `CheckClientSecret` 的类型分支结构。
- `access.go` 中 `getClient` 现有的 `EnforceOAuth21` 免密钥复核分支与错误码选择。

**Test scenarios:**
- Happy path: **Covers AE4.** 认证方式为 `none` 且 `GetSecret()` 返回非空字符串的客户端，仅凭 `client_id` 在令牌端点识别成功。
- Happy path: 认证方式为共享密钥的客户端携带正确凭据时成功换取令牌。
- Error path: **Covers AE5.** 认证方式为非共享密钥且 `GetSecret()` 返回空串的客户端，仅凭 `client_id` 请求令牌时返回 `invalid_client`。
- Error path: 认证方式为非共享密钥的客户端携带任意共享密钥时同样失败。
- Edge case: **Covers AE6.** 未实现认证方式接口且共享密钥为空的客户端仍按公开客户端处理。
- Edge case: 未实现认证方式接口且共享密钥非空的客户端仍必须提供凭据。
- Integration: `AllowClientSecretInParams` 为 false 且 `EnforceOAuth21` 为 false 时，`none` 客户端仍可仅凭 `client_id` 识别。
- Error path: 既无凭据也无 `client_id` 的请求返回 `invalid_request`。

**Verification:**
- 三种认证方式各自走到预期的识别路径；未表达认证方式的客户端行为与改动前一致。

---

### U5. 令牌绑定承载位与存储能力握手

**Goal:** `AccessData` 能承载密钥绑定，且启用发件人约束时零值绑定必然失败、存储不具备持久化能力时立即报错。

**Requirements:** R4, R12, R13, R14

**Dependencies:** U1

**Files:**
- Modify: `access.go`
- Modify: `storage.go`
- Test: `access_test.go`
- Test: `storage_test.go`

**Approach:**
- 在 `AccessData` 末尾追加绑定承载位，零值表示未绑定；既有零值语义不变。
- 新增一个可选扩展接口表达"存储可持久化绑定"，`Storage` 方法集不变。
- 启用发件人约束时，在令牌被使用的位置判定：绑定为零值即失败，不静默放行。覆盖刷新令牌兑换与访问令牌查询两条路径。
- 存储能力握手的位置按 Open Questions 的取向在实现期确定，但必须具备"不可用即报错"的可见失败。

**Patterns to follow:**
- `access.go` 中 `handleRefreshTokenRequest` 的校验块与错误码分工。
- `info.go` 中 `HandleInfoRequest` 的访问令牌校验顺序。
- `storage.go` 的接口注释风格。

**Test scenarios:**
- Happy path: 开关关闭时，绑定为空的令牌照常兑换与查询，行为与现状一致。
- Error path: **Covers AE7.** 开关开启、存储未持久化绑定（重新加载后为零值）时，刷新兑换返回 `invalid_grant` 且不签发新令牌。
- Error path: **Covers AE7.** 开关开启时，绑定为零值的访问令牌查询被拒绝。
- Edge case: 承载位为有值时，开关开启不影响正常流程。
- Integration: **Covers R4.** 存储未实现扩展接口且开关开启时，库以可见错误终止，不退化为无约束令牌。
- Integration: 现有 `TestingStorage` 与 `example/teststorage.go` 在不修改方法集的情况下编译通过。

**Verification:**
- 启用策略且存储不具备能力时，失败可见；未启用时既有路径逐字不变。

---

### U6. 授权响应携带 iss

**Goal:** 配置 issuer 后授权响应包含 `iss`，未配置时不输出。

**Requirements:** R15

**Dependencies:** U1

**Files:**
- Modify: `authorize.go`
- Modify: `response.go`
- Test: `authorize_test.go`
- Test: `response_json_test.go`

**Approach:**
- 在授权响应的输出组装处注入 `iss`，覆盖成功重定向与错误响应两条路径。
- 未配置 issuer 时不写入该参数，保持现状。
- 非重定向的数据型错误响应不携带 `iss`，与 RFC 9207 的适用范围一致。

**Patterns to follow:**
- `response.go` 中 `SetErrorUri` 与 `GetRedirectUrl` 的输出组装顺序。
- `authorize.go` 中 `FinishAuthorizeRequest` 的 `w.Output` 写入位置。

**Test scenarios:**
- Happy path: **Covers AE8.** 配置 issuer 后授权成功重定向的 query 中包含 `iss` 且值等于配置值。
- Happy path: **Covers AE8.** 配置 issuer 后授权错误重定向同样包含 `iss`。
- Edge case: 未配置 issuer 时成功与错误响应都不含 `iss`。
- Edge case: 数据型错误响应（非重定向）不含 `iss`。

**Verification:**
- issuer 配置的有无是 `iss` 输出的唯一开关，现有响应结构不受影响。

---

### U7. 拒绝 plain 的策略开关

**Goal:** 策略开启后拒绝 `code_challenge_method=plain` 的授权请求。

**Requirements:** R16

**Dependencies:** U1

**Files:**
- Modify: `authorize.go`
- Test: `authorize_test.go`

**Approach:**
- 在现有 PKCE 方法校验分支中纳入该策略；仅拒绝显式或隐式落到 `plain` 的请求。
- 默认关闭时 `plain` 与缺省方法的行为保持不变。
- 拒绝时的错误码沿用现有参数层违规的分工。

**Patterns to follow:**
- `authorize.go` 中 `code_challenge_method` 取值校验分支与 `SetErrorState` 的用法。

**Test scenarios:**
- Happy path: **Covers AE9.** 默认配置下 `code_challenge_method=plain` 的请求照常通过。
- Error path: **Covers AE9.** 开关开启时 `code_challenge_method=plain` 的请求返回 `invalid_request`，不下发授权码。
- Edge case: 开关开启时省略 `code_challenge_method`（RFC 7636 缺省为 `plain`）同样被拒绝。
- Edge case: 开关开启时 `code_challenge_method=S256` 的请求照常通过。

**Verification:**
- 开关关闭时既有 PKCE 用例全绿；开启后不存在落到 `plain` 的授权码。

---

### U8. 文档与变更记录

**Goal:** 在 README 与 CHANGELOG 记录新接口、兼容承诺与升级注意事项。

**Requirements:** R18, R19

**Dependencies:** U2, U3, U4, U5, U6, U7

**Files:**
- Modify: `README.md`
- Modify: `CHANGELOG`

**Approach:**
- README 说明两个可选接口的语义、发件人约束与 issuer 开关的适用场景，以及"实现集合接口即精确匹配"的规则。
- CHANGELOG 记录附加式变更、v1 永久兼容承诺，以及无键结构体字面量构造 `DefaultClient` 的编译风险。

**Test expectation:** none -- 纯文档变更，无行为改动。

**Verification:**
- 下游可从 README 判断自己的客户端是否需要改动，且明确知道不改也能编译。

---

## System-Wide Impact

- **Interaction graph:** 授权端点与令牌端点（含四条非授权码路径）共用客户端事实解析入口；`util.go` 与 `access.go` 共享认证方式判定，避免同一事实出现两处判断。
- **Error propagation:** 认证方式与复用事实的失败走既有 `invalid_client` / `invalid_grant` 分工；存储能力不足走可见错误，不静默降级。
- **State lifecycle risks:** `AccessData` 是库写、下游存储持久化的结构，新增承载位对下游自研序列化是运行期风险；靠"零值即失败"把静默丢数据转成显式错误。
- **API surface parity:** `Client` / `Storage` 方法集不变；`DefaultClient` 与 `AccessData` 追加字段；`ServerConfig` 追加字段。
- **Integration coverage:** 授权到令牌的完整链路需要验证集合客户端与 `none` 客户端的端到端行为，单端点桩覆盖不到。
- **Unchanged invariants:** `ValidateUri*` 与 `FirstUri` 的导出语义、`RequirePKCEForPublicClients` 的判定依据、`EnforceOAuth21` 关闭时的全部行为。

---

## Risks & Dependencies

| Risk | Mitigation |
|------|------------|
| 无键结构体字面量构造 `DefaultClient` 的下游编译失败 | 属 Go 兼容承诺排除项，CHANGELOG 注明；仓库内已全部使用带键字面量 |
| 下游嵌入 `DefaultClient` 并定义同名方法时新增方法引发编译冲突 | 本次只新增独立接口与字段，不给具体类型加方法 |
| `AccessData` 承载位被下游存储静默丢弃 | 用"零值即失败"把静默降级转成显式错误，并配对应测试 |
| 集合接口的引入让同一部署出现两套匹配语义 | 事实与比较函数绑定在同一解析结果里返回，调用点无法分别选择 |
| 非共享密钥客户端被误判为公开客户端 | 认证方式解析返回三态，非共享密钥方式在共享密钥比较上直接失败 |
| draft-ietf-oauth-v2-1-16 §7.5.2 的要求与"拒绝 `plain` 属部署策略"冲突 | 抓取受限未核实，列入 Open Questions，冲突时回改 R16 |

---

## Documentation / Operational Notes

- 本计划不改变任何默认行为，下游升级后可先不动代码，再按客户端逐个接入可选接口。
- 发件人约束与拒绝 `plain` 均为默认关闭的部署策略，开启前需确认下游存储已具备持久化绑定的能力。

---

## Sources & References

- **Origin document:** [docs/brainstorms/2026-09-18-oauth21-interface-upgrade-requirements.md](docs/brainstorms/2026-09-18-oauth21-interface-upgrade-requirements.md)
- Related recommendation: [docs/recommendations/2026-09-18-client-registration-accessors.md](docs/recommendations/2026-09-18-client-registration-accessors.md)
- Prior plan: [docs/plans/2026-09-18-001-feat-oauth21-enforcement-plan.md](docs/plans/2026-09-18-001-feat-oauth21-enforcement-plan.md)
- Related code: `client.go`, `util.go`, `access.go`, `authorize.go`, `urivalidate.go`, `config.go`, `storage.go`, `response.go`
- External docs: [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700), [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636), [RFC 9207](https://www.rfc-editor.org/rfc/rfc9207), [RFC 8252 §7.3](https://www.rfc-editor.org/rfc/rfc8252#section-7.3), [draft-ietf-oauth-v2-1](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/)
