---
date: 2026-09-18
topic: client-registration-accessors
status: proposed
---

# 扩展 client 注册访问器：认证方式与 redirect URI 集合

## Summary

`Client` 的 4 个必选方法里，`GetSecret() string` 与 `GetRedirectUri() string` 是两个过窄的表示：前者无法区分"没有密钥"与"密钥为空"，也表达不了公私钥认证；后者只能装一条 URI，集合要靠 `ServerConfig.RedirectUriSeparator` 拼串表达，比较语义又要靠 `EnforceOAuth21` 全局切换。建议把这两处差异升级为 **必选 0 个、可选 2 个**：新增 `RegisteredRedirectURIs() []string` 与 `AuthMethod() TokenEndpointAuthMethod` 两个可选接口，`DefaultClient` 相应增加 2 个字段，旧实现与旧路径不改一行。

---

## Problem Frame

现有 `Client`：`GetId() string`、`GetSecret() string`、`GetRedirectUri() string`、`GetUserData() any`，外加可选的 `ClientSecretMatcher`。两个真实客户端的形状差距落在它身上：

| 维度 | 手工注册的 client | 预注册 Client Identifier URL 的 client |
|---|---|---|
| 凭据 | 有 secret | 无共享密钥（`token_endpoint_auth_method: none`） |
| redirect | 单条，历史语义为同 host 子路径前缀匹配 | 元数据文档里的 URI 集合，逐条全等（RFC 9700） |

具体症状：

1. `GetSecret() == ""` 同时承担"没有密钥"和"密钥是空串"两种含义，且 `private_key_jwt`、`tls_client_auth` 这类既有公钥又无共享密钥的形态无处表达；下游只能额外实现 `ClientSecretMatcher` 来声明"我是公开客户端"。
2. 单值访问器装不下集合，于是引入 `RedirectUriSeparator`：客户端的线上表示变成服务端配置项，调用方被迫"拼接成字符串、再由库拆开"。
3. 比较语义（前缀 vs 全等）与注册形态（单值 vs 集合）本该绑定，现在分别落在客户端返回的字符串和 `ServerConfig` 开关上，同一份服务端代码要按部署而不是按客户端分流。
4. 下游因此派生自己的类型来承载这些差异（例如 staffio 的 `CimdClient`），并在每次解析时做类型断言；差异本身没有进入库的契约。

---

## Recommendation（字段数与字段类型）

| 事实 | 现在的编码 | 建议类型 | 理由 |
|---|---|---|---|
| 客户端如何认证 | `GetSecret() string` + 是否实现 `ClientSecretMatcher` | `AuthMethod() TokenEndpointAuthMethod`，`type TokenEndpointAuthMethod string` + 常量 | 字符串能表达 `none` 与 `private_key_jwt`，`""` 不能；用定义字符串类型而不是 int 枚举，因为它本来就是 RFC 7591 元数据里的值，且注册表会继续加值，未识别的值可原样透传 |
| 注册了哪些 redirect | `GetRedirectUri() string`（+ 全局 `RedirectUriSeparator`） | `RegisteredRedirectURIs() []string` | 切片能区分空/一条/多条，语义就是注册集合；顺带消掉"拼接—拆分"往返与 separator 配置 |
| 如何比较 | 全局 `EnforceOAuth21` | 不新增字段：实现集合访问器即逐条全等（含 RFC 8252 §7.3 的 loopback 端口例外），只实现旧的单值访问器即维持前缀匹配 | 语义已绑定在注册形态上；再加 `ExactMatch bool` 就是同一事实的第二份真相 |
| 传递任意数据 | `GetUserData() any` | 不变 | 已是任意类型的透传通道，无需拆分 |

字段数变化：

- `Client`：4 个必选方法 → 4 个必选方法（**接口不新增方法**）。
- 可选接口：+2（`RegisteredRedirectURIs`、`ClientAuthMethod`），均为单方法接口，可以只实现其中一个。
- `DefaultClient`：4 个字段 → 6 个（新增 `RedirectURIs []string`、`AuthMethod TokenEndpointAuthMethod`），`RedirectUri` 与 `Secret` 保留为旧式写法。

类型选择上刻意避开三种做法：不新增 `Kind`/`Type` 判别字段，不新增 `IsPublic bool`（等价于 `AuthMethod() == none`），不新增每客户端的 `ExactMatch bool`（等价于"是否实现集合访问器"）。

---

## Interface Sketch

```go
// TokenEndpointAuthMethod 是 RFC 7591 的 token_endpoint_auth_method 取值。
type TokenEndpointAuthMethod string

const (
	AuthMethodNone             TokenEndpointAuthMethod = "none"
	AuthMethodClientSecretPost TokenEndpointAuthMethod = "client_secret_post"
	AuthMethodClientSecretJWT  TokenEndpointAuthMethod = "client_secret_jwt"
	AuthMethodPrivateKeyJWT    TokenEndpointAuthMethod = "private_key_jwt"
	AuthMethodTLSClientAuth    TokenEndpointAuthMethod = "tls_client_auth"
)

// RegisteredRedirectURIs 表示客户端注册的是一个 URI 集合，服务端逐条做
// 不透明字符串比较。
type RegisteredRedirectURIs interface {
	RegisteredRedirectURIs() []string
}

// ClientAuthMethod 覆盖 GetSecret()=="" 这一启发式。
type ClientAuthMethod interface {
	AuthMethod() TokenEndpointAuthMethod
}
```

`DefaultClient` 增加两个字段（放在末尾）：

```go
type DefaultClient struct {
	Id          string
	Secret      string
	RedirectUri string // 旧式单值注册
	UserData    any

	RedirectURIs []string                // 新式集合注册，优先于 RedirectUri
	AuthMethod   TokenEndpointAuthMethod // 空值表示沿用 GetSecret() 判定
}
```

---

## Resolution Order（前后兼容规则）

1. 实现 `RegisteredRedirectURIs` 且返回非空集合：使用该集合，逐条全等比较（loopback 端口例外），忽略 `RedirectUriSeparator` 与前缀匹配。
2. 否则回退到 `GetRedirectUri()`：按 `RedirectUriSeparator` 拆分（为空则单值），匹配器由 `EnforceOAuth21` 决定——与今天完全一致。
3. 实现 `ClientAuthMethod`：由其返回值判定公开/机密与令牌端点识别方式。
4. 否则回退：`CheckClientSecret(client, "")` 为真视为 `none`，否则按共享密钥处理；`ClientSecretMatcher` 继续负责密钥比较本身。
5. `EnforceOAuth21` 保留，但作用域收缩为"无法从客户端推断的部署策略"：是否要求机密客户端也走 PKCE、授权码是否必须绑定 `code_challenge`。per-client 的事实搬进类型，配置只留策略。

---

## Compatibility

- 只新增可选接口与结构体字段；`Client` 的方法集不变，外部实现零改动，默认行为不变。
- 唯一理论破坏点：别的模块若用**无键结构体字面量**构造 `DefaultClient`，增加字段后会编译失败。这是 Go 兼容承诺明确排除的一项（`go vet` 的 composites 检查就是为它准备的），在 CHANGELOG 注明即可；仓库内测试已使用带键字面量。
- 版本节奏：作为附加式变更进入 v1.2.0；不得在 v1 内给 `Client` 加方法，破坏式调整留到 v2。
- 测试覆盖：两个访问器各自的正反用例、两处回退路径、以及"集合访问器存在时忽略 separator 与 `EnforceOAuth21`"的断言。

---

## Alternatives Considered

- **给 `Client` 加方法**：破坏所有外部实现，v1 内不可行。
- **加 `Kind` / `Type` 判别字段**：把差异变成每个消费点都要读的字符串，编译器无法保证覆盖完整。
- **`IsPublic bool` 或每客户端 `ExactMatch bool`**：都是可从既有事实推导的第二份真相，必然与认证方式或注册形态漂移。
- **继续用 `RedirectUriSeparator` 表达集合**：把线上表示塞进服务端配置，调用方还得自行拼接，本次 CIMD 实现即为实例。
- **直接发布 v2 改接口**：把全部下游实现拖进同一个破坏性变更，收益不抵成本。

---

## Downstream Impact

以 staffio 为例（`pkg/backends/cimd_client.go`、`pkg/web/server.go`）：

- CIMD 适配类型：`GetRedirectUri()` 换成 `RegisteredRedirectURIs()`，另加 `AuthMethod() = none`；`CimdRedirectURISeparator` 与 `RedirectUriSeparator` 一并删除，约 -10 行。
- 手工客户端类型：今天零改动；将来若要把它也切到精确匹配，只需加一行 `RegisteredRedirectURIs() []string { return []string{c.RedirectURI} }`，按类型迁移而不必再动全局开关。
- 服务端分流：由"按 `EnforceOAuth21` 选择 profile"简化为"由客户端实现决定"，`EnforceOAuth21` 仅保留授权码流程的策略部分。

---

## References

- RFC 9700 §2.1（redirect URI 精确匹配）、§2.2（公开客户端与刷新令牌约束）
- RFC 8252 §7.3（loopback 端口例外）
- RFC 7591 / IANA `token_endpoint_auth_method` 注册表
- draft-ietf-oauth-client-id-metadata-document（Credential and Key Material Restrictions）
- 相关文档：`docs/plans/2026-09-18-001-feat-oauth21-enforcement-plan.md`、`docs/brainstorms/2026-09-17-oauth21-enforcement-requirements.md`
