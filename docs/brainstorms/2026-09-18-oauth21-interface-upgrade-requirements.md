---
date: 2026-09-18
topic: oauth21-interface-upgrade
---

# OAuth 2.1 接口与结构升级（兼容优先）

## Summary

为 OAuth 2.1 完整实现升级 osin 的公共接口与结构：客户端的注册事实改由新增的可选接口承载，令牌的绑定事实改由带显式握手的扩展点承载，服务器的身份与策略收进 `ServerConfig`。所有新增能力以附加方式表达，已有 `Client` / `Storage` 实现无需改动即可编译，且未实现新接口时的行为与当前版本完全一致。

---

## Problem Frame

`EnforceOAuth21` 已经覆盖了授权码流程的三处基线行为，但 2.1 的其余部分在库的公共面上无处表达，缺口集中在三个位置：

- **客户端注册事实过窄。** `GetSecret() string` 同时承担"没有共享密钥"和"共享密钥是空串"两种含义，表达不了 `private_key_jwt`、`tls_client_auth` 这类有密钥材料但无共享密钥的形态；`GetRedirectUri() string` 只能装一条 URI，集合要靠 `ServerConfig.RedirectUriSeparator` 拼串表达，于是客户端的线上表示变成了服务端配置项。下游因此派生自己的类型来承载差异（如 staffio 的 `CimdClient`），并在每次解析时做类型断言。
- **令牌绑定事实无处存放。** DPoP / mTLS 要求服务器把密钥绑定持久化到令牌记录上，重用检测要求能吊销整条刷新令牌链，而 `AccessData` 与 `Storage` 都没有承载位。
- **服务器身份无处配置。** 没有 issuer，授权响应无法按 RFC 9207 返回 `iss`。

约束来自库的形态：下游已经实现了 `Client` 与 `Storage`，而 Go 接口是结构化的，给这两个接口加方法会让所有外部实现编译失败。同时 `AccessData` 是库写、下游存储持久化的结构，给它加字段对下游自研序列化是运行期风险而非编译期风险。因此"能不能升级"不是问题，**"哪一类事实用哪一种兼容策略"**才是。

---

## Actors

- A1. 下游部署方：把 osin 集成进授权服务器，决定开启哪些 2.1 策略。
- A2. 现有 `Client` / `Storage` 实现者：不修改自己的代码即可继续编译与运行。
- A3. 2.1 形态的客户端：注册的是 URI 集合、以 `none` 或非共享密钥方式认证，可能使用发件人约束令牌。
- A4. 库的后续实现者：在本次定下的扩展点上实现 DPoP / mTLS / 重用检测。

---

## Key Flows

- F1. 客户端注册事实解析
  - **Trigger:** 授权端点或令牌端点需要判断"这个客户端注册了哪些重定向 URI、以什么方式认证"。
  - **Actors:** A2, A3
  - **Steps:** 对客户端对象做扩展能力探测；命中新增可选接口时用其返回值；未命中时回退到 `GetSecret()` / `GetRedirectUri()` 与既有配置。
  - **Outcome:** 每条事实只有一处判定来源；同一个部署里新旧客户端可以并存并按客户端逐个迁移。
  - **Covered by:** R1, R2, R3, R6–R11

- F2. 令牌绑定事实的持久化与校验
  - **Trigger:** 启用发件人约束时签发或使用令牌。
  - **Actors:** A1, A4
  - **Steps:** 签发前确认存储具备持久化绑定的能力；把绑定写入令牌记录；令牌被再次使用时读取绑定并校验。
  - **Outcome:** 不具备持久化能力的部署在启用策略时立即失败，不会退化成无约束的 Bearer 令牌。
  - **Covered by:** R4, R12–R14

---

## Requirements

**兼容机制**

- R1. `Client` 与 `Storage` 的方法集保持不变；所有新增能力以新的可选接口表达。
- R2. 库内通过类型断言探测可选接口的实现情况，未实现时回退到现有访问器。
- R3. 承载只读事实的扩展，其缺省行为必须与当前版本完全一致。
- R4. 承载读写事实的扩展，在下游不具备必要能力时必须报错终止，不得静默降级。
- R5. 现有导出类型新增字段时保持既有零值语义不变。

**客户端注册事实**

- R6. 新增单方法可选接口，用于暴露客户端注册的重定向 URI 集合。
- R7. 该接口返回非空集合时，授权端点与令牌端点对这一客户端的匹配按集合逐条精确比较，保留 loopback 端口例外，且不再受 `RedirectUriSeparator` 与 `EnforceOAuth21` 影响。
- R8. 新增单方法可选接口，用于暴露客户端的令牌端点认证方式，取值为 RFC 7591 的 `token_endpoint_auth_method` 字符串。
- R9. 认证方式为 `none` 的客户端，可在令牌端点仅凭 `client_id` 完成识别。
- R10. 认证方式为 `private_key_jwt`、`tls_client_auth` 等非共享密钥方式时，共享密钥比较必须不通过，且该客户端不得被判定为公开客户端。
- R11. 未表达认证方式时沿用现有判定：共享密钥为空即视为公开客户端。

**令牌绑定事实**

- R12. `AccessData` 增加绑定承载位，其零值表示未绑定。
- R13. 启用发件人约束时，零值绑定的令牌数据一律校验失败。
- R14. 存储侧的能力扩展同样以可选接口表达，`Storage` 方法集不变。

**服务器身份与策略**

- R15. `ServerConfig` 增加 issuer；配置后授权响应携带 `iss`（RFC 9207），未配置时不输出。
- R16. 是否拒绝 `plain` 作为独立策略开关，默认保持现状。
- R17. 逐客户端的注册事实由接口承载，`EnforceOAuth21` 只保留"无法从客户端推断的部署策略"语义。
- R18. 库的公共契约在 v1 内永久有效：不存在把新增可选接口合并进 `Client` / `Storage` 主接口的破坏式变更窗口。
- R19. 未来的 2.1 能力扩展只能以新增可选接口、新增导出类型或常量、导出结构体新增字段、`ServerConfig` 新增字段这四种形式表达；无法用这四种形式表达的能力必须重新设计，而不是修改既有接口。

---

## Acceptance Examples

- AE1. **Covers R1, R2, R3.** 现有仓库内与下游的 `Client` / `Storage` 实现在不修改一行代码的情况下编译通过；未实现任何新接口时，授权、令牌、URI 校验与客户端认证行为与升级前一致。
- AE2. **Covers R6, R7.** 客户端实现集合接口并返回两条 URI；`RedirectUriSeparator` 非空、`EnforceOAuth21` 为 false 时，请求集合内的任一条都通过，请求"集合内 URI 追加子路径"被拒绝。
- AE3. **Covers R7.** 客户端注册 `http://127.0.0.1/cb`，请求 `http://127.0.0.1:49152/cb` 通过；请求 `http://127.0.0.1:49152/cb/extra` 被拒绝。
- AE4. **Covers R8, R9.** 认证方式为 `none` 的客户端，即使 `GetSecret()` 返回非空字符串，仍可仅凭 `client_id` 在令牌端点完成识别。
- AE5. **Covers R10.** 认证方式为 `private_key_jwt` 且 `GetSecret()` 返回空串的客户端，仅凭 `client_id` 请求令牌时被拒绝，不得走公开客户端路径。
- AE6. **Covers R11.** 未实现认证方式接口且共享密钥为空的客户端，仍按公开客户端处理，行为与当前版本一致。
- AE7. **Covers R4, R12, R13.** 启用发件人约束、但存储未持久化绑定（重新加载后绑定为零值）时，令牌校验失败且错误可见，不签发也不接受该令牌。
- AE8. **Covers R15.** 配置 issuer 后，授权成功响应与授权错误响应都携带 `iss`；未配置时不出现该参数。
- AE9. **Covers R16.** 默认配置下，携带 `code_challenge_method=plain` 的请求仍按当前行为通过；开启该策略开关后被拒绝。

---

## Success Criteria

- 下游在不修改 `Client` / `Storage` 实现的前提下升级本库，编译与运行行为均不变。
- 新接入的 2.1 客户端可以通过实现可选接口获得精确匹配与 `none` 认证，而不需要改动服务端全局配置。
- 引入发件人约束时，不具备持久化能力的存储会让部署立即失败，而不是静默退化成无约束令牌。
- 后续实现 DPoP / mTLS / 重用检测时，不需要再改动公共接口的方法集。

---

## Scope Boundaries

- DPoP proof 与 mTLS 证书的密码学校验不在本次范围，本次只定接口落点与失败语义。
- 刷新令牌重用检测的判定逻辑不在本次范围，本次只定存储侧的扩展点。
- `ValidateUri` / `ValidateUriList` / `FirstUri` 的导出语义不变。
- implicit 与 ROPC 的移除不在本次范围，`AllowedAuthorizeTypes` / `AllowedAccessTypes` 已覆盖该策略。
- 授权服务器元数据与动态客户端注册端点不在本次范围。
- 破坏式变更不在任何版本的范围内：本库不设"合并可选接口进主接口"的窗口。

---

## Key Decisions

- 新增可选接口而非给主接口加方法：Go 接口结构化，加方法即破坏所有外部实现；可选接口是本库既有模式（`ClientSecretMatcher`）的延续。由于库长期停留在 v1，这不是过渡形态而是长期契约。
- 按"只读事实 / 读写事实"分治兼容策略：只读事实缺省即安全，可以用回退；读写事实缺省即不安全，必须报错。
- 认证方式用定义字符串类型而非整数枚举：值域来自 RFC 7591 注册表且会继续增长，未识别的值应能原样透传。
- 拒绝 `plain` 做成策略开关：RFC 9700 §2.1.1 对服务器只提出 "MUST support PKCE"，未要求拒绝 `plain`，因此这不是协议要求而是部署选择。
- 不新增客户端类型判别字段、公开客户端布尔字段或逐客户端精确匹配开关：三者都能从认证方式与注册形态推导，属于第二份真相。

---

## Dependencies / Assumptions

- 假设下游确实存在 `Client` / `Storage` 的外部实现，因此不能给这两个接口加方法。
- 假设本库长期停留在 v1 大版本，不存在破坏式变更窗口；所有升级必须在保持既有 `Client` / `Storage` 方法集不变的前提下完成。
- RFC 9700 §2.1.1 已逐字核对：公开客户端 MUST 使用 PKCE，机密客户端 RECOMMENDED，客户端 SHOULD 使用不暴露 verifier 的方法（当前只有 S256），授权服务器 MUST 支持 PKCE。
- 未核实的假设：draft-ietf-oauth-v2-1-16 §7.5.2 对 `plain` 的规范用词未能逐字确认（ietf.org 与 datatracker 均返回 403，仅抓到 "The plain method offers no protection against authorization code interception..." 一句）。
- 风险：下游若用无键结构体字面量构造 `DefaultClient`，新增字段会导致编译失败；这是 Go 兼容承诺排除的情形，需在 CHANGELOG 注明。
- 未核实的假设：给具体类型（如 `DefaultClient`）新增方法，对"下游嵌入该类型并定义同名方法"的代码是否存在编译风险；本次已通过"新增独立可选接口、不依赖给具体类型加方法"规避该问题，具体边界由规划阶段核实。

---

## Outstanding Questions

### Deferred to Planning

- [Affects R12][Technical] 绑定承载位的类型选择：值类型字段、指针还是接口，以及零值语义如何表达"未绑定"。
- [Affects R4, R14][Technical] 存储侧能力探测的时机：构造服务器时自检、启用策略时自检，还是首次签发时判定。
- [Affects R10][Technical] 非共享密钥认证方式的客户端在既有 `ClientSecretMatcher` 路径上的交互细节。
- [Affects R15][Technical] `iss` 在授权错误响应中的出现条件，以及 issuer 为空时的回退表现。
- [Affects R17][Technical] `EnforceOAuth21` 收缩后与 `RequirePKCEForPublicClients`、精确匹配路径的兼容关系。
