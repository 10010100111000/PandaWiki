# Panda-Wiki 白盒安全代码审查报告 (基于 OWASP WSTG)

## 执行摘要 (Executive Summary)
本次安全审查针对提供的 web 应用（Panda-Wiki）代码库进行了静态白盒分析，重点评估了后端身份认证、授权、前端存储及会话管理等模块，分析基准为 OWASP Web Security Testing Guide (WSTG) 和 OWASP Top 10 (2021)。
整体安全状况评级为 **中等 (Medium)**。代码中实现了基于 JWT 和 Session 的认证体系，使用 bcrypt 进行密码哈希，并在分享页面有基本的授权检验（EnterpriseAuth / SimpleAuth），以及登录请求频率限制 (Rate Limiting) 防护。然而，系统在前端凭证存储和部分 XSS 渲染机制上存在潜在高危风险。此外，后端存在由于权限验证中间件配置潜在不当而导致的越权风险。

| 严重级别 | 发现数量 |
| -------- | -------- |
| 严重 (Critical) | 0 |
| 高危 (High) | 2 |
| 中危 (Medium) | 2 |
| 低危/信息 (Low/Info) | 1 |

---

## 漏洞发现汇总表 (Findings Summary Table)

| ID | 漏洞类别 (Category) | 严重级别 | 位置 (Location) | 优先级 |
|---|---|---|---|---|
| VULN-001 | WSTG-INPV-02 + A03:2021 注入 (跨站脚本 XSS) | 高危 (High) | `web/app/src/components/markdown2/thinkingRenderer.tsx` + `web/app/src/app/layout.tsx` | 1 |
| VULN-002 | WSTG-ATHN-06 + A04:2021 不安全设计 (不安全的凭证存储) | 高危 (High) | `web/admin/src/utils/fetch.ts`, `web/admin/src/pages/login/index.tsx` 等多处前端文件 | 2 |
| VULN-003 | WSTG-ATHZ-02 + A01:2021 失效的访问控制 (越权风险) | 中危 (Medium) | `backend/middleware/jwt.go` (`ValidateUserRole` 和 `ValidateKBUserPerm`) | 3 |
| VULN-004 | WSTG-SESS-02 + A05:2021 安全配置错误 (会话 Cookie 属性) | 中危 (Medium) | `backend/middleware/session.go` (`SessionMiddleware`) | 4 |
| VULN-005 | WSTG-ERRH-01 + A05:2021 安全配置错误 (错误信息泄露风险) | 低危 (Low) | `backend/server/http/http.go` (Request Logger) 和 `backend/handler/base.go` | 5 |

---

## 详细漏洞分析 (Detailed Findings)

### VULN-001: 前端 `dangerouslySetInnerHTML` 潜在跨站脚本 (XSS) 漏洞
*   **Vulnerability ID:** VULN-001
*   **Category:** WSTG-INPV-02 (Testing for Stored Cross Site Scripting) + A03:2021 – Injection
*   **Description:** 前端多处使用 React 的 `dangerouslySetInnerHTML` 渲染不受信任的内容（特别是 Markdown / AI 思考内容），且代码中未发现明显的输入清理（Sanitization）逻辑（如使用 DOMPurify）。如果 AI 输出或 Markdown 内容包含恶意的 `<script>` 标签或 HTML 属性，可能导致 XSS 攻击。
*   **Location:**
    *   `web/app/src/components/markdown2/thinkingRenderer.tsx` 第 53 行
    *   `web/app/src/app/layout.tsx` 第 102 行
*   **Severity:** 高危 (High)。如果是管理员或大模型生成不可控的恶意载荷，受害者在浏览页面时会执行恶意脚本，导致会话劫持。
*   **Evidence:**
    ```typescript
    // thinkingRenderer.tsx
    <div
      className={`think-inner ${!showThink ? 'three-ellipsis' : ''}`}
      style={{ /* ... */ }}
      dangerouslySetInnerHTML={{ __html: content }} // 未发现对 content 的清理
    />
    ```
*   **Potential Impact:** 攻击者可通过植入恶意脚本获取用户 Token，执行越权操作，或者实施网络钓鱼。
*   **Remediation:** 引入 `DOMPurify` 或类似的安全 HTML 清理库，在传递给 `dangerouslySetInnerHTML` 之前对 `content` 进行深度净化。
    ```typescript
    import DOMPurify from 'dompurify';
    // ...
    dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(content) }}
    ```

### VULN-002: 不安全的前端凭证存储 (Token 存储于 localStorage)
*   **Vulnerability ID:** VULN-002
*   **Category:** WSTG-ATHN-06 (Testing for Vulnerable Remember Password) + A04:2021 – Insecure Design / A01:2021 – Broken Access Control
*   **Description:** 应用在登录成功后，将 JWT 令牌 (`panda_wiki_token`) 以明文形式存储在浏览器的 `localStorage` 中。`localStorage` 可以被任何在同源下执行的 JavaScript 脚本访问，因此如果发生 XSS 攻击（如 VULN-001），攻击者可轻易窃取用户认证令牌。
*   **Location:** `web/admin/src/pages/login/index.tsx` 第 31 行；`web/admin/src/api/request.ts` 第 24 行；`web/admin/src/utils/fetch.ts` 第 56 行等多处前端代码。
*   **Severity:** 高危 (High)。它极大地放大了 XSS 漏洞的危害，使会话劫持变得异常简单。
*   **Evidence:**
    ```typescript
    // web/admin/src/pages/login/index.tsx
    localStorage.setItem('panda_wiki_token', res.token!);

    // web/admin/src/utils/fetch.ts
    const token = localStorage.getItem('panda_wiki_token') || '';
    ```
*   **Potential Impact:** 一旦前端出现任何一个 XSS 漏洞，攻击者无需与后端交互即可直接盗取并复用用户 Token，完全控制用户甚至管理员账号。
*   **Remediation:** 停止使用 `localStorage` 存储敏感的访问令牌。推荐改用后端设置的、带有 `HttpOnly`, `Secure` 和 `SameSite` 属性的 Cookie 来进行基于 API 的会话状态维持。

### VULN-003: JWT 与 API Token 权限验证混用带来的潜在越权风险
*   **Vulnerability ID:** VULN-003
*   **Category:** WSTG-ATHZ-02 (Testing for Bypassing Authorization Schema) + A01:2021 – Broken Access Control
*   **Description:** 在 `backend/middleware/jwt.go` 中，系统支持两种类型的 Bearer Token：普通的 JWT 和 API Token。验证 API Token 时，上下文会被标记为 `IsToken: true`，此时跳过数据库中的真实 Role 验证。如果在业务接口的配置中，未严格使用 `ValidateUserRole(consts.UserRoleAdmin)` 拦截（`ValidateUserRole` 内部会阻挡 token 执行 admin 角色），仅仅依赖于 `MustGetUserID`，API Token 可能会被误当做普通用户执行某些敏感操作。
*   **Location:** `backend/middleware/jwt.go` (方法 `validateAPIToken`, `ValidateUserRole`, `ValidateKBUserPerm`)
*   **Severity:** 中危 (Medium)。依赖于具体的 API 路由配置，由于 `ValidateUserRole` 和 `ValidateKBUserPerm` 在显式调用时做到了阻断，但如果没有显式应用这些中间件的接口，可能存在越权。
*   **Evidence:**
    ```go
    // validateAPIToken 中
    ctx := context.WithValue(c.Request().Context(), domain.CtxAuthInfoKey, &domain.CtxAuthInfo{
		IsToken:    true,
		Permission: apiToken.Permission,
		UserId:     apiToken.UserID, // 注入了普通用户的 ID
		KBId:       apiToken.KbId,
	})
    ```
*   **Potential Impact:** API Token 可能绕过某些预期只能由前端交互会话发起的请求，如果接口未正确添加鉴权中间件，可能导致普通操作越权。
*   **Remediation:** 全面梳理 `backend/handler/v1` 和 `api` 目录下的路由注册，确保所有需要验证具体用户角色的接口（除开放API外）强制附加并执行 `ValidateUserRole` 和 `ValidateKBUserPerm`。同时可对 `IsToken: true` 的请求作全局的严格隔离域控制。

### VULN-004: 会话 Cookie 配置未开启 Secure 属性
*   **Vulnerability ID:** VULN-004
*   **Category:** WSTG-SESS-02 (Testing for Cookies Attributes) + A05:2021 – Security Misconfiguration
*   **Description:** 在 Session 初始化 (`SessionMiddleware`) 时，Cookie 的选项配置了 `HttpOnly` 和 `SameSiteLaxMode`，但未配置 `Secure: true`。在生产环境中，这可能导致 Cookie 在非 HTTPS 连接下被明文传输，从而遭遇中间人（MitM）攻击。
*   **Location:** `backend/middleware/session.go` 第 47-52 行
*   **Severity:** 中危 (Medium)。
*   **Evidence:**
    ```go
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   30 * 86400,
		SameSite: http.SameSiteLaxMode,
		HttpOnly: true,
        // 缺少 Secure: true
	}
    ```
*   **Potential Impact:** 攻击者可通过网络嗅探（如果在非加密网络下）拦截并窃取 Session Cookie。
*   **Remediation:** 建议根据环境配置（例如读取 `config.yml` 中的环境变量）判断是否为生产环境，如果是生产环境且启用了 HTTPS，应设置 `Secure: true`。
    ```go
    store.Options = &sessions.Options{
		// ...
		Secure: config.GetBool("is_production_or_https"),
	}
    ```

### VULN-005: 详细的错误堆栈泄露风险
*   **Vulnerability ID:** VULN-005
*   **Category:** WSTG-ERRH-01 (Testing for Error Code) + A05:2021 – Security Misconfiguration
*   **Description:** 在统一处理错误响应 `NewResponseWithError` 中，虽然使用了 TraceID 隐藏内部详细信息，但在 `backend/server/http/http.go` 的 Request Logger 中，当产生未捕获的 Panic 或错误时，系统直接将 `v.Error.Error()` 写入日志甚至某些情况下暴露回客户端响应 (取决于 Echo 的 Global Error Handler 配置)。这可能暴露后端中间件实现、SQL 错误或依赖包版本等敏感信息。
*   **Location:** `backend/server/http/http.go` (Echo Logger) 和 `backend/handler/base.go` (`NewResponseWithError`)
*   **Severity:** 低危 (Low) / Informational。
*   **Evidence:**
    ```go
    // backend/server/http/http.go
    slog.String("err", v.Error.Error()),
    ```
*   **Potential Impact:** 攻击者可利用暴露的技术栈和数据库错误信息，为后续更高级的漏洞利用（如盲注或反序列化）提供线索。
*   **Remediation:** 生产环境中禁止向前台返回具体的 `err.Error()`，统一返回友好的通用错误提示（例如 "Internal Server Error, TraceID: xxx"），并在日志记录时确保仅内部留存堆栈信息。

---

## 正面安全观察 (Positive Observations)
1. **密码安全：** 系统在 `user.go` 和 `repo` 层正确应用了 `bcrypt` 算法进行密码哈希，不存储明文密码。
2. **防爆破机制：** 在 `backend/handler/v1/user.go` 中，登录接口实现了基于 IP 的 RateLimiter 控制 (`CheckIPLocked`)，有效防止了管理员账号的密码暴力破解。
3. **隔离的分享授权：** `share_auth.go` 中为开放/分享内容提供了独立的权限与会话校验（`X-KB-ID` 校验与 EnterpriseAuth 机制），能够限制对私有知识库的越权访问。
4. **日志与遥测监控审计：** 集成了 APM (OpenTelemetry) 和 Sentry，使得在发生安全事件时能够进行有效的全链路追踪。

## 综合安全建议 (General Recommendations)
1. **彻底改造前端状态管理：** 最紧迫的任务是停止使用 localStorage 存放 Token。引入 HttpOnly 的 Secure Cookie 作为承载凭证的媒介，配合后端的 CSRF Token 防御体系。
2. **全局富文本净化：** 审查全部通过 API 接受并展示到前端的富文本内容，使用成熟的库（如 DOMPurify）统一处理，避免零散防御导致 XSS 逃逸。
3. **加固越权测试用例：** 在自动化测试中增加矩阵化权限测试，确保“普通用户 API Token”、“普通用户 JWT”和“管理员 JWT”在每一处路由控制下表现符合最小权限原则。
