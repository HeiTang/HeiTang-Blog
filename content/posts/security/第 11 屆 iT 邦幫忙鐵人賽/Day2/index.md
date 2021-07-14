---
title: "『 Day 2 』認識 CTF" 
date: 2019-09-18T00:16:14+08:00
hero: security.jpg
menu:
  sidebar:
    name: "『 Day 2 』認識 CTF"
    identifier: Day2
    parent: 第 11 屆 iT 邦幫忙鐵人賽
    weight: 14
math: true
---
### CTF 簡介
- Capture The Flag

- 駭客的搶旗遊戲

- 學習資訊安全攻擊/防禦的競賽

- 利用執行在目標電腦中的應用程式漏洞取得Flag

- 解密藏在檔案或程式中的 Flag

- Flag 通常就是一串文字

### CTF 賽制
#### Jeopardy
- 透過主辦方出題目，會有各種類型的題目，每種類型可能會有數道題目，越難題目分數越高

- 線上賽居多，參與隊伍數、各隊人數較無限制

- 「`CTF 題目類型`」的介紹主要也以這個為主。

#### Attack & Defense

各隊參賽者有自己的主機，主機上執行著各種有漏洞的服務。

- Attack

  透過分析主機上的服務，找到漏洞利用方式並撰寫攻擊程式 (exploit)，入侵其他參賽者維護的主機。

- Defense

  修補自己主機上的漏洞，防止他人偷取你的 Flag。

偷取 Flag 遞交到主辦單位記分板可獲得額外分數，如果成功守護自己的 Flag 也會有分數，但若自己的 Flag 被偷走則拿不到分數。

#### King of the Hill

每個隊伍一開始不會擁有主機，而是要把主辦方提供的主機打下來然後寫入自己的 Flag，例如：改首頁。
同時參賽者要守護已經打下來的主機，不被其他隊伍搶走，每個回合依照擁有主機的數量進行加分，佔領時間愈長，分數愈高。

### CTF 題目類型

#### `Reverse 逆向工程類型`

通常由主辦方給一個或多個 Binary， 過關所需要的 Key 通常加密藏在執行檔裡，要將程式逆向分析出後才能找出。

不外乎就是逆向⼯程 / 拆遊戲 / 拆程式 / 把組合語⾔變回 C / 拆⼿機 APP / 破解 / 繞過驗證等。

##### 流程
1. 參賽者會拿到一個程式（binary）

2. 沒有完整原始法的前提分析

3. 找到隱藏的資訊或改變程式流程

4. 反組譯程式
  
    ```
    int a = 1;
    if (a == 87)
        getFlag();
    else
        print("no flag");
    ```

##### 分析
- 靜態分析(Static Analysis) 
  
  不執行程式，單純從反組譯出的程式碼、組合語言、程式流程圖、Global & Static data 等進行分析。

- 動態分析(Dynamic Analysis)

  直接執行程式，並根據當下程式執行狀況、Registers（暫存器）和 Memory（記憶體）中的值進行分析 。

#### `Pwnable 弱點或漏洞分析類型` 

主辦方會給一個有弱點的程式或 Server 執行檔，主辦方自己會開一台伺服器跑該服務，參賽者要透過靜態分析與動態分析來找出該程式的弱點。例如： Buffer overflow、命令注入等，在遠端伺服器利用漏洞來執行任意指令，進一步取得存在遠端伺服器的金鑰。

##### 流程

- 分析（Analysis）→ 找尋漏洞（Bug）→ 撰寫攻擊程式（Exploit）

##### Exploit
- 利用程式漏洞進而獲得主機控制權（Get Shell） 

#### `Web Security`

獲取資訊或不合法登入或取得對方主機

##### 流程
1. 分析網頁架構
    - 框架（Framework）、撰寫語言之套性、作業系統。
    
    - 舊版本已知漏洞、新版本未修補漏洞。

2. 找尋可控輸入與漏洞
    
    - 網址（POST、GET）、使用者輸入（Login）、檔案上傳等。

3. 攻擊
    
    - XSS, SQL Injection, File Inclusion, Command Injection, …etc
    
    - OWASP Top 10

#### `Crypto 加解密類型`

主辦方會給加密過的密文、加密程式，參賽者必須分析加解密演算法甚至需要找出演算法的弱點來破解出真正的明文。

##### 雜湊

- SHA、MD5

##### 金鑰加密

- AES、DES（對稱性加密）
- RSA（非對稱性加密）

##### 常用工具

- 解密網站
- OpenSSL
- rsatool

#### `Forensic 鑑識類型`

- 主辦方會要求參賽者從封包、Log、 Memory Dump、Disk Image、VM Image 等鑑識出隱藏在之中的金鑰。
- 資訊隱藏學（Steganography）
- 數位鑑識 
- 看 Log、記憶體、封包 
    - 分析封包內的摘要及詳細資訊
    - 工具：Wireshark

#### `Misc 綜合類型`

- 沒有較明確的分類：像是給個遊戲要想辦法作弊破到幾百萬分、給一個壞掉的 QR Code 嘗試修復，或是給張圖片要找出相關的人事物等。
- 組合題

---

### CTF 學習資源

- [LiveOverflow](http://liveoverflow.com/) - 應該是 Youtube 上最棒的 hacking 教學了，從最簡單的到很深入的都有，並且有許多系列的課程，只可惜需要練英聽。

- [Bamboofox](https://bamboofox.cs.nctu.edu.tw/) - 臺灣良心，有講義有課程錄影，也有題目讓你練習( Pwn 多一些)，還是中文資源。

- [HACKSPLAINING](https://www.hacksplaining.com/) - Web 漏洞教學，非常簡單好懂，網站很精美！

- [RE for beginners](https://beginners.re/) - Reversing 教學，網路有中文版，不過太大本很難啃，但對於沒什麼逆向基礎的來說可以很有系統化的學。

- [angelboy youtube](https://www.youtube.com/user/scwuaptx/videos) - 臺灣 Pwn 大神 Youtube 頻道，影片看完後 Pwn 基礎應該就都懂了。

- [CTF TIME](https://ctftime.org/)

- [GitHub - CTFs](https://github.com/ctfs) 

- [HITCON Knowledge Base](http://kb.hitcon.org/)

- [pwnable](http://pwnable.kr/ )

- [Wargames](http://overthewire.org/wargames/)

- [W3Challs](https://w3challs.com/)

---

### CTF 網站

#### 綜合
- [hackme](https://hackme.inndy.tw/) - 也是臺灣人架的，什麼類型題目都有。
- [pwnable.kr](http://pwnable.kr/) - 綜合 Pwn 題目，應該是 Pwn 領域最知名的網站。
- [RingZer0 CTF](https://ringzer0team.com/) - 題目的種類應該是最豐富的。

#### 入門
- [picoCTF](https://picoctf.com/) - 設計給高中生玩的，超級精美，非常好入門。
- [overthewire](http://overthewire.org/wargames/) - 沒有 Linux 基礎的非常適合玩這個，不但教資安也會教 Linux。

#### 偏難
- [pwnable.tw](https://pwnable.tw/) - 高強度 Pwn 題目，我玩了好一陣子。
- [reversing.kr](http://reversing.kr/) - 一系列 Reversing 題目。

#### 其他
- [一堆網站列表](http://captf.com/practice-ctf/)


