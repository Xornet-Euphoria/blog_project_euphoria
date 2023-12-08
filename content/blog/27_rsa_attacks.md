+++
title = "RSA暗号攻撃で他でも使える n のこと"
date = 2021-12-14
description = "今年取り組んだCrypto問題は妙にRSA暗号に対する攻撃を一般化たり、他でも使えるような問題が多かったので、RSAに対する有名な攻撃を一般化したり他でも使えたような例を幾つか紹介します。"

[taxonomies]
tags = ["CTF", "Crypto", "RSA"]
+++

この記事は[CTF Advent Calendar 2021](https://adventar.org/calendars/6914)の14日目の記事です。1つ前の記事は[keymoon](https://twitter.com/kymn_)さんが時間跳躍して[SECCON CTF 2021 参加記/Writeup - 雑記](https://keymoon.hatenablog.com/entry/2021/12/14/194414)を書いてくれました。

(時間跳躍前は[ﾈｺﾁｬﾝ](https://twitter.com/2llr)の[minaminao/ctf-blockchain: Summary of CTF Blockchain Challenges](https://github.com/minaminao/ctf-blockchain)でした。)

今年取り組んだCrypto問題は妙にRSA暗号に対する攻撃を一般化して他でも使えるような問題が多かったので、RSAに対する有名な攻撃を一般化して他でも使えたような例を幾つか紹介します。

<!-- more -->

## Table of Contents

- [はじめに](#hazimeni)
- [Fermat's Method](#fermat-s-method)
- [Håstad's Broadcast Attack](#hastad-s-broadcast-attack)
- [Franklin-Reiter Related Message Attack](#franklin-reiter-related-message-attack)
- [Coppersmith's Short Pad Attack](#coppersmith-s-short-pad-attack)
- [あとがき](#atogaki)
- [参考資料](#can-kao-zi-liao)

## はじめに

英語が読める方は各攻撃の英語版Wikipediaと[Twenty years of attacks on the RSA cryptosystem](https://crypto.stanford.edu/~dabo/abstracts/RSAattack-survey.html)を読めばこの記事は不要です。ここまでのご閲覧ありがとうございました。

また、タイトルはかの有名な資料である[RSA暗号運用でやってはいけない n のこと #ssmjp](https://www.slideshare.net/sonickun/rsa-n-ssmjp)をリスペクトしました(勝手に使ってごめんなさい)。

### Prerequisite

この記事を読むにあたって次の知識が必要になります。

- RSA暗号
- 扱う攻撃のRSA暗号に対する利用方法
  - 後述の「RSA暗号運用でやってはいけない n のこと」等を参照
- Coppersmith's Attack
  - Coppersmith's Attack自体が多変数の場合も含めて強力なソルバになる事は有名なので今回は扱いません
- 終結式
  - Coppersmith's Short Pad Attackで利用

## Fermat's Method

RSA暗号運用でやってはいけない n のこと、では「その3」で紹介されている素因数分解方法です。

よく知られているフェルマー法の適用条件は2つの素因数「$p,q$の差が小さい」というものですが、これは近い2数の積が整数$a$と小さい整数$b$を利用してと表す事が出来る事が出来る事を利用しています。割と「2つの素因数」に対する特効として流通しているようなイメージですが、アルゴリズムを見ればわかるように特に素数である事を利用しているわけではありません。というわけで「2つの差が小さい合成数」の積の因数分解にも拡張出来ます。

これがRSA暗号の問題で特に効く場合は$p,q$の近似整数比がわかっている場合です。次のように2つの素数$p,q$の近似整数比をおいてみます。RSAの例では当然ですが$N \coloneqq pq$とします。

$$
\frac cd \approx \frac pq
$$

これによって$cq \approx dp$という近似が成り立ちます。よってであることから、$cdN$は2つの近い因数$cq, dp$を持ちます。よって$cdN$に対してフェルマー法を適用することで$cq, dp$が求められるので、あとはこれを既知の$c,d$で割れば無事に$N$の素因数分解が出来ます。

### 問題例

- [No Stone Left Unturned - Circle City Con 2021](https://github.com/b01lers/circle-city-ctf-2021/tree/main/crypto/no-stone-left-unturned)
  - [Writeup by me (after CTF)](https://project-euphoria.dev/blog/19-ccc-2021/#no-stone-left-unturned)

## Håstad's Broadcast Attack

RSA暗号運用でやってはいけない n のこと、では「その9」で紹介されている攻撃です。

異なる法で公開鍵の指数$e$回暗号化された場合に中国剰余定理を使えば復号出来るという攻撃です。

余談ですが、これは平文のサイズに関わらず復号可能な回数が$e$回ということであり、平文のサイズが小さければこれより小さい数の暗号文を持ってくることで復号出来る可能性があります([Triplet Luna - TSG Live CTF](https://github.com/tsg-ut/tsg-live-ctf-7/tree/main/crypto/triplet-luna))。これについても正確に書こうと思いましたが、下記一般化に比べれば、攻撃アルゴリズムを読むだけでわかるほぼ自明な事実なので軽く述べるに留まります。

さて、肝心の一般化ですがこれはの異なる$N$における連立方程式とみなす事が出来るので、$f$を一般の$e$次以下のモニック多項式に拡張し、連立方程式を解きます。

これを添字を用いて定式化すると、共通根$m$を持つ高々$e$次のモニック多項式  が$e$個与えられた状況で$m$を求める問題になります。もちろんとします。

また、$n_i$はどのような2つを持ってきても互いに素であるとします。そうでなければ2つの$n_i$で最大公約数を求めることで素因数分解が出来るので、その$n_i$で復号すれば問題は解決します。

この問題は$e$個の多項式を、中国剰余定理を上手く使って係数を求めて線形結合すると$N = \prod_i n_i \gt m^e$を法としたモニック多項式が得られ、これはの線形結合であることから高々$e$次であり、しかも$x=m$が根の1つであることから、Coppersmith's Attackを使って解く事が出来ます。

ではそんな都合の良いをどうやって導出するかですが、まず次のような係数$T_i$を定義します。

$$
T_i = \begin{cases}
1 \mod n_i \cr
0 \mod n_j \ (j \neq i)
\end{cases}
$$

これは中国剰余定理を用いる事で求める事が出来ます。

続いてこの係数を用いてを構成します。この多項式はモニック多項式であり、を満たします。以下で本当でそうであるかを証明しますが、結果だけ欲しい人はCoppersmith's Attackを使うステップまで飛ばしてください。

まずモニック多項式である事を示します。の$e$次(つまり最高次数)の係数を$T$とおくと、各$g_i$がモニック多項式であることから、を満たします。$T_i$の構成方法から、$T \equiv 1 \mod n_i$が各$n_i$に対して成立します。

ここで$T$を総和を用いた定義でなく、$n_i$を法とした連立方程式を中国剰余定理を使って解くことで法$N$の下で求める事を考えます。この連立方程式は実は自明で$T = 1+kN$という整数を持ってくれば各方程式を満たすことがわかります。そして、中国剰余定理より、法$N$の下で解は一意であることから、$T \equiv 1 \mod N$が成り立ちます。つまり、はモニック多項式になります。

では続いてを満たす事を示します。$T_i$はその構成方法から次を満たします。

$$
T_i \equiv 0 \mod \prod_{j=1, j \neq i}^e n_j
$$

また、であるので、この2つから次のような整数$k_0, k_1$が存在します。

$$
\begin{aligned}
T_i &= k_0 \times \prod_{j=1, j \neq i}^e n_j \cr
g_i(m) &= k_1 n_i
\end{aligned}
$$

よって両式を掛けることでが成り立ちます。これはつまりを意味します。

したがって、これを各$i$に対して総和をとると次のようになり、が示されます。

$$
G(m) \equiv \sum_{i=1}^e T_ig_i(m) \equiv 0 \times e \equiv 0 \mod N
$$

これで根が$m$である$e$次の多項式が得られ、であることから、Coppersmith's Attackを利用して$m$を求める事が出来ます。

### 問題例

- [Party Ticket - CakeCTF 2021](https://github.com/theoremoon/cakectf-2021-public/tree/master/crypto/party_ticket)
  - [writeup by author](https://hackmd.io/@theoldmoon0602/H1-3RTSFu)

## Franklin-Reiter Related Message Attack

RSA暗号運用でやってはいけない n のこと、では「その11」で紹介されている攻撃です。パディング方法が既知のような状況で2つの平文$m_1, m_2$が線形の関係$m_2 \equiv am_1 + b \mod n$にある場合に$m_2$を消去して$m_1$が根となる多項式を2つ用意して公約式を求めるという攻撃です。

具体的には次のような場合を考えます。

$$
\begin{aligned}
c_1 &\equiv m_1^{e_1} \mod n \cr
c_2 &\equiv m_2^{e_2} \equiv (am_1 + b)^{e_2} \mod n
\end{aligned}
$$

この時、とという2式を用意すると、となるので、Euclid互除法の要領で公約式を求めると$x-m_1 \mod N$という多項式が出てきてくれます。

もうこの説明の時点で気付いたかもしれませんが、$m_2$が$m_1$の線形変換である必要もRSAの形である必要もありません。法が同じで共通根を有していればどんな2つの多項式でもこの攻撃を適用出来ます。

なお、多項式の次数が大きくなると単純なEuclid互除法で求めるのは遅くなります。特にRSAで良く使われる$e = 65537$では単純なSageの実装で数十分はかかります。そこで多項式の除算と余りの導出の計算量を抑えたものを用いるHalf GCDという手法もあるのですが、筆者があまり理解していないので名前を紹介するのに留めます。興味がある人はググってください。

### 問題例

- [urara - SECCON CTF 2020](https://github.com/SECCON/SECCON2020_online_CTF/tree/main/crypto/urara)
  - [Writeup by author](https://furutsuki.hatenablog.com/entry/2020/10/11/172946#urara-240pts--14solves)
- [ECC-RSA 2 - BSides Ahmedabad CTF 2021](https://gitlab.com/zer0pts/bsides-ahmedabad-ctf-2021/-/tree/master/crypto/ecc_rsa_2)
  - [Writeup by me](https://project-euphoria.dev/blog/25-zer0pts-2-2021/#ecc-rsa-2)

## Coppersmith's Short Pad Attack

RSA暗号運用でやってはいけない n のこと、では紹介されていませんが、後半に名前だけは載っている攻撃です。

前述のFranklin-Reiter Related Message Attackではパディングの形式等が既知で、2つの多項式は$m_1$だけが未知数であったため合同式を用いて解く事が出来ました。そこで未知数が増える事を考えます。

平文$m$に対して$A$を既知とする次のような線形パディングを考えます。但し$r_1, r_2$は未知の比較的小さい数とします。

$$
\begin{aligned}
m_1 \coloneqq Am + r_1 \mod N \cr
m_2 \coloneqq Am + r_2 \mod N
\end{aligned}
$$

この関係からである事がわかります。$r_1, r_2$が小さかった事から$\delta$も小さくなります。

本来のRSA暗号であればとおくことになり、$x=m_1, y = \delta$が解になります。

ここで、終結式を用いて$x$を消去した式を得ると$y$についての多項式となるのでCoppersmith's Attackを用いて$\delta$を求め($\delta$が求解可能なレベルで小さい事が条件)、それを$f_2$に代入することでFranklin-Reiter Related Message Attackへ帰着させるという攻撃になりますが、特にこの形の多項式に限定した攻撃では無いため、$f_1, f_2$に一般性を持たせる事が出来ます。

やや話題が逸れますが終結式自体も「変数を減らす」という点ではかなり強力な概念で、手計算だと骨が折れる式変形を終結式に投げる事で簡単に求める事が出来ることもあります(example: [Madras - ASIS CTF 2021](https://project-euphoria.dev/blog/24-asis-2021/#madras))。同様の概念にグレブナー基底というものもあります。どちらも有用でCTFでの応用例もありますが、本ブログの趣旨を超える為、紹介だけに留めます。

### 問題例

- [Two Rabin - Asian Cyber Security Challenge](https://github.com/acsc-org/acsc-challenges-2021-public/tree/main/crypto/Two%20Rabin)
  - [Writeup by me](https://project-euphoria.dev/blog/21-acsc/#two-rabin)

ここまで書いて、前半2つはそれなりに「日本語記事としての」新規性がありそうな気がしますが、後半2つは手法自体の解説に「多項式が一般化出来る、自明だよね?」みたいな事を言って問題例を挙げているだけな気がしてなりません。まあいいや。

## あとがき

ここまで読んで頂きありがとうございました。この記事が、「RSA暗号運用でやってはいけない n のこと」を読んだ人が次に読んで得るものが多く、楽しめる記事になっていると嬉しいです(もちろん既知の人も再確認等で楽しめるともっと嬉しいです)。

本当は問題例に載せた問題を解くコードも交えて解説しようと思いましたが、面倒な上に時間も無かったのでやめました。Writeupリンクを載せたのでそちらを御覧ください。

なお、問題例をあまり挙げられていないので、今後参加したCTFに類似の問題があったらそれを追加していくかもしれません。もし、良い例がありましたら[@Xornet_Euphoria](https://twitter.com/Xornet_Euphoria)までリプライを飛ばしていただけると幸いです(定型文ですが、スパム対策のためフォロー外へのDMは解放していません。怪しく無ければDMリクエストは承認します)。

ところで、私が問題作成で携わったSECCON CTF 2021に参加してくださった皆様、ありがとうございました。本当は昨日の12/13に自分の作った問題のWriteupを投稿しようと思ったのですが、諸事情で22日に投稿する予定に変更した(これもまた変更されるかもしれない)ので、私の問題を解いた皆さんはこの間に「作者が書くだろうから」なんて言わず投稿してください。CTF中に解いて無くても復習や途中までの過程でも「解けねえよ、作問者出てこい」みたいな苦情も大歓迎です(現時点で思ったより少なくて泣いています)。

CTF Advent Calendarの明日の担当は...いません。というわけでSECCON CTF 2021に出た皆さんはWriteupを書くチャンスですよ!! そうでない方もWriteupでも何でもいいので何か書いて皆で強くなってCTFプレイヤー全員でCTF全クリしましょう。

それが無ければ1日飛んで[DiKO](https://twitter.com/d1k0b3o)さんが

> LLL入門してみます

という内容で書いてくれるそうです。投稿されたら、その記事をきっかけにCTFプレイヤー全員でLLLを習得しましょう。これは蛇足なんですが、SECCON CTF 2021のCryptoでは3/6が格子を使う問題だったらしいですね。記事が公開されたら読んで格子完全理解して解きましょう。

## 参考資料

1. [RSA暗号運用でやってはいけない n のこと #ssmjp](https://www.slideshare.net/sonickun/rsa-n-ssmjp)
2. [Twenty years of attacks on the RSA cryptosystem](https://crypto.stanford.edu/~dabo/abstracts/RSAattack-survey.html)
3. [Fermat's factorization method - Wikipedia](https://en.wikipedia.org/wiki/Fermat%27s_factorization_method#Multiplier_improvement): Multiplier improvementの節
4. [Coppersmith's attack - Wikipedia](https://en.wikipedia.org/wiki/Coppersmith's_attack)
5. [SageMathを使ってCoppersmith's Attackをやってみる - ももいろテクノロジー](https://inaz2.hatenablog.com/entry/2016/01/20/022936)
6. [CryptoHack – RSA challenges](https://cryptohack.org/challenges/rsa/)
