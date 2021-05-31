# unidbg
## 本项目主要是使用unidbg解决一些问题时的案例记录

### 1、ollvm bcf混淆解决的例子unidbg_tools/unidbg-android/src/test/java/com/ollvm/BcfTest.java

### 2、ollvm fla混淆解决的例子unidbg_tools/unidbg-android/src/test/java/com/ollvm/FlaTest.java

### 3、ollvm str混淆解决的例子unidbg_tools/unidbg-android/src/test/java/com/ollvm/DestrTest.java

### 4、trace打印寄存器每一步的变化流程的例子unidbg_tools/unidbg-android/src/test/java/com/tracedemo/TraceTest.java

trace打印效果如下
~~~
[libnative-lib.so] [0x124cc] [ fd 7b bf a9 ] 0x400124cc: stp x29, x30, [sp, #-0x10]!-----x29=0xbffff770	x30=0x400135f8	sp=0xbffff6c0		//x29=0xbffff770
[libnative-lib.so] [0x124d0] [ fd 03 00 91 ] 0x400124d0: mov x29, sp-----x29=0xbffff770	sp=0xbffff6b0		//x29=0xbffff6b0
[libnative-lib.so] [0x124d4] [ ff c3 00 d1 ] 0x400124d4: sub sp, sp, #0x30-----sp=0xbffff6b0		//sp=0xbffff680
[libnative-lib.so] [0x124d8] [ a9 01 00 d0 ] 0x400124d8: adrp x9, #0x40048000-----x9=0x0		//x9=0x40048000
[libnative-lib.so] [0x124dc] [ 29 21 46 f9 ] 0x400124dc: ldr x9, [x9, #0xc40]-----x9=0x40048000	x9=0x40048000		//x9=0x40049568
[libnative-lib.so] [0x124e0] [ aa 01 00 d0 ] 0x400124e0: adrp x10, #0x40048000-----x10=0x0		//x10=0x40048000
[libnative-lib.so] [0x124e4] [ 4a 15 46 f9 ] 0x400124e4: ldr x10, [x10, #0xc28]-----x10=0x40048000	x10=0x40048000		//x10=0x40049560
[libnative-lib.so] [0x124e8] [ 4b 00 80 52 ] 0x400124e8: movz w11, #0x2-----w11=0xffffffff		//w11=0x2
[libnative-lib.so] [0x124ec] [ 4c 01 00 d0 ] 0x400124ec: adrp x12, #0x4003c000-----x12=0xffffffff		//x12=0x4003c000
[libnative-lib.so] [0x124f0] [ 8c f9 00 91 ] 0x400124f0: add x12, x12, #0x3e-----x12=0x4003c000	x12=0x4003c000		//x12=0x4003c03e
[libnative-lib.so] [0x124f4] [ 2d 01 40 b9 ] 0x400124f4: ldr w13, [x9]-----w13=0x0	x9=0x40049568		//w13=0x0
[libnative-lib.so] [0x124f8] [ 4e 01 40 b9 ] 0x400124f8: ldr w14, [x10]-----w14=0x1	x10=0x40049560		//w14=0x0
[libnative-lib.so] [0x124fc] [ af 05 00 71 ] 0x400124fc: subs w15, w13, #1-----w15=0x0	w13=0x0		//w15=0xffffffff
~~~