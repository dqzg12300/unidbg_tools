package com.ollvm;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.LibraryResolver;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.CodeHook;
import com.github.unidbg.arm.backend.DynarmicFactory;
import com.github.unidbg.debugger.Debugger;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.linux.android.dvm.jni.ProxyDvmObject;
import com.github.unidbg.memory.Memory;
import com.kanxue.test2.MainActivity;

import java.io.File;

public class BcfTest {
    private final AndroidEmulator emulator;
    private final VM vm;
    private final DvmClass mainActivityDvm;
    public static void main(String[] args) {
        BcfTest bcfTest = new BcfTest();
        bcfTest.call_calckey();
    }
    private BcfTest(){
        emulator = AndroidEmulatorBuilder
                .for64Bit()
                .build();
        Memory memory = emulator.getMemory();
        LibraryResolver resolver = new AndroidResolver(23);
        memory.setLibraryResolver(resolver);
        vm = emulator.createDalvikVM(null);
        vm.setVerbose(false);
        mainActivityDvm = vm.resolveClass("com/example/ollvmdemo2/MainActivity");
        DalvikModule dm = vm.loadLibrary(new File("unidbg-android/src/test/resources/example_binaries/ollvm_bcf/libnative-lib.so"), false);
        dm.callJNI_OnLoad(emulator);

    }
    //主动调用目标函数
    private void call_calckey(){
        emulator.getBackend().hook_add_new(new CodeHook() {
            @Override
            public void hook(Backend backend, long address, int size, Object user) {
                System.out.println(String.format("0x%x",address-0x40000000));
            }
        },0x400124CC,0x400124CC+0x838,null);
        //调用一个返回值为object的静态的jni函数
        StringObject res = mainActivityDvm.callStaticJniMethodObject(emulator, "stringFromJNI()Ljava/lang/String;");
        System.out.println(res.toString());
    }
}
