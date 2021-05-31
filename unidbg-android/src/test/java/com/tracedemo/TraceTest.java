package com.tracedemo;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.LibraryResolver;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.CodeHook;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.DalvikModule;
import com.github.unidbg.linux.android.dvm.DvmClass;
import com.github.unidbg.linux.android.dvm.StringObject;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.memory.Memory;
import trace.GlobalData;
import trace.KingTrace;

import java.io.File;

public class TraceTest {
    private final AndroidEmulator emulator;
    private final VM vm;
    private final DvmClass mainActivityDvm;
    public static void main(String[] args) {
        TraceTest bcfTest = new TraceTest();
        bcfTest.call_calckey();
    }
    private TraceTest(){
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

        //设置忽略不打印的
        GlobalData.ignoreModuleList.add("libc.so");
        GlobalData.ignoreModuleList.add("libhookzz.so");

        //dump ldr的数据。包括ldr赋值给寄存器的如果是指针，也会dump
        GlobalData.is_dump_ldr=true;
        //dump str的数据
        GlobalData.is_dump_str=true;

        KingTrace trace1=new KingTrace(emulator);
        trace1.initialize(0x400124CC,0x400124CC+0x838,null);
        emulator.getBackend().hook_add_new(trace1,0x400124CC,0x400124CC+0x838,emulator);
        //调用一个返回值为object的静态的jni函数
        StringObject res = mainActivityDvm.callStaticJniMethodObject(emulator, "stringFromJNI()Ljava/lang/String;");
        System.out.println(res.toString());
    }
}
