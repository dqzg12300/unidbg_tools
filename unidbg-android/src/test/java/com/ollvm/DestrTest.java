package com.ollvm;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.LibraryResolver;
import com.github.unidbg.Module;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.memory.Memory;
import javafx.util.Pair;
import trace.OtherTools;

import java.io.*;
import java.util.Map;

public class DestrTest {
    private final AndroidEmulator emulator;
    public DeStrWriteHook trace;
    public Module module;
    public String modulePath="unidbg-android/src/test/resources/example_binaries/ollvm_str/libnative-lib.so";
    public DestrTest(){
        emulator = AndroidEmulatorBuilder
                .for32Bit()
                .build();
        trace = new DeStrWriteHook(false);
        final Memory memory=emulator.getMemory();
        LibraryResolver resolver = new AndroidResolver(23);
        memory.setLibraryResolver(resolver);
        emulator.getBackend().hook_add_new(trace,1,0,emulator);
        module=emulator.loadLibrary(new File(modulePath));
//        byte[] ceshi= emulator.getBackend().mem_read(0x40000000,module.size);
//        System.out.println("ceshi: "+OtherTools.byteToString(ceshi));
//        String savepath=modulePath+".new2";
//        writeFile(ceshi,savepath);
    }

    public static byte[] readFile(String strFile){
        try{
            InputStream is = new FileInputStream(strFile);
            int iAvail = is.available();
            byte[] bytes = new byte[iAvail];
            is.read(bytes);
            is.close();
            return bytes;
        }catch(Exception e){
            e.printStackTrace();
        }
        return null ;
    }

    public static void writeFile(byte[] data,String savefile){
        try {
            FileOutputStream fos=new FileOutputStream(savefile);
            BufferedOutputStream bos=new BufferedOutputStream(fos);
            bos.write(data,0,data.length);
            bos.flush();
            bos.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args){
        DestrTest destr=new DestrTest();
        String savepath=destr.modulePath+".new";
        byte[] sodata=readFile(destr.modulePath);
        long base_addr=destr.module.base;
        long module_size=destr.module.size;
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        int cnt=0;
        //遍历保存的写入地址和写入数据
        for(Map.Entry<Long, Pair<byte[],byte[]> > item : destr.trace.dstr_datas.entrySet()){
            //如果范围是在模块内的。则进行处理
            if(item.getKey()>base_addr && item.getKey()<base_addr+module_size){
                //获取到正确的写入的偏移位置
                baos = new ByteArrayOutputStream();
                Long offset=item.getKey()-base_addr-0x1000;
                byte[] src=item.getValue().getValue();
                byte[] dest=item.getValue().getKey();

                for(int i=offset.intValue();i<offset.intValue()+dest.length;i++){
                    sodata[i]=dest[i-offset.intValue()];
                }
                baos.write(sodata,0,sodata.length);
                cnt++;
                if(cnt%1000==0){
                    System.out.println(String.format("count:%d cur:%d",destr.trace.dstr_datas.size(),cnt));
                }

            }
        }
        writeFile(baos.toByteArray(),savepath);
        System.out.println("task over");

    }
}
