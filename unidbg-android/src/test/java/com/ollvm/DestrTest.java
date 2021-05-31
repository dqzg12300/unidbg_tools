package com.ollvm;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.LibraryResolver;
import com.github.unidbg.Module;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.memory.Memory;
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
        //遍历保存的写入地址和写入数据
        for(Map.Entry<Long, byte[]> item : destr.trace.dstr_datas.entrySet()){
            //如果范围是在模块内的。则进行处理
            if(item.getKey()>base_addr && item.getKey()<base_addr+module_size){
                //获取到正确的写入的偏移位置
                baos = new ByteArrayOutputStream();
                Long offset=item.getKey()-base_addr-0x1000;
                System.out.println(String.format("address:0x%x data:%s",offset, OtherTools.byteToString(item.getValue())));
                //先把前半部分取出来
                byte[] start=new byte[offset.intValue()];
                System.arraycopy(sodata,0,start,0,offset.intValue());
                //然后把后半部分的大小计算出来
                int endsize=sodata.length-offset.intValue()-item.getValue().length;
                //把后半部分的数据填充上
                byte[] end=new byte[endsize];
                System.arraycopy(sodata,offset.intValue()+item.getValue().length,end,0,endsize);
                //将三块位置的数据填充上
                baos.write(start,0,start.length);
                baos.write(item.getValue(),0,item.getValue().length);
                baos.write(end,0,end.length);
                //最后把so保存起来
                sodata=baos.toByteArray();
            }
        }
        writeFile(baos.toByteArray(),savepath);
    }
}
