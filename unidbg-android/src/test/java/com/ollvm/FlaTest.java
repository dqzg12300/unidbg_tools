package com.ollvm;

import capstone.Capstone;
import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.LibraryResolver;
import com.github.unidbg.arm.ARM;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.BlockHook;
import com.github.unidbg.arm.backend.CodeHook;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.utils.Inspector;
import javafx.util.Pair;
import keystone.Keystone;
import keystone.KeystoneArchitecture;
import keystone.KeystoneEncoded;
import keystone.KeystoneMode;
import net.fornwall.jelf.HashTable;
import sun.security.tools.KeyStoreUtil;
import unicorn.Arm64Const;

import java.io.*;
import java.util.*;

public class FlaTest {
    private final AndroidEmulator emulator;
    private final VM vm;
    private final DvmClass mainActivityDvm;
    public static void main(String[] args) {
        FlaTest bcfTest = new FlaTest();
        bcfTest.call_calckey();
    }


    private FlaTest(){
        emulator = AndroidEmulatorBuilder
                .for64Bit()
                .build();
        Memory memory = emulator.getMemory();
        LibraryResolver resolver = new AndroidResolver(23);
        memory.setLibraryResolver(resolver);
        vm = emulator.createDalvikVM(null);
        vm.setVerbose(false);
        mainActivityDvm = vm.resolveClass("com/example/ollvmdemo2/MainActivity");
        DalvikModule dm = vm.loadLibrary(new File("unidbg-android/src/test/resources/example_binaries/ollvm_fla/libnative-lib.so"), false);
        dm.callJNI_OnLoad(emulator);

    }

    //判断真实块
    private boolean OpstrContains(String opstr){
        ArrayList<String> flags= new ArrayList(Arrays.asList("ldur","ldr","str","b","movz","movk","cmp","b.eq"));
        if(flags.contains(opstr)){
            return true;
        }
        return false;
    }

    public static String bytesToHexString(byte[] src){
        StringBuilder stringBuilder = new StringBuilder("");
        if (src == null || src.length <= 0) {
            return null;
        }
        for (int i = 0; i < src.length; i++) {
            int v = src[i] & 0xFF;
            String hv = Integer.toHexString(v);
            if (hv.length() < 2) {
                stringBuilder.append(0);
            }
            stringBuilder.append(hv);
        }
        return stringBuilder.toString();
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
    //真实块列表
    ArrayList<Pair<Long, Capstone.CsInsn[]>> readlyBlock=new ArrayList<Pair<Long, Capstone.CsInsn[]>>();
    //真实块的分支执行块
    ArrayList<Pair<Long, Capstone.CsInsn[]>> readlyBranceBlock=new ArrayList<Pair<Long, Capstone.CsInsn[]>>();

    //根据执行流程得到的所有块，过滤出真实块，并且将块合并成ida中的那样。在这里会用bl和b分割，所以bl分割开来的块我们要合并起来
    private void LoadReadlyAddress(){
        readlyBlock.add(blocks.get(0));
        for(int i=1;i<blocks.size();i++){
            Pair<Long, Capstone.CsInsn[]> pdata=blocks.get(i);
            Capstone.CsInsn[] insns=pdata.getValue();
            Long address=pdata.getKey();
            boolean isReadly=false;
            for(Capstone.CsInsn ins :insns){
                if(readlyBlock.contains(address)){
                    continue;
                }
                if(!OpstrContains(ins.mnemonic)){
                    isReadly=true;
                    String opstr= ARM.assembleDetail(emulator,ins,address,false,false);
                    System.out.println(String.format("block readly address:0x%x opstr:%s",ins.address,opstr) );
                    break;
                }
                else{
//                    String opstr= ARM.assembleDetail(emulator,ins,address,false,false);
//                    System.out.println(String.format("block fla address:0x%x opstr:%s",ins.address,opstr) );
                }
            }
            if(isReadly){
                //先把当前块添加为真实块，并且检查下一个块是否需要合并
                ArrayList<Capstone.CsInsn> arrayInsns=new ArrayList(Arrays.asList(insns));
                //如果这个块的最后一个指令是bl。则把下一个块也给合进来。直到非bl的结束块
                Pair<Long, Capstone.CsInsn[]> curBlock=blocks.get(i);
                while(true){
                    if(i>blocks.size()){
                        break;
                    }
                    Capstone.CsInsn[] curInsns=curBlock.getValue();
                    String mnemonic=curInsns[curInsns.length-1].mnemonic;
                    if(mnemonic.equals("bl")){
                        Pair<Long, Capstone.CsInsn[]> nextBlock=blocks.get(++i);
                        arrayInsns.addAll(Arrays.asList(nextBlock.getValue()));
                        curBlock=nextBlock;
                    }else{
                        break;
                    }
                }
                readlyBlock.add(new Pair<Long,Capstone.CsInsn[]>(address,(Capstone.CsInsn[])arrayInsns.toArray(new Capstone.CsInsn[arrayInsns.size()])));
            }
            if(i>blocks.size()){
                break;
            }
        }
        //把分支的执行流程块也过滤一下真实块。因为主要用来找分支的跳转地址。所以不需要合并块
        for(int i=1;i<branchBlocks.size();i++){
            Pair<Long, Capstone.CsInsn[]> pdata=branchBlocks.get(i);
            Capstone.CsInsn[] insns=pdata.getValue();
            Long address=pdata.getKey();
            boolean isReadly=false;
            for(Capstone.CsInsn ins :insns){
                if(readlyBranceBlock.contains(address)){
                    continue;
                }
                if(!OpstrContains(ins.mnemonic)){
                    isReadly=true;
                    String opstr= ARM.assembleDetail(emulator,ins,address,false,false);
//                    System.out.println(String.format("block readly address:0x%x opstr:%s",ins.address,opstr) );
                    break;
                }
                else{
//                    String opstr= ARM.assembleDetail(emulator,ins,address,false,false);
//                    System.out.println(String.format("block fla address:0x%x opstr:%s",ins.address,opstr) );
                }
            }
            if(isReadly){
                readlyBranceBlock.add(new Pair<Long,Capstone.CsInsn[]>(address,insns));
            }
        }
    }

    //获取block的最后一个指令地址
    private Long GetEndAddress(Capstone.CsInsn[] insns){
        Capstone.CsInsn ins=insns[insns.length-1];
        String opstr= ARM.assembleDetail(emulator,ins,ins.address,false,false);
        //如果最后一个指令是bl。则直接传回最后一个指令的地址+4
//        System.out.println(String.format("end address:0x%x endop:%s",ins.address,opstr));
        return ins.address-0x40000000;
    }
    //获取block的第一个指令地址
    private Long GetStartAddress(Capstone.CsInsn[] insns){
        Capstone.CsInsn ins=insns[0];
        String opstr= ARM.assembleDetail(emulator,ins,ins.address,false,false);
//        System.out.println(String.format("start address:0x%x endop:%s",ins.address,opstr));
        return ins.address-0x40000000;
    }
    //获取csel指令的上一个指令的地址。
    private Long GetCselddress(Capstone.CsInsn[] insns){
        for(Capstone.CsInsn ins : insns){
            if(ins.mnemonic.equals("csel")){
                return ins.address-0x40000000;
            }
        }
        return 0l;
    }

    //获取根据指定block获取对应分支的下一个真实块地址
    private int GetBranchReadlyAddress(Long address){
        for(int i=0;i<readlyBranceBlock.size();i++){
            Pair<Long, Capstone.CsInsn[]> block=readlyBranceBlock.get(i);
            if(block.getKey().intValue()==address.intValue()){
                Pair<Long, Capstone.CsInsn[]> nextBlock=readlyBranceBlock.get(i+1);
                int start_address=GetStartAddress(nextBlock.getValue()).intValue();
                return start_address;
            }
        }
        return 0;
    }

    private int brance_data=0;
    //用来保存所有执行过的block
    ArrayList<Pair<Long, Capstone.CsInsn[]>> blocks=new ArrayList<Pair<Long, Capstone.CsInsn[]>>();
    //保存分支的所有block
    ArrayList<Pair<Long, Capstone.CsInsn[]>> branchBlocks=new ArrayList<Pair<Long, Capstone.CsInsn[]>>();
    //主动调用目标函数
    private void call_calckey(){
        //这里BlockHook就是按照一个block的触发
        emulator.getBackend().hook_add_new(new BlockHook() {
            @Override
            public void hook(Backend backend, long address, int size, Object user) {
                //这里的insns是整个block。
                Capstone.CsInsn[] insns = emulator.disassemble(address, size,0);
//                System.out.println(String.format("address:0x%x size:0x%x",address,insns.length));
                //如果当前块中有分支
                if(brance_data==0){
                    blocks.add(new Pair<Long, Capstone.CsInsn[]>(address,insns));
                }else{
                    branchBlocks.add(new Pair<Long, Capstone.CsInsn[]>(address,insns));
                }

            }
        },0x4000F44C,0x4000F778,null);
        //碰到csel的时候把w8的值修改下。控制走其他分支
        emulator.getBackend().hook_add_new(new CodeHook() {
            @Override
            public void hook(Backend backend, long address, int size, Object user) {
                //这里的insns是整个block。
                Capstone.CsInsn[] insns = emulator.disassemble(address, size,0);
                for(Capstone.CsInsn ins :insns){
                    //这里就是控制如果brance_data为0就固定走第一个分支。为1就固定走第二个分支
                    if(ins.mnemonic.equals("csel")){
                        int w9=emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_W9).intValue();
                        int w10=emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_W10).intValue();
                        if(brance_data==0){
                            emulator.getBackend().reg_write(Arm64Const.UC_ARM64_REG_W10,w9);
                        }else{
                            emulator.getBackend().reg_write(Arm64Const.UC_ARM64_REG_W9,w10);
                        }
                    }
                }
            }
        },0x4000F44C,0x4000F778,null);

        //调用一个返回值为object的静态的jni函数
        StringObject res = mainActivityDvm.callStaticJniMethodObject(emulator, "stringFromJNI()Ljava/lang/String;");
        System.out.println(res.toString());
        brance_data=1;
        StringObject res2 = mainActivityDvm.callStaticJniMethodObject(emulator, "stringFromJNI()Ljava/lang/String;");
        System.out.println(res2.toString());
        //筛选出真实块
        LoadReadlyAddress();
        String modulePath="unidbg-android/src/test/resources/example_binaries/ollvm_fla/libnative-lib.so";
        byte[] sodata=readFile(modulePath);
        //遍历真实块。然后直接修改成跳转真实块
        for(int i=0;i<readlyBlock.size();i++){
            if(i<readlyBlock.size()-1){
                //获取当前真实块
                Pair<Long, Capstone.CsInsn[]>block=readlyBlock.get(i);
                System.out.println(String.format("curBlock address:0x%x",block.getKey()));
                //获取下一个真实块
                Pair<Long, Capstone.CsInsn[]>nextBlock=readlyBlock.get(i+1);

                //取出当前真实块最后一个指令的地址
                int end_address= GetEndAddress(block.getValue()).intValue();
                if(end_address<=0){
                    continue;
                }
                //获取下一个真实块第一个指令的地址
                int start_address=GetStartAddress(nextBlock.getValue()).intValue();
                //这里是最后跳转出结束的地方。由于已经被我们nop掉了循环。所以如果下一个块是跳转出while的。可以直接跳过了
                if(nextBlock.getKey().intValue()==0x4000f76c){
                    continue;
                }
                //获取当前块中的csel地址。如果没有csel则为0
                Long cselAddress=GetCselddress(block.getValue());
                //存在csel指令说明是有分支。然后要特殊处理
                if(cselAddress>0){
                    //获取另一个分支的下一个真实块
                    int start_address2=GetBranchReadlyAddress(block.getKey());
                    try (Keystone keystone = new Keystone(KeystoneArchitecture.Arm64, KeystoneMode.LittleEndian)){
                        /*
                        *要改以下三行的汇编。前面获取出来的cselAddress是CSEL的地址。
                        * TST             W8, #1
                        * CSEL            W8, W9, W10, NE
                        * STR             W8, [SP,#0x50+var_2C]
                        * */
                        int subAddress1=start_address-(cselAddress.intValue())+4;
                        int subAddress2=start_address2-(cselAddress.intValue())+4;
                        String asm1="cmp w8,#0x1";
                        String showAsm1=String.format("b.eq 0x%x",start_address);
                        String showAsm2=String.format("b #0x%x",start_address2);
//                        System.out.println(String.format("address:0x%x chang asm1:%s",cselAddress,showAsm1));
//                        System.out.println(String.format("address:0x%x chang asm2:%s",cselAddress,showAsm2));
                        String asm2=String.format("b.eq 0x%x",subAddress1);
                        String asm3=String.format("b 0x%x",subAddress2);
                        //转换汇编
                        KeystoneEncoded encoded = keystone.assemble(Arrays.asList(asm1,asm2,asm3));
                        byte[] patch = encoded.getMachineCode();
                        if (patch.length <=0) {
                            System.out.println("转换汇编失败");
                            return;
                        }
                        System.out.println(bytesToHexString(patch));
                        //这里去掉基址。再往上一个指令的位置开始写入
                        int replace_address=cselAddress.intValue()-4;
                        //替换原来的字节数据
                        for(int y =0;y<patch.length;y++){
                            sodata[replace_address+y]=patch[y];
                        }
                    }
                    continue;
                }
                //准备转换汇编代码进行替换
                try (Keystone keystone = new Keystone(KeystoneArchitecture.Arm64, KeystoneMode.LittleEndian)) {
                    int subAddress=start_address-end_address;
                    //用来patch修改的asm指令。这里是要计算出当前地址的相对地址跳转。所以上面要减一下。
                    String asmStr=String.format("b #0x%x",subAddress);
                    //这个是我们显示日志看结果的。看看和我们之前手动分析的是不是差不多
                    String showStr=String.format("b #0x%x",start_address);
//                    System.out.println(String.format("address:0x%x chang asm:%s",end_address,showStr));
                    //转换汇编
                    KeystoneEncoded encoded = keystone.assemble(asmStr);
                    byte[] patch = encoded.getMachineCode();
                    if (patch.length <=0) {
                        System.out.println("转换汇编失败");
                        return;
                    }
//                    System.out.println(bytesToHexString(patch));
                    //替换原来的字节数据
                    for(int y =0;y<patch.length;y++){
                        sodata[end_address+y]=patch[y];
                    }
                }
            }
        }
        //循环的地方给nop掉
        byte[] nop_byte=new byte[]{0x1F,0x20,0x03,(byte)0xD5};
        int nop_address=0xF778;
        for(int y =0;y<nop_byte.length;y++){
            sodata[nop_address+y]=nop_byte[y];
        }
        String savepath="unidbg-android/src/test/resources/example_binaries/ollvm_fla/libnative-lib.patch.so";
        writeFile(sodata,savepath);
        System.out.println("处理完成");
    }
}
