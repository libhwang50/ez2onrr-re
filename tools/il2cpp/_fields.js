const mod = Process.getModuleByName("GameAssembly.dll");
const E = n => mod.getExportByName(n);
const D=new NativeFunction(E("il2cpp_domain_get"),'pointer',[]);
const A=new NativeFunction(E("il2cpp_domain_get_assemblies"),'pointer',['pointer','pointer']);
const I=new NativeFunction(E("il2cpp_assembly_get_image"),'pointer',['pointer']);
const IN=new NativeFunction(E("il2cpp_image_get_name"),'pointer',['pointer']);
const CC=new NativeFunction(E("il2cpp_image_get_class_count"),'uint32',['pointer']);
const CL=new NativeFunction(E("il2cpp_image_get_class"),'pointer',['pointer','uint32']);
const CN=new NativeFunction(E("il2cpp_class_get_name"),'pointer',['pointer']);
const CNS=new NativeFunction(E("il2cpp_class_get_namespace"),'pointer',['pointer']);
const FL=new NativeFunction(E("il2cpp_class_get_fields"),'pointer',['pointer','pointer']);
const FN=new NativeFunction(E("il2cpp_field_get_name"),'pointer',['pointer']);
const FO=new NativeFunction(E("il2cpp_field_get_offset"),'uint32',['pointer']);
const FT=new NativeFunction(E("il2cpp_field_get_type"),'pointer',['pointer']);
const TN=new NativeFunction(E("il2cpp_type_get_name"),'pointer',['pointer']);
rpc.exports={run:function(){
  const hits=[]; const ingame=[];
  const dom=D(),sp=Memory.alloc(8),asms=A(dom,sp),n=sp.readU64().toNumber();
  for(let i=0;i<n;i++){
    let img; try{img=I(asms.add(i*Process.pointerSize).readPointer());}catch(e){continue;}
    let nm; try{nm=IN(img).readUtf8String();}catch(e){continue;}
    if(nm!=="Assembly-CSharp.dll")continue;
    const cnt=CC(img);
    for(let c=0;c<cnt;c++){
      let k; try{k=CL(img,c);}catch(e){continue;}
      if(!k||k.isNull())continue;
      let cn; try{cn=CN(k).readUtf8String();}catch(e){continue;}
      let cns=""; try{cns=CNS(k).readUtf8String();}catch(e){}
      let it=Memory.alloc(Process.pointerSize); it.writePointer(NULL);
      let fld;
      while(true){
        try{fld=FL(k,it);}catch(e){break;}
        if(!fld||fld.isNull())break;
        let fname,ftype=null;
        try{fname=FN(fld).readUtf8String();}catch(e){continue;}
        try{ftype=TN(FT(fld)).readUtf8String();}catch(e){}
        const low=(fname||"").toLowerCase();
        const rec={cls:cn,ns:cns,field:fname,off:FO(fld),type:ftype};
        if(cn==="InGameCore")ingame.push(rec);
        if(low.indexOf("crypt")>=0||low.indexOf("aes")>=0||low.indexOf("_key")>=0||low.indexOf("key_")>=0||low.indexOf("key")===0){
          hits.push(rec);
        }
      }
    }
  }
  return {ingame:ingame, cryptHits:hits};
}};
