const mod = Process.getModuleByName("GameAssembly.dll");
const E = n => mod.getExportByName(n);
const D=new NativeFunction(E("il2cpp_domain_get"),'pointer',[]);
const A=new NativeFunction(E("il2cpp_domain_get_assemblies"),'pointer',['pointer','pointer']);
const I=new NativeFunction(E("il2cpp_assembly_get_image"),'pointer',['pointer']);
const IN=new NativeFunction(E("il2cpp_image_get_name"),'pointer',['pointer']);
const CC=new NativeFunction(E("il2cpp_image_get_class_count"),'uint32',['pointer']);
const CL=new NativeFunction(E("il2cpp_image_get_class"),'pointer',['pointer','uint32']);
const CN=new NativeFunction(E("il2cpp_class_get_name"),'pointer',['pointer']);
const FL=new NativeFunction(E("il2cpp_class_get_fields"),'pointer',['pointer','pointer']);
const FN=new NativeFunction(E("il2cpp_field_get_name"),'pointer',['pointer']);
const FO=new NativeFunction(E("il2cpp_field_get_offset"),'uint32',['pointer']);
const FT=new NativeFunction(E("il2cpp_field_get_type"),'pointer',['pointer']);
const TN=new NativeFunction(E("il2cpp_type_get_name"),'pointer',['pointer']);
const FSF=new NativeFunction(E("il2cpp_field_get_flags"),'uint32',['pointer']);
const TARGET={wa:1,wb:1,wy:1,vx:1,zf:1,da:1,qe:1,wx:1,wr:1,wt:1,wu:1,wf:1};
rpc.exports={run:function(){
  const out={};
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
      if(!TARGET[cn])continue;
      const flds=[];
      let it=Memory.alloc(Process.pointerSize); it.writePointer(NULL);
      let fld;
      while(true){
        try{fld=FL(k,it);}catch(e){break;}
        if(!fld||fld.isNull())break;
        let fname,ftype=null;
        try{fname=FN(fld).readUtf8String();}catch(e){continue;}
        try{ftype=TN(FT(fld)).readUtf8String();}catch(e){}
        let flags=0; try{flags=FSF(fld);}catch(e){}
        flds.push({name:fname,off:FO(fld),type:ftype,static:(flags&0x10)!==0});
      }
      out[cn]=flds;
    }
  }
  return out;
}};
