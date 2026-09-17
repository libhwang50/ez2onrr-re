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
rpc.exports.run=function(){
  const out=[];
  const dom=D(),sp=Memory.alloc(8),asms=A(dom,sp),n=Number(sp.readU64().toString());
  for(let i=0;i<n;i++){
    let img; try{img=I(asms.add(i*Process.pointerSize).readPointer());}catch(e){continue;}
    let nm; try{nm=IN(img).readUtf8String();}catch(e){continue;}
    if(nm!=="Assembly-CSharp.dll")continue;
    const cnt=CC(img);
    for(let c=0;c<cnt;c++){
      const k=CL(img,c); if(k.isNull())continue;
      let cn; try{cn=CN(k).readUtf8String();}catch(e){continue;}
      let ns=""; try{ns=CNS(k).readUtf8String();}catch(e){}
      if(/aes|manager|crypt|bundle|pattern|download|web|http|load|file|sheet|music/i.test(cn+ns)) out.push(ns+"|"+cn);
    }
  }
  return out;
};
