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
const FSV=new NativeFunction(E("il2cpp_field_static_get_value"),'void',['pointer','pointer']);
const SC=new NativeFunction(E("il2cpp_string_chars"),'pointer',['pointer']);
const SL=new NativeFunction(E("il2cpp_string_length"),'int32',['pointer']);
function RS(p){if(!p||p.isNull())return null;try{const l=SL(p);if(l<=0||l>20000)return null;return SC(p).readUtf16String(l);}catch(e){return null;}}
rpc.exports={run:function(){
  const dom=D(),sp=Memory.alloc(8),asms=A(dom,sp),n=sp.readU64().toNumber();
  for(let i=0;i<n;i++){
    const img=I(asms.add(i*Process.pointerSize).readPointer());
    let nm;try{nm=IN(img).readUtf8String();}catch(e){continue;}
    if(nm!=="Assembly-CSharp.dll")continue;
    const cnt=CC(img);
    for(let c=0;c<cnt;c++){
      const k=CL(img,c); if(k.isNull())continue;
      if(CN(k).readUtf8String()!=="InGameCore")continue;
      let it=Memory.alloc(Process.pointerSize);it.writePointer(NULL);let fld,inst=null;
      const flds=[];
      while(!(fld=FL(k,it)).isNull()){
        const fname=FN(fld).readUtf8String();
        let t=null;try{t=TN(FT(fld)).readUtf8String();}catch(e){}
        flds.push({name:fname,off:FO(fld),type:t});
        if(fname==="instance")inst=fld;
      }
      const vp=Memory.alloc(Process.pointerSize);FSV(inst,vp);
      const o=vp.readPointer();
      const out={strings:{},bytearrays:{}};
      for(const f of flds){
        if(f.off<=0)continue;
        try{
          if(f.type&&f.type.indexOf("System.String")>=0&&f.type.indexOf("[]")<0){
            const s=RS(o.add(f.off).readPointer()); if(s)out.strings[f.name]=s;
          } else if(f.type&&f.type.indexOf("System.Byte[]")>=0){
            const p=o.add(f.off).readPointer();
            if(!p.isNull()){const l=p.add(0x18).readS32();
              if(l>0&&l<=2048)out.bytearrays[f.name]={len:l,hex:Array.from(new Uint8Array(p.add(0x20).readByteArray(l))).map(b=>b.toString(16).padStart(2,'0')).join('')};}
          }
        }catch(e){}
      }
      return out;
    }
  }
  return {error:"InGameCore not found"};
}};
