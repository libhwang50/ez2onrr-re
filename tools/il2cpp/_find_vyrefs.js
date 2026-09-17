const mod = Process.getModuleByName("GameAssembly.dll");
const E = n => mod.getExportByName(n);
const D = new NativeFunction(E("il2cpp_domain_get"), 'pointer', []);
const A = new NativeFunction(E("il2cpp_domain_get_assemblies"), 'pointer', ['pointer', 'pointer']);
const I = new NativeFunction(E("il2cpp_assembly_get_image"), 'pointer', ['pointer']);
const IN = new NativeFunction(E("il2cpp_image_get_name"), 'pointer', ['pointer']);
const CC = new NativeFunction(E("il2cpp_image_get_class_count"), 'uint32', ['pointer']);
const CL = new NativeFunction(E("il2cpp_image_get_class"), 'pointer', ['pointer', 'uint32']);
const CN = new NativeFunction(E("il2cpp_class_get_name"), 'pointer', ['pointer']);
const CNS = new NativeFunction(E("il2cpp_class_get_namespace"), 'pointer', ['pointer']);
const FL = new NativeFunction(E("il2cpp_class_get_fields"), 'pointer', ['pointer', 'pointer']);
const FN = new NativeFunction(E("il2cpp_field_get_name"), 'pointer', ['pointer']);
const FO = new NativeFunction(E("il2cpp_field_get_offset"), 'uint32', ['pointer']);
const FT = new NativeFunction(E("il2cpp_field_get_type"), 'pointer', ['pointer']);
const TN = new NativeFunction(E("il2cpp_type_get_name"), 'pointer', ['pointer']);
const FSF = new NativeFunction(E("il2cpp_field_get_flags"), 'uint32', ['pointer']);
const FSV = new NativeFunction(E("il2cpp_field_static_get_value"), 'void', ['pointer', 'pointer']);
const SC = new NativeFunction(E("il2cpp_string_chars"), 'pointer', ['pointer']);
const SL = new NativeFunction(E("il2cpp_string_length"), 'int32', ['pointer']);
function RS(p){ if(!p||p.isNull())return null; try{const l=SL(p); if(l<=0||l>20000)return null; return SC(p).readUtf16String(l);}catch(e){return null;} }
rpc.exports.run = function(){
  const hits=[];
  const dom=D(),sp=Memory.alloc(8),asms=A(dom,sp),n=Number(sp.readU64().toString());
  for(let i=0;i<n;i++){
    let img; try{img=I(asms.add(i*Process.pointerSize).readPointer());}catch(e){continue;}
    let nm; try{nm=IN(img).readUtf8String();}catch(e){continue;}
    if(nm!=="Assembly-CSharp.dll")continue;
    const cnt=CC(img);
    for(let c=0;c<cnt;c++){
      const k=CL(img,c); if(k.isNull())continue;
      let cn; try{cn=CN(k).readUtf8String();}catch(e){continue;}
      let cns=""; try{cns=CNS(k).readUtf8String();}catch(e){}
      let it=Memory.alloc(Process.pointerSize); it.writePointer(NULL);
      let fld;
      while(!(fld=FL(k,it)).isNull()){
        const fn=FN(fld).readUtf8String();
        let t=null; try{t=TN(FT(fld)).readUtf8String();}catch(e){}
        if(t && (t==="vy" || t.indexOf("vy")>=0 || t.indexOf("zf.vy")>=0)){
          let flags=0; try{flags=FSF(fld);}catch(e){}
          hits.push({ns:cns,cls:cn,field:fn,type:t,static:(flags&0x10)!==0,off:FO(fld)});
        }
      }
    }
  }
  return hits;
};
