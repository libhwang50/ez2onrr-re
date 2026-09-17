const mod = Process.getModuleByName("GameAssembly.dll");
const E = n => mod.getExportByName(n);
const D = new NativeFunction(E("il2cpp_domain_get"), 'pointer', []);
const A = new NativeFunction(E("il2cpp_domain_get_assemblies"), 'pointer', ['pointer','pointer']);
const I = new NativeFunction(E("il2cpp_assembly_get_image"), 'pointer', ['pointer']);
const IN = new NativeFunction(E("il2cpp_image_get_name"), 'pointer', ['pointer']);
const CC = new NativeFunction(E("il2cpp_image_get_class_count"), 'uint32', ['pointer']);
const CL = new NativeFunction(E("il2cpp_image_get_class"), 'pointer', ['pointer','uint32']);
const CN = new NativeFunction(E("il2cpp_class_get_name"), 'pointer', ['pointer']);
const CM = new NativeFunction(E("il2cpp_class_get_methods"), 'pointer', ['pointer','pointer']);
const MN = new NativeFunction(E("il2cpp_method_get_name"), 'pointer', ['pointer']);
const MPC = new NativeFunction(E("il2cpp_method_get_param_count"), 'uint32', ['pointer']);
const MRT = new NativeFunction(E("il2cpp_method_get_return_type"), 'pointer', ['pointer']);
const TYPEN = new NativeFunction(E("il2cpp_type_get_name"), 'pointer', ['pointer']);
const TATTACH = new NativeFunction(E("il2cpp_thread_attach"), 'pointer', ['pointer']);
const MF = new NativeFunction(E("il2cpp_method_get_flags"), 'uint32', ['pointer','pointer']);
const GD = new NativeFunction(E("il2cpp_gc_disable"), 'void', []);
const GE = new NativeFunction(E("il2cpp_gc_enable"), 'void', []);
function tname(t){ try{return TYPEN(t).readUtf8String();}catch(e){return null;} }
rpc.exports.find = function(){
  const out=[]; const dom=D(),sp=Memory.alloc(8); const asms=A(dom,sp),n=Number(sp.readU64().toString());
  for(let i=0;i<n;i++){ let img; try{img=I(asms.add(i*Process.pointerSize).readPointer());}catch(e){continue;} let nm; try{nm=IN(img).readUtf8String();}catch(e){continue;}
    if(nm!=='Assembly-CSharp.dll')continue; const cnt=CC(img);
    for(let c=0;c<cnt;c++){ let k; try{k=CL(img,c);}catch(e){continue;} if(k.isNull())continue;
      let cn; try{cn=CN(k).readUtf8String();}catch(e){continue;}
      let it=Memory.alloc(Process.pointerSize); it.writePointer(NULL); let m;
      while(!(m=CM(k,it)).isNull()){ if(MPC(m)!==0)continue; let fl=MF(m,Memory.alloc(4)); if((fl&0x10)===0)continue; let rt=tname(MRT(m)); if(rt!=='System.String'&&rt!=='System.Byte[]')continue;
        let mn=''; try{mn=MN(m).readUtf8String();}catch(e){}
        out.push({cls:cn,method:mn,native:m.readPointer().toString()}); if(out.length>=10)return out; }
    } }
  return out;
};
rpc.exports.call0 = function(native, retkind){ TATTACH(D());
  try { const f=new NativeFunction(ptr(native),'pointer',[]); const v=f(); let s=null; try{ if(!v.isNull()){ if(retkind==='System.String'){ const L=new NativeFunction(ptr(Process.getModuleByName('GameAssembly.dll').getExportByName('il2cpp_string_length')),'int',['pointer']); const C=new NativeFunction(ptr(Process.getModuleByName('GameAssembly.dll').getExportByName('il2cpp_string_chars')),'pointer',['pointer']); s=C(v).readUtf16String(L(v)); } else { s='bytes len '+Number(v.add(0x18).readS64().toString()); } } }catch(e2){ s='readerr '+e2; } return {ok:true,val:s}; } catch(e){ return {error:''+e}; } };
