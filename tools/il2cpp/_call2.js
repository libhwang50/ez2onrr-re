const mod = Process.getModuleByName("GameAssembly.dll");
const E = n => mod.getExportByName(n);
const D = new NativeFunction(E("il2cpp_domain_get"), 'pointer', []);
const A = new NativeFunction(E("il2cpp_domain_get_assemblies"), 'pointer', ['pointer','pointer']);
const I = new NativeFunction(E("il2cpp_assembly_get_image"), 'pointer', ['pointer']);
const IN = new NativeFunction(E("il2cpp_image_get_name"), 'pointer', ['pointer']);
const CM = new NativeFunction(E("il2cpp_class_get_methods"), 'pointer', ['pointer','pointer']);
const MN = new NativeFunction(E("il2cpp_method_get_name"), 'pointer', ['pointer']);
const MPC = new NativeFunction(E("il2cpp_method_get_param_count"), 'uint32', ['pointer']);
const MF = new NativeFunction(E("il2cpp_method_get_flags"), 'uint32', ['pointer','pointer']);
const CFN = new NativeFunction(E("il2cpp_class_from_name"), 'pointer', ['pointer','pointer','pointer']);
const ANEW = new NativeFunction(E("il2cpp_array_new"), 'pointer', ['pointer','uint64']);
const FSV = new NativeFunction(E("il2cpp_field_static_get_value"), 'void', ['pointer','pointer']);
const CM2 = new NativeFunction(E("il2cpp_class_get_fields"), 'pointer', ['pointer','pointer']);
const FN = new NativeFunction(E("il2cpp_field_get_name"), 'pointer', ['pointer']);
const TATTACH = new NativeFunction(E("il2cpp_thread_attach"), 'pointer', ['pointer']);
const GD = new NativeFunction(E("il2cpp_gc_disable"), 'void', []);
const GE = new NativeFunction(E("il2cpp_gc_enable"), 'void', []);
function imageByName(name){ const sp=Memory.alloc(8); const asms=A(D(),sp),n=Number(sp.readU64().toString());
  for(let i=0;i<n;i++){ let img; try{img=I(asms.add(i*Process.pointerSize).readPointer());}catch(e){continue;} let nm; try{nm=IN(img).readUtf8String();}catch(e){continue;} if(nm===name)return img;} return null; }
function classByName(img,ns,name){ return CFN(img, Memory.allocUtf8String(ns), Memory.allocUtf8String(name)); }
function methodByName(k,name,np){ let it=Memory.alloc(Process.pointerSize); it.writePointer(NULL); let m;
  while(!(m=CM(k,it)).isNull()){ let mn=''; try{mn=MN(m).readUtf8String();}catch(e){} if(mn===name&&(np==null||MPC(m)===np))return m; } return null; }
function fieldByName(k,name){ let it=Memory.alloc(Process.pointerSize); it.writePointer(NULL); let f;
  while(!(f=CM2(k,it)).isNull()){ let fn=''; try{fn=FN(f).readUtf8String();}catch(e){} if(fn===name)return f; } return null; }
function hexToU8(hex){ const n=hex.length/2; const a=new Uint8Array(n); for(let i=0;i<n;i++)a[i]=parseInt(hex.substr(i*2,2),16); return a; }
rpc.exports.info = function(cls, method){
  const img=imageByName('Assembly-CSharp.dll'); const k=classByName(img,'',cls); const m=methodByName(k,method,null);
  if(!m||m.isNull())return {error:'no method'};
  const f=Memory.alloc(4); const fl=MF(m,f);
  return {native:m.readPointer().toString(), flags:fl, iflags:f.readU32(), paramCount:MPC(m)};
};
rpc.exports.instanceOf = function(cls){ const img=imageByName('Assembly-CSharp.dll'); const k=classByName(img,'',cls);
  const f=fieldByName(k,'instance'); if(!f)return {error:'no instance field'};
  const vp=Memory.alloc(8); FSV(f,vp); return {instance:vp.readPointer().toString()}; };
rpc.exports.callN = function(cls, method, argHexes, withThis){
  TATTACH(D());
  const img=imageByName('Assembly-CSharp.dll'); const k=classByName(img,'',cls); const m=methodByName(k,method,argHexes.length);
  if(!m||m.isNull())return {error:'no method'};
  const native=m.readPointer();
  const mscorlib=imageByName('mscorlib.dll'); const byteKlass=classByName(mscorlib,'System','Byte');
  const args=[];
  if(withThis){ const vp=Memory.alloc(8); FSV(fieldByName(k,'instance'), vp); args.push(vp.readPointer()); }
  for(let i=0;i<argHexes.length;i++){ const u8=hexToU8(argHexes[i]); const arr=ANEW(byteKlass,u8.length); arr.add(0x20).writeByteArray(u8.buffer); args.push(arr); }
  try { GD(); } catch(e) {}
  try {
    const f=new NativeFunction(native,'pointer',args.map(()=> 'pointer'));
    const res=f.apply(null,args);
    let out=null;
    if(res && !res.isNull()){ const len=Number(res.add(0x18).readS64().toString());
      const b=new Uint8Array(res.add(0x20).readByteArray(Math.min(len,64)));
      out={len:len, hex:Array.from(b).map(x=>x.toString(16).padStart(2,'0')).join(''), ascii:Array.from(b).map(x=>(x>=32&&x<127)?String.fromCharCode(x):'.').join('')}; }
    return {ok:true, result:out, nargs:args.length};
  } catch(e){ return {error:''+e, nargs:args.length}; }
};
