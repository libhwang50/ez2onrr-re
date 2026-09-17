const mod = Process.getModuleByName("GameAssembly.dll");
const E = n => mod.getExportByName(n);
const D = new NativeFunction(E("il2cpp_domain_get"), 'pointer', []);
const A = new NativeFunction(E("il2cpp_domain_get_assemblies"), 'pointer', ['pointer','pointer']);
const I = new NativeFunction(E("il2cpp_assembly_get_image"), 'pointer', ['pointer']);
const IN = new NativeFunction(E("il2cpp_image_get_name"), 'pointer', ['pointer']);
const CM = new NativeFunction(E("il2cpp_class_get_methods"), 'pointer', ['pointer','pointer']);
const MN = new NativeFunction(E("il2cpp_method_get_name"), 'pointer', ['pointer']);
const MPC = new NativeFunction(E("il2cpp_method_get_param_count"), 'uint32', ['pointer']);
const CFN = new NativeFunction(E("il2cpp_class_from_name"), 'pointer', ['pointer','pointer','pointer']);
const ANEW = new NativeFunction(E("il2cpp_array_new"), 'pointer', ['pointer','uint64']);
const TATTACH = new NativeFunction(E("il2cpp_thread_attach"), 'pointer', ['pointer']);
function imageByName(name){ const sp=Memory.alloc(8); const asms=A(D(),sp),n=Number(sp.readU64().toString());
  for(let i=0;i<n;i++){ let img; try{img=I(asms.add(i*Process.pointerSize).readPointer());}catch(e){continue;} let nm; try{nm=IN(img).readUtf8String();}catch(e){continue;} if(nm===name)return img;} return null; }
function classByName(img,ns,name){ return CFN(img, Memory.allocUtf8String(ns), Memory.allocUtf8String(name)); }
function methodByName(k,name,np){ let it=Memory.alloc(Process.pointerSize); it.writePointer(NULL); let m;
  while(!(m=CM(k,it)).isNull()){ let mn=''; try{mn=MN(m).readUtf8String();}catch(e){} if(mn===name&&(np==null||MPC(m)===np))return m; } return null; }
function hexToU8(hex){ const n=hex.length/2; const a=new Uint8Array(n); for(let i=0;i<n;i++)a[i]=parseInt(hex.substr(i*2,2),16); return a; }
rpc.exports.call = function(cls, method, argHexes){
  const steps=[];
  try { TATTACH(D()); } catch(e){ return {error:'attach '+e}; }
  const img = imageByName('Assembly-CSharp.dll');
  const k = classByName(img, '', cls);
  const m = methodByName(k, method, argHexes.length);
  if(!m||m.isNull()) return {error:'no method'};
  const native = m.readPointer();
  steps.push('native='+native.toString());
  const mscorlib = imageByName('mscorlib.dll');
  const byteKlass = classByName(mscorlib,'System','Byte');
  const args=[];
  for(let i=0;i<argHexes.length;i++){
    const u8=hexToU8(argHexes[i]);
    const arr=ANEW(byteKlass, u8.length);
    arr.add(0x20).writeByteArray(u8.buffer);
    args.push(arr);
    steps.push('arg'+i+'='+arr.toString()+' len='+u8.length);
  }
  try {
    const f = new NativeFunction(native, 'pointer', args.map(()=> 'pointer'));
    const res = f.apply(null, args);
    steps.push('res='+(res?res.toString():'null'));
    let out=null;
    if(res && !res.isNull()){
      const len=Number(res.add(0x18).readS64().toString());
      const b=new Uint8Array(res.add(0x20).readByteArray(Math.min(len,64)));
      out={len:len, hex:Array.from(b).map(x=>x.toString(16).padStart(2,'0')).join(''), ascii:Array.from(b).map(x=>(x>=32&&x<127)?String.fromCharCode(x):'.').join('')};
    }
    return {ok:true, result:out, steps:steps};
  } catch(e){ return {error:''+e, steps:steps}; }
};
