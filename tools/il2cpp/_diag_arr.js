const mod = Process.getModuleByName("GameAssembly.dll");
const E = n => mod.getExportByName(n);
const D = new NativeFunction(E("il2cpp_domain_get"), 'pointer', []);
const A = new NativeFunction(E("il2cpp_domain_get_assemblies"), 'pointer', ['pointer','pointer']);
const I = new NativeFunction(E("il2cpp_assembly_get_image"), 'pointer', ['pointer']);
const IN = new NativeFunction(E("il2cpp_image_get_name"), 'pointer', ['pointer']);
const CFN = new NativeFunction(E("il2cpp_class_from_name"), 'pointer', ['pointer','pointer','pointer']);
const ANEW = new NativeFunction(E("il2cpp_array_new"), 'pointer', ['pointer','uint64']);
const TATTACH = new NativeFunction(E("il2cpp_thread_attach"), 'pointer', ['pointer']);
function imageByName(name){ const sp=Memory.alloc(8); const asms=A(D(),sp),n=Number(sp.readU64().toString());
  for(let i=0;i<n;i++){ let img; try{img=I(asms.add(i*Process.pointerSize).readPointer());}catch(e){continue;} let nm; try{nm=IN(img).readUtf8String();}catch(e){continue;} if(nm===name)return img;} return null; }
rpc.exports.run = function(){
  const out={};
  try { TATTACH(D()); } catch(e) { out.attachErr=''+e; }
  const mscorlib = imageByName('mscorlib.dll');
  out.mscorlib = mscorlib ? mscorlib.toString() : null;
  const byteKlass = CFN(mscorlib, Memory.allocUtf8String('System'), Memory.allocUtf8String('Byte'));
  out.byteKlass = byteKlass ? byteKlass.toString() : null;
  let arr;
  try { arr = ANEW(byteKlass, 16); } catch(e){ out.arrErr=''+e; return out; }
  out.arr = arr ? arr.toString() : 'null';
  try { out.arrKlass = arr.readPointer().toString(); } catch(e){ out.arrKlassErr=''+e; }
  try { out.arrLen = Number(arr.add(0x18).readS64().toString()); } catch(e){ out.arrLenErr=''+e; }
  try { const r=Process.findRangeByAddress(arr); out.range = r ? (r.base+' size='+r.size+' prot='+r.protection) : 'none'; } catch(e){ out.rangeErr=''+e; }
  try { const r=Process.findRangeByAddress(arr.add(0x20)); out.dataRange = r ? (r.base+' size='+r.size+' prot='+r.protection) : 'none'; } catch(e){ out.dataRangeErr=''+e; }
  try { arr.add(0x20).writeU8(0xAA); out.wroteU8=true; } catch(e){ out.writeU8Err=''+e; }
  try { arr.add(0x20).writeByteArray(new Uint8Array(16).buffer); out.wroteArrBuf=true; } catch(e){ out.writeArrBufErr=''+e; }
  return out;
};
