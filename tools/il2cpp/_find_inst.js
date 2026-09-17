const mod = Process.getModuleByName("GameAssembly.dll");
const E=n=>mod.getExportByName(n);
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
const SC=new NativeFunction(E("il2cpp_string_chars"),'pointer',['pointer']);
const SL=new NativeFunction(E("il2cpp_string_length"),'int32',['pointer']);
function RS(p){if(!p||p.isNull())return null;try{const l=SL(p);if(l<0||l>3000)return null;const s=SC(p).readUtf16String(l);return s;}catch(e){return null;}}
const TARGET={wa:1,wy:1,wb:1,vx:1};
rpc.exports={run:function(){
  const klass={}, fields={};
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
      klass[cn]=k; const fs=[];
      let it=Memory.alloc(Process.pointerSize); it.writePointer(NULL); let fld;
      while(true){
        try{fld=FL(k,it);}catch(e){break;}
        if(!fld||fld.isNull())break;
        let fname,ftype=null; try{fname=FN(fld).readUtf8String();}catch(e){continue;}
        try{ftype=TN(FT(fld)).readUtf8String();}catch(e){}
        let flags=0;try{flags=FSF(fld);}catch(e){}
        if((flags&0x10)===0) fs.push({name:fname,off:FO(fld),type:ftype});
      }
      fields[cn]=fs;
    }
  }
  const out={};
  for(const cn in klass){
    const buf=Memory.alloc(8); buf.writePointer(klass[cn]);
    const pat=Array.from(new Uint8Array(buf.readByteArray(8))).map(b=>b.toString(16).padStart(2,'0')).join(' ');
    const found=[];
    const ranges=Process.enumerateRanges('rw-');
    for(const r of ranges){
      if(r.size<64||r.size>256*1024*1024)continue;
      let m; try{m=Memory.scanSync(r.base,r.size,pat);}catch(e){continue;}
      for(const x of m){ if(found.length>=6)break; found.push(x.address); }
      if(found.length>=6)break;
    }
    const recs=[];
    for(const addr of found){
      const rec={address:addr.toString(),vals:{}};
      for(const f of (fields[cn]||[])){
        if(f.off<=0)continue;
        try{
          if(f.type==="System.String"){ rec.vals[f.name]=RS(addr.add(f.off).readPointer()); }
          else if(f.type==="System.Int32"){ rec.vals[f.name]=addr.add(f.off).readS32(); }
          else if(f.type==="System.Single"){ rec.vals[f.name]=addr.add(f.off).readFloat(); }
        }catch(e){}
      }
      recs.push(rec);
    }
    out[cn]=recs;
  }
  return out;
}};
