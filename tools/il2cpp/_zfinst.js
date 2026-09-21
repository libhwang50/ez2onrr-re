// Read the zf (WebManager) singleton's TicketValue / TicketReceive etc.
rpc.exports.zfinst = function () {
  return Il2Cpp.perform(() => {
    const img = Il2Cpp.domain.assembly("Assembly-CSharp").image;
    const zf = img.class("zf");
    const out = {};
    const inst = zf.field("instance").value;
    out.instance_is_null = inst === null || inst === undefined;
    if (!inst) return JSON.stringify(out);
    const want = ["TicketReceive", "TicketValue", "vui", "vuj", "vuk", "vul"];
    for (const name of want) {
      try {
        const v = inst.field(name).value;
        out["f_" + name] = (v === null || v === undefined) ? null : String(v);
      } catch (e) { out["f_" + name] = "ERR " + e; }
    }
    return JSON.stringify(out);
  });
};
