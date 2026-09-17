#!/bin/bash
if [ ! -f "EZ2ON REBOOT R/EZ2ON_Data/il2cpp_data/Metadata/global-metadata_decrypted.dat" ]; then
    echo "global-metadata_decrypted.dat not found! Please run the game once with Frida Gadget to dump metadata."
    exit 1
fi

mkdir -p il2cpp_out
dotnet exec --roll-forward Major /tmp/Il2CppDumper/Il2CppDumper/bin/Release/net8.0/Il2CppDumper.dll \
    "EZ2ON REBOOT R/GameAssembly.dll" \
    "EZ2ON REBOOT R/EZ2ON_Data/il2cpp_data/Metadata/global-metadata_decrypted.dat" \
    il2cpp_out

echo "Metadata dumped to il2cpp_out/"
