from keystone import *
import struct, subprocess, os
import Utils

def AssembleShellCode(assemblyCode, arch, debug=False):
    '''Tranform ASM code into opcodes (machine code)'''
    if(arch == "x64"):
        # Initialize keystone-engine in 64-Bit mode
        ks = Ks(KS_ARCH_X86, KS_MODE_64)
    elif(arch == "x86"):
        # Initialize keystone-engine in 32-Bit mode
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
    shellcode = ""
    try:
        instructions, count = ks.asm(assemblyCode)
        sh = b""
        CSharpOutput = ""
        if(debug):
            sh = AddDebugLine(sh)
        for opcode in instructions:
            sh += struct.pack("B", opcode) # To encode for execution
            CSharpOutput += "0x{0:02x},".format(int(opcode)).rstrip("\n") # For C# shellcode
        shellcode = bytearray(sh)
    except KsError as e:
        print("Assembling failed")
        print("Error: ", end="")
        print(e)
        print(str(e.get_asm_count()))
        return bytearray(b"")
    
    print("Successfully encoded {} instructions!".format(count))
    print("Shellcode size: %d " % len(shellcode))
    
    Utils.PrintCSharpPayload(CSharpOutput[:-1], len(shellcode))
    Utils.PrintPythonPayload(shellcode)
    Utils.WritePayloadToFile(CSharpOutput[:-1]) # TODO ADD A FILENAME PARAM

    return shellcode
