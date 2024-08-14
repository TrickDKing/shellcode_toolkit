import struct
import binascii, os, sys
import Utils # Custom import
import subprocess
from capstone import *

def DisassembleShellcode(shellcode, arch, debug=False):
    '''Dissasembles the opcodes and operands (machine code) and returns the ASM code'''
    if(arch == "x64"):
       # Initialize capstone-engine in 64-Bit mode
       md = Cs(CS_ARCH_X86, CS_MODE_64)
    elif(arch == "x86"):
       # Initialize capstone-engine in 32-Bit mode
       md = Cs(CS_ARCH_X86, CS_MODE_32)

    if(debug):
        shellcode = Utils.AddDebugLine(shellcode)

    print("Disassembling shellcode")
    ASMCode = md.disasm(shellcode, 0x0)
    
    Utils.PrintASMCode(ASMCode)
