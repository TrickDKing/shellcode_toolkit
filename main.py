import sys
import Utils
import Disassemble
import Assemble

def main():
    args = Utils.PrintArguments()
    if(args.read_shellcode and args.read_hexa_shellcode):
        print("Invalid argument, choose only one read option")
        exit()
    if(args.entropy):    
        entropy = Utils.calculateEntropy(args.file)
    if(args.read_shellcode): # Read byte array literals from a file, unreadable bin file etc
        assemblyCode = Utils.ReadByteFile(args.file)
        Disassemble.DisassembleShellcode(assemblyCode, args.architecture, args.debug_line)
        Utils.ExecuteShellCode(bytearray(assemblyCode), args.architecture)
    elif(args.read_hexa_shellcode): # hex dumped from ida ghidra etc
        shellcodeString = Utils.ReadFile(args.file)
        hexaShellcode = shellcodeString.replace(",", "").replace("0x", "")
        shellCode = bytearray(bytes.fromhex(hexaShellcode))
        Disassemble.DisassembleShellcode(shellCode, args.architecture)
        Utils.ExecuteShellCode(shellCode, args.architecture)
    elif(args.write_shellcode): # For Exploit Dev/shellcode editing
        customShellcode = Utils.ReadASMFile(args.file)
        shellCode = Assemble.AssembleShellCode(customShellcode, args.architecture, args.debug_line)
        Utils.ExecuteShellCode(shellCode, args.architecture)
        #if(args.attach):
        #    Utils.AttachToDebugger()
    else:
        exit()

if __name__ == "__main__":
    main()
