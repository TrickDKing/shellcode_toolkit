import argparse, sys, numpy
from argparse import RawTextHelpFormatter
import ctypes, struct
# These below are for calculating entropy
import math
import statistics
from collections import Counter

def PrintArguments():
    parser = argparse.ArgumentParser(
        description="Dissasemble or Assemble Windows x86 & x64 shellcode\nConverts shellcode to binary (.bin) files\nExample: python main.py -f test.bin -arch x86\nAvailable Architectures: Intel x86 or x64",
        formatter_class=RawTextHelpFormatter
    )

    parser.add_argument(
        "-o",
        "--output",
        help="specify the target file to write to",
        action="store_true"
    )

    parser.add_argument(
        "-r",
        "--read-shellcode",
        help="reads shellcode in binary format from a file",
        action="store_true"
    )

    parser.add_argument(
        "-w",
        "--write-shellcode",
        help="Writes keystone-engine custom shellcode as binary format to a file",
        action="store_true"
    )

    parser.add_argument(
        "-b",
        "--read-hexa-shellcode",
        help="reads shellcode in hexadecimal representation from a file",
        action="store_true"
    )

    parser.add_argument(
        "-d",
        "--debug-line",
        help="adds a '\\" + str('xcc') + "' byte INT3 debug statement to the front of the shellcode",
        action="store_true"
    )

    parser.add_argument(
        "-a",
        "--attach",
        help="Attaches to WinDBG 11 (Non-Administrator)",
        action="store_true"
    )

    parser.add_argument(
        "-e",
        "--entropy",
        help="Calculate Shannon entropy of a file",
        action="store_true"
    )

    parser.add_argument(
        "-f",
        "--file",
        help="specify the target file to read",
        action="store",
        required=True
    )

    parser.add_argument(
        "-arch",
        "--architecture",
        help="specify the architecture",
        action="store",
        required=True
    )

    if(len(sys.argv) == 1):
        parser.print_help()

    args = parser.parse_args()
    return args

def PrintPythonPayload(shellCode):
    '''Adjust format and neatly print shellcode for Python'''
    chunk_size = 11
    print(f'Python Payload\nshellcode  = b""')
    for i in range(0, len(shellCode), chunk_size):
        chunk = shellCode[i:i+chunk_size]
        byte_str = ''.join(f"\\x{byte:02x}" for byte in chunk)
        print(f'shellcode += b"{byte_str}"')

def PrintCSharpPayload(payload, payloadSize):
    '''Prints the shellcode in CSharp format, define the payload size as param'''
    print("C# Payload\nbyte[] payload = new byte [%d] { \n%s\n};" % (payloadSize, payload))

def PrintASMCode(ASMCode):
    '''Neatly prints ASM code when disassembled'''
    print("\nFull Assembly Code")
    print("+----------------------------------------------------------------------------------+")
    print("| Address  | OpCode                    | Instruction                               |")
    print("+----------------------------------------------------------------------------------+")

    for instructions in ASMCode:
        hex_width = len(instructions.bytes) * 3
        spaces_width = 20 - hex_width   
        bytes_str = '' 
        for b in instructions.bytes:
            bytes_str += f'{b:02x} '
        print("0x{:08x} : {:s}{:s}\t{:s}\t{:s}".format(instructions.address, bytes_str, ' ' * spaces_width, instructions.mnemonic, instructions.op_str))

def rol_str(byte, count):
    binb = numpy.base_repr(byte, 2).zfill(32)
    while count > 0:
        binb = binb[1:] + binb[0]
        count -= 1
    return (int(binb, 2))

def ror_str(byte, count):
    binb = numpy.base_repr(byte, 2).zfill(32)
    while count > 0:
        binb = binb[-1] + binb[0:-1]
        count -= 1
    return (int(binb, 2))

def ComputeHash(targetFunction):
    '''Takes in a string function name'''
    try:
        edx = 0x00 # Initialize variables
        ror_count = 0
        esi = targetFunction
        for eax in esi:
            edx = edx + ord(eax)
            if ror_count < len(esi)-1:
                edx = ror_str(edx, 0xd)
            ror_count += 1
        print("Computed Hash for function %s: %s" %(targetFunction, hex(edx)))
        return(hex(edx))
    except Exception as e:
        print(f"Error: Unable to compute hash for function name")
        return None  

def ReverseHash(hashValue):
    try:
        #edx = int(hashValue, 16)  # Convert hash value to integer
        edx = hashValue
        esi = bytearray()
        while True:
            eax = edx & 0xFF
            edx >>= 8
            edx = (edx << 13) | (eax >> 3)
            if eax == 0:
                break
            esi.append(eax)
        return bytes(esi[::-1]).decode('utf-8')
    except Exception as e:
        print(f"Error: Unable to reverse hash for function name")
        return None

def ReadByteFile(fileName):
    '''Reads the bytes from a file'''
    try:
        f = open(fileName, 'rb')
        data = f.read()
        print("Read from file %s successful" % fileName)
        return data
    except FileNotFoundError:
        print(f"Error: File not found or unable to read - {fileName}")
        exit()

def ReadFile(fileName):
    '''Reads from a file as a string'''
    try:
        f = open(fileName, 'r')
        data = f.read()
        print("Read from file %s successful" % fileName)
        return data
    except FileNotFoundError:
        print(f"Error: File read error - {fileName}")
        exit()

def WriteBinFile(fileName, shellcode):
    '''Writes the shellcode to file'''
    try:
        f = open(fileName, 'wb')
        print(bytes(shellcode))
        data = f.write(shellcode)
        f.close()
        print(f"Shellcode has been written to {fileName}")
    except Exception as e:
        print(f"Error: File write error - {fileName}")
        exit()

def WritePayloadToFile(payload): # TODO ADD A FILENAME PARAM THRU ARGS
    '''Writes the payload to file for usage later in C# shellcode runner'''
    try:
        fileName = "payload.txt"
        f = open(fileName, "w")
        f.write(payload)
        print("Payload written to %s" % fileName)
    except Exception as e:
        print(e)
        print(f"Error: File write error - {fileName}")
        exit()

def ReadASMFile(fileName):
    '''Reads ASM files that was developed on Keystone-Engine Python'''
    try:
        f = open(fileName, "r")
        asmCode = f.read()
        
        SHELL = ''
        for line in asmCode.split('\n'):
            SHELL += line.split("#")[0].strip()[1:SHELL.find('"')] + '\n'  
        return SHELL
    except Exception as e:
        print(e)
        print(f"Error: File read error - {fileName}")
        exit()

def calculateEntropy(pathToFile):
    '''Calculates the Shannon entropy of a given file.'''

    # Read the file content
    content = ReadByteFile(pathToFile)

    # Calculate the frequency distribution of byte values
    freq_dist = Counter(content)

    # Calculate the probability distribution
    prob_dist = [count / len(content) for count in freq_dist.values()]

    # S ( X ) = − ∑ i = 1 N p ( x i ) log 2 ⁡ ( p ( x i ) )
    # Calculate the entropy using the Shannon entropy formula
    entropy = -sum(p * math.log2(p) for p in prob_dist)

    print(f"Shannon entropy of {pathToFile}: {entropy:.6f} bits per byte")

    return entropy

def AttachToDebugger():
    print("Attaching to debugger, process ID: " + str(os.getpid()))
    subprocess.Popen(["WinDbgX", "/g","/p", str(os.getpid())], shell=True)

def ExecuteShellCode(assemblyCode, arch):
    '''Takes in a bytearray, executes shellcode from the allocated memory'''
    ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_void_p

    ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),
                                          ctypes.c_int(len(assemblyCode)),
                                          ctypes.c_int(0x3000),
                                          ctypes.c_int(0x40))
    buf = (ctypes.c_char * len(assemblyCode)).from_buffer(assemblyCode)
    print("Shellcode located at address %s" % hex(ptr))
    #subprocess.Popen(["WinDbgX", "/g","/p", str(os.getpid())], shell=True)
    input("Press any key to continue...")
    if(arch == "x86"):
        ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr), buf, ctypes.c_int(len(assemblyCode)))
        ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.c_int(ptr),
                                         ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.pointer(ctypes.c_int(0)))
        ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht), ctypes.c_int(-1))
    elif(arch == "x64"):
        ctypes.windll.kernel32.RtlCopyMemory.argtypes = ( ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t ) 
        ctypes.windll.kernel32.CreateThread.argtypes = ( ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.POINTER(ctypes.c_int) ) 
 
        ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_void_p(ptr),buf,ctypes.c_int(len(assemblyCode)))
        handle = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),ctypes.c_int(0),ctypes.c_void_p(ptr),ctypes.c_int(0),ctypes.c_int(0),ctypes.pointer(ctypes.c_int(0)))
        ctypes.windll.kernel32.WaitForSingleObject(handle, -1)
    
def AddDebugLine(assemblyCode):
    '''Append debug int3 to front of code'''
    debugByte = b'\xcc'
    return debugByte + assemblyCode
