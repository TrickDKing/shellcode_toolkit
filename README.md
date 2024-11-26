# shellcode_toolkit
Mini capstone project for assembling and disassembling shellcode\
Project is similar to the functions with msfvenom just more flexible in assembling shellcode for specific functions\
Using WinDbg to figure out the WinAPI calls and set a breakpoint right before certain WinAPI calls involving external connection/socket communications\
### How to use, execute 32-bit or 64-bit Python3 according to architecture of shellcode 
$ python main.py -f [file] 

## Setup
1. Install WinDBG (Classic or Windows 11)
2. Install Python 32-bit and 64-bit
3. pip install dependencies for both x86 and x64 versions of Python
4. python/python3 -m pip install -r requirements.txt
5. Open a Windows Prompt and execute the script
6. F6 > Attach to process
   
## Features 
\xcc INT3 DEBUG byte automatically added at the front of shellcode for debug
