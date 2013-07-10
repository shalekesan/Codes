#!/usr/bin/env python

'''
 This script is for identify packer/protector and compiler used in your target binary 
 the first version have more than about 5000 signatures ... we will try to updates signatures monthly 
 and for now it will use entry point scaning method ...
 
 Tree Important Notes : 
 First  the database signatures are reaped by lots of people we should thanks them : BoBSoft at Team PEID  , fly , diablo2oo2 and others you can find their name in list ... 
 Second A big thanks to Ero Carrera for his nice python pefile lib the hard part of processing singanutes is done by his library . 
 Third  we updated some of signatures and will keep update them monthly  for detection newer version of packers / comprassion algorithm (hopefully) 
 
 thanks to nicolas waisman / Muts (offsec) and all of abysssec memebers ...
 
 Feel free to contact me with admin [at] abysssec.com
'''

#import python libraries 
import os
import sys
import getopt
import pefile          
import immlib          
import peutils
import hashlib
import shutil
import urllib



__VERSION__ = '0.2'

DESC= "Immunity PyCommand PeDectect will help you to identfy packer / protection used in target binary" 
USAGE = "!PeDetect"



#global
downloaded = 0

#Using debugger functionality 
imm = immlib.Debugger()

# pedram's urllib_hook
def urllib_hook (idx, slice, total):
    global downloaded

    downloaded += slice

    completed = int(float(downloaded) / float(total) * 100)

    if completed > 100:
        completed = 100
        

    imm.Log("   [+] Downloading new signatures ... %d%%" % completed)

# Downloader function
def get_it (url, file_name):
    global downloaded

    downloaded = 0
    u = urllib.urlretrieve(url, reporthook=urllib_hook)
    #imm.Log("")
    shutil.move(u[0], file_name)

# Calculate MD5Checksum for specific file
def md5checksum(fileName, excludeLine="", includeLine=""):
    m = hashlib.md5()
    try:
        fd = open(fileName,"rb")
    except IOError:
        imm.Log("Unable to open the file in readmode:", filename)
        return
    content = fd.readlines()
    fd.close()
    for eachLine in content:
        if excludeLine and eachLine.startswith(excludeLine):
            continue
        m.update(eachLine)
    m.update(includeLine)
    return m.hexdigest()



# Simple Usage Function
def usage(imm):
    imm.Log("!PeDetect -u (for updating signature ... )" )

# Auto-Update function 
def update():
    
    # Using urlretrieve won't overwrite anything 
    try:
        download = urllib.urlretrieve('http://abysssec.com/AbyssDB/Database.TXT')
    except Exception , problem:
        imm.Log ("Error : %s"% problem)
    
    # Computation MD5 cheksum for both existing and our current database
    AbyssDB = md5checksum(download[0])
    ExistDB = md5checksum('Data/Database.TXT')
    
    imm.Log(" [!] Checking for updates ..." , focus=1, highlight=1)
    imm.Log("")
    imm.Log(" [*] Our  database checksum : %s "%AbyssDB)
    imm.Log(" [*] Your database checksum : %s "%ExistDB)
    imm.Log("")
    
    if AbyssDB != ExistDB:
        
        imm.Log("[!] Some update founds updating ....")        
        
        # Removing existing one for be sure ...
        if os.path.exists('Data/Database.txt'):
            os.remove('Data/Database.txt')
         
        # Download latest database 
        try:
            get_it("http://abysssec.com/AbyssDB/Database.TXT", "Data/Database.txt")
        except Exception,mgs:
            return " [-] Problem in downloading new database ..." % mgs
        
        
        imm.log("   [+] Update Comepelete !")
        
    else:
        imm.Log(" [!] You have our latest database ...")
    
        

# Main Fuction 
def main(args):
    
    if args:
        if args[0].lower() == '-u':
            update()
        else:
            imm.Log("[-] Bad argumant use -u for update ...")
            return  "[-] Bad argumant use -u for update ..."
    else:    
        try:
            # Getting loded exe path 
            path = imm.getModule(imm.getDebuggedName()).getPath()
        except Exception, msg:
            return "Error: %s" % msg
        
        # Debugged Name
        name = imm.getDebuggedName()
     
        # Loading loaded pe !
        pe = pefile.PE(path)
        
        # Loading signatures Database 
        signatures = peutils.SignatureDatabase('Data/Database.TXT')
        
        # Mach the signature using scaning entry point only !
        matched = signatures.match(pe , ep_only=True)        
        
        imm.Log("===================  WwW.Abysssec.com  =======================")
        imm.Log("")
        imm.Log("[*] PeDetect By Shahin Ramezany" , focus=1, highlight=2)
        #imm.Log("=============================================================")
        imm.Log("[*] Total loaded  signatures : %d" % (signatures.signature_count_eponly_true + signatures.signature_count_eponly_false + signatures.signature_count_section_start))
        imm.Log("[*] Total ep_only signatures : %d" % signatures.signature_count_eponly_true)
        #imm.Log("=============================================================")
        imm.Log("")
        
        
        # Signature found or not found !
        if matched:
            imm.log("[*] Processing : %s " % name)
            imm.Log("[+] Signature Found  : %s "   % matched , focus=1, highlight=1)
            imm.Log("")
        else:
            imm.log("[*] Processing   %s !" % name)
            imm.Log("   [-] Signatue Not Found !" , focus=1, highlight=1)
            imm.Log("")
    
    # Checking for arguements !
        if not args:
            usage(imm)
            
        return "[+] See log window (Alt-L) for output / result ..."
    
