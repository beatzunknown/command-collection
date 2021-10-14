# Command Collection

## Unix Commands

### CLI Tricks & Shortcuts

* `cd -` - takes you to previous directory (instead of parent)
* `sudo !!` - `!!` runs previous command, so this will run previous command as `sudo`
* `^wrong^right` - runs previous command while changing the `wrong` text to `right` text
* `Ctrl+R` - search through previously run commands
* `CDPATH=".:~/"` - lets you `cd` into not just directories in current directory, but also directories in `$HOME`
* `cd ~` or `cd` - lets you change current directory to `$HOME` dir. Latter may not work if you have set your own `$CDPATH`

### binwalk

* View embedded files within files
  * `binwalk -e <file>`
* Extract embedded files within files
  * `binwalk --dd='.*' <filename>`

### grep

* Simple matches
  * `grep <pattern> <file>`
* Show N number of lines before the match
  * `grep <pattern> <file> -B <N>`
* Show N number of lines after the match
  * `grep <pattern> <file> -A <N>`
* Show list of files containing a match
  * `grep -l <pattern> *`
* Use extended regex: `-E`
* Use Perl regex: `-P`
* Inverted match: `-v`
* Whole word grep: `-w`
* Ignore case: `-i`
* Show only match (not whole line with match): `-o`

### strings

* Find all printable strings in file
  * `strings <filename>`
* Limit results to strings at least `n` characters long
  * `strings -n <length> <filename>`
* Prefix each result with offset within file
  * `strings -t -d <filename>`
* Prefix each result with offset within file, in hex
  * `strings -t x <filename>`

### Miscellaneous

* `head` - extract first number of bytes from a file
  * `head -c <number of bytes> <file>`
* `tail` - extract last number of bytes from a file
  * `tail -c <number of bytes> <file>`
* `xxd` - get hex dump of file
  * `xxd <in-file>` - generate a hex dump
  * `xxd -r <in-file> <out-file>` - reverse hexdump: generate a binary output file from an input hex dump
* Mount shared folder in a Linux VM (VMWare)
  * `sudo mount -t fuse.vmhgfs-fuse .host:/ "<folder path>" -o allow_other && echo ".host:/ <folder path> fuse.vmhgfs-fuse allow_other 0 0" >>/etc/fstab`
* Mount Bitlocker encrypted drive in Linux with [dislocker](https://github.com/Aorimn/dislocker)
  * Install: `apt install dislocker`
  * Find drive partition: `sudo fdisk -l`
  * Unlock the drive: `sudo dislocker-fuse -V <drive partition> -u<password> -- /media/bitlocker`
  * Mount the drive: `sudo mount /media/bitlocker/dislocker-file /media/usb -o loop`

## RE / Binary Exploitation

### objdump
* View file header information
  * `objdump -f <binary>`
* View symbol table
  * `objdump -t <binary>`
* Disassemble binary with Intel syntax
  * `objdump -d -Mintel <binary>`
* View contents of a section (hexdump)
  * `objdump -s -j .<section> <binary>`

### Pwndbg

* [Pwndbg](https://github.com/pwndbg/pwndbg) is a GDB plug-in to assist with reverse engineering and exploitation development

* Install:

  * ```
    git clone https://github.com/pwndbg/pwndbg
    cd pwndbg
    ./setup.sh
    ```

* Debug an executable:
  * `gdb <binary>`
  
* Attach a process to gdb
  * `gdb -p <process id>`
  
* Execute GDB commands upon start
  * `gdb -ex "<commands>" <binary>`
  
* Start GDB with specified arguments to pass in
  * `gdb --args <binary> <arg1> <arg2> ...`
  
* Standard GDB commands:
  * `b 0x1337` - break at address 0x1337
  * `c` - continue execution until the next breakpoint or end of program
  * `si` - single step into instruction
  * `ni` - next instruction (doesn't step into)
  * `fin` - execute until the end of current function
  * `x 0x1337` - examine at address 0x1337
  * `x/20wx 0x1337` - examine 20 words (32 bit values) from 0x1337
  * `x/s 0x1337` - examine string at 0x1337
  * `att 1234` - attach to running process 1234
  * `set $<reg>=value` - set the register to the value. Eg: `set $ebx=1`
  
* Heap commands:
  * `heap` - view overview of the heap
  * `bins` - view current heap bins
  * `vis_heap_chunks <address> <num>` - view a number of heap chunks from the specified address. There is no way to show all heap chunks

### rabin2
* `rabin2` is a tool to extract information about binary files. It comes bundles with `radare2`.

* Install `radare2`:

  * ```
    git clone https://github.com/radareorg/radare2
    radare2/sys/install.sh
    ```

* View general information about the binary
  * `rabin2 -I <binary>`
  
* View a list of linked libraries
  * `rabin2 -l <binary>`
  
* View a list of imported library functions
  * `rabin2 -i <binary>`
  
* View a list of string literal in the binary
  * `rabin2 -z <binary>`

### readelf
* `readelf` is a Linux tool to display information about the contents of ELF binary files.
* Display ELF file header
  * `readelf -h <file>`
* Display the program headers
  * `readelf -l <file>`
* Display the sections headers
  * `readelf -S <file>`
* Display the symbol table
  * `readelf -s <file>`

### Ropper

* [Ropper](https://github.com/sashs/Ropper) is a tool to find gadgets for use in ROP chains
* Install: `pip install ropper`
* View all gadgets
  * `ropper -f <binary>`
* Search for gadget
  * `ropper -f <binary> --search '<instruction>'`
  * Eg: `ropper -f <binary> --search 'pop rdi; ret;'`
  * Eg with placeholders: `ropper -f <binary> --search 'pop ???; ret;'`
* Search for strings
  * `ropper -f <binary> --search '<string>'`
* Filter our gadgets with bad bytes
  * `ropper -f <binary> -b <bytes>`
  * Eg to filter newline and null: `ropper -f <binary> -b 000a`

### Disassemblers

* [Binary Ninja](https://binary.ninja/)
* [Ghidra](https://github.com/NationalSecurityAgency/ghidra)

### Miscellaneous

* `strace` - trace system calls during binary execution
  * `strace ./binary`
* `ltrace` - trace library calls during binary execution
  * `ltrace ./binary`
* [checksec](https://www.trapkit.de/tools/checksec/) - a tool to check the properties of executables
  * `checksec <binary>`
* `dmesg` - view segmentation faults and their locations, from processes

## Web Exploitation/Testing

* [Burp Suite](https://portswigger.net/burp/communitydownload) - set of tools for penetration testing of web applications (see below for more details)
* [Fiddler](https://www.telerik.com/download/fiddler) - web debugger / proxy tool that captures ingoing and outgoing network traffic by apps
* [Postman](https://www.postman.com/downloads/) - web API building/testing tool

### BurpSuite

#### Intruder

* Used for attack automation by taking a base HTTP request and modifying various aspects of it
* Various attack types:
  * Sniper - Single wordlist. Used to enumerate each parameter one at a time (while leaving rest of parameters blank).
  * Battering Ram - Single wordlist. Used to enumerate all parameters, using the same payload in each
  * Pitchfork - Multiple wordlists. Enumerates over multiple parameters at the same time, by essentially creating a zip list of the wordlists
  * Cluster bomb - Multiple wordlists. Enumerates over all parameters by using all permutations of wordlists.

## Digital Forensics

* [pkcrack](https://github.com/keyunluo/pkcrack) - known plaintext attack (KPA) to break password protected zips
  * `pkcrack -C encrypted-ZIP -c ciphertext_filename -P plaintext-ZIP -p plaintext_filename -d decrypted_file -a`

### File Enumeration
* `exiftool` - view and write file metadata
  * View metadata - `exiftool <filename>`

### File Carving

* [scalpel](https://github.com/sleuthkit/scalpel) - general file carving
  * `scalpel -o <output dir> -c <config file> <image file>`
* [PhotoRec](https://www.cgsecurity.org/wiki/PhotoRec) - file data recovery software, originally for digital camera memory
  * `photorec /d <output dir> <image file>`
* [recoverjpeg](https://github.com/samueltardieu/recoverjpeg) - tool for recovering JFIF and MOV files from damaged memory
  * `recoverjpeg -o <output dir> <image file>`

### MacOS Forensics

#### Account Password Cracking (OS X Catalina)

* plist password file: `/private/var/db/dslocal/nodes/Default/users/<username>.plist`
* [plistutil](https://github.com/libimobiledevice/libplist) - handle Apple property list files in binary of xml formats
  * Install: `apt install libplist-utils`
  * Convert to xml: `plistutil -i <input plist> -o <output xml>` 
* xmllint - XML and XPath parser
  * Install: `apt install libxml2-utils`
  * Get ShadowHash plist: `xmllint --xpath "//key[text()='ShadowHashData']/following-sibling::array[1]/data/text()" <user xml> | tr -d " \t\n\r" | base64 -d > shadowhash.plist`
* Get ShadowHash XML:
  * `plistutil -i shadowhash.plist -o shadowhash.xml`
* Base64 decode `entropy`, `salt` and `iterations`
* Construct `hashcat`-compatible string of structure:
  * `$ml$<iterations>$<salt>$<entropy>`
* [hashcat](https://github.com/hashcat/hashcat) - password recovery utility
  * Install: `apt install hashcat`
  * Crack password: `hashcat -m 7100 <file with hash string> /usr/share/wordlists/rockyou.txt`

#### Keychain Cracking

##### System Keychain
* Keychain: `/Library/Keychain/System.keychain`
* Key: `/private/var/db/SystemKey`
* [chainbreaker](https://github.com/n0fate/chainbreaker) - Extracts secrets from a Keychain, given a SystemKey or master key from `volatility`/`volafox`
  * `./chainbreaker.py -f <System.keychain> -u <SystemKey>`

##### User Keychain
* Keychain: `~/Library/Keychain/login.keychain-db`
* Key: Known user password
* [Dumpkeychain](https://security.opentext.com/appDetails/Dumpkeychain) - Windows utility for decrypting credentials from keychains
  * `dumpkeychain.exe -u <login.keychain-db> <known password> <output file>`

### Memory Forensics

#### Volatility

* [Volatility](https://github.com/volatilityfoundation/volatility) or [Volatility 3.0](https://github.com/volatilityfoundation/volatility3) are advanced memory forensics frameworks that support analysis of memory images, using OS specific profiles
* Get volatility 3: `git clone https://github.com/volatilityfoundation/volatility3.git`
* Get volatility 2 (outdated): `git clone https://github.com/volatilityfoundation/volatility.git`
* Determine profile of image
  * `volatility -f <imagefile> imageinfo`
* 

### Network Forensics



### GUI Programs

* [FTK Imager](https://accessdata.com/products-services/forensic-toolkit-ftk/ftkimager) - evidence acquisition and viewer tool
* [Autopsy](https://www.sleuthkit.org/autopsy/) - digital forensics platform

## Malware Analysis



## OSINT (Open Source Intelligence)

