# Command Collection

## Unix Commands

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
* Mount shared folder in a Linux VM (VMWare)
  * `sudo mount -t fuse.vmhgfs-fuse .host:/ "<folder path>" -o allow_other && echo ".host:/ <folder path> fuse.vmhgfs-fuse allow_other 0 0" >>/etc/fstab`
* Mount Bitlocker encrypted drive in Linux with [dislocker](https://github.com/Aorimn/dislocker)
  * Find drive partition: `sudo fdisk -l`
  * Unlock the drive: `sudo dislocker-fuse -V <drive partition> -u<password> -- /media/bitlocker`
  * Mount the drive: `sudo mount /media/bitlocker/dislocker-file /media/usb -o loop`

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
* Determine profile of image
  * `volatility -f <imagefile> imageinfo`
* 

### Network Forensics



### GUI Programs

* [FTK Imager](https://accessdata.com/products-services/forensic-toolkit-ftk/ftkimager) - evidence acquisition and viewer tool
* [Autopsy](https://www.sleuthkit.org/autopsy/) - digital forensics platform