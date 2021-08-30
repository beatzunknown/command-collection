#!/usr/bin/python3

from pwn import *

PROG_NAME = "./"
REMOTE_IP = ""
REMOTE_PORT = 

if args.REMOTE:
    p = remote(REMOTE_IP, REMOTE_PORT)
    elf = ELF(PROG_NAME)
    rop = ROP(elf)
else:
    p = process(PROG_NAME)
    elf = p.elf
    rop = ROP(elf)

if args.ATTACH:
	gdb.attach(p, '''break main''')

p.interactive()