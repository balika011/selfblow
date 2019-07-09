#!/usr/bin/env python2

# Copyright (c) 2015, NVIDIA CORPORATION.  All rights reserved.
# Copyright (c) 2019, Balázs Tiszka (balika011@gmail.com)
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#  * Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#  * Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#  * Neither the name of NVIDIA CORPORATION nor the names of its
#    contributors may be used to endorse or promote products derived
#    from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS ``AS IS'' AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
# EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
# PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
# OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import argparse
import os.path
import shutil
import struct
import sys

def int_anybase(s):
    return int(s, 0)

parser = argparse.ArgumentParser(description='Add tboot headers to a bootloader binary')
parser.add_argument('--debug', action='store_true', help='Turn on debugging prints')
parser.add_argument('--cpuparams', action='store_true', help='Add a "cpuparams" header too')
parser.add_argument('bootloader', help='Bootloader input file')
parser.add_argument('blloadaddr', type=int_anybase, help='Bootloader load address')
parser.add_argument('image', help='Image output file')
parser.add_argument('imgloadaddr', nargs='?', help='File to contain image load address')
args = parser.parse_args()
if args.debug: print(args)

tboot_hdr_struct = ('<' +
    'I' +      # Reserved
    'cccc' +         # Magic
    'Q' +            # LengthInsecure
    'Q' +            # LoadAddressInsecure
    ('x' * 64 * 4) + # PublicKey
    ('x' * 4 * 4) +  # Signature.CryptoHash
    ('x' * 64 * 4) + # Signature.RsaPssSig
    ('x' * 2 * 4) +  # Padding
    ('x' * 4 * 4) +  # RandomAesBlock
    'Q' +            # LengthSecure
    'Q' +            # LoadAddressSecure
    'Q')             # EntryPoint
tboot_hdr_size = struct.calcsize(tboot_hdr_struct)

cpu_params_hdr = chr(0) * 0x90
cpu_params_hdr_size = len(cpu_params_hdr)

bl_len = os.path.getsize(args.bootloader)

hdr_load_addr = args.blloadaddr - tboot_hdr_size
hdr_entry_addr = args.blloadaddr
image_len = bl_len + tboot_hdr_size
if args.cpuparams:
    hdr_load_addr -= cpu_params_hdr_size
    hdr_entry_addr -= cpu_params_hdr_size
    image_len += cpu_params_hdr_size

tboot_hdr = struct.pack(tboot_hdr_struct,
	0xEA000094, # B 0x258
    'T', 'B', 'C', '\x00',
    image_len,
    hdr_load_addr,
    image_len,
    hdr_load_addr,
    hdr_entry_addr)

fo = file(args.image, 'wb')
fo.write(tboot_hdr)
if args.cpuparams:
    fo.write(cpu_params_hdr)
fi = file(args.bootloader, 'rb')
shutil.copyfileobj(fi, fo)
fi.close()
fo.close()

if args.imgloadaddr:
    fo = file(args.imgloadaddr, 'wt')
    print >>fo, '0x%x' % hdr_load_addr
    fo.close()
