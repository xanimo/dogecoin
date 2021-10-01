#!/usr/bin/env python3
# Copyright (c) 2015-2017 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
'''
Test script for security-check.py
'''
import subprocess
from typing import List
import unittest

from utils import determine_wellknown_cmd

def write_testcode(filename):
    with open(filename, 'w') as f:
        f.write('''
    #include <stdio.h>
    int main()
    {
        printf("the quick brown fox jumps over the lazy god\\n");
        return 0;
    }
    ''')

def call_security_check(cc, source, executable, options):
    # This should behave the same as AC_TRY_LINK, so arrange well-known flags
    # in the same order as autoconf would.
    #
    # See the definitions for ac_link in autoconf's lib/autoconf/c.m4 file for
    # reference.
    env_flags: List[str] = []
    for var in ['CFLAGS', 'CPPFLAGS', 'LDFLAGS']:
        env_flags += filter(None, os.environ.get(var, '').split(' '))

    subprocess.run([*cc,source,'-o',executable] + env_flags + options, check=True)
    p = subprocess.run(['./contrib/devtools/security-check.py',executable], stdout=subprocess.PIPE, universal_newlines=True)
    return (p.returncode, p.stdout.rstrip())

class TestSecurityChecks(unittest.TestCase):
    def test_ELF(self):
        source = 'test1.c'
        executable = 'test1'
        cc = determine_wellknown_cmd('CC', 'gcc')
        write_testcode(source)

        self.assertEqual(call_security_check(cc, source, executable, ['-Wl,-zexecstack','-fno-stack-protector','-Wl,-znorelro']), 
                (1, executable+': failed PIE NX RELRO Canary'))
        self.assertEqual(call_security_check(cc, source, executable, ['-Wl,-znoexecstack','-fno-stack-protector','-Wl,-znorelro']), 
                (1, executable+': failed PIE RELRO Canary'))
        self.assertEqual(call_security_check(cc, source, executable, ['-Wl,-znoexecstack','-fstack-protector-all','-Wl,-znorelro']), 
                (1, executable+': failed PIE RELRO'))
        self.assertEqual(call_security_check(cc, source, executable, ['-Wl,-znoexecstack','-fstack-protector-all','-Wl,-znorelro','-pie','-fPIE']), 
                (1, executable+': failed RELRO'))
        self.assertEqual(call_security_check(cc, source, executable, ['-Wl,-znoexecstack','-fstack-protector-all','-Wl,-zrelro','-Wl,-z,now','-pie','-fPIE']), 
                (0, ''))

    def test_PE(self):
        source = 'test1.c'
        executable = 'test1.exe'
        cc = determine_wellknown_cmd('CC', 'i686-w64-mingw32-gcc')
        write_testcode(source)

        self.assertEqual(call_security_check(cc, source, executable, ['-Wl,--no-nxcompat','-Wl,--disable-reloc-section','-Wl,--no-dynamicbase','-Wl,--no-high-entropy-va','-no-pie','-fno-PIE']),
            (1, executable+': failed PIE DYNAMIC_BASE HIGH_ENTROPY_VA NX RELOC_SECTION'))
        self.assertEqual(call_security_check(cc, source, executable, ['-Wl,--nxcompat','-Wl,--disable-reloc-section','-Wl,--no-dynamicbase','-Wl,--no-high-entropy-va','-no-pie','-fno-PIE']),
            (1, executable+': failed PIE DYNAMIC_BASE HIGH_ENTROPY_VA RELOC_SECTION'))
        self.assertEqual(call_security_check(cc, source, executable, ['-Wl,--nxcompat','-Wl,--enable-reloc-section','-Wl,--no-dynamicbase','-Wl,--no-high-entropy-va','-no-pie','-fno-PIE']),
            (1, executable+': failed PIE DYNAMIC_BASE HIGH_ENTROPY_VA'))
        self.assertEqual(call_security_check(cc, source, executable, ['-Wl,--nxcompat','-Wl,--enable-reloc-section','-Wl,--no-dynamicbase','-Wl,--no-high-entropy-va','-pie','-fPIE']),
            (1, executable+': failed PIE DYNAMIC_BASE HIGH_ENTROPY_VA'))  # -pie -fPIE does nothing unless --dynamicbase is also supplied
        self.assertEqual(call_security_check(cc, source, executable, ['-Wl,--nxcompat','-Wl,--enable-reloc-section','-Wl,--dynamicbase','-Wl,--no-high-entropy-va','-pie','-fPIE']),
            (1, executable+': failed HIGH_ENTROPY_VA'))
        self.assertEqual(call_security_check(cc, source, executable, ['-Wl,--nxcompat','-Wl,--enable-reloc-section','-Wl,--dynamicbase','-Wl,--high-entropy-va','-pie','-fPIE']),
            (0, ''))

        clean_files(source, executable)

    def test_MACHO(self):
        source = 'test1.c'
        executable = 'test1'
        cc = determine_wellknown_cmd('CC', 'clang')
        write_testcode(source)

        self.assertEqual(call_security_check(cc, source, executable, []), 
                (1, executable+': failed PIE NX'))
        self.assertEqual(call_security_check(cc, source, executable, ['-Wl,--nxcompat']), 
                (1, executable+': failed PIE'))
        self.assertEqual(call_security_check(cc, source, executable, ['-Wl,--nxcompat','-Wl,--dynamicbase']), 
                (0, ''))

if __name__ == '__main__':
    unittest.main()
