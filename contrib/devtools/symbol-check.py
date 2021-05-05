#!/usr/bin/env python3
# Copyright (c) 2014 Wladimir J. van der Laan
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
'''
A script to check that the (Linux) executables produced by gitian only contain
allowed gcc, glibc and libstdc++ version symbols.  This makes sure they are
still compatible with the minimum supported Linux distribution versions.

Example usage:

    find ../gitian-builder/build -type f -executable | xargs python contrib/devtools/symbol-check.py
'''
import subprocess
import sys
import os
from typing import List, Optional

import lief
import pixie

# Debian 6.0.9 (Squeeze) has:
#
# - g++ version 4.4.5 (https://packages.debian.org/search?suite=default&section=all&arch=any&searchon=names&keywords=g%2B%2B)
# - libc version 2.11.3 (https://packages.debian.org/search?suite=default&section=all&arch=any&searchon=names&keywords=libc6)
# - libstdc++ version 4.4.5 (https://packages.debian.org/search?suite=default&section=all&arch=any&searchon=names&keywords=libstdc%2B%2B6)
#
# Ubuntu 10.04.4 (Lucid Lynx) has:
#
# - g++ version 4.4.3 (http://packages.ubuntu.com/search?keywords=g%2B%2B&searchon=names&suite=lucid&section=all)
# - libc version 2.11.1 (http://packages.ubuntu.com/search?keywords=libc6&searchon=names&suite=lucid&section=all)
# - libstdc++ version 4.4.3 (http://packages.ubuntu.com/search?suite=lucid&section=all&arch=any&keywords=libstdc%2B%2B&searchon=names)
#
# Taking the minimum of these as our target.
#
# According to GNU ABI document (http://gcc.gnu.org/onlinedocs/libstdc++/manual/abi.html) this corresponds to:
#   GCC 4.4.0: GCC_4.4.0
#   GCC 4.4.2: GLIBCXX_3.4.13, CXXABI_1.3.3
#   (glibc)    GLIBC_2_11
#
MAX_VERSIONS = {
'GCC':       (4,4,0),
'CXXABI':    (1,3,3),
'GLIBCXX':   (3,4,13),
'GLIBC':     (2,11),
'LIBATOMIC': (1,0),
'V':         (0,5,0) # xkb (qt only)
}
# See here for a description of _IO_stdin_used:
# https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=634261#109

# Ignore symbols that are exported as part of every executable
IGNORE_EXPORTS = {
'_edata', '_end', '__end__', '_init', '__bss_start', '__bss_start__', '_bss_end__', '__bss_end__', '_fini', '_IO_stdin_used', 'stdin', 'stdout', 'stderr',
'environ', '_environ', '__environ',
}
CPPFILT_CMD = os.getenv('CPPFILT', '/usr/bin/c++filt')

# Allowed NEEDED libraries
ELF_ALLOWED_LIBRARIES = {
# bitcoind and bitcoin-qt
'libgcc_s.so.1', # GCC base support
'libc.so.6', # C library
'libpthread.so.0', # threading
'libanl.so.1', # DNS resolve
'libm.so.6', # math library
'librt.so.1', # real-time (clock)
'libatomic.so.1',
'ld-linux-x86-64.so.2', # 64-bit dynamic linker
'ld-linux.so.2', # 32-bit dynamic linker
'ld-linux-aarch64.so.1', # 64-bit ARM dynamic linker
'ld-linux-armhf.so.3', # 32-bit ARM dynamic linker
'ld-linux-riscv64-lp64d.so.1', # 64-bit RISC-V dynamic linker
# bitcoin-qt only
'libX11-xcb.so.1', # part of X11
'libX11.so.6', # part of X11
'libxcb.so.1', # part of X11
'libxkbcommon.so.0', # keyboard keymapping
'libxkbcommon-x11.so.0', # keyboard keymapping
'libfontconfig.so.1', # font support
'libfreetype.so.6', # font parsing
'libdl.so.2' # programming interface to dynamic linker
}
ARCH_MIN_GLIBC_VER = {
pixie.EM_386:    (2,1),
pixie.EM_X86_64: (2,2,5),
pixie.EM_ARM:    (2,4),
pixie.EM_AARCH64:(2,17),
pixie.EM_RISCV:  (2,27)
}

MACHO_ALLOWED_LIBRARIES = {
# bitcoind and bitcoin-qt
'libc++.1.dylib', # C++ Standard Library
'libSystem.B.dylib', # libc, libm, libpthread, libinfo
# bitcoin-qt only
'AppKit', # user interface
'ApplicationServices', # common application tasks.
'Carbon', # deprecated c back-compat API
'CoreFoundation', # low level func, data types
'CoreGraphics', # 2D rendering
'CoreServices', # operating system services
'CoreText', # interface for laying out text and handling fonts.
'Foundation', # base layer functionality for apps/frameworks
'ImageIO', # read and write image file formats.
'IOKit', # user-space access to hardware devices and drivers.
'libobjc.A.dylib', # Objective-C runtime library
'DiskArbitration',
'OpenGL',
'AGL',
'Security',
'SystemConfiguration',
'libcups.2.dylib',
'CFNetwork',

}

PE_ALLOWED_LIBRARIES = {
'ADVAPI32.dll', # security & registry
'IPHLPAPI.DLL', # IP helper API
'KERNEL32.dll', # win32 base APIs
'msvcrt.dll', # C standard library for MSVC
'SHELL32.dll', # shell API
'USER32.dll', # user interface
'WS2_32.dll', # sockets
'comdlg32.dll',
'COMDLG32.DLL',
'CRYPT32.dll',
'WINSPOOL.DRV',
# bitcoin-qt only
'dwmapi.dll', # desktop window manager
'GDI32.dll', # graphics device interface
'IMM32.dll', # input method editor
'IMM32.DLL',
'ole32.dll', # component object model
'OLEAUT32.dll', # OLE Automation API
'SHLWAPI.dll', # light weight shell API
'UxTheme.dll',
'VERSION.dll', # version checking
'WINMM.dll', # WinMM audio API
'WINMM.DLL',
}

class CPPFilt(object):
    '''
    Demangle C++ symbol names.

    Use a pipe to the 'c++filt' command.
    '''
    def __init__(self):
        self.proc = subprocess.Popen(CPPFILT_CMD, stdin=subprocess.PIPE, stdout=subprocess.PIPE, universal_newlines=True)

    def __call__(self, mangled):
        self.proc.stdin.write(mangled + '\n')
        self.proc.stdin.flush()
        return self.proc.stdout.readline().rstrip()

    def close(self):
        self.proc.stdin.close()
        self.proc.stdout.close()
        self.proc.wait()

def check_version(max_versions, version, arch) -> bool:
    if '_' in version:
        (lib, _, ver) = version.rpartition('_')
    else:
        lib = version
        ver = '0'
    ver = tuple([int(x) for x in ver.split('.')])
    if not lib in max_versions:
        return False
    return ver <= max_versions[lib] or lib == 'GLIBC' and ver <= ARCH_MIN_GLIBC_VER[arch]

def check_imported_symbols(filename) -> bool:
    elf = pixie.load(filename)
    cppfilt = CPPFilt()
    ok = True

    for symbol in elf.dyn_symbols:
        if not symbol.is_import:
            continue
        sym = symbol.name.decode()
        version = symbol.version.decode() if symbol.version is not None else None
        if version and not check_version(MAX_VERSIONS, version, elf.hdr.e_machine):
            print('{}: symbol {} from unsupported version {}'.format(filename, cppfilt(sym), version))
            ok = False
    return ok

def check_exported_symbols(filename) -> bool:
    elf = pixie.load(filename)
    cppfilt = CPPFilt()
    ok = True
    for symbol in elf.dyn_symbols:
        if not symbol.is_export:
            continue
        sym = symbol.name.decode()
        if elf.hdr.e_machine == pixie.EM_RISCV or sym in IGNORE_EXPORTS:
            continue
        print('{}: export of symbol {} not allowed'.format(filename, cppfilt(sym)))
        ok = False
    return ok

def check_ELF_libraries(filename) -> bool:
    ok = True
    elf = pixie.load(filename)
    for library_name in elf.query_dyn_tags(pixie.DT_NEEDED):
        assert(isinstance(library_name, bytes))
        if library_name.decode() not in ELF_ALLOWED_LIBRARIES:
            print('{}: NEEDED library {} is not allowed'.format(filename, library_name.decode()))
            ok = False
    return ok

def check_MACHO_libraries(filename) -> bool:
    ok: bool = True
    binary = lief.parse(filename)
    for dylib in binary.libraries:
        split = dylib.name.split('/')
        if split[-1] not in MACHO_ALLOWED_LIBRARIES:
            print(f'{split[-1]} is not in ALLOWED_LIBRARIES!')
            ok = False
    return ok

def check_MACHO_min_os(filename) -> bool:
    binary = lief.parse(filename)
    if binary.build_version.minos == [10,14,0]:
        return True
    return False

def check_PE_libraries(filename) -> bool:
    ok: bool = True
    binary = lief.parse(filename)
    for dylib in binary.libraries:
        if dylib not in PE_ALLOWED_LIBRARIES:
            print(f'{dylib} is not in ALLOWED_LIBRARIES!')
            ok = False
    return ok

CHECKS = {
'ELF': [
    ('IMPORTED_SYMBOLS', check_imported_symbols),
    ('EXPORTED_SYMBOLS', check_exported_symbols),
    ('LIBRARY_DEPENDENCIES', check_ELF_libraries)
],
'MACHO': [
    ('DYNAMIC_LIBRARIES', check_MACHO_libraries),
    ('MIN_OS', check_MACHO_min_os),
],
'PE' : [
    ('DYNAMIC_LIBRARIES', check_PE_libraries)
]
}

def identify_executable(executable) -> Optional[str]:
    with open(filename, 'rb') as f:
        magic = f.read(4)
    if magic.startswith(b'MZ'):
        return 'PE'
    elif magic.startswith(b'\x7fELF'):
        return 'ELF'
    elif magic.startswith(b'\xcf\xfa'):
        return 'MACHO'
    return None

if __name__ == '__main__':
    retval = 0
    for filename in sys.argv[1:]:
        try:
            etype = identify_executable(filename)
            if etype is None:
                print(f'{filename}: unknown format')
                retval = 1
                continue

            failed = []
            for (name, func) in CHECKS[etype]:
                if not func(filename):
                    failed.append(name)
            if failed:
                print(f'{filename}: failed {" ".join(failed)}')
                retval = 1
        except IOError:
            print(f'{filename}: cannot open')
            retval = 1
    sys.exit(retval)
