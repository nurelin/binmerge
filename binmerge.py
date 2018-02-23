#!/usr/bin/python3

import os
import lief
import argparse

lib_exceptions = [ "libc.so.6" ]

def merge(path):
    # Parse the binary
    binary = lief.parse(path)

    # Get and Parse its libraries
    imported_libs_filename = binary.libraries
    print("Imported libs: {}".format(imported_libs_filename))
    libs = list()
    for lib_name in imported_libs_filename:
        if lib_name in lib_exceptions:
            continue
        lib_path = os.path.join('/usr/lib', lib_name)
        lib = lief.parse(lib_path)
        libs.append(lib)
    print("Loaded {} libs".format(len(libs)))

    for lib in libs:
        code_segment = None
        # Merge the LOAD sections
        for segment in lib.segments:
            if segment.type == lief.ELF.SEGMENT_TYPES.LOAD:
                segment_address = binary.add(segment)
                if segment.has(lief.ELF.SEGMENT_FLAGS.X):
                    code_segment = segment_address
        # Relocate the symbols


    # Drop the imported libraries
    for lib in libs:
        binary.remove_library(lib.name)

    # Dump the resulting file
    output_name = os.path.basename(path) + "_merged"
    binary.write(output_name)
    print("Result file written to", output_name)

def check(path):
    if lief.is_pe(path):
        print("PE not supported")
        return -1
    if lief.is_macho(path):
        print("Macho not supported")
        return -1
    if lief.is_elf(path):
        return 0
    return -1

def main():
    arg_parser = argparse.ArgumentParser(description='Merge binary and shared library')
    arg_parser.add_argument('binary_path',
                            metavar='binary',
                            type=str,
                            help='Binary file to merge')
    args = arg_parser.parse_args()

    if check(args.binary_path) is not 0:
        return -1

    merge(args.binary_path)

if __name__ == "__main__":
    main()
