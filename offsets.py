import pkg_resources

filecache = {}

type_sizes = {
    'UChar': 1,
    'UShort': 2,
    'UInt': 4,
    'ULong': 8, 'ULONG': 8,
    'U128': 16,
    'U256': 32
}

arch_data = {}

defines = {
    'VEX_GUEST_PPC32_REDIR_STACK_SIZE': 16*2,
    'VEX_GUEST_PPC64_REDIR_STACK_SIZE': 16*2
}

def to_int(ival):
    if ival in defines:
        return defines[ival]
    return int(ival, 0)

def load_arch(archh):
    if archh not in arch_data:
        arch_data[archh] = {}

    if archh not in filecache:
        filecache[archh] = open(pkg_resources.resource_filename('pyvex', 'include/libvex_guest_%s.h' % archh)).read()

    return filecache[archh]

a = open(pkg_resources.resource_filename('pyvex', 'include/libvex_guest_offsets.h')).read().splitlines()
for line in a:
    _, defname, offstr = line.split()
    offset = int(offstr, 0)
    _, archname, fieldname = defname.split('_', 2)
    fieldname = fieldname.lower()
    arch_defs = load_arch(archname)

    arraylen = None
    typename = None
    lst = arch_defs.split()
    for i, k in enumerate(lst):
        if k.lower().split('[')[0].strip(';') == 'guest_%s' % fieldname:
            typename = lst[i-1].strip('/*')
            if typename not in type_sizes:
                continue
            if '[' in k:
                arraylen = to_int(k.split('[')[1].split(']')[0])
            break
    else:
        raise Exception("Could not find field in arch %s for %s" % (archname, fieldname))

    fieldsize = type_sizes[typename] * (1 if arraylen is None else arraylen)
    arch_data[archname][fieldname] = (offset, fieldsize)

import archinfo
def canon_name(archh, offseth):
    for some_name, (some_offset, _) in archh.registers.items():
        if some_offset == offseth and some_name in arch_data[archh.vex_arch[7:].lower()]:
            return some_name
    return None

for archname in arch_data:
    try:
        arch = archinfo.arch_from_id(archname)
    except (archinfo.ArchError, RuntimeError):
        print('Skipping', archname)
        continue

    new_register_names = {}
    new_registers_reverse = {}
    misses = []
    for a_offset, a_fieldname in arch.register_names.items():
        cname = canon_name(arch, a_offset)
        if cname is None:
            misses.append((a_offset, a_fieldname))
            continue
        new_offset, new_size = arch_data[archname][cname]
        # deal with picking up subregisters? shouldn't need to, beyond the above...
        new_register_names[new_offset] = a_fieldname

        for alt_name, (sub_offset, sub_size) in arch.registers.items():
            if sub_offset >= a_offset and sub_offset < a_offset + new_size:
                new_sub_offset = new_offset + (sub_offset - a_offset)
                if new_sub_offset not in new_registers_reverse:
                    new_registers_reverse[new_sub_offset] = []
                new_registers_reverse[new_sub_offset].append((sub_size, alt_name))

    for misso, miss in misses:
        for dlist in new_registers_reverse.values():
            for _, alt_name in dlist:
                if alt_name == miss:
                    new_register_names[misso] = miss
                    break
            else:
                continue
            break
        else:
            raise Exception('Arch %s: %s has no name that matches vex' % (arch.name, miss))

    # get ready to write back to archinfo source
    arch_fname = 'archinfo/%s.py' % arch.__class__.__module__.split('.')[-1]
    orig_lines = iter(list(open(arch_fname, 'rb')))
    file_fp = open(arch_fname, 'wb')
    # copy initial lines
    for line in orig_lines:
        if '    register_names = ' in line:
            break
        file_fp.write(line)

    # discard lines we want to replace
    for line in orig_lines:
        if '    registers = ' in line:
            break
    for line in orig_lines:
        if '}' in line:
            break

    # dump out the new data
    file_fp.write('    register_names = {\n')
    for new_offset in sorted(list(new_register_names)):
        file_fp.write('        %d: \'%s\',\n' % (new_offset, new_register_names[new_offset]))
    file_fp.write('    }\n\n')
    file_fp.write('    registers = {\n')

    for new_offset, dlist in sorted(new_registers_reverse.items()):
        for new_size, new_name in sorted(dlist):
            file_fp.write('        \'%s\': (%d, %d),\n' % (new_name, new_offset, new_size))
    file_fp.write('    }\n')

    # dump out the rest of the file
    for line in orig_lines:
        file_fp.write(line)
