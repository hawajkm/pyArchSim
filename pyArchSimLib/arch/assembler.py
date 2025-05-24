# assembler.py
# --------------------------------------------------------------------
#   Assembler to generate an executable binary for MIPS32.
#
# Author\ Khalid Al-Hawaj
# Date  \ 02 May 2025

import os
import re
import json
import struct
import random

class assembler():
  def __init__(s, isa):
    s.arch = isa.arch()
    s.dtype_re = isa.dtype_re

  def getAlignment(s, decl):
    match = s.dtype_re.match(decl)

    elem_sz   = 0
    num_elems = 0

    if match:
      dtype = match.group(1).strip()
      args  = match.group(2).strip()

      dtype_def = s.arch['dtypes'][dtype]

      elem_sz = dtype_def['elem_sz']
      syntax  = dtype_def['syntax' ]

    return elem_sz

  def getAllocSize(s, decl):
    match = s.dtype_re.match(decl)

    elem_sz   = 0
    num_elems = 0

    if match:
      dtype = match.group(1).strip()
      args  = match.group(2).strip()

      dtype_def = s.arch['dtypes'][dtype]

      elem_sz = dtype_def['elem_sz']
      syntax  = dtype_def['syntax' ]

      if   syntax == 'n':
        num_elems = int(args)
      elif syntax == 'str':
        num_elems = len(eval(args))
      elif syntax == 'strz':
        num_elems = len(eval(args)) + 1
      else:
        num_elems = len(args.split(","))

    return elem_sz, num_elems

  def assembleDataDeclaration(s, decl):
    match = s.dtype_re.match(decl)

    byte_array = []
    elem_sz    = 0
    num_elems  = 0 
    if match:
      dtype = match.group(1).strip()
      args  = match.group(2).strip()

      dtype_def = s.arch['dtypes'][dtype]

      elem_sz = dtype_def['elem_sz']
      syntax  = dtype_def['syntax' ]

      if syntax == 'n':
        num_elems = int(args)
        byte_array = [random.randint(0, 256) for _ in range(num_elems)]
      elif syntax == 'str':
        data = eval(args).encode(encoding="utf-8")
        num_elems = len(data)
        byte_array = [x for x in data]
      elif syntax == 'strz':
        data = eval(args).encode(encoding="utf-8")
        num_elems = len(data) + 1
        byte_array = [x for x in data]
        byte_array.append(0)
      else:
        elems = args.split(",")
        num_elems = len(elems)
        for elem in elems:
          data = eval(elem.strip())
          for i in range(elem_sz):
            byte_array.append(data & 0xff)
            data = int(data / 0x100)

    return elem_sz, num_elems, byte_array

  def assembleInstruction(s, pc, inst_str, sym_tbl):
    inst_parts = inst_str.split(" ")

    byte_array = []

    mnemonics = inst_parts[0].strip()
    operands  = " ".join(inst_parts[1:]).strip()

    inst_metadata = s.arch['insts'][mnemonics] if mnemonics in s.arch['insts'] else None

    if inst_metadata:
      op_syntax = inst_metadata['syntax'  ]
      assemble  = inst_metadata['assemble']
      opcode    = inst_metadata['opcode'  ]
      funct     = inst_metadata['funct'   ]
      cond      = inst_metadata['cond'    ]
      shamt     = inst_metadata['shamt'   ]
      code      = inst_metadata['code'    ]

      operands_lst = [x.strip() for x in operands .split(",")]
      syntax_lst   = [x.strip() for x in op_syntax.split(",")]

      fields = {}
      fields['opcode'] = opcode
      fields['rd'    ] = 0
      fields['rs'    ] = 0
      fields['rt'    ] = 0
      fields['shamt' ] = 0
      fields['imm16' ] = 0
      fields['imm26' ] = 0
      fields['funct' ] = funct

      for op,field in zip(operands_lst, syntax_lst):
        if   field == 'd':
          fields['rd'] = s.arch['regs'][op]
        elif field == 'T':
          fields['rt'] = s.arch['regs'][op]
        elif field == 's':
          fields['rs'] = s.arch['regs'][op]
        elif field == 't':
          fields['rt'] = s.arch['regs'][op]
        elif field == 'S':
          fields['shamt'] = eval(op) & 0x1f
        elif field == 'i':
          lbl_re = re.compile(r"(^LSH|^MSH)\((.*)\)$")
          parsed = lbl_re.match(op.strip())
          if parsed:
            addr = sym_tbl[parsed.group(2)]
            if   parsed.group(1) == 'LSH':
              op = (addr >>  0) & 0xffff
            elif parsed.group(1) == 'MSH':
              op = (addr >> 16) & 0xffff
            op = '{:#010x}'.format(op)
          fields['imm16'] = eval(op) & 0xffff
        elif field == 'm':
          mem_re = re.compile(r"^([\d]*)\((.*)\)$")
          parsed = mem_re.match(op)
          if parsed:
            offset_str = '0'
            if parsed.group(1) is not None:
              offset_str = parsed.group(1).strip()
            offset = eval(offset_str)
            base_reg = s.arch['regs'][parsed.group(2).strip()]
            fields['imm16'] = offset
            fields['rs'   ] = base_reg
        elif field == 'p':
          # We use the PC-relative addressing mode
          target_pc = sym_tbl[op]
          offset = int((target_pc - pc - 4) / 4) & 0xffff
          fields['imm16'] = offset
        elif field == 'l':
          # Pseudo-direct addressing mode
          target_pc = sym_tbl[op]
          assert(int(pc >> 26) == int(target_pc >> 26))
          imm = (target_pc >> 2) & 0x3ffffff
          fields['imm26'] = imm

      # hawajkm: I don't know of a better way to handle the 'cond' field!
      #          This shows how MIPS is not that elegant after all, aye.
      if cond is not None:
        fields['rt'] = cond

      if shamt is not None:
        fields['shamt'] = shamt

      if code is not None:
        fields['rs'   ] = (code >> 15) & 0x1f
        fields['rt'   ] = (code >> 10) & 0x1f
        fields['rd'   ] = (code >>  5) & 0x1f
        fields['shamt'] = (code >>  0) & 0x1f

      # Ready?
      inst = assemble(fields)

      byte_array = []
      for i in range(4):
        byte = inst & 0xff
        byte_array.append(byte)
        inst = int(inst / 0x100)
    else:
      print('')
      print('  ERROR! Instruction with mnemonics \'{}\' is undefined.'.format(mnemonics))
      print('')

      exit(-1)

    return byte_array

  def getElem(s, elem):
    if isinstance(elem, str):
      return '\'{}\''.format(elem)
    else:
      return '{}'.format(elem)

  def assemble(s, raw_asm):
    arch = s.arch

    # Remove comments and empty lines
    comm = re.compile(f'([^#]*)(#.*$)')
    asm = []
    for line in raw_asm:
      match = comm.match(line)
      if match is not None:
        line = match.group(1)
      if line.strip():
        asm.append(line.strip())

    # Inline all labels
    old_asm = asm
    asm = []
    buffer = ''
    for line in old_asm:
      buffer = buffer + line
      if line.endswith(':'):
        buffer = buffer + ' '
      else:
        asm.append(buffer)
        buffer = ''

    # Process pseudo-instructions
    # As if, lol...

    # Let's support 'la' at least
    la_re = re.compile(r'(^.*)(la)\s+(.*)\s*,\s*(.*)\s*$')
    old_asm = asm
    asm = []
    buffer = ''
    for line in old_asm:
      buffer = buffer + line
      if line.endswith(':'):
        buffer = buffer + ' '
      else:
        parsed = la_re.match(buffer)

        if parsed:
          rd  = parsed.group(3)
          lbl = parsed.group(4)
          expand  = ''
          expand +=        'lui {}, MSH({})'.format(rd, lbl)
          expand += '\n' + 'ori {}, {}, LSH({})'.format(rd, rd, lbl)
          buffer  = parsed.group(1) + expand

        buffers = buffer.split('\n')
        for buf in buffers:
          asm.append(buf)
        buffer = ''

    # After this point, there should NEVER be any additions to static code
    # hawajkm: we perhaps do not need en elaborate code to handle symbols?

    # Symbol table
    sym_tbl = {}

    # Two sections: Data and Text
    text_section = {'base_addr': 0x0400_0000,
                    'bytes'    : [],
                    'raw'      : [],
                    'curr_addr': 0}
    data_section = {'base_addr': 0x1000_0000,
                    'bytes'    : [],
                    'raw'      : [],
                    'curr_addr': 0}

    lst_dtypes = r'|'.join([r'\.' + x for x in s.arch['dtypes']])
    data_directive = re.compile(r'(^{})(.*$)'.format(lst_dtypes))

    # Fill-in the raw part of the sections and construct the symbol table
    curr_section = 0 # By default, we are in the text section

    # Initialize
    text_section['curr_addr'] = text_section['base_addr']
    data_section['curr_addr'] = data_section['base_addr']

    for line in asm:
      if   line.lower() == '.data':
        curr_section = 1
      elif line.lower() == '.text':
        curr_section = 0
      else:
        # Get active section
        section = None
        if   curr_section == 0:
          section = text_section
        elif curr_section == 1:
          section = data_section

        # Get all labels
        parts = [x.strip() for x in line.split(':')]
        labels = parts[0:-1]
        line   = parts[-1]

        # Get address
        addr = section['curr_addr']

        # Process data
        isDataDirective = s.dtype_re.match(line)
        if isDataDirective:
          elem_sz = s.getAlignment(line)
          if addr % elem_sz != 0:
            addr = addr + (elem_sz - (addr % elem_sz))
            section['curr_addr'] = addr

        # Add labels
        for label in labels:
          if label in sym_tbl:
            continue # hawajkm: throw error
          else:
            sym_tbl[label] = addr

        allocSize = 4

        # Process data
        isDataDirective = s.dtype_re.match(line)
        if isDataDirective:
          directive = isDataDirective.group(1).strip()
          elems     = isDataDirective.group(2).strip()

          elems = elems.replace(r'"', r"'")
          elems_decl = eval(r"[{}]".format(elems))
          line = [r'.' + directive + ' ' + s.getElem(x) for x in elems_decl]

          allocSize = 0
          for alloc in line:
            elem_sz, num_elems = s.getAllocSize(alloc)
            allocSize += (num_elems * elem_sz)

        section['curr_addr'] += allocSize

        # Add to section
        if type(line) is list:
          section['raw'].extend(line)
        else:
          section['raw'].append(line)

    # Substitute symbols

    # Generate binary
    ## Start with data section
    addr = data_section['base_addr']
    for decl in data_section['raw']:
      elem_sz, num_elems, byte_array = s.assembleDataDeclaration(decl)
      if addr % elem_sz != 0:
        padding_sz = elem_sz - (addr % elem_sz)
        addr += padding_sz
        # Add padding
        data_section['bytes'].extend([random.randint(0, 256) for _ in range(padding_sz)])
      data_section['bytes'].extend(byte_array)
      addr += (num_elems * elem_sz)

    ## Now, we do the text section
    addr = text_section['base_addr']
    for inst in text_section['raw']:
      byte_array = s.assembleInstruction(addr, inst, sym_tbl)
      # All instructions should be aligned
      text_section['bytes'].extend(byte_array)
      addr += len(byte_array)

    # Print it?
    #print('Text Section:----------------------')
    #print(os.linesep.join(['  ' + x for x in text_section['raw']]))
    #print('-----------------------------------')
    #print('Data Section:----------------------')
    #print(os.linesep.join(['  ' + x for x in data_section['raw']]))
    #print('-----------------------------------')
    #print('Symbol Table:----------------------')
    #for x in sym_tbl:
    #  print("{} | {:#010x}".format(x.ljust(15), sym_tbl[x]))
    #print('-----------------------------------')
    #print('Assembled Data Section:------------', end='')
    #i = 0
    #for i in range(len(data_section['bytes'])):
    #  if i % 16 == 0: print('\n{:#010x}  '.format(data_section['base_addr'] + i), end='')
    #  print("{:02x} ".format(data_section['bytes'][i]), end='')
    #print('\n-----------------------------------')
    #print('Assembled Text Section:------------', end='')
    #i = 0
    #for i in range(len(text_section['bytes'])):
    #  if i % 16 == 0: print('\n{:#010x}  '.format(text_section['base_addr'] + i), end='')
    #  print("{:02x} ".format(text_section['bytes'][i]), end='')
    #print('\n-----------------------------------')

    elf = {}
    elf['sections'] = {}
    elf['sections']['data'] = data_section
    elf['sections']['text'] = text_section

    return elf
