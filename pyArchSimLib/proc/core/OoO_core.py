# oOo_core.py
# --------------------------------------------------------------------
# A Tomasulo-style Out-of-Order Core for MIPS32 in pyArchSim

from pyArchSimLib.arch.isa import mips32
import random

class OoOCore:
    def __init__(s, entry_point=0x04000000, rob_size=32, rs_size=16):
        # Pipeline control
        s.squash = False
        s.squash_pc = entry_point

        # Instruction completion flag
        s.inst_c = False

        # Program counter
        s.pc = entry_point

        # Register file (32 regs)
        s.rf = [0] * 32
        s.rf[0] = 0

        # Reorder Buffer (ROB)
        s.rob = [None] * rob_size
        s.rob_head = 0
        s.rob_tail = 0
        s.rob_size = rob_size

        # Register Alias Table (RAT)
        s.rat = {f"${i}": None for i in range(32)}

        # Reservation Stations
        s.rs_size = rs_size
        s.rs = {
            'ALU': [None] * rs_size,
            'LS':  [None] * rs_size
        }

        # Memory interface pointers
        s.iMemCanReq = None
        s.iMemSendReq = None
        s.iMemHasResp = None
        s.iMemRecvResp = None
        s.dMemCanReq = None
        s.dMemSendReq = None
        s.dMemHasResp = None
        s.dMemRecvResp = None

        # Syscall memory functions
        s.MemReadFunct = None
        s.MemWriteFunct = None

        # Exit status
        s.exited = False
        s.exit_status = 0

        # Fetch buffer
        s.fetch_buffer = None

    #====================
    # Interface setters
    #====================
    def setIMemCanReq(s, fn):   s.iMemCanReq = fn
    def setIMemSendReq(s, fn):  s.iMemSendReq = fn
    def setIMemHasResp(s, fn):  s.iMemHasResp = fn
    def setIMemRecvResp(s, fn): s.iMemRecvResp = fn

    def setDMemCanReq(s, fn):   s.dMemCanReq = fn
    def setDMemSendReq(s, fn):  s.dMemSendReq = fn
    def setDMemHasResp(s, fn):  s.dMemHasResp = fn
    def setDMemRecvResp(s, fn): s.dMemRecvResp = fn

    def setMemReadFunct(s, fn):  s.MemReadFunct = fn
    def setMemWriteFunct(s, fn): s.MemWriteFunct = fn

    #====================
    # Pipeline stages
    #====================
    def fetch(s):
        # Check ROB space
        next_tail = (s.rob_tail + 1) % s.rob_size
        if next_tail == s.rob_head:
            return 'ROB_FULL'.ljust(10)

        if s.fetch_buffer is None:
            if s.iMemCanReq and s.iMemCanReq():
                ppc = s.pc; npc = s.pc + 4
                s.iMemSendReq({'op':0,'addr':ppc,'data':None,'size':4,'mask':None,'tag':None})
                s.fetch_buffer = {'pc':ppc,'npc':npc}
                s.pc = npc
                return f"{ppc:#010x}".ljust(10)
            else:
                return 'S_imem'.ljust(10)
        else:
            return 'S <<<'.ljust(10)

    def decode(s):
        if s.fetch_buffer and s.iMemHasResp and s.iMemHasResp():
            resp = s.iMemRecvResp()
            inst = sum(resp['data'][i] << (8*i) for i in range(4))
            pc = s.fetch_buffer['pc']

            # Decode fields
            opcode = (inst >> 26) & 0x3F
            funct  = inst & 0x3F
            rs_idx = (inst >> 21) & 0x1F
            rt_idx = (inst >> 16) & 0x1F
            rd_idx = (inst >> 11) & 0x1F
            imm16  = inst & 0xFFFF
            imm26  = inst & 0x3FFFFFF

            # Determine mnemonic and memory flag
            mnemonic = 'unknown'; isMem = False
            if opcode == 0x00:
                if funct == 0x0C:   mnemonic = 'syscall'
                elif funct == 0x20: mnemonic = 'add'
                elif funct == 0x21: mnemonic = 'addu'
                elif funct == 0x22: mnemonic = 'sub'
                elif funct == 0x24: mnemonic = 'and'
                elif funct == 0x25: mnemonic = 'or'
                # ... other R-types
            elif opcode == 0x02: mnemonic = 'j'
            elif opcode == 0x03: mnemonic = 'jal'
            elif opcode == 0x04: mnemonic = 'beq'
            elif opcode == 0x05: mnemonic = 'bne'
            elif opcode == 0x08: mnemonic = 'addi'
            elif opcode == 0x09: mnemonic = 'addiu'
            elif opcode == 0x0C: mnemonic = 'andi'
            elif opcode == 0x0D: mnemonic = 'ori'
            elif opcode == 0x23: mnemonic = 'lw';   isMem = True
            elif opcode == 0x21: mnemonic = 'lh';   isMem = True
            elif opcode == 0x20: mnemonic = 'lb';   isMem = True
            elif opcode == 0x2B: mnemonic = 'sw';   isMem = True
            elif opcode == 0x29: mnemonic = 'sh';   isMem = True
            elif opcode == 0x28: mnemonic = 'sb';   isMem = True

            mop = {
                'mnemonic': mnemonic,
                'isMem': isMem,
                'pc': pc,
                'inst': inst,
                'rs_data': None,
                'rt_data': None,
                'rd': None,
                'imm16': imm16,
                'imm26': imm26
            }

            # ROB entry
            rid = s.rob_tail
            s.rob[rid] = {'busy':True,'ready':False,'mop':mop}
            s.rob_tail = (s.rob_tail + 1) % s.rob_size

            # Rename destination
            if mnemonic not in ['sw','sh','sb','syscall','j','jal','beq','bne']:
                dest = rd_idx if opcode == 0x00 else rt_idx
                mop['rd'] = dest
                s.rat[f'${dest}'] = rid

            # Source operands
            for src,fld in [(rs_idx,'rs_data'),(rt_idx,'rt_data')]:
                tag = s.rat[f'${src}']
                if tag is None or (s.rob[tag] and s.rob[tag]['ready']):
                    mop[fld] = s.rf[src]
                else:
                    mop[fld] = ('TAG', tag)

            # Dispatch to RS
            unit = 'LS' if isMem else 'ALU'
            for i,slot in enumerate(s.rs[unit]):
                if slot is None:
                    s.rs[unit][i] = {'rob_id':rid,'mop':mop}
                    break

            s.fetch_buffer = None
            return f"{mnemonic:<8}".ljust(10)
        return ' D<<<'.ljust(10)

    def issue(s):
        for unit,slots in s.rs.items():
            for i,slot in enumerate(slots):
                if slot:
                    mop = slot['mop']; rid = slot['rob_id']
                    ready = all(not (isinstance(mop[f],tuple) and mop[f][0]=='TAG') \
                                for f in ['rs_data','rt_data'])
                    if ready:
                        slots[i] = None
                        s.execute_op(rid)
        return ' I<<<'.ljust(10)

    def execute_op(s, rob_id):
        entry = s.rob[rob_id]; mop = entry['mop']
        m = mop['mnemonic']
        rs = mop['rs_data']; rt = mop['rt_data']; imm = mop['imm16']

        # Branch/jump
        if m == 'beq' and rs == rt:
            s.squash = True
            s.squash_pc = mop['pc'] + 4 + (s.sign_extend(imm) << 2)
        elif m == 'bne' and rs != rt:
            s.squash = True
            s.squash_pc = mop['pc'] + 4 + (s.sign_extend(imm) << 2)
        elif m == 'j':
            s.squash = True
            s.squash_pc = (mop['pc'] & 0xF0000000) | (mop['imm26'] << 2)
        elif m == 'jal':
            s.squash = True
            s.squash_pc = (mop['pc'] & 0xF0000000) | (mop['imm26'] << 2)
            entry['value'] = mop['pc'] + 4
            entry['ready'] = True
            s.inst_c = True
            return

        # ALU
        if m in ['add','addu','addi','addiu','sub','subu','and','or','xor','nor']:
            val = (rs + (rt if m not in ['addi','addiu'] else imm)) & 0xFFFFFFFF
            entry.update({'value':val,'ready':True}); s.inst_c=True
        # Load
        elif m in ['lw','lh','lhu','lb','lbu']:
            addr = rs + s.sign_extend(imm)
            data = s.MemReadFunct(addr,4)
            val = sum(data[i]<<(8*i) for i in range(len(data)))
            entry.update({'value':val,'ready':True}); s.inst_c=True
        # Store
        elif m in ['sw','sh','sb']:
            entry.update({'value':None,'ready':True}); s.inst_c=True

        # Broadcast result
        for u in s.rs:
            for slot in s.rs[u] or []:
                mop2 = slot['mop']
                for fld in ['rs_data','rt_data']:
                    v = mop2[fld]
                    if isinstance(v,tuple) and v[1]==rob_id:
                        mop2[fld] = entry['value']

    def commit(s):
        entry = s.rob[s.rob_head]
        if entry and entry['ready']:
            mop = entry['mop']; m = mop['mnemonic']
            # Syscall exit
            if m=='syscall' and s.rf[2]==10:
                s.exit_status = s.rf[4]
                s.exited = True
            # Writeback
            if mop.get('rd') is not None:
                dst = mop['rd']; s.rf[dst] = entry['value']
                if s.rat[f'${dst}']==s.rob_head: s.rat[f'${dst}']=None
            # Store
            elif m in ['sw','sh','sb']:
                addr = mop['rs_data'] + s.sign_extend(mop['imm16'])
                data = [(mop['rt_data']>>(8*i))&0xFF for i in range(4)]
                s.MemWriteFunct(addr,data,4)
            s.rob[s.rob_head] = None
            s.rob_head = (s.rob_head + 1) % s.rob_size
        return ' W<<<'.ljust(10)

    def tick(s):
        s.inst_c = False
        if s.squash:
            # Flush pipeline state
            s.fetch_buffer = None
            s.pc = s.squash_pc
            s.rob = [None] * s.rob_size
            s.rat = {f"${i}": None for i in range(32)}
            s.rs = {'ALU': [None]*s.rs_size, 'LS': [None]*s.rs_size}
            s.squash = False
        s.commit(); s.issue(); s.decode(); s.fetch()

    def linetrace(s):
        return f"OOO: PC={s.pc:#010x} ROB=[{s.rob_head}->{s.rob_tail}]"

    def instCompletionFlag(s):
        return s.inst_c

    def getExitStatus(s):
        return (s.exited, s.exit_status)

    def roiFlag(s):
        return False

    @staticmethod
    def sign_extend(val, bits=16):
        mask = (1<<bits) - 1; v = val & mask
        if v & (1<<(bits-1)): v -= 1<<bits
        return v
