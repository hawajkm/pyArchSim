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
            resp   = s.iMemRecvResp()
            inst   = sum(resp['data'][i] << (8*i) for i in range(4))
            pc     = s.fetch_buffer['pc']

            # decode fields
            opcode = (inst >> 26) & 0x3F
            funct  = inst & 0x3F
            rs     = (inst >> 21) & 0x1F
            rt     = (inst >> 16) & 0x1F
            rd     = (inst >> 11) & 0x1F
            imm16  = inst & 0xFFFF
            imm26  = inst & 0x3FFFFFF

            # default metadata
            mnemonic = 'unknown'
            isMem    = False
            uses_rs  = False
            uses_rt  = False

            # figure out what it is
            if opcode == 0x00:
                # special / R-type
                if   funct == 0x08:
                    mnemonic = 'jr';   uses_rs = True
                elif funct == 0x0C:
                    mnemonic = 'syscall'; uses_rs = True
                else:
                    uses_rs = uses_rt = True
                    if   funct == 0x20: mnemonic = 'add'
                    elif funct == 0x21: mnemonic = 'addu'
                    elif funct == 0x22: mnemonic = 'sub'
            elif opcode == 0x02:
                mnemonic = 'j'
            elif opcode == 0x04:
                mnemonic = 'beq';  uses_rs = uses_rt = True
            elif opcode == 0x08:
                mnemonic = 'addi'; uses_rs = True
            elif opcode == 0x09:
                mnemonic = 'addiu';uses_rs = True
            elif opcode == 0x23:
                mnemonic = 'lw';   isMem = True;  uses_rs = True
            elif opcode == 0x2B:
                mnemonic = 'sw';   isMem = True;  uses_rs = uses_rt = True

            # build micro-op
            mop = {
                'mnemonic': mnemonic,
                'isMem':    isMem,
                'pc':       pc,
                'inst':     inst,
                'rs_data':  0,
                'rt_data':  0,
                'rd':       None,
                'imm16':    imm16,
                'imm26':    imm26
            }

            # read or rename rs
            if uses_rs:
                tag = s.rat[f'${rs}']
                if tag is None or s.rob[tag] is None or s.rob[tag]['ready']:
                    mop['rs_data'] = s.rf[rs]
                else:
                    mop['rs_data'] = ('TAG', tag)

            # read or rename rt
            if uses_rt:
                tag = s.rat[f'${rt}']
                if tag is None or s.rob[tag] is None or s.rob[tag]['ready']:
                    mop['rt_data'] = s.rf[rt]
                else:
                    mop['rt_data'] = ('TAG', tag)

            # rename destination
            if mnemonic not in ('sw','sb','sh','syscall','j','jr','beq'):
                dest = (rd if opcode==0x00 else rt)
                mop['rd'] = dest
                s.rat[f'${dest}'] = s.rob_tail

            # enqueue into RS & ROB
            unit = 'LS' if isMem else 'ALU'
            for i,slot in enumerate(s.rs[unit]):
                if slot is None:
                    s.rs[unit][i] = {'rob_id': s.rob_tail, 'mop': mop}
                    break

            s.rob[s.rob_tail] = {'busy': True, 'ready': False, 'mop': mop}
            s.rob_tail = (s.rob_tail + 1) % s.rob_size
            s.fetch_buffer = None

            return f"{mnemonic:<8}".ljust(10)
        return ' D<<<'.ljust(10)

    def issue(s):
        for unit,slots in s.rs.items():
            for i,slot in enumerate(slots):
                if slot:
                    mop = slot['mop']; rid = slot['rob_id']
                    ready = all(not (isinstance(mop[f],tuple) and mop[f][0]=='TAG') for f in ['rs_data','rt_data'])
                    if ready:
                        s.rs[unit][i] = None
                        s.execute_op(rid)
        return ' I<<<'.ljust(10)

    def execute_op(s, rob_id):
        entry = s.rob[rob_id]
        mop   = entry['mop']
        m     = mop['mnemonic']

        # 1) control flow
        if m in ('j','jr'):
            if m == 'j':
                target = (mop['pc'] & 0xF0000000) | (mop['imm26'] << 2)
            else:  # jr
                target = mop['rs_data']
            s.squash    = True
            s.squash_pc = target
            entry['ready'] = True

        # 2) branch
        elif m == 'beq':
            if mop['rs_data'] == mop['rt_data']:
                offset = s.sign_extend(mop['imm16']) << 2
                s.squash_pc = mop['pc'] + 4 + offset
                s.squash    = True
            entry['ready'] = True

        # 3) memory
        elif m in ('lw','sw'):
            addr = mop['rs_data'] + s.sign_extend(mop['imm16'])
            if m == 'lw':
                data = s.MemReadFunct(addr, 4)
                entry['value'] = sum(data[i] << (8*i) for i in range(4))
            else:
                data = [(mop['rt_data'] >> (8*i)) & 0xFF for i in range(4)]
                s.MemWriteFunct(addr, data, 4)
            entry['ready'] = True

        # 4) ALU
        else:
            if   m == 'add':   val = mop['rs_data'] + mop['rt_data']
            elif m == 'addu':  val = (mop['rs_data'] + mop['rt_data']) & 0xFFFFFFFF
            elif m == 'sub':   val = mop['rs_data'] - mop['rt_data']
            elif m == 'addi':  val = mop['rs_data'] + s.sign_extend(mop['imm16'])
            elif m == 'addiu': val = (mop['rs_data'] + s.sign_extend(mop['imm16'])) & 0xFFFFFFFF
            else:              val = 0
            entry['value'] = val & 0xFFFFFFFF
            entry['ready'] = True

        # 5) broadcast wake-ups
        for unit in ('ALU','LS'):
            for slot in s.rs[unit]:
                if slot:
                    for fld in ('rs_data','rt_data'):
                        tag = slot['mop'][fld]
                        if isinstance(tag, tuple) and tag[1] == rob_id:
                            slot['mop'][fld] = entry['value']


    def commit(s):
        entry = s.rob[s.rob_head]
        if entry is None:
            return ' ' * 10

        mop      = entry['mop']
        mnemonic = mop['mnemonic']

        # finish outstanding loads/stores
        if mop['isMem'] and not entry['ready']:
            if mnemonic in ('lw','lh','lhu','lb','lbu') and s.dMemHasResp and s.dMemHasResp():
                resp = s.dMemRecvResp()
                entry['value'] = sum(resp['data'][i] << (8*i) for i in range(4))
                entry['ready'] = True
            elif mnemonic in ('sw','sh','sb') and s.dMemHasResp and s.dMemHasResp():
                s.dMemRecvResp()
                entry['ready'] = True

        # if ready, retire it!
        if entry.get('ready', False):
            s.inst_c = True                    # <— mark it completed
            if mop.get('rd') is not None:
                s.rf[mop['rd']] = entry['value']
                if s.rat[f'${mop["rd"]}'] == s.rob_head:
                    s.rat[f'${mop["rd"]}'] = None

            if mnemonic == 'syscall' and s.rf[2] == 10:
                s.exit_status = s.rf[4]
                s.exited = True

            s.rob[s.rob_head] = None
            s.rob_head = (s.rob_head + 1) % s.rob_size
            return ' W<<<'.ljust(10)

        return ' ' * 10



    def tick(s):
        s.inst_c = False
        if s.squash:
            # Flush pipeline state
            s.fetch_buffer = None
            s.pc = s.squash_pc
            # completely empty the ROB and reset head/tail so head == tail
            s.rob = [None] * s.rob_size
            s.rob_head = 0
            s.rob_tail = 0

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
