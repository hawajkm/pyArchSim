# basic.py
# --------------------------------------------------------------------
#   A basic system with a five-stage processor and a memory
#
# Author\ Khalid Al-Hawaj
# Date  \ 03 May 2025

# Imports
from pyArchSimLib.proc      import FiveStageInorderProcessor
from pyArchSimLib.proc.core import FiveStageInorderCore
from pyArchSimLib.mem       import SimpleMultiportedMemory

class BasicSystem():
  # Constructor
  def __init__(s, doLinetrace=False, proc=None):
    # hawajkm: basic system includes a memory and a processor (for now).
    s.proc = proc or FiveStageInorderProcessor()
    s.mem  = SimpleMultiportedMemory(2)

    # Connect the parts
    s.proc.setMemCanReq    (s.mem.canReq  )
    s.proc.setMemSendReq   (s.mem.sendReq )
    s.proc.setMemHasResp   (s.mem.hasResp )
    s.proc.setMemRecvResp  (s.mem.recvResp)

    s.proc.setMemReadFunct (s.mem.read    )
    s.proc.setMemWriteFunct(s.mem.write   )

    # Linetrace
    s.doLinetrace = doLinetrace

  # Executable loader
  def loader(s, elf):
    for section_name in elf['sections']:
      section   = elf['sections'][section_name]
      base_addr = section['base_addr']
      byte_arr  = section['bytes']
      s.mem.write(base_addr, byte_arr, len(byte_arr))

  # Get memory
  def getMem(s):
    return s.mem

  # Exit
  def getExitStatus(s):
    return s.proc.getExitStatus()

  # Flags
  def roiFlag(s):
    return s.proc.roiFlag()
  def instCompletionFlag(s):
    return s.proc.instCompletionFlag()

  # Clocking
  def tick(s):
    s.proc.tick()
    s.mem .tick()

  # Linetracing
  def linetrace(s):
    if s.doLinetrace:
      trace_proc = s.proc.linetrace()
      trace_mem  = s.mem .linetrace()

      trace = '{} | >>=||=>> | {} |'.format(trace_proc, trace_mem)

      return trace
