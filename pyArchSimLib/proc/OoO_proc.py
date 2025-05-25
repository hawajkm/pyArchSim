# pyArchSimLib/proc/oOo_processor.py

from pyArchSimLib.proc.core import OoOCore
from pyArchSimLib.mem.cache   import NoCache

class OutOfOrderProcessor:
    def __init__(self):
        self.core   = OoOCore()
        self.icache = NoCache(0)
        self.dcache = NoCache(1)

        # hook up instruction port
        self.core.setIMemCanReq   (self.icache.canReq)
        self.core.setIMemSendReq  (self.icache.sendReq)
        self.core.setIMemHasResp  (self.icache.hasResp)
        self.core.setIMemRecvResp (self.icache.recvResp)
        # hook up data port
        self.core.setDMemCanReq   (self.dcache.canReq)
        self.core.setDMemSendReq  (self.dcache.sendReq)
        self.core.setDMemHasResp  (self.dcache.hasResp)
        self.core.setDMemRecvResp (self.dcache.recvResp)

    def setMemReadFunct(self, f):   self.core.setMemReadFunct(f)
    def setMemWriteFunct(self, f):  self.core.setMemWriteFunct(f)
    def setMemCanReq(self,  f):     self.icache.setMemCanReq(f); self.dcache.setMemCanReq(f)
    def setMemSendReq(self, f):     self.icache.setMemSendReq(f); self.dcache.setMemSendReq(f)
    def setMemHasResp(self, f):     self.icache.setMemHasResp(f); self.dcache.setMemHasResp(f)
    def setMemRecvResp(self,f):     self.icache.setMemRecvResp(f);self.dcache.setMemRecvResp(f)

    def roiFlag(self):           return self.core.roiFlag()
    def instCompletionFlag(self): return self.core.instCompletionFlag()
    def getExitStatus(self):    return self.core.getExitStatus()

    def tick(self):
        # advance OoO pipeline
        self.core.tick()
        self.icache.tick()
        self.dcache.tick()

    def linetrace(self):
        # combine core + caches if you like
        return self.core.linetrace()
