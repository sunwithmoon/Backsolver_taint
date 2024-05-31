class Loop():
    def __init__(self, loop_body, loop_in, loop_out):
        self.loop_body = loop_body
        self.loop_in = loop_in
        self.loop_out = loop_out

class Block():
    def __init__(self, addr, function, size=None):
        self.addr = addr
        self.succ = set()
        self.pred = set()
        self.call_functions = set() # the functions called by this block
        self.function = function # the function this block belongs to
        self.post_idom = set() # immediate dominator
        self.size = size

class Func():
    def __init__(self, addr):
        self.addr = addr
        self.caller_block = set()
        self.blocks = set()