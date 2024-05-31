import logging
import angr
from program_analyze.structure import Loop
import claripy
from claripy import ast
import os
import pickle
from func_timeout import func_set_timeout

l = logging.getLogger(name="getloop")
# l.setLevel("DEBUG")

class GetLoops:
    def __init__(self, binary, cfg=None):
        self.p = angr.Project(binary, auto_load_libs=False)
        self.cfg = cfg

    def add_loop(self, new_loop, func_addr):
    # add new loop
        if func_addr not in self.loops:
            self.loops[func_addr] = []

        l.debug("add loop: %r", [hex(addr) for addr in new_loop])
        for i in range(len(self.loops[func_addr])):
            if self.loops[func_addr][i] & new_loop:
                self.loops[func_addr][i] |= new_loop
                l.debug("merge loop: %r", [hex(addr) for addr in self.loops[func_addr][i]])
                return
        # l.debug("add loop: %r", [hex(addr) for addr in new_loop])
        self.loops[func_addr].append(new_loop)

    def identify_func_loops(self, func_addr, func_cfg_succ, node, trace):
        trace.append(node.addr)
        self.visited.add(node.addr)
        for new_node in func_cfg_succ[node]:
            if func_cfg_succ[node][new_node]['type'] not in ('transition','fake_return'):
                continue
            if new_node.addr == node.addr:
                # self-loop
                self.add_loop(set([node.addr]), func_addr)
                continue
            if new_node.addr in trace:
                index = trace.index(new_node.addr)

                # the instruction in the block might be the start instruction of another block
                for addr in self.p.factory.block(node.addr).instruction_addrs:
                    if addr in trace and trace.index(addr) < index:
                        index = trace.index(addr)

                self.add_loop(set(trace[index:]), func_addr)
                continue
            # if new_node.addr in self.visited:
            #     continue
            self.identify_func_loops(func_addr, func_cfg_succ, new_node, trace)
        trace.pop(-1)

    def loop_format_change(self, loop, func):
        fl = Loop(loop, set(), set())
        func_succ = self.cfg.kb.functions[func].transition_graph.succ
        for node in func_succ:
            if node.addr in loop:
                for next_node in func_succ[node]:
                    if func_succ[node][next_node]['type'] not in ('transition', 'fake_return'):
                        continue
                    if next_node.addr not in loop:
                        fl.loop_out.add(next_node.addr)

        func_pred = self.cfg.kb.functions[func].transition_graph.pred
        for node in func_pred:
            if node.addr in loop:
                for next_node in func_pred[node]:
                    if func_pred[node][next_node]['type'] not in ('transition', 'fake_return'):
                        continue
                    if next_node.addr not in loop:
                        fl.loop_in.add(next_node.addr)
        return fl

    def take_same_set(self, sets):
        for i in range(len(sets)):
            for j in range(len(sets)):
                if i==j:
                    continue
                if sets[i] & sets[j]:
                    sets[i] = sets[i] | sets[j]
                    sets.pop(j)
                    self.take_same_set(sets)
                    return
        return


    def get_loops(self):
        """
        Identifying the loops of a binary and return the loop entrance addr and addr of bbl in the loop
        :return: [(loop_entrance,[bbl_addr])]
        """
        self.loops = {}
        self.format_loops = {}
        '''
        self.format_loops = {func_addr: [Loop(loop_body, loop_in, loop_out)]}
        '''
        self.visited = set()
        if not self.cfg:
            # cfg = self._current_p.analyses.CFG(collect_data_references=True, extra_cross_references=True)
            self.cfg = self.p.analyses.CFGFast()

        cfg_func = self.cfg.kb.functions
        for func_addr in cfg_func:
            if func_addr >= self.p.loader.main_object.min_addr and func_addr <= self.p.loader.main_object.max_addr:
                # self.identify_func_loops(func_addr, cfg_func[func_addr].transition_graph.succ, cfg_func[func_addr].startpoint, [])
                loop_finder = self.p.analyses.LoopFinder([self.cfg.functions[func_addr]])

            # if func_addr not in self.loops:
            #     continue
                format_loop = []
                self.format_loops[func_addr] = format_loop

                # self.take_same_set(self.loops[func_addr])

                for loop in loop_finder.loops:
                    entry = []
                    if len(loop.entry_edges) != 1:
                        l.warning("loop entry edges more than one: {}".format([hex(n.addr) for n, _ in loop.entry_edges]))
                    for node, _ in loop.entry_edges:
                        entry.append(node.addr)
                    out = []
                    for _, node in loop.break_edges:
                        out.append(node.addr)
                    body = [node.addr for node in loop.body_nodes]
                    format_loop.append(Loop(set(body), set(entry), set(out)))
        return self.format_loops

    def get_loop_out(self):
        loop_out = set()
        for func in self.format_loops:
            for loop in self.format_loops[func]:
                if loop_out & loop.loop_out:
                    print("same loop out: %r, %r" % ([hex(addr) for addr in loop.loop_out], [hex(addr) for addr in loop_out & loop.loop_out]))
                    exit()
                loop_out |= loop.loop_out
        return loop_out


def test_nested_loop():
    binary = "/home/waterfire/fuzz/example/libpng-1.6.36/pngimage"
    gl = GetLoops(binary)
    loops = gl.get_loops()
    for f in loops:
        ls = list(loops[f])
        for i in range(len(loops[f])):
            for j in range(i + 1, len(loops[f])):
                if ls[i].loop_body & ls[j].loop_body:
                    print("func: %s" % hex(f))
                    print("loop: %r" % [hex(addr) for addr in ls[i].loop_body])
                    print("loop_in: %r" % [hex(addr) for addr in ls[i].loop_in])
                    print("loop_out: %r" % [hex(addr) for addr in ls[i].loop_out])
                    print("loop: %r" % [hex(addr) for addr in ls[j].loop_body])
                    print("loop_in: %r" % [hex(addr) for addr in ls[j].loop_in])
                    print("loop_out: %r" % [hex(addr) for addr in ls[j].loop_out])
                    print("---")
                    break



if __name__ == "__main__":
    test_nested_loop()

