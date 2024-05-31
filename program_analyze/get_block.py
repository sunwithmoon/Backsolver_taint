import angr

from angr.analyses.cfg.indirect_jump_resolvers.default_resolvers import default_indirect_jump_resolvers
from angr.analyses.cfg.indirect_jump_resolvers.resolver import IndirectJumpResolver
from program_analyze.structure import Block
from program_analyze.graph import PostDominators
import logging
import re
from program_analyze.ucse_utils import UCSE

l = logging.getLogger(__name__)
l.setLevel("DEBUG")

class SwitchResolver(IndirectJumpResolver):
    def __init__(self, project, switch_targets=None):
        super(SwitchResolver, self).__init__(project, timeless=True)
        self._switch_targets = switch_targets

    def filter(self, cfg, addr, func_addr, block, jumpkind):
        """
        Check if this resolution method may be able to resolve the indirect jump or not.

        :param int addr:        Basic block address of this indirect jump.
        :param int func_addr:   Address of the function that this indirect jump belongs to.
        :param block:           The basic block. The type is determined by the backend being used. It's pyvex.IRSB if
                                pyvex is used as the backend.
        :param str jumpkind:    The jumpkind.
        :return: True if it is possible for this resolution method to resolve the specific indirect jump, False
                 otherwise.
        :rtype:  bool
        """
        if addr in self._switch_targets:
            return True
        return False

    def resolve(self, cfg, addr, func_addr, block, jumpkind):
        if self._switch_targets is None or addr not in self._switch_targets:
            return False, []
        return True, sorted(self._switch_targets[addr])


class GetBlocks:
    def __init__(self, binary, cfg=None, rm_func_blocks=True):
        self.binary = binary
        self.p = angr.Project(binary, auto_load_libs=False)
        self.cfg = cfg if cfg else self.p.analyses.CFGFast(normalize=True)
        self.ucse = UCSE(self.p, self.cfg)
        self.funcs = {}
        self.rm_func_blocks = rm_func_blocks
        self.RET = -1 # addr for super return block (used for post dom)
        self.switch_pattern = re.compile(r"[qd]word ptr \[([a-z]+)\*([48]) \+ (0x[0-9a-f]+)\]")
        self.switch_pattern2 = re.compile(r"^([a-z]+)$")

    def add_edge(self, func, pred, succ, pred_size=None, succ_size=None):
        if pred not in self.blocks:
            block = Block(pred, func, pred_size)
            self.blocks[pred] = block
        else:
            block = self.blocks[pred]
        block.succ.add(succ)

        if succ not in self.blocks:
            block = Block(succ, func, succ_size)
            self.blocks[succ] = block
        else:
            block = self.blocks[succ]
        block.pred.add(pred)

    def rm_edge(self, pred, succ):
        if pred not in self.blocks:
            return
        block = self.blocks[pred]
        block.succ.remove(succ)

        if succ not in self.blocks:
            return
        block = self.blocks[succ]
        block.pred.remove(pred)

    def add_call_function(self, block_addr, call_func):
        block = self.blocks[block_addr]
        block.call_functions.add(call_func)

    def is_switch_block(self, block):
        ins = self.get_block_last_ins(block)
        if ins.mnemonic != 'jmp':
            return False
        if not self.switch_pattern.match(ins.op_str) and not self.switch_pattern2.match(ins.op_str):
            return False
        return True

    def get_switch_targets(self, block, prev_block, func_addr):
        '''
        recognize switch pattern and get the targets
        :param block:
        :return: {switch_table_addr: target}
        '''
        ins = self.get_block_last_ins(block)

        res_state = self.ucse.UCSE_explore(prev_block, ins.address, init_sym_reg=True, arg_num=0)
        if len(res_state) == 0:
            return None
        state = res_state[0]
        if self.switch_pattern.match(ins.op_str):
            l.error("fix switch pattern")
            exit()
            reg, step, addr_table = self.switch_pattern.match(ins.op_str).groups()

            # need to step over the current block
            # states = self.ucse.UCSE_step(init_state=state)
            # assert len(states) >= 1 and len(states) < 100, "in block %x switch index range is too large: %s"%(block, states)
            # switch_target = [s.addr for s in states]
            # l.info("switch target: %s"%[hex(x) for x in switch_target])
            # assert all([x>0x400000 and x<0x500000 for x in switch_target])
            reg_v = getattr(state.regs, reg)
            switch_start, switch_end = (state.solver.min(reg_v), state.solver.max(reg_v))
            step = int(step)
            addr_table = int(addr_table, 16)
            targets = {}
            if switch_end - switch_start > 100:
                l.warning("Error switch index: %d, %d"%(switch_start, switch_end))
                l.warning("try to infer max 100 switch targets.")
                threshold = 0x10000  # heuristic judgement
                for i in range(100):
                    if step == 8:
                        addr = state.mem[addr_table + i * step].long.concrete
                    else:
                        addr = state.mem[addr_table + i * step].int.concrete
                    if abs(addr - block) > threshold:
                        break
                    targets[addr_table + i * step] = addr
                l.warning("infer %d switch targets: %s"%(len(targets), [hex(x) for x in targets]))
            else:
                assert switch_start == 0, "block %x switch index start from %d"%(block, switch_start)
                for i in range(switch_start, switch_end + 1):
                    if step == 8:
                        addr = state.mem[addr_table + i * step].long.concrete
                    else:
                        addr = state.mem[addr_table + i * step].int.concrete
                    targets[addr_table + i * step] = addr
            return targets
        else:
            reg = self.switch_pattern2.match(ins.op_str).groups()[0]
            reg_v = getattr(state.regs, reg)
            targets = state.solver.eval_upto(reg_v, 40)
            if len(targets) == 40:
                state = self.ucse.UCSE_explore(func_addr, ins.address, init_sym_reg=True)[0]
                reg_v = getattr(state.regs, reg)
                targets = state.solver.eval_upto(reg_v, 40)
                if len(targets) == 40:
                    l.warning("switch identify fail")
                    exit()

            return targets


    def get_node_from_trans_graph(self, addr, trans_graph):
        for node in trans_graph.nodes():
            if isinstance(node, angr.codenode.BlockNode) and node.addr == addr:
                return node
        return None


    def resolve_switch(self):
        '''
        resolve switch table
        :return:  {switch_block: set(targets)}
        '''
        self.switch_targets = {}
        cfg_func = self.cfg.kb.functions
        for func_addr in cfg_func:
            if cfg_func[func_addr].alignment:
                continue
            if func_addr < self.p.loader.main_object.min_addr or func_addr > self.p.loader.main_object.max_addr:
                continue
            func_switch_table = {}
            trans_graph = cfg_func[func_addr].transition_graph
            block_addrs = [block.addr for block in trans_graph.nodes() if isinstance(block, angr.codenode.BlockNode)]
            for node in trans_graph.pred:
                if node.addr < self.p.loader.main_object.min_addr or node.addr > self.p.loader.main_object.max_addr:
                    continue
                prev_addr = []
                for pred_node in trans_graph.pred[node]:
                    if trans_graph.pred[node][pred_node]['type'] == 'call':
                        continue
                    if trans_graph.pred[node][pred_node]['type'] not in ('transition', 'fake_return') or \
                            (trans_graph.pred[node][pred_node]['outside'] and pred_node.addr not in block_addrs):
                        continue
                    if any([ins.address in self.cfg.kb.functions for ins in
                            self.p.factory.block(node.addr).capstone.insns]):
                        # Align before a function, or a call to a no-return function
                        continue
                    prev_addr.append(pred_node.addr)
                if self.is_switch_block(node.addr):
                    assert len(prev_addr) == 1, "switch block %x has %d prev block"%(node.addr, len(prev_addr))
                    res = self.get_switch_targets(node.addr, prev_addr[0], func_addr)
                    if res:
                        func_switch_table[node.addr] = res

            for block in func_switch_table:
                self.switch_targets[block] = set(func_switch_table[block])
                l.info("0x%x switch targets: %s"% (block, [hex(x) for x in self.switch_targets[block]]))

        # now we need to update the CFG
        sr = SwitchResolver(self.p, self.switch_targets)
        indirect_jump_resolvers = [sr] + default_indirect_jump_resolvers(self.binary, self.p)
        self.cfg = self.p.analyses.CFGFast(normalize=True, indirect_jump_resolvers=indirect_jump_resolvers)




    def get_func_blocks(self, func_addr, trans_graph):
        blocks = trans_graph.nodes()
        block_addrs = [block.addr for block in blocks if isinstance(block, angr.codenode.BlockNode)]
        self.funcs[func_addr] = block_addrs

        hit_nodes = {func_addr}
        for node in trans_graph.succ:
            if node.addr not in self.blocks and isinstance(node, angr.codenode.BlockNode):
                self.blocks[node.addr] = Block(node.addr, func_addr, node.size)

            add_edges = []
            for next_node in trans_graph.succ[node]:
                if trans_graph.succ[node][next_node]['type'] == 'call':
                    self.add_call_function(node.addr, next_node.addr)
                    if next_node.addr in self.no_ret_funcs:
                        # The block does not have any successor, remove the edges
                        for succ in add_edges:
                            self.rm_edge(node.addr, succ)
                        break
                if trans_graph.succ[node][next_node]['type'] not in ('transition','fake_return') or \
                        (trans_graph.succ[node][next_node]['outside'] and next_node.addr not in block_addrs):
                    continue
                if any([ins.address in self.cfg.kb.functions for ins in self.p.factory.block(next_node.addr).capstone.insns]):
                    # Align before a function, or a call to a no-return function
                    l.info("succ node of 0x%x is a function: 0x%x, bypass", node.addr, next_node.addr)
                    continue
                self.add_edge(func_addr, node.addr, next_node.addr, node.size, next_node.size)
                add_edges.append(next_node.addr)
                hit_nodes.add(next_node.addr)

            # res = self.get_switch_targets(node.addr)
            # if res:
            #     func_switch_table[node.addr] = res
            #     switch_targets = set(res.values())
            #     l.info("%x switch targets: %s"% (node.addr, [hex(x) for x in switch_targets]))
            #     for target in switch_targets:
            #         if target not in add_edges:
            #             self.add_edge(func_addr, node.addr, target)
            #             add_edges.append(target)
            #             hit_nodes.add(target)




        # we need to remove the nodes that not int the function
        not_hit = set(self.funcs[func_addr]) - hit_nodes
        if not_hit:
            for addr in not_hit:
                if not self.is_align_block(addr):
                    l.info("func 0x%x node 0x%x, first ins: %s" % (func_addr, addr, \
                                                                   str(self.get_block_ins(addr, self.blocks[addr].size)[0])))
                if self.rm_func_blocks:
                    self.funcs[func_addr].remove(addr)


    def get_block_succ(self, blocks, node):
        if node not in blocks:
            if type(node) == int:
                l.info("block 0x%x not in blocks" % node)
            return []
        else:
            if node in self.ret_nodes:
                # add a supper node RET in afraid of multiple return
                return [self.RET]
            return blocks[node].succ - self.bypass_nodes

    def get_no_ret_funcs(self):
        self.no_ret_funcs = set()
        cfg_func = self.cfg.kb.functions
        try:
            plt_start = self.p.loader.main_object.sections_map['.plt'].min_addr
            plt_end = self.p.loader.main_object.sections_map['.plt'].max_addr
        except:
            plt_start = 0
            plt_end = 0
        jmp_funcs = set() # some function is a block that jmps to another function
        for func_addr in cfg_func:
            if cfg_func[func_addr].alignment:
                continue
            if func_addr >= self.p.loader.main_object.min_addr and func_addr <= self.p.loader.main_object.max_addr:
                if func_addr >= plt_start and func_addr <= plt_end:
                    # plt function
                    continue
                has_ret = False
                if cfg_func[func_addr].has_return is False:
                    if len(cfg_func[func_addr].nodes) <= 2:
                        l.info("function 0x%x has no return, but only %d nodes, bypass", func_addr, len(cfg_func[func_addr].nodes))
                        continue
                    for block in cfg_func[func_addr].endpoints:
                        last_ins = self.get_block_last_ins(block.addr, block.size)
                        if last_ins.mnemonic not in ('ret', 'call', 'jmp', 'ud2'):
                            # angr recognize a wrong function, bypass
                            continue
                        if last_ins.mnemonic in ('ret', 'jmp'):
                            # some func return by jmp to another function
                            has_ret = True
                        elif last_ins.mnemonic == 'call':
                            # After calling the target function, the program ends.
                            self.no_ret_funcs.add(last_ins.operands[0].value.imm)
                    if not has_ret:
                        self.no_ret_funcs.add(func_addr)

    def set_post_dom(self, bypass_nodes=set(), ret_nodes=set()):
        self.bypass_nodes = bypass_nodes
        self.ret_nodes = ret_nodes
        for func_addr in self.funcs:
            # build PostDominators graph
            post_dominators = PostDominators(self.blocks, func_addr, successors_func=self.get_block_succ).post_dom.succ
            for block in post_dominators:
                if type(block) == int:
                    if block in self.blocks:
                        for key in post_dominators[block]:
                            if post_dominators[block][key]:
                                l.error("block 0x%x idom 0x%x has something: %s" % (
                                block, key, str(post_dominators[block][key])))
                                exit()
                        res = set([key for key in post_dominators[block] if type(key) == int])
                        if not res.issubset(set(self.funcs[func_addr]) | {self.RET}):
                            l.error("bypass block 0x%x post dom not in func 0x%x" % (block, func_addr))
                            continue
                        if block == self.RET:
                            self.blocks[block].post_idom.update(res)
                        else:
                            self.blocks[block].post_idom = res
                    else:
                        if block > 0x4000000 and block < 0x5000000:
                            l.error("block 0x%x not in blocks when get blocks" % block)



    def get_blocks(self):
            """
            Identifying the loops of a binary and return the loop entrance addr and addr of bbl in the loop
            :return: [(loop_entrance,[bbl_addr])]
            """
            self.blocks = {}
            # set a super block RET for multiple return
            # For every ret node, we add a virtual edge to RET (by self.get_block_succ)
            self.blocks[self.RET] = Block(self.RET, self.RET, 0)

            self.resolve_switch()

            self.get_no_ret_funcs()

            cfg_func = self.cfg.kb.functions
            for func_addr in cfg_func:
                if cfg_func[func_addr].alignment:
                    continue
                if func_addr >= self.p.loader.main_object.min_addr and func_addr <= self.p.loader.main_object.max_addr:
                    self.get_func_blocks(func_addr, cfg_func[func_addr].transition_graph)
            self.set_post_dom()
            return self.blocks

    def is_align_block(self, block):
        if block not in self.blocks:
            block_first_ins = self.get_block_ins(block, size = self.blocks[block].size)[0]
        else:
            block_first_ins = self.get_block_ins(block)[0]
        if '\tnop\t' in str(block_first_ins):
            return True
        else:
            return False

    def get_block_last_ins(self, block, size=None):
        return self.p.factory.block(block, size).capstone.insns[-1]

    def get_block_ins(self, block, size=None):
        return self.p.factory.block(block, size).capstone.insns

    def get_no_ret_blocks(self):
        # get the blocks whose last instruction is a call to an exit-like function
        no_ret_blocks = []
        no_succ_blocks = []
        for block in self.blocks:
            if self.blocks[block].succ or not self.blocks[block].pred:
                # we need to bypass the blocks without pred
                # because of align might misunderstand the block range
                # besides, the no ret we need to locate must have pred blocks, otherwise it makes no influence for us
                continue
            last_ins = self.get_block_last_ins(block)
            assert last_ins.mnemonic in ('ret', 'call', 'jmp', 'ud2'), (last_ins.mnemonic, hex(block))
            if last_ins.mnemonic == 'call':
                # call a no return function
                no_ret_blocks.append(block)
                self.no_ret_funcs |= self.blocks[block].call_functions
            no_succ_blocks.append(block)
        return no_ret_blocks, no_succ_blocks

    def get_ret_blocks(self):
        # get the blocks whose last instruction is a call to an exit-like function
        ret_blocks = []
        for block in self.blocks:
            if self.blocks[block].succ or not self.blocks[block].pred:
                # we need to bypass the blocks without pred
                # because of align might misunderstand the block range
                continue
            last_ins = self.get_block_last_ins(block)
            assert last_ins.mnemonic in ('ret', 'call', 'jmp', 'ud2'), (last_ins.mnemonic, hex(block))
            if last_ins.mnemonic in ('ret', 'jmp'):
                # some function return by jmp to another function
                ret_blocks.append(block)
        return ret_blocks

    def get_all_post_doms(self, block):
        '''
        get all the post dominators of block
        :param block:
        :return:
        '''
        post_doms = {block}
        for post_idom in self.blocks[block].post_idom:
            post_doms.add(post_idom)
            post_doms.update(self.get_all_post_doms(post_idom))
        return post_doms

    def get_all_no_ret_blocks(self):
        '''
        get the blocks that must reach a call to a no-return function
        '''
        results = set()
        no_ret_blocks, _ = self.get_no_ret_blocks()
        for block in no_ret_blocks:
            results.update(self.get_all_post_doms(block))
        return results


    def get_parents_with_only_child(self, addr):
        '''
        get the parents of addr that only have one child
        :param addr:
        :return:
        '''
        res = set()
        for parent in self.blocks[addr].pred:
            if len(self.blocks[parent].succ) == 1:
                res.add(parent)
                res.update(self.get_parents_with_only_child(parent))
        return res

    # @deprecated
    # def get_direct_to_ret(self):
    #     '''
    #     get the blocks that only have one path to return instruction or a call to exit function
    #     :return:
    #     '''
    #     direct_to_ret_blocks = set()
    #     for block in self.blocks:
    #         if self.blocks[block].succ or not self.blocks[block].pred:
    #             # we need to bypass the blocks without pred
    #             # because of align might misunderstand the block range
    #             # besides, the no ret we need to locate must have pred blocks, otherwise it makes no influence for us
    #             continue
    #         direct_to_ret_blocks.add(block)
    #         direct_to_ret_blocks.update(self.get_parents_with_only_child(block))
    #     return direct_to_ret_blocks
    #
    # @deprecated
    # def get_direct_to_no_ret(self):
    #     '''
    #     Get the blocks that only have one successor and reach a call to exit function
    #     :return:
    #     '''
    #     no_ret_blocks, _ = self.get_no_ret_blocks()
    #     direct_to_no_ret_blocks = set()
    #     for block in no_ret_blocks:
    #         direct_to_no_ret_blocks.update(self.get_parents_with_only_child(block))
    #     return direct_to_no_ret_blocks

def get_func_blocks(gb):
    all_func_blocks = set()
    for func in gb.funcs:
        all_func_blocks.update(gb.funcs[func])
    return all_func_blocks

def test_no_pred_block():
    binary = "/home/waterfire/fuzz/example/libpng-1.6.36/pngimage"
    gb = GetBlocks(binary, rm_func_blocks=False)
    blocks = gb.get_blocks()
    all_func_blocks = get_func_blocks(gb)

    gb2 = GetBlocks(binary, rm_func_blocks=True)
    blocks2 = gb2.get_blocks()
    all_func_blocks2 = get_func_blocks(gb2)
    del_blocks = all_func_blocks - all_func_blocks2
    for b in list(del_blocks):
        if gb.is_align_block(b):
            del_blocks.remove(b)

    # TODO: we will deal with the switch jmp targets later
    print("switch jmp targets:", del_blocks)

    res = {}
    for func in gb2.funcs:
        res[func] = []
        for b in gb2.funcs[func]:
            if b == func:
                continue
            bl = gb2.blocks[b]
            if not bl.pred:
                res[func].append(b)
        if not res[func]:
            del res[func]
    print(res)

if __name__ == '__main__':
    test_no_pred_block()

