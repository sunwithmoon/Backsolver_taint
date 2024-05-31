import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__),os.pardir)))
from launcher import TaintLauncher
from taint_tracking import apply_taint, is_tainted, new_tainted_value
from defines import TAINT_BUF, SYM_READ_ADDR, SYM_READ_SAVE_ADDR, SYM_WRITE_ADDR, TAINT_APPLIED

import argparse
import claripy
import pickle
from functools import reduce
from program_analyze import GetLoops, get_func_xref, get_xref, get_all_succ_blocks_weight, \
    GetBlocks, GetPrefix, get_call_arg_list, get_arg, get_concrete_arg, GetMergeInfo, get_section_range,\
    expr_in_list, get_ite_cond, get_expr_ops
from program_analyze.ucse_utils.source_recognize import SourceRecognize
from program_analyze.ucse_utils.utils import CallAnalyze
from exploration_techniques import TaintMerge
import angr
from angr.errors import AngrError
from defines import MEM, DEREFS, state_copy, APPLY_LIB_TAINT
import signal
import logging
import re
import copy
from pympler import tracker

l = logging.getLogger("ifv_finder")
l.setLevel(logging.INFO)
logging.getLogger("mydfs").setLevel(logging.INFO)
logging.getLogger("angr").setLevel(logging.ERROR)
logging.getLogger("exploration_techniques.taint_merge").setLevel(logging.ERROR + 10)
tm = TaintMerge({}, {}, {})



# Timeout handler function
def handler(signum, frame):
    raise TimeoutError("Solver operation timed out")


class IFVFinder:
    def __init__(self, binary, ifv_path, cgc, get_subfunc_writeloc, save_number_write=False, use_rand=True):
        self.binary = binary
        filename = os.path.basename(binary)
        self.tl = TaintLauncher(binary,)
        self.proj = self.tl._p
        main_bin = self.proj.loader.shared_objects[filename]
        self.main_range = (main_bin.mapped_base, main_bin.max_addr)
        self.ifv_path = ifv_path
        self.main_addr = self.tl._p.loader.main_object.symbols_by_name['main'].rebased_addr
        self.pc_count = 0
        self.taint_meet = set()
        self.ifv_meet = set()
        self.cgc = cgc
        self.filter_id = 'FILTER'
        self._get_subfunc_writeloc = get_subfunc_writeloc
        self.save_number_write = save_number_write # eg: mov ptr byte [eax], 1
        self.use_rand = use_rand
        self.func_hash = {}
        self.indirect_calls = {}
        self.read_cons = []
        self.read_addr = []
        self.simplify_res = {}
        '''
        func_addr: {
            'start_state': start_state,
            'end_state': end_state,
            'indirect_call_target': indirect_call_target,
            'caller_states':{
                caller_addr: [caller_states]
            }
            'branch_conds': {branch_addr: branch_conds}
            'is_over': True/False
        }
        '''

        if cgc:
            from cgc_receive import cgc_receive
            from cgc_transmit import cgc_transmit
            self.tl._p.hook_symbol('cgc_receive', cgc_receive(), replace=True)
            self.tl._p.hook_symbol('cgc_transmit', cgc_transmit(), replace=True)
            self.cgc_receive_addrs = (self.tl._p.loader.main_object.plt['cgc_receive'],)
        else:
            # TODO: hook more read functions
            from procedures.procedure_dict import hook_funcs

            self.cgc_receive_addrs = set()
            apply_taint_funcs = ('fgetc', 'fread', 'fread_unlocked','fgetc_unlocked','getc_unlocked','fgets', 'getc', 'read', 'recv', 'recvfrom', 'recvmsg', 'readv', 'readlink', 'readlinkat', 'getcwd', 'getwd')
            l.info("-----------find target library functions-------------")
            for func_name in hook_funcs:
                if func_name in self.tl._p.loader.main_object.plt:
                    l.info("find %s", func_name)
                    if func_name in apply_taint_funcs:
                        self.cgc_receive_addrs.add(self.tl._p.loader.main_object.plt[func_name])
                    self.tl._p.hook_symbol(func_name, hook_funcs[func_name](), replace=True)

    '''
    Theses functions are used for breakpoint.
    '''
    def call_taint_func(self, state):
        if state.history.bbl_addrs.hardcopy[-2] in self.cgc_receive_addrs:
            args = get_call_arg_list(state, arg_num=4)
            taint_addr = args[1]
            # if is_tainted(args[2], state):
            taint_bits = state.solver.eval(args[2] * 8)
            assert type(taint_bits) == int
            if taint_bits > 1024:
                taint_bits = 1024
            l.debug("taint %d bits at %r in %r", taint_bits, taint_addr, state)
            apply_taint(state, taint_addr, taint_id="receive", bits=taint_bits, inspect=True)
            state.globals['already_read'] = True

    def save_taint_ins(self, state):
        if is_tainted(state.inspect.mem_write_expr, state):
            if 'cnt_pt_by' not in str(state.inspect.mem_write_expr):
                self.taint_meet.add(state.addr)
        addr = state.inspect.mem_write_address
        if type(addr) is not int and addr.symbolic:
            return
        if type(addr) is not int:
            addr = addr.args[0]
        state.globals["changed_mem"].append((addr, str(state.inspect.mem_write_expr)))
        for i in range(1, state.inspect.mem_write_expr.length // 8):
            state.globals["changed_mem"].append((addr + i, ''))


    def save_taint_reg(self, state):
        if is_tainted(state.inspect.reg_write_expr, state):
            if 'cnt_pt_by' not in str(state.inspect.reg_write_expr):
                self.taint_meet.add(state.addr)

    def concrete_pc_in_func(self, state):
        pc_offset = state.arch.get_register_offset('pc')
        if type(state.inspect.reg_write_offset) == int:  # The offset of the register being written.
            write_off = state.inspect.reg_write_offset
        else:
            write_off = state.inspect.reg_write_offset.args[0]
        if write_off == pc_offset and not state.inspect.reg_write_expr.concrete:
            pred = state.addr
            if state.addr not in self.block_info:
                pred = state.history.addr
                if pred not in self.block_info:
                    # maybe in read function
                    return
            if self.block_info[pred].call_functions:
                # return from current function
                l.info("%x manual fake retrun"% pred)
                self.tl._tt._fake_ret(state)
                return
            new_pc = state.solver.BVS('PC%d' % (self.pc_count), state.arch.bits)
            state.inspect.reg_write_expr = new_pc
            state.scratch.target = new_pc
            self.pc_count += 1
            cond = []
            for addr in self.block_info[pred].succ:
                cond.append(new_pc == addr)
            state.add_constraints(state.solver.Or(*cond))


    def check_func(self, state):
        relevant_variables = set()
        if not state.history.jump_guards.hardcopy:
            return
        for arg in get_arg(state.history.jump_guards.hardcopy[-1]):
            if not arg.concrete:
                relevant_variables.add(arg)

        for arg in relevant_variables:
            if is_tainted(arg, state):
                # The last branch condition is tainted
                last = state.history.bbl_addrs.hardcopy[-2]  # the branch address
                if last not in self.ifv_meet:
                    l.info("tainted branch %x: %s"%(last, state.history.jump_guards.hardcopy[-1]))
                    self.ifv_meet.add(last)
                    self.get_ifvs_info(last)
                break


    '''
    end
    '''

    def load_data(self, suffix=""):
        if os.path.exists(self.ifv_path[:-3] + suffix + '.pk'):
            fp = open(self.ifv_path, "rb")
            data = pickle.load(fp)
            return data
        return {}

    def save_data(self, data, suffix=""):
        fp = open(self.ifv_path[:-3] + suffix + '.pk', "wb")
        pickle.dump(data, fp)
        fp.close()

    def dfs_in_range(self, block, addr_range, avoid_blocks, visited_blocks, end_block=None):
        """
        start a DFS in the target
        NOTE: WILL NOT JMP BACK!

        :param node:
        :param addr_range:
        :param avoid_blocks:
        :param visited_blocks:
        :return:
        """
        visited_blocks.add(block)

        # pass avoid addr
        if block in avoid_blocks:
            return

        if not self.block_info[block].succ:
            if end_block is not None:
                end_block.append(block)
        for new_block in self.block_info[block].succ:
            # keep dfs in the target
            if new_block not in addr_range:
                continue

            if new_block in visited_blocks:
                continue

            self.dfs_in_range(new_block, addr_range, avoid_blocks, visited_blocks, end_block)

    def block_in_loop(self, block):

        if self.block_info[block].function not in self.f_loop:
            return None
        # there might be several loops in one function
        # we need to get the min loop which contains the block
        loops = []
        for loop in self.f_loop[self.block_info[block].function]:
            if block in loop.loop_body:
                loops.append(loop)
        if not loops:
            return None
        loops.sort(key = lambda l: len(l.loop_body))
        return loops[0]

    def get_branch_diff(self, branch_block, func_body):
        avoid_blocks = set([branch_block])
        branch1_blocks = set()
        branch2_blocks = set()
        successors = list(self.block_info[branch_block].succ)

        # TODO: handle the case that the branch has more than 2 successors (switch)
        while len(successors) < 2:
            assert len(successors) == 1
            branch_block = successors[0]
            successors = list(self.block_info[branch_block].succ)
            l.warning("successors != 2")

        loop = self.block_in_loop(branch_block)
        if loop:
            func_body = loop.loop_body

        end1 = []
        if successors[0] in func_body:
            self.dfs_in_range(successors[0], func_body, avoid_blocks, branch1_blocks, end1)
        end2 = []
        if successors[1] in func_body:
            self.dfs_in_range(successors[1], func_body, avoid_blocks, branch2_blocks, end2)


        if (not branch1_blocks or not branch2_blocks) and loop and set(successors) & loop.loop_out:
            if successors[0] in self.no_ret_blocks or successors[1] in self.no_ret_blocks:
                l.warning("a branch ends with a no-ret block in a loop")
                return successors[0], set(), successors[1], set(), loop if loop else None
        # the two branch should have different accessed block
        if branch1_blocks == branch2_blocks:
            l.error("same branch addr")
        diff1 = branch1_blocks - branch2_blocks
        diff2 = branch2_blocks - branch1_blocks
        for block in end1 + end2:
            if block in self.no_ret_blocks and block in (diff1 | diff2):
                l.warning("a branch ends with a no-ret block")
                return successors[0], set(), successors[1], set(), loop if loop else None
        return successors[0], diff1, successors[1], diff2, loop if loop else None

    def get_write_locations(self, addr, is_sub_func):
        def is_number(string):
            try:
                return type(eval(string)) == int
            except:
                return False

        block = self.proj.factory.block(addr)
        ins_idx = -1
        write_addr = set()
        for st in block.vex.statements:
            if st.tag == 'Ist_IMark':
                current_addr = st.addr
                if current_addr in self.block_info[addr].succ:
                    # use IDA cfg
                    break
                ins_idx += 1
                assert block.capstone.insns[ins_idx].address == current_addr
            if st.tag == 'Ist_Store':
                # exclude push call ...
                mne = block.capstone.insns[ins_idx].mnemonic
                op_str = block.capstone.insns[ins_idx].op_str
                if mne.startswith('bt'):
                    continue
                assert mne in ('push', 'call', 'add', 'sub', 'or', 'and', 'not') or mne.startswith('mov') or \
                       mne.startswith('set') or 'ptr [' in op_str.split(',')[0], (hex(addr), st, mne)
                if mne.startswith('mov'):
                    if self.save_number_write or not is_number(op_str.split(', ')[-1]):
                        write_addr.add((current_addr, addr, is_sub_func, self.block_info[addr].function))
                else:
                    dst = op_str.split(', ')[0]
                    if '[' in dst and ']' in dst:
                        write_addr.add((current_addr, addr, is_sub_func, self.block_info[addr].function))

        return write_addr

    def update_write_location(self, blocks, write_locations, called_func=set(), is_sub_func=False):
        for b in blocks:
            if b not in self.block_info:
                l.warning("0x{:x} not in block_info".format(b))
                continue
            write_locations |= self.get_write_locations(b, is_sub_func)
            if self._get_subfunc_writeloc:
                for func in self.block_info[b].call_functions:
                    # log mem write ins in sub funcs
                    if func < self.tl._p.loader.main_object.min_addr or func > self.tl._p.loader.main_object.max_addr:
                        continue
                    if func not in called_func:
                        called_func.add(func)
                        if func==0:
                            continue
                        self.update_write_location(self.func_block_info[func], write_locations, called_func, is_sub_func=True)

    def bfs_in_target(self, block, addr_range, avoid=set()):
        '''
        start a BFS in addr_range
        :param block:
        :param addr_range:
        :return:
        '''
        paths = [[block]]
        over = []
        while paths:
            cur_path = paths.pop()
            parent = cur_path[-1]
            if len(self.block_info[parent].succ) >= 1:
                has_child = False
                for addr in self.block_info[parent].succ:
                    if addr in addr_range and addr not in avoid and addr not in cur_path:
                        has_child = True
                        tmp = cur_path.copy()
                        tmp.append(addr)
                        paths.append(tmp)
                if not has_child:
                    over.append(cur_path)
            else:
                over.append(cur_path)
        return over

    def dfs_paths(self, block, visited_moves=None, path=None):
        if visited_moves is None:
            visited_moves = set()
        if path is None:
            path = []
        path = path + [block]
        if not self.block_info[block].succ:
            return [path]
        paths = []
        for child in self.block_info[block].succ:
            move = (block, child)
            if len(self.block_info[block].succ) > 1 and move in visited_moves:
                continue
            new_visited_moves = visited_moves.copy()
            new_visited_moves.add(move)
            if len(new_visited_moves) % 5 == 0:
                print(len(new_visited_moves))
            new_path = path.copy()
            new_paths = self.dfs_paths(child, new_visited_moves, new_path)
            paths.extend(new_paths)
        return paths


    def get_mandatory_blocks(self, paths):
        return reduce(lambda x,y: x & y ,map(lambda x:set(x), paths))

    def cacul_mandatory_weight(self, paths, target):
        # caculate the place of target in each path
        # The further ahead the target is in the path, the greater the weight will be (smaller value)
        return sum(map(lambda p : (p.index(target) + 1) / len(p), paths))/len(paths)


    def is_into_loop(self, addr, function):
        for loop in self.f_loop[function]:
            if addr in loop.loop_in:
                return loop.loop_out
        return False

    def get_merge_addr(self, branch1, branch2, function, exclude_ret=False):

        paths = []
        loop_out = self.is_into_loop(branch1, function)
        if loop_out:
            for loop_out_addr in loop_out:
                paths.append([branch1, loop_out_addr])
        else:
            paths.append([branch1])
        loop_out = self.is_into_loop(branch2, function)
        if loop_out:
            for loop_out_addr in loop_out:
                paths.append([branch2, loop_out_addr])
        else:
            paths.append([branch2])

        waiting_level = len(paths) # how many paths in the current generation
        next_level = waiting_level
        old_path_str = ""
        while paths:
            if len(paths) > 10240:
                l.debug("too many paths")
                return 0
            cur_path = paths.pop(0)
            waiting_level -= 1
            next_level -= 1
            parent = cur_path[-1]
            has_child = False
            for addr in self.block_info[parent].succ:
                if addr in cur_path and len(self.block_info[parent].succ) > 1:
                    continue
                if exclude_ret and addr in self.direct_to_no_ret_blocks:
                    continue
                has_child = True
                loop_out = self.is_into_loop(addr, function)
                if loop_out:
                    for loop_out_addr in loop_out:
                        tmp = cur_path.copy()
                        tmp.extend([addr, loop_out_addr])
                        paths.append(tmp)
                        next_level += 1
                else:
                    tmp = cur_path.copy()
                    tmp.append(addr)
                    paths.append(tmp)
                    next_level += 1

            if not has_child:
                if parent not in self.no_ret_blocks:
                    # if a path ends with a not return call, drop it because it cannot merge
                    # otherwise do not drop it
                    paths.append(cur_path)
                    next_level += 1

            if waiting_level == 0:
                waiting_level = next_level
                res = self.get_mandatory_blocks(paths)
                if res:
                    return sorted(res, key=lambda t: self.cacul_mandatory_weight(paths, t))[0]
                new_path_str = str([[hex(x) for x in p] for p  in paths])
                if new_path_str == old_path_str:
                    l.debug("branch has no new path: {}".format(new_path_str))
                    l.debug(
                        "still could not find mandatory blocks\n{}".format(str([[hex(x) for x in p] for p in paths])))
                    end_addrs = list(map(lambda p:p[-1], paths))
                    target = max(end_addrs, key=end_addrs.count)
                    paths = list(filter(lambda p: p[-1] == target, paths))
                old_path_str = new_path_str
                res = self.get_mandatory_blocks(paths)
                if res:
                    return sorted(res, key=lambda t: self.cacul_mandatory_weight(paths, t))[0]




        l.debug("no merge addr")
        return 0

    def get_func_callers(self, func_addr):
        callers = set()
        for b in self.func_block_info[func_addr]:
            callers.update(self.block_info[b].call_functions)
        return callers


    def get_ifvs_info(self, block):
        data = self.load_data()
        """
        data = {
            branch:
            {
                "type": 'LOOP' or 'BRANCH'
                "write_ins" : [(ins_addr, block_addr, is_in_sub_func, func_addr)],  
                'merge_addr': merge_addr,
                'backtrack_addr': set(backtrack_addr,...),
                'addr_range': set(addrs), # when get out of the range at the top level, check constraints
                'check_addr': set(addrs),
                'influent_branch': set(branch_addr,...), # will be set in the second taint
            }
        }
        """
        l.debug("meet ifvs branch: 0x%x", block)

        func = self.block_info[block].function
        if block not in data:
            data[block] = {
                "write_ins": set(),  # (ins_addr, block_addr, is_in_sub_func)
                "merge_addr": set(),
            }

        branch1, branch1_blocks, branch2, branch2_blocks, loop = self.get_branch_diff(block,
                                                                           self.cfg.kb.functions[func].block_addrs_set)
        l.debug("branch1: 0x%x,%s" % (branch1, str([hex(b) for b in branch1_blocks])))
        l.debug("branch2: 0x%x,%s" % (branch2, str([hex(b) for b in branch2_blocks])))
        if branch1_blocks or branch2_blocks:
            self.update_write_location(branch1_blocks, data[block]["write_ins"])
            self.update_write_location(branch2_blocks, data[block]["write_ins"])
        else:
            return

        if not branch1_blocks and not loop:
            merge_addr = branch1
        elif not branch2_blocks and not loop:
            merge_addr = branch2
        elif block in self.merge_info:
            merge_addr = list(self.merge_info[block])[0]
            data[block]["merge_addr"] |= self.merge_info[block]
        else:
            l.error("block: 0x%x not in merge info, now try to dfs..." % block)
            merge_addr = self.get_merge_addr(branch1, branch2, func, exclude_ret=True)
            if not merge_addr:
                merge_addr = self.get_merge_addr(branch1, branch2, func)
        l.debug("merge addr: 0x%x", merge_addr)
        data[block]["merge_addr"].add(merge_addr)
        data[block]["backtrack_addr"] = loop.loop_in if loop else {block}
        data[block]["addr_range"] = loop.loop_body if loop else (branch1_blocks | branch2_blocks)
        data[block]["type"] = "LOOP" if loop else "BRANCH"
        data[block]["check_addr"] = loop.loop_out if loop else {merge_addr}

        self.save_data(data)




    def del_empty_ifv(self):
        data = self.load_data()
        for l_addr in [key for key in data]:
            if not data[l_addr]['write_ins']:
                data.pop(l_addr)
        self.save_data(data)

    def is_addr_in_data_segment(self, addr):
        if addr > self.bss_range[0] and addr <= self.bss_range[1]:
            return True
        elif addr > self.data_range[0] and addr <= self.data_range[1]:
            return True
        return False

    def is_addr_in_mem(self, addr):
        if addr > self.rodata_range[0] and addr < self.rodata_range[1] + 0x1000:
            return True
        elif addr > self.data_range[0] and addr < self.data_range[1] + 0x1000:
            return True
        elif addr > self.bss_range[0] and addr < self.bss_range[1] + 0x1000:
            return True
        elif addr > self.text_range[0] and addr < self.text_range[1] + 0x1000:
            return True
        elif addr > 0x7f0000000000000 and addr < 0x800000000000000:
            # stack
            return True
        elif addr > 0xc0000000 and addr < 0xc1000000:
            # malloc
            return True
        return False

    def get_ite_addr(self, expr):
        var_value_dict = get_ite_cond(expr)
        total_possible = tm.get_ite_possible_value_num(expr, var_value_dict)
        if not tm.expr_is_ite_outside(expr) or (total_possible < 64 and var_value_dict):
            ite_exprs = tm.get_ite_value_by_set_cond(expr, var_value_dict, total_possible)
            if all([e.concrete for e in ite_exprs]):
                res = []
                for e in ite_exprs:
                    addr = e.args[0]
                    if self.is_addr_in_mem(addr):
                        res.append(addr)
                return res

    def simplify_expr(self, expr, try_if=True):
        if str(expr) in self.simplify_res:
            return self.simplify_res[str(expr)]
        if tm.expr_contain_if(expr) and try_if:
            used_vars = set()
            ite_values = tm.get_ite_exprs(expr)
            res = ite_values[0]
            if len(ite_values) > 1:
                if not all([v.concrete for v in ite_values]):
                    for v in ite_values:
                        leaves = set(filter(self.leaf_filter, v.recursive_leaf_asts))
                        if leaves - used_vars:
                            res |= v
                            used_vars |= leaves
                else:
                    res = tm.merge_expr(None, ite_values)
            if not self.judge_simple_expr(res) or (res.concrete and res.args[0] == 1):
                # can not simplify by parse ite
                return self.simplify_expr(expr, try_if=False)
        else:
            # we simply preserve the variable
            leaves = list(set(filter(self.leaf_filter, expr.recursive_leaf_asts)))
            res = leaves[0]
            for l in leaves[1:]:
                if res.length + l.length <= expr.length:
                    res = claripy.Concat(l, res)
                else:
                    if l.length < res.length:
                        l = claripy.Concat(claripy.BVV(0, res.length-l.length), l)
                    elif l.length > res.length:
                        res = claripy.Concat(claripy.BVV(0, l.length-res.length), res)
                    res |= l
            if res.length < expr.length:
                res = claripy.Concat(claripy.BVV(0, expr.length-res.length), res)
        self.simplify_res[str(expr)] = res
        return res


    def leaf_filter(self, e):
        if e.concrete:
            return False
        if "mvar" in str(e):
            return False
        return True

    def judge_simple_expr(self, expr):
        length = len(str(expr))
        if length < 200:
            return True
        leaves = list(filter(self.leaf_filter, expr.recursive_leaf_asts))
        if len(leaves) == 0:
            # no symbolic value
            return True
        ops = get_expr_ops(expr)
        if len(ops) > 10:
            return False
        if expr.depth < 5:
            return True

        return False

    def hook_sym_write(self, state):
        try:
            endness = state.inspect.mem_write_endness
            if not state.globals[APPLY_LIB_TAINT]:
                # filter mode, we set taint labels when trigger target instructions
                if state.regs.pc.concrete and state.addr in self.write_loc:
                    already_taint = {hex(state.addr)}
                    if is_tainted(state.inspect.mem_write_expr, state, TAINT_BUF + '_' + self.filter_id + '_'):
                        print(state.inspect.mem_write_expr)
                        for addr_list in self.pattern_taint2.findall(str(state.inspect.mem_write_expr)):
                            for addr in self.pattern_hex.findall(addr_list):
                                already_taint.add(addr)
                    l.info("apply taint at 0x%x", state.addr)
                    taint_id = self.filter_id + '_' + '_'.join(already_taint) + "_END"
                    bits = state.inspect.mem_write_expr.length
                    data = new_tainted_value(taint_id, bits)
                    state.inspect.mem_write_expr = data
                    state.globals[TAINT_APPLIED] = True

            addr = state.inspect.mem_write_address
            data = state.inspect.mem_write_expr
            if not self.judge_simple_expr(data):
                state.inspect.mem_write_expr = self.simplify_expr(data)
            if type(addr) is not int and addr.symbolic:
                if tm.expr_contain_if(addr):
                    targets = self.get_ite_addr(addr)
                    if targets:
                        if len(targets) == 1:
                            state.inspect.mem_write_address = targets[0]
                            return
                        else:
                            for target in targets:
                                state.memory.store(target, state.inspect.mem_write_expr, endness=endness)
                            state.inspect.mem_write_address = claripy.BVV(SYM_WRITE_ADDR, state.arch.bits)
                            state.inspect.mem_write_condition = claripy.BoolV(False)
                            return

                if endness and endness != state.arch.memory_endness:
                    data = claripy.simplify(claripy.Reverse(state.inspect.mem_write_expr))
                else:
                    data = state.inspect.mem_write_expr
                self.save_mem(state, addr, data)
                # do not write
                state.inspect.mem_write_address = claripy.BVV(SYM_WRITE_ADDR, state.arch.bits)
                state.inspect.mem_write_condition = claripy.BoolV(False)
            else:
                if type(addr) is not int:
                    addr_BVV = addr
                    addr_int = addr.args[0]
                else:
                    addr_int = addr
                    addr_BVV = claripy.BVV(addr, state.arch.bits)
                if self.is_addr_in_data_segment(addr_int):
                    self.save_mem(state, addr_BVV, state.inspect.mem_write_expr)
                state.globals["changed_mem"].append((addr_int, str(state.inspect.mem_write_expr)))
                for i in range(1, state.inspect.mem_write_expr.length // 8):
                    state.globals["changed_mem"].append((addr_int + i, ''))
        except:
            import traceback
            traceback.print_exc()
            import IPython
            IPython.embed()
        return

    def save_mem(self, state, addr, expr):
        addr = claripy.simplify(addr)
        state.globals["mem"][addr] = expr
        return

    def hook_reg_write_before(self, state):
        data = state.inspect.reg_write_expr
        if not self.judge_simple_expr(data):
            state.inspect.reg_write_expr = self.simplify_expr(data)

    def hook_sym_read_before(self, state):
        # l.info("hook sym read before: addr %s", state.inspect.mem_read_address)
        addr = state.inspect.mem_read_address
        length = state.inspect.mem_read_length
        max_len = state.solver.max(length)
        if max_len > 0x1000:
            state.inspect.mem_read_length = 0x1000
        if type(addr) is not int and addr.symbolic:
            if tm.expr_contain_if(addr):
                targets = self.get_ite_addr(addr)
            else:
                targets = None
            if targets:
                if len(targets) == 1:
                    state.inspect.mem_read_address = targets[0]
                    return
                else:
                    exprs = []
                    for target in targets:
                        expr = state.memory.load(target, state.inspect.mem_read_length, endness=state.arch.memory_endness)
                        exprs.append(expr)
                    expr_res = tm.merge_expr(None, exprs)
                    state.memory.store(SYM_READ_SAVE_ADDR, expr_res, endness=state.arch.memory_endness)
                    state.inspect.mem_read_address = claripy.BVV(SYM_READ_SAVE_ADDR, state.arch.bits)
                    return
            oldcon_cache_keys = []
            for con in state.solver.constraints:
                oldcon_cache_keys.append(con.cache_key)
            self.read_cons.append(oldcon_cache_keys)
            self.read_addr.append(addr)
            # l.info("read_cons: %s" % self.read_cons)
            state.inspect.mem_read_address = claripy.BVV(SYM_READ_ADDR, state.arch.bits)
            state.inspect.mem_read_condition = claripy.false
            return

    def sym_addr_in_range(self, addr, start, length):
        index_expr = claripy.simplify(addr - start)
        if index_expr.symbolic:
            return -1
        index = index_expr.args[0] * 8
        if index >= 0 and index < length:
            return index
        return -1

    def get_state_sym_mem(self, state, addr, read_bits):
        for used_addr in state.globals["mem"]:
            index = self.sym_addr_in_range(addr, used_addr, state.globals["mem"][used_addr].length)
            if index == -1:
                continue
            data = state.globals["mem"][used_addr][:index]
            if data.length >= read_bits:
                return claripy.simplify(data[read_bits - 1:0])
            else:
                left = state.memory.load(addr + data.length // 8,
                                         (read_bits - data.length) // 8)
                return claripy.simplify(state.solver.Concat(left, data))
        if tm.expr_contain_if(addr):
            addrs = tm.get_ite_exprs(addr)
            exprs = []
            for addr in addrs:
                if addr.concrete:
                    continue
                exprs.append(self.get_state_sym_mem(state, addr, read_bits))
            if not exprs:
                return claripy.BVV(1, read_bits)
            return tm.merge_expr(None, exprs)
        # check if the target addr is dereferenced in other states
        for expr in state.globals["derefs"]:
            if str(state.globals["derefs"][expr]) == str(addr):
                # self.save_mem(state, addr, expr)
                if expr.length > read_bits:
                    return expr[read_bits - 1:0]
                elif expr.length == read_bits:
                    return expr
                else:
                    left = state.memory.load(addr + expr.length // 8,
                                             (read_bits - expr.length) // 8,
                                             endness=state.arch.memory_endness)
                    return state.solver.Concat(left, expr)

        # if not, we create a new dereferenced variable
        if len(str(addr)) > 2000:
            # we do not save too long expressions
            return claripy.BVV(1, read_bits)
        expr = claripy.BVS("deref[%s]" % (str(addr)), read_bits)
        state.globals["derefs"][expr] = addr
        return expr

    def hook_sym_read(self, state):
        try:
            addr = state.inspect.mem_read_address
            read_bits = state.inspect.mem_read_length * 8
            endness = state.inspect.mem_read_endness
            if type(addr) is not int and (addr.symbolic or addr.args[0] == SYM_READ_ADDR):
                # l.info("before pop addr: %s" % self.read_addr)
                if not self.read_addr:
                    return
                addr = self.read_addr.pop(-1)
                addr = claripy.simplify(addr)
                state.inspect.mem_read_expr = self.get_state_sym_mem(state, addr, read_bits)
                if endness and endness != state.arch.memory_endness:
                    state.inspect.mem_read_expr = claripy.simplify(state.solver.Reverse(state.inspect.mem_read_expr))
                # l.info("read over: %s   %s", addr, state.inspect.mem_read_expr)
            if self.is_addr_in_data_segment(state.solver.eval(addr)):
                if type(addr) is int:
                    addr = claripy.BVV(addr, state.arch.bits)
                state.inspect.mem_read_expr = self.get_state_sym_mem(state, addr, read_bits)
                if endness and endness != state.arch.memory_endness:
                    state.inspect.mem_read_expr = claripy.simplify(state.solver.Reverse(state.inspect.mem_read_expr))

        except:
            import traceback
            traceback.print_exc()
            import IPython
            IPython.embed()
        return

    def hash_call(self, state):
        try:
            # multiple call targets
            multiple_targets = []
            if state.globals.get('jmp_targets', None) is not None:
                cons = state.globals.pop('constraints')
                pc_expr = state.globals.pop('pc_expr')
                state.solver.reload_solver(cons)  # the constraints might be simplified, so we need to restore them
                for target in state.globals.pop('jmp_targets'):
                    if any([s for s in state.inspect.sim_successors.flat_successors if s.addr == target]):
                        continue
                    if target in self.function_blacklist:
                        continue
                    s = state.copy()
                    state_copy(s)
                    s.regs.pc = claripy.BVV(target, state.arch.bits)
                    s.solver.reload_solver(cons[:-1] + [pc_expr == target])
                    multiple_targets.append(s)
            for s in multiple_targets:
                state.inspect.sim_successors.flat_successors.append(s)
                self.hash_call(s)

            if state.addr in self.func_block_info:
                if state.addr > self.text_range[1] or state.addr < self.text_range[0]:
                    # lib function
                    return
                func_addr = state.addr
                if func_addr in self.function_blacklist:
                    l.info("no ret function: %s make errored" % state)
                    raise AngrError
                if func_addr in self.fake_ret_func:
                    l.info("fake ret function: %s" % state)
                    self.call_analyze.fake_ret(state)
                    return
                # call new function
                if func_addr not in self.func_hash:
                    l.info("generate func hash for 0x%x", func_addr)
                    self.func_hash[func_addr] = None
                    self.generate_func_hash_state(func_addr, step_num=self.step_num, apply_lib_taint=state.globals.get(APPLY_LIB_TAINT, False))
                if self.func_hash[func_addr]['is_over']:
                    if getattr(state.globals, MEM, None) is not None:
                        state.globals[MEM] = copy.deepcopy(state.globals[MEM])
                    l.info("synchroning %x", func_addr)
                    self.state_sync(state, func_addr)
                    succ_states = []
                    for succ_state in state.inspect.sim_successors.flat_successors:
                        if succ_state.regs.pc.concrete and succ_state.addr == func_addr:
                            # we need to remove the jmp_targets
                            succ_state.globals.pop('jmp_targets', None)
                            succ_states.append(succ_state)
                    for succ_state in succ_states:
                        if succ_state.addr == func_addr:
                            self.state_sync(succ_state, func_addr)
                    l.info("func 0x%x hash synchronized over, current state: %s", func_addr, state)
                else:
                    l.info("func 0x%x hash not over, try fake return", func_addr)
                    self.call_analyze.fake_ret(state)
            return
        except AngrError:
            raise AngrError
        except:
            import traceback
            traceback.print_exc()
            import IPython
            IPython.embed()

    def concrete_pc(self, state):
        '''
        If there is multiple jump targets (less than 10),
        we choose one target as the value of pc, and save other results in state.globals['jmp_targets']
        :param state:
        :return:
        '''
        try:
            pc_offset = state.arch.get_register_offset('pc')
            if type(state.inspect.reg_write_offset) == int:  # The offset of the register being written.
                write_off = state.inspect.reg_write_offset
            else:
                write_off = state.inspect.reg_write_offset.args[0]
            if write_off != pc_offset:
                return
            try:
                s = state.copy()
                state_copy(s)
                res = s.solver.eval_upto(state.inspect.reg_write_expr, 20)
                if len(res) == 20:
                    succ = self.block_info[state.history.addr].succ
                    if len(succ) > 1:
                        # it is not an indirect call, so just use our switch analysis result
                        res = list(succ)
                if len(res) == 20:
                    if state.history.addr in self.indirect_calls:
                        res = list(self.indirect_calls[state.history.addr])
                if len(res) == 20:
                    func_addr = state.globals["start"]
                    if func_addr in self.func_hash:
                        if not self.func_hash[func_addr]['is_over']:
                            # record indirect call
                            if state.history.addr not in self.func_hash[func_addr]['indirect_call_exprs']:
                                self.func_hash[func_addr]['indirect_call_exprs'][state.history.addr] = []
                            if not expr_in_list(state.inspect.reg_write_expr, self.func_hash[func_addr]['indirect_call_exprs'][state.history.addr]):
                                self.func_hash[func_addr]['indirect_call_exprs'][state.history.addr].append(state.inspect.reg_write_expr)
                    l.error("Too many possible values for pc")
                    if state.history.jumpkind == 'Ijk_Call' or (state.history.jumpkind == 'Ijk_Boring' and not self.block_info[state.history.addr].succ):
                        self.call_analyze.fake_ret(state, use_callstack=False, ret=0)
                        state.scratch.target = state.addr
                    else:
                        state.add_constraints(state.inspect.reg_write_expr == 0)
                        state.inspect.reg_write_expr = claripy.BVV(0, state.arch.bits)
                    return
                del s
                # manually fork states

                if len(res) > 1:
                    state.globals['jmp_targets'] = res[1:]
                    # we have to save the previous constraints
                    # otherwise, they will be simplified
                    state.globals['pc_expr'] = state.inspect.reg_write_expr
                    state.globals['constraints'] = state.solver.constraints
                else:
                    if len(res) == 1:
                        if state.regs.pc.concrete and res[0] == state.addr:
                            # check ud2
                            try:
                                if self.proj.factory.block(state.addr).capstone.insns[-1].mnemonic == 'ud2':
                                    raise AngrError
                            except AngrError:
                                raise AngrError
                            except:
                                pass

                state.add_constraints(state.inspect.reg_write_expr == res[0])
                state.inspect.reg_write_expr = claripy.BVV(res[0], state.arch.bits)
            except AngrError:
                raise AngrError
            except Exception as e:
                print(e)
                import traceback
                traceback.print_exc()
                import IPython
                IPython.embed()
        except AngrError:
            raise AngrError
        except:
            import traceback
            traceback.print_exc()
            import IPython
            IPython.embed()



    def hash_collect_branch(self, state):
        if state.history.actions.hardcopy[-1].type == "constraint":
            prev_addr = state.history.bbl_addrs.hardcopy[-2]
            func_addr = state.globals["start"]
            if prev_addr not in self.func_hash[func_addr]['branch_conds']:
                self.func_hash[func_addr]['branch_conds'][prev_addr] = set()
            cond = state.history.jump_guards.hardcopy[-1]
            for c in list(filter(self.leaf_filter, cond.recursive_leaf_asts)):
                self.func_hash[func_addr]['branch_conds'][prev_addr].add(c)


    def recover_expr(self, expr, var_dict):
        if type(expr) is int or expr.concrete:
            return expr
        expr_leaves = list(expr.recursive_leaf_asts)
        for var in var_dict:
            if expr_in_list(var, expr_leaves):
                expr = expr.replace(var, var_dict[var])
        return expr

    def add_indirect_target(self, addr, target):
        if addr not in self.indirect_calls:
            self.indirect_calls[addr] = set()
        self.indirect_calls[addr].add(target)

    def add_indirect_targets(self, addr, targets):
        if addr not in self.indirect_calls:
            self.indirect_calls[addr] = set()
        for target in targets:
            self.indirect_calls[addr].add(target)



    def state_sync(self, state, func_addr):
        var_dict = {}
        arg_num = self.sr.func_info[func_addr] if func_addr in self.sr.func_info else 10
        if arg_num < 10:
            arg_num = 10
        args = self.call_analyze.n_args(state, arg_num)
        for i in range(arg_num):
            if i >= len(self.func_hash[func_addr]['input_vars']['args']):
                break
            var_dict[self.func_hash[func_addr]['input_vars']['args'][i]] = args[i]
        for deref_var in self.func_hash[func_addr]['input_vars']['derefs']:
            addr = self.func_hash[func_addr]['input_vars']['derefs'][deref_var]
            real_addr = self.recover_expr(addr, var_dict)
            real_expr = state.memory.load(real_addr, deref_var.length // 8, endness=self.proj.arch.memory_endness)
            if 'mem' in str(real_expr):
                # read an uninitialized memory
                continue
            var_dict[deref_var] = real_expr

        # recover mem
        for addr, value in self.func_hash[func_addr]['mem_op']:
            real_addr = self.recover_expr(addr, var_dict)
            real_value = self.recover_expr(value, var_dict)
            state.memory.store(real_addr, real_value, endness=self.proj.arch.memory_endness)
        for offset, value in self.func_hash[func_addr]['mem_op_stack']:
            stack_addr = self.call_analyze.get_sp_value(state) + offset
            real_value = self.recover_expr(value, var_dict)
            state.memory.store(stack_addr, real_value, endness=self.proj.arch.memory_endness)
        self.call_analyze.fake_ret(state, use_callstack=False)
        # recover return reg
        ret_expr = self.recover_expr(self.func_hash[func_addr]['ret'], var_dict)
        self.call_analyze.set_ret_value(state, ret_expr)


        # try to solve indirect calls
        tmp = state.copy()
        state_copy(tmp)
        tmp.solver.reload_solver()
        for addr in self.func_hash[func_addr]['indirect_call_exprs']:
            target_exprs = self.func_hash[func_addr]['indirect_call_exprs'][addr]
            for target_expr in target_exprs:
                real_target = self.recover_expr(target_expr, var_dict)
                res = tmp.solver.eval_upto(real_target, 10)
                if len(res) < 10:
                   for t in res:
                       if t > self.text_range[0] and t < self.text_range[1]:
                        self.add_indirect_target(addr, t)
                        l.info("update indirect call target at 0x%x to %s", addr, hex(t))
                else:
                    caller = state.globals['start']
                    l.warning("cannot solve indirect call at 0x%x in func 0x%x", addr, func_addr)
                    if caller in self.func_hash:
                        l.warning("save expr in the caller hash 0x%x" % caller)
                        # record indirect call in caller function
                        if addr not in self.func_hash[caller]['indirect_call_exprs']:
                            self.func_hash[caller]['indirect_call_exprs'][addr] = []
                        if not expr_in_list(real_target, self.func_hash[caller]['indirect_call_exprs'][addr]):
                            self.func_hash[caller]['indirect_call_exprs'][addr].append(real_target)
                    else:
                        l.warning("indirect call analyze failed!")

        # check the tainted branches
        for branch_addr in self.func_hash[func_addr]['branch_conds']:
            for cond in self.func_hash[func_addr]['branch_conds'][branch_addr]:
                real_cond = self.recover_expr(cond, var_dict)
                if is_tainted(real_cond, state):
                    if state.globals.get(APPLY_LIB_TAINT, False):
                        if branch_addr not in self.ifv_meet:
                            l.info("tainted branch %x: %s" % (branch_addr, real_cond))
                            self.ifv_meet.add(branch_addr)
                            self.get_ifvs_info(branch_addr)
                    else:
                        # fileter important write
                        for addrs in self.pattern_taint2.findall(str(real_cond)):
                            for addr in self.pattern_hex.findall(addrs):
                                addr_v = int(addr, 16)
                                important = True
                                for is_sub_func, func in self.write_loc[addr_v]:
                                    if state.callstack.func_addr == func:
                                        if is_sub_func:
                                            # the ifv should be able to effect branchs in other functions
                                            important = False
                                            break
                                if important:
                                    if addr not in self.filter_res:
                                        self.filter_res[addr] = set()
                                    self.filter_res[addr].add(branch_addr)
                                    # l.info("important write %x: %s" % (branch_addr, real_cond))

                # we need to save the condition in the caller function
                caller = state.globals['start']
                if caller in self.func_hash:
                    conds = list(filter(self.leaf_filter, real_cond.recursive_leaf_asts))
                    if conds:
                        if branch_addr not in self.func_hash[caller]['branch_conds']:
                            self.func_hash[caller]['branch_conds'][branch_addr] = []
                    for c in conds:
                        if not expr_in_list(c, self.func_hash[caller]['branch_conds'][branch_addr]):
                            self.func_hash[caller]['branch_conds'][branch_addr].append(c)


        return






    def generate_func_hash_state(self, func_addr, bp_list=None, step_num=1024, apply_lib_taint=True):
        '''
        func_addr: {
            'start_state': start_state,
            'end_state': end_state,
            'indirect_call_exprs':{state_addr:[exprs]}
            'caller_states':{
                caller_addr: [caller_states]
            }
            'branch_conds': {branch_addr: branch_conds}
            'mem_op': [(addr, value)]
            'mem_op_stack': [(offset, value)]
            'ret': value
            'input_vars':{
                'args': [],
                'regs': {reg_name: sym_reg}
                'deref': { # deref values
                    addr: value
                }
            }
            'is_over': True/False
        }
        '''
        self.func_hash[func_addr] = {
            'start_state': None,
            'end_state': None,
            'indirect_call_exprs': {},
            'caller_states': {},
            'branch_conds': {},
            'mem_op': [],
            'mem_op_stack': [],
            'ret' : 0,
            'input_vars': {
                'args': [],
                'derefs': []
            },
            'is_over': False
        }
        if bp_list is None:
            bp_list = [(self.hook_sym_write, 'mem_write', angr.BP_BEFORE),
                       (self.hook_sym_read_before, 'mem_read', angr.BP_BEFORE),
                        (self.hook_sym_read, 'mem_read', angr.BP_AFTER),
                        (self.hash_call, 'engine_process', angr.BP_AFTER),
                        (self.hash_collect_branch, 'irsb', angr.BP_BEFORE),
                        (self.concrete_pc, 'reg_write', angr.BP_BEFORE),
                       (self.hook_reg_write_before, 'reg_write', angr.BP_BEFORE),
                       ]
        # if not apply_lib_taint:
        #     bp_list.append((self.add_taint2, 'mem_write', angr.BP_AFTER))

        tl = TaintLauncher(self.binary, self.proj)
        meet_addrs = tl.run(from_entry=False,
                                 start_func=func_addr,
                                 start_addr=func_addr,
                                 init_sym_reg=False,
                                 arg_num=self.sr.func_info[func_addr] if (func_addr in self.sr.func_info and self.sr.func_info[func_addr]>10) else 10,
                                 check_function=self.check_func, bp_list=bp_list,
                                 step_num=step_num,
                                 apply_lib_taint=apply_lib_taint,
                                 sym_bss=False,
                                 interfunction_level=100,
                                 prioritize=True,
                                 use_dfs=False,
                                 use_merge=True,
                                 no_ret_blocks=self.direct_to_no_ret_blocks,
                                 merge_info=self.merge_info, func_loop=self.f_loop, use_manual_merge=True,
                                 loop_limit=2,
                                 n_iter_loop=2,
                                 main_range=(self.main_range[0], 0x500000),
                                 use_smart_concretization=False,
                                 smart_call=False,
                                 avoid_addrs=self.no_ret_funcs,
                                 use_rand=self.use_rand,
                                 save_states=True,
                                 save_return_states=True,
                                 optimistic_solve=True,
                                 rodata_range=self.rodata_range,
                                 )
        if getattr(self.tl, 'meet_addrs', None) is not None:
            self.tl.meet_addrs |= meet_addrs
        start_state = tl.start_state[func_addr]
        # self.func_hash[func_addr]['start_state'] = start_state
        sp = start_state.solver.eval(self.call_analyze.get_sp_value(start_state))
        ret_states = tl.ret_states[func_addr]
        if len(ret_states) > 1:
            tl.tm.manual_merge(ret_states, ret_states[0], [[]])
        elif not ret_states:
            self.func_hash[func_addr]['is_over'] = True
            return
        ret_state = ret_states[0]

        # self.func_hash[func_addr]['end_state'] = ret_state
        diff_mem = tl.tm.get_diff_mem_by_log([start_state, ret_state])
        for addr, size in diff_mem:
            if addr < sp and addr > sp - 0x100000:
                # the stack memory that will not be used
                continue
            if addr > sp and addr < sp + 0x100000:
                # the local variable
                self.func_hash[func_addr]['mem_op_stack'].append((addr - sp, ret_state.memory.load(addr, size, endness=ret_state.arch.memory_endness)))
                continue
            self.func_hash[func_addr]['mem_op'].append((addr, ret_state.memory.load(addr, size, endness=ret_state.arch.memory_endness)))
        for addr_expr in ret_state.globals[MEM]:
            if '__or__' in get_expr_ops(addr_expr):
                continue
            self.func_hash[func_addr]['mem_op'].append((addr_expr, ret_state.globals[MEM][addr_expr]))
        ret_val = self.call_analyze.get_ret_value(ret_state)
        self.func_hash[func_addr]['ret'] = ret_val
        self.func_hash[func_addr]['input_vars'] = {
            'args': ret_state.globals['args'],
            'derefs': ret_state.globals['derefs']
        }
        self.func_hash[func_addr]['is_over'] = True
        with open(self.func_hash_path, "wb") as f:
            pickle.dump(self.func_hash, f)



    def initial_analyze(self, run=True, step_num=1024, dfs_limit=10, use_pickle=False, save_states=False, solve_indirect=True):

        self.cfg = self.tl._p.analyses.CFGFast(normalize=True)
        self.text_range = get_section_range(self.tl._p, ".text")
        self.data_range = get_section_range(self.tl._p, ".data")
        self.rodata_range = get_section_range(self.tl._p, ".rodata")
        self.bss_range = get_section_range(self.tl._p, ".bss")
        pickle_path = self.ifv_path[:-3] + "_data.pk"
        indirect_path = self.ifv_path[:-3] + '_indirect.pk'
        self.func_hash_path = self.ifv_path[:-3] + '_func_hash.pk'
        if use_pickle:
            if os.path.exists(pickle_path):
                self.caller_to_receive, self.block_info, self.f_loop, self.merge_info, self.no_ret_blocks, self.no_succ_blocks, self.no_ret_funcs, self.direct_to_no_ret_blocks, self.func_block_info, self.prior_addr, self.block_succ_dict, self.sr = pickle.load(open(pickle_path, "rb"))
            else:
                use_pickle = False
            if os.path.exists(indirect_path):
                self.indirect_calls = pickle.load(open(indirect_path, "rb"))
            if os.path.exists(self.func_hash_path):
                self.func_hash = pickle.load(open(self.func_hash_path, "rb"))

        if not use_pickle:
            self.caller_to_receive = set()
            for target in self.cgc_receive_addrs:
                self.caller_to_receive.update(get_func_xref(self.cfg, target, recursive=True))
            self.caller_to_receive.update(self.cgc_receive_addrs)

            gb = GetBlocks(self.binary, self.cfg)
            self.block_info = gb.get_blocks()
            self.cfg = gb.cfg # already solved switch

            gl = GetLoops(self.binary, self.cfg)
            self.f_loop = gl.get_loops()



            loop_info = gl.loops
            self.no_ret_blocks, self.no_succ_blocks = gb.get_no_ret_blocks()
            self.direct_to_no_ret_blocks = gb.get_all_no_ret_blocks()
            self.no_ret_funcs = gb.no_ret_funcs
            self.ret_blocks = gb.get_ret_blocks()

            # Before get merge info, we need to ignore the direct_to_no_ret_blocks
            gb.set_post_dom(bypass_nodes=self.direct_to_no_ret_blocks, ret_nodes=self.ret_blocks)
            gm = GetMergeInfo(self.binary, self.cfg, self.tl._p, gb=gb, gl=gl)
            self.merge_info = gm.get_merge_info()

            self.func_block_info = gb.funcs
            self.gp = GetPrefix(self.block_info)
            self.gp.get_func_caller()

            self.prior_addr = {}
            '''
            {
                addr : distance
            }
            '''
            for target in self.cgc_receive_addrs:
                for caller in get_xref(self.cfg, target):
                    self.prior_addr.update(self.gp.get_prefix(caller))

            self.block_succ_dict = {}
            get_all_succ_blocks_weight(self.cfg, self.block_succ_dict, self.main_range)
            l.debug("total block number: %d", len(self.block_succ_dict))

            l.info("recognize function arg...")
            self.sr = SourceRecognize(self.tl._p, self.cfg, self.cfg)
            l.info("over")

            # save pickle data
            data = (self.caller_to_receive, self.block_info, self.f_loop, self.merge_info, self.no_ret_blocks, self.no_succ_blocks, self.no_ret_funcs, self.direct_to_no_ret_blocks, self.func_block_info, self.prior_addr, self.block_succ_dict, self.sr)
            with open(pickle_path, "wb") as f:
                pickle.dump(data, f)
            self.indirect_calls = {}

        self.call_analyze = CallAnalyze(self.proj, self.cfg)
        self.all_blocks = self.block_info.keys()
        self.bp_list = [(self.hook_sym_write, 'mem_write', angr.BP_BEFORE),
                    (self.hook_sym_read_before, 'mem_read', angr.BP_BEFORE),
                    (self.hook_sym_read, 'mem_read', angr.BP_AFTER),
                   (self.hash_call, 'engine_process', angr.BP_AFTER),
                   (self.concrete_pc, 'reg_write', angr.BP_BEFORE),
                   ]

        self.func_call_args = {}
        if self.cgc:
            self.bp_list.append((self.call_taint_func, 'return', angr.BP_BEFORE),)
        self.step_num = step_num
        self.limit = dfs_limit


        self.function_blacklist = self.no_ret_funcs
        self.fake_ret_func = set()

        for addr in list(self.func_hash):
            if not self.func_hash[addr]["is_over"]:
                self.func_hash.pop(addr)
        if run:
            if os.path.exists(self.ifv_path):
                os.remove(self.ifv_path)

            start, from_entry = self.main_addr, False
            if solve_indirect:
                meet_addrs = self.tl.run(from_entry=from_entry,
                                         start_func=start,
                                         start_addr=start,
                                         apply_lib_taint=True,
                                         check_function=self.check_func, bp_list=self.bp_list,
                                         step_num=self.step_num,
                                         sym_bss=False, function_whitelist=list(self.caller_to_receive),
                                         function_blacklist=self.function_blacklist,
                                         interfunction_level=100,
                                         prioritize=True,
                                         prior_addr=self.prior_addr,
                                         block_succ_dict=self.block_succ_dict,
                                         use_dfs=False,
                                         use_merge=True,
                                         no_ret_blocks=self.direct_to_no_ret_blocks,
                                         merge_info=self.merge_info, func_loop=self.f_loop, use_manual_merge=True,
                                         loop_limit=2,
                                         n_iter_loop=2,
                                         main_range=(self.main_range[0], 0x500000),
                                         use_smart_concretization=False,
                                         # use_dfs=False
                                         smart_call=False,
                                         avoid_addrs= self.no_ret_funcs,
                                         use_rand=self.use_rand,
                                         save_states=save_states,
                                         save_return_states=True,
                                         rodata_range=self.rodata_range,
                                         )
                l.info("solve indirect over: %s"%(str(self.indirect_calls)))
                with open(indirect_path, "wb") as f:
                    pickle.dump(self.indirect_calls, f)
                self.func_hash = {}
            if (solve_indirect and self.indirect_calls) or (not solve_indirect):
                meet_addrs = self.tl.run(from_entry=from_entry,
                                         start_func=start,
                                         start_addr=start,
                                         apply_lib_taint=True,
                                         check_function=self.check_func, bp_list=self.bp_list,
                                         step_num=self.step_num,
                                         sym_bss=False, function_whitelist=list(self.caller_to_receive),
                                         function_blacklist={0x402150, 0x404530},
                                         interfunction_level=100,
                                         prioritize=True,
                                         prior_addr=self.prior_addr,
                                         block_succ_dict=self.block_succ_dict,
                                         use_dfs=False,
                                         use_merge=True,
                                         no_ret_blocks=self.direct_to_no_ret_blocks,
                                         merge_info=self.merge_info, func_loop=self.f_loop, use_manual_merge=True,
                                         loop_limit=2,
                                         n_iter_loop=2,
                                         main_range=(self.main_range[0], 0x500000),
                                         use_smart_concretization=False,
                                         # use_dfs=False
                                         smart_call=False,
                                         avoid_addrs=self.no_ret_funcs,
                                         use_rand=self.use_rand,
                                         save_states=save_states,
                                         save_return_states=True,
                                         rodata_range=self.rodata_range,
                                         )


            self.del_empty_ifv()
            print("First over")
            return

    def filter_important_write(self, step_num=1024, limit=10, pass_func=False):
        data = self.load_data()
        self.tainted_ins = set()
        self.write_loc = {}
        self.filter_res = {}
        self.pattern_taint = re.compile(TAINT_BUF + '_'+ self.filter_id +  r'_(0x[0-9a-fA-F]+)_')
        self.pattern_taint2 = re.compile(TAINT_BUF + '_' + self.filter_id + r'([_x0-9a-fA-F]+?)END')
        self.pattern_hex = re.compile("_(0x[0-9a-fA-F]+)")
        target_functions = {} # {target_func: set(prior)}
        for branch in list(data):
            if 0 in data[branch]["merge_addr"] and len(data[branch]["merge_addr"]) == 1:
                del data[branch]

        for branch in data:
            cur_func = self.block_info[branch].function
            target_functions[cur_func] = {}

            for write_ins, block, is_sub_func, func in data[branch]["write_ins"]:
                target_functions[cur_func][block] = 0
                if write_ins not in self.write_loc:
                    self.write_loc[write_ins] = {(is_sub_func, func)}
                else:
                    if (is_sub_func, func) not in self.write_loc[write_ins]:
                        self.write_loc[write_ins].add((is_sub_func, func))

        self.func_hash = {}
        meet_addrs = self.tl.run(from_entry=False,
                                 start_func = self.main_addr, start_addr = self.main_addr,
                                 apply_lib_taint=False,
                                 check_function=self.check_func, bp_list=self.bp_list,
                                 step_num=self.step_num,
                                 sym_bss=False, function_whitelist=list(self.caller_to_receive),
                                 function_blacklist={0x402150, 0x404530},
                                 interfunction_level=100,
                                 prioritize=True,
                                 prior_addr=self.prior_addr,
                                 block_succ_dict=self.block_succ_dict,
                                 use_dfs=False,
                                 use_merge=True,
                                 no_ret_blocks=self.direct_to_no_ret_blocks,
                                 merge_info=self.merge_info, func_loop=self.f_loop, use_manual_merge=True,
                                 loop_limit=2,
                                 n_iter_loop=2,
                                 main_range=(self.main_range[0], 0x500000),
                                 use_smart_concretization=False,
                                 # use_dfs=False
                                 smart_call=False,
                                 avoid_addrs=self.no_ret_funcs,
                                 use_rand=self.use_rand,
                                 save_return_states=True,
                                 rodata_range=self.rodata_range,
                                 )


        self.save_data(self.filter_res, suffix="_filter")
        # if multiple branch write to the same location, choose the minimum branch
        LOOP_SUB = 0
        for branch in data:
            data[branch]["number"] = len(data[branch]["write_ins"])
            if data[branch]['type'] == "LOOP":
                data[branch]["number"] -= LOOP_SUB
        new_data = {}
        for ifv in self.filter_res:
            ifv_int = int(ifv, 16)
            candidates = list(filter(lambda b: \
                                         ifv_int in list(map(lambda a: a[0], data[b]['write_ins'])) and \
                                         (data[b]["type"] == 'LOOP' or (self.filter_res[ifv]-data[b]["addr_range"])) ,\
                                     data))
            if not candidates:
                continue
            candidates.sort(key=lambda b: data[b]["number"])
            res = candidates[0]

            if res not in new_data:
                new_data[res] = {
                    "write_ins": set(),
                    "merge_addr": data[res]["merge_addr"],
                    "backtrack_addr" : data[res]["backtrack_addr"],
                    "addr_range" : data[res]["addr_range"],
                    "type": data[res]["type"],
                    "influent_branch":set(),
                    "check_addr": data[res]["check_addr"],

                }
            for ifv_info in data[res]["write_ins"]:
                if ifv_info[0] == ifv_int:
                    new_data[res]["write_ins"].add(ifv_info)
            new_data[res]["influent_branch"] |= self.filter_res[ifv]

        self.save_data(new_data, suffix='_fin')








if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Taint Analysis")
    parser.add_argument("binary", help="target binary file")
    parser.add_argument("--ifv_path", default="pickle_data/data.pk", help="path of the IFV information file")
    parser.add_argument("--cgc", action="store_true")
    parser.add_argument("--get_subfunc_writeloc", action="store_true", help="When record write locations, whether to record the write locations in subfunctions")
    parser.add_argument("--not_rand", action="store_true",
                        help="If set, do not add random in dfs")
    parser.add_argument("--use_pickle", action="store_true",
                        help="Use pickle data")
    parser.add_argument("--save_states", action="store_true",
                        help="Save states")

    args = parser.parse_args()

    finder = IFVFinder(args.binary, args.ifv_path, args.cgc, args.get_subfunc_writeloc, save_number_write=True, use_rand=not args.not_rand)
    finder.initial_analyze(run=True, solve_indirect=True, step_num=10240000, dfs_limit=1, use_pickle=args.use_pickle, save_states=args.save_states)
    finder.filter_important_write(step_num=10240000, limit=1, pass_func=False)

