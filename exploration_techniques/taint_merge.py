import copy
import logging
import angr
import time
import itertools
from angr.exploration_techniques import ExplorationTechnique
import claripy
from taint_tracking import apply_taint, is_tainted, is_or_points_to_tainted_data
from program_analyze import get_ite_values, ConcatParser, IteParser, get_ite_cond, get_ite_total_values, is_expr_contain_union, get_expr_union_num, simplify_union, expr_in_list
from defines import MEM, DEREFS
import sys

level = logging.INFO
l = logging.getLogger(name=__name__)
l.setLevel(level)




def merge_intervals(intervals):
    intervals.sort(key=lambda x: x[0])
    merged = []
    for interval in intervals:
        if not merged or merged[-1][1] < interval[0]:
            merged.append(interval)
        else:
            merged[-1][1] = max(merged[-1][1], interval[1])
    return merged

class TaintMerge(ExplorationTechnique):
    def __init__(self, merge_info, func_loop, no_ret_blocks, loop_limit=2, use_manual_merge=False):
        '''
        :param merge_info:  a dict of merge information
        :param func_loop:   a dict of loop information
        :param loop_limit:  the maximum number of loops to be merged
        '''
        super(TaintMerge, self).__init__()
        self.merge_info = merge_info
        self.func_loop = func_loop
        self.no_ret_blocks = no_ret_blocks
        self.loop_limit = loop_limit
        self.use_manual_merge = use_manual_merge
        self.block_loop_out = {}
        self.block_loop_out_ignore = {}
        self.var_count = 0
        self.simlified_ites = {}
        self.map_block_to_loop_out() # init self.block_loop_out

        '''
        {
            merge_waiting_addr: {
                1: [states], # merge_count: [states]
                2: [states],
                ...
            }
        }
        '''

    def map_block_to_loop_out(self):
        '''
        map the block to the loop out address
        :return:
        '''
        for func in self.func_loop:
            for loop in self.func_loop[func]:
                for block in loop.loop_body:
                    if block not in self.block_loop_out:
                        self.block_loop_out[block] = set()
                    self.block_loop_out[block].update(loop.loop_out)
                if len(loop.loop_body) > 20:
                    # we only execute one cycle for big loops
                    for block in loop.loop_body:
                        if block not in self.block_loop_out_ignore:
                            self.block_loop_out_ignore[block] = set()
                        self.block_loop_out_ignore[block].update(loop.loop_out)

    def setup(self, simgr):
        if self.use_manual_merge:
            # To use manual merge, we need to record the write operations on regs and memory.
            for s in simgr.active:
                s.globals['merge_stack'] = [] # [(merge_addr,),]
                s.globals['wait_key'] = ['wait_0'] # init as 0
                s.globals['loop_out'] = {}

        self.wait_key = 0
        self.merge_wait_stash_stack = [] # save the name of the merge waiting stashes
        self.none_wait_key = []

        self.stop_addr = set(self.merge_info)
        for key in self.merge_info:
            if self.merge_info[key]:
                self.stop_addr.update(self.merge_info[key])

    def get_merge_constraints(self, group):
        '''
        get constrains of a group of states to merge
        :param group:   a group of states
        :return:        constraints
        '''
        start = self.get_common_ancestors_len([state.solver.constraints for state in group])
        constraints = [state.solver.constraints[start:] for state in group]
        l.debug("Merge original constraints: %s" % constraints)
        new_constraints = self.create_merge_constraints(len(group))
        return constraints, new_constraints

    def get_common_ancestors_len(self, lists):
        '''
        Get the length of the common ancestors.
        It is also the index of the first different element.
        :param lists:
        :return:
        '''
        i = 0
        min_len = min(map(len, lists))
        while i < min_len:
            elements = [lst[i] for lst in lists]
            if not all(x is elements[0] for x in elements):
                break
            i += 1
        return i

    def get_diff_actions(self, states, step=False):
        '''
        Before merging states, find different actions on reg/mem
        :param states:
        :param step: step states to get more actions.
                    Because we use extra_stop_points and might lose actions.
        :return: [actions1, actions2, ...]
        '''
        actions = [s.history.actions.hardcopy for s in states]
        start = self.get_common_ancestors_len(actions)
        diff_actions = []
        for i in range(len(actions)):
            diff_actions.append(actions[i][start:])
        return diff_actions

    def get_diff_mem_by_log(self, states):
        '''
        Get different memory by comparing the log.
        :param states:
        :return: set([mem1, mem2, ...])
        '''
        end = min([len(s.globals["changed_mem"]) for s in states])
        i = 0
        while i != end:
            if not all(s.globals["changed_mem"][i] == states[0].globals["changed_mem"][i] for s in states):
                break
            i += 1
        diff_mem = set()
        for s in states:
            diff_mem.update(set(map(lambda x:x[0], s.globals["changed_mem"][i:])))
        diff_mem = sorted(diff_mem)
        res = []
        if self.project.arch.bits == 32:
            sizes = [1, 2, 4]
        else:
            sizes = [1, 2, 4, 8]
        i = 0
        while i < len(diff_mem):
            size = self.get_reg_size(i, diff_mem, sizes)
            res.append((diff_mem[i], size))
            i += size
        return res

    def get_diff_reg_mem(self, states, is_reg=True):
        if is_reg:
            plugin_name = "registers"
        else:
            plugin_name = "memory"
        plugins = [s.plugins[plugin_name] for s in states]
        plugin = plugins[0]
        others = plugins[1:]
        for o in others:
            plugin.changed_pages(o)
        changed_pages = set()
        changed_bytes = set()
        all_changed_bytes = set()
        for o in others:
            changed_pages |= plugin.changed_pages(o)

        for page_no in sorted(changed_pages):
            l.debug("%s on page %x", plugin_name, page_no)
            page_addr = page_no * plugin.page_size
            page = plugin._get_page(page_no, True)
            other_pages = []

            for o in others:
                if page_no in o._pages:
                    other_pages.append(o._get_page(page_no, False))

            for o in other_pages:
                changed_bytes |= page.changed_bytes(o, page_addr=page_addr)

            all_changed_bytes |= set(map(lambda offset: page_addr + offset, changed_bytes))
        return all_changed_bytes

    def simplify_concat(self, concat_parser):
        res = []
        for expr in concat_parser:
            if type(expr) == IteParser:
                self.simplify_ite(expr, True)
            res.append(expr)
        concat_parser.set_concat_list(res)


    def simplify_ite(self, ite_parser, simplify=False):

        concats = []
        i = 0
        for expr in ite_parser:
            if type(expr) == ConcatParser:
                concats.append((expr, i))
            else:
                if simplify and is_tainted(expr):
                    ite_parser.set_ite_list([expr])
                    return
            i += 1
        if simplify and not concats:
            ite_parser.set_ite_list([list(ite_parser)[0]])
            return
        for concat_parser, i in concats:
            self.simplify_concat(concat_parser)
            ite_parser.ite_list[i] = concat_parser


    def expr_contain_if(self, expr):
        if expr is None or type(expr) in (int, str, bool, float):
            return False
        if getattr(expr, "op", None) == "If":
            return True
        if getattr(expr, "args", None) is None:
            return False

        for arg in expr.args:
            if self.expr_contain_if(arg):
                return True

        return False

    def expr_is_ite_outside(self, expr):
        '''
        check if ite is not used as other operations' arguments
        e.g. expr_is_ite_outside(1 + If(x > 0, 1, 0)) == False
             expr_is_ite_outside(If(x > 0, 1 + e, 0)) == True

        :param expr:
        :return:
        '''
        if expr.op not in ("If", "Concat") and self.expr_contain_if(expr):
            try:
                expr = expr.ite_excavated
            except:
                l.error("ite_excavated error:%.500s" % expr)
                l.error("ite_depth:%d" % expr.ite_depth)
        if expr.op in ("If", "Concat"):
            if expr.op == "If":
                return self.expr_is_ite_outside(expr.args[1]) and self.expr_is_ite_outside(expr.args[2])
            else:
                for arg in expr.args:
                    if not self.expr_is_ite_outside(arg):
                        return False
        else:
            # other operations, should not contain a ite operation
            for arg in expr.args:
                if self.expr_contain_if(arg):
                    return False
        return True

    def get_ite_possible_value_num(self, expr, var_value_dict, rm=True):
        total_possible = 1
        for var in list(var_value_dict):
            if rm:
                if type(var.args[0]) != str or "mvar" not in var.args[0]:
                    var_value_dict.pop(var)
                    continue
                var_value_dict[var].add(claripy.BVV(0, var.size()))
            total_possible *= len(var_value_dict[var])
        return total_possible

    def get_ite_value_by_set_cond(self, expr, var_value_dict=None, total_possible=None):
        if var_value_dict is None:
            var_value_dict = get_ite_cond(expr)
        if total_possible is None:
            total_possible = self.get_ite_possible_value_num(expr, var_value_dict)
        if not var_value_dict:
            # l.error("var_value_dict is None, expr: %s" % expr)
            return [claripy.BVV(1, expr.length)]
            # return self.get_ite_value_by_set_cond2(expr)
        if total_possible > 1024:
            l.error("total_possible: %d, expr: %.500s" % (total_possible, expr))
            for var in list(var_value_dict):
                var_value_dict[var] = set(list(var_value_dict[var])[:2])
            for var in list(var_value_dict):
                while len(var_value_dict[var]) > 1:
                    var_value_dict[var].pop()
                total_possible = 1
                for var in list(var_value_dict):
                    total_possible *= len(var_value_dict[var])
                if total_possible <= 1024:
                    break
        # l.error("total_possible: %d, var_value_dict: %.500s" % (total_possible, str(var_value_dict)))
        ite_exprs = set()
        keys, values = zip(*var_value_dict.items())
        all_cond = [list(zip(keys, v)) for v in itertools.product(*values)]
        for cond in all_cond:
            new_expr = expr
            for var, value in cond:
                new_expr = new_expr.replace(var, value)
            ite_exprs.add(claripy.simplify(new_expr))
        ite_exprs = list(ite_exprs)
        return ite_exprs

    def replace_expr(self, expr, var, value):
        if not expr_in_list(var, list(expr.recursive_children_asts)):
            return expr
        if not self.expr_contain_if(expr):
            return expr
        if expr.op == "If" and str(expr.args[0]) == str(var):
            cond = expr.args[0]
            true_expr = expr.args[1]
            if expr_in_list(var, list(true_expr.recursive_children_asts)):
                true_expr = self.replace_expr(true_expr, var, value)
            false_expr = expr.args[2]
            if expr_in_list(var, list(false_expr.recursive_children_asts)):
                false_expr = self.replace_expr(false_expr, var, value)
            return claripy.If(value, true_expr, false_expr)
        new_args = []
        for arg in expr.args:
            if expr_in_list(var, list(arg.recursive_children_asts)):
                arg = self.replace_expr(arg, var, value)
            new_args.append(arg)
        expr.args = tuple(new_args)
        return expr

    def gen_new_ite_cond(self, expr):
        res = {}
        id = 0
        for e in expr.recursive_children_asts:
            if e.op == "If":
                var = e.args[0]
                if var not in res:
                    res[var] = claripy.BVS("new_mvar%d" % id, 8) == 0
        return res

    def get_ite_value_by_set_cond2(self, expr, var_value_dict=None):
        if var_value_dict is None:
            var_value_dict = self.gen_new_ite_cond(expr)

            for old in var_value_dict:
                expr = self.replace_expr(expr, old, var_value_dict[old])
            ite_values = self.get_ite_value_by_set_cond(expr)
            for old in var_value_dict:
                expr = self.replace_expr(expr, var_value_dict[old], old)
        return ite_values

    def clear_ite_exprs(self, ite_exprs):
        sym_exprs = set()
        rm_indexs = set()
        add_exprs = set()
        for i in range(len(ite_exprs)):
            v = ite_exprs[i]
            # we need to remove the symbolic value to avoid long expression
            if v.symbolic and 'var_' not in str(v.variables):
                sym_exprs.add(v)
                rm_indexs.add(i)
            # if v.concrete and v.args[0] == 0:
            #     # we remove 0 value
            #     sym_exprs.add(v)
            #     rm_indexs.add(i)
            if self.expr_contain_if(v):
                sym_exprs.add(v)
                rm_indexs.add(i)
                if str(v) in self.simlified_ites:
                    v_values = self.simlified_ites[str(v)]
                else:
                    v_values = self.get_ite_value_by_set_cond(v)
                    self.clear_ite_exprs(v_values)
                    self.simlified_ites[str(v)] = v_values

                for v_v in v_values:
                    add_exprs.add(v_v)


        for i in sorted(rm_indexs, reverse=True):
            ite_exprs.pop(i)
        for v in add_exprs:
            if not expr_in_list(v, ite_exprs):
                ite_exprs.append(v)
        if not ite_exprs and sym_exprs:
            ite_exprs.append(list(sym_exprs)[0])
        if len(str(ite_exprs)) > 1000:
            tmp = sorted(ite_exprs, key=lambda x: len(str(x)))
            ite_exprs.clear()
            while len(str(ite_exprs)) < 1000:
                ite_exprs.append(tmp.pop(0))



    def get_ite_exprs(self, expr):
        var_value_dict = get_ite_cond(expr)
        total_possible = self.get_ite_possible_value_num(expr, var_value_dict)
        if not self.expr_is_ite_outside(expr) or (total_possible < 64 and var_value_dict):
            ite_exprs = self.get_ite_value_by_set_cond(expr, var_value_dict, total_possible)
        else:
            is_extract = False
            ite_exprs, is_all_ite = get_ite_values(expr)
            if not is_all_ite:
                self.simplify_ite(ite_exprs)
                ite_exprs = ite_exprs.get_total_values()
            if is_extract:
                ite_exprs = [v[max:min] for v in ite_exprs]
                expr = expr[max:min]
            ite_exprs = list(set(ite_exprs))

        ite_limit = 100
        if len(ite_exprs) > ite_limit:
            # l.error("ite_exprs more than %d" % ite_limit)
            ite_exprs = ite_exprs[:ite_limit]
        try:
            any([is_tainted(v) for v in ite_exprs])
        except:
            print("error in any([is_tainted(v) for v in ite_exprs])")
            import IPython
            IPython.embed()
        if any([is_tainted(v) for v in ite_exprs]):
            # we use the longest tainted value as expr result
            byte_len = expr.size() // 8
            max_tainted_bytes = 0
            res = None
            for e in ite_exprs:
                if is_tainted(e):
                    if res is None:
                        res = e
                        continue
                    res |= e
            return [res]
        else:
            self.clear_ite_exprs(ite_exprs)
        return ite_exprs

    def simplify_ite_expr(self, expr):
        if expr.depth <= 3 or not self.expr_contain_if(expr):
            return expr
        ite_exprs = self.get_ite_exprs(expr)
        try:
            if len(ite_exprs) > 10:
                ite_exprs = ite_exprs[:10]
            expr_cons = self.create_merge_constraints(len(ite_exprs))
            expr = self.merge_expr(None, ite_exprs, expr_cons, simplify=False)
            return expr
        except Exception as e:
            l.error("Merge expr failed: %.1000s" % e)
            import traceback
            traceback.print_exc()
            exit()
    def sync_expr_size(self, exprs):
        if len(exprs) >= 2:
            max_len = max([m.length for m in exprs])
            tmp = []
            for expr in exprs:
                if expr.length == max_len:
                    tmp.append(expr)
            for expr in exprs:
                if expr.length != max_len:
                    tmp.append(claripy.Concat(tmp[0][max_len - 1:expr.length], expr))
            for i in range(len(exprs)):
                exprs[i] = tmp[i]

    def merge_expr(self, state, exprs, constraints=None, simplify=True, new_constraints=None):
        '''
        Merge expressions
        :param exprs:
        :return:
        '''
        # bit_size = exprs[0].size()
        # var = claripy.BVS(name="var{}".format(self.var_count), size=bit_size)
        # self.var_count += 1

        self.sync_expr_size(exprs)
        USE_UNION = False
        if USE_UNION:
            limit = 2
            expr_res = simplify_union(exprs[0], limit)
            for i in range(len(exprs) - 1):
                expr = simplify_union(exprs[i + 1], limit)
                expr_res = expr_res.union(expr)
            expr_res = simplify_union(expr_res, limit)
            return expr_res
        else:
            if new_constraints is None:
                new_constraints = self.create_merge_constraints(len(exprs))
            # else:
            #     simplify = False
            if len(exprs) > 1:
                expr_res = self.simplify_ite_expr(exprs[0])
            else:
                expr_res = exprs[0]
            for i in range(len(exprs) - 1):
                expr = self.simplify_ite_expr(exprs[i + 1])
                if expr.length != expr_res.length:
                    print("should not reach here!")
                    import IPython
                    IPython.embed()
                    if expr.length > expr_res.length:
                        expr_res = claripy.Concat(expr[expr.length-1:expr_res.length], expr_res)
                    else:
                        expr = claripy.Concat(expr_res[expr_res.length-1:expr.length], expr)
                expr_res = claripy.If(claripy.And(*new_constraints[i + 1]), expr, expr_res)
            if simplify:
                expr_res = self.simplify_ite_expr(expr_res)
            return expr_res

    def create_merge_constraints(self, n):
        var = claripy.BVS(name="mvar{}".format(self.var_count), size=8)
        self.var_count += 1
        constraints = [[var == i] for i in range(n)]
        return constraints

    def get_reg_size(self, start, offsets, sizes):
        size_index = len(sizes) - 1
        size = sizes[size_index]
        while size_index >= 1:
            for i in range(sizes[size_index - 1], sizes[size_index]):
                if offsets[start] + i in offsets[start:]:
                    return size
            size_index -= 1
            size = sizes[size_index]
        return size

    def reg_offsets_to_names(self, diff_reg_offsets):
        '''
        Change offsets list to the corresponding register names
        :param offsets:
        :return:
        '''

        if self.project.arch.bits == 32:
            sizes = [1, 2, 4]
        else:
            sizes = [1, 2, 4, 8]
        reg_size_names = self.project.arch.register_size_names
        names = []
        i = 0
        while i < len(diff_reg_offsets):
            size = self.get_reg_size(i, diff_reg_offsets, sizes)
            if (diff_reg_offsets[i], size) not in reg_size_names:
                # # 'cc_op' is (144, 8), but we might get (144, 1)
                reg_off = diff_reg_offsets[i]
                while reg_off not in self.project.arch.register_names:
                    reg_off -= 1
                names.append(self.project.arch.register_names[reg_off])
            else:
                names.append(reg_size_names[(diff_reg_offsets[i], size)])
            i += size
        return names

    def manual_merge(self, states, res_state, constraints, new_constraints=None):
        '''
        We assume res_state is the first element of states
        :param states:
        :param res_state:
        :param constraints: we remove state constraints according to the
        : new_constraints: we create new constraints for merging
        :return:
        '''
        diff_regs = sorted(self.get_diff_reg_mem(states, is_reg=True))
        # diff_mem = self.get_diff_reg_mem(states, is_reg=False)
        diff_mem = self.get_diff_mem_by_log(states)

        # update registers
        reg_names = self.reg_offsets_to_names(diff_regs)
        l.debug("register names: %s", reg_names)
        for name in reg_names:
            l.debug("merge register %s", name)
            if "cc" in name:
                size = res_state.registers.load(name).size()
                expr = claripy.BVV(0, size)
                res_state.registers.store(name, expr)
                continue
            l.debug("expr: %s", [s.registers.load(name) for s in states])
            reg_expr = self.merge_expr(res_state, [s.registers.load(name) for s in states], new_constraints=new_constraints)
            l.debug("merged result: %s", reg_expr)
            res_state.registers.store(name, reg_expr)

        # update memory
        for addr, size in diff_mem:
            mem_expr = self.merge_expr(res_state, [s.memory.load(addr, size, endness=res_state.arch.memory_endness) for s in states], new_constraints=new_constraints)
            res_state.memory.store(addr, mem_expr, endness=res_state.arch.memory_endness)

        # process function hash
        if MEM in res_state.globals and DEREFS in res_state.globals:
            # merge hash MEM
            mem_merge = {}
            for addr_expr in res_state.globals[MEM]:
                mem_merge[addr_expr] = [res_state.globals[MEM][addr_expr]]
            for state in states[1:]:
                try:
                    for addr_expr in state.globals[MEM]:
                        if addr_expr in mem_merge:
                            mem_merge[addr_expr].append(state.globals[MEM][addr_expr])
                        else:
                            deref = state.globals[MEM][addr_expr]
                            # try:
                            #     expr = res_state.memory.load(addr_expr,deref.size()//8, endness=res_state.arch.memory_endness)
                            #     mem_merge[addr_expr] = [deref, expr]
                            # except:
                            mem_merge[addr_expr] = [deref]
                except:
                    l.error("Error in merging MEM hash")
                    import traceback
                    traceback.print_exc()
                    import IPython
                    IPython.embed()
            for addr_expr in mem_merge:
                try:
                    res_state.globals[MEM][addr_expr] = self.merge_expr(res_state, mem_merge[addr_expr], new_constraints=new_constraints)
                except:
                    print("Error in merging MEM hash")
                    exit()


        while res_state.solver.constraints and constraints[0] and res_state.solver.constraints[-1].cache_key == constraints[0][-1].cache_key:
            res_state.solver.constraints.pop()
            constraints[0].pop()

    def gen_wait_key(self):
        self.wait_key += 1
        return 'wait_%d'%(self.wait_key)


    def limit_loop(self, states):
        # drop the states that reach loop limit
        added_jump = []
        for state in list(states):
            if state.history.addr in self.block_loop_out and state.addr in self.block_loop_out[state.history.addr]:
                # bypass the block that call no-ret function
                if state.addr in self.no_ret_blocks:
                    continue
                if state.history.addr in self.block_loop_out_ignore and state.addr in self.block_loop_out_ignore[state.history.addr]:
                    loop_limit = 1
                else:
                    loop_limit = self.loop_limit
                # a loop out jmp, we need to check the brother of the state
                remove_bro = False
                jmps = []
                for bro_state in list(states):
                    if bro_state.addr in self.no_ret_blocks:
                        # we do not regard a no-ret block as a loop count
                        continue
                    if bro_state.addr != state.addr and bro_state.history.addr == state.history.addr:
                        # check if the brother state is should be dropped
                        jmp = (bro_state.history.addr, bro_state.addr)
                        if jmp in added_jump:
                            # do not delete in one step
                            continue
                        added_jump.append(jmp)
                        jmps.append(jmp)
                        if jmp not in bro_state.globals['loop_out']:
                            bro_state.globals['loop_out'][jmp] = 1
                        else:
                            bro_state.globals['loop_out'][jmp] += 1
                        if bro_state.globals['loop_out'][jmp] > loop_limit:
                            states.remove(bro_state)
                            remove_bro = True
                if remove_bro:
                    for jmp in jmps:
                        if jmp in state.globals['loop_out']:
                            state.globals['loop_out'].pop(jmp)






    def check_merge_entry(self, simgr, stash='active'):
        '''
        Check if any state reaches a merge entry
        If so, move other states into wait stash, and there will only be one state in active stash
        '''
        # check for merge entry
        for i in range(len(simgr.stashes[stash])):
            state = simgr.stashes[stash][i]
            if state.addr in self.merge_info:
                # A state reaches a merge entry, move other states into wait stashes
                # and save update wait key and merge stack
                merge_addresses = self.merge_info[state.addr]
                wait_stash = state.globals['wait_key'][-1]
                l.info("hit merge entry: 0x%x, current wait_key: %s" % (state.addr, wait_stash))
                if merge_addresses:
                    l.info("merge addr: %s" % str([hex(x) for x in merge_addresses]))
                    self.merge_wait_stash_stack.append((str([hex(x) for x in merge_addresses]), set()))
                else:
                    l.info("merge addr: None")
                    self.merge_wait_stash_stack.append(("None:"+state.globals['wait_key'][-1], set()))
                    # The current states will exit, then we need to load the same level states from wait stash
                    # So we record the level
                    self.none_wait_key.append(state.globals['wait_key'][-1])
                state.globals['wait_key'] = state.globals['wait_key'] + [self.gen_wait_key()]
                state.globals['merge_stack'] = state.globals['merge_stack'] + [merge_addresses]
                # move the states in the same level into wait stash
                simgr.move(stash, wait_stash, lambda s: s.globals['wait_key'][-1] == wait_stash)
                l.info("move states in stash %s to stash %s" % (stash, wait_stash))
                l.info("%s: %s" % (wait_stash, simgr.stashes[wait_stash]))
                l.info("active stash: %s" % str(simgr.stashes[stash]))

                break

    def merge_states(self, simgr, stash='active'):
        cur_wait_key = None
        if not self.merge_wait_stash_stack:
            # no state to merge
            return
        for merge_waiting_stash in self.merge_wait_stash_stack.pop()[-1]:
            l.info("merge waiting stash: %s" % merge_waiting_stash)
            l.info("merge waiting stash states: %s" % str(simgr.stashes[merge_waiting_stash]))
            merge_tmp = simgr.stashes[merge_waiting_stash]
            if len(merge_tmp) == 1:
                # no need to merge
                state = merge_tmp[0]
                state.globals['wait_key'].pop()
                state.globals['merge_stack'].pop()
                cur_wait_key = state.globals['wait_key'][-1]
                simgr.move(merge_waiting_stash, stash)
                continue
            o = merge_tmp[0]
            try:
                constraints, new_constraints = self.get_merge_constraints(merge_tmp)
                # l.info("merge constraints: %s" % str(constraints))
                assert all([s.addr == o.addr for s in merge_tmp[1:]]), "merge states have different addresses: %s" % str([hex(s.addr) for s in merge_tmp])
                m = o
                if self.use_manual_merge:
                    # use manual merge to change the merged exprs
                    self.manual_merge(merge_tmp, m, constraints, new_constraints)

                # move to a higher level
                m.globals['wait_key'].pop()
                m.globals['merge_stack'].pop()
                cur_wait_key = m.globals['wait_key'][-1]
                while merge_tmp:
                    merge_tmp.pop()
                merge_tmp.append(m)
                simgr = simgr.move(merge_waiting_stash, stash)
            except Exception as e:
                import traceback
                l.error("Merge failed: %s", e)
                l.error("Error line: %s", traceback.format_exc())
                import IPython
                IPython.embed()
        if cur_wait_key:
            # After merging, we need to activate the states that have the same wait level

            # But the states at the same wait level might be already in the merge waiting stash and need to be merged again
            if self.merge_wait_stash_stack and cur_wait_key in str(self.merge_wait_stash_stack[-1][-1]) and len(simgr.stashes[cur_wait_key]) == 0:
                pass
            else:
                l.info("activate states in stash %s: %s" % (cur_wait_key, str(simgr.stashes[cur_wait_key])))
                simgr.move(cur_wait_key, stash)
        l.info("after merging, self.merge_wait_stash_stack: %s" % self.merge_wait_stash_stack[-10:])


    def check_reaching_merge_points(self, simgr, stash='active'):
        # move states into merge waiting stash
        for state in list(simgr.stashes[stash]):
            if not state.globals['merge_stack'] or not state.globals['merge_stack'][-1]:
                continue
            if state.addr in state.globals['merge_stack'][-1]:
                merge_waiting_stash = "merge_{}_0x{:x}".format(state.globals['wait_key'][-1], state.addr)
                self.merge_wait_stash_stack[-1][-1].add(merge_waiting_stash)
                simgr.stashes[stash].remove(state)
                if merge_waiting_stash not in simgr.stashes:
                    simgr.stashes[merge_waiting_stash] = []
                simgr.stashes[merge_waiting_stash].append(state)
                l.info("%s reach %s: %s" % (state, merge_waiting_stash, simgr.stashes[merge_waiting_stash]))
                l.info("state merge waiting stack: %s" % str(self.merge_wait_stash_stack[-10:]))
                if hex(state.addr) not in self.merge_wait_stash_stack[-1][0]:
                    print("merge stack: %s" % str(state.globals['merge_stack'][-1]))
                    import IPython
                    IPython.embed()


    def step(self, simgr, stash='active', **kwargs):
        '''
        We use two kinds of stashes to save states
        wait_stash: states that are at the higher level of the current level,
            they will be explored after all states at current level are explored (i.e., DFS).
        merge_wait_stash: states that will be merged in the current level once there is no active states
        '''
        # we need to force stop at the merge address
        extra_stop_points = set(kwargs.pop("extra_stop_points", []))
        extra_stop_points.update(self.stop_addr)
        if not self.merge_wait_stash_stack:
            self.check_merge_entry(simgr, stash=stash)
        l.error("before step: %s" % str(simgr.stashes[stash]))
        # perform all our analysis as a post-mortem on a given step
        simgr = simgr.step(stash=stash, extra_stop_points=extra_stop_points, **kwargs)
        # manually fork states when pc can be multiple values
        for state in list(simgr.stashes[stash]):
            if state.globals.get('jmp_targets', None) is not None:
                cons = state.globals.pop('constraints')
                pc_expr = state.globals.pop('pc_expr')
                state.solver.reload_solver(cons) # the constraints might be simplified, so we need to restore them
                for target in state.globals.pop('jmp_targets'):
                    if any([s for s in simgr.stashes[stash] if s.addr == target]):
                        continue
                    s = state.copy()
                    s.regs.pc = claripy.BVV(target, self.project.arch.bits)
                    s.solver.reload_solver(cons[:-1] + [pc_expr == target])
                    simgr.stashes[stash].append(s)
        l.error("step: %s" % str(simgr.stashes[stash]))
        for state in simgr.stashes[stash]:
            # l.error("state %s: %s" % (state, state.solver.constraints))
            state.globals['loop_out'] = copy.deepcopy(state.globals['loop_out'])
            state.globals['wait_key'] = copy.deepcopy(state.globals['wait_key'])
            state.globals['merge_stack'] = copy.deepcopy(state.globals['merge_stack'])
        while simgr.errored:
            # A state has errored, we should take the waiting states
            err = simgr.errored.pop()
            state = err.state
            l.error("state %s errored: %s" % (state, err))
            if simgr.stashes[stash]:
                # we have other states to explore, the current level is not ended
                continue
            if self.merge_wait_stash_stack and len(self.merge_wait_stash_stack[-1][-1]) == 0:
                # The merge target could not be merged, so we remove it
                self.merge_wait_stash_stack.pop()
                if len(state.globals['wait_key']) >= 2:
                    wait_key = state.globals['wait_key'][-2]
                    l.error("errored wait_key: %s" % wait_key)
                    simgr.move(wait_key, stash)
                    if self.none_wait_key:
                        self.none_wait_key.pop()
                    l.info("self.merge_wait_stash_stack[-10]: %s"%self.merge_wait_stash_stack[-10:])


        self.limit_loop(simgr.stashes[stash])

        if len(set([s.globals['wait_key'][-1] for s in simgr.stashes[stash]])) > 1:
            l.error("All states in the same level should have the same wait key: %s" % str([s.globals['wait_key'][-1] for s in simgr.stashes[stash]]))
            import IPython
            IPython.embed()

        for state in simgr.stashes[stash]:
            try:
                l.debug("state info: %s"%state)
                l.debug("wait key: %s"%state.globals['wait_key'][-10:])
                l.debug("merge stack: %s"% [[hex(x) for x in l] for l in state.globals['merge_stack'][-10:]])
                l.debug("constraint: %s"%state.solver.constraints)
            except:
                pass

        self.check_reaching_merge_points(simgr, stash=stash)
        self.check_merge_entry(simgr, stash=stash)

        # see if it's time to merge (out of active or hit the wait limit)
        if len(simgr.stashes[stash]) != 0:
            return simgr

        while self.none_wait_key:
            self.merge_wait_stash_stack.pop()
            if len(simgr.stashes[self.none_wait_key[-1]]) > 0:
                simgr.move(self.none_wait_key[-1], stash)
                self.none_wait_key.pop()
                # do not need to check reaching merge points again because before the none wait level, we have checked it
                # now we need to check merge entry again
                self.check_merge_entry(simgr, stash=stash)
                return simgr
            else:
                # the higher level states are in the merge waiting stash, just merge
                self.none_wait_key.pop()

        l.info("No active states, try to merge")
        if not self.merge_wait_stash_stack:
            return simgr

        l.info("merge wait stash stack: %s" % str(self.merge_wait_stash_stack))
        while len(simgr.stashes[stash]) == 0 and self.merge_wait_stash_stack:
            self.merge_states(simgr, stash=stash)
            # check the states reaching merge points again
            self.check_reaching_merge_points(simgr, stash=stash)
            # Now we need to check if any state reaches a merge entry again
            self.check_merge_entry(simgr, stash=stash)

        return simgr
