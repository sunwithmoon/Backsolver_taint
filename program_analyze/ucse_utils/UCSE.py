import angr
import claripy
from .arch import arg_order, ret_reg
from .force_explore import Force
from .utils import CallAnalyze
import logging
from angr.exploration_techniques import DFS
from func_timeout import func_timeout, FunctionTimedOut, func_set_timeout

l=logging.getLogger(__name__)
meet = set()
class UCSE:
    def __init__(self, proj, cfg=None):
        '''

        :param proj:
        :param cfg:
        :param func_max_level:
        :param only_into_lib: when call functions, only step library functions, otherwise fake return
        '''
        self.proj = proj
        self.cfg = cfg if cfg else self.proj.analyses.CFGFast()

        self.init_states = {}
        self.main_state = None
        self.call_analyze = CallAnalyze(self.proj, self.cfg)

    def _set_up_bp(self, state):
        # state.inspect.b('mem_read', when=angr.BP_AFTER,
        #                 action=self._mem_read_hook)
        state.inspect.b('mem_read', when=angr.BP_AFTER,
                        action=self._mem_read_hook2)
        state.inspect.b('mem_write', when=angr.BP_BEFORE,
                        action=self._mem_write_hook)
        state.globals["call_level"] = 0
        state.inspect.b('call', when=angr.BP_AFTER,
                        action=self._call_hook)
        state.inspect.b('return', when=angr.BP_AFTER,
                        action=self._return)

        return state

    def _find_in_list(self, child, sym_vars):
        for x in sym_vars:
            if child.length != x.length:
                continue
            elif not isinstance(child, type(x)):
                continue
            result = child == x
            if result.is_true():
                return True

        return False

    def _find_child_in_list(self, ast, vars):
        # try:
        for child in list(set(ast.recursive_leaf_asts)):
            if self._find_in_list(child, vars):
                return True
        # except claripy.ClaripyOperationError:
        #     # Could not iterate over leaf ast's
        #     #TODO how to handle this ?
        #     return False

        if self._find_in_list(ast, vars):
            return True

        return False

    def _get_child_from_list(self, ast, sym_vars):
        for child in list(set(ast.recursive_leaf_asts)):
            if self._find_in_list(child, sym_vars):
                return child

        if self._find_in_list(ast, sym_vars):
            return ast

    def _find_bit_in_ast(self, bit, ast):
        for idx in range(0, ast.length):
            result = ast[idx] == bit
            if result.is_true():
                return idx

        return None

    def _mem_write_hook(self, state):
        try:
            if not state.solver.satisfiable():
                state.solver._stored_solver.constraints = []
                state.solver.reload_solver()
            expr = state.inspect.mem_write_address

            if type(expr) == int:
                return
            if expr.concrete:
                return
            expr = claripy.simplify(expr)
            if self._find_in_list(expr, state.globals['sym_vars']) is False:
                return
            state.globals['derefs'][expr] = state.inspect.mem_write_expr
            state.inspect.mem_condition = claripy.BoolV(False)

        except Exception as e:
            print(state, "in write hook", e)
            # exit()


    def _mem_read_hook(self, state):
        try:
            expr = state.inspect.mem_read_address
            val = state.inspect.mem_read_expr

            # Don't need to worry if this address is
            # 1) An address in the BSS
            # 2) Not dependent on the arguments
            # 3) Already dereferenced before
            if type(expr) == int:
                return

            if self._find_child_in_list(expr, state.globals['sym_vars']) is False:
                return

            flag1 = self._find_in_list(expr, state.globals['derefs'])
            flag2 = self._find_child_in_list(val, state.globals['sym_vars'])

            if flag1 and flag2:
                return

            if state.globals.get('no_create', False) is True:
                state.globals['sym_vars'].append(val)
                state.globals['derefs'].append(expr)
                return

            sym_var = claripy.BVS('df_var', state.inspect.mem_read_length*8)
            state.globals['derefs'].append(expr)
            state.globals['sym_vars'].append(sym_var)
            state.memory.store(expr, sym_var, endness=angr.archinfo.Endness.LE)
            state.inspect.mem_read_expr = sym_var
        except Exception as e:
            print(state, 'in read hook', e)
            exit()

    def _mem_read_hook2(self, state):
        try:
            expr = state.inspect.mem_read_address
            val = state.inspect.mem_read_expr
            expr = claripy.simplify(expr)

            # Don't need to worry if this address is
            # 1) An address in the BSS
            # 2) Not dependent on the arguments
            # 3) Already dereferenced before
            if type(expr) == int:
                return

            if self._find_child_in_list(expr, state.globals['sym_vars']) is False:
                return

            if "mem" not in str(val):
                # read success
                return

            flag1 = self._find_in_list(expr, state.globals['derefs'])
            # flag2 = self._find_child_in_list(val, state.globals['sym_vars'])

            if flag1:
                state.inspect.mem_read_expr = state.globals['derefs'][expr]
                return
            sym_var = claripy.BVS('df_var', state.inspect.mem_read_length * 8)
            state.globals['derefs'][expr] = sym_var
            state.globals['sym_vars'].append(sym_var)
            # state.memory.store(expr, sym_var, endness=angr.archinfo.Endness.LE)
            state.inspect.mem_read_expr = sym_var
        except Exception as e:
            print(state, 'in after read hook:', e)
            exit()

    def _call_hook(self, state):
        if self._only_into_lib:
            if state.addr >= self.proj.loader.main_object.min_addr and \
                    state.addr <= self.proj.loader.main_object.max_addr:
                self.call_analyze.fake_ret(state)
                return
        if state.globals["call_level"] < self._func_max_level:
            state.globals["call_level"] += 1
            return

        self.call_analyze.fake_ret(state)

    def _return(self, state):
        state.globals["call_level"] -= 1


    def get_main_state(self):
        if self.main_state:
            return self.main_state
        main_addr = self.proj.loader.main_object.symbols_by_name['main'].rebased_addr
        assert main_addr, "No main function found!"
        state = self.proj.factory.entry_state()
        sm = self.proj.factory.simulation_manager(state)
        sm.explore(find=main_addr)
        self.main_state = sm.found[0]
        self.main_state.options.add(angr.sim_options.LAZY_SOLVES)
        return self.main_state



    def create_init_state(self, addr, init_sym_reg=False, arg_num=10, set_bp=True):
        if addr in self.init_states:
            return self.init_states[addr]

        sym_vars = []
        for x in range(arg_num):
            sym_vars.append(claripy.BVS('var_' + str(x), self.proj.arch.bits))
        self._init_args = sym_vars.copy()
        init_state = self.get_main_state()
        # init_state.regs.pc = addr
        # self.set_arg_for_func(init_state, 0, sym_vars[0])
        if init_sym_reg:
            for reg in self.proj.arch.register_names:
                reg_name = self.proj.arch.register_names[reg]
                bypass = False
                for name in ['pc', 'lr', 'cpsr', 'sp', 'bp']:
                    if name in reg_name:
                        bypass = True
                        break
                if bypass:
                    continue
                init_state.registers.store(reg_name, claripy.BVS(reg_name, self.proj.arch.bits))

        init_state = self.proj.factory.call_state(addr, *sym_vars, base_state=init_state)
        if self.proj.arch.name == 'MIPS32':
            # the value of t9 should be current function address
            # at the entry of the function gp will add t9
            init_state.regs.t9 = addr
        init_state.globals['sym_vars'] = sym_vars
        init_state.globals['derefs'] = {}
        if set_bp:
            self._set_up_bp(init_state)
        def print_ip(state):
            global meet
            if state.addr not in meet:
                print(state)
                meet.add(state.addr)
        # init_state.inspect.b('statement', when=angr.BP_BEFORE, action=print_ip)
        self.init_states[addr] = init_state
        return init_state

    @property
    def init_args(self):
        return self._init_args

    def update_stack_mem_range(self, state):
        sp_name = self.proj.arch.register_size_names[(self.proj.arch.sp_offset, self.proj.arch.bits // 8)]
        sp = getattr(state.regs, sp_name, None)
        if sp is None:
            raise Exception("No stack pointer found {} at {}".format(sp_name, state))
        if sp.symbolic:
            raise Exception("Symbolic stack pointer at {}".format(state))
        sp = state.solver.eval(sp)
        min_mask = 0xf << (sp.bit_length()//4 * 4)
        max_mask = (1 << (sp.bit_length()//4 * 4)) - 1
        self.stack_min = sp & min_mask
        self.stack_max = sp | max_mask

    # @func_set_timeout(180)
    def UCSE_explore(self, start, end, cfg_fast=None, init_state=None, init_args=None, init_sym_reg=False, func_max_level=0, only_into_lib=False, force_explore=False, add_techs=None, **kwargs):
        '''
        start from the entry of the function,
        try to reach every address in end.

        :param start:
        :param end:
        :param init_sym_reg: set all general registers to symbolic values
        :return:
        '''
        self._func_max_level = func_max_level
        self._only_into_lib = only_into_lib
        if type(end) == int:
            end = [end]
        else:
            end = end.copy()
        if init_state is None:
            init_state = self.create_init_state(start, init_sym_reg=init_sym_reg, **kwargs)
            if not init_sym_reg:
                self.update_stack_mem_range(init_state)
        else:
            self._init_args = init_args

        sm = self.proj.factory.simulation_manager(init_state, save_unsat=True)
        if force_explore:
            sm.use_technique(Force())
        if add_techs:
            for tech in add_techs:
                sm.use_technique(tech)
        # sm.use_technique(DFS())

        res = []
        while end:
            if not sm.active:
                l.error("No active state found! 0x{:x} -> {}".format(start, [hex(x) for x in end]))
                return res
            sm.explore(find=end, num_find=len(end))
            active_ids = [id(s) for s in sm.active]
            active_addrs = [s.addr for s in sm.active]
            # TODO: choose a good state

            for s in sm.found:
                if s.addr in end:
                    if s.addr not in active_addrs or id(s) not in active_ids:
                        sm.active.append(s)
                    end.remove(s.addr)
                    res.append(s)
            sm.found.clear()
        return res

    def UCSE_step(self, start=None, init_state=None, func_max_level=0, only_into_lib=False,
                     force_explore=False, step_num=1, **kwargs):
        '''
        start from the entry of the function,
        try to reach every address in end.

        :param start:
        :param end:
        :return:
        '''
        self._func_max_level = func_max_level
        self._only_into_lib = only_into_lib

        if init_state is None:
            init_state = self.create_init_state(start, **kwargs)
            self.update_stack_mem_range(init_state)

        sm = self.proj.factory.simulation_manager(init_state, save_unsat=True)
        if force_explore:
            sm.use_technique(Force())
        # sm.use_technique(DFS())

        res = []
        while sm.active and step_num > 0:
            print("UCSE step:", sm.active)
            sm.step()
            step_num -= 1
        return sm.active
