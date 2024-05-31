import signal

import claripy

from taint_tracking import *
# from dfs import *
from angr.exploration_techniques import BFS, DFS
import datetime
import pickle
import os

import sys
from functools import reduce
sys.setrecursionlimit(10000)

l = logging.getLogger("TaintLauncher")
l.setLevel(logging.ERROR)
logging.getLogger("angr.exploration_techniques.bfs").setLevel(logging.INFO)


class TimeOutException(Exception):
    def __init__(self, message):
        super(TimeOutException, self).__init__(message)


class TaintLauncher:
    """
    Provides an easy interface to run a taint tracking analysis
    """

    def __init__(self, binary_path,
                 project=None,
                 log_path='/tmp/angr_taint.out',
                 **angr_opts):
        """
        Init method: prepare the angr project.

        :param binary_path: binary path
        :param angr_opts: angr options
        """

        # timeout stuff
        self._force_exit_after = -1
        self._timer = -1

        if not angr_opts:
            angr_opts = {'auto_load_libs': False}

        self._p = project if project else angr.Project(binary_path, **angr_opts)
        self._log = open(log_path, 'w')
        self._tt = None
        self._simgr = None
        self.main_state = None
        self.init_states = {}
        self.start_state = {}
        self.ret_states = {}
        self.conds = {}

    def count_states(self, simgr):
        count = 0
        for key in simgr.stashes:
            count += len(simgr.stashes[key])
        return count

    def get_main_state(self):
        if self.main_state:
            return self.main_state
        main_addr = self._p.loader.main_object.symbols_by_name['main'].rebased_addr
        assert main_addr, "No main function found!"
        state = self._p.factory.entry_state()
        sm = self._p.factory.simulation_manager(state)
        sm.explore(find=main_addr)
        self.main_state = sm.found[0]
        self.main_state.options.add(angr.sim_options.LAZY_SOLVES)
        return self.main_state

    def create_init_state(self, addr, init_sym_reg=False, arg_num=10):
        if addr in self.init_states:
            return self.init_states[addr]

        sym_vars = []
        for x in range(arg_num):
            sym_vars.append(claripy.BVS('var_' + str(x), self._p.arch.bits))
        init_args = sym_vars.copy()
        init_state = self.get_main_state()
        # init_state.regs.pc = addr
        # self.set_arg_for_func(init_state, 0, sym_vars[0])
        if init_sym_reg:
            sym_regs = {}
            for reg in self._p.arch.register_names:
                reg_name = self._p.arch.register_names[reg]
                bypass = False
                for name in ['pc', 'lr', 'cpsr', 'cc_']:
                    if name in reg_name:
                        bypass = True
                        break
                if bypass:
                    continue
                reg = claripy.BVS(reg_name, self._p.arch.bits)
                sym_regs[reg_name] = reg
                init_state.registers.store(reg_name, reg)

        init_state = self._p.factory.call_state(addr, *sym_vars, base_state=init_state, ret_addr=0xdeadbeef)

        if self._p.arch.name == 'MIPS32':
            # the value of t9 should be current function address
            # at the entry of the function gp will add t9
            init_state.regs.t9 = addr
        init_state.globals['sym_vars'] = sym_vars
        init_state.globals['derefs'] = {}
        init_state.globals['mem'] = {}
        init_state.globals['changed_mem'] = []
        init_state.globals['args'] = init_args
        if init_sym_reg:
            init_state.globals['sym_regs'] = sym_regs

        self.init_states[addr] = init_state
        return init_state

    def run(self,
            from_entry=True,
            start_func=None,
            start_addr=None,
            init_sym_reg=False,
            arg_num=10,
            check_function=lambda x: None,
            bp_list = [],
            sym_bss=True,
            use_dfs=True,
            use_mydfs=False,
            use_merge=False,
            merge_info=None,
            func_loop=None,
            no_ret_blocks=None,
            use_manual_merge=False,
            step_num=1024,
            dfs_limit = 1,
            prioritize=False,
            prior_addr=None,
            block_succ_dict={},
            loop_out=set(),
            main_range=None,
            use_rand=True,
            loop_limit=3,
            save_states=False,
            save_return_states=False,
            apply_lib_taint=True,
            **kwargs):
        """
        Prepare the analysis instance and run the analysis

        :param start_addr: analysis starting address
        :param check_function: callback function that is called for every visited basic block
        :param sym_bss: make bss symbolic
        :param use_dfs: use a depth first seach approach
        :param kwargs
        """

        def check_read_addr(state):
            read_loc = state.inspect.mem_read_address
            read_len = state.inspect.mem_read_length
            if type(read_loc) is not int and not read_loc.concrete:
                try:
                    state.solver.eval(read_loc)
                    return
                except:
                    print("read addr unsolvable")
            return



        if save_states:
            states = {}
        if from_entry:
            start_state = self._p.factory.entry_state()
            start_state.globals['changed_mem'] = []
        else:
            start_state = self.create_init_state(start_func, init_sym_reg=init_sym_reg, arg_num=arg_num)
        if start_addr:
            simgr = self._p.factory.simgr(start_state, save_unsat=True)
            simgr.explore(find=start_addr)
            # FIXME: try del this
            if not simgr.found:
                return
            start_state = simgr.found[0]
        start_state.globals["start"] = start_addr if start_addr else start_func
        if apply_lib_taint:
            start_state.globals[APPLY_LIB_TAINT] = True
        else:
            start_state.globals[APPLY_LIB_TAINT] = False


        if sym_bss:
            self._unconstrain_bss(start_state)

        self._tt = TaintTracker(precise_argument_check=False, **kwargs)
        tt = self._tt
        self._tt.add_callback(check_function, 'irsb', angr.BP_BEFORE)
        for func, event_type, when in bp_list:
            self._tt.add_callback(func, event_type, when)
        self._simgr = self._p.factory.simgr(start_state, save_unsat=True)
        self._simgr.use_technique(self._tt)

        if use_dfs and use_merge:
            l.error("use_dfs and use_merge cannot be used together")
            exit()
        if use_dfs:
            if use_mydfs:
                from mydfs import MyDFS
                self._simgr.use_technique(MyDFS(prior_addr=prior_addr, loop_out=loop_out, limit=dfs_limit, block_succ_dict=block_succ_dict, use_random=use_rand, loop_limit=loop_limit))
            else:
                self._simgr.use_technique(DFS(prioritize=prioritize, prior_addr=prior_addr,block_succ_dict=block_succ_dict))
        if use_merge:
            from exploration_techniques import TaintMerge
            self.tm = TaintMerge(merge_info, func_loop, no_ret_blocks, use_manual_merge=True, loop_limit=loop_limit, )
            self._simgr.use_technique(self.tm)
        if save_return_states:
            self.start_state[start_func] = start_state
            self.ret_states[start_func] = []

        state = self._simgr.one_active
        self.meet_addrs = set()
        if start_addr:
            self.meet_addrs.add(start_addr)
        count = 0
        while step_num > 0:
            count += 1
            self._simgr.step(stash='active')
            if not self._simgr.active:
                break
            for state in self._simgr.active:
                if main_range and state.addr >= main_range[0] and state.addr <= main_range[1]:
                    self.meet_addrs.add(state.addr)
                if save_states:
                    states[state.addr] = state
                if save_return_states and state.addr == 0xdeadbeef:
                    self.ret_states[start_func].append(state.copy())
            step_num -= 1
        self.ret_states[start_func] += tt.ret_states
        return self.meet_addrs


    def stop(self):
        l.info("Stopping the analysis")
        self._tt.stop()

    def _handler(self, signum, frame):
        """
        Timeout handler

        :param signum: signal number
        :param frame:  frame
        :return:
        """

        log.info("Timeout triggered, %s left...." % str(self._force_exit_after))
        self.stop()
        self._force_exit_after -= 1
        self.set_timeout(self._timer, self._force_exit_after)
        if self._force_exit_after <= 0:
            # time to stop this non-sense!
            raise TimeOutException("Hard timeout triggered")

    def set_timeout(self, timer, n_tries=0):
        # setup a consistent initial state
        signal.signal(signal.SIGALRM, self._handler)
        signal.alarm(timer)
        self._force_exit_after = n_tries
        self._timer = timer

    def _unconstrain_bss(self, state):
        bss = [s for s in self._p.loader.main_object.sections if s.name == '.bss']
        if not bss:
            return

        bss = bss[0]
        min_addr = bss.min_addr

        max_addr = bss.max_addr

        for a in range(min_addr, max_addr + 1):
            var = get_sym_val(name="bss_", bits=8)
            state.memory.store(a, var)

    def start_logging(self):
        self._log.write("Starts: \n" + str(datetime.datetime.now().time()) + "=================================\n\n")

    def log(self, msg):
        self._log.write(msg)

    def stop_logging(self):
        self._log.write("Ends: \n" + str(datetime.datetime.now().time()) + "=================================\n\n")
        self._log.close()
