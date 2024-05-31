from program_analyze.ucse_utils.utils2 import Utils
from program_analyze.ucse_utils.arch import arg_order
from defines import state_copy

# Arch spec info
def ordered_argument_registers(arch):
    if arch.name in arg_order:
        return sorted(list(filter(lambda x: x.argument is True, arch.register_list)), key=lambda x:arg_order[arch.name].index(x.name))
    raise NotImplementedError

def addr_in_binary(addr, proj):
    if addr >= proj.loader.main_object.min_addr and addr <= proj.loader.main_object.max_addr:
        return True
    return False

def func_in_binary(func_addr, proj, cfg):
    if func_addr >= proj.loader.main_object.min_addr and func_addr <= proj.loader.main_object.max_addr:
        if not cfg.kb.functions[func_addr].alignment:
            return True

    return False

def is_tainted(var, taint_buf='TAINT'):

   res = [l for l in var.recursive_leaf_asts if taint_buf in str(l)]
   if res:
       return True
   return False

class CallAnalyze:
    def __init__(self, proj, cfg=None):
        self.cfg = cfg
        self.proj = proj
        self.utils = Utils(proj)

    def _push_regs(self, state):
        '''
        In x64, the first 6 arguments are passed via regsiters.
        In order to maintain a similar method to retrieve these arguments,
        we'll push the registers in the reverse order to the stack
        '''
        state.stack_push(state.regs.r9)
        state.stack_push(state.regs.r8)
        state.stack_push(state.regs.rcx)
        state.stack_push(state.regs.rdx)
        state.stack_push(state.regs.rsi)
        state.stack_push(state.regs.rdi)

    def _push_regs_other(self, state, arch_name):
        '''
        In arm, the first 6 arguments are passed via regsiters.
        In order to maintain a similar method to retrieve these arguments,
        we'll push the registers in the reverse order to the stack
        '''
        if 'ARM' in arch_name:
            state.stack_push(state.regs.r3)
            state.stack_push(state.regs.r2)
            state.stack_push(state.regs.r1)
            state.stack_push(state.regs.r0)
        elif arch_name == 'MIPS32':
            state.stack_push(state.regs.a3)
            state.stack_push(state.regs.a2)
            state.stack_push(state.regs.a1)
            state.stack_push(state.regs.a0)
        else:
            raise NotImplementedError("The arch is not realized")

    def get_sp_name(self):
        '''
        Get the stack pointer name
        '''
        return self.utils.vex_to_name(self.utils.arch.sp_offset, self.utils.arch.bytes)

    def get_sp_value(self, state):
        '''
        Get the stack pointer value
        '''
        name = self.get_sp_name()
        return getattr(state.regs, name)

    def set_ret_value(self, state, ret_value):
        '''
        Set the return value of the function
        '''
        name = self.utils.vex_to_name(self.utils.ret_reg, self.utils.arch.bytes)
        setattr(state.regs, name, ret_value)

    def get_ret_value(self, state):
        '''
        Get the return value of the function
        '''
        name = self.utils.vex_to_name(self.utils.ret_reg, self.utils.arch.bytes)
        return getattr(state.regs, name)

    def n_args(self, state, n, saved_pc=False):
        '''
        Return the first n arguments from the state
        '''
        if n == 0:
            name = self.utils.vex_to_name(self.utils.ret_reg, self.utils.arch.bytes)
            return getattr(state.regs, name)

        s = state.copy()
        state_copy(s)
        if self.proj.arch.name in ('AMD64', 'X86') or saved_pc is True:
            _ = s.stack_pop()

        if self.proj.arch.name == 'AMD64':
            self._push_regs(s)
        elif 'X86' != self.proj.arch.name:
            self._push_regs_other(s, self.proj.arch.name)

        args = []
        for x in range(n):
            args.append(s.stack_pop())

        return args

    def set_n_args(self, state, args, saved_pc=False):
        '''
        Set the first n arguments from the state
        '''
        if self.proj.arch.name == 'AMD64':
            self._push_regs(state)
        elif 'X86' != self.proj.arch.name:
            self._push_regs_other(state, self.proj.arch.name)

        if saved_pc is True:
            state.stack_pop()

        for arg in args:
            state.stack_push(arg)

    def fake_ret(self, state, use_callstack=True, ret=None):
        """
        Let the state return from the current function.
        NOTE: We suppose the state is at the function entry,
              otherwise the stack might be disrupted.
        :param: state: state to transform
                proj : project
        :return:
        """

        # Set the jumpkind
        state.history.jumpkind = "Ijk_FakeRet"

        if use_callstack:
            # Set the PC to whatever was in the link register
            state.regs.pc = state.callstack.current_return_target
            # Clean up angr's internal callstack details so everything's consistent.
            state.callstack.ret()
        else:
            if state.arch.name in ('AMD64', 'X86'):
                state.regs.pc = state.memory.load(state.regs.sp, state.arch.bits // 8, endness=state.arch.memory_endness)
            else:
                raise NotImplementedError

        # pop pc
        if state.arch.name == 'AMD64':
            state.regs.rsp += state.arch.bits // 8
        elif state.arch.name == 'X86':
            state.regs.esp += state.arch.bits // 8
        elif state.arch.name in ('ARMEL', 'ARMHF', 'ARMCortexM', 'AARCH64', 'MIPS32', 'MIPS64'):
            pass
        else:
            raise NotImplementedError

        if state.globals.get('ret_vars', False) is False:
            state.globals['ret_vars'] = []
        if ret is None:
            ret_var = state.solver.BVS('FAKERETvar_' + str(len(state.globals['ret_vars'])), state.arch.bits)
        else:
            ret_var = state.solver.BVV(ret, state.arch.bits)
        state.globals['ret_vars'].append(ret_var)
        # ret.set_value(state, ret_var)
        self.set_ret_value(state, ret_var)
        return