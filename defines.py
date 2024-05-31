#
# Defined constants
#
import copy
import claripy
import archinfo

# Taint/Untaint
TAINT_BUF = "taint_buf"
PAGE_SIZE = 4096  # 1 page
BOGUS_RETURN = 0x41414141
BOGUS_RETURN_64 = 0x4141414141414141
GLOB_TAINT_DEP_KEY = 'taint_deps'
UNTAINT_DATA = 'untainted_data'
UNTAINTED_VARS = 'untainted_vars'

# Taint dependency
SEEN_MASTERS = 'seen_masters'
CURRENT_IFL = 'current_ifl'
TAINT_APPLIED = 'taint_applied'

# Loops
BACK_JUMPS = 'back_jumps'
APPLY_LIB_TAINT = 'apply_lib_taint'

# func hash
MEM = 'mem'
DEREFS = 'derefs'
SYM_WRITE_ADDR = 0
SYM_READ_SAVE_ADDR = 8
SYM_READ_ADDR = 42

# Flags
FLAGS = 'flags'
IL = 'interfunction_level'
SC = 'smart_call'
PAC = 'precise_argument_check'
FU = 'follow_unsat'
NFC = 'not_follow_any_calls'
TR = 'taint_returns_from_unfollowed_calls'
TA = 'taint_arguments_from_unfollowed_call'
AU = 'allow_untaint'
SCC = 'use_smart_concretization'

arg_order = {
    'AMD64' : ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9', 'r10'],
    # 'X86' process stack
}
# Arch spec info
def ordered_argument_registers(arch):
    if arch.name in arg_order:
        return sorted(list(filter(lambda x: x.argument is True, arch.register_list)), key=lambda x:arg_order[arch.name].index(x.name))
    raise NotImplementedError

# HACK: FIXME: This works, but this is an accident
def return_register(arch):
    if arch.name in ('AMD64', 'X86'):
        return arch.register_list[0]
    raise NotImplementedError

def state_copy(state):
    state.globals[BACK_JUMPS] = copy.deepcopy(state.globals[BACK_JUMPS])
    state.globals[GLOB_TAINT_DEP_KEY] = copy.deepcopy(state.globals[GLOB_TAINT_DEP_KEY])
    state.globals[UNTAINT_DATA] = copy.deepcopy(state.globals[UNTAINT_DATA])
    if MEM in state.globals:
        state.globals[MEM] = copy.deepcopy(state.globals[MEM])
    if "changed_mem" in state.globals:
        state.globals["changed_mem"] = copy.deepcopy(state.globals["changed_mem"])