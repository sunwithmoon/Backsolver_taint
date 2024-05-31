arg_order = {
    'AMD64' : ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9', 'r10'],
    'MIPS32': ['a0', 'a1', 'a2', 'a3'],
    'MIPS64': ['a0', 'a1', 'a2', 'a3'],
    'ARMEL': ['r0', 'r1', 'r2', 'r3'],
    'ARMHF': ['r0', 'r1', 'r2', 'r3'],
    'AARCH64': ['x0', 'x1', 'x2', 'x3'],
    # 'X86' process stack
}
ret_reg = {
    'AMD64' :  ('rax', 64),
    'X86' :  ('eax', 32), # 'eax' is the 32-bit version of 'rax
    'MIPS32':  ('v0', 32),
    'MIPS64':  ('v0', 64),
    'ARMEL' :  ('r0', 32),
    'ARMHF' :  ('r0', 32),
    'AARCH64': ('x0', 64),

}