import angr
import logging
from taint_tracking import apply_taint, is_tainted, is_or_points_to_tainted_data, new_tainted_value
from defines import PAGE_SIZE

l = logging.getLogger(name=__name__)

class memcpy(angr.SimProcedure):
    #pylint:disable=arguments-differ
    ALT_NAMES = ('memmove',)
    def run(self, dst_addr, src_addr, limit):
        if not self.state.solver.symbolic(limit):
            # not symbolic so we just take the value
            conditional_size = self.state.solver.eval(limit)
        else:
            if is_tainted(limit, self.state):
                conditional_size = PAGE_SIZE
            else:
                # constraints on the limit are added during the store
                max_memcpy_size = self.state.libc.max_memcpy_size
                max_limit = self.state.solver.eval(limit)
                # min_limit = self.state.solver.min_int(limit)
                conditional_size = min(max_memcpy_size, max_limit)
                if max_limit > max_memcpy_size and conditional_size < max_limit:
                    l.warning("memcpy upper bound of %#x outside limit, limiting to %#x instead",
                              max_limit, conditional_size)
                    conditional_size = 0x100
                if conditional_size <= 0:
                    conditional_size = 0x100

        l.debug("Memcpy running with conditional_size %#x", conditional_size)

        if conditional_size > self.state.libc.max_memcpy_size:
            conditional_size = 0x100
        if conditional_size > 0:
            src_mem = self.state.memory.load(src_addr, conditional_size, endness='Iend_BE')
            if ABSTRACT_MEMORY not in self.state.options:
                self.state.memory.store(dst_addr, src_mem, size=conditional_size, endness='Iend_BE')
            else:
                self.state.memory.store(dst_addr, src_mem, size=limit, endness='Iend_BE')


        return dst_addr

from angr.sim_options import ABSTRACT_MEMORY
