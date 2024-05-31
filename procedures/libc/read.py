import angr
import claripy
from cle.backends.externs.simdata.io_file import io_file_data_for_arch
from taint_tracking import apply_taint, is_tainted, is_or_points_to_tainted_data, new_tainted_value
from defines import PAGE_SIZE, APPLY_LIB_TAINT
######################################
# fread
######################################

class read(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, fd, dst, size):
        apply_lib_taint = self.state.globals.get(APPLY_LIB_TAINT, False)
        if (type(size) == int or size.concrete):
            bits = self.state.solver.eval(size * 8)
        else:
            bits = PAGE_SIZE
        if apply_lib_taint:
            var = new_tainted_value('read', bits)
        else:
            var = self.state.solver.BVS('read', bits)
        apply_taint(self.state, dst, taint_id='read', bits=bits, var=var, inspect=True)
        if apply_lib_taint:
            return self.state.solver.If(size == 0, 0, new_tainted_value("read_ret", self.state.arch.bits))
        return self.state.solver.If(size == 0, 0, claripy.BVS("read_ret", self.state.arch.bits))



