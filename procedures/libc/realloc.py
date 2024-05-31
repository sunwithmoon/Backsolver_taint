import angr
import claripy
from cle.backends.externs.simdata.io_file import io_file_data_for_arch
from taint_tracking import apply_taint, is_tainted, is_or_points_to_tainted_data, new_tainted_value
######################################
# fread
######################################

class realloc(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, addr, size):
        return addr


