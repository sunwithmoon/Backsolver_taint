import angr
from taint_tracking import apply_taint, is_tainted, is_or_points_to_tainted_data, new_tainted_value
from  defines import TAINT_APPLIED, APPLY_LIB_TAINT

######################################
# fgetc
######################################


class fgetc(angr.SimProcedure):
    # pylint:disable=arguments-differ
    ALT_NAMES = ('getc', 'fgetc_unlocked', 'getc_unlocked', '_IO_getc')
    def run(self, stream, simfd=None):
        if self.state.globals.get(APPLY_LIB_TAINT, False):
            self.state.globals[TAINT_APPLIED] = True
            return new_tainted_value("fgetc", 8)
        return self.state.solver.BVS("getc", 8)

