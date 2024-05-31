import angr
from taint_tracking import apply_taint, is_tainted, is_or_points_to_tainted_data, new_tainted_value
from  defines import TAINT_APPLIED

######################################
# fgetc
######################################


class printf(angr.SimProcedure):
    ALT_NAMES = ('__fprintf_chk', '__vfprintf_chk', '__printf_chk',)
    def run(self):
        return 0

