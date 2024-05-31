import angr
from taint_tracking import apply_taint, is_tainted, is_or_points_to_tainted_data, new_tainted_value
from  defines import TAINT_APPLIED

######################################
# fgetc
######################################


class bypass_func(angr.SimProcedure):
    ALT_NAMES = ('fprintf', 'fputs', 'fputc','fwrite','vfprintf')
    def run(self):
        return 0

