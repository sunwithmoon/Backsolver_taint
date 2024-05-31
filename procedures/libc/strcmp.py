import angr
import logging
from taint_tracking import apply_taint, is_tainted, is_or_points_to_tainted_data, new_tainted_value
from defines import PAGE_SIZE

l = logging.getLogger(name=__name__)

class strcmp(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, dst_addr, src_addr):
        if is_or_points_to_tainted_data(dst_addr, self.state) or is_or_points_to_tainted_data(src_addr, self.state):
            return new_tainted_value("strcmp", self.state.arch.bits)
        return 0

from angr.sim_options import ABSTRACT_MEMORY
