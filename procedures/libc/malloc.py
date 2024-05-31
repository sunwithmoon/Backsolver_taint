import angr
import itertools

######################################
# malloc
######################################

malloc_mem_counter = itertools.count()
alloc_size = 0
class malloc(angr.SimProcedure):
    #pylint:disable=arguments-differ
    def run(self, sim_size):
        global alloc_size
        if alloc_size == 0:
            alloc_size = self.state.heap.heap_location - self.state.heap.heap_base
        self.state.heap.heap_location = self.state.heap.heap_base + alloc_size
        old = self.state.heap.heap_location
        addr = self.state.heap._malloc(sim_size)
        new = self.state.heap.heap_location
        alloc_size += new - old
        return addr
