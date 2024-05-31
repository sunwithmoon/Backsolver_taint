import angr
class read(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, file_ptr, dst, size):
        data = self.state.solver.BVS('posix0', self.state.solver.eval(size) * 8)
        self.state.memory.store(dst, data)

        return size