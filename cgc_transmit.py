import angr

class cgc_transmit(angr.SimProcedure):
    #pylint:disable=arguments-differ,attribute-defined-outside-init,redefined-outer-name

    def run(self, fd, buf, count, tx_bytes):
        self.state.memory.store(tx_bytes, count, endness='Iend_LE')
        return 0