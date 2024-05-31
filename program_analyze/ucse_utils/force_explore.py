from angr.exploration_techniques import ExplorationTechnique
import random
import logging
import angr
import copy
l = logging.getLogger(name=__name__)



class Force(ExplorationTechnique):


    def __init__(self):

        super(Force, self).__init__()
        self.addr_count = {}

    def _drop_constraints(self, state):
        state.solver._stored_solver.constraints = []
        state.solver.reload_solver()
        return

    def step(self, simgr, stash='active', **kwargs):

        # print(simgr.active)
        simgr = simgr.step(stash=stash, **kwargs)
        if len(simgr.unsat) > 0:
            for state in simgr.unsat:
                self._drop_constraints(state)
            simgr.move(from_stash='unsat', to_stash='active')
        for s in simgr.active:
            if s.addr in self.addr_count:
                self.addr_count[s.addr] += 1
            else:
                self.addr_count[s.addr] = 1
            if self.addr_count[s.addr] > 3:
                simgr.stashes[stash].remove(s)


        return simgr
