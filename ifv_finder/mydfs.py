from angr.exploration_techniques import ExplorationTechnique
import random
import logging
import angr
import copy
l = logging.getLogger(name=__name__)


def crc(prev, cur):
    prev = (prev >> 4) ^ (prev << 8)
    prev &= 65535
    prev = prev >> 1

    cur = (cur >> 4) ^ (cur << 8)
    cur &= 65535
    return cur ^ prev

class MyDFS(ExplorationTechnique):
    """
    Board-first search, but we add some factors to choose execution paths.

    We will consider:
        1. If the block is in the prior_addr, the weight will be high;
        2. If the hit count of a block is small, the weight will be high;
        3. If the successor block number is big, the weight will be high;


    Will only keep one path active at a time, any others will be stashed in the 'deferred' stash.
    When we run out of active paths to step, we take one from deferred and continue.
    """

    def __init__(self, deferred_stash='deferred', prior_addr=None, limit=1, loop_out=set(), block_succ_dict={}, use_random=True, loop_limit=3):
        '''

        :param deferred_stash:
        :param prioritize:  Note! if you set this True,
                            it will take a less executed block,
                            and it's not depth-first!
        :param limit:  max number of active states
        :param loop_out:
        :param block_succ_dict:  The more succ blocks one block has, less value it will be
        '''
        super(MyDFS, self).__init__()
        self._use_random = use_random
        self._random = random.Random()
        self._random.seed(10)
        self.deferred_stash = deferred_stash
        self.prior_addr = prior_addr if prior_addr is not None else {}
        self.limit = limit
        self.loop_out = loop_out
        self.meet_count = {}
        self.block_succ_dict = block_succ_dict
        self.init = True
        self.loop_limit = loop_limit



    def get_bitmap(self, index):
        if index not in self.bitmap:
            self.bitmap[index] = 0
        return self.bitmap[index]





    def update_weight(self, state):
        '''
        update the weight of the state
        :param state:
        :return:
        '''
        state.globals['weight'] = 0
        if state.globals.get('drop', False):
            state.globals['weight'] = -1
            if self._use_random:
                state.globals['weight'] += self._random.random()/10
            state.globals['drop'] = False
            return

        if state.addr not in self.meet_count:
            # 1.0~ 1.1
            # add 0.5 to cover prior_addr
            state.globals['weight'] += 1
            if self._use_random:
                state.globals['weight'] += self._random.random()/10
        else:
            # 0.63 ~1
            if self.meet_count[state.addr] <= 10:
                state.globals['weight'] += 1/(2.7**self.meet_count[state.addr]) - 0.37 + 1.0
            else:
                state.globals['weight'] += - 0.37 + 1.0
        if state.addr in self.block_succ_dict:
            # The more succ blocks one block has, less value it will be
            # 0 ~ 1
            state.globals['weight'] += 1 - self.block_succ_dict[state.addr]
        state.globals['weight'] += 1
        if state.addr in self.prior_addr:
            state.globals['weight'] += 1.5 + 1/(self.prior_addr[state.addr] + 2)
        if state.globals.get('already_read', False):
            state.globals['weight'] += 2







    def state_split(self, state_list):
        '''
        split the state_list to several parts
        :param state_list:
        :param use_length: if use_length is True, it will split the state_list by the history length of the state_list
        :return:
        '''

        res = {}
        for state in state_list:
            key = hash(str(state.history.bbl_addrs.hardcopy))
            if key not in res:
                res[key] = [state]
            else:
                res[key].append(state)

        return [res[key] for key in res]

    def get_function_addr(self, state):
        '''
        get the function addr of the state
        :param state:
        :return:
        '''
        return state.callstack.func_addr if state.callstack.func_addr else self.top_function

    def update_missed_dict(self, state_list):
        '''
        update the missed dict
        :param state_list:
        :return:
        '''
        if len(state_list) < 2:
            return
        splited_states = self.state_split(state_list)
        for branch_states in splited_states:
            if len(branch_states) > 2: # maybe switch
                print("multiple branches: %r"% branch_states)
                continue
            if len(branch_states) != 2:
                continue
            s1 = branch_states[0]
            s2 = branch_states[1]


            missed_dict = s1.globals['missed_dict'][hex(self.get_function_addr(s1))]
            s2.globals['missed_dict'] = copy.deepcopy(s2.globals['missed_dict'])
            if s1.addr not in missed_dict:
                missed_dict[s1.addr] = 1
            else:
                missed_dict[s1.addr] += 1
                if missed_dict[s1.addr] == self.loop_limit:
                    s1.globals['drop'] = True
                    missed_dict[s1.addr] = 0
            missed_dict = s2.globals['missed_dict'][hex(self.get_function_addr(s2))]
            if s2.addr not in missed_dict:
                missed_dict[s2.addr] = 1
            else:
                missed_dict[s2.addr] += 1
                if missed_dict[s2.addr] == self.loop_limit:
                    s2.globals['drop'] = True
                    missed_dict[s2.addr] = 0


    def set_bp(self, s):
        def func_return(s):
            s.globals['missed_dict'][hex(self.get_function_addr(s))] = {}
        def into_func(s):
            if hex(self.get_function_addr(s)) not in s.globals['missed_dict']:
                s.globals['missed_dict'][hex(self.get_function_addr(s))] = {}


        s.inspect.b('call', angr.BP_AFTER, action=into_func)
        s.inspect.b('return', angr.BP_BEFORE, action=func_return)

    def check_addr_in_block(self, block, addr):
        for ins in self.project.factory.block(block).capstone.insns:
            if ins.address == addr:
                return True
        return False

    def step(self, simgr, stash='active', **kwargs):
        if self.init:
            self.top_function = simgr.stashes[stash][0].addr
            for s in simgr.stashes[stash]:
                s.globals['missed_dict'] = {hex(s.addr):{}} # main func
                self.set_bp(s)
            self.init = False
        simgr = simgr.step(stash=stash, **kwargs)
        self.update_missed_dict(simgr.stashes[stash])

        if len(simgr.stashes[stash]) == 2:
            s1 = simgr.stashes[stash][0]
            s2 = simgr.stashes[stash][1]
            if self.check_addr_in_block(s1.addr, s2.addr):
                s2.globals['drop'] = True
            elif self.check_addr_in_block(s2.addr, s1.addr):
                s1.globals['drop'] = True

        for state in list(simgr.stashes[stash]):
            if state.globals.get('drop', False):
                simgr.stashes[stash].remove(state)

        for state in simgr.stashes[stash]:
            self.update_weight(state)
        for state in list(simgr.stashes[stash]):
            if state.globals.get('drop', False):
                simgr.stashes[stash].remove(state)

        if len(simgr.stashes[stash]) > self.limit:
            simgr.stashes[stash].sort(key=lambda s: s.globals['weight'], reverse=True)
            # self.bitmap[crc(simgr.stashes[stash][0].history.addr, simgr.stashes[stash][0].addr)] += 1
            simgr.split(from_stash=stash, to_stash=self.deferred_stash, limit=self.limit)
            # if simgr.stashes[stash][0].addr not in self.prior_addr and self.over:
            #     self.limit += self.limit_step
            #     self.over = False
        for state in simgr.stashes[stash]:
            if state.addr not in self.meet_count:
                self.meet_count[state.addr] = 0
            self.meet_count[state.addr] += 1


        if len(simgr.stashes[stash]) == 0:
            if len(simgr.stashes[self.deferred_stash]) == 0:
                l.warning("dfs stack no left state!")
                return simgr
            l.info('DFS switch\n')
            simgr.stashes[self.deferred_stash].sort(key=lambda s: s.globals['weight'])
            simgr.split(from_stash=self.deferred_stash, to_stash=stash, limit=len(simgr.stashes[self.deferred_stash]) - self.limit)
            # if len(simgr.stashes[self.deferred_stash]) > 100:
            #     for i in range(len(simgr.stashes[self.deferred_stash]) - 100):
            #         s = simgr.stashes[self.deferred_stash].pop(-1)
            #         del s
            #     simgr.stashes[self.deferred_stash] = simgr.stashes[self.deferred_stash][:100]
            # s = simgr.stashes[self.deferred_stash][0]
            # self.bitmap[crc(s.history.addr, s.addr)] += 1
            # simgr.stashes[stash].append(simgr.stashes[self.deferred_stash].pop())

        return simgr
