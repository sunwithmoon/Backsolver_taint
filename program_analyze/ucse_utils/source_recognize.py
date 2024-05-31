
from .UCSE import UCSE
from .utils import addr_in_binary,  func_in_binary, CallAnalyze, is_tainted
from .get_func_arg import get_arg_by_callsites
from tqdm import tqdm
import random
import logging
import pickle
import os
import string
import angr
l = logging.getLogger(__name__)
logging.getLogger('angr').setLevel(logging.ERROR)
MODEL_1 = 1
MODEL_2 = 2
MODEL_3 = 4
MODEL_4 = 8
FUNC_MAX = 10240
class SourceRecognize(object):
    def __init__(self, proj, cfg=None, cfg_fast=None,res_path="arg_type_info.pk"):
        self.proj = proj
        self.cfg = cfg if cfg else self.proj.analyses.CFGFast()
        self.cfg_fast = cfg_fast if cfg_fast else self.proj.analyses.CFGFast()
        self._random = random.Random()
        self._random.seed(0)

        self.call_analyze = CallAnalyze(self.proj, self.cfg)
        self.ucse = UCSE(self.proj, self.cfg)
        self.res_path = res_path
        filter_funcs = self.filter_freq_callee(num=FUNC_MAX)
        self.func_info = {}
        '''
        {
            func_name: arg_num
        }
        '''
        for func_name, addr, _ in filter_funcs:
            self.func_info[addr] = self.get_func_arg_num(addr)
        # 0 means not step into functions and fake return
    def get_call_state_args(self, state):
        '''
        get the args of a call state
        :param state:
        :return: a list of args
        '''
        func_addr = state.addr
        if func_addr in self.func_info:
            arg_num = self.func_info[func_addr]
            if arg_num == 0:
                return []
        else:
            return []

        args = self.call_analyze.n_args(state, arg_num)
        return args




    def get_func_callsites(self, func, targets=None):
        '''
        get the callsites in the function,
        the callees are in the targets
        :param func:
        :param targets: targets could be [func_name] or [func_addr]
                        if targets is None, return all callsites
        :return:
        '''
        if type(targets) in (str, int):
            targets = [targets]
        res = []
        for callsite, callee, callee_name in self.caller_info[func]:
            if not targets:
                res.append(callsite)
                continue
            if callee_name in targets or callee in targets:
                res.append(callsite)
        return res



    def get_func_arg_num(self, callee):
        '''
        get the args of a function
        :param func_name: function name
        :param func_addr: function address
        :return:          a list of args
        '''
        callee_func = self.cfg.kb.functions[callee]
        cc = self.proj.analyses.CallingConvention(callee_func, analyze_callsites=True).cc
        if not cc or not cc.args:
            callsites = list(map(lambda x: x[0], self.callee_info[callee]['callsite']))
            # TODO: add when the function has no callsites, analyze the function internal. Maybe not necessary?
            callsites.sort(key=lambda a: self._random.random())
            sim_args, ret = get_arg_by_callsites(self.proj, callsites[:10], strategy="most")
            arg_num = len(sim_args)
        else:
            arg_num = len(cc.args)
        return arg_num




    def filter_freq_callee(self, num=20):
        '''
        get the functions that are frequently called
        :param proj: angr project
        :param num:  the number of most called functions
        :return:     [(name, addr ,call count)]
        '''

        cfg_func = self.cfg.kb.functions
        self.callee_info = {}
        '''
        {
            callee_addr: {
                'name': name,
                'callsite': [(callsite1, caller), (callsite2, caller), ...]
            }
        }
        'callsite_n' is the block addr of the callsite, rather than the call instruction address   
        '''
        self.caller_info = {}
        '''
        {
            caller_func: [(callsite1, callee, callee_name), (callsite2, callee, callee_name), ...]
        }
        '''
        self.name2addr = {}
        for func_addr in cfg_func:
            if func_addr < self.proj.loader.main_object.min_addr or func_addr > self.proj.loader.main_object.max_addr:
                continue
            if cfg_func[func_addr].alignment:
                continue
            func = self.cfg.kb.functions[func_addr]
            self.caller_info[func_addr] = []
            for site in func.get_call_sites():
                callee = func.get_call_target(site)  # addr
                target = self.cfg.functions.function(callee)
                name = target.demangled_name
                if name == 'UnresolvableCallTarget':
                    continue
                if name not in self.name2addr:
                    self.name2addr[name] = callee
                if callee not in self.callee_info:
                    self.callee_info[callee] = {
                        'name': name,
                        'callsite': []
                    }
                self.callee_info[callee]['callsite'].append((site, func_addr))
                self.caller_info[func_addr].append((site, callee, name))
        callees = list(map(lambda a: (self.callee_info[a]['name'], a, len(self.callee_info[a]['callsite'])), self.callee_info))
        for callee_info in list(callees):
            callee = callee_info[1]
            if callee < self.proj.loader.main_object.min_addr or callee > self.proj.loader.main_object.max_addr:
                # do not check lib functions
                callees.remove(callee_info)
        callees.sort(key=lambda a: a[2], reverse=True)
        l.info("all callees:\n%r", callees)

        return callees[:num]

    def get_prev_block(self, pred, node, distance=1):

        prev_blocks = [set([node])]
        while distance > 0:
            for new_node in prev_blocks.pop():
                for pre_node in pred[new_node]:
                    if pred[node][pre_node]['type'] not in ('transition', 'fake_return'):
                        continue
                    if not prev_blocks:
                        prev_blocks.append(set())
                    prev_blocks[-1].add(pre_node)
            distance -= 1
        return prev_blocks[0]

    def save_data(self):
        with open(self.res_path, 'wb') as f:
            pickle.dump(self.arg_type_info, f)
    def load_data(self):
        if os.path.exists(self.res_path):
            with open(self.res_path, 'rb') as f:
                self.arg_type_info = pickle.load(f)
        else:
            self.arg_type_info = {}







