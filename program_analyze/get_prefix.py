from program_analyze.structure import Func

class GetPrefix:
    def __init__(self, block_info):
        self.func_caller = {}
        self.block_info = block_info
    def add_func_caller(self, func, caller):
        if func not in self.func_caller:
            self.func_caller[func] = Func(func)
        self.func_caller[func].caller_block.add(caller)

    def get_func_caller(self):
        '''
        get the caller function of the function
        :return:
        '''

        for block in self.block_info:
            for func in self.block_info[block].call_functions:
                self.add_func_caller(func, block)


    def get_prefix_in_func(self, target, prefix, distance):
        for block in self.block_info[target].pred:
            if block not in prefix or prefix[block] > distance:
                prefix[block] = distance
                self.get_prefix_in_func(block, prefix, distance + 1)


    def get_prefix(self, target, prefix=None, distance=0):
        if prefix is None:
            prefix = {}
        # First, find prefix blocks in the same function
        self.get_prefix_in_func(target, prefix, distance)
        # Second, find prefix blocks in the caller function rescursively
        target_func = self.block_info[target].function
        if target_func not in self.func_caller:
            return prefix
        for caller in self.func_caller[target_func].caller_block:
            if caller in prefix:
                continue
            self.get_prefix(caller, prefix)
        return prefix

