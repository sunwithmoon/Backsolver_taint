import angr
from angr.sim_options import refs
from collections import defaultdict
import logging
from . import GetBlocks, GetLoops

l = logging.getLogger(__name__)
class GetMergeInfo:
    def __init__(self, binary, cfg=None, project=None, gb=None, gl=None):
        self.p = project if project else angr.Project(binary, load_options={'auto_load_libs': False})
        self.cfg = cfg if cfg else self.p.analyses.CFGFast(normalize=True)
        if gb:
            self._gb = gb
        else:
            self._gb = GetBlocks(binary, cfg)
            self._gb.get_blocks()
        if gl:
            self._gl = gl
        else:
            self._gl = GetLoops(binary, cfg)
            self._gl.get_loops()

        self.loops = self._gl.format_loops
        self.blocks = self._gb.blocks
        self.funcs = self._gb.funcs
        self._post_idom_re = {}
        self.RET = -1


    def _reverse_post_idom(self, func):
        post_idom_re = {}
        for block in self.funcs[func] + [self.RET]:
            for post_idom in self.blocks[block].post_idom:
                if post_idom not in self.funcs[func]:
                    continue
                if post_idom not in post_idom_re:
                    post_idom_re[post_idom] = set()
                post_idom_re[post_idom].add(block)
        self._post_idom_re[func] = post_idom_re


    def _get_merge_points(self, func, branch):
        # find the post dominator of the branch
        # the post dominator is the merge point

        if branch not in self._post_idom_re[func]:
            l.error("The branch 0x{:x} is not in the post idom re".format(branch))
            return set()
        return self._post_idom_re[func][branch]



    def get_merge_info(self):
        """
        Get the merge information of the binary.
        :return: {merge_entry: [merge_addr]}
        """
        merge_info = {}

        # First, get the blocks to a no return call (e.g., exit())
        # The merge addr of them is None
        direct_to_no_ret_blocks = self._gb.get_all_no_ret_blocks()
        for block in direct_to_no_ret_blocks:
            merge_info[block] = None

        for func in self.funcs:
            self._reverse_post_idom(func)
            for block in self.funcs[func]:
                if block in merge_info:
                    # Bypass the no-return blocks
                    continue

                # Second, the blocks that call functions are merge entries
                if self.blocks[block].call_functions:
                    assert len(self.blocks[block].succ) <= 1, \
                        "The block 0x{:x} has more than one successor {}".format(block, [hex(x) for x in self.blocks[block].succ])
                    merge_info[block] = self.blocks[block].succ

            # Third, the loop entries are merge entries
            func_loop_blocks = {}
            for loop in self.loops[func]:
                for block in loop.loop_in:
                    if block in merge_info:
                        l.error("Loop entry 0x{:x} should not be in merge_info".format(block))
                        continue
                    merge_info[block] = loop.loop_out
                # we save the function loop info
                for block in loop.loop_body:
                    if block not in func_loop_blocks:
                        func_loop_blocks[block] = loop
                    else:
                        assert not (func_loop_blocks[block].loop_body - loop.loop_body) or \
                               not (loop.loop_body - func_loop_blocks[block].loop_body), \
                               "block 0x%x in intersection loop"
                        if func_loop_blocks[block].loop_body - loop.loop_body:
                            func_loop_blocks[block] = loop


            # Fourth, we find the merge points for branches
            for block in self.funcs[func]:
                # If the block has more than one successor, it is a merge point
                if len(self.blocks[block].succ) > 1:
                    if block in merge_info:
                        l.error("Block 0x{:x} should not be in merge_info".format(block))
                        continue
                    merge_points = self._get_merge_points(func, block)
                    if merge_points and list(merge_points)[0] == -1:
                        continue
                    if not merge_points:
                        continue
                    if block in func_loop_blocks:
                        if merge_points - func_loop_blocks[block].loop_body:
                            # the merge point is out of the loop
                            continue
                    merge_info[block] = merge_points

        self.merge_info = merge_info
        return merge_info










