from angr.knowledge_plugins.functions.function import Function
def get_func_xref(cfg, func_addr, recursive=False, caller=None):
    '''
    get callers of a function
    :param cfg:
    :param func_addr: target function addr
    :param recursive: if True, find callers of func's callers recursively
    :param caller: used for recursive
    :return:
    '''
    if caller is None:
        caller = set()
    for func, jmp_type in cfg.kb.callgraph.pred[func_addr].items():
        assert len(jmp_type) == 1
        if jmp_type[0]['type'] == 'call':
            if func in caller:
                continue
            caller.add(func)
            if recursive:
                caller.update(get_func_xref(cfg, func, True, caller))
    return caller

def get_xref(cfg, callee):
    '''
    get callers basic block addr
    :param cfg:
    :param callee:
    :return:
    '''

    caller_bbl = set()
    for caller in get_func_xref(cfg, callee):
        for node in cfg.kb.functions[caller].transition_graph.pred:
            if type(node) == Function and node.addr == callee:
                for caller_node, jmp_type in cfg.kb.functions[caller].transition_graph.pred[node].items():
                    assert jmp_type['type'] == 'call'
                    caller_bbl.add(caller_node.addr)
    return caller_bbl

def get_succ_blocks(cfg, func, node, visited=set(), outside=set()):
    # Do not consider jmp back edge
    if node.addr in visited:
        return
    visited.add(node.addr)
    func_cfg_succ=cfg.kb.functions[func].transition_graph.succ
    for new_node in func_cfg_succ[node]:
        if type(new_node)==Function:
            continue
        if func_cfg_succ[node][new_node]['type'] not in ('transition', 'fake_return'):
            continue
        if cfg.kb.functions[func].transition_graph.succ[node][new_node]['outside']:
            outside.add(new_node.addr)
            continue
        get_succ_blocks(cfg, func, new_node, visited, outside)



def get_succ_blocks_weight(cfg, func, block_succ_dict):
    # the lager the number of successors is, the higher the weight
    outside = set()
    for block in cfg.kb.functions[func].transition_graph.succ:
        if type(block)==Function:
            continue
        block_succ_dict[block.addr] = set()
        get_succ_blocks(cfg, func, block, block_succ_dict[block.addr], outside)

    total = len(block_succ_dict[func])
    for block in cfg.kb.functions[func].transition_graph.succ:
        if type(block)==Function:
            continue
        block_succ_dict[block.addr] = 1 - len(block_succ_dict[block.addr]) / total


def get_all_succ_blocks_weight(cfg, block_succ_dict, main_range):

    for func_addr in cfg.kb.functions:
        # some align will be recognized as a function
        if main_range and (func_addr < main_range[0] or func_addr > main_range[1]):
            continue
        if cfg.kb.functions[func_addr].alignment:
            continue
        get_succ_blocks_weight(cfg, func_addr, block_succ_dict)






