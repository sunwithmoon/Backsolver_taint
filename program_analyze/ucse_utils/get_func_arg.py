import angr
from .arch import arg_order, ret_reg
# Arch spec info
def ordered_argument_registers(arch):
    if arch.name in arg_order:
        return sorted(list(filter(lambda x: x.argument is True, arch.register_list)), key=lambda x:arg_order[arch.name].index(x.name))
    raise NotImplementedError


def return_register(arch):
    if arch.name in ret_reg:
        return ret_reg[arch.name]
    raise NotImplementedError

def get_arg_by_callsites(proj, callsites, strategy='most'):
    '''
    Get the arguments of a function by looking at the callsites
    :param proj:
    :param callsites: block addr where the callsite happen
    :param strategy:
        'most': return the most common number of arguments
        'max': return the maximum number of arguments
    :return:
    '''
    if proj.arch.name in arg_order:
        # get the previous bb (the one leading to the call)
        arg_regs = ordered_argument_registers(proj.arch)
        ret_info = return_register(proj.arch)

        #
        # Argument registers
        #
        expected_offset = [reg.vex_offset for reg in arg_regs]
        verified = -1
        sim_args_len = []
        for callsite_bbl in callsites:
            try:
                caller_bl = proj.factory.block(callsite_bbl)
            except:
                pass

            puts = [s for s in caller_bl.vex.statements if s.tag == 'Ist_Put']

            index = 0


            # Looks for function arguments in the block containing the call
            # falling the cc order so to filter false positives

            while True:
                if index >= len(puts):
                    break
                if verified >= len(arg_regs):
                    break
                p = puts[index]
                if p.offset in expected_offset:
                    id = expected_offset.index(p.offset)
                    if id > verified:
                        verified = id
                index += 1

            sim_args_len.append(verified + 1)
        if strategy == 'most':
            arg_num =  max(set(sim_args_len), key=sim_args_len.count)
        elif strategy == 'max':
            arg_num = max(sim_args_len)
        else:
            raise NotImplementedError

        sim_args = []
        for i in range(arg_num):
            reg_name = arg_regs[i].name
            reg_size = arg_regs[i].size
            var = angr.calling_conventions.SimRegArg(reg_name, reg_size)
            sim_args.append(var)


        #
        # Return register
        #

        name = ret_info[0]
        size = ret_info[1]
        ret = angr.calling_conventions.SimRegArg(name, size)

        return sim_args, ret