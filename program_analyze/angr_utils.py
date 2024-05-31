from claripy import ast, Concat, Extract
import claripy
import itertools
from taint_tracking import is_tainted

def get_section_range(proj, section_name):
    for section in proj.loader.main_object.sections:
        if section.name == section_name:
            # Print the start and end addresses of the .data segment
            start = section.min_addr
            end = section.max_addr
            return start, end
    print("no section %s!" % section_name)
    return None, None

def get_call_arg_list(state, arg_num=4):
    if state.arch.name == "AMD64":
        if arg_num > 4:
            raise NotImplementedError
        return [state.regs.rdi, state.regs.rsi, state.regs.rdx, state.regs.rcx]
    elif state.arch.name == "X86":
        return [state.mem[state.regs.esp + 4 * i].int.resolved for i in range(arg_num)]

def get_arg(expr):
    try:
        if expr.concrete:
            return []
    except:
        return []
    args = []
    for arg in expr.args:
        if type(arg) not in (ast.bv.BV,):
            args += get_arg(arg)
        else:
            args.append(arg)
    return args

def get_expr_ops(expr):
    ops = [expr.op]
    for e in expr.recursive_children_asts:
        if e.op not in ops:
            ops.append(e.op)
    return ops

def get_concat_values(expr):

    if expr.op != "Concat":
        return [expr]
    res = []
    for arg in expr.args:
        if arg.op == "If":
            res.append(get_ite_list(arg))
        else:
            res.append(arg)
    return res

def get_direct_ite_values(expr):
    '''
    return concat list of ite values
    :param expr:
    :return: [ite values]
    '''
    def add_concat_to_list(res, expr):
        if not res:
            res.append(expr)
        else:
            for i in range(len(res)):
                res[i] = Concat(res[i], expr)


    return get_ite_list(expr.args[1]) + get_direct_ite_values(expr.args[2])
    # if expr.op == "Concat":
    #     concat_args = get_concat_values(expr)
    #     res = []
    #     for arg in concat_args:
    #         if type(arg) == list:
    #             res_old = res.copy()
    #             res = []
    #             for i in range(len(arg)):
    #                 tmp = res_old.copy()
    #                 add_concat_to_list(tmp, arg[i])
    #                 res += tmp
    #         else:
    #             add_concat_to_list(res, arg)
    #     return res
    # else:
    #     return [expr]


def get_ite_list(expr):
    '''
    return concat list of ite values
    :param expr:
    :return: [ite1, ite2, ite3, ...]
        if ite1 is a concat, ite1 will be a list [[], ]
    '''
    if expr.op == "If":
        return get_ite_list(expr.args[1]) + get_ite_list(expr.args[2])
    if expr.op == "Concat":
        res = [get_concat_values(expr)]
        return res
    if not expr_contain_if(expr):
        return [expr]
    if expr_contain_if(expr.ite_excavated) and expr.ite_excavated.op not in ("If", "Concat"):
        print(expr)
        import IPython
        IPython.embed()
    return get_ite_list(expr.ite_excavated)

def get_ite_cond(expr):
    res = {}
    for e in expr.recursive_children_asts:
        if type(e) == ast.bool.Bool and len(e.args) > 1 and e.depth == 2:
            var = e.args[0]
            value = e.args[1]
            if var not in res:
                res[var] = set()
            res[var].add(value)
    for var in res:
        i = 0
        extra_v = claripy.BVV(i, list(res[var])[0].length)
        while extra_v in res[var] and i < 256:
            i += 1
            extra_v = claripy.BVV(i, list(res[var])[0].length)
        res[var].add(extra_v)
    return res

def gen_ite_cond(expr):
    res = {}
    id = 0
    for e in expr.recursive_children_asts:
        if e.op=="If":
            var = e.args[0]
            if var not in res:
                res[var] = claripy.BVS("cond%d" % id, 8) == 0
    return res

def replace_ite_with_cond(expr, cond_value):
    if expr.op == "If":
        stack = [expr.args[1], expr.args[2]]
    else:
        stack = [expr]
    while stack:
        e = stack.pop()
        # if
        if e.op != "If":
            pass
    # while e.op
    # if expr.op == "If":




def expr_contain_if(expr):
    if expr is None or type(expr) in (int, str, bool, float):
        return False
    if getattr(expr, "op", None) == "If":
        return True
    if getattr(expr, "args", None) is None:
        return False
    for arg in expr.args:
        if expr_contain_if(arg):
            return True

    return False

def get_ite_total_values(expr):
    ite_parser = IteParser(expr)
    return ite_parser.get_total_values()


def get_ite_values(expr, max_len=64):
    '''
    return concat list of ite values
    :param expr:
    :return: ([ite values], is_all_ite)
    '''
    ite_parser = IteParser(expr)
    if ite_parser.get_total_value_num() < max_len:
        return ite_parser.get_total_values(), True
    return ite_parser, False

def get_concrete_arg(expr):
    if expr.concrete:
        return [expr.args[0]]
    args = []
    for arg in expr.args:
        if type(arg) == ast.BV:
            args += get_concrete_arg(arg)
    return args


class ConcatParser():
    def __init__(self, concat_list):
        self.concat_list = concat_list
        if all([type(e) != list for e in concat_list]):
            self.concat_list = [Concat(*concat_list)]
    def __repr__(self):
        return " .. ".join([str(part) for part in self.get_parts()])
    def __iter__(self):
        return iter(self.get_parts())

    def set_concat_list(self, concat_list):
        self.concat_list = concat_list

    def get_bit(self, n):
        cur_bits = 0
        for expr in self.concat_list:
            if type(expr) not in (list, IteParser):
                if n >= cur_bits and n < cur_bits + expr.size():
                    return [expr[n - cur_bits]]
                cur_bits += expr.size()
            else:
                # ite
                ite_parser = IteParser(ite_list=expr)
                size = ite_parser.get_size()
                if n >= cur_bits and n < cur_bits + size:
                    return ite_parser.get_bit(n - cur_bits)
                cur_bits += size

    def get_parts(self):
        res = []
        for expr in self.concat_list:
            if type(expr) not in (list, IteParser):
                res.append(expr)
            else:
                # ite
                res.append(IteParser(ite_list=expr))
        return res


    def get_size(self):
        size = 0
        for expr in self.concat_list:
            if type(expr) not in (list, IteParser):
                size += expr.size()
            else:
                # ite
                size += IteParser(expr).get_size()
        return size



class IteParser():
    def __init__(self, expr=None, ite_list=None):
        self.expr = expr
        if ite_list is None:
            assert expr is not None
            self.ite_list = get_ite_list(expr)
        else:
            self.ite_list = ite_list
    def __repr__(self):
        return repr(self.get_values())
    def __iter__(self):
        return iter(self.get_values())

    def set_ite_list(self, ite_list):
        self.ite_list = ite_list

    def get_bit(self, n):
        res = []
        for expr in self.ite_list:
            if type(expr) not in (list, ConcatParser):
                res.append(expr[n])
            else:
                # concat
                res.extend(ConcatParser(expr).get_bit(n))
        return list(set(res))

    def get_byte(self, n):
        res = []
        for i in range(8):
            res.append(self.get_bit(n * 8 + i))
        return res

    def get_size(self):
        if self.expr is not None:
            return self.expr.size()
        else:
            res = list(filter(lambda e:type(e) not in (list, ConcatParser), self.ite_list))
            if res:
                return res[0].size()
            return ConcatParser(self.ite_list[0]).get_size()


    def get_total_value_num(self, ite_list=None):
        if ite_list is None:
            ite_list = self.ite_list
        res = 0
        for expr in ite_list:
            if type(expr) in (list, ConcatParser):
                # concat
                total = 1
                for concat_expr in expr:
                    if type(concat_expr) == list:
                        total *= self.get_total_value_num(concat_expr)
                res += total
            else:
                res += 1
        return res

    def concat_values_to_list(self, target, exprs):
        if not target:
            for expr in exprs:
                target.append(expr)
            return
        tmp = target.copy()
        target.clear()
        for e in tmp:
            for expr in exprs:
                target.append(Concat(e, expr))



    def concat_values(self, concat_list):
        res = []
        for part in concat_list:
            if type(part) not in (list, IteParser):
                self.concat_values_to_list(res, [part])
            else:
                # ite part
                new_exprs = self.get_total_values(part)

                self.concat_values_to_list(res, new_exprs)

        return res

    def get_total_values(self, ite_list=None):
        if ite_list is None:
            ite_list = self.ite_list
        res = []
        for expr in ite_list:
            if type(expr) in (list, ConcatParser):
                # concat
                res += self.concat_values(expr)
            else:
                res.append(expr)
        return res

    def get_values(self):
        res = []
        for expr in self.ite_list:
            if type(expr) == list:
                # concat
                res.append(ConcatParser(expr))
            else:
                res.append(expr)
        return res


    # def parse(self, expr):
    #     if expr.op == "If":
    #         self.parse(expr.args[1])
    #         self.parse(expr.args[2])
    #     elif expr.op == "Concat":
    #         self.ite_list.append(get_concat_values(expr))
    #     else:
    #         self.ite_list.append([expr])
    #
    # def get_ite_list(self):
    #     return self.ite_list

def replace_expr(expr, var, value):
    if expr.op == "If":
        cond = expr.args[0]
        true_expr = expr.args[1]
        if expr_in_list(var, list(true_expr.recursive_children_asts)):
            true_expr = replace_expr(true_expr, var, value)
        false_expr = expr.args[2]
        if expr_in_list(var, list(false_expr.recursive_children_asts)):
            false_expr = replace_expr(false_expr, var, value)
        if str(cond) == str(var):
            return claripy.If(value, true_expr, false_expr)
    if not expr_contain_if(expr):
        return expr
    new_args = []
    for arg in expr.args:
        if expr_in_list(var, list(expr.recursive_children_asts)):
            arg = replace_expr(arg, var, value)
        new_args.append(arg)
    expr.args = tuple(new_args)
    return expr

def get_ite_value_by_set_cond2(expr, var_value_dict=None, total_possible=None):
    if var_value_dict is None:
        var_value_dict = gen_ite_cond(expr)


        for old in var_value_dict:
            expr = replace_expr(expr, old, var_value_dict[old])
    return expr

def test_ite_parser():
    var3_231_8 = claripy.BVS('var3_231_8', 8)
    var2_230_8 = claripy.BVS('var2_230_8', 8)

    bvv_278 = claripy.BVV(0x278, 16)
    bvv_700278 = claripy.BVV(0x700278, 64)
    bvv_0_48 = claripy.BVV(0, 48)
    bvv_0_8 = claripy.BVV(0, 8)
    bvv_1_8 = claripy.BVV(1, 8)

    expr = claripy.If(
        var3_231_8 == 1,
        bvv_700278,
        claripy.Concat(
            bvv_0_48,
            claripy.If(
                var3_231_8 == 1,
                bvv_278,
                claripy.Concat(
                    bvv_0_8,
                    claripy.If(
                        var2_230_8 == 1,
                        bvv_0_8,
                        bvv_1_8
                    )
                )
            )
        )
    )
    print("expr:", expr)
    print("var cond:", gen_ite_cond(expr))
    get_ite_value_by_set_cond2(expr)
    var_value_dict = get_ite_cond(expr)
    total_possible = 1
    for var in set(var_value_dict):
        if type(var.args[0]) != str or "var" not in var.args[0]:
            var_value_dict.pop(var)
            continue
        total_possible *= len(var_value_dict[var])
    if total_possible <= 100:
        ite_exprs = []
        keys, values = zip(*var_value_dict.items())
        all_cond = [list(zip(keys, v)) for v in itertools.product(*values)]
        for cond in all_cond:
            new_expr = expr
            for var, value in cond:
                new_expr = new_expr.replace(var, value)

            ite_exprs.append(new_expr)
    print("total possible:", total_possible)
    print("ite exprs:", ite_exprs)
    print("get_ite_total_values:", get_ite_total_values(expr))
    print(get_ite_list(expr))
    ite_parser = IteParser(expr)
    print(ite_parser.get_total_value_num())
    print(ite_parser.get_total_values())
    print("size:", ite_parser.get_size())
    n=20
    print("bit %d"%n, ite_parser.get_bit(n))

def is_expr_contain_union(expr):
    if "union" in str(expr):
        return True

def get_expr_union_num(expr):
    return str(expr).count("union")

def sort_weight(expr):
    if is_tainted(expr):
        return 0
    if type(expr) != int and expr.symbolic:
        return 1
    return 2

def choose_candidate(union_expr):
    res = sorted(set(union_expr.args), key=sort_weight)
    return res

def is_parent(child, parent):
    for expr in parent.recursive_children_asts:
        if str(child) == str(expr):
            return True
    return False

def expr_in_list(expr, expr_list):
    for e in expr_list:
        if str(expr) == str(e):
            return True
    return False

def get_expr_index(expr, expr_list):
    for i, e in enumerate(expr_list):
        if str(expr) == str(e):
            return i
    return -1


def get_union_child_dict(expr, union_child_dict):
    if not is_expr_contain_union(expr) or str(expr) in union_child_dict:
        return
    union_child_dict[str(expr)] = []
    for arg in expr.args:
        if not is_expr_contain_union(arg):
            continue
        if arg.op == "union":
            if not expr_in_list(arg, union_child_dict[str(expr)]):
                union_child_dict[str(expr)].append(arg)
        else:
             get_union_child_dict(arg, union_child_dict)
             for child in union_child_dict[str(arg)]:
                 if not expr_in_list(child, union_child_dict[str(expr)]):
                     union_child_dict[str(expr)].append(child)


def simplify_union(expr, limit=1024):
    union_child_dict = {}
    union_exprs = [expr]
    union_value_dict = {}
    if not is_expr_contain_union(expr):
        return expr
    for child in expr.recursive_children_asts:
        while expr_in_list(child, union_exprs):
            # put child to the end of the list
            union_exprs.pop(get_expr_index(child, union_exprs))
        if child.op == "union":
            union_exprs.append(child)
        get_union_child_dict(child, union_child_dict)
    get_union_child_dict(expr, union_child_dict)

    for ue in union_exprs[::-1]:
        if str(ue) in union_value_dict:
            continue
        if str(ue) in union_child_dict and all([(str(child) in union_value_dict) for child in union_child_dict[str(ue)] if is_expr_contain_union(child)]):
            union_value_dict[ue] = []
            keys = union_child_dict[str(ue)]
            values = [union_value_dict[str(child)] for child in keys]
            all_cond = [list(zip(keys, v)) for v in itertools.product(*values)]
            ue_res = []
            for cond in all_cond:
                new_expr = ue
                for var, value in cond:
                    args = [arg for arg in new_expr.recursive_children_asts if str(arg) == str(var)]
                    assert args
                    for arg in args:
                        new_expr = new_expr.replace(arg, value)
                new_expr = claripy.simplify(new_expr)
                if new_expr.op == "union":
                    for e in choose_candidate(new_expr):
                        if not expr_in_list(e, ue_res):
                            ue_res.append(e)
                else:
                    if not expr_in_list(new_expr, ue_res):
                        ue_res.append(new_expr)
                if len(ue_res) >= limit:
                    break
            union_value_dict[str(ue)] = ue_res
        else:
            # the union expr has no child
            union_value_dict[str(ue)] = choose_candidate(ue)

    if len(union_value_dict[str(expr)]) == 1:
        return union_value_dict[str(expr)][0]
    res = union_value_dict[str(expr)][0]
    for e in union_value_dict[str(expr)][1:]:
        res = res.union(e)
    return res



def test_union_parser():
    bvv_278 = claripy.BVV(0x278, 16)
    bvv_700278 = claripy.BVV(0x700278, 64)
    bvv_0_48 = claripy.BVV(0, 48)
    bvv_0_8 = claripy.BVV(0, 8)
    bvv_1_8 = claripy.BVV(1, 8)

    expr = bvv_700278.union(
        claripy.Concat(
            bvv_0_48,
                bvv_278.union(
                claripy.Concat(
                    bvv_0_8,
                        bvv_0_8.union(
                        bvv_1_8
                    )
                )
            )
        )
    )
    print("expr:", expr)
    print("union num:", get_expr_union_num(expr))
    print("simplify_union:", simplify_union(expr))
    a = claripy.BVS('a', 8)
    b = claripy.BVS('b', 8)
    result_expression = a.union(b).union(a).union(b). \
        union(a.union(b).union(a).union(b)). \
        union(a.union(b).union(a).union(b).union(a.union(b).union(a).union(b))). \
        union(a.union(b).union(a).union(b).union(a.union(b).union(a).union(b)).union(a.union(b).union(a).union(b))). \
        union(
        a.union(b).union(a).union(b).union(a.union(b).union(a).union(b)).union(a.union(b).union(a).union(b)).union(
            a.union(b).union(a).union(b))). \
        union(
        a.union(b).union(a).union(b).union(a.union(b).union(a).union(b)).union(a.union(b).union(a).union(b)).union(
            a.union(b).union(a).union(b)).union(a.union(b).union(a).union(b)))
    print("expr:", result_expression)
    print("union num:", get_expr_union_num(result_expression))
    print("simplify_union:", simplify_union(result_expression))


if __name__ == "__main__":
    print(test_ite_parser())

