import logging
import os

l = logging.getLogger(name=__name__)

from angr.misc import autoimport
from angr.sim_procedure import SimProcedure
from angr.procedures import SIM_PROCEDURES

# Import all classes under the current directory, and group them based on
# lib names.
hook_funcs = {}
path = os.path.dirname(os.path.abspath(__file__))
skip_dirs = ['definitions', '__pycache__']

for pkg_name, package in autoimport.auto_import_packages('procedures', path, skip_dirs):
    for _, mod in autoimport.filter_module(package, type_req=type(os)):
        for name, proc in autoimport.filter_module(mod, type_req=type, subclass_req=SimProcedure):

            if hasattr(proc, "__provides__"):
                for custom_pkg_name, custom_func_name in proc.__provides__:
                    hook_funcs[custom_func_name] = proc
            else:
                hook_funcs[name] = proc
                if hasattr(proc, "ALT_NAMES") and proc.ALT_NAMES:
                    for altname in proc.ALT_NAMES:
                        hook_funcs[altname] = proc
                if name == 'UnresolvableJumpTarget':
                    hook_funcs['UnresolvableTarget'] = proc


class _SimProcedures:
    def __getitem__(self, k):
        l.critical("the SimProcedures dictionary is DEPRECATED. Please use the angr.SIM_PROCEDURES global dict instead.")
        return SIM_PROCEDURES[k]

    def __setitem__(self, k, v):
        l.critical("the SimProcedures dictionary is DEPRECATED. Please use the angr.SIM_PROCEDURES global dict instead.")
        SIM_PROCEDURES[k] = v

SimProcedures = _SimProcedures()
