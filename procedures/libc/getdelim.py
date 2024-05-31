import angr
from cle.backends.externs.simdata.io_file import io_file_data_for_arch
from  defines import TAINT_APPLIED, APPLY_LIB_TAINT
from taint_tracking import apply_taint, is_tainted, is_or_points_to_tainted_data, new_tainted_value
import logging
import claripy

l = logging.getLogger(name=__name__)

######################################
# __getdelim
######################################

class __getdelim(angr.SimProcedure):
    # this code is modified from the 'fgets' implementation
    #   to take an arbitrary delimiter
    #   with no max size for concrete data

    # pylint: disable=arguments-differ
    def run(self, line_ptrptr, len_ptr, delim, file_ptr):
        # let's get the memory back for the file we're interested in and find the delimiter
        fd_offset = io_file_data_for_arch(self.state.arch)['fd']
        fd = self.state.mem[file_ptr + fd_offset:].int.resolved
        simfd = self.state.posix.get_fd(fd)
        if simfd is None:
            return -1

        # case 1: the data is concrete. we should read it a byte at a time since we can't seek for
        # the newline and we don't have any notion of buffering in-memory
        if not delim.to_claripy().symbolic and simfd.read_storage.concrete:
            realloc = angr.SIM_PROCEDURES['libc']['realloc']

            # #dereference the destination buffer
            line_ptr = self.state.memory.load(line_ptrptr,8, endness='Iend_LE')
            size = 120
            # im just always going to realloc and restart at size = 120, regardless of if a proper size buffer exists.
            # this doesn't match the exact behavior of get delim, but is the easiest way to ignore symbolic sizes.
            dst = self.inline_call(realloc, line_ptr, size).ret_expr

            count = 0
            while True:
                data, real_size = simfd.read_data(1)
                if self.state.solver.is_true(real_size == 0):
                    break
                self.state.memory.store(dst + count, data, endness='Iend_LE')
                count += 1
                if count == size:
                    size = count + size + 1
                    dst = self.inline_call(realloc, dst, size).ret_expr
                if self.state.solver.is_true(data == delim):
                    break

            self.state.memory.store(dst + count, b'\0', endness='Iend_LE')
            self.state.memory.store(len_ptr,count, endness='Iend_LE')
            self.state.memory.store(line_ptrptr,dst, endness='Iend_LE')
            return count


        # case 2: the data is symbolic, the delimiter could be anywhere. Read some maximum number of bytes
        # and add a constraint to assert the delimiter nonsense.
        # caveat: there could also be no delimiter and the file could EOF.
        else:
            # Just a guess as to a good value for a max size
            size = 1024
            if self.state.globals.get(APPLY_LIB_TAINT, False):
                self.state.globals[TAINT_APPLIED] = True
                data = new_tainted_value("fgetc", 8 * size)
                real_size = size
            else:
                # data, real_size = simfd.read_data(size)
                data = claripy.BVS("getdelim", 8 * size)
                real_size = size
            delim_byte = chr(self.state.solver.eval(delim))

            for i, byte in enumerate(data.chop(8)):
                self.state.solver.add(byte != delim_byte)

            malloc = angr.SIM_PROCEDURES['libc']['malloc']
            dst = self.inline_call(malloc, real_size).ret_expr

            self.state.memory.store(dst, data, size=real_size, endness='Iend_LE')
            self.state.memory.store(dst+real_size, b'\0', endness='Iend_LE')
            self.state.memory.store(len_ptr,real_size, endness='Iend_LE')
            self.state.memory.store(line_ptrptr,dst, endness='Iend_LE')

            return real_size