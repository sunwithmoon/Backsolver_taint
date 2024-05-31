import angr


######################################
# fgetc
######################################


class fclose(angr.SimProcedure):
    # pylint:disable=arguments-differ
    ALT_NAMES = ( 'fcloseall', 'fclose_unlocked')
    def run(self):
        return 1
