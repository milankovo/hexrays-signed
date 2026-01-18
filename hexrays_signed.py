import idaapi
import re
import logging

logger = logging.getLogger("hexrays-signed")
logger.setLevel(logging.INFO)

hexsigned_cb_info = None
hexsigned_cb = None

enabled = True

"""
  cot_sge      = 24,  ///< x >= y signed or fpu (see EXFL_FPOP)
  cot_uge      = 25,  ///< x >= y unsigned
  cot_sle      = 26,  ///< x <= y signed or fpu (see EXFL_FPOP)
  cot_ule      = 27,  ///< x <= y unsigned
  cot_sgt      = 28,  ///< x >  y signed or fpu (see EXFL_FPOP)
  cot_ugt      = 29,  ///< x >  y unsigned
  cot_slt      = 30,  ///< x <  y signed or fpu (see EXFL_FPOP)
  cot_ult      = 31,  ///< x <  y unsigned
"""

# note on adding new operations:
# 1) add it to the regex
# 2) add corresponding idaapi.cot_xxx to the list below

#
rg = re.compile("\1\\((........|................)\1\t(>|<|>=|<=|%|/)\2\t")
signed_opts = [
    idaapi.cot_sge,
    idaapi.cot_sle,
    idaapi.cot_sgt,
    idaapi.cot_slt,
    idaapi.cot_smod,
    idaapi.cot_sdiv,
]


def modifytext(cfunc):
    ps = cfunc.get_pseudocode()

    def callback(m):
        it = int(m.group(1), 16)
        res = m.group(0)
        itm = cfunc.treeitems[it]
        if itm.op in signed_opts:
            # res=res.replace("\t", "\x12")#err
            # res=res.replace("\t", "\x0d")#err
            # res=res.replace("\t", "\x1D")#greenish
            cex = itm.cexpr.x.cexpr
            if cex.type and not cex.type.empty() and cex.type.get_size() == 2:
                res = res.replace("\t", "\x0d")  # err
            else:
                res = res.replace("\t", "\x22")  # redish

        return res

    for pseudocode_line in ps:
        pseudocode_line.line = rg.sub(callback, pseudocode_line.line)


class hexrays_callback_info(object):
    def event_callback(self, event, *args):
        if not enabled:
            return 0
        if event == idaapi.hxe_func_printed:
            (cfunc,) = args
            modifytext(cfunc)
        return 0


def remove():
    if hexsigned_cb:
        idaapi.remove_hexrays_callback(hexsigned_cb)


class HexSignedPlugin_t(idaapi.plugin_t):
    flags = 0
    comment = "highlights signed comparisons in the Pseudocode-View"
    help = ""
    wanted_name = "HexSigned"
    wanted_hotkey = ""

    def init(self):
        # Some initialization
        global hexsigned_cb_info, hexsigned_cb

        if idaapi.init_hexrays_plugin():
            hexsigned_cb_info = hexrays_callback_info()
            hexsigned_cb = hexsigned_cb_info.event_callback
            if not idaapi.install_hexrays_callback(hexsigned_cb):
                logger.error("could not install hexrays_callback")
                return idaapi.PLUGIN_SKIP
            logger.debug("Hexrays Signed plugin installed")
            addon = idaapi.addon_info_t()
            addon.id = "milankovo.hexrays-signed"
            addon.name = "Hexrays Signed"
            addon.producer = "Milankovo"
            addon.url = "https://github.com/milankovo/hexrays-signed"
            addon.version = "1.0.0"
            idaapi.register_addon(addon)
            return idaapi.PLUGIN_KEEP
        logger.error("init_hexrays_plugin failed")
        return idaapi.PLUGIN_SKIP

    def run(self, arg=0):
        global enabled
        enabled = not enabled
        logger.info("hexrays-signed plugin enabled: %s", enabled)
        return

    def term(self):
        remove()


def PLUGIN_ENTRY():
    return HexSignedPlugin_t()
