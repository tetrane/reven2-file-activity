"""Retrieve prototype information from resources
"""

import functools

from .demangle import msvc_demangle

from .msdnxml.msdn_xml_file import MsdnXmlFile
from .msdnxml.clangparser import ProtoStrParser


def clang_parse(proto_parser, proto_str, callconv):
    clang = proto_parser.get_proto(proto_str, callconv)
    unknown_types = clang.diag.unknown_types()
    if not unknown_types:
        return clang.proto

    clang = proto_parser.clang()
    for t in unknown_types:
        clang.add_typedef(t, "addr")
    clang.parse_proto(proto_str, callconv)

    return clang.proto


class CallInfo(object):
    def __init__(
        self, msdn_xml, msdn_typedefs_conf
    ):
        self.msdn_xml = MsdnXmlFile(msdn_xml)
        self.proto_parser = ProtoStrParser(msdn_typedefs_conf)

    @functools.lru_cache(maxsize=2048)
    def resolve_proto(self, symbol_name):
        callconv, func_name = msvc_demangle(symbol_name)

        # msdn.xml
        proto_str = self.msdn_xml.function_proto_str(func_name)
        if proto_str is not None:
            maybe_proto = clang_parse(self.proto_parser, proto_str, callconv)
            if maybe_proto is not None:
                return maybe_proto

        # demangled
        if "(" in func_name:  # assume demangled proto
            proto_str = func_name + ";"
            maybe_proto = clang_parse(self.proto_parser, proto_str, callconv)
            if maybe_proto is not None:
                return maybe_proto

        return None
