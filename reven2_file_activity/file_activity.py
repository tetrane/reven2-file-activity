import argparse
import itertools
from enum import Enum as _Enum
from collections import OrderedDict

import reven2
from reven2.types import CString, Encoding, Pointer, U16, USize
import reven2.util as util
from .prototypes.call_info import CallInfo
from .resources import (
    msdn_xml,
    msdn_typedefs_conf
)

from .prototype_formatter import format_value, get_argument_values
from .reven.reven_helper import get_ret_point


def _get_filepath_in_object_attributes(ctx, object_attributes_addr):
    addr_string_pointer = object_attributes_addr + 0x10
    addr_string = ctx.read(addr_string_pointer, Pointer(USize))
    size = ctx.read(addr_string, U16)
    addr_buffer = ctx.read(addr_string + 0x8, Pointer(USize))
    try:
        return ctx.read(addr_buffer, CString(encoding=Encoding.Utf16, max_size=size))
    except (UnicodeDecodeError, RuntimeError):
        return None


class Argument(object):
    def __init__(self, info, value):
        self.info = info
        self.value = value


class FileActivityEventType(_Enum):
    Open = 0
    Access = 1


class FileActivityEvent(object):
    def __init__(self, ctx, symbol, type, info):
        self.ctx = ctx
        self.type = type
        self.symbol = symbol
        self.proto = info.resolve_proto(symbol.name)
        self._proc = None
        self._loc = None
        self._args = None
        self._ret_tr = -1
        self._ntstatus = None

    @property
    def args(self):
        if self._args is None and self.proto is not None:
            self._args = OrderedDict()
            for info, value in get_argument_values(self.tr, self.proto):
                self._args[info.name] = Argument(info, value)
        return self._args

    @property
    def process(self):
        if self._proc is None:
            self._proc = self.ctx.ossi.process()
        return self._proc

    @property
    def tr(self):
        return self.ctx.transition_after()

    @property
    def call_tr(self):
        return self.ctx.transition_before()

    @property
    def ret_tr(self):
        if self._ret_tr is not None and type(self._ret_tr) != reven2.trace.Transition:
            self._ret_tr = get_ret_point(self.call_tr)
        return self._ret_tr

    @property
    def ntstatus(self):
        if self._ntstatus is None and self.ret_tr is not None:
            self._ntstatus = self.ret_tr.context_before().read(reven2.arch.x64.rax)
        return self._ntstatus

    @property
    def success(self):
        return self.ntstatus == 0

    @property
    def fail(self):
        return not self.success


class FileActivityOpenEvent(FileActivityEvent):
    def __init__(self, ctx, symbol, type, info):
        super().__init__(ctx, symbol, type, info)
        self._file = ''
        self._handle = None

    @property
    def file(self):
        if self._file != '':
            return self._file

        if "ObjectAttributes" in self.args:
            value = self.args["ObjectAttributes"].value
            addr = Pointer(USize).parse(value, self.ctx)
            self._file = _get_filepath_in_object_attributes(self.ctx, addr)
        else:
            self._file = None
        return self._file

    @property
    def handle(self):
        if self.fail or self.ret_tr is None:
            return self._handle
        if self._handle is None and ("FileHandle" in self.args or "DirectoryHandle" in self.args):
            value = self.args["FileHandle"].value if "FileHandle" in self.args else self.args["DirectoryHandle"].value
            ptr = Pointer(USize).parse(value, self.ctx)
            self._handle = self.ret_tr.context_before().read(ptr, USize)
        return self._handle

    def __str__(self):
        str = "#{} - {}({}) - {}:".format(self.tr.id, self.process.name, self.process.pid,
                                          self.symbol.name)
        for arg in self.args.values():
            str += "\n- {} = {}".format(arg.info.name, format_value(arg.value, arg.info.type.format, self.call_tr))
            if arg.info.name == "ObjectAttributes":
                str += "\n    - file = {}".format(self.file)
        if self.ret_tr is None:
            str += "\n=> Unknown return point"
        elif self.success:
            str += "\n=> Return at #{}: SUCCESS".format(self.ret_tr.id)
            str += "\n    - handle value = {:#x}".format(self.handle)
        else:
            str += "\n=> Return at #{}. FAILURE".format(self.ret_tr.id)
            str += "\n    - ntstatus = {}".format(self.ntstatus)
        return str


class FileActivityAccessEvent(FileActivityEvent):
    def __init__(self, ctx, symbol, type, info):
        super().__init__(ctx, symbol, type, info)
        self._file = ''
        self._handle = None

    @property
    def file(self):
        if self._file != '':
            return self._file

        if "ObjectAttributes" in self.args:
            value = self.args["ObjectAttributes"].value
            addr = Pointer(USize).parse(value, self.ctx)
            self._file = _get_filepath_in_object_attributes(self.ctx, addr)
        else:
            self._file = None
        return self._file

    @property
    def handle(self):
        if self._handle is None and "FileHandle" in self.args:
            value = self.args["FileHandle"].value
            self._handle = USize.parse(value, self.ctx)
        return self._handle

    def __str__(self):
        str = "#{} - {}({}) - {}:".format(self.tr.id, self.process.name, self.process.pid,
                                          self.symbol.name)
        for arg in self.args.values():
            str += "\n- {} = {}".format(arg.info.name, format_value(arg.value, arg.info.type.format, self.call_tr))
            if arg.info.name == "ObjectAttributes":
                str += "\n    - file = {}".format(self.file)
        if self.ret_tr is None:
            str += "\n=> Unknown return point"
        elif self.success:
            str += "\n=> Return at #{}: SUCCESS".format(self.ret_tr.id)
        else:
            str += "\n=> Return at #{}: FAILURE".format(self.ret_tr.id)
            str += "\n    - ntstatus = {}".format(self.ntstatus)
        return str


class FileActivity(object):
    def __init__(self, rvn):
        self._rvn = rvn
        self._call_info = CallInfo(
            rvn, msdn_xml, msdn_typedefs_conf
        )

        binary = "c:/windows/system32/ntoskrnl.exe"
        open_symbols = ['^NtCreateFile$', '^NtOpenFile$', '^NtOpenDirectoryObject$']
        self._open_symbols = []
        for symbol in open_symbols:
            try:
                self._open_symbols.append((next(self._rvn.ossi.symbols(symbol, binary_hint=binary)),
                                           FileActivityEventType.Open))
            except StopIteration:
                continue

        access_symbols = ['^NtQueryAttributesFile$', '^NtSetInformationFile$',
                          '^NtReadFile$', '^NtWriteFile$']
        self._access_symbols = []
        for symbol in access_symbols:
            try:
                self._access_symbols.append((next(self._rvn.ossi.symbols(symbol, binary_hint=binary)),
                                             FileActivityEventType.Access))
            except StopIteration:
                continue

    def events(self, open_events=True, access_events=True, pid=None):
        queries = []
        if open_events:
            queries += [zip(self._rvn.trace.search.symbol(symbol), itertools.repeat((symbol, type)))
                        for symbol, type in self._open_symbols]
        if access_events:
            queries += [zip(self._rvn.trace.search.symbol(symbol), itertools.repeat((symbol, type)))
                        for symbol, type in self._access_symbols]

        for match, info in util.collate(queries, lambda ctx_type: ctx_type[0]):
            if info[1] == FileActivityEventType.Open:
                event = FileActivityOpenEvent(match, info[0], info[1], self._call_info)
                if pid is None:
                    yield event
                if pid == event.process.pid:
                    yield event
            else:
                event = FileActivityAccessEvent(match, info[0], info[1], self._call_info)
                if pid is None:
                    yield event
                if pid == event.process.pid:
                    yield event


def parse_cli_args():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--host",
        type=str,
        default="localhost",
        help='reven host, as a string (default: "localhost")',
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default="13370",
        help="reven port, as an int (default: 13370)",
    )
    parser.add_argument(
        "--no-open-events",
        action="store_true",
        help="Print only open file events and discard access ones"
    )
    parser.add_argument(
        "--no-access-events",
        action="store_true",
        help="Print only access file events and discard open ones"
    )
    parser.add_argument(
        "--pid",
        type=int,
        help="Print only file events for the process with the given PID"
    )
    return parser.parse_args()


def main():
    args = parse_cli_args()
    host = args.host
    port = args.port
    opens = not args.no_open_events
    accesses = not args.no_access_events
    pid = args.pid

    rvn = reven2.RevenServer(host, port)
    file_activity = FileActivity(rvn)
    for event in file_activity.events(opens, accesses, pid):
        print('{}\n'.format(event))


if __name__ == "__main__":
    main()
