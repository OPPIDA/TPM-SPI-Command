import ctypes
import os
import sys
from enum import Enum
from random import Random

from saleae.analyzers import AnalyzerFrame, ChoicesSetting

sys.path.insert(1,
    os.path.join(
        os.path.dirname(__file__),
        'bitlocker-spi-toolkit',
        'TPM-SPI-Transaction'
    )
)
from HighLevelAnalyzer import Operation, Hla as TransactionHla
from PacketParser import PacketParser

FITEST_SEED         = 0x1337
FITEST_PROBABILITY  = 0.01

# TCG PC Client Specific TPM Interface Specification (TIS)
# Specification Version 1.3
# Revision 27
# https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientTPMInterfaceSpecification_TIS__1-3_27_03212013.pdf

REGION              = 0xd4
REG_STS             = 0x000018
REG_FIFO            = 0x000024
NUM_LOCALITY        = 5

class Offset(ctypes.Union):
    class Bits(ctypes.Structure):
        _pack_ = 1
        _fields_ = [
            ("register",    ctypes.c_uint32,    12),
            ("locality",    ctypes.c_uint32,    4),
            ("region",      ctypes.c_uint32,    8)
        ]

    _fields_ = [
        ("b", Bits),
        ("i", ctypes.c_uint32)
    ]

    def __init__(self, integer):
        super().__init__()
        self.i = integer

class TPM_STS_x(ctypes.Union):
    class Bits(ctypes.Structure):
        _pack_ = 1
        _fields_ = [
            ("reserved",        ctypes.c_uint32,    1),
            ("responseReady",   ctypes.c_uint32,    1),
            ("selfTestDone",    ctypes.c_uint32,    1),
            ("Expect",          ctypes.c_uint32,    1),
            ("dataAvail",       ctypes.c_uint32,    1),
            ("tpmGo",           ctypes.c_uint32,    1),
            ("commandReady",    ctypes.c_uint32,    1),
            ("stsValid",        ctypes.c_uint32,    1),
            ("burstCount",      ctypes.c_uint32,    16),
        ]

    _fields_ = [
        ("b", Bits),
        ("i", ctypes.c_uint32)
    ]

    def __init__(self, integer):
        super().__init__()
        self.i = integer

class CommandState(Enum):
    IDLE                = 1
    SENDING_COMMAND     = 2
    EXECUTING_COMMAND   = 3
    SENDING_RESPONSE    = 4

class FifoData:
    start_time: float
    end_time: float
    data: bytearray()
    is_response: bool
    locality: int

    def __init__(self, is_response, locality):
        self.start_time = None
        self.end_time = None
        self.data = bytearray()
        self.is_response = is_response
        self.locality = locality

    def is_empty(self):
        return len(self.data) == 0

    def add_byte(self, start_time, end_time, byte):
        if self.start_time is None:
            self.start_time = start_time
        self.end_time = end_time
        self.data += bytearray((byte,))

    def build_frame(self):
        frame_type = 'response' if self.is_response else 'command'
        parser = PacketParser(self.data, self.is_response)
        return AnalyzerFrame(
            frame_type,
            self.start_time,
            self.end_time,
            {
                'Locality': f'{self.locality:1d}',
                'Tag': parser.get_tag_name(),
                'Code': parser.get_code_name(),
                'Header': parser.get_header().hex(),
                'Body': parser.get_body().hex(),
            }
        )

class CommandAnalyzer:
    state = [CommandState.IDLE] * NUM_LOCALITY
    fifo = [None] * NUM_LOCALITY

    def parse_transaction(self, start_time, end_time, addr, data, is_read):
        offset = Offset(addr)
        register = offset.b.register
        locality = offset.b.locality
        region = offset.b.region

        if region != REGION:
            return AnalyzerFrame(
                'error',
                start_time,
                end_time,
                {'Message': f'Unexpected region: {addr:06x}'}
            )
        elif locality >= NUM_LOCALITY:
            return AnalyzerFrame(
                'error',
                start_time,
                end_time,
                {'Message': f'Unexpected locality: {locality}'}
            )

        if register == REG_STS:
            return self._access_sts(start_time, end_time, data, is_read, locality)
        elif register == REG_FIFO:
            return self._access_fifo(start_time, end_time, data, is_read, locality)

    def _access_sts(self, start_time, end_time, data, is_read, locality):
        state_machine = {
            CommandState.IDLE:              self._state_idle,
            CommandState.SENDING_COMMAND:   self._state_sending_command,
            CommandState.EXECUTING_COMMAND: self._state_executing_command,
            CommandState.SENDING_RESPONSE:  self._state_sending_response
        }
        state = self.state[locality]
        status = TPM_STS_x(data)
        return state_machine[state](start_time, end_time, status, is_read, locality)

    def _access_fifo(self, start_time, end_time, data, is_read, locality):
        state = self.state[locality]
        if state not in (CommandState.SENDING_COMMAND, CommandState.SENDING_RESPONSE):
            return AnalyzerFrame(
                'error',
                start_time,
                end_time,
                {'Message': f'FIFO accessed while in invalid state: {state}'}
            )
        elif self.fifo[locality].is_response != is_read:
            return AnalyzerFrame(
                'error',
                start_time,
                end_time,
                {'Message': f'Unexpected FIFO direction: {"read" if is_read else "write"}'}
            )
        elif data not in range(0x100):
            return AnalyzerFrame(
                'error',
                start_time,
                end_time,
                {'Message': f'FIFO data is out of range: {data:x}'}
            )

        self.fifo[locality].add_byte(start_time, end_time, data)
        return None

    def _state_idle(self, start_time, end_time, status, is_read, locality):
        if not is_read and status.b.commandReady:
            self.state[locality] = CommandState.SENDING_COMMAND
            self.fifo[locality] = FifoData(False, locality)

    def _state_sending_command(self, start_time, end_time, status, is_read, locality):
        if not is_read and status.b.tpmGo:
            if self.fifo[locality].is_empty():
                return AnalyzerFrame(
                    'error',
                    start_time,
                    end_time,
                    {'Message': f'tpmGo raised w/o data'}
                )

            self.state[locality] = CommandState.EXECUTING_COMMAND
            frame = self.fifo[locality].build_frame()
            self.fifo[locality] = None
            return frame

    def _state_executing_command(self, start_time, end_time, status, is_read, locality):
        if is_read and status.b.dataAvail:
            self.state[locality] = CommandState.SENDING_RESPONSE
            self.fifo[locality] = FifoData(True, locality)

    def _state_sending_response(self, start_time, end_time, status, is_read, locality):
        if is_read and not status.b.dataAvail:
            if self.fifo[locality].is_empty():
                return AnalyzerFrame(
                    'error',
                    start_time,
                    end_time,
                    {'Message': f'dataAvail lowered w/o data'}
                )

            self.state[locality] = CommandState.IDLE
            frame = self.fifo[locality].build_frame()
            self.fifo[locality] = None
            return frame

class CommandHla(TransactionHla):
    addr_filter_setting = ""
    operation_setting = "Both"
    fitest_enabled = ChoicesSetting(['', 'Enabled'], label="DEBUG: Corrupt input randomly")

    result_types = {
        'command': {
            'format': 'CMD: C={{data.Code}}, T={{data.Tag}}, L={{data.Locality}}'
        },
        'response': {
            'format': 'RSP: C={{data.Code}}, T={{data.Tag}}, L={{data.Locality}}'
        },
        'error': {
            'format': 'ERR: {{data.Message}}'
        }
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.command_analyzer = CommandAnalyzer()
        self.prng = Random(FITEST_SEED)

    def decode(self, *args, **kwargs):
        out_frame = None
        with open(os.devnull, 'w') as devnull:
            sys.stdout, stdout = devnull, sys.stdout
            out_frame = super().decode(*args, **kwargs)
            sys.stdout = stdout

        if out_frame is None:
            return None

        txn = self.current_transaction
        start_time = txn.start_time
        end_time = txn.end_time
        addr = int.from_bytes(txn.address, 'big')
        data = int.from_bytes(txn.data, 'little')
        is_read = txn.operation == Operation.READ

        if self.fitest_enabled:
            addr, data, is_read = self._corrupt_input(start_time, addr, data, is_read)

        return self.command_analyzer.parse_transaction(
            start_time,
            end_time,
            addr,
            data,
            is_read
        )

    def _corrupt_input(self, start_time, addr, data, is_read):
        if self.prng.random() < FITEST_PROBABILITY:
            new_addr = self.prng.choice((REGION << 16, 0))
            new_addr |= self.prng.choice(range(0x0000, (NUM_LOCALITY + 1) << 12, 0x1000))
            new_addr |= self.prng.choice((REG_FIFO, REG_STS, 0))
            print(f"[{start_time}] addr {addr:06x} => {new_addr:06x}")
            addr = new_addr
        if self.prng.random() < FITEST_PROBABILITY:
            new_data = self.prng.choice(range(0x100))
            print(f"[{start_time}] data {data:02x} => {new_data:02x}")
            data = new_data
        if self.prng.random() < FITEST_PROBABILITY:
            is_read = not is_read
        return addr, data, is_read
