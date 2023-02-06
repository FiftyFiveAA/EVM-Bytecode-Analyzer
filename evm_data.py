class EVMData():
    def __init__(self):
        self.opcode_dict = {
            #
            # Stop and Arithmetic
            #
            0x00: "stop",
            0x01: "add",
            0x02: "mul",
            0x03: "sub",
            0x04: "div",
            0x05: "sdiv",
            0x06: "mod",
            0x07: "smod",
            0x08: "addmod",
            0x09: "mulmod",
            0x0A: "exp",
            0x0B: "signextend",
            #
            # Comparison and Bitwise Logic
            #
            0x10: "lt",
            0x11: "gt",
            0x12: "slt",
            0x13: "sgt",
            0x14: "eq",
            0x15: "iszero",
            0x16: "and",
            0x17: "or",
            0x18: "xor",
            0x19: "not",
            0x1A: "byte",
            0x1B: "shl",
            0x1C: "shr",
            0x1D: "sar",
            #
            # Sha3
            #
            0x20: "sha3",
            #
            # Environment Information
            #
            0x30: "address",
            0x31: "balance",
            0x32: "origin",
            0x33: "caller",
            0x34: "callvalue",
            0x35: "calldataload",
            0x36: "calldatasize",
            0x37: "calldatacopy",
            0x38: "codesize",
            0x39: "codecopy",
            0x3A: "gasprice",
            0x3B: "extcodesize",
            0x3C: "extcodecopy",
            0x3D: "returndatasize",
            0x3E: "returndatacopy",
            0x3F: "extcodehash",
            #
            # Block Information
            #
            0x40: "blockhash",
            0x41: "coinbase",
            0x42: "timestamp",
            0x43: "number",
            0x44: "difficulty",
            0x45: "gaslimit",
            0x46: "chainid",
            0x47: "selfbalance",
            #
            # Stack, Memory, Storage and Flow Operations
            #
            0x50: "pop",
            0x51: "mload",
            0x52: "mstore",
            0x53: "mstore8",
            0x54: "sload",
            0x55: "sstore",
            0x56: "jump",
            0x57: "jumpi",
            0x58: "pc",
            0x59: "msize",
            0x5A: "gas",
            0x5B: "jumpdest",
            #
            # Push Operations
            #
            0x60: "push1",
            0x61: "push2",
            0x62: "push3",
            0x63: "push4",
            0x64: "push5",
            0x65: "push6",
            0x66: "push7",
            0x67: "push8",
            0x68: "push9",
            0x69: "push10",
            0x6A: "push11",
            0x6B: "push12",
            0x6C: "push13",
            0x6D: "push14",
            0x6E: "push15",
            0x6F: "push16",
            0x70: "push17",
            0x71: "push18",
            0x72: "push19",
            0x73: "push20",
            0x74: "push21",
            0x75: "push22",
            0x76: "push23",
            0x77: "push24",
            0x78: "push25",
            0x79: "push26",
            0x7A: "push27",
            0x7B: "push28",
            0x7C: "push29",
            0x7D: "push30",
            0x7E: "push31",
            0x7F: "push32",
            #
            # Duplicate Operations
            #
            0x80: "dup1",
            0x81: "dup2",
            0x82: "dup3",
            0x83: "dup4",
            0x84: "dup5",
            0x85: "dup6",
            0x86: "dup7",
            0x87: "dup8",
            0x88: "dup9",
            0x89: "dup10",
            0x8A: "dup11",
            0x8B: "dup12",
            0x8C: "dup13",
            0x8D: "dup14",
            0x8E: "dup15",
            0x8F: "dup16",
            #
            # Exchange Operations
            #
            0x90: "swap1",
            0x91: "swap2",
            0x92: "swap3",
            0x93: "swap4",
            0x94: "swap5",
            0x95: "swap6",
            0x96: "swap7",
            0x97: "swap8",
            0x98: "swap9",
            0x99: "swap10",
            0x9A: "swap11",
            0x9B: "swap12",
            0x9C: "swap13",
            0x9D: "swap14",
            0x9E: "swap15",
            0x9F: "swap16",
            #
            # Logging
            #
            0xA0: "log0",
            0xA1: "log1",
            0xA2: "log2",
            0xA3: "log3",
            0xA4: "log4",
            #
            # System
            #
            0xF0: "create",
            0xF1: "call",
            0xF2: "callcode",
            0xF3: "return",
            0xF4: "delegatecall",
            0xF5: "create2",
            0xFA: "staticcall",
            0xFD: "revert",
            0xFE: "invalid",
            0xFF: "selfdestruct",
        }

        self.stack_diffs = {
            "create": -2,
            "create2": -3,
            "invalid": None,
            "add": -1,
            "addmod": -2,
            "sub": -1,
            "mod": -1,
            "smod": -1,
            "mul": -1,
            "mulmod": -2,
            "div": -1,
            "sdiv": -1,
            "exp": -1,
            "signextend": -1,
            "shl": -1,
            "shr": -1,
            "sar": -1,
            "blockhash": 0,
            "coinbase": 1,
            "selfdestruct": -1,
            "timestamp": 1,
            "number": 1,
            "difficulty": 1,
            "gaslimit": 1,
            "lt": -1,
            "gt": -1,
            "slt": -1,
            "sgt": -1,
            "eq": -1,
            "iszero": 0,
            "and": -1,
            "or": -1,
            "xor": -1,
            "not": 0,
            "byte": -1,
            "balance": 0,
            "origin": 1,
            "address": 1,
            "selfbalance": 1,
            "chainid": 1,
            "call": -6,
            "callcode": -6,
            "delegatecall": -5,
            "staticcall": -5,
            "caller": 1,
            "callvalue": 1,
            "calldataload": 0,
            "calldatasize": 1,
            "calldatacopy": -3,
            "codesize": 1,
            "codecopy": -3,
            "gasprice": 1,
            "extcodesize": 0,
            "extcodehash": 0,
            "extcodecopy": -4,
            "returndatasize": 1,
            "returndatacopy": -3,
            "dup_XX": 1,
            "stop": 0,
            "jump": -1,
            "jumpi": -2,
            "jumpdest": 0,
            "pc": 1,
            "gas": 1,
            "log0": -2,
            "log1": -3,
            "log2": -4,
            "log3": -5,
            "log4": -6,
            "mstore": -2,
            "mstore8": -2,
            "mload": 0,
            "msize": 1,
            "sha3": -1,
            "pop": -1,
            "push_XX": 1,
            "sstore": -2,
            "sload": 0,
            "return": -2,
            "revert": -2,
            "assert_fail": 0,
            "push": 1,
            "dup": 1,
            "swap": 0,
            "push1": 1,
            "push2": 1,
            "push3": 1,
            "push4": 1,
            "push5": 1,
            "push6": 1,
            "push7": 1,
            "push8": 1,
            "push9": 1,
            "push10": 1,
            "push11": 1,
            "push12": 1,
            "push13": 1,
            "push14": 1,
            "push15": 1,
            "push16": 1,
            "push17": 1,
            "push18": 1,
            "push19": 1,
            "push20": 1,
            "push21": 1,
            "push22": 1,
            "push23": 1,
            "push24": 1,
            "push25": 1,
            "push26": 1,
            "push27": 1,
            "push28": 1,
            "push29": 1,
            "push30": 1,
            "push31": 1,
            "push32": 1,
            "dup1": 1,
            "swap1": 0,
            "dup2": 1,
            "swap2": 0,
            "dup3": 1,
            "swap3": 0,
            "dup4": 1,
            "swap4": 0,
            "dup5": 1,
            "swap5": 0,
            "dup6": 1,
            "swap6": 0,
            "dup7": 1,
            "swap7": 0,
            "dup8": 1,
            "swap8": 0,
            "dup9": 1,
            "swap9": 0,
            "dup10": 1,
            "swap10": 0,
            "dup11": 1,
            "swap11": 0,
            "dup12": 1,
            "swap12": 0,
            "dup13": 1,
            "swap13": 0,
            "dup14": 1,
            "swap14": 0,
            "dup15": 1,
            "swap15": 0,
            "dup16": 1,
            "swap16": 0,
        }

    def fromHexString(self, value):
        return bytes.fromhex(value)

    def toHexString(self, value):
        return value.hex()

    # Stop and Arithmetic
    def stop(self, global_variables, stack, storage, memory):
        event = ""
        return stack, storage, memory, event

    def add(self, global_variables, stack, storage, memory):
        # Get the 2 values to add from the stack
        a = stack.pop()
        b = stack.pop()
        # Convert the hex strings to integer
        # Make it mod 2^256-1 to handle overflows
        result = (int(a, 16) + int(b, 16)) % (2**256)
        # Check if there was an int overflow
        overflow = ""
        if((int(a, 16) + int(b, 16)) > (2**256)-1):
            overflow = "overflow"
        # Convert the int to a 32 byte hex string
        stack.append(format(result, "064x"))
        return stack, storage, memory, overflow

    def mul(self, global_variables, stack, storage, memory):
        # Get the 2 values to add from the stack
        a = stack.pop()
        b = stack.pop()
        # Convert the hex strings to integer
        # Make it mod 2^256-1 to handle overflows
        result = (int(a, 16) * int(b, 16)) % (2**256)
        # Check if there was an int overflow
        overflow = ""
        if((int(a, 16) * int(b, 16)) > (2**256)-1):
            overflow = "overflow"
        # Convert the int to a 32 byte hex string
        stack.append(format(result, "064x"))
        return stack, storage, memory, overflow

    def sub(self, global_variables, stack, storage, memory):
        # Get the 2 values to add from the stack
        a = stack.pop()
        b = stack.pop()
        # Convert the hex strings to integer
        # Make it mod 2^256-1 to handle overflows
        result = (int(a, 16) - int(b, 16)) % (2**256)
        # Check if there was an int overflow
        underflow = ""
        if((int(a, 16) - int(b, 16)) < 0):
            underflow = "underflow"
        # Convert the int to a 32 byte hex string
        stack.append(format(result, "064x"))
        return stack, storage, memory, underflow

    def div(self, global_variables, stack, storage, memory):
        # Get the 2 values to add from the stack
        a = stack.pop()
        b = stack.pop()
        event = ""
        # If the denominator is 0, then return 0
        if(int(b, 16) == 0):
            result = 0
            event = "divide by 0 returns 0"
        else:
            # Convert the hex strings to integers
            result = (int(a, 16) // int(b, 16))
        # Convert the int to a 32 byte hex string
        stack.append(format(result, "064x"))
        return stack, storage, memory, event

    def sdiv(self, global_variables, stack, storage, memory):
        # Get the 2 values to add from the stack
        a = stack.pop()
        b = stack.pop()
        event = ""

        a = int(a, 16)
        b = int(b, 16)

        # If the denominator is 0, then return 0
        if(b == 0):
            result = 0
            event = "Signed division by 0 returns 0"
        else:
            # Turn ints into 2's complement
            if(a < 2**255):
                pass
            else:  # AKA the MSB is 1, so it's a signed number
                a = a - 2**256
                
            if(b < 2**255):
                pass
            else: # AKA the MSB is 1, so it's a signed number
                b = b - 2**256
            
            result = a // b
            if(result >= 0 and result < 2**255):
                pass
            else:
                result = result + 2**256
                
        # Convert the int to a 32 byte hex string
        stack.append(format(result, "064x"))
        return stack, storage, memory, event

    def mod(self, global_variables, stack, storage, memory):
        # Get the 2 values to add from the stack
        a = stack.pop()
        b = stack.pop()

        event = ""
        if(b == 0):
            result = 0
            event = "MOD 0 returns 0"
        else:
            result = int(a, 16) % int(b, 16)

        # Convert the int to a 32 byte hex string
        stack.append(format(result, "064x"))
        return stack, storage, memory, event

    def smod(self, global_variables, stack, storage, memory):
        # Get the 2 values to add from the stack
        a = stack.pop()
        b = stack.pop()
        event = ""

        a = int(a, 16)
        b = int(b, 16)

        # If the denominator is 0, then return 0
        if(b == 0):
            result = 0
            event = "Signed MOD 0 returns 0"
        else:
            # Turn ints into 2's complement
            if(a < 2**255):
                pass
            else:  # AKA the MSB is 1, so it's a signed number
                a = a - 2**256
                
            if(b < 2**255):
                pass
            else: # AKA the MSB is 1, so it's a signed number
                b = b - 2**256
            
            result = a % b
            if(result >= 0 and result < 2**255):
                pass
            else:
                result = result + 2**256
        
        # Convert the int to a 32 byte hex string
        stack.append(format(result, "064x"))
        return stack, storage, memory, event

    def addmod(self, global_variables, stack, storage, memory):
        # Get the 3 values to add from the stack
        a = stack.pop()
        b = stack.pop()
        n = stack.pop()

        event = ""
        if(b == 0):
            result = 0
            event = "MOD 0 returns 0"
        else:
            result = (int(a, 16) + int(b,16)) % int(n, 16)

        # Convert the int to a 32 byte hex string
        stack.append(format(result, "064x"))
        return stack, storage, memory, event

    def mulmod(self, global_variables, stack, storage, memory):
        # Get the 3 values to add from the stack
        a = stack.pop()
        b = stack.pop()
        n = stack.pop()

        event = ""
        if(b == 0):
            result = 0
            event = "MOD 0 returns 0"
        else:
            result = (int(a, 16) * int(b,16)) % int(n, 16)

        # Convert the int to a 32 byte hex string
        stack.append(format(result, "064x"))
        return stack, storage, memory, event

    def exp(self, global_variables, stack, storage, memory):
        # Get the 2 values from the stack
        a = stack.pop()
        b = stack.pop()
        # Convert the hex strings to integer
        # Make it mod 2^256-1 to handle overflows
        result = (int(a, 16) ** int(b, 16)) % (2**256)
        # Check if there was an int overflow
        overflow = ""
        if((int(a, 16) ** int(b, 16)) > (2**256)-1):
            overflow = "overflow"
        # Convert the int to a 32 byte hex string
        stack.append(format(result, "064x"))
        return stack, storage, memory, overflow

    def signextend(self, global_variables, stack, storage, memory):
        # Get the 2 values from the stack
        b = stack.pop()  # size in byte - 1 of the integer to sign extend
        x = stack.pop()  # integer value to sign extend
        # https://github.com/ethereum/py-evm/blob/1af151ab218b905f4fdf7a285cbe14ebf094a7c4/eth/vm/logic/arithmetic.py
        b = int(b, 16)
        x = int(x, 16)
        event = ""
        
        if(b <= 31):
            testbit = (b * 8) + 7
            sign_bit = (1 << testbit)
            if(x & sign_bit):
                result = x | (2**256 - sign_bit)
            else:
                result = x & (sign_bit - 1)
        else:
            result = x
        
        # Convert the int to a 32 byte hex string
        stack.append(format(result, "064x"))
        return stack, storage, memory, event

    # Comparison and Bitwise Logic
    def lt(self, global_variables, stack, storage, memory):
        # Get the 2 values from the stack
        a = stack.pop()
        b = stack.pop()
        # Convert the hex strings to integer
        a = int(a, 16)
        b = int(b, 16)
        event = ""

        if(a < b):
            result = 1
        else:
            result = 0
        # Convert the int to a 32 byte hex string
        stack.append(format(result, "064x"))
        return stack, storage, memory, event

    def gt(self, global_variables, stack, storage, memory):
        # Get the 2 values from the stack
        a = stack.pop()
        b = stack.pop()
        # Convert the hex strings to integer
        a = int(a, 16)
        b = int(b, 16)
        event = ""

        if(a > b):
            result = 1
        else:
            result = 0
        # Convert the int to a 32 byte hex string
        stack.append(format(result, "064x"))
        return stack, storage, memory, event

    def slt(self, global_variables, stack, storage, memory):
        # Get the 2 values from the stack
        a = stack.pop()
        b = stack.pop()
        # Convert the hex strings to integer
        a = int(a, 16)
        b = int(b, 16)
        event = ""

        # Turn ints into 2's complement
        if(a < 2**255):
            pass
        else:  # AKA the MSB is 1, so it's a signed number
            a = a - 2**256
            
        if(b < 2**255):
            pass
        else: # AKA the MSB is 1, so it's a signed number
            b = b - 2**256

        if(a < b):
            result = 1
        else:
            result = 0
        # Convert the int to a 32 byte hex string
        stack.append(format(result, "064x"))
        return stack, storage, memory, event

    def sgt(self, global_variables, stack, storage, memory):
        # Get the 2 values from the stack
        a = stack.pop()
        b = stack.pop()
        # Convert the hex strings to integer
        a = int(a, 16)
        b = int(b, 16)
        event = ""

        # Turn ints into 2's complement
        if(a < 2**255):
            pass
        else:  # AKA the MSB is 1, so it's a signed number
            a = a - 2**256
            
        if(b < 2**255):
            pass
        else: # AKA the MSB is 1, so it's a signed number
            b = b - 2**256

        if(a > b):
            result = 1
        else:
            result = 0
        # Convert the int to a 32 byte hex string
        stack.append(format(result, "064x"))
        return stack, storage, memory, event

    def eq(self, global_variables, stack, storage, memory):
        # Get the 2 values from the stack
        a = stack.pop()
        b = stack.pop()
        # Convert the hex strings to integer
        a = int(a, 16)
        b = int(b, 16)
        event = ""

        if(a == b):
            result = 1
        else:
            result = 0
        # Convert the int to a 32 byte hex string
        stack.append(format(result, "064x"))
        return stack, storage, memory, event

    def iszero(self, global_variables, stack, storage, memory):
        # Get the 1 value from the stack
        a = stack.pop()

        # Convert the hex strings to integer
        a = int(a, 16)
        event = ""

        if(a == 0):
            result = 1
        else:
            result = 0
        # Convert the int to a 32 byte hex string
        stack.append(format(result, "064x"))
        return stack, storage, memory, event

    def And(self, global_variables, stack, storage, memory):
        # Get the 2 values to add from the stack
        a = stack.pop()
        b = stack.pop()
        # Convert the hex strings to integer
        a = int(a, 16)
        b = int(b, 16)
        event = ""
        # Make it mod 2^256-1 to handle overflows
        result = a & b
        # Convert the int to a 32 byte hex string
        stack.append(format(result, "064x"))
        return stack, storage, memory, event

    def Or(self, global_variables, stack, storage, memory):
        # Get the 2 values to add from the stack
        a = stack.pop()
        b = stack.pop()
        # Convert the hex strings to integer
        a = int(a, 16)
        b = int(b, 16)
        event = ""
        # Make it mod 2^256-1 to handle overflows
        result = a | b
        # Convert the int to a 32 byte hex string
        stack.append(format(result, "064x"))
        return stack, storage, memory, event

    def xor(self, global_variables, stack, storage, memory):
        # Get the 2 values to add from the stack
        a = stack.pop()
        b = stack.pop()
        # Convert the hex strings to integer
        a = int(a, 16)
        b = int(b, 16)
        event = ""
        # Make it mod 2^256-1 to handle overflows
        result = a ^ b
        # Convert the int to a 32 byte hex string
        stack.append(format(result, "064x"))
        return stack, storage, memory, event

    def Not(self, global_variables, stack, storage, memory):
        # Get the 1 value from the stack
        a = stack.pop()

        # Convert the hex strings to integer
        a = int(a, 16)
        event = ""

        result = (2**256) - 1 - a
        # Convert the int to a 32 byte hex string
        stack.append(format(result, "064x"))
        return stack, storage, memory, event

    def Byte(self, global_variables, stack, storage, memory):
        # Get the 2 values to add from the stack
        i = stack.pop()
        x = stack.pop()
        # Convert the hex strings to integer
        i = int(i, 16)
        x = int(x, 16)
        event = ""

        if(i >= 32):
            result = 0
        else:
            result = (x // pow(256, 31-i)) % 256
        # Convert the int to a 32 byte hex string
        stack.append(format(result, "064x"))
        return stack, storage, memory, event

    def shl(self, global_variables, stack, storage, memory):
        return stack, storage, memory

    def shr(self, global_variables, stack, storage, memory):
        return stack, storage, memory

    def sar(self, global_variables, stack, storage, memory):
        return stack, storage, memory

    # SHA
    def sha3(self, global_variables, stack, storage, memory):
        return stack, storage, memory

    # Environment Information
    def address(self, global_variables, stack, storage, memory):
        return stack, storage, memory

    def balance(self, global_variables, stack, storage, memory):
        return stack, storage, memory

    def origin(self, global_variables, stack, storage, memory):
        return stack, storage, memory

    def caller(self, global_variables, stack, storage, memory):
        return stack, storage, memory

    def callvalue(self, global_variables, stack, storage, memory):
        return stack, storage, memory

    def calldataload(self, global_variables, stack, storage, memory):
        return stack, storage, memory

    def calldatasize(self, global_variables, stack, storage, memory):
        return stack, storage, memory

    def calldatacopy(self, global_variables, stack, storage, memory):
        return stack, storage, memory

    def codesize(self, global_variables, stack, storage, memory):
        return stack, storage, memory

    def codecopy(self, global_variables, stack, storage, memory):
        return stack, storage, memory

    def gasprice(self, global_variables, stack, storage, memory):
        return stack, storage, memory

    def extcodesize(self, global_variables, stack, storage, memory):
        return stack, storage, memory

    def extcodecopy(self, global_variables, stack, storage, memory):
        return stack, storage, memory

    def returndatasize(self, global_variables, stack, storage, memory):
        return stack, storage, memory

    def returndatacopy(self, global_variables, stack, storage, memory):
        return stack, storage, memory

    def extcodehash(self, global_variables, stack, storage, memory):
        return stack, storage, memory

    # Block Information
    def blockhash(self, global_variables, stack, storage, memory):
        return stack, storage, memory

    def coinbase(self, global_variables, stack, storage, memory):
        return stack, storage, memory

    def timestamp(self, global_variables, stack, storage, memory):
        return stack, storage, memory

    def number(self, global_variables, stack, storage, memory):
        return stack, storage, memory

    def difficulty(self, global_variables, stack, storage, memory):
        return stack, storage, memory

    def gaslimit(self, global_variables, stack, storage, memory):
        return stack, storage, memory

    def chainid(self, global_variables, stack, storage, memory):
        return stack, storage, memory

    def selfbalance(self, global_variables, stack, storage, memory):
        return stack, storage, memory

    # Stack, Memory, Storage and Flow Operations
    def pop(self, global_variables, stack, storage, memory):
        return stack, storage, memory

    def mload(self, global_variables, stack, storage, memory):
        return stack, storage, memory

    def mstore(self, global_variables, stack, storage, memory):
        return stack, storage, memory

    def mstore8(self, global_variables, stack, storage, memory):
        return stack, storage, memory

    def sload(self, global_variables, stack, storage, memory):
        return stack, storage, memory

    def sstore(self, global_variables, stack, storage, memory):
        return stack, storage, memory

    def jump(self, global_variables, stack, storage, memory):
        return stack, storage, memory

    def jumpi(self, global_variables, stack, storage, memory):
        return stack, storage, memory

    def pc(self, global_variables, stack, storage, memory):
        return stack, storage, memory

    def msize(self, global_variables, stack, storage, memory):
        return stack, storage, memory

    def gas(self, global_variables, stack, storage, memory):
        return stack, storage, memory

    def jumpdest(self, global_variables, stack, storage, memory):
        return stack, storage, memory

    # Push Operations
    def push(self, n, global_variables, stack, storage, memory):
        stack.append(n.zfill(64))
        #print("stack", stack, "\n")
        return stack, storage, memory

    # Duplicate Operations
    def dup(self, n, global_variables, stack, storage, memory):
        return stack, storage, memory

    # Exchange Operations
    def swap(self, n, global_variables, stack, storage, memory):
        return stack, storage, memory

    # Logging
    def log0(self, global_variables, stack, storage, memory):
        return stack, storage, memory

    def log1(self, global_variables, stack, storage, memory):
        return stack, storage, memory

    def log2(self, global_variables, stack, storage, memory):
        return stack, storage, memory

    def log3(self, global_variables, stack, storage, memory):
        return stack, storage, memory

    def log4(self, global_variables, stack, storage, memory):
        return stack, storage, memory

    # System
    def create(self, global_variables, stack, storage, memory):
        return stack, storage, memory

    def call(self, global_variables, stack, storage, memory):
        return stack, storage, memory

    def callcode(self, global_variables, stack, storage, memory):
        return stack, storage, memory

    def Return(self, global_variables, stack, storage, memory):
        return stack, storage, memory

    def delegatecall(self, global_variables, stack, storage, memory):
        return stack, storage, memory

    def create2(self, global_variables, stack, storage, memory):
        return stack, storage, memory

    def staticcall(self, global_variables, stack, storage, memory):
        return stack, storage, memory

    def revert(self, global_variables, stack, storage, memory):
        return stack, storage, memory

    def invalid(self, global_variables, stack, storage, memory):
        return stack, storage, memory

    def selfdestruct(self, global_variables, stack, storage, memory):
        return stack, storage, memory


    def opcode_func(self, instruction, global_variables, stack, storage, memory):
        #print(instruction)
        event = ""
        # Stop and Arithmetic
        if(instruction == "stop"):
            stack, storage, memory, event = self.stop(global_variables, stack, storage, memory)
        elif(instruction == "add"):
            stack, storage, memory, event = self.add(global_variables, stack, storage, memory)
        elif(instruction == "mul"):
            stack, storage, memory, event = self.mul(global_variables, stack, storage, memory)
        elif(instruction == "sub"):
            stack, storage, memory, event = self.sub(global_variables, stack, storage, memory)
        elif(instruction == "div"):
            stack, storage, memory, event = self.div(global_variables, stack, storage, memory)
        elif(instruction == "sdiv"):
            stack, storage, memory, event = self.sdiv(global_variables, stack, storage, memory)
        elif(instruction == "mod"):
            stack, storage, memory, event = self.mod(global_variables, stack, storage, memory)
        elif(instruction == "smod"):
            stack, storage, memory, event = self.smod(global_variables, stack, storage, memory)
        elif(instruction == "addmod"):
            stack, storage, memory, event = self.addmod(global_variables, stack, storage, memory)
        elif(instruction == "mulmod"):
            stack, storage, memory, event = self.mulmod(global_variables, stack, storage, memory)
        elif(instruction == "exp"):
            stack, storage, memory, event = self.exp(global_variables, stack, storage, memory)
        elif(instruction == "signextend"):
            stack, storage, memory, event = self.signextend(global_variables, stack, storage, memory)

        # Comparison and Bitwise Logic
        elif(instruction == "lt"):
            stack, storage, memory, event = self.lt(global_variables, stack, storage, memory)
        elif(instruction == "gt"):
            stack, storage, memory, event = self.gt(global_variables, stack, storage, memory)
        elif(instruction == "slt"):
            stack, storage, memory, event = self.slt(global_variables, stack, storage, memory)
        elif(instruction == "sgt"):
            stack, storage, memory, event = self.sgt(global_variables, stack, storage, memory)
        elif(instruction == "eq"):
            stack, storage, memory, event = self.eq(global_variables, stack, storage, memory)
        elif(instruction == "iszero"):
            stack, storage, memory, event = self.iszero(global_variables, stack, storage, memory)
        elif(instruction == "and"):
            stack, storage, memory, event = self.And(global_variables, stack, storage, memory)
        elif(instruction == "or"):
            stack, storage, memory, event = self.Or(global_variables, stack, storage, memory)
        elif(instruction == "xor"):
            stack, storage, memory, event = self.xor(global_variables, stack, storage, memory)
        elif(instruction == "not"):
            stack, storage, memory, event = self.Not(global_variables, stack, storage, memory)
        elif(instruction == "byte"):
            stack, storage, memory, event = self.Byte(global_variables, stack, storage, memory)
        elif(instruction == "shl"):
            stack, storage, memory, event = self.shl(global_variables, stack, storage, memory)
        elif(instruction == "shr"):
            stack, storage, memory, event = self.shr(global_variables, stack, storage, memory)
        elif(instruction == "sar"):
            stack, storage, memory, event = self.sar(global_variables, stack, storage, memory)

        # Sha3
        elif(instruction == "sha3"):
            stack, storage, memory, event = self.sha3(global_variables, stack, storage, memory)

        # Environment Information
        elif(instruction == "address"):
            stack, storage, memory, event = self.address(global_variables, stack, storage, memory)
        elif(instruction == "balance"):
            stack, storage, memory, event = self.balance(global_variables, stack, storage, memory)
        elif(instruction == "origin"):
            stack, storage, memory, event = self.origin(global_variables, stack, storage, memory)
        elif(instruction == "caller"):
            stack, storage, memory, event = self.caller(global_variables, stack, storage, memory)
        elif(instruction == "callvalue"):
            stack, storage, memory, event = self.callvalue(global_variables, stack, storage, memory)
        elif(instruction == "calldataload"):
            stack, storage, memory, event = self.calldataload(global_variables, stack, storage, memory)
        elif(instruction == "calldatasize"):
            stack, storage, memory, event = self.calldatasize(global_variables, stack, storage, memory)
        elif(instruction == "calldatacopy"):
            stack, storage, memory, event = self.calldatacopy(global_variables, stack, storage, memory)
        elif(instruction == "codesize"):
            stack, storage, memory, event = self.codesize(global_variables, stack, storage, memory)
        elif(instruction == "codecopy"):
            stack, storage, memory, event = self.codecopy(global_variables, stack, storage, memory)
        elif(instruction == "gasprice"):
            stack, storage, memory, event = self.gasprice(global_variables, stack, storage, memory)
        elif(instruction == "extcodesize"):
            stack, storage, memory, event = self.extcodesize(global_variables, stack, storage, memory)
        elif(instruction == "extcodecopy"):
            stack, storage, memory, event = self.extcodecopy(global_variables, stack, storage, memory)
        elif(instruction == "returndatasize"):
            stack, storage, memory, event = self.returndatasize(global_variables, stack, storage, memory)
        elif(instruction == "returndatacopy"):
            stack, storage, memory, event = self.returndatacopy(global_variables, stack, storage, memory)
        elif(instruction == "extcodehash"):
            stack, storage, memory, event = self.extcodehash(global_variables, stack, storage, memory)

        # Block Information
        elif(instruction == "blockhash"):
            stack, storage, memory, event = self.blockhash(global_variables, stack, storage, memory)
        elif(instruction == "coinbase"):
            stack, storage, memory, event = self.coinbase(global_variables, stack, storage, memory)
        elif(instruction == "timestamp"):
            stack, storage, memory, event = self.timestamp(global_variables, stack, storage, memory)
        elif(instruction == "number"):
            stack, storage, memory, event = self.number(global_variables, stack, storage, memory)
        elif(instruction == "difficulty"):
            stack, storage, memory, event = self.difficulty(global_variables, stack, storage, memory)
        elif(instruction == "gaslimit"):
            stack, storage, memory, event = self.gaslimit(global_variables, stack, storage, memory)
        elif(instruction == "chainid"):
            stack, storage, memory, event = self.chainid(global_variables, stack, storage, memory)
        elif(instruction == "selfbalance"):
            stack, storage, memory, event = self.selfbalance(global_variables, stack, storage, memory)    

        # Stack, Memory, Storage and Flow operations
        elif(instruction == "pop"):
            stack, storage, memory, event = self.pop(global_variables, stack, storage, memory)
        elif(instruction == "mload"):
            stack, storage, memory, event = self.mload(global_variables, stack, storage, memory)
        elif(instruction == "mstore"):
            stack, storage, memory, event = self.mstore(global_variables, stack, storage, memory)
        elif(instruction == "mstore8"):
            stack, storage, memory, event = self.mstore8(global_variables, stack, storage, memory)
        elif(instruction == "sload"):
            stack, storage, memory, event = self.sload(global_variables, stack, storage, memory)
        elif(instruction == "sstore"):
            stack, storage, memory, event = self.sstore(global_variables, stack, storage, memory)
        elif(instruction == "jump"):
            stack, storage, memory, event = self.jump(global_variables, stack, storage, memory)
        elif(instruction == "jumpi"):
            stack, storage, memory, event = self.jumpi(global_variables, stack, storage, memory)
        elif(instruction == "pc"):
            stack, storage, memory, event = self.pc(global_variables, stack, storage, memory)
        elif(instruction == "msize"):
            stack, storage, memory, event = self.msize(global_variables, stack, storage, memory)
        elif(instruction == "gas"):
            stack, storage, memory, event = self.gas(global_variables, stack, storage, memory)
        elif(instruction == "jumpdest"):
            stack, storage, memory, event = self.jumpdest(global_variables, stack, storage, memory)

        # PUSH operations
        elif("push" in instruction):
            stack, storage, memory, event = self.push(instruction.split(" ")[1], global_variables, stack, storage, memory)

        # DUP operations
        elif("dup" in instruction):
            stack, storage, memory, event = self.dup(int(instruction.split(" ")[0].replace("dup","")),global_variables, stack, storage, memory)

        # PUSH operations
        elif("swap" in instruction):
            stack, storage, memory, event = self.swap(int(instruction.split(" ")[0].replace("swap","")),global_variables, stack, storage, memory)

        # Logging
        elif(instruction == "log0"):
            stack, storage, memory, event = self.log0(global_variables, stack, storage, memory)
        elif(instruction == "log1"):
            stack, storage, memory, event = self.log1(global_variables, stack, storage, memory)
        elif(instruction == "log2"):
            stack, storage, memory, event = self.log2(global_variables, stack, storage, memory)
        elif(instruction == "log3"):
            stack, storage, memory, event = self.log3(global_variables, stack, storage, memory)
        elif(instruction == "log4"):
            stack, storage, memory, event = self.log4(global_variables, stack, storage, memory)

        # System
        elif(instruction == "create"):
            stack, storage, memory, event = self.create(global_variables, stack, storage, memory)
        elif(instruction == "call"):
            stack, storage, memory, event = self.call(global_variables, stack, storage, memory)
        elif(instruction == "callcode"):
            stack, storage, memory, event = self.callcode(global_variables, stack, storage, memory)
        elif(instruction == "return"):
            stack, storage, memory, event = self.Return(global_variables, stack, storage, memory)
        elif(instruction == "delegatecall"):
            stack, storage, memory, event = self.delegatecall(global_variables, stack, storage, memory)
        elif(instruction == "create2"):
            stack, storage, memory, event = self.create2(global_variables, stack, storage, memory)
        elif(instruction == "staticcall"):
            stack, storage, memory, event = self.staticcall(global_variables, stack, storage, memory)
        elif(instruction == "revert"):
            stack, storage, memory, event = self.revert(global_variables, stack, storage, memory)
        elif(instruction == "invalid"):
            stack, storage, memory, event = self.invalid(global_variables, stack, storage, memory)
        elif(instruction == "selfdestruct"):
            stack, storage, memory, event = self.selfdestruct(global_variables, stack, storage, memory)


        return stack, storage, memory, event

