import web3

class EVMInstructions():
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

    def readMemory(self, memory, offset, size):
        memory_data = ""
        # read the bytes from memory
        # you may have to read from multiple addresses
        try:
            # make sure the offset is a hex string
            offset = format(offset, "064x")
        except:
            pass
        while(size > 0):
            try:
                print(offset, memory_data, size)
                # get the value from memory
                if(size >= 32):
                    memory_data += memory[offset]
                else:
                    # the last bytes man not occupy the full 32 bytes
                    # at the memory address
                    # read from MSB
                    memory_data += memory[offset][:(size*2)]
                offsetvalue = int(offset, 16)
                # read the next memory address
                offsetvalue += 1
                offset = format(offsetvalue, "064x")
                # read 32 bytes, so subtract them
                size -= 32
            except:
                break
        return memory_data

    def writeMemory(self, memory, offset, size, data):
        index = 0
        # write the bytes to memory
        # you may have to write to multiple addresses
        try:
            # make sure the offset is a hex string
            offset = format(offset, "064x")
        except:
            pass
        while(size > 0):
            try:
                # write 32 bytes to a memory address
                if(size >= 32):
                    # We're dealing with hexstrings so it's 32 bytes * 2
                    memory[offset] = data[index:index+64]
                else:
                    # move the last of the bytes into memory
                    memory[offset] = data[index:index+(size*2)] # .zfill(64)  zero filling causes problems. calldata as an example
                offsetvalue = int(offset, 16)
                # read the next memory address
                offsetvalue += 1
                offset = format(offsetvalue, "064x")
                # wrote 32 bytes, so subtract them
                size -= 32
                # this is the index into the hex string, so 32*2
                index += 64
            except Exception as e:
                print(e)
        return memory

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
            overflow = "overflow add"
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
            overflow = "overflow mul"
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
            underflow = "underflow sub"
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
            event = "signed division by 0 returns 0"
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
            overflow = "overflow exp"
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
        # Get the 2 values from the stack
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
        # Get the 2 values from the stack
        shift = stack.pop()
        value = stack.pop()
        # Convert the hex strings to integer
        shift = int(shift, 16)
        value = int(value, 16)
        event = ""

        if(shift >= 256):
            result = 0
        else:
            result = (value << shift) & ((2**256) - 1)
        # Convert the int to a 32 byte hex string
        stack.append(format(result, "064x"))
        return stack, storage, memory, event

    def shr(self, global_variables, stack, storage, memory):
        # Get the 2 values from the stack
        shift = stack.pop()
        value = stack.pop()
        # Convert the hex strings to integer
        shift = int(shift, 16)
        value = int(value, 16)
        event = ""

        if(shift >= 256):
            result = 0
        else:
            result = (value >> shift) & ((2**256) - 1)
        # Convert the int to a 32 byte hex string
        stack.append(format(result, "064x"))
        return stack, storage, memory, event

    def sar(self, global_variables, stack, storage, memory):
        # Get the 2 values from the stack
        shift = stack.pop()
        value = stack.pop()
        # Convert the hex strings to integer
        shift = int(shift, 16)
        value = int(value, 16)
        event = ""
        
        # Turn ints into 2's complement
        if(value < 2**255):
            pass
        else:  # AKA the MSB is 1, so it's a signed number
            value = value - 2**256
 
        if(shift >= 256):
            if(value >= 0):
                result = 0
            else:
                result = (2**255) - 1
        else:
            result = (value >> shift) & ((2**256) - 1)
        # Convert the int to a 32 byte hex string
        stack.append(format(result, "064x"))
        return stack, storage, memory, event

    # SHA
    def sha3(self, global_variables, stack, storage, memory):
        # Get the 2 values from the stack
        offset = stack.pop()
        size = stack.pop()
        # Convert the hex strings to integer
        size = int(size, 16)
        event = ""

        if(size > 32):  # assume the size can not be greater than 32
            result = "00".zfill(64)
            event = "SHA3 called with size > 32"
        else:
            data = memory[offset]
            data = data[-size*2:]  # get the least significant bytes
            result = web3.Web3.keccak(hexstr=data).hex().replace("0x","").zfill(64)
        
        # Convert the int to a 32 byte hex string
        stack.append(result)
        return stack, storage, memory, event

    # Environment Information
    def address(self, global_variables, stack, storage, memory):
        # get the contract's address
        event = ""
        contract_address = global_variables["contract.address"].replace("0x","").zfill(64)
        # add it to the stack
        stack.append(contract_address)
        return stack, storage, memory, event

    def balance(self, global_variables, stack, storage, memory):
        # get the 1 value from the stack
        address = stack.pop()
        event = ""

        # remove the 0x if the address starts w/ that
        address = address.replace("0x","")

        # Make sure it's 32 bytes long
        address = address.zfill(64)
        # get the balance of the address
        try:
            balance = int(global_variables["balances"][address], 16)
        except:
            balance = 0

        # add the result to the stack
        stack.append(format(balance, "064x"))
        return stack, storage, memory, event

    def origin(self, global_variables, stack, storage, memory):
        # get the contract's origin
        event = ""
        tx_origin = global_variables["tx.origin"].replace("0x","").zfill(64)
        # add it to the stack
        stack.append(tx_origin)
        return stack, storage, memory, event

    def caller(self, global_variables, stack, storage, memory):
        # get the contract's origin
        event = ""
        caller = global_variables["msg.sender"].replace("0x","").zfill(64)
        # add it to the stack
        stack.append(caller)
        return stack, storage, memory, event

    def callvalue(self, global_variables, stack, storage, memory):
        # get the value sent to the contract
        event = ""
        call_value = int(global_variables["msg.value"])
        
        # add it to the stack
        stack.append(format(call_value, "064x"))
        return stack, storage, memory, event

    def calldataload(self, global_variables, stack, storage, memory):
        # get the offset argument
        offset = stack.pop()
        event = ""

        offset = int(offset, 16)

        calldata = global_variables["calldata"]
        # if calldata is empty then just return 0s
        if(calldata == ""):
            calldata = "00".zfill(64)
        else:
            # if calldata starts w/ 0x then remove it
            calldata = calldata.replace("0x","")

            # get 32 bytes of the calldata starting at the provided offset
            # Check if the 32 bytes extend past the end of our value

            # multiply offset by 2 because it's a byte offset and we are using a hex string which is 2 characters ber byte
            if((offset*2)+64 > len(calldata)):
                calldata = calldata[(offset*2):]
                # pad the right side w/ zeros
                # this is just some trickiness to do that
                calldata = calldata[::-1].zfill(64)[::-1]
            # elif the offset is just larger than our data return 00s
            elif((offset*2) > len(calldata)):
                calldata = "00".zfill(64)
            else:
                # normal scenario
                calldata = calldata[(offset*2):(offset*2)+64]

        # add it to the stack
        stack.append(calldata)
        return stack, storage, memory, event

    def calldatasize(self, global_variables, stack, storage, memory):
        # get the calldata global variable
        calldata = global_variables["calldata"]
        event = ""

        # remove the "0x" if it exists
        calldata = calldata.replace("0x","")

        # get the length of the calldata in bytes
        size = int(len(calldata) / 2)

        # add it to the stack
        stack.append(format(size, "064x"))
        return stack, storage, memory, event

    def calldatacopy(self, global_variables, stack, storage, memory):
        destOffset = stack.pop()
        offset = stack.pop()
        size = stack.pop()
        event = ""

        calldata = global_variables["calldata"]

        # get the required bytes from calldata
        size = int(size, 16)
        offset = int(offset, 16)

        # if calldata is empty then just return 0s
        if(calldata == ""):
            calldata = "00".zfill(64)
        else:
            # if calldata starts w/ 0x then remove it
            calldata = calldata.replace("0x","")

            # get 32 bytes of the calldata starting at the provided offset
            # Check if the 32 bytes extend past the end of our value

            # multiply offset by 2 because it's a byte offset and we are using a hex string which is 2 characters ber byte
            if((offset*2)+64 > len(calldata)):
                calldata = calldata[(offset*2):]
                # pad the right side w/ zeros
                # this is just some trickiness to do that
                calldata = calldata[::-1].zfill(64)[::-1]
            # elif the offset is just larger than our data return 00s
            elif((offset*2) > len(calldata)):
                calldata = "00".zfill(64)
            else:
                # normal scenario
                calldata = calldata[(offset*2):(offset*2)+64]

        # just get the need bytes of calldata
        calldata = calldata[:(size*2)]

        # copy them to memory
        destOffset = int(destOffset, 16)
        destOffset = format(destOffset, "064x")

        # if there's stuff in the memory address
        if(destOffset in memory.keys()):
            # replace the first few bytes but keep the rest
            memory[destOffset] = calldata + memory[destOffset][len(calldata):]
        else:
            memory[destOffset] = calldata
        
        return stack, storage, memory, event

    def codesize(self, global_variables, stack, storage, memory):
        # get the contract's bytecode
        event = ""
        codesize = global_variables["bytecode"]
        codesize = int(len(codesize)/2)

        stack.append(format(codesize, "064x"))
        return stack, storage, memory, event

    def codecopy(self, global_variables, stack, storage, memory):
        destOffset = stack.pop()
        offset = stack.pop()
        size = stack.pop()
        event = ""

        code = global_variables["bytecode"]

        # get the required bytes from calldata
        size = int(size, 16)
        offset = int(offset, 16)

        memory = self.writeMemory(memory, destOffset, size, code[(offset*2):])
        
        return stack, storage, memory, event

    def gasprice(self, global_variables, stack, storage, memory):
        event = ""

        gasprice = int(global_variables["gas.price"])

        stack.append(format(gasprice, "064x"))
        return stack, storage, memory, event

    def extcodesize(self, global_variables, stack, storage, memory):
        # get the contract's bytecode
        extcode_address = stack.pop()
        event = ""
        try:
            codesize = global_variables["extcode"][extcode_address]
            codesize = int(len(codesize)/2)
        except:
            codesize = 0

        stack.append(format(codesize, "064x"))
        return stack, storage, memory, event


    def extcodecopy(self, global_variables, stack, storage, memory):
        extcode_address = stack.pop()
        destOffset = stack.pop()
        offset = stack.pop()
        size = stack.pop()
        event = ""

        try:
            code = global_variables["extcode"][extcode_address]
        except:
            code = ""

        # get the required bytes from calldata
        size = int(size, 16)
        offset = int(offset, 16)

        # if calldata is empty then just return 0s
        if(code == ""):
            code = "00".zfill(64)
        else:
            # if calldata starts w/ 0x then remove it
            code = code.replace("0x","")

            # get 32 bytes of the calldata starting at the provided offset
            # Check if the 32 bytes extend past the end of our value

            # multiply offset by 2 because it's a byte offset and we are using a hex string which is 2 characters ber byte
            if((offset*2)+64 > len(code)):
                code = code[(offset*2):]
                # pad the right side w/ zeros
                # this is just some trickiness to do that
                code = code[::-1].zfill(64)[::-1]
            # elif the offset is just larger than our data return 00s
            elif((offset*2) > len(code)):
                code = "00".zfill(64)
            else:
                # normal scenario
                code = code[(offset*2):(offset*2)+64]

        # just get the needed bytes of calldata
        code = code[:(size*2)]

        # copy them to memory
        destOffset = int(destOffset, 16)
        destOffset = format(destOffset, "064x")

        # if there's stuff in the memory address
        if(destOffset in memory.keys()):
            # replace the first few bytes but keep the rest
            memory[destOffset] = code + memory[destOffset][len(code):]
        else:
            memory[destOffset] = code
        
        return stack, storage, memory, event


    def returndatasize(self, global_variables, stack, storage, memory):
        event = ""
        return stack, storage, memory, event

    def returndatacopy(self, global_variables, stack, storage, memory):
        event = ""
        return stack, storage, memory, event

    def extcodehash(self, global_variables, stack, storage, memory):
        # Get the target address
        address = stack.pop()
        event = ""

        try:
            extcode = global_variables[address]
            result = web3.Web3.keccak(hexstr=extcode).hex()
        except:
            result = format(0, "064x")
            event = "extcodehash returns 0"
        
        # Convert the int to a 32 byte hex string
        stack.append(result)
        return stack, storage, memory, event

    # Block Information
    def blockhash(self, global_variables, stack, storage, memory):
        # get the block hash
        event = ""
        blockhash = global_variables["block.hash"].replace("0x","").zfill(64)
        # add it to the stack
        stack.append(blockhash)
        return stack, storage, memory, event

    def coinbase(self, global_variables, stack, storage, memory):
        # get the block miner's address
        event = ""
        miners_addr = global_variables["block.coinbase"].replace("0x","").zfill(64)
        # add it to the stack
        stack.append(miners_addr)
        return stack, storage, memory, event

    def timestamp(self, global_variables, stack, storage, memory):
        # get the block timestamp
        event = ""
        timestamp = int(global_variables["block.timestamp"])
        # add it to the stack
        stack.append(format(timestamp, "064x"))
        return stack, storage, memory, event

    def number(self, global_variables, stack, storage, memory):
        # get the block number
        event = ""
        block_num = int(global_variables["block.number"])
        # add it to the stack
        stack.append(format(block_num, "064x"))
        return stack, storage, memory, event

    def difficulty(self, global_variables, stack, storage, memory):
        # get the difficulty
        event = ""
        difficulty = int(global_variables["block.difficulty"])
        # add it to the stack
        stack.append(format(difficulty, "064x"))
        return stack, storage, memory, event

    def gaslimit(self, global_variables, stack, storage, memory):
        # get the gas limit
        event = ""
        gas_limit = int(global_variables["block.gaslimit"])
        # add it to the stack
        stack.append(format(gas_limit, "064x"))
        return stack, storage, memory, event

    def chainid(self, global_variables, stack, storage, memory):
        # get the chain id
        event = ""
        chain_id = int(global_variables["block.chainid"])
        # add it to the stack
        stack.append(format(chain_id, "064x"))
        return stack, storage, memory, event

    def selfbalance(self, global_variables, stack, storage, memory):
        # get the contract's balance
        event = ""
        try:
            contract_balance = int(global_variables["balances"][global_variables["contract.address"]], 16)
        except:
            contract_balance = 0
        # add it to the stack
        stack.append(format(contract_balance, "064x"))
        return stack, storage, memory, event

    # Stack, Memory, Storage and Flow Operations
    def pop(self, global_variables, stack, storage, memory):
        event = ""
        # just pop a value off the stack
        value = stack.pop()
        return stack, storage, memory, event

    def mload(self, global_variables, stack, storage, memory):
        # Get the offset from the stack
        offset = stack.pop()

        # Get the value from memory, if it doesn't exist
        # in the dict then just return zeros
        try:
            value = memory[offset]
        except:
            value = "00"

        event = ""

        value = value.zfill(64)
        stack.append(value)
        
        return stack, storage, memory, event

    def mstore(self, global_variables, stack, storage, memory):
        # Get the 2 values from the stack
        offset = stack.pop()
        value = stack.pop()

        event = ""

        # Update value in memory dict
        memory[offset] = value.zfill(64)
        
        return stack, storage, memory, event

    def mstore8(self, global_variables, stack, storage, memory):
        # Get the 2 values from the stack
        offset = stack.pop()
        value = stack.pop()

        # Get the least significant byte and store that in memory
        lsb = value[-2:]
        event = ""

        # Update value in memory dict
        memory[offset] = lsb.zfill(64)
        
        return stack, storage, memory, event

    def sload(self, global_variables, stack, storage, memory):
        # Get the offset from the stack
        slot = stack.pop()

        # Get the value from storage, if it doesn't exist
        # in the dict then just return zeros
        try:
            value = storage[slot]
        except:
            value = "00"

        event = ""

        value = value.zfill(64)
        stack.append(value)
        
        return stack, storage, memory, event

    def sstore(self, global_variables, stack, storage, memory):
        # Get the 2 values from the stack
        slot = stack.pop()
        value = stack.pop()

        event = ""

        # Update value in storage dict
        storage[slot] = value.zfill(64)
        
        return stack, storage, memory, event

    def jump(self, pc, instructions, global_variables, stack, storage, memory):
        event = ""
        offset = stack.pop()
        offset = int(offset, 16)
        if(str(offset) in instructions):
            # make sure destination is jumpdest
            if(instructions[str(offset)][0] == "jumpdest"):
                pc = offset
        else:
            event = "invalid jump"
            
        return pc, stack, storage, memory, event

    def jumpi(self, pc, instructions, global_variables, stack, storage, memory):
        # Check if 2nd arg is != 0
        event = ""
        offset = stack.pop()
        condition = stack.pop()  # if not 0, then jump
        offset = int(offset, 16)
        condition = int(condition, 16)
        if(condition != 0):
            # condition != 0 so jump
            if(str(offset) in instructions):
                # make sure destination is jumpdest
                if(instructions[str(offset)][0] == "jumpdest"):
                    pc = offset
            else:
                event = "invalid jump"
        else:
            # condition = 0 so just go onto next instruction
            pc += 1
            
        return pc, stack, storage, memory, event

    def pc(self, pc, global_variables, stack, storage, memory):
        # Code in runBytecode method
        event = ""
        stack.append(format(pc, "064x"))
        return stack, storage, memory, event

    def msize(self, global_variables, stack, storage, memory):
        event = ""
        memory_addresses = memory.keys()
        largest_value = 0
        # get the largest memory address and return that
        for address in memory_addresses:
            value = int(address, 16)
            if(value > largest_value):
                largest_value = value
        stack.append(format(largest_value, "064x"))
        return stack, storage, memory, event

    def gas(self, global_variables, stack, storage, memory):
        event = ""
        stack.append(format(global_variables["gas"], "064x"))
        return stack, storage, memory, event

    def jumpdest(self, global_variables, stack, storage, memory):
        event = ""
        return stack, storage, memory, event

    # Push Operations
    def push(self, n, global_variables, stack, storage, memory):
        event = ""
        stack.append(n.zfill(64))
        #print("stack", stack, "\n")
        return stack, storage, memory, event

    # Duplicate Operations
    def dup(self, n, global_variables, stack, storage, memory):
        event = ""
        stack.append(stack[-n])
        
        return stack, storage, memory, event

    # Exchange Operations
    def swap(self, n, global_variables, stack, storage, memory):
        event = ""
        stack[-1], stack[-1 - n] = stack[-1 - n], stack[-1]
        return stack, storage, memory, event

    # Logging
    def log0(self, global_variables, stack, storage, memory):
        event = "log0"
        # Get the offset from the stack
        offset = stack.pop()
        size = stack.pop()
        size = int(size, 16)

        # Get the value from memory, if it doesn't exist
        # in the dict then just return zeros
        try:
            value = memory[offset]
            if(size > 32):  # assume the size can not be greater than 32
                result = "00".zfill(64)
                event = "LOG called with size > 32"
            else:
                value = value[-size*2:]  # get the least significant bytes
        except:
            value = "00"

        value = value.zfill(64)
        # What to do with this?
        
        return stack, storage, memory, event

    def log1(self, global_variables, stack, storage, memory):
        event = "log1"
        # Get the offset from the stack
        offset = stack.pop()
        size = stack.pop()
        size = int(size, 16)
        topic = stack.pop()

        # Get the value from memory, if it doesn't exist
        # in the dict then just return zeros
        try:
            value = memory[offset]
            if(size > 32):  # assume the size can not be greater than 32
                result = "00".zfill(64)
                event = "LOG called with size > 32"
            else:
                value = value[-size*2:]  # get the least significant bytes
        except:
            value = "00"

        value = value.zfill(64)
        # topic
        # What to do with this?

        return stack, storage, memory, event

    def log2(self, global_variables, stack, storage, memory):
        event = "log2"
        # Get the offset from the stack
        offset = stack.pop()
        size = stack.pop()
        size = int(size, 16)
        topic = stack.pop()
        topic2 = stack.pop()

        # Get the value from memory, if it doesn't exist
        # in the dict then just return zeros
        try:
            value = memory[offset]
            if(size > 32):  # assume the size can not be greater than 32
                result = "00".zfill(64)
                event = "LOG called with size > 32"
            else:
                value = value[-size*2:]  # get the least significant bytes
        except:
            value = "00"

        value = value.zfill(64)
        # topic
        # topic2
        # What to do with this?
        
        return stack, storage, memory, event

    def log3(self, global_variables, stack, storage, memory):
        event = "log3"
        # Get the offset from the stack
        offset = stack.pop()
        size = stack.pop()
        size = int(size, 16)
        topic = stack.pop()
        topic2 = stack.pop()
        topic3 = stack.pop()

        # Get the value from memory, if it doesn't exist
        # in the dict then just return zeros
        try:
            value = memory[offset]
            if(size > 32):  # assume the size can not be greater than 32
                result = "00".zfill(64)
                event = "LOG called with size > 32"
            else:
                value = value[-size*2:]  # get the least significant bytes
        except:
            value = "00"

        value = value.zfill(64)
        # topic
        # topic2
        # topic3
        # What to do with this?
        
        return stack, storage, memory, event

    def log4(self, global_variables, stack, storage, memory):
        event = "log4"
        # Get the offset from the stack
        offset = stack.pop()
        size = stack.pop()
        size = int(size, 16)
        topic = stack.pop()
        topic2 = stack.pop()
        topic3 = stack.pop()
        topic4 = stack.pop()

        # Get the value from memory, if it doesn't exist
        # in the dict then just return zeros
        try:
            value = memory[offset]
            if(size > 32):  # assume the size can not be greater than 32
                result = "00".zfill(64)
                event = "LOG called with size > 32"
            else:
                value = value[-size*2:]  # get the least significant bytes
        except:
            value = "00"

        value = value.zfill(64)
        # topic
        # topic2
        # topic3
        # topic4
        # What to do with this?
        
        return stack, storage, memory, event

    # System
##    def create(self, global_variables, stack, storage, memory):
##        event = ""
##        return stack, storage, memory, event

##    def call(self, global_variables, stack, storage, memory):
##        event = ""
##        return stack, storage, memory, event

##    def callcode(self, global_variables, stack, storage, memory):
##        event = ""
##        return stack, storage, memory, event

    def Return(self, global_variables, stack, storage, memory):
        event = ""
        return stack, storage, memory, event

##    def delegatecall(self, global_variables, stack, storage, memory):
##        event = ""
##        return stack, storage, memory, event

##    def create2(self, global_variables, stack, storage, memory):
##        event = ""
##        return stack, storage, memory, event

##    def staticcall(self, global_variables, stack, storage, memory):
##        event = ""
##        return stack, storage, memory, event

    def revert(self, global_variables, stack, storage, memory):
        event = ""
        return stack, storage, memory, event

    def invalid(self, global_variables, stack, storage, memory):
        event = ""
        return stack, storage, memory, event

    def selfdestruct(self, global_variables, stack, storage, memory):
        event = ""
        return stack, storage, memory, event


    def opcode_func(self, pc, instructions, instruction, global_variables, stack, storage, memory):
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
            pc, stack, storage, memory, event = self.jump(pc, instructions, global_variables, stack, storage, memory)
            # Return here so the program counter isn't incremented
            return pc, stack, storage, memory, event
        elif(instruction == "jumpi"):
            pc, stack, storage, memory, event = self.jumpi(pc, instructions, global_variables, stack, storage, memory)
            # Return here so the program counter isn't incremented
            return pc, stack, storage, memory, event
        elif(instruction == "pc"):
            stack, storage, memory, event = self.pc(pc, global_variables, stack, storage, memory)
        elif(instruction == "msize"):
            stack, storage, memory, event = self.msize(global_variables, stack, storage, memory)
        elif(instruction == "gas"):
            stack, storage, memory, event = self.gas(global_variables, stack, storage, memory)
        elif(instruction == "jumpdest"):
            stack, storage, memory, event = self.jumpdest(global_variables, stack, storage, memory)

        # PUSH operations
        elif("push" in instruction):
            stack, storage, memory, event = self.push(instruction.split(" ")[1], global_variables, stack, storage, memory)
            # push instructions can be more than 1 byte
            # so modify the program counter here
            inc = int(len(instructions[str(pc)][1])/2)
            pc += inc
            return pc, stack, storage, memory, event

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
            #stack, storage, memory, event = self.create(global_variables, stack, storage, memory)
            pass
        elif(instruction == "call"):
            #stack, storage, memory, event = self.call(global_variables, stack, storage, memory)
            pass
        elif(instruction == "callcode"):
            #stack, storage, memory, event = self.callcode(global_variables, stack, storage, memory)
            pass
        elif(instruction == "return"):
            stack, storage, memory, event = self.Return(global_variables, stack, storage, memory)
        elif(instruction == "delegatecall"):
            #stack, storage, memory, event = self.delegatecall(global_variables, stack, storage, memory)
            pass
        elif(instruction == "create2"):
            #stack, storage, memory, event = self.create2(global_variables, stack, storage, memory)
            pass
        elif(instruction == "staticcall"):
            #stack, storage, memory, event = self.staticcall(global_variables, stack, storage, memory)
            pass
        elif(instruction == "revert"):
            stack, storage, memory, event = self.revert(global_variables, stack, storage, memory)
        elif(instruction == "invalid"):
            stack, storage, memory, event = self.invalid(global_variables, stack, storage, memory)
        elif(instruction == "selfdestruct"):
            stack, storage, memory, event = self.selfdestruct(global_variables, stack, storage, memory)

        # increment the program counter
        pc += 1
        return pc, stack, storage, memory, event

