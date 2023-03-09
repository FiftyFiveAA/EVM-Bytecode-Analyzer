import evm_data

# https://github.com/volcano852/pyevm/blob/master/pyevm/

class EVM(evm_data.EVMData):
    def __init__(self):
        # Inherit all the child class methods and properties
        super().__init__()
        

    def parseBytecode(self, bytecode):
        '''
        INPUTS: a hex string of EVM bytecode
        PROCESSING: Parses hex string and turns it into human readable EVM instructions
                    PUSH instructions are more than 1 byte, so they make the parsing a little weird
        OUTPUTS: a list of lists of instructions [[program_counter, human readable instruction, hex bytes of instruction],[...],...]
        '''

        # Turn hexstring into bytes
        bytecode = bytes.fromhex(bytecode)
        # create empty dict for the instructions
        instructions = {}
        # start the program counter at 0    
        program_counter = 0
        # skip_bytes is used for PUSH instructions which are longer than 1 byte
        skip_bytes = 0
        # go through each byte
        for i in range(0, len(bytecode)):
            # if there's a PUSH instruction then skip a couple bytes
            if(skip_bytes > 0):
                skip_bytes -= 1
                continue

            # Try to lookup the instruction in our list
            try:
                instruction = self.opcode_dict[bytecode[i]]
            except:  # else just mark it as "invalid"
                instruction = "invalid"

            # if the instruction is a PUSH then this will store how many bytes are being pushed
            len_push = ""
            if("push" in instruction):
                len_push = int(instruction.replace("push",""))
                
            # if it is not a PUSH instruction
            if(len_push == ""):
                instructions[str(program_counter)] = [instruction, format(bytecode[i], "x")]
                program_counter += 1  # increment program counter like normal
            # else it is a PUSH instruction
            else:
                instructions[str(program_counter)] = [instruction + " " + bytecode[i+1:i+1+len_push].hex(), bytecode[i:i+1+len_push].hex()]
                # skip the next couple bytes
                skip_bytes = len_push
                # update the program_counter to the next instruction
                program_counter += len_push + 1
        # return the list of lists of instructions
        return instructions

    def runBytecode(self, instructions, global_variables, stack, storage, memory):
        end = ""
        return_data = ""

        # max_offset will contain the last instruction
        # we'll use this to see if the contract reaches the end of the code
        all_offsets = instructions.keys()
        max_offset = 0
        for offset in all_offsets:
            if(int(offset) > max_offset):
                max_offset = int(offset)

        # max number of instructions
        # since we aren't implementing gas
        # this is to stop loops that never end
        instruction_counter = 0
        max_num_of_instructions = 10000

        # start the program counter at 0
        pc = 0
        while(1):
            # This is our equivalent to running out of gas
            instruction_counter += 1
            if(instruction_counter > max_num_of_instructions):
                end = "ran out of gas"
                break
            
            print("\n", str(pc), instructions[str(pc)])
            if(instructions[str(pc)][0] == "stop"):
                end = "stop"
                break
            elif(instructions[str(pc)][0] == "return"):
                end = "return"
                offset = stack.pop()
                size = stack.pop()
                size = int(size, 16)
                return_data = ""
                # read the bytes from memory
                # you may have to read from multiple addresses
                while(size > 0):
                    try:
                        return_data += memory[offset]
                        offsetvalue = int(offset, 16)
                        # read the next memory address
                        offsetvalue += 1
                        offset = format(offsetvalue, "064x")
                        # read 32 bytes, so subtract them
                        size -= 32
                    except:
                        break
                break
            elif(instructions[str(pc)][0] == "revert"):
                end = "revert"
                offset = stack.pop()
                size = stack.pop()
                size = int(size, 16)
                return_data = ""
                # read the bytes from memory
                # you may have to read from multiple addresses
                while(size > 0):
                    try:
                        return_data += memory[offset]
                        offsetvalue = int(offset, 16)
                        # read the next memory address
                        offsetvalue += 1
                        offset = format(offsetvalue, "064x")
                        # read 32 bytes, so subtract them
                        size -= 32
                    except:
                        break
                break
            elif(instructions[str(pc)][0] == "invalid"):
                end = "invalid"
                break
            elif(instructions[str(pc)][0] == "create"):
                pass
                #print("DUP")
                #evm2 = EVM()
                #bytecode = "60806040526000340361001157600080fd5b610206806100206000396000f3fe60806040526004361061001e5760003560e01c8063a30da70d14610023575b600080fd5b61002b61002d565b005b610035610106565b610070816000019067ffffffffffffffff16908167ffffffffffffffff168152505034815101815261006d816000015163ffffffff16565b50565b61007861007a565b565b600034146100bd576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016100b490610181565b60405180910390fd5b3373ffffffffffffffffffffffffffffffffffffffff166108fc479081150290604051600060405180830381858888f19350505050158015610103573d6000803e3d6000fd5b50565b604051806020016040528061011a81525090565b6101226101a1565b565b600082825260208201905092915050565b7f646f6e742073656e642066756e64732100000000000000000000000000000000600082015250565b600061016b601083610124565b915061017682610135565b602082019050919050565b6000602082019050818103600083015261019a8161015e565b9050919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052605160045260246000fdfea26469706673582212202984a32427ae50c08b30f852a00a90f1afccf0ee5e5ceeb78f8227cdb1ec28ad64736f6c63430008110033"
                #message, return_data, stack, storage, memory = evm2.main(bytecode, global_variables)
                

        
            # Execute the instruction
            pc, stack, storage, memory, event = self.opcode_func(pc, instructions, instructions[str(pc)][0], global_variables, stack, storage, memory)

            # if the program counter is past the last instruction then break
            if(pc > max_offset):
                break

            # If something special happened like an integer over flow then show that
            if(event != ""):
                print(event)
            events = ["overflow add", "overflow mul", "underflow sub", "divide by 0 returns 0",
                      "signed division by 0 returns 0", "MOD 0 returns 0", "Signed MOD 0 returns 0",
                      "overflow exp", "SHA3 called with size > 32", "invalid jump",
                      "LOG called with size > 32", "extcodehash returns 0"]
        return end, return_data, stack, storage, memory
                
    def main(self, bytecode, global_variables):
        # turn into human readable instructions
        self.instructions = self.parseBytecode(bytecode)
        # Stack
        stack = []

        # Storage
        storage = {}

        # Memory
        memory = {}
        
        message, return_data, stack, storage, memory = self.runBytecode(self.instructions, global_variables, stack, storage, memory)
        print(message, return_data)
        return message, return_data, stack, storage, memory

evm = EVM()
    
bytecode = "60806040526000340361001157600080fd5b610206806100206000396000f3fe60806040526004361061001e5760003560e01c8063a30da70d14610023575b600080fd5b61002b61002d565b005b610035610106565b610070816000019067ffffffffffffffff16908167ffffffffffffffff168152505034815101815261006d816000015163ffffffff16565b50565b61007861007a565b565b600034146100bd576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016100b490610181565b60405180910390fd5b3373ffffffffffffffffffffffffffffffffffffffff166108fc479081150290604051600060405180830381858888f19350505050158015610103573d6000803e3d6000fd5b50565b604051806020016040528061011a81525090565b6101226101a1565b565b600082825260208201905092915050565b7f646f6e742073656e642066756e64732100000000000000000000000000000000600082015250565b600061016b601083610124565b915061017682610135565b602082019050919050565b6000602082019050818103600083015261019a8161015e565b9050919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052605160045260246000fdfea26469706673582212202984a32427ae50c08b30f852a00a90f1afccf0ee5e5ceeb78f8227cdb1ec28ad64736f6c63430008110033"

# Global Variables
global_variables = {"block.chainid":"1",
                    "block.coinbase":"0x0000000000000000000000000000000000000000",
                    "block.difficulty":"0",
                    "block.gaslimit":"6721975",
                    "block.number":"144",
                    "block.timestamp":"1675125106",
                    "block.hash":"0x33045A592007D0C246EF02C2223560DA9522D0CF0F73282C79A1BC8F0BB2C237",
                    "msg.sender":"0x59ad9d5ddf09f2276D5a5A701d9105c3f989D961",
                    "msg.sig":"0xa30da70d",
                    "msg.value":"0",
                    "tx.origin":"0x59ad9d5ddf09f2276D5a5A701d9105c3f989D961",
		    "calldata":"0x0000000000000000000000000000000000000000",
		    "contract.address":"0x9bbfed6889322e016e0a02ee459d306fc19545d8",
		    "balances":{},
		    "bytecode":bytecode,
		    "gas.price":"10",
                    "gas":"1000",
		    "extcode":{},
                    }
        
message, return_data, stack, storage, memory = evm.main(bytecode, global_variables)




