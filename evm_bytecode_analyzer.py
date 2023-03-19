import evm_instructions
import web3
import binascii
import hashlib

# https://github.com/volcano852/pyevm/blob/master/pyevm/

class EVM(evm_instructions.EVMInstructions):
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

    def create(self, global_variables, stack, storage, memory):
        value = stack.pop()  # value in wei to send to the new account
        offset = stack.pop()
        size = stack.pop()

        size = int(size, 16)
        value = int(value, 16)

        # read the new contract's bytecode from memory                
        bytecode_read_from_memory = self.readMemory(memory, offset, size)

        # Calculate the address of the new contract
        new_contract_addr = global_variables["contract.address"]
        new_contract_binary = binascii.unhexlify(new_contract_addr.replace("0x",""))
        # concatentate sender address and nonce
        nonce = 0  # technically this should be the # of contracts the account has created
        new_contract_concat = new_contract_binary + nonce.to_bytes(32, byteorder="big")
        # calculate the hash
        keccak_hash = web3.Web3.keccak(new_contract_concat)
        # get the last 20 bytes
        new_contract_addr = web3.Web3.toChecksumAddress(keccak_hash[-20:].hex())
        # turn into 32 byte hexstring (zero filled)
        new_contract_addr = new_contract_addr.replace("0x","").zfill(64)
        
        # create a copy of the global variables and modify it slightly
        # the new contract will have different bytecode, address, etc...
        global_variables_create = global_variables.copy()
        global_variables_create["msg.sender"] = global_variables_create["contract.address"]
        global_variables_create["msg.value"] = value
        global_variables_create["calldata"] = "0000000000000000000000000000000000000000"
        global_variables_create["contract.address"] = new_contract_addr
        global_variables_create["bytecode"] = bytecode_read_from_memory
        global_variables_create["returndata"] = bytecode_read_from_memory

        # Check if the creator of the new contract has enough eth
        end = ""
        try:
            # get the balance of the creator contract
            creator_addr = global_variables["contract.address"]
            balance_addr = int(global_variables["balances"][creator_addr], 16)
            # make sure it has enough eth to deploy the contract
            if(balance_addr < value):
                end = "CREATE failed not enough ETH"
                return message, end, return_data_2, stack_2, storage_2, memory_2, new_contract_addr, bytecode_read_from_memory, stack, global_variables_create, global_variables
        except:
            end = "CREATE failed not enough ETH"
            return message, end, return_data_2, stack_2, storage_2, memory_2, new_contract_addr, bytecode_read_from_memory, stack, global_variables_create, global_variables
        # Update the balance in the global_variables dict
        # add eth to the new contract
        global_variables["balances"][new_contract_addr] = format(value, "064x")
        # subtract eth from the creator contract
        global_variables["balances"][creator_addr] = format(balance_addr-value, "064x")

        # create a new evm instance
        evm_2 = EVM()     
        # create a new stack
        stack_2 = []
        # create a new storage
        storage_2 = {}
        # create a new memory
        memory_2 = {}
        # start the program counter at 0
        pc_2 = 0
        breakpoints_2 = []
        
        # run the new contract
        message, return_data_2, stack_2, storage_2, memory_2 = evm_2.main(bytecode_read_from_memory, pc_2, breakpoints_2, global_variables_create, stack_2, storage_2, memory_2, "")
        return message, end, return_data_2, stack_2, storage_2, memory_2, new_contract_addr, bytecode_read_from_memory, stack, global_variables_create, global_variables

    def create2(self, global_variables, stack, storage, memory):
        value = stack.pop()  # value in wei to send to the new account
        offset = stack.pop()
        size = stack.pop()
        salt = stack.pop()

        size = int(size, 16)
        value = int(value, 16)

        # read the new contract's bytecode from memory                
        bytecode_read_from_memory = self.readMemory(memory, offset, size)

        # Calculate the address of the new contract
        new_contract_addr = global_variables["contract.address"]
        new_contract_addr_binary = binascii.unhexlify(new_contract_addr.replace("0x",""))
        # turn the contract's bytecode to bytes
        new_contract_bytecode_binary = web3.Web3.keccak(binascii.unhexlify(bytecode_read_from_memory))
        # concat(ff + sender_addr + salt + bytecode)
        new_contract_concat = b"\xff" + new_contract_addr_binary + binascii.unhexlify(salt) + new_contract_bytecode_binary
        # calculate the hash
        keccak_hash = web3.Web3.keccak(new_contract_concat)
        # get the last 20 bytes
        new_contract_addr = web3.Web3.toChecksumAddress(keccak_hash[-20:].hex())
        # turn into 32 byte hexstring (zero filled)
        new_contract_addr = new_contract_addr.replace("0x","").zfill(64)
        
        # create a copy of the global variables and modify it slightly
        # the new contract will have different bytecode, address, etc...
        global_variables_create2 = global_variables.copy()
        global_variables_create2["msg.sender"] = global_variables_create2["contract.address"]
        global_variables_create2["msg.value"] = value
        global_variables_create2["calldata"] = "0000000000000000000000000000000000000000"
        global_variables_create2["contract.address"] = new_contract_addr
        global_variables_create2["bytecode"] = bytecode_read_from_memory
        global_variables_create2["returndata"] = bytecode_read_from_memory

        # Check if the creator of the new contract has enough eth
        end = ""
        try:
            # get the balance of the creator contract
            creator_addr = global_variables["contract.address"]
            balance_addr = int(global_variables["balances"][creator_addr], 16)
            # make sure it has enough eth to deploy the contract
            if(balance_addr < value):
                end = "CREATE2 failed not enough ETH"
                return message, end, return_data_2, stack_2, storage_2, memory_2, new_contract_addr, bytecode_read_from_memory, stack, global_variables_create2, global_variables
        except:
            end = "CREATE2 failed not enough ETH"
            return message, end, return_data_2, stack_2, storage_2, memory_2, new_contract_addr, bytecode_read_from_memory, stack, global_variables_create2, global_variables
        # Update the balance in the global_variables dict
        # add eth to the new contract
        global_variables["balances"][new_contract_addr] = format(value, "064x")
        # subtract eth from the creator contract
        global_variables["balances"][creator_addr] = format(balance_addr-value, "064x")

        # create a new evm instance
        evm_2 = EVM()     
        # create a new stack
        stack_2 = []
        # create a new storage
        storage_2 = {}
        # create a new memory
        memory_2 = {}
        # start the program counter at 0
        pc_2 = 0
        breakpoints_2 = []
        
        # run the new contract
        message, return_data_2, stack_2, storage_2, memory_2 = evm_2.main(bytecode_read_from_memory, pc_2, breakpoints_2, global_variables_create2, stack_2, storage_2, memory_2, "")
        return message, end, return_data_2, stack_2, storage_2, memory_2, new_contract_addr, bytecode_read_from_memory, stack, global_variables_create2, global_variables

    def call(self, global_variables, stack, storage, memory):
        event = ""
        
        gas = stack.pop()  # amount of gas for sub context
        address = stack.pop()  # address to contract to run
        value = stack.pop()  # value in wei to send to the new account
        argsOffset = stack.pop()  # memory offset which contains calldata for subcontext
        argsSize = stack.pop()  # size of calldata
        retOffset = stack.pop()  # memory offset where return data will be stored
        retSize = stack.pop()  # size of return data

        value = int(value, 16)
        argsSize = int(argsSize, 16)
        retSize = int(retSize, 16)

        # read the calldata for the subcontext               
        calldata_read_from_memory = self.readMemory(memory, argsOffset, argsSize)
        
        # create a copy of the global variables and modify it slightly
        # the called contract will have different global variables
        global_variables_call = global_variables.copy()
        global_variables_call["msg.sender"] = global_variables_call["contract.address"]
        global_variables_call["msg.value"] = value
        global_variables_call["calldata"] = calldata_read_from_memory
        global_variables_call["contract.address"] = address
        try:
            # Check if the called contract has bytecode
            called_contract_bytecode = global_variables_call["extcode"][address]
            global_variables_call["bytecode"] = called_contract_bytecode
        except:
            global_variables_call["bytecode"] = 0

        # The called contract doesn't have bytecode so return 0
        no_bytecode = False
        if(global_variables_call["bytecode"] == 0):
            event = "CALL failed, no bytecode at address"
            no_bytecode = True
            message = "revert"

        # Check if the caller has enough eth
        not_enough_eth = False
        try:
            # get the balance of the creator contract
            creator_addr = global_variables["contract.address"]
            balance_addr = int(global_variables["balances"][creator_addr], 16)
            # make sure it has enough eth to deploy the contract
            if(balance_addr < value):
                event = "CALL failed not enough ETH"
                not_enough_eth = True
                message = "revert"
        except:
            event = "CALL failed not enough ETH"
            not_enough_eth = True
            message = "revert"

        # If no errors then call the contract
        if(no_bytecode == False and not_enough_eth == False):
            # Update the balance in the global_variables dict
            # add eth to the called contract
            try:
                # if the called contract already has eth, then add some more
                called_contract_balance = int(global_variables["balances"][address], 16)
                global_variables["balances"][address] = format(called_contract_balance + value, "064x")
            except:
                # else the called contract has no eth
                called_contract_balance = 0
                global_variables["balances"][address] = format(called_contract_balance + value, "064x")
            
            # subtract eth from the creator contract
            global_variables["balances"][creator_addr] = format(balance_addr-value, "064x")

            # create a new evm instance
            evm_2 = EVM()     
            # create a new stack
            stack_2 = []
            # use the contract's storage if it has one, or create a new one if it doesn't
            try:
                storage_2 = global_variables["storage"][address]
            except:
                storage_2 = {}
            # create a new memory
            memory_2 = {}
            # start the program counter at 0
            pc_2 = 0
            breakpoints_2 = []
            
            # run the called contract
            message, return_data_2, stack_2, storage_2, memory_2 = evm_2.main(bytecode_read_from_memory, pc_2, breakpoints_2, global_variables_call, stack_2, storage_2, memory_2, "")
            
            return message, event, no_bytecode, retOffset, retSize, return_data_2, stack_2, storage_2, memory_2, address, stack, global_variables_call, global_variables
        return message, event, no_bytecode, retOffset, retSize, return_data_2, stack_2, storage_2, memory_2, address, stack, global_variables_call, global_variables

    def staticcall(self, global_variables, stack, storage, memory):
        event = ""
        
        gas = stack.pop()  # amount of gas for sub context
        address = stack.pop()  # address to contract to run
        argsOffset = stack.pop()  # memory offset which contains calldata for subcontext
        argsSize = stack.pop()  # size of calldata
        retOffset = stack.pop()  # memory offset where return data will be stored
        retSize = stack.pop()  # size of return data

        argsSize = int(argsSize, 16)
        retSize = int(retSize, 16)

        # read the calldata for the subcontext               
        calldata_read_from_memory = self.readMemory(memory, argsOffset, argsSize)
        
        # create a copy of the global variables and modify it slightly
        # the called contract will have different global variables
        global_variables_staticcall = global_variables.copy()
        global_variables_staticcall["msg.sender"] = global_variables_staticcall["contract.address"]
        #global_variables_call["msg.value"] = value
        global_variables_staticcall["calldata"] = calldata_read_from_memory
        global_variables_staticcall["contract.address"] = address
        try:
            # Check if the called contract has bytecode
            called_contract_bytecode = global_variables_staticcall["extcode"][address]
            global_variables_staticcall["bytecode"] = called_contract_bytecode
        except:
            global_variables_staticcall["bytecode"] = 0

        # The called contract doesn't have bytecode so return 0
        no_bytecode = False
        if(global_variables_staticcall["bytecode"] == 0):
            event = "CALL failed, no bytecode at address"
            no_bytecode = True
            message = "revert"

##        # Check if the caller has enough eth
##        not_enough_eth = False
##        try:
##            # get the balance of the creator contract
##            creator_addr = global_variables["contract.address"]
##            balance_addr = int(global_variables["balances"][creator_addr], 16)
##            # make sure it has enough eth to deploy the contract
##            if(balance_addr < value):
##                event = "CALL failed not enough ETH"
##                not_enough_eth = True
##                message = "revert"
##        except:
##            event = "CALL failed not enough ETH"
##            not_enough_eth = True
##            message = "revert"

        # If no errors then call the contract
        if(no_bytecode == False): # and not_enough_eth == False):
            # Update the balance in the global_variables dict
            # add eth to the called contract
##            try:
##                # if the called contract already has eth, then add some more
##                called_contract_balance = int(global_variables["balances"][address], 16)
##                global_variables["balances"][address] = format(called_contract_balance + value, "064x")
##            except:
##                # else the called contract has no eth
##                called_contract_balance = 0
##                global_variables["balances"][address] = format(called_contract_balance + value, "064x")
##            
##            # subtract eth from the creator contract
##            global_variables["balances"][creator_addr] = format(balance_addr-value, "064x")

            # create a new evm instance
            evm_2 = EVM()     
            # create a new stack
            stack_2 = []
            # use the contract's storage if it has one, or create a new one if it doesn't
            try:
                storage_2 = global_variables["storage"][address]
            except:
                storage_2 = {}
            # create a new memory
            memory_2 = {}
            # start the program counter at 0
            pc_2 = 0
            breakpoints_2 = []
            
            # run the called contract
            message, return_data_2, stack_2, storage_2, memory_2 = evm_2.main(bytecode_read_from_memory, pc_2, breakpoints_2, global_variables_staticcall, stack_2, storage_2, memory_2, "staticcall")
            
            return message, event, no_bytecode, retOffset, retSize, return_data_2, stack_2, storage_2, memory_2, address, stack, global_variables_staticcall, global_variables
        return message, event, no_bytecode, retOffset, retSize, return_data_2, stack_2, storage_2, memory_2, address, stack, global_variables_staticcall, global_variables

    def callcode(self, global_variables, stack, storage, memory):
        event = ""
        
        gas = stack.pop()  # amount of gas for sub context
        address = stack.pop()  # address to contract to run
        value = stack.pop()  # value in wei to send to the new account
        argsOffset = stack.pop()  # memory offset which contains calldata for subcontext
        argsSize = stack.pop()  # size of calldata
        retOffset = stack.pop()  # memory offset where return data will be stored
        retSize = stack.pop()  # size of return data

        value = int(value, 16)
        argsSize = int(argsSize, 16)
        retSize = int(retSize, 16)

        # read the calldata for the subcontext               
        calldata_read_from_memory = self.readMemory(memory, argsOffset, argsSize)
        
        # create a copy of the global variables and modify it slightly
        # the called contract will have different global variables
        global_variables_callcode = global_variables.copy()
        global_variables_callcode["msg.sender"] = global_variables_callcode["contract.address"]
        global_variables_callcode["msg.value"] = value
        global_variables_callcode["calldata"] = calldata_read_from_memory
        global_variables_callcode["contract.address"] = address

        try:
            # Check if the called contract has bytecode
            called_contract_bytecode = global_variables_callcode["extcode"][address]
            global_variables_callcode["bytecode"] = called_contract_bytecode
        except:
            global_variables_callcode["bytecode"] = 0

        # The called contract doesn't have bytecode so return 0
        no_bytecode = False
        if(global_variables_callcode["bytecode"] == 0):
            event = "CALLCODE failed, no bytecode at address"
            no_bytecode = True
            message = "revert"

        # Check if the caller has enough eth
        not_enough_eth = False
        try:
            # get the balance of the creator contract
            creator_addr = global_variables["contract.address"]
            balance_addr = int(global_variables["balances"][creator_addr], 16)
            # make sure it has enough eth to deploy the contract
            if(balance_addr < value):
                event = "CALLCODE failed not enough ETH"
                not_enough_eth = True
                message = "revert"
        except:
            event = "CALLCODE failed not enough ETH"
            not_enough_eth = True
            message = "revert"

        # If no errors then call the contract
        if(no_bytecode == False and not_enough_eth == False):
            # Update the balance in the global_variables dict
            # add eth to the called contract
            try:
                # if the called contract already has eth, then add some more
                called_contract_balance = int(global_variables["balances"][address], 16)
                global_variables["balances"][address] = format(called_contract_balance + value, "064x")
            except:
                # else the called contract has no eth
                called_contract_balance = 0
                global_variables["balances"][address] = format(called_contract_balance + value, "064x")
            
            # subtract eth from the creator contract
            global_variables["balances"][creator_addr] = format(balance_addr-value, "064x")

            # create a new evm instance
            evm_2 = EVM()     
            # create a new stack
            stack_2 = []
            # use the current contract's storage
            
            # create a new memory
            memory_2 = {}
            # start the program counter at 0
            pc_2 = 0
            breakpoints_2 = []
            
            # run the called contract
            message, return_data_2, stack_2, storage, memory_2 = evm_2.main(bytecode_read_from_memory, pc_2, breakpoints_2, global_variables_callcode, stack_2, storage, memory_2, "")
            return message, event, no_bytecode, retOffset, retSize, return_data_2, stack_2, storage, memory_2, address, stack, global_variables_callcode, global_variables
        return message, event, no_bytecode, retOffset, retSize, return_data_2, stack_2, storage, memory_2, address, stack, global_variables_callcode, global_variables

    def delegatecall(self, global_variables, stack, storage, memory):
        event = ""
        
        gas = stack.pop()  # amount of gas for sub context
        address = stack.pop()  # address to contract to run
        value = stack.pop()  # value in wei to send to the new account
        argsOffset = stack.pop()  # memory offset which contains calldata for subcontext
        argsSize = stack.pop()  # size of calldata
        retOffset = stack.pop()  # memory offset where return data will be stored
        retSize = stack.pop()  # size of return data

        value = int(value, 16)
        argsSize = int(argsSize, 16)
        retSize = int(retSize, 16)

        # read the calldata for the subcontext               
        calldata_read_from_memory = self.readMemory(memory, argsOffset, argsSize)
        
        # create a copy of the global variables and modify it slightly
        # the called contract will have different global variables
        global_variables_delegatecall = global_variables.copy()
        #global_variables_delegatecall["msg.sender"] = global_variables_delegatecall["contract.address"]
        #global_variables_delegatecall["msg.value"] = value
        global_variables_delegatecall["calldata"] = calldata_read_from_memory
        global_variables_delegatecall["contract.address"] = address

        try:
            # Check if the called contract has bytecode
            called_contract_bytecode = global_variables_delegatecall["extcode"][address]
            global_variables_delegatecall["bytecode"] = called_contract_bytecode
        except:
            global_variables_delegatecall["bytecode"] = 0

        # The called contract doesn't have bytecode so return 0
        no_bytecode = False
        if(global_variables_delegatecall["bytecode"] == 0):
            event = "CALLCODE failed, no bytecode at address"
            no_bytecode = True
            message = "revert"

        # Check if the caller has enough eth
        not_enough_eth = False
        try:
            # get the balance of the creator contract
            creator_addr = global_variables["contract.address"]
            balance_addr = int(global_variables["balances"][creator_addr], 16)
            # make sure it has enough eth to deploy the contract
            if(balance_addr < value):
                event = "CALLCODE failed not enough ETH"
                not_enough_eth = True
                message = "revert"
        except:
            event = "CALLCODE failed not enough ETH"
            not_enough_eth = True
            message = "revert"

        # If no errors then call the contract
        if(no_bytecode == False and not_enough_eth == False):
            # Update the balance in the global_variables dict
            # add eth to the called contract
            try:
                # if the called contract already has eth, then add some more
                called_contract_balance = int(global_variables["balances"][address], 16)
                global_variables["balances"][address] = format(called_contract_balance + value, "064x")
            except:
                # else the called contract has no eth
                called_contract_balance = 0
                global_variables["balances"][address] = format(called_contract_balance + value, "064x")
            
            # subtract eth from the creator contract
            global_variables["balances"][creator_addr] = format(balance_addr-value, "064x")

            # create a new evm instance
            evm_2 = EVM()     
            # create a new stack
            stack_2 = []
            # use the current contract's storage
            
            # create a new memory
            memory_2 = {}
            # start the program counter at 0
            pc_2 = 0
            breakpoints_2 = []
            
            # run the called contract
            message, return_data_2, stack_2, storage, memory_2 = evm_2.main(bytecode_read_from_memory, pc_2, breakpoints_2, global_variables_delegatecall, stack_2, storage, memory_2, "")
            
            return message, event, no_bytecode, retOffset, retSize, return_data_2, stack_2, storage, memory_2, address, stack, global_variables_delegatecall, global_variables
        return message, event, no_bytecode, retOffset, retSize, return_data_2, stack_2, storage, memory_2, address, stack, global_variables_delegatecall, global_variables

   
    def runBytecode(self, pc, instructions, breakpoints, global_variables, stack, storage, memory):
        '''
        INPUTS: The program counter, instructions, global variables, stack, storage, and memory
        PROCESSING: Executes every instruction, including recursive contract calls
        OUTPUTS: end, return_data, stack, storage, memory
                end: is what caused the contract to end such as "revert" or "ran out of gas"
                return_data: the data returned by the contract which is affected by multiple instructions
                stack, storage, memory probably don't need to be returned
        '''
                
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
        max_num_of_instructions = 100000

        # List of events that happen during execution
        event_log = []
        # Used for events generated while in subcontexts AKA recursive stuff involving
        # other contracts
        event_recursive = ""

        while(1):
            # This is our equivalent to running out of gas
            instruction_counter += 1
            if(instruction_counter > max_num_of_instructions):
                end = "ran out of gas"
                break

            # if there's a breakpoint, then stop execution
            if(pc in breakpoints):
                end = "breakpoint"
                break

            # if there's an invalid program counter then stop execution
            if(str(pc) not in instructions):
                end = "invalid pc"
                break

            if(self.caller == "staticcall"):
                if(instructions[str(pc)][0] == "create" or
                   instructions[str(pc)][0] == "create2" or
                   "log" in instructions[str(pc)][0] or
                   instructions[str(pc)][0] == "sstore" or
                   instructions[str(pc)][0] == "selfdestruct" or
                   instructions[str(pc)][0] == "call"):
                    end = "staticcall attempted state changing instruction"
                    break
            
            print("\n", str(pc), instructions[str(pc)])

            # Handle a few instructions seperately from the others
            # The first few are instructions that stop contract execution
            # The last few are recursive instructions that involve calling other contracts
            if(instructions[str(pc)][0] == "stop"):
                end = "stop"
                break
            elif(instructions[str(pc)][0] == "return"):
                end = "return"
                offset = stack.pop()
                size = stack.pop()
                size = int(size, 16)
                
                return_data = self.readMemory(memory, offset, size)
                break
            elif(instructions[str(pc)][0] == "revert"):
                end = "revert"
                offset = stack.pop()
                size = stack.pop()
                size = int(size, 16)
                
                return_data = self.readMemory(memory, offset, size)
                break            
            elif(instructions[str(pc)][0] == "invalid"):
                end = "invalid"
                break
            elif(instructions[str(pc)][0] == "selfdestruct"):
                end = "selfdestruct"
                address = stack.pop()
                current_addr = global_variables["contract.address"]
                balance = int(global_variables["balances"][current_addr], 16)
                try:
                    # send eth to provided contract
                    provided_contract_balance = int(global_variables["balances"][address], 16)
                    global_variables["balances"][address] = format(provided_contract_balance + balance, "064x")
                    global_variables["balances"][current_addr] = format(0, "064x")
                except:
                    provided_contract_balance = 0
                    global_variables["balances"][address] = format(provided_contract_balance + balance, "064x")
                    global_variables["balances"][current_addr] = format(0, "064x")
                break
            elif(instructions[str(pc)][0] == "create"):
                self.call_depth += 1

                # run the CREATE instruction
                message, end, return_data_2, stack_2, storage_2, memory_2, new_contract_addr, bytecode_read_from_memory, stack, global_variables_create, global_variables = self.create(global_variables, stack, storage, memory)
                # if there was an error, then break
                if(end != ""):
                    break
                
                if(message == "revert" or message == "call_depth reached" or
                   message == "ran out of gas"):
                    # if the new contract failed then put 0 on the stack
                    stack.append(format(0, "064x"))
                else:
                    # else put the new contract's addr on the stack
                    stack.append(new_contract_addr)
                    # put the return_data to the bytecode of the new contract
                    return_data = bytecode_read_from_memory
                    # Update the global variable storage w/ the contract's storage
                    global_variables["storage"][new_contract_addr] = storage_2

            elif(instructions[str(pc)][0] == "create2"):
                self.call_depth += 1

                # run the CREATE2 instruction
                message, end, return_data_2, stack_2, storage_2, memory_2, new_contract_addr, bytecode_read_from_memory, stack, global_variables_create2, global_variables = self.create2(global_variables, stack, storage, memory)
                # if there was an error, then break
                if(end != ""):
                    break
                
                if(message == "revert" or message == "call_depth reached" or
                   message == "ran out of gas"):
                    # if the new contract failed then put 0 on the stack
                    stack.append(format(0, "064x"))
                else:
                    # else put the new contract's addr on the stack
                    stack.append(new_contract_addr)
                    # put the return_data to the bytecode of the new contract
                    return_data = bytecode_read_from_memory
                    # Update the global variable storage w/ the contract's storage
                    global_variables["storage"][new_contract_addr] = storage_2

            elif(instructions[str(pc)][0] == "call"):
                self.call_depth += 1

                # run the CALL instruction
                message, event_recursive, no_bytecode, retOffset, retSize, return_data_2, stack_2, storage_2, memory_2, address, stack, global_variables_call, global_variables = self.call(global_variables, stack, storage, memory)
                    
                if(message == "revert" or message == "call_depth reached" or
                   message == "ran out of gas"):
                    if(no_bytecode == True):
                        # if the contract failed but only because it doesn't have bytecode
                        # this is an exeption where you still need to return 1 to the stack
                        stack.append(format(1, "064x"))
                    else:
                        # if the called contract failed then put 0 on the stack
                        stack.append(format(0, "064x"))
                else:
                    # else put 1 on the stack, since it was successful
                    stack.append(format(1, "064x"))
                    # move the return_data to memory
                    memory = self.writeMemory(memory, retOffset, retSize, return_data_2)
                    # Update the global variable storage w/ the contract's storage
                    global_variables["storage"][address] = storage_2

            elif(instructions[str(pc)][0] == "staticcall"):
                self.call_depth += 1

                # run the CALL instruction
                message, event_recursive, no_bytecode, retOffset, retSize, return_data_2, stack_2, storage_2, memory_2, address, stack, global_variables_call, global_variables = self.staticcall(global_variables, stack, storage, memory)
                    
                if(message == "revert" or message == "call_depth reached" or
                   message == "ran out of gas"):
                    if(no_bytecode == True):
                        # if the contract failed but only because it doesn't have bytecode
                        # this is an exeption where you still need to return 1 to the stack
                        stack.append(format(1, "064x"))
                    else:
                        # if the called contract failed then put 0 on the stack
                        stack.append(format(0, "064x"))
                else:
                    # else put 1 on the stack, since it was successful
                    stack.append(format(1, "064x"))
                    # move the return_data to memory
                    memory = self.writeMemory(memory, retOffset, retSize, return_data_2)
                    # Update the global variable storage w/ the contract's storage
                    #global_variables["storage"][address] = storage_2

            elif(instructions[str(pc)][0] == "callcode"):
                # DEPRECATED
                self.call_depth += 1

                # run the CALLCODE instruction
                message, event_recursive, no_bytecode, retOffset, retSize, return_data_2, stack_2, storage, memory_2, address, stack, global_variables_call, global_variables = self.callcode(global_variables, stack, storage, memory)
                    
                if(message == "revert" or message == "call_depth reached" or
                   message == "ran out of gas"):
                    if(no_bytecode == True):
                        # if the contract failed but only because it doesn't have bytecode
                        # this is an exeption where you still need to return 1 to the stack
                        stack.append(format(1, "064x"))
                    else:
                        # if the called contract failed then put 0 on the stack
                        stack.append(format(0, "064x"))
                else:
                    # else put 1 on the stack, since it was successful
                    stack.append(format(1, "064x"))
                    # move the return_data to memory
                    memory = self.writeMemory(memory, retOffset, retSize, return_data_2)
                    # Update the global variable storage w/ the contract's storage
                    creator_addr = global_variables["contract.address"]
                    global_variables["storage"][creator_addr] = storage

            elif(instructions[str(pc)][0] == "delegatecall"):
                # Updated version of callcode
                self.call_depth += 1

                # run the CALLCODE instruction
                message, event_recursive, no_bytecode, retOffset, retSize, return_data_2, stack_2, storage, memory_2, address, stack, global_variables_call, global_variables = self.delegatecall(global_variables, stack, storage, memory)
                    
                if(message == "revert" or message == "call_depth reached" or
                   message == "ran out of gas"):
                    if(no_bytecode == True):
                        # if the contract failed but only because it doesn't have bytecode
                        # this is an exeption where you still need to return 1 to the stack
                        stack.append(format(1, "064x"))
                    else:
                        # if the called contract failed then put 0 on the stack
                        stack.append(format(0, "064x"))
                else:
                    # else put 1 on the stack, since it was successful
                    stack.append(format(1, "064x"))
                    # move the return_data to memory
                    memory = self.writeMemory(memory, retOffset, retSize, return_data_2)
                    # Update the global variable storage w/ the contract's storage
                    creator_addr = global_variables["contract.address"]
                    global_variables["storage"][creator_addr] = storage

                  
            # Execute the instruction
            pc, stack, storage, memory, event = self.opcode_func(pc, instructions, instructions[str(pc)][0], global_variables, stack, storage, memory)

            # Update the global variable storage w/ the contract's storage
            current_address = global_variables["contract.address"]
            global_variables["storage"][current_address] = storage

            # -1 means just break after executing one instruction
            if(-1 in breakpoints):
                end = "breakpoint"
                break

            # if the program counter is past the last instruction then break
            if(pc > max_offset):
                end = "tried executing past last instruction"
                break

            # there's the potential with recursion to cause a DOS
            # limit the number of contracts that can call other contracts
            if(self.call_depth > 1000):
                end = "call_depth reached"
                break
            
            # If something special happened like an integer over flow then show that
            if(event_recursive != ""):
                print(event_recursive)
                event_log.append([pc, event_recursive])
                event_recursive = ""
            elif(event != ""):
                print(event)
                event_log.append([pc, event])
            events = ["overflow add", "overflow mul", "underflow sub", "divide by 0 returns 0",
                      "signed division by 0 returns 0", "MOD 0 returns 0", "Signed MOD 0 returns 0",
                      "overflow exp", "SHA3 called with size > 32", "invalid jump",
                      "LOG called with size > 32", "extcodehash returns 0", "CALL failed, no bytecode at address"]

        return end, return_data, stack, storage, memory, event_log
                
    def main(self, bytecode, pc, breakpoints, global_variables, stack, memory, caller):
        # set the call depth to 0
        self.call_depth = 0
        self.caller = caller
        # Check if the storage exists, if not create empty storage
        if(global_variables["contract.address"] in global_variables["extcode"]):
            contract_addr = global_variables["contract.address"]
            storage = global_variables["extcode"][contract_addr]
        else:
            storage = {}
        # turn into human readable instructions
        self.instructions = self.parseBytecode(bytecode)
        print(self.instructions)
        
        message, return_data, stack, storage, memory, event_log = self.runBytecode(pc, self.instructions, breakpoints, global_variables, stack, storage, memory)
        print(message, return_data, event_log)
        return message, return_data, stack, storage, memory, event_log

if(__name__ == "__main__"):
    evm = EVM()
        
    bytecode = "60806040526000340361001157600080fd5b610206806100206000396000f3fe60806040526004361061001e5760003560e01c8063a30da70d14610023575b600080fd5b61002b61002d565b005b610035610106565b610070816000019067ffffffffffffffff16908167ffffffffffffffff168152505034815101815261006d816000015163ffffffff16565b50565b61007861007a565b565b600034146100bd576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016100b490610181565b60405180910390fd5b3373ffffffffffffffffffffffffffffffffffffffff166108fc479081150290604051600060405180830381858888f19350505050158015610103573d6000803e3d6000fd5b50565b604051806020016040528061011a81525090565b6101226101a1565b565b600082825260208201905092915050565b7f646f6e742073656e642066756e64732100000000000000000000000000000000600082015250565b600061016b601083610124565b915061017682610135565b602082019050919050565b6000602082019050818103600083015261019a8161015e565b9050919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052605160045260246000fdfea26469706673582212202984a32427ae50c08b30f852a00a90f1afccf0ee5e5ceeb78f8227cdb1ec28ad64736f6c63430008110033"

    # Global Variables
    global_variables = {"block.chainid":"1",
                        "block.coinbase":"0000000000000000000000000000000000000000000000000000000000000000",
                        "block.difficulty":"0",
                        "block.gaslimit":"6721975",
                        "block.number":"144",
                        "block.timestamp":"1675125106",
                        "block.hash":"33045A592007D0C246EF02C2223560DA9522D0CF0F73282C79A1BC8F0BB2C237",
                        "msg.sender":"00000000000000000000000059ad9d5ddf09f2276D5a5A701d9105c3f989D961",
                        "msg.sig":"00000000000000000000000000000000000000000000000000000000a30da70d",
                        "msg.value":"0",
                        "tx.origin":"00000000000000000000000059ad9d5ddf09f2276D5a5A701d9105c3f989D961",
                        "calldata":"0000000000000000000000000000000000000000000000000000000000000000",
                        "contract.address":"0000000000000000000000009bbfed6889322e016e0a02ee459d306fc19545d8",
                        "balances":{},
                        "bytecode":bytecode,
                        "gas.price":"10",
                        "gas":"1000",
                        "extcode":{},
                        "returndata":"",
                        "storage":{}
                        }

    # Stack
    stack = []

    # Memory
    memory = {}

    # start the program counter at 0
    pc = 0

    # breakpoints
    breakpoints = []

    # used for STATICCALL instruction
    caller = ""
            
    message, return_data, stack, storage, memory, event_log = evm.main(bytecode, pc, breakpoints, global_variables, stack, memory, caller)




