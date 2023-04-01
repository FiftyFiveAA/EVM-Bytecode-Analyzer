import evm_bytecode_analyzer
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading
import requests
import json

class APIServer(threading.Thread):
    '''
    This class runs the webserver

    Inputs: 
    Processing: 
    Outputs: http://127.0.0.1:12345
    '''

    def __init__(self, port):
        print("starting API server... on http://127.0.0.1:" + str(port))
        # Call the Thread class's init function
        threading.Thread.__init__(self)
        self.port = port

    def run(self):
        # This is a method of the Thread class
        # which is called after Thread.start()

        # run the apiserver
        while(1):
            with HTTPServer(('localhost', self.port), handler) as server:
                server.serve_forever()

class APIServerInit:
    def __init__(self):
        # Initial values used by the API server
        try:
            with open("states.json", "r") as f:
                self.states = json.load(f)
        except:
            self.states = {'default': {'bytecode': '60806040526000340361001157600080fd5b610206806100206000396000f3fe60806040526004361061001e5760003560e01c8063a30da70d14610023575b600080fd5b61002b61002d565b005b610035610106565b610070816000019067ffffffffffffffff16908167ffffffffffffffff168152505034815101815261006d816000015163ffffffff16565b50565b61007861007a565b565b600034146100bd576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016100b490610181565b60405180910390fd5b3373ffffffffffffffffffffffffffffffffffffffff166108fc479081150290604051600060405180830381858888f19350505050158015610103573d6000803e3d6000fd5b50565b604051806020016040528061011a81525090565b6101226101a1565b565b600082825260208201905092915050565b7f646f6e742073656e642066756e64732100000000000000000000000000000000600082015250565b600061016b601083610124565b915061017682610135565b602082019050919050565b6000602082019050818103600083015261019a8161015e565b9050919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052605160045260246000fdfea26469706673582212202984a32427ae50c08b30f852a00a90f1afccf0ee5e5ceeb78f8227cdb1ec28ad64736f6c63430008110033', 'global_variables': {'block.chainid': '1', 'block.coinbase': '0000000000000000000000000000000000000000000000000000000000000000', 'block.difficulty': '0', 'block.gaslimit': '6721975', 'block.number': '144', 'block.timestamp': '1675125106', 'block.hash': '33045A592007D0C246EF02C2223560DA9522D0CF0F73282C79A1BC8F0BB2C237', 'msg.sender': '00000000000000000000000059ad9d5ddf09f2276D5a5A701d9105c3f989D961', 'msg.sig': '00000000000000000000000000000000000000000000000000000000a30da70d', 'msg.value': '0', 'tx.origin': '00000000000000000000000059ad9d5ddf09f2276D5a5A701d9105c3f989D961', 'calldata': '0000000000000000000000000000000000000000000000000000000000000000', 'contract.address': '0000000000000000000000009bbfed6889322e016e0a02ee459d306fc19545d8', 'balances': {}, 'bytecode': '60806040526000340361001157600080fd5b610206806100206000396000f3fe60806040526004361061001e5760003560e01c8063a30da70d14610023575b600080fd5b61002b61002d565b005b610035610106565b610070816000019067ffffffffffffffff16908167ffffffffffffffff168152505034815101815261006d816000015163ffffffff16565b50565b61007861007a565b565b600034146100bd576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016100b490610181565b60405180910390fd5b3373ffffffffffffffffffffffffffffffffffffffff166108fc479081150290604051600060405180830381858888f19350505050158015610103573d6000803e3d6000fd5b50565b604051806020016040528061011a81525090565b6101226101a1565b565b600082825260208201905092915050565b7f646f6e742073656e642066756e64732100000000000000000000000000000000600082015250565b600061016b601083610124565b915061017682610135565b602082019050919050565b6000602082019050818103600083015261019a8161015e565b9050919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052605160045260246000fdfea26469706673582212202984a32427ae50c08b30f852a00a90f1afccf0ee5e5ceeb78f8227cdb1ec28ad64736f6c63430008110033', 'gas.price': '10', 'gas': '1000', 'extcode': {}, 'returndata': '', 'storage': {}}, 'stack': [], 'storage': {}, 'memory': {}, 'pc': 0, 'breakpoints': [], "caller": "", "instructions":{}}}

        # get an instance of the EVM
        self.evm = evm_bytecode_analyzer.EVM()
                
    def save(states):
        try:
            with open("states.json", "w") as f:
                json.dump(states, f)
        except Exception as e:
            print(e)
            print("Failed to update states.json file. api_server.py -> APIServerInit -> save()")

    init_complete = False
    current_state = "default"

# This class handles requests sent to the web server
class handler(BaseHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        if(APIServerInit.init_complete):
            # We've already read states.json
            # So get the value from the class
            self.states = APIServerInit.states
            self.evm = APIServerInit.evm
        else:
            # Initialize the APIServerInit class
            self.api_server_init = APIServerInit()
            # Get the "states" and "evm" objects
            self.states = self.api_server_init.states
            self.evm = self.api_server_init.evm
            # Update the class for future calls
            # This prevents having to read the states.json
            # file on every HTTP request
            APIServerInit.init_complete = True
            APIServerInit.states = self.states
            APIServerInit.evm = self.evm
        
        super().__init__(*args, **kwargs)

    # stop the apiserver from printing out request information
    # to the command line
    def log_message(self, format, *args):
        return

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Content-type','application/json')  # Return a json generic error message
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Headers', '*')
        self.end_headers()  # End the headers section

   # If the request is a GET request then follow this logic
    def do_GET(self):
        # Hard code valid paths
        valid_paths = ["/api/v1/globalVariables",
                       "/api/v1/breakpoints",
                       "/api/v1/programCounter",
                       "/api/v1/stack",
                       "/api/v1/memory",
                       "/api/v1/caller",
                       "/api/v1/getAllStates",
                       "/api/v1/currentState"]

        # If the requested path is not allowed then return an error
        if(self.path not in valid_paths):
            self.send_response(404)  # Send a 404 Forbidden
            self.send_header('Content-type','application/json')  # Return a json generic error message
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()  # End the headers section
            self.wfile.write('''{"error":"Invalid Path"}'''.encode("utf-8"))  # write the error message
            return

        if(self.path == "/api/v1/globalVariables"):
            try:
                json.dumps(APIServerInit.states[APIServerInit.current_state]["global_variables"]).encode("utf-8")
            except:
                self.send_response(400)
                self.send_header('Content-type','application/json')  # Return a json generic error message
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()  # End the headers section
                self.wfile.write('''{"error":"error"}'''.encode("utf-8"))  # write the error message
                return
            self.send_response(200)
            self.send_header('Content-type','application/json')  # Return a json generic error message
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()  # End the headers section
            self.wfile.write(json.dumps(APIServerInit.states[APIServerInit.current_state]["global_variables"]).encode("utf-8"))  # write the response
            return
        
        elif(self.path == "/api/v1/breakpoints"):
            try:
                json.dumps(APIServerInit.states[APIServerInit.current_state]["breakpoints"]).encode("utf-8")
            except:
                self.send_response(400)
                self.send_header('Content-type','application/json')  # Return a json generic error message
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()  # End the headers section
                self.wfile.write('''{"error":"error"}'''.encode("utf-8"))  # write the error message
                return
            self.send_response(200)
            self.send_header('Content-type','application/json')  # Return a json generic error message
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()  # End the headers section
            self.wfile.write(json.dumps({"breakpoints":APIServerInit.states[APIServerInit.current_state]["breakpoints"]}).encode("utf-8"))  # write the response
            return
        
        elif(self.path == "/api/v1/programCounter"):
            try:
                json.dumps(APIServerInit.states[APIServerInit.current_state]["pc"]).encode("utf-8")
            except:
                self.send_response(400)
                self.send_header('Content-type','application/json')  # Return a json generic error message
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()  # End the headers section
                self.wfile.write('''{"error":"error"}'''.encode("utf-8"))  # write the error message
                return
            self.send_response(200)
            self.send_header('Content-type','application/json')  # Return a json generic error message
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()  # End the headers section
            self.wfile.write(json.dumps({"pc":APIServerInit.states[APIServerInit.current_state]["pc"]}).encode("utf-8"))  # write the response
            return
        
        elif(self.path == "/api/v1/stack"):
            try:
                json.dumps(APIServerInit.states[APIServerInit.current_state]["stack"]).encode("utf-8")
            except:
                self.send_response(400)
                self.send_header('Content-type','application/json')  # Return a json generic error message
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()  # End the headers section
                self.wfile.write('''{"error":"error"}'''.encode("utf-8"))  # write the error message
                return
            self.send_response(200)
            self.send_header('Content-type','application/json')  # Return a json generic error message
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()  # End the headers section
            self.wfile.write(json.dumps({"stack":APIServerInit.states[APIServerInit.current_state]["stack"]}).encode("utf-8"))  # write the response
            return
        
        elif(self.path == "/api/v1/memory"):
            try:
                json.dumps(APIServerInit.states[APIServerInit.current_state]["memory"]).encode("utf-8")
            except:
                self.send_response(400)
                self.send_header('Content-type','application/json')  # Return a json generic error message
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()  # End the headers section
                self.wfile.write('''{"error":"error"}'''.encode("utf-8"))  # write the error message
                return
            self.send_response(200)
            self.send_header('Content-type','application/json')  # Return a json generic error message
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()  # End the headers section
            self.wfile.write(json.dumps({"memory":APIServerInit.states[APIServerInit.current_state]["memory"]}).encode("utf-8"))  # write the response
            return
        
        elif(self.path == "/api/v1/caller"):
            try:
                json.dumps({"caller":APIServerInit.states[APIServerInit.current_state]["caller"]}).encode("utf-8")
            except:
                self.send_response(400)
                self.send_header('Content-type','application/json')  # Return a json generic error message
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()  # End the headers section
                self.wfile.write('''{"error":"error"}'''.encode("utf-8"))  # write the error message
                return
            self.send_response(200)
            self.send_header('Content-type','application/json')  # Return a json generic error message
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()  # End the headers section
            self.wfile.write(json.dumps({"caller":APIServerInit.states[APIServerInit.current_state]["caller"]}).encode("utf-8"))  # write the response
            return
        
        elif(self.path == "/api/v1/getAllStates"):
            try:
                json.dumps(APIServerInit.states).encode("utf-8")
            except:
                self.send_response(400)
                self.send_header('Content-type','application/json')  # Return a json generic error message
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()  # End the headers section
                self.wfile.write('''{"error":"error"}'''.encode("utf-8"))  # write the error message
                return
            self.send_response(200)
            self.send_header('Content-type','application/json')  # Return a json generic error message
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()  # End the headers section
            self.wfile.write(json.dumps(APIServerInit.states).encode("utf-8"))  # write the response
            return
        
        elif(self.path == "/api/v1/currentState"):
            try:
                json.dumps({"stateName":APIServerInit.current_state}).encode("utf-8")
            except:
                self.send_response(400)
                self.send_header('Content-type','application/json')  # Return a json generic error message
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()  # End the headers section
                self.wfile.write('''{"error":"error"}'''.encode("utf-8"))  # write the error message
                return
            self.send_response(200)
            self.send_header('Content-type','application/json')  # Return a json generic error message
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()  # End the headers section
            self.wfile.write(json.dumps({"stateName":APIServerInit.current_state}).encode("utf-8"))  # write the response
            return
        
##            print(self.states)
##            try:
##                APIServerInit.states["counter"] += 1
##            except:
##                APIServerInit.states["counter"] = 0
##            APIServerInit.save(self.states)
            
    # If the request is a POST request then follow this logic
    def do_POST(self):
        # Hard code valid paths
        valid_paths = ["/api/v1/parseBytecode",
                       "/api/v1/runBytecode",
                       "/api/v1/globalVariables",
                       "/api/v1/breakpoints",
                       "/api/v1/programCounter",
                       "/api/v1/stack",
                       "/api/v1/memory",
                       "/api/v1/caller",
                       "/api/v1/saveAllStates",
                       "/api/v1/createState",
                       "/api/v1/updateState",
                       "/api/v1/currentState",
                       "/api/v1/removeState"]

        # If the requested path is not allowed then return an error
        if(self.path not in valid_paths):
            self.send_response(404)  # Send a 404 Forbidden
            self.send_header('Content-type','application/json')  # Return a json generic error message
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()  # End the headers section
            self.wfile.write('''{"error":"Invalid Path"}'''.encode("utf-8"))  # write the error message
            return

        if(self.path == "/api/v1/parseBytecode"):
            try:
                # read the request's body, convert to dict
                content_length = int(self.headers["Content-Length"])
                body = self.rfile.read(content_length)
                request_body = json.loads(body.decode("utf-8"))

                # parse the JSON
                bytecode = request_body["bytecode"]
                # parse the bytecode
                instructions = self.evm.parseBytecode(bytecode)
                # make sure the response is json
                json.dumps(instructions).encode("utf-8")
                # Update the current state's bytecode
                APIServerInit.states[APIServerInit.current_state]["bytecode"] = bytecode
                # Update the current state's instructions
                APIServerInit.states[APIServerInit.current_state]["instructions"] = instructions
            except:
                self.send_response(400)
                self.send_header('Content-type','application/json')  # Return a json generic error message
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()  # End the headers section
                self.wfile.write('''{"error":"error"}'''.encode("utf-8"))  # write the error message
                return
            self.send_response(200)
            self.send_header('Content-type','application/json')  # Return a json generic error message
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()  # End the headers section
            self.wfile.write(json.dumps(instructions).encode("utf-8"))  # write the response
            return
        
        elif(self.path == "/api/v1/runBytecode"):
            try:
                # read the request's body, convert to dict
                content_length = int(self.headers["Content-Length"])
                body = self.rfile.read(content_length)
                instructions = json.loads(body.decode("utf-8"))

                # run the bytecode
                pc = APIServerInit.states[APIServerInit.current_state]["pc"]
                breakpoints = APIServerInit.states[APIServerInit.current_state]["breakpoints"]
                global_variables = APIServerInit.states[APIServerInit.current_state]["global_variables"]
                stack = APIServerInit.states[APIServerInit.current_state]["stack"]
                # get the contract's storage from the global variables if it exists
                if(global_variables["contract.address"] in global_variables["extcode"]):
                    contract_addr = global_variables["contract.address"]
                    storage = global_variables["extcode"][contract_addr]
                else:
                    storage = {}
                memory = APIServerInit.states[APIServerInit.current_state]["memory"]
                # now actually run the bytecode
                self.call_depth = 0
                end, return_data, stack, storage, memory, event_log = self.evm.apiRunBytecode(pc, instructions, breakpoints, global_variables, stack, storage, memory)
                # make sure the response is json
                json.dumps({"message":end, "return_data":return_data, "stack":stack,
                            "storage":storage, "memory":memory, "event_log":event_log}).encode("utf-8")
            except Exception as e:
                print(e)
                self.send_response(400)
                self.send_header('Content-type','application/json')  # Return a json generic error message
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()  # End the headers section
                self.wfile.write('''{"error":"error"}'''.encode("utf-8"))  # write the error message
                return
            self.send_response(200)
            self.send_header('Content-type','application/json')  # Return a json generic error message
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()  # End the headers section
            self.wfile.write(json.dumps({"message":end, "return_data":return_data, "stack":stack,
                            "storage":storage, "memory":memory, "event_log":event_log}).encode("utf-8"))  # write the response
            return
        
        elif(self.path == "/api/v1/globalVariables"):
            try:
                # read the request's body, convert to dict
                content_length = int(self.headers["Content-Length"])
                body = self.rfile.read(content_length)
                request_body = json.loads(body.decode("utf-8"))

                # Update the current state's global_variables
                APIServerInit.states[APIServerInit.current_state]["global_variables"] = request_body

                json.dumps(request_body).encode("utf-8")

            except:
                self.send_response(400)
                self.send_header('Content-type','application/json')  # Return a json generic error message
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()  # End the headers section
                self.wfile.write('''{"error":"error"}'''.encode("utf-8"))  # write the error message
                return
            self.send_response(200)
            self.send_header('Content-type','application/json')  # Return a json generic error message
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()  # End the headers section
            self.wfile.write(json.dumps(request_body).encode("utf-8"))  # write the response
            return
        
        elif(self.path == "/api/v1/breakpoints"):
            try:
                # read the request's body, convert to dict
                content_length = int(self.headers["Content-Length"])
                body = self.rfile.read(content_length)
                request_body = json.loads(body.decode("utf-8"))

                # parse the json
                breakpoints = request_body["breakpoints"]
                # Update the current state's breakpoints
                APIServerInit.states[APIServerInit.current_state]["breakpoints"] = breakpoints

                json.dumps({"breakpoints":breakpoints}).encode("utf-8")

            except:
                self.send_response(400)
                self.send_header('Content-type','application/json')  # Return a json generic error message
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()  # End the headers section
                self.wfile.write('''{"error":"error"}'''.encode("utf-8"))  # write the error message
                return
            self.send_response(200)
            self.send_header('Content-type','application/json')  # Return a json generic error message
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()  # End the headers section
            self.wfile.write(json.dumps({"breakpoints":breakpoints}).encode("utf-8"))  # write the response
            return
        
        elif(self.path == "/api/v1/programCounter"):
            try:
                # read the request's body, convert to dict
                content_length = int(self.headers["Content-Length"])
                body = self.rfile.read(content_length)
                request_body = json.loads(body.decode("utf-8"))

                # parse the json
                pc = request_body["pc"]
                # Update the current state's program counter
                APIServerInit.states[APIServerInit.current_state]["pc"] = pc

                json.dumps({"pc":pc}).encode("utf-8")

            except:
                self.send_response(400)
                self.send_header('Content-type','application/json')  # Return a json generic error message
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()  # End the headers section
                self.wfile.write('''{"error":"error"}'''.encode("utf-8"))  # write the error message
                return
            self.send_response(200)
            self.send_header('Content-type','application/json')  # Return a json generic error message
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()  # End the headers section
            self.wfile.write(json.dumps({"pc":pc}).encode("utf-8"))  # write the response
            return
        
        elif(self.path == "/api/v1/stack"):
            try:
                # read the request's body, convert to dict
                content_length = int(self.headers["Content-Length"])
                body = self.rfile.read(content_length)
                request_body = json.loads(body.decode("utf-8"))

                # parse the json
                stack = request_body["stack"]
                # Update the current state's stack
                APIServerInit.states[APIServerInit.current_state]["stack"] = stack

                json.dumps({"stack":stack}).encode("utf-8")

            except:
                self.send_response(400)
                self.send_header('Content-type','application/json')  # Return a json generic error message
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()  # End the headers section
                self.wfile.write('''{"error":"error"}'''.encode("utf-8"))  # write the error message
                return
            self.send_response(200)
            self.send_header('Content-type','application/json')  # Return a json generic error message
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()  # End the headers section
            self.wfile.write(json.dumps({"stack":stack}).encode("utf-8"))  # write the response
            return
        
        elif(self.path == "/api/v1/memory"):
            try:
                # read the request's body, convert to dict
                content_length = int(self.headers["Content-Length"])
                body = self.rfile.read(content_length)
                request_body = json.loads(body.decode("utf-8"))

                # parse the json
                memory = request_body["memory"]
                # Update the current state's memory
                APIServerInit.states[APIServerInit.current_state]["memory"] = memory

                json.dumps({"memory":memory}).encode("utf-8")

            except:
                self.send_response(400)
                self.send_header('Content-type','application/json')  # Return a json generic error message
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()  # End the headers section
                self.wfile.write('''{"error":"error"}'''.encode("utf-8"))  # write the error message
                return
            self.send_response(200)
            self.send_header('Content-type','application/json')  # Return a json generic error message
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()  # End the headers section
            self.wfile.write(json.dumps({"memory":memory}).encode("utf-8"))  # write the response
            return
        
        elif(self.path == "/api/v1/caller"):
            try:
                # read the request's body, convert to dict
                content_length = int(self.headers["Content-Length"])
                body = self.rfile.read(content_length)
                request_body = json.loads(body.decode("utf-8"))

                # parse the json
                caller = request_body["caller"]
                # Update the current state's memory
                APIServerInit.states[APIServerInit.current_state]["caller"] = caller

                json.dumps({"caller":caller}).encode("utf-8")

            except:
                self.send_response(400)
                self.send_header('Content-type','application/json')  # Return a json generic error message
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()  # End the headers section
                self.wfile.write('''{"error":"error"}'''.encode("utf-8"))  # write the error message
                return
            self.send_response(200)
            self.send_header('Content-type','application/json')  # Return a json generic error message
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()  # End the headers section
            self.wfile.write(json.dumps({"caller":caller}).encode("utf-8"))  # write the response
            return
        
        elif(self.path == "/api/v1/saveAllStates"):
            try:
                # Save the current state to "state.json"
                APIServerInit.save(self.states)

            except:
                self.send_response(400)
                self.send_header('Content-type','application/json')  # Return a json generic error message
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()  # End the headers section
                self.wfile.write('''{"error":"error"}'''.encode("utf-8"))  # write the error message
                return
            self.send_response(200)
            self.send_header('Content-type','application/json')  # Return a json generic error message
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()  # End the headers section
            self.wfile.write(json.dumps({"result":"SUCCESS"}).encode("utf-8"))  # write the response
            return
        
        elif(self.path == "/api/v1/createState"):
            try:
                # read the request's body, convert to dict
                content_length = int(self.headers["Content-Length"])
                body = self.rfile.read(content_length)
                request_body = json.loads(body.decode("utf-8"))

                # parse the json
                stateName = request_body["stateName"]
                # Update the current state's memory
                APIServerInit.states[stateName] = {}

                json.dumps({"stateName":stateName}).encode("utf-8")

            except:
                self.send_response(400)
                self.send_header('Content-type','application/json')  # Return a json generic error message
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()  # End the headers section
                self.wfile.write('''{"error":"error"}'''.encode("utf-8"))  # write the error message
                return
            self.send_response(200)
            self.send_header('Content-type','application/json')  # Return a json generic error message
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()  # End the headers section
            self.wfile.write(json.dumps({"stateName":stateName}).encode("utf-8"))  # write the response
            return
        
        elif(self.path == "/api/v1/updateState"):
            try:
                # read the request's body, convert to dict
                content_length = int(self.headers["Content-Length"])
                body = self.rfile.read(content_length)
                request_body = json.loads(body.decode("utf-8"))

                # parse the json
                for state in request_body:
                    # Update the state
                    APIServerInit.states[state] = request_body[state]

                json.dumps(request_body).encode("utf-8")

            except:
                self.send_response(400)
                self.send_header('Content-type','application/json')  # Return a json generic error message
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()  # End the headers section
                self.wfile.write('''{"error":"error"}'''.encode("utf-8"))  # write the error message
                return
            self.send_response(200)
            self.send_header('Content-type','application/json')  # Return a json generic error message
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()  # End the headers section
            self.wfile.write(json.dumps(request_body).encode("utf-8"))  # write the response
            return
        
        elif(self.path == "/api/v1/currentState"):
            try:
                # read the request's body, convert to dict
                content_length = int(self.headers["Content-Length"])
                body = self.rfile.read(content_length)
                request_body = json.loads(body.decode("utf-8"))

                # parse the json
                stateName = request_body["stateName"]
                # make sure the stateName exists
                if(stateName not in APIServerInit.states):
                    self.send_response(400)
                    self.send_header('Content-type','application/json')  # Return a json generic error message
                    self.send_header('Access-Control-Allow-Origin', '*')
                    self.end_headers()  # End the headers section
                    self.wfile.write('''{"error":"invalid stateName"}'''.encode("utf-8"))  # write the error message
                    return
                # update the current state
                APIServerInit.current_state = stateName

                json.dumps({"stateName":stateName}).encode("utf-8")

            except:
                self.send_response(400)
                self.send_header('Content-type','application/json')  # Return a json generic error message
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()  # End the headers section
                self.wfile.write('''{"error":"error"}'''.encode("utf-8"))  # write the error message
                return
            self.send_response(200)
            self.send_header('Content-type','application/json')  # Return a json generic error message
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()  # End the headers section
            self.wfile.write(json.dumps({"stateName":stateName}).encode("utf-8"))  # write the response
            return
        
        elif(self.path == "/api/v1/removeState"):
            try:
                # read the request's body, convert to dict
                content_length = int(self.headers["Content-Length"])
                body = self.rfile.read(content_length)
                request_body = json.loads(body.decode("utf-8"))

                # parse the json
                stateName = request_body["stateName"]
                if(stateName != "default"):
                    # remove the provided state
                    APIServerInit.states.pop(stateName)

                json.dumps({"stateName":stateName}).encode("utf-8")

            except:
                self.send_response(400)
                self.send_header('Content-type','application/json')  # Return a json generic error message
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()  # End the headers section
                self.wfile.write('''{"error":"error"}'''.encode("utf-8"))  # write the error message
                return
            self.send_response(200)
            self.send_header('Content-type','application/json')  # Return a json generic error message
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()  # End the headers section
            self.wfile.write(json.dumps({"stateName":stateName}).encode("utf-8"))  # write the response
            return
           
if(__name__ == "__main__"):
    # run the APIServer on http://127.0.0.1:12345
    APIServer_thread = APIServer(12345)
    APIServer_thread.start()
    
