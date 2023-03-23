from web3 import Web3
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading
import requests
import json

class WebServer(threading.Thread):
    '''
    This class runs the webserver

    Inputs: 
    Processing: 
    Outputs: http://127.0.0.1:12346
    '''

    def __init__(self, port):
        print("starting web server... on http://127.0.0.1:" + str(port))
        # Call the Thread class's init function
        threading.Thread.__init__(self)
        self.port = port

    def run(self):
        # This is a method of the Thread class
        # which is called after Thread.start()

        # run the webserver
        while(1):
            with HTTPServer(('localhost', self.port), handler) as server:
                server.serve_forever()

# This class handles requests sent to the web server
class handler(BaseHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    # stop the webserver from printing out request information
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
        valid_paths = ["/",
                       "/index.html",
                       "/favicon.ico",
                       "/w3.css",
                       "/main.css",
                       "/jquery-3.6.1.js"]
        
        # If the requested path is not allowed then return an error
        if(self.path not in valid_paths):
            self.send_response(404)  # Send a 404 Forbidden
            self.send_header('Content-type','application/json')  # Return a json generic error message
            self.end_headers()  # End the headers section
            self.wfile.write('''{"error":"error"}'''.encode("utf-8"))  # write the error message
            return
           
        # The path is valid therefore return data
        # Send a 200 OK to the browser
        self.send_response(200)

        # Return the appropriate Content-type header
        try:
            # Look at the file extension of the requested resource and
            # return the correct content type
            file_type = self.path.split(".")[-1]
            if(file_type == "js"):
                self.send_header('Content-type','text/javascript; charset=UTF-8')
            elif(file_type == "css"):
                self.send_header('Content-type','text/css')
            elif(file_type == "json"):
                self.send_header('Content-type','application/json')
            elif(file_type == "html" or self.path == "/"):
                self.send_header('Content-type','text/html; charset=UTF-8')
            elif(file_type == "ico"):
                self.send_header('Content-type','image/x-icon')
            else:
                self.send_header('Content-type','text/html; charset=UTF-8')
        except:
            pass
        self.end_headers()  # End the headers section

        # If the request is to an allowed javascript or css resource
        # then load that file and return its contents
        # This is manually intensive but ensures the web server isn't
        # returning unintended local files
        if(self.path == "/" or self.path == "/index.html"):
            with open("web server/index.html", "rb") as f:
                self.wfile.write(f.read())
        elif(self.path == "/w3.css"):
            with open("web server/css/w3.css", "rb") as f:
                self.wfile.write(f.read())
        elif(self.path == "/main.css"):
            with open("web server/css/main.css", "rb") as f:
                self.wfile.write(f.read())
        elif(self.path == "/favicon.ico"):
            with open("web server/images/favicon.ico", "rb") as f:
                self.wfile.write(f.read())
        elif(self.path == "/jquery-3.6.1.js"):
            with open("web server/js/jquery-3.6.1.js", "rb") as f:
                self.wfile.write(f.read())

if(__name__ == "__main__"):
    # run the web server on http://127.0.0.1:12346
    webServer_thread = WebServer(12346)
    webServer_thread.start()
