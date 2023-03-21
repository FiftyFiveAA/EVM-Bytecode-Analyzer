import api_server
import web_server

APIServer_thread = api_server.APIServer(12345)
APIServer_thread.start()

WebServer_thread = web_server.WebServer(12346)
WebServer_thread.start()


