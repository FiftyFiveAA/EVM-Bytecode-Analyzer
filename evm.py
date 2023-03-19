import api_server

APIServer_thread = api_server.APIServer(12345)
APIServer_thread.start()

print("hi")


