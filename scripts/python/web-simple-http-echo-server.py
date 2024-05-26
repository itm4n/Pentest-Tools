#!/usr/bin/env python3

import signal
from http.server import HTTPServer, BaseHTTPRequestHandler

LHOST = "0.0.0.0"
LPORT = 8080
SEPERATOR = "-"*64

class RequestHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        self.print_request()
        print("%s\n%s" % (SEPERATOR, self.headers))
        self.send_response(200)
        
    def do_POST(self):
        self.print_request()
        request_headers = self.headers
        content_length = self.headers.get_all('Content-Length')
        length = int(content_length[0]) if content_length else 0
        print("%s\n%s%s\n" % (SEPERATOR, str(self.headers), self.rfile.read(length).decode('UTF-8')))
        self.send_response(200)
    
    def print_request(self):
        # 127.0.0.1 - - [20/Mar/2020 19:41:13] "GET /foo123 HTTP/1.1" 200 -
        client_ip = self.address_string()
        date_time = self.log_date_time_string()
        msg = "%s\n[%s] %s - \"%s\"" % (SEPERATOR, date_time, client_ip, self.requestline)
        print(msg)
        
    do_PUT = do_POST
    do_DELETE = do_GET
    do_HEAD = do_GET
    
    def log_message(self, format, *args):
        return

def keyboardInterruptHandler(signal, frame):
    print("Received KeyboardInterrupt. Exiting.")
    exit(0)

def main():
    print("Listening on: %s:%i\n" % (LHOST, LPORT))
    server = HTTPServer((LHOST, LPORT), RequestHandler)
    server.serve_forever()

if __name__ == "__main__":
    signal.signal(signal.SIGINT, keyboardInterruptHandler)
    main()

