import select
import socket
import threading
import re
from scapy.all import *
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
import ipaddress

load_layer("http")

DNS_SERVER = "1.1.1.1"

def threaded(fn):
    def wrapper(*args, **kwargs):
        _thread = threading.Thread(target=fn, args=args, kwargs=kwargs)
        _thread.start()
        return _thread

    return wrapper

class DnsQuery:
    @staticmethod
    def hostname_extractor(host_string):
        if "://" in host_string:
            return host_string.split("://")[1].split("/")[0]
        else:
            print("DNS1")
            return host_string

    @staticmethod
    def ip_validation(input_str):
        try:
            ipaddress.ip_address(input_str)
            return True
        except:
            print("DNS2")
            return False

    @staticmethod
    def dns_query(http_host_field):
        hostname = DnsQuery.hostname_extractor(http_host_field)
        if not DnsQuery.ip_validation(hostname):
            try:
                answer = sr1(IP(dst=DNS_SERVER)/UDP(sport=random.randint(1025,65500),dport=53)/DNS(rd=1,qd=DNSQR(qname=hostname)),verbose = 0)
                return answer.an[answer.ancount-1].rdata
            except:
                print("DNS ERROR")
                return
        else:
            return hostname

class HTTPProxy(object):

    def __init__(self, host, port):
        self.host = host
        self.port = port

        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.settimeout(1)
        self.server.bind((self.host, self.port))
        self.stop = False

    @threaded
    def tunnel(self, client_sock: socket.socket, server_sock: socket.socket, chunk_size=1024):
        try:
            while not self.stop:
                r, w, x = select.select([client_sock, server_sock], [], [], 1)
                if client_sock in r:
                    data = client_sock.recv(chunk_size)
                    if len(data) == 0:
                        break
                    server_sock.sendall(data)

                if server_sock in r:
                    data = server_sock.recv(chunk_size)
                    if len(data) == 0:
                        break
                    client_sock.sendall(data)
        except Exception as e:
            print(f"Tunnel exception: {e}")
        finally:
            client_sock.close()
            server_sock.close()

    def handle_client(self, client_sock):
        request = client_sock.recv(4096)
        print(request)
        if not request:
            client_sock.close()
            return
        httpRequest = HTTP() / HTTPRequest(request)
        #httpRequest.show()
        host = DnsQuery.dns_query(httpRequest.Path.decode('utf-8'))
        #print(serverIp, 100 * '-')
        port = 80

        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.connect((host, port))
        
        server_sock.sendall(request)

        self.tunnel(client_sock, server_sock)

    def run(self) -> None:
        self.server.listen()

        while not self.stop:
            try:
                client_sock, addr = self.server.accept()
                if client_sock is None:
                    continue
                self.handle_client(client_sock)
            except KeyboardInterrupt:
                self.stop = True
            except TimeoutError as exp:
                pass
            except Exception as exp:
                print("Exception:", exp)


if __name__ == "__main__":
    http_proxy = HTTPProxy("0.0.0.0", 8082)
    http_proxy.run()
