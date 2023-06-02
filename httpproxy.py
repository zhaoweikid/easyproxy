# coding: utf-8
if __name__ == '__main__':
    from gevent import monkey; monkey.patch_all()
import os, sys
import struct
import socket
import time
import traceback
import config
import urllib
import urllib.parse
import logging
import gevent
from errno import EAGAIN, EBADF, EPIPE, ECONNRESET

log = logging.getLogger()

auth_html = b'''<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
 "http://www.w3.org/TR/1999/REC-html401-19991224/loose.dtd">
<HTML>
  <HEAD>
    <TITLE>Error</TITLE>
    <META HTTP-EQUIV="Content-Type" CONTENT="text/html; charset=ISO-8859-1">
  </HEAD>
  <BODY><H1>401 Unauthorized.</H1></BODY>
</HTML>'''

class HTTPHeader:
    def __init__(self):
        self.method = ''
        self.uri = ''
        self.scheme = ''
        self.domain = ''
        self.addr = ['', 80]
        self.path = ''
        self.version = '1.0'

        self.username = ''
        self.password = ''

        self.content_len = 0 
        self.chunked = False
        self.keepalive = False

        self.status = ''
        self.status_text = ''

        self.header = []

    def __str__(self):
        return 'domain:%s keepalive:%s' % (self.domain, self.keepalive)

    def firstline(self, line):
        if line.startswith(b'HTTP/'):
            return self.response_firstline(line)
        else:
            return self.request_firstline(line)


    def request_firstline(self, line):
        p = line.decode('utf-8').strip().split()
        self.method = p[0]
        self.uri = p[1]
        self.version = p[2][5:]


        if self.method == 'CONNECT':
            self.domain = self.uri
        else:
            p = urllib.parse.urlparse(self.uri)
            #log.debug('parse uri:%s', p)
            self.scheme = p.scheme
            self.domain = p.netloc
            self.path = p.path

            if self.scheme == 'http' or self.scheme == 'ws':
                self.addr[1] = 80
            elif self.scheme == 'https' or self.scheme == 'wss':
                self.addr[1] = 443

        if ':' in self.domain:
            a = self.domain.split(':')
            self.addr[0] = a[0]
            self.addr[1] = int(a[1])
        else:
            self.addr[0] = self.domain
        
        log.debug('addr: %s', self.addr)

    def response_firstline(self, line):
        p = line.decode('utf-8').strip().split(None, 2)
        self.version = p[0][5:]
        self.status = p[1]
        self.status_text = p[2]


    def line(self, line):
        self.header.append(line)
        if line == b'\r\n' or line == b'\n':
            return
        p = [x.strip() for x in line.decode('utf-8').strip().split(':', 1)]
        #log.debug('line:%s', p)
        name = p[0].lower()
        value = p[1].lower()
        if name == 'content-length':
            self.content_len = int(value)
        elif name == 'connection' and value == 'keep-alive':
            self.keepalive = True
        elif name == 'proxy-connection' and value == 'keep-alive':
            self.keepalive = True
        elif name == 'transfer-encoding' and value == 'chunked':
            self.chunked = True
        elif name == 'proxy-authorization':
            a = p[1].strip().split()
            if a[0].lower() == 'basic':
                v = base64.b64decode(a[1]).split(':')
                self.username = v[0]
                self.password = v[1]


    def whether_close(self):
        if self.version == '1.0':
            return True
        if self.keepalive == False:
            return True

        return False

    def make(self):
        header = []
        if self.status:
            first = 'HTTP/%s %s %s\r\n' % (self.version, self.status, self.status_text)
            header.append(first.encode('utf-8'))
        else:
            first = '%s %s HTTP/%s\r\n' % (self.method, self.path, self.version)
            header.append(first.encode('utf-8'))

        for x in self.header:
            header.append(x)
        if header[-1] != b'\r\n':
            header.append(b'\r\n')
        s = b''.join(header)

        return s


class HttpSocket:
    def __init__(self, addr=None, sock=None):
        self.addr = addr
        self.sock = sock
        self.data = b''

    def close(self):
        if self.sock:
            self.sock.close()
            self.sock = None

    def connect(self):
        if self.sock:
            return
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(config.timeout)
        log.debug('connect to %s', self.addr)
        self.sock.connect(self.addr)
        
    def read_until(self, utilstr, origin=b''):
        data = origin
        pos = data.find(utilstr)
        if pos >= 0:
            return pos, data
        while True:
            s = self.sock.recv(1024)
            log.debug('recv:%d', len(s))
            if not s:
                return -1, data
            data += s

            pos = data.find(utilstr)
            if pos >= 0:
                return pos, data


    def readn(self, n):
        data = b''
        while n > 0:
            s = self.sock.recv(n)
            log.debug('recv:%d', len(s))
            if not s:
                return data
            data += s
            n -= len(s)

        return data
 
    def read_header(self):
        h = HTTPHeader()
        pos, data = self.read_until(b'\n')
        if pos < 0:
            raise ValueError('read header error')
        first = data[:pos+1]
        log.debug('header first: %s', repr(first))
        h.firstline(first)
        
        data = data[pos+1:]
        while True:
            pos, data = self.read_until(b'\n', data)
            if pos < 0:
                raise ValueError('read header error')
            line = data[:pos+1]
            data = data[pos+1:]
            
            #log.debug('header line: %s', repr(line))
            h.line(line)
            line = line.strip()
            if not line:
                self.data = data
                break
           
        return h


   
    def read_body(self, header):
        data = self.data
        self.data = b''
        if header.content_len > 0:
            log.debug('read body:%d', header.content_len)
            s = data + self.readn(header.content_len-len(data))
            return s
        elif header.chunked:
            log.debug('read body chunked')
            s = []
            while True:
                pos, data = self.read_until(b'\n', data)
                if pos < 0:
                    raise ValueError('chunk data error: pos=%d', pos)
                #log.debug('data:%s', data)
                lenstr = data[:pos+1]
                data = data[pos+1:]
                length = int(lenstr.decode('utf-8').strip(), 16)
                log.debug('lenstr:%s length:%d', lenstr, length)
                if length == 0:
                    if len(data) < 2:
                        self.readn(2-len(data))
                    return b''.join(s)
                if len(data) < length+2:
                    a = self.readn(length+2-len(data))
                    data += a 
                    s.append(data[:-2])
                    data = b''
                else:
                    s.append(data[:length])
                    # skip \r\n
                    data = data[length+2:]

        else:
            log.debug('read body until close')
            s = [data]
            while True:
                data = sock.read(8092) 
                log.debug(repr(data))
                if not data:
                    return b''.join(s)
                s.append(data)



class HTTPProxyProtocol:
    def __init__(self, sock):
        self.client = HttpSocket(sock=sock)
        self.remote = None
        self.bufsize = 8192
        
    def close(self):
        log.info('close client and remote')
        if self.client:
            self.client.close()
            self.client = None

        if self.remote:
            self.remote.close()
            self.remote = None

    def run(self):
        while True:
            try:
                header = self.client.read_header()
                log.debug('header %s', header)
                body = b''
                if header.method == 'POST':
                    body = self.client.read_body(header)

                if config.must_auth and not header.username:
                    log.info('must_auth:%s', config.must_auth)
                    self.auth_note()
                    continue

                if header.username:
                    log.info('have http basic auth')
                    ps = config.user.get(header.username)
                    if not ps:
                        self.auth_error()
                        continue 

                    if ps != header.password:
                        self.auth_error()
                        continue 
                    
                log.debug('method:%s', header.method)
                if header.method == 'CONNECT':
                    self.create_conn(header.addr)
                    self.conn_succ()

                    gevent.spawn(self.client_recv)
                    self.remote_recv()

                    return
                else:
                    self.create_conn(header.addr)
                    s = header.make() + body
                    log.debug('send to remote:%d', len(s))
                    #log.debug('send to remote:%d %s', len(s), repr(s))
                    self.remote.sock.sendall(s)

                    log.debug('recv remote response ...') 
                    h = self.remote.read_header()
                    log.debug('header:%s', h)
                    body = self.remote.read_body(h)
                    s = h.make() + body
                    log.debug('send to client:%d', len(s))
                    #log.debug('send to client:%d %s', len(s), repr(s))
                    self.client.sock.sendall(s)

                    if h.whether_close():
                        self.close()
                        return
            except:
                log.info(traceback.format_exc())
                self.close()
                return
            
       
    def create_conn(self, addr):
        if self.remote:
            return
        self.remote = HttpSocket(tuple(addr))
        self.remote.connect()

    def conn_succ(self):
        s = b'HTTP/1.1 200 Connection established\r\nContent-Length: 0\r\n\r\n'
        self.client.sock.sendall(s)

    def auth_note(self):
        s = b'HTTP/1.0 401 Authorization Required\r\nWWW-Authenticate: Basic realm="Secure Area"\r\n'
        s += b'Content-Length: %d\r\n\r\n' % len(auth_html) + auth_html
        self.client.sock.sendall(s)

    def remote_recv(self):
        tn = 0
        log.debug('remote recv ...')
        while True:
            try:
                data = self.remote.sock.recv(self.bufsize, socket.MSG_DONTWAIT)
                #log.debug('remote recv:%d %s', len(data), data)
                if not data:
                    log.debug('remote recv null')
                    #gevent.sleep(1)
                    #continue
                    self.close()
                    return
                tn = 0
                self.client.sock.sendall(data)
            except socket.timeout:
                log.info('remote timeout')
                tn += 1
                if tn >= 3:
                    log.info('remote timeout 3, close')
                    self.close()
                    return 
            except socket.error as e:
                log.info('socket error:%s', e.args)
                if e.args[0] == EAGAIN:
                    continue
                if e.args[0] in (EBADF, EPIPE, ECONNRESET):
                    log.info('socket closed')
                else:
                    log.info(traceback.format_exc())
                self.close()
                return
            except Exception as e:
                log.debug(e)
                log.info(traceback.format_exc())
                self.close()
                return

    def client_recv(self):
        tn = 0
        log.debug('client recv ...')
        while True:
            try:
                data = self.client.sock.recv(self.bufsize, socket.MSG_DONTWAIT)
                #log.debug('client recv:%d %s', len(data), data)
                if not data:
                    log.debug('client recv null')
                    return
                tn = 0
                ret = self.remote.sock.sendall(data)
                #log.debug('send remote:%d', len(data))
            except socket.timeout:
                log.info('client timeout')
                tn += 1
                if tn >= 3:
                    log.info('client timeout 3, close')
                    self.close()
                    return 
            except socket.error as e:
                log.info('socket error:%s', e.args)
                if  e.args[0] == EAGAIN:
                    continue
                if e.args[0] in (EBADF, EPIPE, ECONNRESET):
                    log.info('socket closed')
                else:
                    log.info(traceback.format_exc())
                self.close()
                return
            except:
                log.info(traceback.format_exc())
                self.close()
                return



class HTTPProxyServer:
    def __init__(self):
        self.config = config.http
        self.create_server()

    def create_server(self):
        log.warning('http proxy server start at %s:%d', self.config['addr'][0], self.config['addr'][1])

        #self.sock = socket.create_server(self.config['addr'])
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(self.config['addr'])
        self.sock.listen(256)
 
        self.sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)

    def run(self):
        while True:
            try:
                conn, addr = self.sock.accept()
                log.info('new client %s:%d' % addr)

                proto = HTTPProxyProtocol(conn)
                gevent.spawn(proto.run)
            except KeyboardInterrupt:
                break
            except socket.error:
                log.info(traceback.format_exc())
            except:
                log.info(traceback.format_exc())


def server(port):
    import logger
    global log
    log = logger.install('stdout')
    s = HTTPProxyServer()
    s.run()

if __name__ == '__main__':
    port = 1080
    if len(sys.argv) == 2:
        port = int(sys.argv[1])
    server(port)


