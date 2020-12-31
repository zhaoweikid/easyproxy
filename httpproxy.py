# coding: utf-8
if __name__ == '__main__':
    from gevent import monkey; monkey.patch_all()
import os, sys
import struct
import socket
import time
import traceback
import config
import gevent
from errno import EAGAIN, EBADF, EPIPE


class HTTPHeader:
    def __init__(self):
        self.method = ''
        self.uri = ''
        self.path = ''
        self.version = '1.0'

        self.content_len = 0 
        self.chunked = False
        self.keepalive = False

        self.header = []

    def firstline(self, line):
        p = line.strip().split()
        self.method = p[0]
        self.uri = p[1]
        self.version = p[2][5:]

    def line(self, line):
        self.header.append(line)
        p = [x.strip().lower() for x in line.stirp().split(':')]
        name = p[0]
        value = p[1]
        if name == 'content-length':
            self.content_len = int(value)
        elif name == 'connection' and value == 'keep-alive':
            self.keepalive = True
        elif name == 'transfer-encoding' and value == 'chunked':
            self.chunked = True


    def whether_close(self):
        if self.version == '1.0':
            return True
        if keepalive == False:
            return True

        return True

    def make(self):
        header = []
        first = '%s %s HTTP/%s\r\n' % (self.method, self.path, self.version)
        header.append(first)
        for x in self.header:
            header.append(x)
        if header[-1] != '\r\n':
            header.append('\r\n')
        s = ''.join(header)

        return s


class HTTPProxyProtocol:
    def __init__(self, sock):
        self.client = sock
        self.bufsize = 8192
        self.client_keepalive = False
        self.remote_keepalive = False

        self.clientfile = self.client.makefile()

        self.remote = None

    def close(self):
        if self.client:
            self.client.close()
            self.client = None
        if self.remote:
            self.remote.close()
            self.remote = None

    def run(self):
        header =  self.read_header(self.clientfile)
        
        

    def read_header(self, sockfile):
        h = HTTPHeader()
        first = sockfile.readline()
        h.firstline(first)
       
        while True:
            line = sockfile.readline()
            h.line(line)
            line = line.strip()
            if not line:
                break
           
        return h

    def remote_recv(self):
        tn = 0
        log.debug('remote recv ...')
        while True:
            try:
                data = self.remote.recv(self.bufsize, socket.MSG_DONTWAIT)
                #log.debug('remote recv:%d %s', len(data), data)
                if not data:
                    log.debug('remote recv null')
                    #gevent.sleep(1)
                    #continue
                    server_info.close_conn(self.key)
                    return
                tn = 0
                self.client.sendall(data)
            except socket.timeout:
                log.info('remote timeout')
                tn += 1
                if tn >= 3:
                    log.info('remote timeout 3, close')
                    server_info.close_conn(self.key)
                    return 
            except socket.error as e:
                log.info('socket error:%s', e.args)
                if e.args[0] == EAGAIN:
                    continue
                if e.args[0] in (EBADF, EPIPE, ECONNRESET):
                    log.info('socket closed')
                else:
                    log.info(traceback.format_exc())
                server_info.close_conn(self.key)
                return
            except Exception as e:
                log.debug(e)
                log.info(traceback.format_exc())
                server_info.close_conn(self.key)
                return

    def client_recv(self):
        tn = 0
        log.debug('client recv ...')
        while True:
            try:
                data = self.client.recv(self.bufsize, socket.MSG_DONTWAIT)
                #log.debug('client recv:%d %s', len(data), data)
                if not data:
                    log.debug('client recv null')
                    return
                tn = 0
                ret = self.remote.sendall(data)
                #log.debug('send remote:%d', len(data))
            except socket.timeout:
                log.info('client timeout')
                tn += 1
                if tn >= 3:
                    log.info('client timeout 3, close')
                    server_info.close_conn(self.key)
                    return 
            except socket.error as e:
                log.info('socket error:%s', e.args)
                if  e.args[0] == EAGAIN:
                    continue
                if e.args[0] in (EBADF, EPIPE, ECONNRESET):
                    log.info('socket closed')
                else:
                    log.info(traceback.format_exc())
                server_info.close_conn(self.key)
                return
            except:
                log.info(traceback.format_exc())
                server_info.close_conn(self.key)
                return



class HTTPProxyServer:
    def __init__(self):
        self.config = config.http
        self.create_server()

    def create_server(self):
        log.warning('http proxy server start at %s:%d', self.config['addr'][0], self.config['addr'][1])
        self.sock = socket.create_server(self.config['addr'])
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


