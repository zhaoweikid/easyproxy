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
from errno import EAGAIN, EBADF, EPIPE, ECONNRESET
import logging

log = logging.getLogger()

VERSION = 5

METHOD_NOAUTH   = 0
METHOD_GSSAPI   = 1
METHOD_AUTH     = 2
METHOD_IANA     = 3
METHOD_RESERVED = 4
METHOD_NO       = 0xff

CMD_CONNECT = 1
CMD_BIND    = 2
CMD_UDP     = 3

ATYP_IPv4   = 1
ATYP_DOMAIN = 3
ATYP_IPv6   = 4

OK = 0
ERR = 1
ERR_NOT_ALLOW = 2
ERR_NET = 3
ERR_HOST = 4
ERR_REFUSED = 5
ERR_EXPIRE = 6
ERR_NOT_SUPPORT = 7
ERR_ADDR = 8

err = {
}


RET_OK = 0
RET_AUTH = 1
RET_ERR = -1
RET_CONN = 2
RET_BIND = 3
RET_UDP = 4

class ServerInfo:
    def __init__(self):
        # {'client':clientsock, 'bindaddr':None, 'bind':sock, 'remoteaddr':'', 'remote':sock,}
        self.conn_info = {}
        # {'sock':sock, 'proto':'tcp/udp'}
        #self.bind_info = {}

    def haskey(self, key):
        return key in self.conn_info

    def get(self, key):
        return self.conn_info.get(key)

    def create_conn(self, key, conn):
        x = {'client':conn}
        self.conn_info[key] = x
        return x

    def close_conn(self, key):
        log.info('close %s', key)
        info = self.conn_info.get(key)
        if not info:
            return

        for nm in ('bind','remote','client'):
            sock = info.get(nm)
            if sock:
                sock.close()
        
        self.conn_info.pop(key) 

    def add_bind(self, key, bind, bindaddr):
        self.add(key, 'bind', bind, bindaddr)

    def add_remote(self, key, remote, remoteaddr):
        self.add(key, 'remote', remote, remoteaddr)

    def add(self, key, name, sock, sockaddr):
        if name not in ('bind', 'remote'):
            return
        info = self.conn_info[key]
        info[name] = sock
        info[name+'addr'] = sockaddr

    def set_client_addr(self, key, addr):
        info = self.conn_info[key]
        info['clientaddr'] = addr



server_info = ServerInfo()


class TCPDataServer:
    def __init__(self, key):
        self.key = key
        info = server_info.get(key)
        self.info = info
        self.client = info['client']
        self.remote = info['remote']

        self.bufsize = 16384
        self.timeoutn = 3

    def run(self):
        gevent.spawn(self.remote_recv)
        self.client_recv()

    def remote_recv(self):
        tn = 0
        #log.debug('remote recv ...')
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
        #log.debug('client recv ...')
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


class UDPDataServer:
    def __init__(self, key):
        self.key = key
        info = server_info.get(key)
        self.info = info
        self.bindsock = info['bind']

    def run(self):
        remoteaddr = info['remoteaddr']
        clientaddr = info['clientaddr']

        while True:
            try:
                data, addr = self.bindsock.recvfrom(1024)
                if addr[0] == clientaddr[0] and addr[1] == clientaddr[1]:
                    self.bindsock.sendto(data, remoteaddr)
                else:
                    self.bindsock.sendto(data, clientaddr)
            except:
                log.info(traceback.format_exc())
                server_info.close_conn(self.key)
                return


    def udp_data(self, addr, data):
        rsv, frag, atyp = struct.unpack('>Hbb', data[:4])
        if atyp != ATYP_IPv4:
            log.info('udp relay only support ipv4')
            return None
        ip = socket.inet_ntoa(data[4:8])
        port = struct.unpack('>H', data[8:10])
        data = data[10:]
        return (ip, port), data


class Sock5Protocol:
    def __init__(self, key):
        global server_info
        self.key = key
        self.info = server_info.get(key)
        self.conn = self.info['client']
        self.allow_methods = [METHOD_NOAUTH, METHOD_AUTH]
        self.timeout = 30

        self.conn.settimeout(self.timeout)

    def run(self):
        global server_info
        try:
            ret = self.shake()
            if ret < 0:
                server_info.close_conn(self.key)
                return
            if ret == RET_AUTH:
                ret = self.auth()
                if ret < 0:
                    server_info.close_conn(self.key)
                    return

            ret = self.action()
            if ret < 0:
                server_info.close_conn(self.key)
                return
            
            if ret == RET_CONN:
                r = TCPDataServer(self.key)
                r.run()
            elif ret == RET_BIND:
                self.wait_accept(sock)
                r = TCPDataServer(self.key)
                r.run()
            else: # UDP
                r = UDPDataServer(self.key)
                gevent.spawn(r.run)
                while True:
                    ret = self.conn.recv(1024)
                    if not ret:
                        break
        except:
            log.info(traceback.format_exc())
        finally:
            server_info.close_conn(self.key)


    def wait_accept(self, sock):
        global server_info
        
        conn, addr = sock.accept()
        server_info.add_remote(self.key, conn, addr)
            
        s = struct.pack('>bbbb4sH', VERSION, OK, 0, 1, 
                socket.inet_aton(addr[0]), addr[1]) 
        log.debug('remote:%s', repr(s))
        self.conn.sendall(s)


    def shake(self):
        data = self.conn.recv(2)
        req = data
        ver, n = struct.unpack('>bb', data)
        #log.debug('version:%d method_n:%d', ver, n)
        if ver != VERSION:
            log.debug('version error: %d', ver)
            self.simple_err(err=METHOD_NO)
            return RET_ERR

        data = self.conn.recv(n)
        req += data
        log.debug('shake req: %s', repr(req))
        methods = struct.unpack('>'+'b'*n, data)
        #log.debug('req methods: %s', methods)

        m = set(self.allow_methods) & set(methods)
        if len(m) == 0:
            self.simple_err(err=METHOD_NO)
            return RET_ERR
        m = list(m)
        #log.debug('choose method: %d', m[0])
        s = struct.pack('>bb', VERSION, m[0])
        log.debug('shake: %s', repr(s))
        self.conn.sendall(s)
        if m[0] == METHOD_AUTH:
            return RET_AUTH
        return RET_OK

    def auth(self):
        data = self.conn.recv(2)
        ver, ulen = struct.unpack('>bb', data)
        #log.debug('auth ver:%d ulen:%d', ver, ulen)
        if ver != 1:
            log.debug('auth version error:%d', ver)
            self.simple_err(1, 3)
            return RET_ERR
        if ulen <= 0:
            log.debug('auth user len error:%d', ulen)
            self.simple_err(1, 2)
            return RET_ERR
        user = self.conn.recv(ulen)
        data = self.conn.recv(1)
        plen, = struct.unpack('>b', data)
        #log.debug('auth plen:%d', plen)
        if plen <= 0:
            log.debug('auth password len error:%d', plen)
            self.simple_err(1, 2)
            return RET_ERR
        password = self.conn.recv(plen)
        log.debug('user:%s password:%s', user, password)
        
        p = self.user.get(user)
        if not p or p != password:
            log.debug('auth password error')
            self.simple_err(1, 1)
            return RET_ERR
        
        s = struct.pack('>bb', 1, 0)
        log.debug('auth:%s', repr(s))
        self.conn.sendall(s)
        return RET_OK

    def action(self):
        data = self.conn.recv(10)
        if not data:
            log.debug('action req recv null')
            return RET_ERR
        log.debug('action req: %s', repr(data))
        ver, cmd, rsv, atyp = struct.unpack('>bbbb', data[:4])
        if ver != VERSION:
            log.debug('version error')
            self.action_err()
            return RET_ERR
        if atyp not in (ATYP_IPv4, ATYP_DOMAIN):
            log.debug('atype error:%d', atyp)
            self.action_err()
            return RET_ERR
        #data2 = data[4:]
        if atyp == ATYP_DOMAIN:
            dlen, = struct.unpack('>b', data[4:5])
            #log.debug('dlen: %d', dlen)
            d2 = self.conn.recv(dlen+1-4)
            data += d2
            ip = data[5:5+dlen]
            port, = struct.unpack('>H', data[5+dlen:])
        else:
            ip, port = struct.unpack('>4sH', data[4:])
            ip = socket.inet_ntoa(ip)
        log.debug('ip:%s port:%d', ip, port)
        sock = None

        newip = '0.0.0.0'
        newport = 0
        if cmd == CMD_CONNECT:
            try:
                addr = (ip, port)
                sock = socket.create_connection(addr, self.timeout) 
                sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
                log.info('connected %s:%d', addr[0], addr[1])
            except:
                log.info('connect error %s:%d', addr[0], addr[1])
                log.info(traceback.format_exc())
                self.action_err(ERR_NET)
                return RET_ERR
            newip, newport = sock.getsockname()
            server_info.add_remote(self.key, sock, addr)
        elif cmd == CMD_BIND:
            try:
                sock = socket.create_server(('0.0.0.0', 0))
                sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
                addr = sock.getsockname()
                log.info('bind %s:%d', addr[0], addr[1])
            except:
                log.info('bind error %s:%d', addr[0], addr[1])
                log.info(traceback.format_exc())
                self.action_err(ERR_NET)
                return RET_ERR
            server_info.add_bind(self.key, sock, addr)
        elif cmd == CMD_UDP:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
                sock.bind('0.0.0.0', 0)
            except:
                log.info(traceback.format_exc())
                self.action_err(ERR_NET)
                return RET_ERR
            addr = sock.getsockname()
            server_info.add_bind(self.key, sock, addr)
            server_info.set_client_addr(self.key, (ip, port))
        else:
            self.action_err()
            return RET_ERR

        s = struct.pack('>bbbb4sH', VERSION, OK, 0, 1, socket.inet_aton(newip), newport) 
        #if atyp == ATYP_IPv4:
        #    s = struct.pack('>bbbb4sH', VERSION, OK, 0, 1, socket.inet_aton(newip), newport) 
        #elif atyp == ATYP_DOMAIN:
        #    s = struct.pack('>bbbbb', VERSION, OK, 0, 1, len(newip)) 
        #    s += newip.encode('utf-8')
        #    s += struct.pack('>H', newport)

        log.debug('action: %s ok', repr(s))
        self.conn.sendall(s)

        if cmd == CMD_CONNECT:
            return RET_CONN
        elif cmd == CMD_BIND:
            return RET_BIND
        else:
            return RET_UDP

    def action_err(self, err=ERR):
        s = struct.pack('>bbbbIH', VERSION, err, 0, 1, 0, 0)
        log.debug('action err:%s', repr(s))
        self.conn.sendall(s)

    def simple_err(self, ver=VERSION, err=ERR):
        s = struct.pack('>bb', ver, err)
        log.debug('simple err:%s', repr(s))
        self.conn.sendall(s)

class Socks5Server:
    def __init__(self):
        self.config = config.socks5
        self.create_server()
        #self.info = ServerInfo()
        #self.proto = Sock5Protocol(self)

    def create_server(self):
        log.warning('sock5 server start at %s:%d', self.config['addr'][0], self.config['addr'][1])
        self.sock = socket.create_server(self.config['addr'])
        self.sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)

    def run(self):
        global server_info
        while True:
            try:
                conn, addr = self.sock.accept()
                log.info('new client %s:%d' % addr)
                key = '%s:%d' % addr
                if key in server_info.conn_info:
                    server_info.close_conn(key)

                server_info.create_conn(key, conn)

                proto = Sock5Protocol(key)
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
    s = Socks5Server()
    s.run()

if __name__ == '__main__':
    port = 1080
    if len(sys.argv) == 2:
        port = int(sys.argv[1])
    server(port)


