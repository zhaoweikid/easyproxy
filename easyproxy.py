# coding: utf-8
from gevent import monkey; monkey.patch_all()
import os, sys
import traceback
import gevent
import socks5, httpproxy, logger
import config

def usage():
    print('usage:')
    print('\tpython3 easyproxy.py')
    print('')
    sys.exit(0)

def main():
    logger.install(config.logfile)
    
    if config.socks5 and config.socks5['enable']:
        s = socks5.Socks5Server()
        gevent.spawn(s.run)

    if config.http and config.http['enable']:
        h = httpproxy.HttpProxyServer()
        gevent.spawn(h.run)

    gevent.wait()

if __name__ == '__main__':
    main()


