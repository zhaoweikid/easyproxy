# coding: utf-8
 
#日志文件
logfile = 'stdout'

# 允许连接的ip，为空表示无限制, 每项为一个python正则表达式
allow_ip = []

# 用户名和密码
user = {}

# 是必须用户验证, True/False
must_auth = False

# 网络操作超时时间, 单位秒
timeout = 10

# socks5代理的地址配置
socks5 = {
    'enable': True,
    'addr': ('0.0.0.0', 1080)
}

# http代理的地址配置
http = {
    'enable': True,
    'addr': ('0.0.0.0', 8080)
}

