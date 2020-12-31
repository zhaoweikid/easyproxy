# coding: utf-8
 
#日志文件
logfile = 'stdout'

# 允许连接的ip，为空表示无限制, 每项为一个python正则表达式
allow_ip = []

# 用户名和密码
user = {}

# 是否允许无用户验证, True/False
is_noauth = False

# socks5代理的地址配置
socks5 = {
    'enable': True,
    'addr': ('0.0.0.0', 1080)
}

# http代理的地址配置
http = {
    'enable': False,
    'addr': ('0.0.0.0', 8080)
}

