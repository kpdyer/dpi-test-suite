import sys
import socket
import os
import time

FTE_RELEASE = 'fte_relay-current'
SERVER_IP = '128.105.214.241'
CLIENT_IP = '131.252.42.31'
CLIENT_PORT = '8079'
LISTEN_PORTS = [8079,9000,9001,9002,9003,9004,9005,9006,9007]

if FTE_RELEASE == None:
    print 'Please set FTE_RELEASE in main.py to your fte directory'
    sys.exit(1)
if CLIENT_IP == None:
    print 'Please set CLIENT_IP in main.py to the interface you want fte to use'
    sys.exit(1)

REGEX_PAIRS = []
#for type in ['appid','yaf1','yaf2','l7','intersection','manual','scott']:
for type in ['intersection','manual','scott']:
    for protocol in ['smb','http','ssh']:
        REGEX_PAIRS.append([type + '-' + protocol + '-request',
                            type + '-' + protocol + '-response'])

def execute(cmd):
    print cmd
    os.system(cmd)

for pair in REGEX_PAIRS:
    execute('cd '+FTE_RELEASE+' && ./bin/fte_relay --mode client --client_ip '+CLIENT_IP+' --server_ip '+SERVER_IP+' --upstream-format '+str(pair[0])+' --downstream-format '+str(pair[1])+' &')
    if pair[0]=='scott-http-request':
        time.sleep(60)
    else:
        time.sleep(5)
    dst_dir = '-'.join(pair[0].split('-')[:-1])
    execute('python doCollection.py socks-over-fte '+dst_dir)
    execute('mv data/socks-over-fte data/'+dst_dir)
    #execute('python doBenchmark.py '+dst_dir+' 100M')
    execute('cd '+FTE_RELEASE+' && ./bin/fte_relay --mode client --stop')

    for port in LISTEN_PORTS:
        while True:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.bind((CLIENT_IP, port))
                sock.close()
                break
            except socket.error:
                time.sleep(1)
                continue
