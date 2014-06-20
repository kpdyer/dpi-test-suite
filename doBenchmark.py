import sys
import threading
import string
import os
import time
import subprocess
from subprocess import Popen

INTERFACE = 'eth0'
CLIENT_IP = '131.252.42.31'
SERVER_IP = '128.105.214.241'

METHOD = sys.argv[1]
URL = sys.argv[2]

#CMD = 'time curl -s --socks5 '+CLIENT_IP+':8079 '+URL
CMD = 'sudo -u kdyer scp -P 8079 kpdyer@131.252.42.31:~/100M.test .'
CMD_DIRECT = 'sudo -u kdyer scp -P 2222 kpdyer@'+SERVER_IP+':~/100M.test .'

class Recorder(threading.Thread):
    def __init__(self, pcap_file):
        threading.Thread.__init__(self)
        self.pcap_file = pcap_file

        self.scapy_filter = '(tcp) and'
        self.scapy_filter += ' ((src host ' + CLIENT_IP + ') and (dst host ' + SERVER_IP + '))'
        self.scapy_filter += ' or ((src host ' + SERVER_IP + ') and (dst host ' + CLIENT_IP + '))'

    def stop(self):
        try:
            time.sleep(1)
            self.process.terminate()
            while self.process.poll() == None:
                time.sleep(0.1)
        except:
            pass

    def run(self):
        cmd = ['tcpdump', '-i', INTERFACE, '-w', self.pcap_file, self.scapy_filter]
        self.process = Popen(cmd, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
        time.sleep(1)


for i in range(10):
    dst_dir = 'data/'+METHOD
    if not os.path.exists(dst_dir):
        os.makedirs(dst_dir)
    pcap_file = string.rjust(str(i),3,'0')+'.pcap'

    recorder = Recorder(dst_dir+'/'+pcap_file)
    recorder.start()
    start = time.time()
    os.system(CMD)
    res = time.time()-start
    recorder.stop()

    with open('logs/benchmark.log','a') as f:
        f.write(METHOD+','+str(URL)+','+str(res)+'\n')

METHOD = 'direct'
for i in range(10):
    dst_dir = 'data/'+METHOD
    if not os.path.exists(dst_dir):
        os.makedirs(dst_dir)
    pcap_file = string.rjust(str(i),3,'0')+'.pcap'

    recorder = Recorder(dst_dir+'/'+pcap_file)
    recorder.start()
    start = time.time()
    os.system(CMD_DIRECT)
    res = time.time()-start
    recorder.stop()

    with open('logs/benchmark.log','a') as f:
        f.write(METHOD+','+str(URL)+','+str(res)+'\n')
