import os

with open('logs/socks-over-fte.log') as f:
    contents = f.read().strip()

for line in contents.split('\n'):
    bits = line.split(',')
    if bits[3] == 'ERROR':
        pcap = 'data/'+bits[-1]+'/'+bits[2]+'/'+bits[0]+'.pcap'
        print pcap
        os.system('rm '+pcap)
    elif int(bits[-2]) > 10000000:
        pcap = 'data/'+bits[-1]+'/'+bits[2]+'/'+bits[0]+'.pcap'
        print pcap
        os.system('rm '+pcap)
    elif int(bits[-2]) == 4096:
        pcap = 'data/'+bits[-1]+'/'+bits[2]+'/'+bits[0]+'.pcap'
        print pcap
        os.system('rm '+pcap)
    elif int(bits[3]) > 60:
        pcap = 'data/'+bits[-1]+'/'+bits[2]+'/'+bits[0]+'.pcap'
        print pcap
        os.system('rm '+pcap)
