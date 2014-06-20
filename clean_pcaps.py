import os
import glob
import hashlib
import multiprocessing

mapper = {}
mapper['ssh'] = '22'
mapper['smtp'] = '25'
mapper['http'] = '80'
mapper['sip'] = '5060'
mapper['smb'] = '445'
mapper['rtsp'] = '554'
mapper['bittorrent'] = '6881'

def execute(cmd):
    #print cmd
    os.system(cmd)

def getFiles(rootdir, extension='pcap'):
    fileList = []
    for root, subFolders, files in os.walk(rootdir):
        for file in files:
            filename = os.path.join(root, file)
            if filename.endswith('.' + extension):
                fileList.append(filename)
    return fileList

def doClean(directory):
    files = getFiles(directory)
    p = multiprocessing.Pool(multiprocessing.cpu_count())
    p.map(cleanFile,files)
    p.map(removeEmptyStreams,files)
    p.close()


def removeEmptyStreams(pcap_file):
    m = hashlib.md5()
    m.update(pcap_file)
    dir = m.hexdigest()
    execute('mkdir '+dir+' && cd '+dir+' && tcpflow -r ../'+pcap_file)
    src_ports = []
    dst_ports = []
    for file in glob.glob(dir+'/*'):
        if file.endswith('.xml'): continue
        src_port = file.split('-')[0].split('.')[-1]
        dst_port = file.split('-')[1].split('.')[-1]
        src_ports.append(src_port)
        dst_ports.append(dst_port)

    good_ports = []
    for src_port in src_ports:
        if src_port in dst_ports:
            good_ports.append(str(int(src_port)))
    for dst_port in dst_ports:
        if dst_port in src_ports:
            good_ports.append(str(int(dst_port)))

    execute('rm -rf '+dir)

    good_ports = list(set(good_ports))
    good_ports.sort()
    for val in mapper.values():
        if val in good_ports: good_ports.remove(val)
    for i in range(len(good_ports)):
        good_ports[i] = 'tcp.port=='+good_ports[i]
    GOOD_PORTS = ' || '.join(good_ports)

    cmd = 'tshark -r '+pcap_file+' -R "'+GOOD_PORTS+'" -w '+pcap_file+'.tmp'
    execute(cmd)
    cmd = 'mv '+pcap_file+'.tmp '+pcap_file
    execute(cmd)
    print pcap_file



def cleanFile(file):
    print file
    cmd = 'tshark -r '+file+' -R "tcp.port==8080" -w '+file+'.tmp'
    execute(cmd)
    cmd = 'mv '+file+'.tmp '+file
    execute(cmd)

    dst_port = file.split('/')[1].split('-')[-1]
    cmd = 'tcprewrite --infile='+file+' --outfile='+file+'.tmp --portmap=8080:'+mapper[dst_port]+' 2>/dev/null > /dev/null'
    execute(cmd)
    cmd = 'mv '+file+'.tmp '+file
    execute(cmd)

doClean('data')
