import threading
import multiprocessing
import glob
import os

import appid

LD_LIBRARY_PATH = "./classifiers/opt/lib:./classifiers/opt/lib/yaf"
BRO_BIN = "./classifiers/opt/bin/bro"
YAF_BIN = "./classifiers/opt/bin/yaf"
YAFSCII_BIN = "./classifiers/opt/bin/yafscii"
NPROBE_BIN = "./classifiers/opt/bin/nprobe"

FORMATS = []
for type in ['scott','manual', 'intersection']:
#for type in ['scott','manual','appid', 'intersection', 'yaf1', 'yaf2', 'l7']:
    for protocol in ['http', 'ssh', 'smb']:
        FORMATS.append(type + '-' + protocol)

def execute(cmd):
    cmd = "LD_LIBRARY_PATH=" + LD_LIBRARY_PATH + ' ' + cmd
    print cmd
    os.system(cmd)

def getFiles(rootdir, extension = 'pcap'):
    fileList = []
    for root, subFolders, files in os.walk(rootdir):
        for file in files:
            filename = os.path.join(root, file)
            if filename.endswith('.' + extension):
                fileList.append(filename)
    return fileList

def readBroConnFile(conn_file, index = 7):
    retval = []

    with open(conn_file) as f:
        content = f.read().strip()

    for line in content.split('\n'):
        line = line.strip()
        if line.startswith('#') or not line: continue
        if line.startswith('#close'): continue
        #if line.split('\t')[9] == '-': continue 
        #if line.split('\t')[10] == '-': continue 
        #if line.split('\t')[9] == '0': continue 
        #if line.split('\t')[10] == '0': continue 
        if line.split('\t')[10] == 'RSTRH': continue 
        retval.append(line.split('\t')[index])

    return retval

def readBroSmbFile(smb_file):
    retval = []

    try:
        with open(smb_file) as f:
            content = f.read().strip()
    except:
        return []

    for line in content.split('\n'):
        if not line: continue
        if line.startswith('#close'):
            break
        if line.startswith('#') or not line:
            continue
        retval.append(line.split('\t')[3])

    return retval

def doBro():
    for format in FORMATS:
        if format.split('-')[1] == 'smb':
            accuracy = set()
            baseline = set()
        else:
            accuracy = []

        files = getFiles('data/' + format)
        for file in files:
            cmd = BRO_BIN + ' -C -r ' + file
            execute(cmd)

            if format.split('-')[1] == 'smb':
                cmd_file = 'smb_cmd.log'
                conn_file = 'conn.log'
                _acc = set(readBroSmbFile(cmd_file))
                _base = set(readBroConnFile(conn_file, 3))
                if str(445) in _base:
                    _base.remove(str(445))
                accuracy = accuracy.union(_acc)
                baseline = baseline.union(_base)
                accuracy = set(accuracy)
                baseline = set(baseline)
            else:
                conn_file = 'conn.log'
                try:
                    accuracy += readBroConnFile(conn_file)
                except IOError:
                    pass

            cmd = 'rm *.log'
            execute(cmd)

        if len(accuracy)==0: continue
        with open('results/bro-' + format + '.log', 'w') as f:
            if format.split('-')[1] == 'smb':
                if len(accuracy)==0:
                    result = 0.0
                else:
                    result = 1.0 - (1.0 * len(baseline.difference(accuracy)) / len(baseline))
            else:
                result = str(1.0 * accuracy.count(format.split('-')[1]) / len(accuracy))
            f.write('bro-' + format + ' ' + str(result))
            f.write('\n')

def readYAFFile(conn_file):
    retval = []

    with open(conn_file) as f:
        content = f.read().strip()

    for line in content.split('\n'):
        line = line.strip()
        if line.split(' ')[2] == 'tcp': continue
        # print len(line.split(' '))
        if line.endswith('applabel: 80'):
            retval.append('http')
        elif line.endswith('applabel: 22'):
            retval.append('ssh')
        elif line.endswith('applabel: 25'):
            retval.append('smtp')
        elif line.endswith('applabel: 554'):
            retval.append('rtsp')
        elif line.endswith('applabel: 5060'):
            retval.append('sip')
        elif line.endswith('applabel: 139'):
            retval.append('smb')
        else:
            retval.append('-')

    return retval

def doYAF():
    p = multiprocessing.Pool(multiprocessing.cpu_count())
    p.map(doSingleYaf, FORMATS)

def doSingleYaf(format):
    accuracy = []
    target_file = 'yaf.tmp.' + format
    for file in getFiles('data/' + format):
        cmd = YAF_BIN + ' --applabel --max-payload 2048 -i ' + file + ' -o '+target_file
        execute(cmd)

        cmd = YAFSCII_BIN + ' -i ' + target_file + ' -o ' + target_file + '.yaf'
        execute(cmd)

        conn_file = target_file + '.yaf'
        res = readYAFFile(conn_file)
        accuracy += res
        print file, res

        cmd = 'rm ' + target_file
        execute(cmd)
        cmd = 'rm ' + target_file + '.yaf'
        execute(cmd)

    if len(accuracy) > 0:
        with open('results/yaf-' + format + '.log', 'w') as f:
            f.write('yaf-' + format + ' ' + str(1.0 * accuracy.count(format.split('-')[1]) / len(accuracy)))
            f.write('\n')

def readL7File(conn_file):
    retval = []

    with open(conn_file) as f:
        content = f.read().strip()

    # print content.strip()
    for line in content.split('\n'):
        if not line.strip():
            continue
        line = line.strip()
        if line.split(' ')[-1] == 'eof': continue
        retval.append(line.strip())

    return retval

def doL7():
    p = multiprocessing.Pool(multiprocessing.cpu_count())
    p.map(doOneL7, FORMATS)

def doOneL7(format):
    accuracy = []
    for file in getFiles('data/' + format):
        dst_dir = 'l7-' + format
        cmd = 'mkdir ' + dst_dir + ' && cd ' + dst_dir + ' && tcpflow -b 2048 -r ../' + file
        execute(cmd)

        for file in glob.glob(dst_dir + '/128.105.214.241*'):
            with open(file) as f:
                if len(f.read().strip())==0: continue
            cmd = 'cat ' + file
            cmd += '| ./classifiers/l7-protocols-2009-05-28/testing/test_speed-userspace'
            cmd += ' -f ./classifiers/l7-protocols-2009-05-28/protocols/' + format.split('-')[1] + '.pat >> ' + dst_dir + '/l7.results'
            # print cmd
            execute(cmd)
            with open(dst_dir + '/l7.results', 'a') as f:
                f.write('\n')

        conn_file = dst_dir + '/l7.results'
        accuracy += readL7File(conn_file)

        cmd = 'rm -rfv ' + dst_dir
        execute(cmd)

    print accuracy
    if len(accuracy) > 0:
        with open('results/l7-' + format + '.log', 'w') as f:
            f.write('l7-' + format + ' ' + str(1.0 * accuracy.count('match') / len(accuracy)))
            f.write('\n')

def readNprobeFile(conn_file):
    with open(conn_file) as f:
        content = f.read().strip()

    retval = []
    for line in content.split('\n')[1:]:
        if not line: continue
        if '|' not in line: continue
        retval.append(line.split('|')[0].lower())

    return retval

def doNprobe():
    for format in FORMATS:
        print format
        accuracy = []
        for file in getFiles('data/' + format):
            print file
            cmd = NPROBE_BIN + ' -V 9 -T "%L7_PROTO_NAME %PROTOCOL %L4_SRC_PORT %L4_DST_PORT %IPV4_SRC_ADDR %IPV4_DST_ADDR" -P . -i ' + file
            execute(cmd)

            flow_files = glob.glob('2013/*/*/*/*.flows')
            for ff in flow_files:
                res = readNprobeFile(ff)
                accuracy += res

            cmd = 'rm -rf 2013'
            execute(cmd)

        if len(accuracy) > 0:
            with open('results/nprobe-' + format + '.log', 'w') as f:
                proto = format.split('-')[1]
                if proto == "http":
                    http_labels = ['http', 'twitter', 'netflix', 'facebook', 'dropbox', 'gmail', 'google maps', 'google',
                    'youtube', 'apple', 'lastfm']
                    count = 0.0
                    for l in http_labels:
                        count += accuracy.count(l)
                else:
                    count = accuracy.count(format.split('-')[1])
                f.write('nprobe-' + format + ' ' + str(1.0 * count / len(accuracy)))
                f.write('\n')

def readAPPIDFile(conn_file):
    retval = []

    with open(conn_file) as f:
        content = f.read().strip()

    # print content.strip()
    for line in content.split('\n'):
        if not line.strip():
            continue
        line = line.strip()
        retval.append(line.strip())

    return retval

def doAPPID():
    p = multiprocessing.Pool(multiprocessing.cpu_count())
    p.map(doOneAPPID, FORMATS)

def doOneAPPID(format):
    accuracy = []

    TCP_PROTO = 6
    for file in getFiles('data/' + format):
        dst_dir = 'appid-' + format
        cmd = 'mkdir ' + dst_dir + ' && cd ' + dst_dir + ' && tcpflow -b 2048 -r ../' + file
        execute(cmd)

        for file in glob.glob(dst_dir + '/128.105.214.241*'):
            with open(file) as f:
                if len(f.read().strip())==0: continue
            dst_dir = file.split('/')[0]
            file = file.split('/')[1]
            src_ip = '.'.join(file.split('-')[0].split('.')[:4])
            dst_ip = '.'.join(file.split('-')[1].split('.')[:4])
            src_port = file.split('.')[4].split('-')[0]
            dst_port = file.split('.')[-1]
            if format.split('-')[1] in ['sip']:
                file = dst_dir + '/' + dst_ip + '.' + dst_port + '-' + src_ip + '.' + src_port
                print file
                dst_port = int(dst_port)
                src_port = int(src_port)
                with open(file) as f:
                    stream = f.read().strip()
                res = appid.appid().process(TCP_PROTO, src_port, dst_port, stream)
            else:
                file = dst_dir + '/' + file
                dst_port = int(dst_port)
                src_port = int(src_port)
                with open(file) as f:
                    stream = f.read().strip()
                res = appid.appid().process(TCP_PROTO, src_port, dst_port, stream)
            # print [TCP_PROTO, src_port, dst_port, stream[:32]]
            # print file, (appid.app_to_name(res[0]), res[1])
            accuracy.append(appid.app_to_name(res[0]).lower())

        cmd = 'rm -rf ' + dst_dir
        execute(cmd)
        # print accuracy

    if len(accuracy) > 0:
        with open('results/appid-' + format + '.log', 'w') as f:
            f.write('appid-' + format + ' ' + str(1.0 * accuracy.count(format.split('-')[1]) / len(accuracy)))
            f.write('\n')


class ThreadClass(threading.Thread):
    def setEngine(self, engine):
        self.engine = engine
    def run(self):
        if self.engine == 'bro':
            doBro()
        elif self.engine == 'yaf':
            doYAF()
        elif self.engine == 'l7':
            doL7()
        elif self.engine == 'appid':
            doAPPID()
        elif self.engine == 'nprobe':
            doNprobe()

if not os.path.exists('results'):
    os.mkdir('results')

threads = []
for engine in ['appid','l7', 'bro', 'nprobe', 'yaf']:
#for engine in ['bro']:
    t = ThreadClass()
    t.setEngine(engine)
    threads.append(t)
    t.start()

for t in threads:
    t.join()
