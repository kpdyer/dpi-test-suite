import os
import time
import sys
import datetime
import subprocess
import threading

from subprocess import Popen
from pyvirtualdisplay import Display
from selenium import webdriver
from selenium.webdriver.firefox.firefox_binary import FirefoxBinary

# Modes
# "socks" : direct SOCKS connection to remote server
# "tor" : direct Tor connection via client-side tor client
# "socks-over-fte" : SOCKS through FTE tunnel
# "tor-over-fte" : Tor through FTE tunnel

INTERFACE = 'eth0'
CLIENT_IP = '131.252.42.31'
SERVER_IP = '128.105.214.241'

if CLIENT_IP == None:
    print 'Please set CLIENT_IP in doCollection.py to the interface you want fte to use'
    sys.exit(1)

BLACKLIST = []

TRACES_TO_COLLECT = 5
NUM_URLS = 50
OFFSET = 0

RECORD = True
SCREENSHOT = True
DEBUG = True
HEADLESS = True
LOG_DIR = 'logs'
DATA_DIR = 'data'
PAGE_LOAD_TIMEOUT = 60

PCAP_SHUTDOWN_DELAY = 2

SSH_PORT = 22
HTTP_PORT = 80
TOR_SOCKS_PORT = 8078
FTE_CLIENT_PORT = 8079
FTE_SERVER_PORT = 8080
DANTE_PORT = 8081
TOR_PORT = 9001

CAPTURE_DNS = False
DNS_FILTER = 'port 53 or ' if CAPTURE_DNS else ''

config = {}
config['direct'] = {'IP':None     , 'PORT':None           , 'FILTER':DNS_FILTER + 'port ' + str(HTTP_PORT)}
config['socks'] = {'IP':SERVER_IP, 'PORT':DANTE_PORT     , 'FILTER':DNS_FILTER + 'port ' + str(DANTE_PORT)}
config['tor'] = {'IP':CLIENT_IP, 'PORT':TOR_SOCKS_PORT , 'FILTER':DNS_FILTER + 'port ' + str(TOR_PORT)}
config['socks-over-fte'] = {'IP':CLIENT_IP, 'PORT':FTE_CLIENT_PORT, 'FILTER':DNS_FILTER + 'port ' + str(FTE_SERVER_PORT)}
config['socks-over-ssh'] = {'IP':CLIENT_IP, 'PORT':FTE_CLIENT_PORT, 'FILTER':DNS_FILTER + 'port ' + str(SSH_PORT)}
config['tor-over-fte'] = {'IP':CLIENT_IP, 'PORT':TOR_SOCKS_PORT , 'FILTER':DNS_FILTER + 'port ' + str(FTE_SERVER_PORT)}

class Recorder(threading.Thread):
    def __init__(self, pcap_file, png_file, scapy_filter):
        threading.Thread.__init__(self)
        self.pcap_file = pcap_file
        self.start_time = time.time()

        #self.scapy_filter = '(tcp) and (dst port 80 or src port 80 or src port 443 or dst port 443)'
        self.scapy_filter = '(tcp) and'
        self.scapy_filter += ' ((src host ' + CLIENT_IP + ') and (dst host ' + SERVER_IP + '))'
        self.scapy_filter += ' or ((src host ' + SERVER_IP + ') and (dst host ' + CLIENT_IP + '))'

    def stop(self):
        try:
            time.sleep(1)
            self.process.terminate()
        except:
            pass

    def run(self):
        cmd = ['tcpdump', '-i', INTERFACE, '-s', '0', '-w', self.pcap_file, self.scapy_filter]
        self.process = Popen(cmd, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
        time.sleep(.5)

def doDownload(browser, url, dst_file, pcap_file, mode):
    browser = initBrowser()

    if RECORD:
        recorder = Recorder(pcap_file, dst_file, config[mode]['FILTER'])
        recorder.start()

    try:
        print ' - starting get for', url
        start = time.time()

        browser.get(url)
        browser.page_source

        total = time.time() - start
        print ' - finished get for', url, total

        if SCREENSHOT:
            browser.get_screenshot_as_file(dst_file)
    except Exception as e:
        browser.close()
        browser.quit()

        if RECORD:
            recorder.stop()

        raise e

    browser.close()
    browser.quit()

    if RECORD:
        recorder.stop()

    return total

def doCollection(browser, mode, date_time, url):
    URL_SPECIFIC_DATA_DIR = os.path.join(DATA_DIR, mode, url)

    if not os.path.exists(URL_SPECIFIC_DATA_DIR):
        os.makedirs(URL_SPECIFIC_DATA_DIR)

    OUTPUT_PNG = os.path.join(URL_SPECIFIC_DATA_DIR, date_time + '.png')
    OUTPUT_PCAP = os.path.join(URL_SPECIFIC_DATA_DIR, date_time + '.pcap')

    time_elapsed = doDownload(browser, 'http://www.' + url, OUTPUT_PNG, OUTPUT_PCAP, mode)

    PCAP_SIZE = -1
    if RECORD:
        PCAP_SIZE = os.path.getsize(OUTPUT_PCAP)

    PNG_SIZE = -1
    if SCREENSHOT:
        PNG_SIZE = str(os.path.getsize(OUTPUT_PNG))

    retval = [date_time,
              mode,
              url,
              str(time_elapsed),
              str(PNG_SIZE),
              str(PCAP_SIZE)]

    return retval

def logResults(filename, results):
    f = open(filename, 'a')
    if DEBUG: print results
    f.write(','.join(results) + '\n')
    f.close()

def initBrowser():
    fp = webdriver.FirefoxProfile()

    if config[mode]['IP'] and config[mode]['PORT']:
        PROXY_HOST = config[mode]['IP']
        PROXY_PORT = config[mode]['PORT']

        fp.set_preference("network.proxy.type", 1)
        fp.set_preference("network.proxy.socks_remote_dns", True)
        fp.set_preference("network.proxy.socks", PROXY_HOST)
        fp.set_preference("network.proxy.socks_port", PROXY_PORT)

    fp.set_preference("browser.startup.page", 0)
    fp.set_preference("browser.cache.disk.enable", False)
    fp.set_preference("browser.cache.disk.capacity", 0)
    fp.update_preferences()

    binary = FirefoxBinary('./firefox/firefox-bin')
    browser = webdriver.Firefox(firefox_binary = binary, firefox_profile = fp)
    browser.set_page_load_timeout(PAGE_LOAD_TIMEOUT)

    return browser

if __name__ == "__main__":
    if RECORD and os.getuid() != 0:
        print "Sorry, you must run this script as root when data recording is enabled."
        sys.exit(1)

    mode = sys.argv[1]
    nickname = sys.argv[2] if len(sys.argv) == 3 else sys.argv[1]

    if not os.path.exists(LOG_DIR):
        os.mkdir(LOG_DIR)

    f = open('top-50-usa.csv', 'r')
    contents = f.read()
    f.close()

    URLS = []
    for line in contents.split('\n'):
        url = line.split(',')[1]
        if url in BLACKLIST: continue
        URLS.append(url)
        if len(URLS) == NUM_URLS: break

    URLS = URLS * TRACES_TO_COLLECT
    URLS = URLS[OFFSET:]

    if HEADLESS:
        display = Display(visible = 0, size = (1024, 768))
        display.start()

    browser = None

    for i in range(len(URLS)):
        url = URLS[i]

        date_time = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")

        try:
            print 'starting collection for', url
            results = doCollection(browser, mode, date_time, url)
            print 'finished collection for', url
        except Exception as e:
            results = [date_time, mode, url, 'ERROR', str(e)]

        results.append(nickname)
        logResults(LOG_DIR + '/' + mode + '.log', results)

    if HEADLESS:
        display.stop()
