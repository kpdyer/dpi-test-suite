import sys
import random
import matplotlib.pyplot as plt
from numpy.random import normal, uniform

MAX_X = 30
MAX_Y = 250
BINS    = MAX_X
ALPHA   = 0.55

def mean(myList):
    return 1.0*sum(myList)/len(myList)

def median(mylist):
    sorts = sorted(mylist)
    length = len(sorts)
    if not length % 2:
        return (sorts[length / 2] + sorts[length / 2 - 1]) / 2.0
    return sorts[length / 2]

def modeToPP( mode ):
    return mode
    if mode=='socks':
        return 'SOCKS'
    if mode=='tor':
        return 'Tor'

def readFile( filename ):
    f = open(filename,'r')
    content = f.read().strip()
    f.close()

    numErrors = 0
    txd = []
    retval = []
    for line in content.split('\n'):
        if not line: continue
        bits = line.split(',')
        if bits[3] == 'ERROR':
            numErrors += 1
            continue
        val  = float( bits[3] )
        retval.append( val )
        txd.append( int( bits[-2] ) )

        #print bits[0], bits[1], bits[2], bits[-1]

    return retval, numErrors, txd

def makeGraph( vanilla, fte ):
    fig = plt.gcf()
    fig.clear()
    fig.set_size_inches(6,4)
    
    vanilla_data, vanilla_errors, vanilla_txd = readFile('logs/'+vanilla+'.log')
    fte_data    , fte_errors    , fte_txd     = readFile('logs/'+fte+'.log')

    #vanilla_data = vanilla_data[:min(len(vanilla_data),len(fte_data))]
    #fte_data     = fte_data[:min(len(vanilla_data),len(fte_data))]

    #print vanilla_txd
    #print fte_txd

    #print vanilla_data
    #print fte_data

    ax = fig.add_subplot(111)
    
    if len(vanilla_data):
        print vanilla+' avg/median:', str(mean(vanilla_data)) +'/'+ str(median(vanilla_data)), '(', len(vanilla_data), '/', vanilla_errors, ')', mean(vanilla_txd)
        ax.hist(vanilla_data, bins=BINS, histtype='stepfilled', normed=False, color='b', alpha=ALPHA, label=modeToPP(vanilla))

    if len(fte_data):
        print fte+' avg/median:',str(mean(fte_data)) +'/'+ str(median(fte_data)), '(', len(fte_data), '/', fte_errors, ')', mean(fte_txd)
        ax.hist(fte_data, bins=BINS, histtype='stepfilled', normed=False, color='r', alpha=ALPHA, label=modeToPP(fte))

    #plt.title( modeToPP(mode) )
    plt.title( 'FTE Performance' )
    plt.xlabel("Download Time (seconds)")
    plt.ylabel("# of trials")
    plt.legend()
    
    ax.set_xlim([0,MAX_X])
    ax.set_ylim([0,MAX_Y])

    plt.savefig('evaluation-'+vanilla+'-histogram.png',dpi=100, bbox_inches='tight')

makeGraph( 'socks-over-ssh', 'socks-over-fte' )
