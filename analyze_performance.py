from sets import Set

import numpy as np
import matplotlib.pyplot as plt

LOG = 'performance-client.log'
COLORS = ['r', 'g', 'b', 'c', 'm', 'y', 'k', 'w', 'r', 'g']

def makeGraph(timeSpent):
    if 'encoder_thread' in timeSpent.keys():
        total_time = timeSpent['encoder_thread']
        del timeSpent['encoder_thread']
        title = 'Encoder Thread'
        thread_type = 'encoder'
    elif 'decoder_thread' in timeSpent.keys():
        total_time = timeSpent['decoder_thread']
        del timeSpent['decoder_thread']
        title = 'Decoder Thread'
        thread_type = 'decoder'
    else:
        return

    total = 0
    for val in timeSpent:
        total += timeSpent[val]
    timeSpent['other'] = total_time - total

    N = 1
    ind = np.arange(N)  # the x locations for the groups
    width = 0.35  # the width of the bars: can also be len(x) sequence
    bars = []
    offset = 0
    i = 0
    for key in timeSpent.keys():
        bars.append(plt.bar(ind, timeSpent[key], width = 0.5 , color = COLORS[i], bottom = offset))
        i += 1
        offset += timeSpent[key]

    plt.ylabel('time spent (s)')
    plt.title(title)
    plt.xticks([])
    plt.yticks(np.arange(0, total_time * 1.5, 1))
    plt.legend(bars, timeSpent.keys())

    plt.savefig('fte-performance-' + thread_type + '.png')

with open(LOG) as f:
    contents = f.read().strip()

lines = contents.split('\n')

thread_ids = []
for line in lines:
    bits = line.split(',')
    thread_ids.append(int(bits[0]))
thread_ids = Set(thread_ids)

def folding(val):
    if val == 'decryptCovertextFooter':
        return 'decrypt'
    elif val == 'encryptCovertextFooter':
        return 'encrypt'
    else:
        return val

print thread_ids
for thread_id in thread_ids:
    _store = {}
    _timeSpent = {}
    for line in lines:
        bits = line.split(',')

        bits[1] = folding(bits[1])
        if bits[1] == 'getMessageLen':
            continue
        if int(bits[0]) != thread_id:
            continue

        # print line

        if bits[2] == 'start':
            if bits[1] in _store.keys():
                assert False
            else:
                _store[bits[1]] = float(bits[3])
        elif bits[2] == 'stop':
            if bits[1] in _store.keys():
                if not bits[1] in _timeSpent:
                    _timeSpent[bits[1]] = 0
                _timeSpent[bits[1]] += float(bits[3]) - _store[bits[1]]
                del _store[bits[1]]
            else:
                assert False

    for val in _timeSpent:
        print thread_id, val, _timeSpent[val]

    makeGraph(_timeSpent)
