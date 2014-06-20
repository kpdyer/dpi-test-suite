from statlib import stats

import numpy as np
import matplotlib.pyplot as plt

def mkGraph(data):
    N = len(data)

    ind = np.arange(N)  # the x locations for the groups
    width = 0.25  # the width of the bars

    fig = plt.figure(figsize = (20, 5))
    ax = fig.add_subplot(111)
    rects1 = ax.bar(ind, data.values(), width, color = 'gray')

    # womenMeans = (25, 32, 34, 20, 25)
    # womenStd = (3, 5, 2, 3, 3)
    # rects2 = ax.bar(ind + width, womenMeans, width, color = 'y', yerr = womenStd)

    # add some
    ax.set_ylabel('Scores')
    ax.set_title('Scores by group and gender')
    ax.set_xticks(ind + width)
    ax.set_xticklabels(data.keys(), horizontalalignment = 'center', size = 12)

    # ax.legend((rects1[0], rects2[0]), ('Men', 'Women'))

    def autolabel(rects):
        # attach some text labels
        for rect in rects:
            height = rect.get_height()
            ax.text(rect.get_x() + rect.get_width() / 2., 1.05 * height,
                    '%d' % int(height),
                    ha = 'center', va = 'bottom')

    # autolabel(rects1)

    labels = ax.get_xticklabels()
    for label in labels:
        label.set_rotation(45)

    plt.savefig('performance-bargraph.png', width = 800, height = 600, dpi = 100, bbox_inches = 'tight')

# with open('logs/socks-over-ssh.log') as f:
with open('logs/socks-over-fte.log') as f:
    contents = f.read().strip()

formats = {}
for line in contents.split('\n'):
    key = line.split(',')[-1]
    if line.split(',')[3] == 'ERROR': continue
    if not formats.get(key):
        formats[key] = []
    val = float(line.split(',')[3])
    formats[key].append(val)

keys = formats.keys()
keys.sort()
for key in keys:
    formats[key].sort()

data = {}
for key in keys:
    if key.endswith('ssh') or key.endswith('http'):
        data[key] = stats.mean(formats[key])

data['socks-overs-ssh'] = 6.2

mkGraph(data)
