from statlib import stats

#with open('logs/socks-over-ssh.log') as f:
with open('logs/socks-over-fte.log') as f:
    contents = f.read().strip()

formats = {}
formats_bw = {}
for line in contents.split('\n'):
    key = line.split(',')[-1]
    if line.split(',')[3] == 'ERROR': continue
    if not formats_bw.get(key):
        formats_bw[key] = []
    if not formats.get(key):
        formats[key] = []
    print line.split(',')
    val = float(line.split(',')[3])
    val_bw = float(line.split(',')[4])
    formats[key].append(val)
    formats_bw[key].append(val_bw)

keys = formats.keys()
keys.sort()
for key in keys:
    formats[key].sort()

keys = formats_bw.keys()
keys.sort()
for key in keys:
    formats_bw[key].sort()

for key in keys:
    print key, '&', round(stats.mean(formats[key])/6.2,2), '&', round(stats.mean(formats_bw[key])/1308543.7521,2), '\\\\'
