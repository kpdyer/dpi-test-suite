import sys
import string

for protocol in ['http','ssh','smb']:
    print '\\midrule'
    print '\\multirow{4}{*}{'+protocol.upper()+'}'
    for format in ['appid','l7','yaf1','yaf2']:
    #for format in ['intersection']:
        if format =='learned_ag' and protocol!='http': continue
        if format =='manual' and protocol not in ['http','smb','ssh']: continue
        if format =='scott' and protocol not in ['http','smb','ssh']: continue
        if format=='intersection': print '\\cline{2-15}'
        sys.stdout.write( '& '+string.replace(format,'_','\_')+' &' )
        for classifier in ['appid','l7','yaf','bro','nprobe']:
            try:
                with open('results/'+classifier+'-'+format+'-'+protocol+'.log') as f:
                    contents = f.read()
            except:
                contents = 'tmp -1'
            with open('results/expected.log') as f:
                contents_e = f.read()
                expected = '-'
                for line in contents_e.split('\n'):
                    if classifier in ['yaf1','yaf2']:
                        classifier = 'yaf'
                    if line.startswith(format+'-'+protocol+' '+classifier+'-'+protocol):
                        expected = str(round(float(line.split(' ')[2]),2))
                        break
            accuracy = str(round(float(contents.split(' ')[1]),2))
            accuracy = '-' if float(accuracy)==-1 else accuracy
            if classifier in ['yaf','l7','appid']:
                sys.stdout.write( ' && '+accuracy)#  + ' / ' + expected )
            else:
                sys.stdout.write( ' && '+accuracy)#  + ' / ' + expected )
        print ' && 1.0 & - & - \\\\'
print '\\midrule'
