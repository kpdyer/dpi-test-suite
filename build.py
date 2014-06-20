import os
import multiprocessing
import platform

PREFIX = os.path.abspath('./classifiers/opt')
PLATFORM = platform.system().lower()

def execute(cmd):
    print cmd
    os.system(cmd)

#execute('cd classifiers/l7-protocols-2009-05-28/testing && make')
execute('cd classifiers/bro-2.1 && chmod 755 configure && ./configure --enable-debug --prefix='+PREFIX+' && make clean && make -j'+str(multiprocessing.cpu_count())+' && make install')
#execute('cd classifiers/libfixbuf-1.3.0 && chmod 755 configure && ./configure --prefix='+PREFIX+' && make -j'+str(multiprocessing.cpu_count())+' && make install')
#execute('cd classifiers/yaf-2.3.3 && chmod 755 configure && ./configure --prefix='+PREFIX+' --enable-applabel && make -j'+str(multiprocessing.cpu_count())+' && make install')
#execute('cd classifiers/nprobe_6.9.5_052312 && chmod 755 autogen.sh && ./autogen.sh --prefix='+PREFIX+' && make -j'+str(multiprocessing.cpu_count())+' && make install')
#if PLATFORM == 'darwin':
#    execute('cd classifiers/appid && ./configure --prefix=/opt/local/Library/Frameworks/Python.framework/Versions/2.7 --with-python && make -j'+str(multiprocessing.cpu_count())+' && sudo make install')
#else:
#    execute('cd classifiers/appid && ./configure --with-python && make -j'+str(multiprocessing.cpu_count())+' && sudo make install')
