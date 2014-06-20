#
# appid.pyx
#
# Python appid module.
#
# Copyright 2005-2007 Arbor Networks, Inc.
#
# $Id: appid.pyx 2 2007-06-04 18:16:24Z dugsong $

cdef extern from "Python.h":
    int PyObject_AsCharBuffer(object obj, char **buffer, int *buffer_len)

cdef extern from "appid.h":
    ctypedef struct appid_t:
        int __xxx
    struct appid_rv:
        int application
        int confidence
    
    appid_t *appid_open()
    appid_rv appid_process(appid_t *a, int proto, int sport, int dport,
                           char *buf, int len)
    void     appid_close(appid_t **a)
    int      appid_uses_port(int app, int proto, int port)
    int      appid_port_to_app(int proto, int port)
    char    *appid_app_to_name(int appid)

cdef class appid:
    """appid() -> application fingerprint matcher

    An appid handle is only valid for a single flow half
    (e.g. client data for a flow, or server data for a flow).
    """
    cdef appid_t *__appid
    
    def __init__(self):
        self.__appid = appid_open()
        if self.__appid == NULL:
            raise OSError
    
    def process(self, proto, sport, dport, buf):
        """process(proto, sport, dport, buf) -> (appid, confidence)

        Processes packet payload data and returns (appid, confidence),
        where appid is one of APPID_CONTINUE (-1), APPID_UNKNOWN (0),
        or a positive appid, and confidence is from 0 to 4.
        """
        cdef char *p
        cdef int n
        cdef appid_rv rv
        
        if PyObject_AsCharBuffer(buf, &p, &n) < 0:
            raise TypeError
        rv = appid_process(self.__appid, proto, sport, dport, p, n)
        return (rv.application, rv.confidence)

    def __dealloc__(self):
        if self.__appid != NULL:
            appid_close(&self.__appid)

def app_to_name(int app):
    """app_to_name(app) -> protocol name

    Convert from numeric appid to protocol name.
    """
    return appid_app_to_name(app)

def uses_port(int app, int proto, int port):
    """uses_port(app, proto, port) -> boolean

    Returns boolean result for a matching appid and protocol/port.
    """
    return appid_uses_port(app, proto, port) == 1
