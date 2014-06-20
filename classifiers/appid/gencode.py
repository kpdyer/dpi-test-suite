#!/usr/bin/env python

import glob, os, re, sys
import stpy

_attr_value_pat = re.compile("^([\w-]+):\s*(.*)$")

def parse_sig(name, buf):
    """Parse appid signature file into dict representation."""
    sig = { 'description':'', 'ragel':'' }
    for line in buf.splitlines():
        match = _attr_value_pat.match(line)
        if match:
            attr = match.group(1)
            value = match.group(2)
            sig[attr.lower()] = value
        elif line.strip() and not line.startswith('#'):
            sig['ragel'] += line + '\n'
    sig['full_name'] = sig.pop('name')
    sig['name'] = name
    if 'appid' in sig:
        sig['appid'] = int(sig['appid'])
    if 'port' in sig:
        sig['ports'] = sig['port'].split()
        for p in ('tcp', 'udp'):
            sig[p + '_ports'] = [ int(s[len(p)+1:]) for s in sig['ports']
                                  if s.startswith(p) and not s.endswith('*') ]
    return sig

# XXX - yuk
def get_app_ragel(app):
    """
    Given a specific application description and the ragel machine in
    which it belongs, return the Ragel code for it.
    Primary job here is to properly handle <MATCH> substitution.
    """
    # if no appid, this is just a fragment
    if 'appid' not in app:
        return app['ragel']

    #
    # Define <MATCH> here.
    #
    # Each machine has a default confidence level, and a default 
    # modifier action.
    #
    # The default confidence is a normal confidence level.
    # The default modifier is: if the protocol matched and 
    # is running on the port it is supposed to be, then the
    # confidence level goes up by one.
    #
    if 'confidence' in app:
        confidence = app['confidence']
    else:
        confidence = 'APPID_CONFIDENCE_NORMAL'

    expr = []
    for port in app['ports']:
        port_number, protocol = port.split('/')
        if not port_number.isdigit(): continue
        expr.append("src_ip_port == %s || dst_ip_port == %s" % \
                (port_number,port_number))

    if len(expr)!=0:
        expr = ' || '.join(expr)
        confidence = "%s + ((%s) ? +1 : -1)" % (confidence, expr)

    #
    # fragile: if confidence levels are mismanaged, we're gonna have
    # to improve the "confidence" arithmetic.
    #
    c_match = """
    a->match_count ++;
    if(a->confidence < %(confidence)s) {
        a->application = %(appid)d;
        a->confidence = %(confidence)s;
        a->match_payload = a->payload_offset + (p - payload);
        if (%(confidence)s > APPID_CONFIDENCE_NORMAL) fbreak;
    }
""" % { "appid" : app['appid'], "confidence" : confidence }

    #
    # put the C code above into a ragel action:
    #
    return app['ragel'].replace("<MATCH>", "{ %s }" % c_match)

def main():
    # Load our appid sigs.
    apps = []
    sigs = []
    for filename in glob.glob('apps/*'):
        if filename in ['apps/COPYING', 'apps/LICENSE']:
            continue
        sig = parse_sig(os.path.basename(filename).lower(),
                        open(filename).read())
        sigs.append(sig)
        if 'appid' in sig:
            apps.append(sig)
    apps.sort(key=lambda a: a['appid'])
    app_by_name = dict([ (a['name'], a) for a in sigs ])
    
    # Organize sigs by machine, with required sigs first.
    machine_list = [ 'dns', 'default', 'any8', 'any4', 'any16', 'any' ]
    apps_by_machine = {}
    for m in machine_list:
        apps_by_machine[m] = []
    for app in sigs:
        m = app.get('machine', 'default')
        if 'requires' in app:
            r = app_by_name[app['requires'].lower()]
            try: apps_by_machine[m].remove(r)
            except ValueError: pass
            apps_by_machine[m].insert(0, r)
        if not app in apps_by_machine[m]:
            apps_by_machine[m].append(app)

    # Organize ports by app name.
    app_ports = {}
    for app in apps:
        d = { 'tcp':[], 'udp':[] }
        for svc in app['ports']:
            proto, port = svc.split('/')
            if port != '*':
                d[proto].append(port)
        if d['tcp'] or d['udp']:
            app_ports[app['name']] = d
    
    # Write output files from templates using our sigs.
    for infile in glob.glob('*.tmpl'):
        outfile = os.path.splitext(infile)[0]
        print >>sys.stderr, '==> %s' % outfile
        f = open(outfile, 'w')
        t = stpy.Template(open(infile).read())
        f.write(t.render(machine_list=machine_list,
                         apps=apps, apps_by_machine=apps_by_machine,
                         app_ports=app_ports, get_app_ragel=get_app_ragel))
        f.close()

if __name__ == '__main__':
    main()

    
