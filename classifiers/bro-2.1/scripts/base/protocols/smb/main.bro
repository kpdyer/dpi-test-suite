##! Custom SMB analysis script.

@load base/frameworks/notice
@load base/utils/site
@load base/utils/thresholds
@load base/utils/conn-ids
@load base/utils/directions-and-hosts

module SMB;

export {
## The SMB protocol logging stream identifier.
redef enum Log::ID += { LOG };

type Info: record {
## Time when the SMB connection began.
ts:	 time	 &log;
## Unique ID for the connection.
uid:	 string	 &log;
## The connection's 4-tuple of endpoint addresses/ports.
id:	 conn_id	 &log;
## The connection's smb_hdr variables
status:	 count	 &log &optional;
smb_flags:	count	 &log &optional;
smb_flags2:	count	 &log &optional;
## The connection's tree path (at the share level)
smb_share:	string	 &log &optional;
## SMB path (past the share level)
smb_path:	string	 &log &default="\\";
};

global paths: set[string];
}

const smbports = {
135/tcp, 137/tcp, 138/tcp, 139/tcp, 445/tcp
};

# Configure DPD and the packet filter
redef capture_filters += {
["msrpc"] = "tcp port 135",
["netbios-ns"] = "tcp port 137",
["netbios-ds"] = "tcp port 138",
["netbios"] = "tcp port 139",
["smb"] = "tcp port 445",
};
redef dpd_config += { [ANALYZER_SMB] = [$ports = smbports] };
redef likely_server_ports += { 445/tcp };

redef record connection += {
smb: Info &optional;
};

event bro_init() &priority=5
{
Log::create_stream(SMB::LOG, [$columns=Info]);
}

function set_session(c: connection, hdr: smb_hdr)
{
if ( ! c?$smb )
{
c$smb = [$ts=network_time(), $id=c$id, $uid=c$uid];
c$smb$status = hdr$status;
c$smb$smb_flags = hdr$flags;
c$smb$smb_flags2 = hdr$flags2;
}
}

event smb_com_tree_connect_andx(c: connection, hdr: smb_hdr, path: string, service: string) &priority=5
{
set_session(c,hdr);
local path_name = escape_string(path);
c$smb$smb_share = path_name;
}

event smb_com_nt_create_andx(c: connection, hdr: smb_hdr, name: string) &priority=0
{
set_session(c,hdr);

c$smb$ts=network_time();

# If the path has changed, then log the new name, otherwise skip it (may need to revisit)
if ( name !in paths )
{
add paths[name];
c$smb$smb_path = gsub(name,/ /,"%20");
Log::write(SMB::LOG, c$smb);
}
}
