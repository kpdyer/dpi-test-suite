@load frameworks/communication/listen

redef Communication::nodes += {
	["v6addrs-over-v6"] = [$host=[::1], $connect=F, $ssl=F,
	$events=/broccoli_.*/],
	["v6addrs-over-v4"] = [$host=127.0.0.1, $connect=F, $ssl=F,
	$events=/broccoli_.*/]
};

event bro_addr(a: addr)
	{
	print fmt("bro_addr(%s)", a);
	}

event bro_subnet(s: subnet)
	{
	print fmt("bro_subnet(%s)", s);
	}

event broccoli_addr(a: addr)
	{
	print fmt("broccoli_addr(%s)", a);
	}

global cnt = 0;

event broccoli_subnet(s: subnet)
	{
	print fmt("broccoli_subnet(%s)", s);
	cnt = cnt + 1;
	if ( cnt == 2 ) terminate();
	}

event remote_connection_handshake_done(p: event_peer)
    {
	print "handshake done with peer";
	event bro_addr(1.2.3.4);
	event bro_subnet(10.0.0.0/16);
	event bro_addr([2607:f8b0:4009:802::1014]);
	event bro_subnet([2607:f8b0:4009:802::1014]/32);
    }
