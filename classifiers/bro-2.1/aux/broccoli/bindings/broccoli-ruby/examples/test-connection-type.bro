@load frameworks/communication/listen

redef Communication::listen_port = 47758/tcp;
redef Communication::nodes += {
	["test-connection-type"] = [$host = 127.0.0.1, $connect=F, $ssl=F]
};

event test_conn(c: connection)
	{
	print "sent test_conn event";
	schedule 5secs { test_conn(c) };
	}

event bro_init()
	{
	local a: string_set = table();
	local c: connection = 
		[$id=[$orig_h=1.2.3.4, $orig_p=1/tcp, $resp_h=4.3.2.1, $resp_p=2/tcp], 
		 $orig=[$size=0, $state=4, $num_pkts=1, $num_bytes_ip=40], 
		 $resp=[$size=0, $state=4, $num_pkts=0, $num_bytes_ip=0], 
		 $start_time=network_time(), 
		 $duration=1sec, 
		 $service=a, 
		 $addl="", 
		 $hot=0, 
		 $history="Sh", 
		 $uid="tRvksWon37g",
		 $extract_orig=F,
		 $extract_resp=F];
	event test_conn(c);
	}