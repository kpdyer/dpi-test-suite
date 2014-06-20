@load frameworks/communication/listen

redef Communication::listen_port = 47758/tcp;
redef Communication::nodes += {
	["broping"] = [$host = 127.0.0.1, $events = /ping/, $connect=F, $ssl=F]
};

event pong(src_time: time, dst_time: time, seq: count)
	{
	print fmt("ping received, seq %d, %f at src, %f at dest, one-way: %f",
	          seq, src_time, dst_time, dst_time-src_time);
	}

event ping(src_time: time, seq: count)
	{
	event pong(src_time, current_time(), seq);
	}
