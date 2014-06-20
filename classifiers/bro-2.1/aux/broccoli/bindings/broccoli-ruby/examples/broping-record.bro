@load frameworks/communication/listen

redef Communication::listen_port = 47758/tcp;
redef Communication::nodes += {
	["broping"] = [$host = 127.0.0.1, $events = /ping/, $connect=F, $ssl=F]
};

type PingData: record {
	seq: count;
	src_time: time;
};

type PongData: record {
	seq: count;
	src_time: time;
	dst_time: time;
};

event pong(data: PongData)
	{
	print fmt("ping received, seq %d, %f at src, %f at dest, one-way: %f",
	          data$seq, data$src_time, data$dst_time, data$dst_time - data$src_time);
	}

event ping(data: PingData)
	{
	local pdata: PongData;
	pdata$seq      = data$seq;
	pdata$src_time = data$src_time;
	pdata$dst_time = current_time();

	event pong(pdata);
	}
