@load frameworks/communication/listen

# Let's make sure we use the same port no matter whether we use encryption or not:
redef Communication::listen_port = 47758/tcp;

# Redef this to T if you want to use SSL.
redef Communication::listen_ssl = F;

# Set the SSL certificates being used to something real if you are using encryption.
#redef ssl_ca_certificate   = "<path>/ca_cert.pem";
#redef ssl_private_key      = "<path>/bro.pem";


redef Communication::nodes += {
	["broping"] = [$host = 127.0.0.1, $events = /ping/, $connect=F, $ssl=F]
};

global ping_log = open_log_file("ping");

type ping_data: record {
	seq: count;
	src_time: time;
};

type pong_data: record {
	seq: count;
	src_time: time;
	dst_time: time;
};

# global pdata: pong_data;

global ping: event(data: ping_data);
global pong: event(data: pong_data);

event ping(data: ping_data)
        {
	local pdata: pong_data;
	
	pdata$seq      = data$seq;
	pdata$src_time = data$src_time;
	pdata$dst_time = current_time();

        event pong(pdata);
        }

event pong(data: pong_data)
        {
        print ping_log, fmt("ping received, seq %d, %f at src, %f at dest, one-way: %f",
                            data$seq, data$src_time, data$dst_time, data$dst_time - data$src_time);
        }
