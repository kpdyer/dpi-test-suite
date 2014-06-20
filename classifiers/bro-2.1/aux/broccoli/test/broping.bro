@load frameworks/communication/listen

# Let's make sure we use the same port no matter whether we use encryption or not:
redef Communication::listen_port = 47758/tcp;

# Redef this to T if you want to use SSL.
redef Communication::listen_ssl = F;

# Set the SSL certificates being used to something real if you are using encryption.
#redef ssl_ca_certificate   = "<path>/ca_cert.pem";
#redef ssl_private_key      = "<path>/bro.pem";

global ping_log = open_log_file("ping");

global ping: event(src_time: time, seq: count);
global pong: event(src_time: time, dst_time: time, seq: count);

redef Communication::nodes += {
	["broping"] = [$host = 127.0.0.1, $events = /ping/, $connect=F, $ssl=F]
};

event ping(src_time: time, seq: count)
        {
        event pong(src_time, current_time(), seq);
        }

event pong(src_time: time, dst_time: time, seq: count)
        {
        print ping_log, fmt("ping received, seq %d, %f at src, %f at dest, one-way: %f",
                            seq, src_time, dst_time, dst_time-src_time);
        }
