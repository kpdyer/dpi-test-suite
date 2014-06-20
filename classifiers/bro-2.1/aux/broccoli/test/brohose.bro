@load frameworks/communication/listen

# Let's make sure we use the same port no matter whether we use encryption or not:
redef Communication::listen_port = 47758/tcp;

# Redef this to T if you want to use SSL.
redef Communication::listen_ssl = F;

# Set the SSL certificates being used to something real if you are using encryption.
#redef ssl_ca_certificate   = "<path>/ca_cert.pem";
#redef ssl_private_key      = "<path>/bro.pem";

redef Communication::nodes += {
	["brohose"] = [$host = 127.0.0.1, $events = /brohose/, $connect=F, $ssl=F]
};

event brohose(id: string) {
	print brohose_log, fmt("%s %s", id, current_time());
}
