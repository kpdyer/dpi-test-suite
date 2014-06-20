@load frameworks/communication/listen

# Let's make sure we use the same port no matter whether we use encryption or not:
redef Communication::listen_port = 47758/tcp;

# Redef this to T if you want to use SSL.
redef Communication::listen_ssl = F;

# Set the SSL certificates being used to something real if you are using encryption.
#redef ssl_ca_certificate   = "<path>/ca_cert.pem";
#redef ssl_private_key      = "<path>/bro.pem";

redef Communication::nodes += {
	["broconn"] = [$host = 127.0.0.1, $connect=F, $ssl=F]
};

function services_to_string(ss: string_set): string
{
	local result = "";

	for (s in ss)
	    result = fmt("%s %s", result, s);
	
	return result;
}

event new_connection(c: connection)
{
	print fmt("new_connection: %s, services:%s",
	          id_string(c$id), services_to_string(c$service));
}

event connection_finished(c: connection)
{
	print fmt("connection_finished: %s, services:%s",
	          id_string(c$id), services_to_string(c$service));
}
