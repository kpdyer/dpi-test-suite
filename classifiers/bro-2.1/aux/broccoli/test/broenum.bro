@load frameworks/communication/listen

# Let's make sure we use the same port no matter whether we use encryption or not:
redef Communication::listen_port = 47758/tcp;

# Redef this to T if you want to use SSL.
redef Communication::listen_ssl = F;

# Set the SSL certificates being used to something real if you are using encryption.
#redef ssl_ca_certificate   = "<path>/ca_cert.pem";
#redef ssl_private_key      = "<path>/bro.pem";

module enumtest;

type enumtype: enum { ENUM1, ENUM2, ENUM3, ENUM4 };

redef Communication::nodes += {
	["broenum"] = [$host = 127.0.0.1, $events = /enumtest/, $connect=F, $ssl=F]
};

event enumtest(e: enumtype)
	{
	print fmt("Received enum val %d/%s", e, e);
	}
