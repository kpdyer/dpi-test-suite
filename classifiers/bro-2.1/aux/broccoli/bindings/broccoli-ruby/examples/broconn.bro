@load frameworks/communication/listen

redef Communication::listen_port = 47758/tcp;
redef Communication::nodes += {
	["broconn"] = [$host = 127.0.0.1, $connect=F, $ssl=F]
};
