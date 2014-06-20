@load frameworks/communication/listen

redef Communication::listen_port = 47758/tcp;
redef Communication::nodes += {
	["brohose"] = [$host = 127.0.0.1, $events = /brohose/, $connect=F, $ssl=F]
};

event brohose(id: string) {
	print fmt("%s %s", id, current_time());
}
