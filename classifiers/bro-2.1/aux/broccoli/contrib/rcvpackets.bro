
@load frameworks/communication/listen
	
redef Remote::destinations +=  {
    ["broccoli"] = [$host=127.0.0.1, $accept_state=T, $sync=F]
};
	

	
	
	
