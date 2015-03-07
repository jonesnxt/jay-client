var _hash = {
		init: SHA256_init,
		update: SHA256_write,
		getBytes: SHA256_finalize
	};

function byteArrayToBigInteger(byteArray, startIndex) {
		var value = new BigInteger("0", 10);
		var temp1, temp2;
		for (var i = byteArray.length - 1; i >= 0; i--) {
			temp1 = value.multiply(new BigInteger("256", 10));
			temp2 = temp1.add(new BigInteger(byteArray[i].toString(10), 10));
			value = temp2;
		}

		return value;
	}

function simpleHash(message) {
		_hash.init();
		_hash.update(message);
		return _hash.getBytes();
	}


	 function getPublicKey(secretPhrase) {
		
			var secretPhraseBytes = converters.stringToByteArray(secretPhrase);
			var digest = simpleHash(secretPhraseBytes);
			return curve25519.keygen(digest).p;
	}


	 function getAccountIdFromPublicKey(publicKey, RSFormat) {
		var hex = converters.hexStringToByteArray(publicKey);

		_hash.init();
		_hash.update(hex);

		var account = _hash.getBytes();

		account = converters.byteArrayToHexString(account);

		var slice = (converters.hexStringToByteArray(account)).slice(0, 8);

		var accountId = byteArrayToBigInteger(slice).toString();

		if (RSFormat) {
			var address = new NxtAddress();

			if (address.set(accountId)) {
				return address.toString();
			} else {
				return "";
			}
		} else {
			return accountId;
		}
	}

	function areByteArraysEqual(bytes1, bytes2) {
		if (bytes1.length !== bytes2.length)
			return false;

		for (var i = 0; i < bytes1.length; ++i) {
			if (bytes1[i] !== bytes2[i])
				return false;
		}

		return true;
	}

	
	 function verifyBytes(signature, message, publicKey) {
		var signatureBytes = signature;
		var messageBytes = message;
		var publicKeyBytes = publicKey;
		var v = signatureBytes.slice(0, 32);
		var h = signatureBytes.slice(32);
		var y = curve25519.verify(v, h, publicKeyBytes);

		var m = simpleHash(messageBytes);

		_hash.init();
		_hash.update(m);
		_hash.update(y);
		var h2 = _hash.getBytes();

		return areByteArraysEqual(h, h2);
	}

	 function signBytes(message, secretPhrase) {
		var messageBytes = message;
		var secretPhraseBytes = converters.stringToByteArray(secretPhrase);

		var digest = simpleHash(secretPhraseBytes);
		var s = curve25519.keygen(digest).s;

		var m = simpleHash(messageBytes);

		_hash.init();
		_hash.update(m);
		_hash.update(s);
		var x = _hash.getBytes();

		var y = curve25519.keygen(x).p;

		_hash.init();
		_hash.update(m);
		_hash.update(y);
		var h = _hash.getBytes();

		var v = curve25519.sign(h, x, s);

		return (v.concat(h));
	}


function pad(length, val) {
    var array = [];
    for (var i = 0; i < length; i++) {
        array[i] = val;
    }
    return array;
}

function rndstr(len)
{
	var letters = "abcdefghjklmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
	var ret = "";
	var nums = window.crypto.getRandomValues(new Uint32Array(len));

	for(var a=0;a<len;a++)
	{
		ret += letters[nums[a]%letters.length];
	}
	return ret;
}


var epochNum = 1385294400;
var online = false;
$(document).ready(function() {

	if(String(window.location).indexOf("jnxt") === -1) {
		$(".location").text("localhost");
	}
	else {
	 	$(".location").text("jnxt server");
	}


	function connect() { $(".network").text("online"); online = true;}
	function notconnect() { $(".network").text("offline"); online = false;}

	$.ajax({
		method: "get",
		type: "json",
		url: "http://jnxt.org/vapor/network.php",
		success: connect,
		error: notconnect,
		timeout: 1000});


		
	$(".tx").submit(function(e) {
		e.preventDefault();
		// what to do... ok so lets generate the tx bytes
		// then sign them, then include the tx bytes in the sig
		// then give them the tx bytes and the link to send them to
		var zeroArray = [0];


		var txbytes = [];
		var type = 0;
		txbytes.push(type);
		var version = 1;
		var subtype = 0;
		txbytes.push((version << 4));
		var timestamp = Math.floor(Date.now() / 1000) - 1385294400;
		txbytes = txbytes.concat(converters.int32ToBytes(timestamp));
		txbytes.push(160);
		txbytes.push(5); // deadline
		txbytes = txbytes.concat(getPublicKey($(".passphrase").val()));

		var rec = new NxtAddress();
		rec.set($(".recipient").val());
		var recipient = (new BigInteger(rec.account_id())).toByteArray().reverse();
		txbytes = txbytes.concat(recipient);
		var amount = ((new BigInteger(String(parseInt($(".amount").val()*100000000))))).toByteArray().reverse();
		while(amount.length != 8) amount = amount.concat(zeroArray);
		txbytes = txbytes.concat(amount);
		var fee = (converters.int32ToBytes(100000000))
		while(fee.length != 8) fee = fee.concat(zeroArray);

		txbytes = txbytes.concat(fee);
		txbytes = txbytes.concat(pad(32, 0)); // ref full hash
		txbytes = converters.hexStringToByteArray(converters.byteArrayToHexString(txbytes));
		var signable = txbytes;

		txbytes = txbytes.concat(pad(64, 0)); // signature

		if($(".publickey").val())
		{
			txbytes.push(4);
			txbytes = txbytes.concat(pad(3, 0));
			txbytes = txbytes.concat(pad(12, 0));
			txbytes = txbytes.concat([1]);
			txbytes = txbytes.concat(converters.hexStringToByteArray($(".publickey").val()));
		} 
		else  {
			txbytes = txbytes.concat(pad(16, 0)); // ignore everything else

		}

		var sig = signBytes(txbytes, $(".passphrase").val());

		signable = signable.concat(sig);
		
		if($(".publickey").val())
		{
			signable.push(4);
			signable = signable.concat(pad(3, 0));
			signable = signable.concat(pad(12, 0));
			signable = signable.concat([1]);
			signable = signable.concat(converters.hexStringToByteArray($(".publickey").val()));
		} 
		else  {
			signable = signable.concat(pad(16, 0)); // ignore everything else

		}

		// now we have a full tx...

		var fulltx = converters.byteArrayToHexString(signable);

		$(".bytes").val(fulltx);
				qr.makeCode(fulltx);
				qrbig.makeCode(fulltx);

		$(".broadcast").removeAttr("disabled");
	});


	$(".txl").submit(function(e) {
		e.preventDefault();
		// what to do... ok so lets generate the tx bytes
		// then sign them, then include the tx bytes in the sig
		// then give them the tx bytes and the link to send them to
		var zeroArray = [0];


		var txbytes = [];
		var type = 4;
		txbytes.push(type);
		var version = 1;
		var subtype = 0;
		txbytes.push((version << 4));
		var timestamp = Math.floor(Date.now() / 1000) - 1385294400;
		txbytes = txbytes.concat(converters.int32ToBytes(timestamp));
		txbytes.push(160);
		txbytes.push(5); // deadline
		txbytes = txbytes.concat(getPublicKey($(".passphrasel").val()));

		var rec = new NxtAddress();
		rec.set($(".recipientl").val());
		var recipient = (new BigInteger(rec.account_id())).toByteArray().reverse();
		txbytes = txbytes.concat(recipient);
		var amount = (new BigInteger("0")).toByteArray().reverse();
		while(amount.length != 8) amount = amount.concat(zeroArray);
		txbytes = txbytes.concat(amount);
		var fee = (converters.int32ToBytes(100000000))
		while(fee.length != 8) fee = fee.concat(zeroArray);

		txbytes = txbytes.concat(fee);
		txbytes = txbytes.concat(pad(32, 0)); // ref full hash
		txbytes = converters.hexStringToByteArray(converters.byteArrayToHexString(txbytes));
		var signable = txbytes;

		txbytes = txbytes.concat(pad(64, 0)); // signature

		txbytes = txbytes.concat(pad(16, 0)); // ignore everything else
		var amt = ((new BigInteger($(".lengthl").val()))).toByteArray().reverse();
		if(amt.length == 1) amt = amt.concat(zeroArray);
		txbytes.push(1);
		txbytes = txbytes.concat(amt);


		//var blks = 
		var sig = signBytes(txbytes, $(".passphrasel").val());

		signable = signable.concat(sig);
		
		signable = signable.concat(pad(16, 0)); // ignore everything else
		var amt = ((new BigInteger($(".lengthl").val()))).toByteArray().reverse();
		if(amt.length == 1) amt = amt.concat(zeroArray);
		signable.push(1);
		signable = signable.concat(amt);


		// now we have a full tx...

		var fulltx = converters.byteArrayToHexString(signable);

		$(".bytes").val(fulltx);
		qr.makeCode(fulltx);
		qrbig.makeCode(fulltx);
		$(".broadcast").removeAttr("disabled");
	});

	$(".gen").submit(function(e) {e.preventDefault()});

	$(".passphraseg").bind('input propertychange', genacc)

	function genacc() {
		// generate account and public key, display them
		var pass = $(".passphraseg").val();
		var pub = converters.byteArrayToHexString(getPublicKey(pass));
		var rs = getAccountIdFromPublicKey(pub, true)

		$(".accountg").val(rs);
		$(".pubkeyg").val(pub);

	};


	$(".rnd").click(function() {


		$(".passphraseg").val(rndstr(50));
		genacc();
	})
	

	function broad(resp)
	{
		$(".bytes").val(JSON.stringify(resp));
	}


	$(".broadcast").click(function() {
			var d = {requestType: "broadcastTransaction", transactionBytes: $(".bytes").val()};

		
		$.ajax("http://jnxt.org:7876/nxt", {
			url: "http://jnxt.org:7876/nxt",
			data: d,
			type: "POST",
			success: broad,
			timeout: 2000,
			fail: broad});

	});


	$(".bcb").click(function(e) {
		e.preventDefault();
			var d = {requestType: "broadcastTransaction", transactionBytes: $(".broad").val()};

		
		$.ajax("http://jnxt.org:7876/nxt", {
			url: "http://jnxt.org:7876/nxt",
			data: d,
			type: "POST",
			success: broad,
			timeout: 2000,
			fail: broad});

	});

	var qr = new QRCode("qr", {
		  width: 256,
    	height: 256,
   		colorDark : "#000000",
    	colorLight : "#ffffff",
    	correctLevel : QRCode.CorrectLevel.L
	});
	var qrbig = new QRCode("qrbigr", {
		  width: 512,
    	height: 512,
   		colorDark : "#000000",
    	colorLight : "#ffffff",
    	correctLevel : QRCode.CorrectLevel.L
	});

});