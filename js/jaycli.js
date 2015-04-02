var DEFAULT_NODE = "jnxt.org";

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

	function toByteArray(long) {
    // we want to represent the input as a 8-bytes array
    var byteArray = [0, 0, 0, 0];

    for ( var index = 0; index < byteArray.length; index ++ ) {
        var byte = long & 0xff;
        byteArray [ index ] = byte;
        long = (long - byte) / 256 ;
    }

    return byteArray;
};

function toIntVal(byteArray) {
    // we want to represent the input as a 8-bytes array
    var intval = 0;

    for ( var index = 0; index < byteArray.length; index ++ ) {
    	var byt = byteArray[index] & 0xFF;
    	var value = byt * Math.pow(256, index);
    	intval += value;
    }

    return intval;
};

function generateToken(websiteString, secretPhrase)
{
		//alert(converters.stringToHexString(websiteString));
		var hexwebsite = converters.stringToHexString(websiteString);
        var website = converters.hexStringToByteArray(hexwebsite);
        var data = [];
        data = website.concat(getPublicKey(secretPhrase));
        var unix = Math.round(+new Date()/1000);
        var timestamp = unix-epochNum;
        var timestamparray = toByteArray(timestamp);
        data = data.concat(timestamparray);

        var token = [];
        token = getPublicKey(secretPhrase).concat(timestamparray);

        var sig = signBytes(data, secretPhrase);

        token = token.concat(sig);
        var buf = "";

        for (var ptr = 0; ptr < 100; ptr += 5) {

        	var nbr = [];
        	nbr[0] = token[ptr] & 0xFF;
        	nbr[1] = token[ptr+1] & 0xFF;
        	nbr[2] = token[ptr+2] & 0xFF;
        	nbr[3] = token[ptr+3] & 0xFF;
        	nbr[4] = token[ptr+4] & 0xFF;
        	var number = byteArrayToBigInteger(nbr);

            if (number < 32) {
                buf+="0000000";
            } else if (number < 1024) {
                buf+="000000";
            } else if (number < 32768) {
                buf+="00000";
            } else if (number < 1048576) {
                buf+="0000";
            } else if (number < 33554432) {
                buf+="000";
            } else if (number < 1073741824) {
                buf+="00";
            } else if (number < 34359738368) {
                buf+="0";
            }
            buf +=number.toString(32);

        }
        return buf;

    }

function parseToken(tokenString, website)
{
 		var websiteBytes = converters.stringToByteArray(website);
        var tokenBytes = [];
        var i = 0;
        var j = 0;

        for (; i < tokenString.length; i += 8, j += 5) {

        	var number = new BigInteger(tokenString.substring(i, i+8), 32);
            var part = converters.hexStringToByteArray(number.toRadix(16));

            tokenBytes[j] = part[4];
            tokenBytes[j + 1] = part[3];
            tokenBytes[j + 2] = part[2];
            tokenBytes[j + 3] = part[1];
            tokenBytes[j + 4] = part[0];

        }

        if (i != 160) {
            new Error("tokenString parsed to invalid size");
        }
        var publicKey = [];
        publicKey = tokenBytes.slice(0, 32);
        var timebytes = [tokenBytes[32], tokenBytes[33], tokenBytes[34], tokenBytes[35]];

        var timestamp = toIntVal(timebytes);
        var signature = tokenBytes.slice(36, 100);

        var data = websiteBytes.concat(tokenBytes.slice(0, 36));
       	
        var isValid = verifyBytes(signature, data, publicKey);

        var ret = {};
        ret.isValid = isValid;
        ret.timestamp = timestamp;
        ret.publicKey = converters.byteArrayToHexString(publicKey);

        return ret;

}


function pad(length, val) {
    var array = [];
    for (var i = 0; i < length; i++) {
        array[i] = val;
    }
    return array;
}

function timeago(timestamp)
{
	var fromnow =  currentNxtTime() - timestamp;
		
	var days =  Math.floor(fromnow/86400);
	var hours = Math.floor((fromnow%86400)/3600);
	var minutes = Math.floor((fromnow%3600)/60);
	var seconds = Math.floor(fromnow&60);
	var acc = "";
	if(days != 0 && days != 1) acc = days + " days ago";
	else if(days == 1) acc = " 1 day ago";
	else if(hours != 0 && hours != 1) acc = hours + " hours ago";
	else if(hours == 1) acc = "1 hour ago";
	else if(minutes != 0 && minutes != 1) acc = minutes + " minutes ago";
	else if(minutes == 1) acc = "1 minute ago";
	else if(seconds != 0 && seconds != 1) acc = seconds + " seconds ago";
	else if(seconds == 1) acc = "1 second ago";
	else acc = "just now";
		
	return acc;
}


// 48 -> 57
// 65 -> 90
// 97 -> 122

	/**
	 * Encoders and decoders for base-62 formatted data. Uses the alphabet 0..9 a..z
	 * A..Z, e.g. '0' => 0, 'a' => 10, 'A' => 35 and 'Z' => 61.
	 * 
	 */
	 	var BASE62 = new BigInteger("62");

	  function valueForByte(key) {
	  	var p = key;
		if(p >= 48 && p <= 57)
		{
			return p - 48;
		}
		else if(p >= 65 && p <= 90)
		{
			return p - 65 + 10;
		}
		else if(p >= 97 && p <= 122)
		{
			return p - 97 + 10 + 26;
		}
	    new Error("base62 digit not found");
	    return -1;
	  }

	  /**
	   * Convert a base-62 string known to be a number.
	   * 
	   * @param s
	   * @return
	   */
		function base62Decode(s) {
	    return base62DecodeBytes(converters.stringToByteArray(s));
	  }

	  /**
	   * Convert a base-62 string known to be a number.
	   * 
	   * @param s
	   * @return
	   */
	  	function base62DecodeBytes(bytes) {
	    var res = new BigInteger("0");
	    var multiplier = new BigInteger("1");

	    for (var i = bytes.length - 1; i >= 0; i--) {
	      res = res.add(multiplier.multiply(new BigInteger(valueForByte(bytes[i]).toString())));
	      multiplier = multiplier.multiply(BASE62);
	    }
	    var btr = res.toByteArray();
	    return positiveByteArray(btr);
	  }

function rndstr(len)
{
	var letters = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
	var ret = "";
	var nums = window.crypto.getRandomValues(new Uint32Array(len));

	for(var a=0;a<len;a++)
	{
		ret += letters[nums[a]%letters.length];
	}
	return ret;
}

function generateSecretPhrase()
{
	return rndstr(6) + "_" + rndstr(6) +  "_" + rndstr(6) + "_" + rndstr(6) + "_" + rndstr(6);
}

function encryptSecretPhrase(phrase, key)
{
	var rkey = prepKey(key);
	return CryptoJS.AES.encrypt(phrase, rkey);
}

function decryptSecretPhrase(cipher, key, checksum)
{
	var rkey = prepKey(key);
	var data = CryptoJS.AES.decrypt(cipher, rkey);

	if(converters.byteArrayToHexString(simpleHash(converters.hexStringToByteArray(data.toString()))) == checksum)
	 return converters.hexStringToString(data.toString());
	else return false;
}

function prepKey(key)
{
	var rounds = 1000;
	var digest = key;
	for(var i=0;i<rounds;i++)
	{
		digest = converters.byteArrayToHexString(simpleHash(digest));
	}
	return digest;
}

function newAccount(secretPhrase, key)
{
	var accountData = {};
	accountData["secretPhrase"] = secretPhrase;
	accountData["publicKey"] = converters.byteArrayToHexString(getPublicKey(accountData["secretPhrase"]));
	accountData["accountRS"] = getAccountIdFromPublicKey(accountData["publicKey"], true);
	accountData["key"] = key;
	accountData["cipher"] = encryptSecretPhrase(accountData["secretPhrase"], key).toString();
	accountData["checksum"] = converters.byteArrayToHexString(simpleHash(converters.stringToByteArray(accountData["secretPhrase"])));
	return accountData;
}

function storeAccount(account)
{ 
	var sto = [];
	if(localStorage["accounts"])
	{
		sto = JSON.parse(localStorage["accounts"]);
	}
	var acc = {};
	acc["accountRS"] = account["accountRS"];
	acc["publicKey"] = account["publicKey"];
	acc["cipher"] = account["cipher"];
	acc["checksum"] = account["checksum"];
	sto.push(acc);

	localStorage["accounts"] = JSON.stringify(sto);
}

var epochNum = 1385294400;
var noAccountsMessage = "No Accounts Added";
var accounts;
var pendingAccount;

function popoutOpen()
{
	if(!localStorage.hasOwnProperty("node"))
	{
		localStorage["node"] = DEFAULT_NODE;
		localStorage["isTestnet"] = false;
	}
	// ok lets deal with any popup setup thats needed.
	if(!localStorage["accounts"] || JSON.parse(localStorage["accounts"]).length == 0)
	{
		// no accounts, take us to the accounts tab first..
		$("#popout_tabs a[href='#accounts']").tab("show");
		addAccountOption(noAccountsMessage);
	}
	else
	{
		loadAccounts();
	}

}	

function loadAccounts()
{
	clearAccountOptions();
	var accounts = JSON.parse(localStorage["accounts"]);
	if(accounts && accounts.length > 0)
	{
		for(var a=0;a<accounts.length;a++)
		{
			addAccountOption(accounts[a]["accountRS"]);
		}
	}
	else
	{
		addAccountOption(noAccountsMessage);
	}
}

function addAccountOption(option)
{
	if($("#transact_account").html().indexOf(noAccountsMessage) > -1)
	{
		clearAccountOptions();
	}
	$("#transact_account").append("<option>"+option+"</option>");
	$("#token_account").append("<option>"+option+"</option>");
	$("#message_account").append("<option>"+option+"</option>");
	$("#accounts_account").append("<option>"+option+"</option>");
}

function clearAccountOptions()
{
	$("#transact_account").html("");
	$("#token_account").html("");
	$("#message_account").html("");
	$("#accounts_account").html("");
}

function broadcastTransaction(nd, bytes)
{
	var params = {requestType: "broadcastTransaction", transactionBytes: bytes};
	$.ajax(nd, {
		url: nd,
		data: params,
		type: "POST",
		success: transactionBroadcasted,
		timeout: 2000,
		fail: transactionBroadcasted
	});
}

function transactionBroadcasted(resp, state)
{
	var response = JSON.parse(resp);
	$("#modal_signed").modal("hide");
	$("#modal_quick_sure").modal("hide");
	if(state != "success")
	{
		infoModal("Couldn't reach server");
	}
	if(response.errorCode != undefined)
	{
		$("#modal_tx_response_title").text("Transaction Error");
		$("#modal_tx_response_key_1").text("Error Code");
		$("#modal_tx_response_value_1").text(response.errorCode);
		$("#modal_tx_response_key_2").text("Error Description");
		$("#modal_tx_response_value_2").text(response.errorDescription); 
		$("#modal_tx_response").modal("show");

	}
	if(response.transaction != undefined)
	{
		$("#modal_tx_response_title").text("Transaction Successful");
		$("#modal_tx_response_key_1").text("Transaction Id");
		$("#modal_tx_response_value_1").text(response.transaction);
		$("#modal_tx_response_key_2").text("Full Hash");
		$("#modal_tx_response_value_2").text(response.fullHash);
		$("#modal_tx_response").modal("show");
	}
}

function setBroadcastNode(node, isTestnet)
{
	localStorage["node"] = node;
	localStorage["isTestnet"] = (isTestnet === true);
}

function getBroadcastNode()
{
	var node = "http://";
	if(localStorage["node"] == undefined)
	{
		node += DEFAULT_NODE;
		localStorage["node"] = DEFAULT_NODE;
	}
	else node += localStorage["node"];
	if(localStorage["isTestnet"] == "true") node += ":6876";
	else node += ":7876";
	return node + "/nxt";
}

function pinHandler(source, pin)
{
	if(source == "accounts_new")
	{
		accountsNewHandler(pin);
	}
	else if(source == "change")
	{
		changePinHandler(pin);
	}
	else if(source == "newpin")
	{
		newPinHandler(pin);
	}
	else if(source == "export")
	{
		exportHandler(pin);
	}
	else if(source == "delete")
	{
		deleteHandler(pin);
	}
	else if(source == "import")
	{
		importHandler(pin);
	}
	else if(source == "token")
	{
		tokenHandler(pin);
	}
	else if(source == "quicksend")
	{
		quicksendHandler(pin);
	}
	else if(source == "review")
	{
		reviewHandler(pin);
	}

}

function accountsNewHandler(pin)
{
	$("#modal_accounts_new").modal("show");
	var account = newAccount(generateSecretPhrase(), pin);
	pendingAccount = account;
	$("#modal_accounts_new_address").text(account["accountRS"]);
	$("#modal_accounts_new_recovery").val(account["secretPhrase"]);
}

function changePinHandler(pin)
{
	var address = $("#accounts_account option:selected").text();
	var account = findAccount(address);
	var data = decryptSecretPhrase(account.cipher, pin, account.checksum);
	if(data === false)
	{
		// incorrect
		$("#modal_basic_info").modal("show");
		$("#modal_basic_info_title").text("Incorrect PIN");
	}
	else
	{
		data = undefined;
		$("#modal_enter_pin").data("source", "newpin");
		$("#modal_enter_pin").data("pin", pin);
		setTimeout(function() {$("#modal_enter_pin").modal("show");}, 600);
	}
}

function newPinHandler(pin)
{
	var address = $("#accounts_account option:selected").text();
	var accounts = JSON.parse(localStorage["accounts"]);
	var oldpin = $("#modal_enter_pin").data("pin");
	$("#modal_enter_pin").removeAttr("data-pin");


	for(var a=0;a<accounts.length;a++)
	{
		if(accounts[a]["accountRS"] == address)
		{
			// now lets handle...
			var sec = decryptSecretPhrase(accounts[a]["cipher"], oldpin, accounts[a]["checksum"]).toString();
			var newcipher = encryptSecretPhrase(sec, pin).toString();
			accounts[a]["cipher"] = newcipher;
		}
	}
	localStorage["accounts"] = JSON.stringify(accounts);
	infoModal("PIN Change Successful");
}

function exportHandler(pin)
{
	var address = $("#accounts_account option:selected").text();
	account = findAccount(address);
	var data = decryptSecretPhrase(account.cipher, pin, account.checksum);
	if(data === false)
	{
		// incorrect
		infoModal("Incorrect PIN");
	}
	else
	{
		$("#modal_export").modal("show");
		$("#modal_export_address").text(account["accountRS"]);
		$("#modal_export_key").val(data);
		data = undefined;
	}
}

function deleteHandler(pin)
{
	var address = $("#accounts_account option:selected").text();
	account = findAccount(address);

	var data = decryptSecretPhrase(account.cipher, pin, account.checksum);
	if(data === false)
	{
		// incorrect
		infoModal("Incorrect PIN");
	}
	else
	{
		$("#modal_delete").modal("show");
		$("#modal_delete_address").text(account["accountRS"]);
		data = undefined;
	}
}

function importHandler(pin)
{
	var secretPhrase = $("#modal_import").data("import");
	$("#modal_import").data("import", "");
	var account = newAccount(secretPhrase, pin);
	storeAccount(account);
	loadAccounts();
	infoModal("Account Successfully Imported");
}

function tokenHandler(pin)
{
	var address = $("#token_account option:selected").text();
	var account = findAccount(address);
	var secretPhrase = decryptSecretPhrase(account.cipher, pin, account.checksum);
	var websiteString = $("#token_data").val();

	if(secretPhrase === false)
	{
		infoModal("Incorrect PIN");
	}
	else
	{
		var token = generateToken(websiteString, secretPhrase);
		$("#modal_token_box").val(token);
		$("#modal_token").modal("show");
	}
}

function isHex(hex)
{
	for(var a=0;a<hex.length;a++)
	{
		var p = hex.charCodeAt(a)
		if((p < 48) || (p > 57 && p < 65) || (p > 70 && p < 97) || (p > 102))
		{
			return false;
		}
	}
	return true;
}

function startTransact()
{
	var account = $("#transact_account option:selected").val();
	var tx = $("#transact_transaction").val();
	// decide what kind of tx it is
	if(tx.indexOf("NXT-") == 0)
	{
		// nxt addy, quicksend format...
		startQuicksend(account, tx);
	}
	else if(tx.indexOf("TX_") == 0)
	{
		// TRF
		startTRF(account, tx);
	}
	else
	{
		if(isHex(tx))
		{
			// its hex
			if(tx.length == 64)
			{
				startQuicksend(account, tx, true);
			}
			else
			{
				startHex(account, tx);
			}
		}
		else
		{
			infoModal("Transaction Format Unrecognized")
		}
	}
}

function startQuicksend(sender, recipient, pub)
{
	$("#modal_quicksend").modal("show");
	if(pub == undefined || pub == false)
	{
		$("#modal_quicksend_address").val(recipient);
	}
	else if(pub == true)
	{
		var accid = getAccountIdFromPublicKey(recipient, true);
		$("#modal_quicksend_address").val(accid);
	}
	$("#modal_quicksend").data("sender", sender);
	$("#modal_quicksend").data("recipient", recipient);
}

/*255 here..


29 bytes normal tx...
*/

// 0100101234123412341234010000000000000000e1f5050000000000000000
// TX_3YoYmaTiHaxe7ApnLdGR JWnLUnmbB4r9lSsr5pudM

function currentNxtTime()
{
	return Math.floor(Date.now() / 1000) - 1385294400;
}

function nxtTimeBytes()
{
	return converters.int32ToBytes(currentNxtTime());
}

function positiveByteArray(byteArray)
{
	return converters.hexStringToByteArray(converters.byteArrayToHexString(byteArray));
}

function startTRF(sender, trfBytes)
{
	var bytes = base62Decode(trfBytes.substring(3));
	console.log(JSON.stringify(bytes));
	if(bytes[0] == '1')
	{
		bytes = bytes.slice(1);
		if(bytes.length == 31) bytes = bytes.slice(0, 30);

		var collect = [];
		collect = [bytes[0],bytes[1]]; // type ver & subtype
		collect = collect.concat(nxtTimeBytes()); // timestamp
		collect = collect.concat(wordBytes(1440)); // deadline
		var senderPubKey = converters.hexStringToByteArray(findAccount(sender).publicKey);
		collect = collect.concat(senderPubKey);
		collect = collect.concat(bytes.slice(2, 2+8)); // recipient/genesis
		collect = collect.concat(bytes.slice(10, 10+8)); // amount
		collect = collect.concat(bytes.slice(18, 18+8)); // fee
		collect = collect.concat(pad(32, 0)); // reftxhash
		collect = collect.concat(pad(64, 0)); // signature bytes
		collect = collect.concat(bytes.slice(26, 26+4)); // flags
		collect = collect.concat(pad(4, 0)); // EC blockheight
		collect = collect.concat(pad(8, 0)); // EC blockid
		if(bytes.length > 30) collect = collect.concat(bytes.slice(30)); // attachment/appendages
		startHex(converters.byteArrayToHexString(collect));
	}


}

function startHex(hex)
{
	// now we have hex bytes, lets deal with them...
	var bytes = converters.hexStringToByteArray(hex);

	// get important things from this, verify it?..
	extractBytesData(bytes);
}

function clearReview()
{
	setReview(1, "", "");
	setReview(2, "", "");
	setReview(3, "", "");
	setReview(4, "", "");
	setReview(5, "", "");
	setReview(6, "", "");

}

function extractBytesData(bytes)
{
	// lets think here.
	// first we take out the version and subversion, and then think from there
	// have about 8 different places to put data, then account for all possible types
	// appendages will have dropdowns with their content and won't take up much room.
	// the 8 zones will need to be really small.
	// type sender amount recip extra for attachment...
	clearReview();
	$("#modal_review_description").attr("disabled", "true");
	$("#modal_review_description").attr("data-content", "");
	$("#modal_review").data("bytes", converters.byteArrayToHexString(bytes));
	var type = bytes[0];
	var subtype = bytes[1] % 16;
	var sender = getAccountIdFromPublicKey(converters.byteArrayToHexString(bytes.slice(8, 8+32)), true);
	var r = new NxtAddress();
	r.set(byteArrayToBigInteger(bytes.slice(40, 48)).toString());
	var recipient = r.toString();
	var amount = byteArrayToBigInteger(bytes.slice(48, 48+8));
	var fee = byteArrayToBigInteger(bytes.slice(56, 56+8));
	var flags = converters.byteArrayToSignedInt32(bytes.slice(160, 160+4));
	rest = [];
	if(bytes.length > 176) rest = bytes.slice(176);
	var msg = [];
	if(type == 0)
	{
		if(subtype == 0)
		{
			typeName = "Ordinary Payment";
			setReview(1, "Type", typeName);
			setReview(2, "Sender", sender);
			setReview(3, "Recipient", recipient);
			setReview(4, "Amount", amount/100000000 + " nxt");
			setReview(5, "Fee", fee/100000000 + " nxt");
			if(rest.length) msg = rest;
		}
	}
	else if(type == 1)
	{
		if(subtype == 0)
		{
			typeName = "Arbitrary Message";
			setReview(1, "Type", typeName);
			setReview(2, "Sender", sender);
			setReview(3, "Recipient", recipient);
			setReview(4, "Fee", fee/100000000 + " nxt");
			if(rest.length) msg = rest;
		}
		else if(subtype == 1) 
		{
			typeName = "Alias Assignment";
			setReview(1, "Type", typeName);
			setReview(2, "Registrar", sender);
			var alias = converters.byteArrayToString(rest.slice(2, rest[1]+2));
			setReview(3, "Alias Name", alias);
			setReview(4, "Fee", fee/100000000 + " nxt");
			var data = converters.byteArrayToString(rest.slice(4+rest[1], 4+rest[1]+bytesWord([rest[2+rest[1]], rest[3+rest[1]]])));
			$("#modal_review_description").removeAttr("disabled");
			$("#modal_review_description").attr("data-content", data);
			if(rest.length > 2+rest[1]+bytesWord(rest.slice(2+rest[1], 4+rest[1]))) msg = rest.slice(2+rest[1]+bytesWord(rest.slice(2+rest[1], 4+rest[1])));
		}
		else if(subtype == 2)
		{
			typeName = "Poll Creation"; //  not yet
		}
		else if(subtype == 3) 
		{
			typeName = "Vote Casting"; // not yet
		}
		else if(subtype == 4)
		{
			typeName = "Hub Announcement"; //  what even is this?
		}
		else if(subtype == 5) 
		{
			typeName = "Account Info";
			setReview(1, "Type", typeName);
			setReview(2, "Account", sender);
			var alias = converters.byteArrayToString(rest.slice(2, rest[1]+2));
			setReview(3, "Name", alias);
			setReview(4, "Fee", fee/100000000 + " nxt");
			var data = converters.byteArrayToString(rest.slice(4+rest[1], 4+rest[1]+bytesWord([rest[2+rest[1]], rest[3+rest[1]]])));
			$("#modal_review_description").removeAttr("disabled");
			$("#modal_review_description").attr("data-content", data);
			if(rest.length > 2+rest[1]+bytesWord(rest.slice(2+rest[1], 4+rest[1]))) msg = rest.slice(2+rest[1]+bytesWord(rest.slice(2+rest[1], 4+rest[1])));
		}
		else if(subtype == 6) 
		{
			typeName = "Alias Sell";
			setReview(1, "Type", typeName);
			setReview(2, "Seller", sender);
			var alias = converters.byteArrayToString(rest.slice(2, rest[1]+2));
			if(recipient == "NXT-2222-2222-2222-22222") setReview(3, "Buyer", "Anyone");
			else setReview(3, "Buyer", recipient);
			setReview(4, "Alias Name", alias);
			var price = byteArrayToBigInteger(rest.slice(2+rest[1], 10+rest[1])).toString();
			setReview(5, "Sell Price", price);
			setReview(6, "Fee", fee/100000000 + " nxt");
			if(rest.length > 10+rest[1]) msg = rest.slice(10+rest[1]);
		}
		else if(subtype == 7) 
		{
			typeName = "Alias Buy";
			setReview(1, "Type", typeName);
			setReview(2, "Buyer", sender);
			setReview(3, "Seller", recipient);
			var alias = converters.byteArrayToString(rest.slice(2, rest[1]+2));
			setReview(4, "Alias", alias);
			setReview(5, "Buy Price", amount/100000000 + " nxt");
			setReview(6, "Fee", fee/100000000 + " nxt");
			if(rest.length > 2+rest[1]) msg = rest.slice(2+rest[1])
		}
	}
	else if(type == 2)
	{
		if(subtype == 0) 
		{
			typeName = "Asset Issuance";
			setReview(1, "Type", typeName);
			setRevieW(2, "Issuer", sender);
			var name = converters.byteArrayToString(rest.slice(2,rest[1]+2));
			setReview(3, "Asset Name", name);
			var data = converters.byteArrayToString(rest.slice(4+rest[1], 4+rest[1]+bytesWord([rest[2+rest[1]], rest[3+rest[1]]])));
			var newpos = 4+rest[1]+bytesWord([rest[2+rest[1]], rest[3+rest[1]]]);
			$("#modal_review_description").removeAttr("disabled");
			$("#modal_review_description").attr("data-content", data);
			var units = byteArrayToBigInteger(rest.slice(newpos, newpos+8));
			setReview(4, "Units", units);
			setReview(5, "Decimals", rest[newpos+8]);
			setReview(6, "Fee", fee/100000000 + " nxt");
		}
		else if(subtype == 1) 
		{
			typeName = "Asset Transfer";
			setReview(1, "Type", typeName);
			setReview(2, "Sender", sender);
			setReview(3, "Recipient", recipient);
			var assetId = byteArrayToBigInteger(rest.slice(1, 1+8)).toString();
			setReview(4, "Asset Id", assetId);
			var amount = byteArrayToBigInteger(rest.slice(1+8, 1+16)).toString();
			setReview(5, "Amount", amount + " QNT");
			setReview(6, "Fee", fee/100000000 + " nxt");
			if(rest.length > 17) msg = rest.slice(17);
		}
		else if(subtype == 2) 
		{
			typeName = "Ask Order Placement";
			setReview(1, "Type", typeName);
			setReview(2, "Trader", sender);
			var assetId = byteArrayToBigInteger(rest.slice(1, 1+8)).toString();
			setReview(3, "Asset Id", assetId);
			var amount = byteArrayToBigInteger(rest.slice(1+8, 1+16)).toString();
			setReview(4, "Amount", amount + " QNT");
			var price = byteArrayToBigInteger(rest.slice(1+16, 1+24)).toString();
			setReview(5, "Price", price/100000000 + " nxt");
			setReview(6, "Fee", fee/100000000 + " nxt");
			if(rest.length > 25) msg = rest.slice(25);
		}
		else if(subtype == 3) 
		{
			typeName = "Bid Order Placement";
			setReview(1, "Type", typeName);
			setReview(2, "Trader", sender);
			var assetId = byteArrayToBigInteger(rest.slice(1, 1+8)).toString();
			setReview(3, "Asset Id", assetId);
			var amount = byteArrayToBigInteger(rest.slice(1+8, 1+16)).toString();
			setReview(4, "Amount", amount + " QNT");
			var price = byteArrayToBigInteger(rest.slice(1+16, 1+24)).toString();
			setReview(5, "Price", price/100000000 + " nxt");
			setReview(6, "Fee", fee/100000000 + " nxt");
			if(rest.length > 25) msg = rest.slice(25);
		}
		else if(subtype == 4) 
		{
			typeName = "Ask Order Cancellation";
			setReview(1, "Type", typeName);
			setReview(2, "Trader", sender);
			var order = byteArrayToBigInteger(rest.slice(1, 1+8)).toString();
			setReview(3, "Order Id", order);
			setReview(4, "Fee", fee/100000000 + " nxt");
			if(rest.length > 9) msg = rest.slice(9);
		}
		else if(subtype == 5)
		{
			typeName = "Bid Order Cancellation";
			setReview(1, "Type", typeName);
			setReview(2, "Trader", sender);
			var order = byteArrayToBigInteger(rest.slice(1, 1+8)).toString();
			setReview(3, "Order Id", order);
			setReview(4, "Fee", fee/100000000 + " nxt");
			if(rest.length > 9) msg = rest.slice(9);
		}
	}
	else if(type == 3)
	{
		if(subtype == 0) 
		{
			typeName = "Goods Listing";
			setReview(1, "Type", typeName);
			setRevieW(2, "Seller", sender);
			var name = converters.byteArrayToString(rest.slice(3,rest[1]+2));
			setReview(3, "Good Name", name);
			var data = converters.byteArrayToString(rest.slice(4+rest[1], 4+rest[1]+bytesWord([rest[2+rest[1]], rest[3+rest[1]]])));
			var newpos = 4+rest[1]+bytesWord([rest[2+rest[1]], rest[3+rest[1]]]);
			var tags = converters.byteArrayToString(rest.slice(newpos+2, newpos+2+bytesWord([rest[newpos],rest[newpos+1]])));
			newpos = newpos+2+bytesWord([rest[newpos],rest[newpos+1]]);
			setReview(4, "Tags", tags);
			$("#modal_review_description").removeAttr("disabled");
			$("#modal_review_description").attr("data-content", data);
			var amount = converters.byteArrayToSignedInt32(rest.slice(newpos, newpos+4));
			var price = byteArrayToBigInteger(rest.slice(newpos+4, newpos+12)).toString();
			setReview(5, "Amount (price)", amount + "(" + price/100000000 + " nxt)");
			setReview(6, "Fee", fee/100000000 + " nxt");
		}
		else if(subtype == 1) 
		{
			typeName = "Goods Delisting";
			setReview(1, "Type", typeName);
			setReview(2, "Seller", sender);
			var order = byteArrayToBigInteger(rest.slice(1, 1+8)).toString();
			setReview(3, "Item Id", order);
			setReview(4, "Fee", fee/100000000 + " nxt");
			if(rest.length > 9) msg = rest.slice(9);

		}
		else if(subtype == 2) 
		{
			typeName = "Price Change";
			setReview(1, "Type", typeName);
			setReview(2, "Seller", sender);
			var goodid = byteArrayToBigInteger(rest.slice(1, 1+8)).toString();
			setReview(3, "Item Id", goodid);
			var newprice = byteArrayToBigInteger(rest.slice(1+8, 1+8+8)).toString();
			setReview(4, "New Price", nowprice/100000000 + " nxt");
			setReview(5, "Fee", fee/100000000 + " nxt");
			if(rest.length > 1+8+8) msg = rest.slice(17);
		}
		else if(subtype == 3) 
		{
			typeName = "Quantity Change";
			setReview(1, "Type", typeName);
			setReview(2, "Seller", sender);
			var goodid = byteArrayToBigInteger(rest.slice(1, 1+8)).toString();
			setReview(3, "Item Id", goodid);
			var chg = converters.byteArrayToSignedInt32(rest.slice(1+8, 1+8+4));
			if(chg < 0) setReview(4, "Decrease By", -chg);
			else setReview(4, "Increase By", chg);
			setReview(5, "Fee", fee/100000000 + " nxt");
			if(rest.length > 1+8+4) msg = rest.slice(13);
		}
		else if(subtype == 4)
		{
			typeName = "Purchase";
			setReview(1, "Type", typeName);
			setReview(2, "Buyer", sender);
			var goodid = byteArrayToBigInteger(rest.slice(1, 1+8)).toString();
			setReview(3, "Item Id", goodid);
			var qnt = byteArrayToBigInteger(rest.slice(1+8, 1+8+4)).toString();
			setReview(4, "Quantity", qnt);
			var price = byteArrayToBigInteger(rest.slice(1+8+4, 1+16+4)).toString();
			setReview(5, "Price", price/100000000 + " nxt");
			setReview(6, "Fee", fee/100000000 + " nxt");
			if(rest.length > 1+16+8) msg = rest.slice(25);
		}
		else if(subtype == 5)
		{
			typeName = "Delivery";
			setReview(1, "Type", typeName);
			setReview(2, "Seller", sender);
			var goodid = byteArrayToBigInteger(rest.slice(1, 1+8)).toString();
			setReview(3, "Item Id", goodid);
			var discount = byteArrayToBigInteger(rest.slice(rest.length-8)).toString();
			setReview(4, "Discount", discount/100000000 + " nxt");
			setReview(5, "Fee", fee/100000000 + " nxt");
			if(rest.length > 1+8) msg = rest.slice(9);
		
		}
		else if(subtype == 6) 
		{
			typeName = "Feedback";
			setReview(1, "Type", typeName);
			setReview(2, "User", sender);
			setReview(3, "Seller", recipient);
			var goodid = byteArrayToBigInteger(rest.slice(1, 1+8)).toString();
			setReview(4, "Item Id", goodid);
			setReview(5, "Fee", fee/100000000 + " nxt");
			if(rest.length > 1+8) msg = rest.slice(9);
		}
		else if(subtype == 7) 
		{
			typeName = "Refund";
			setReview(1, "Type", typeName);
			setReview(2, "Seller", sender);
			var goodid = byteArrayToBigInteger(rest.slice(1, 1+8)).toString();
			setReview(3, "Purchase Id", goodid);
			var discount = byteArrayToBigInteger(rest.slice(1+8,1+16)).toString();
			setReview(4, "Refund Amount", discount/100000000 + " nxt");
			setReview(5, "Fee", fee/100000000 + " nxt");
			if(rest.length > 1+16) msg = rest.slice(17);
		}
	}
	else if(type == 4)
	{
		if(subtype == 0)
		{
			typeName = "Balance Leasing";
			setReview(1, "Type", typeName);
			setReview(2, "Lessor", sender);
			var lease = bytesWord(rest.slice(1,3));
			setReview(3, "Length", lease + " blocks");
			setReview(4, "Fee", fee/100000000 + " nxt");
			if(rest.length > 3) msg = rest.slice(3);
		} 
	}
	else if(type == 5)
	{
		if(subtype == 0)
		{
			typeName = "Issue Currency";
		}
		else if(subtype == 1)
		{
			typeName = "Reserve Increase";
			setReview(1, "Type", typeName);
			setReview(2, "Reserver", sender);
			var assetid = converters.byteArrayToString(rest.slice(1, 1+8));
			setReview(3, "Currency Id", assetId);
			var amount = byteArrayToBigInteger(rest.slice(1+8, 1+16)).toString();
			setReview(4, "Amount per Unit", amount + " nxt");
			setReview(5, "Fee", fee/100000000 + " nxt");
			if(rest.length > 17) msg = rest.slice(17);
		}
		else if(subtype == 2)
		{
			typeName = "Reserve Claim";
		}
		else if(subtype == 3)
		{
			typeName = "Currency Transfer";
			setReview(1, "Type", typeName);
			setReview(2, "Sender", sender);
			setReview(3, "Recipient", recipient);
			var ms = byteArrayToBigInteger(rest.slice(1, 1+8)).toString();
			setReview(4, "Currency Id", ms);
			var amount = byteArrayToBigInteger(rest.slice(1+8, 1+16)).toString();
			setReview(5, "Amount", amount + " QNT");
			setReview(6, "Fee", fee/100000000 + " nxt");
			if(rest.length > 17) msg = rest.slice(17);
		}
		else if(subtype == 4)
		{
			typeName = "Exchange Offer";
		}
		else if(subtype == 5)
		{
			typeName = "Exchange Buy";
		}
		else if(subtype == 6)
		{
			typeName = "Exchange Sell";
		}
		else if(subtype == 7)
		{
			typeName = "Mint Currency";
			setReview(1, "Type", typeName);
			setReview(2, "Minter", sender);
			var assetid = byteArrayToBigInteger(rest.slice(1, 1+8)).toString();
			setReview(3, "Currency Id", assetId);
			var amount = byteArrayToBigInteger(rest.slice(1+16, 1+24)).toString();
			setReview(4, "Amount To Mint", amount + " Units");
			setReview(5, "Fee", fee/100000000 + " nxt");
			if(rest.length > 16+16+1) msg = rest.slice(33);
		}
		else if(subtype == 8)
		{
			typeName = "Delete Currency";
		}
	}

	var message = getModifierBit(flags, 0);
	var publicKey = getModifierBit(flags, 2);
	if(message && msg.length)
	{
		$("#modal_review_message").removeAttr("disabled");
		var len = bytesWord([msg[1],msg[2]]);
		var str = converters.byteArrayToString(msg.slice(5,5+len));
		$("#modal_review_message").attr("data-content", str);
		msg = msg.slice(3+len);
	}
	else $("#modal_review_message").attr("disabled", "true");
	if(publicKey && msg.length)
	{
		$("#modal_review_public_key").removeAttr("disabled");
		var str = converters.byteArrayToHexString(msg.slice(1,65));
		$("#modal_review_public_key").attr("data-content", str);
		msg = msg.slice(65);
	}
	else $("#modal_review_public_key").attr("disabled","true");

	// appendages... ugh... and no icons, how will I do this..

	$("#modal_review").modal("show");
}

function getModifierBit(target, position)
{
	return (target >> position)%2;
}

function setReview(number, key, value)
{
	$("#modal_review_key_"+number).text(key);
	$("#modal_review_value_"+number).text(value);
}


function quicksendHandler(pin)
{
	var amount = $("#modal_enter_pin").data("amount");
	$("#modal_enter_pin").removeAttr("data-amount");
	var recipient = $("#modal_enter_pin").data("recipient");
	$("#modal_enter_pin").removeAttr("data-recipient");
	var sender = $("#modal_enter_pin").data("sender");
	$("#modal_enter_pin").removeAttr("data-sender");
	var account = findAccount(sender)

	var secretPhrase = decryptSecretPhrase(account.cipher, pin, account.checksum);

	if(secretPhrase === false)
	{
		infoModal("Incorrect PIN");
	}
	else
	{
		var quickbytes = createQuicksend(recipient, amount, secretPhrase);
		$("#modal_quick_sure").data("tx", converters.byteArrayToHexString(quickbytes));
		$("#modal_quick_sure_sender").text(sender);
		if(recipient.indexOf("NXT-") == 0)
		{
			$("#modal_quick_sure_recipient").text(recipient);
		}
		else
		{
			$("#modal_quick_sure_recipient").text(getAccountIdFromPublicKey(recipient, true) + " (with Public Key)");
		}
		$("#modal_quick_sure_amount").text(amount + " nxt");
		$("#modal_quick_sure").modal("show");

		// now we open the "are you sure" modal...tomorrow..
	}
}

function createQuicksend(recipient, amount, secretPhrase)
{
	var txbytes = [];
	txbytes.push(0) // type
	txbytes.push(0 + (1 << 4)); // version/type
	txbytes = txbytes.concat(nxtTimeBytes()); // timestmp
	txbytes = txbytes.concat(wordBytes(1440)); // deadline
	txbytes = txbytes.concat(getPublicKey(secretPhrase)); // public Key

	if(recipient.indexOf("NXT-") == 0)
	{
		recipientRS = recipient;
	}
	else
	{
		recipientRS = getAccountIdFromPublicKey(recipient, true);
	}
	var rec = new NxtAddress();
	rec.set(recipientRS);
	var recip = (new BigInteger(rec.account_id())).toByteArray().reverse();
	if(recip.length == 9) recip = recip.slice(0, 8);
	while(recip.length < 8) recip = recip.concat(pad(1, 0));
	txbytes = txbytes.concat(recip);

	var amt = ((new BigInteger(String(parseInt(amount*100000000))))).toByteArray().reverse();
	if(amt.length == 9) amt = amt.slice(0, 8);
	while(amt.length < 8) amt = amt.concat(pad(1, 0));
	txbytes = txbytes.concat(amt); 

	var fee = (converters.int32ToBytes(100000000));
	while(fee.length < 8) fee = fee.concat(pad(1, 0));
	txbytes = txbytes.concat(fee);

	txbytes = txbytes.concat(pad(32, 0)); // ref full hash
	txbytes = txbytes.concat(pad(64, 0)); // signature

	if(recipient.indexOf("NXT-") == 0)
	{
		txbytes = txbytes.concat(pad(16, 0)); // ignore everything else
	}
	else
	{
		txbytes.push(4);
		txbytes = txbytes.concat(pad(3, 0));
		txbytes = txbytes.concat(pad(12, 0));
		txbytes = txbytes.concat([1]);
		txbytes = txbytes.concat(converters.hexStringToByteArray(recipient));
	}

	txbytes = positiveByteArray(txbytes);
	var sig = signBytes(txbytes, secretPhrase);

	signable = txbytes.slice(0, 96);
	signable = signable.concat(sig);
	signable = signable.concat(txbytes.slice(96+64));

	// now we have a full tx...
	return signable;
}

function wordBytes(word)
{
	return [(word%256), Math.floor(word/256)];
}

function bytesWord(bytes)
{
	return bytes[1]*256+bytes[0];
}

function infoModal(message)
{
	$("#modal_basic_info").modal("show");
	$("#modal_basic_info_title").text(message);
}

function reviewHandler(pin)
{
	var bytes = converters.hexStringToByteArray($("#modal_enter_pin").data("bytes"));
	$("#modal_enter_pin").removeAttr("data-bytes");
	var address = $("#accounts_account option:selected").text();
	account = findAccount(address);
	var secretPhrase = decryptSecretPhrase(account.cipher, pin, account.checksum);
	if(secretPhrase === false)
	{
		// incorrect
		infoModal("Incorrect PIN");
	}
	else
	{
		var sig = signBytes(bytes, secretPhrase);
		var signed = bytes.slice(0,96);
		signed = signed.concat(sig);
		signed = signed.concat(bytes.slice(96+64));
		$("#modal_signed_box").val(converters.byteArrayToHexString(signed));
		$("#modal_signed").modal("show");
	}
}

function verifyToken()
{
	var token = $("#modal_verify_token_token").val();
	var websiteString = $("#token_data").val();
	var resp = parseToken(token, websiteString);

	if(token.length == 160)
	{
		if(resp.isValid)
		{
			$("#modal_verify_token_group").removeClass("has-error");
			$("#modal_verify_token_group").addClass("has-success");
			$("#modal_verify_token_insert").text("(valid)");
		}
		else
		{
			$("#modal_verify_token_group").addClass("has-error");
			$("#modal_verify_token_group").removeClass("has-success");
			$("#modal_verify_token_insert").text("(invalid)");
		}
		$("#modal_verify_token_address").text(getAccountIdFromPublicKey(resp.publicKey, true));
		$("#modal_verify_token_timestamp").text(timeago(resp.timestamp));
	}
	else if(token.length == 0)
	{
		$("#modal_verify_token_group").removeClass("has-error");
		$("#modal_verify_token_group").removeClass("has-success");
		$("#modal_verify_token_insert").text("");	
		$("#modal_verify_token_address").text("N/A");
		$("#modal_verify_token_timestamp").text("N/A");
	}
	else
	{
		$("#modal_verify_token_group").addClass("has-error");
		$("#modal_verify_token_group").removeClass("has-success");
		$("#modal_verify_token_insert").text("(invalid)");	
		$("#modal_verify_token_address").text("Token Length Incorrect");
		$("#modal_verify_token_timestamp").text("N/A");
	}
}


function findAccount(address)
{
	var accounts = JSON.parse(localStorage["accounts"]);
	if(accounts && accounts.length > 0)
	{
		for(var a=0;a<accounts.length;a++)
		{
			if(accounts[a]["accountRS"] == address) return accounts[a];
		}
	}
	return false;
}

$("document").ready(function() {

	$("#modal_enter_pin").on("show.bs.modal", function(e) {
		$("#modal_enter_pin_input").val("");

		var source = $(e.relatedTarget).data("source");
		if(source === undefined) source = $("#modal_enter_pin").data("source");

		if(source == "accounts_new")
		{
			$("#modal_enter_pin_title").text("Enter PIN for New Account");
		}
		else if(source == "change")
		{
			$("#modal_enter_pin_title").text("Enter Old PIN");
		}
		else if(source == "newpin")
		{
			$("#modal_enter_pin_title").text("Enter New PIN");
		}
		else if(source =="export")
		{
			$("#modal_enter_pin_title").text("Enter PIN to Export");
		}
		else if(source == "delete")
		{
			$("#modal_enter_pin_title").text("Enter PIN to Delete");
		}
		else if(source == "import")
		{
			$("#modal_enter_pin_title").text("Enter PIN for New Account");
		}
		else if(source == "token")
		{
			$("#modal_enter_pin_title").text("Enter PIN to Create Token");
		}
		else if(source == "quicksend")
		{
			$("#modal_enter_pin_title").text("Enter PIN to Quicksend");
		}
		else if(source == "review")
		{
			$("#modal_enter_pin_title").text("Enter PIN to Sign Transaction");
		}
		$("#modal_enter_pin_accept").data("source", source);
	});

	$("#modal_enter_pin_cancel").click(function() {
		$("#modal_enter_pin_input").val("");
	});
	$("#modal_enter_pin_accept").click(function() {
		$(this).modal("hide");
		pinHandler($("#modal_enter_pin_accept").data("source"), $("#modal_enter_pin_input").val());
	})

	$(".modal_enter_pin_number").click(function() {
		$("#modal_enter_pin_input").val($("#modal_enter_pin_input").val() + $(this).data("number"));
	});
	$("#modal_enter_pin_clear").click(function() {
		$("#modal_enter_pin_input").val("");
	})
	$("#modal_enter_pin_back").click(function() {
		$("#modal_enter_pin_input").val($("#modal_enter_pin_input").val().substring(0, $("#modal_enter_pin_input").val().length-1));
	})

	$(".account_selector").change(function(e) {
		var source = $(this).data("source");
		var account = $("#"+source+"_account option:selected").text();

		$(".account_selector option").removeAttr("selected");
		$(".account_selector option:contains("+account+")").attr("selected", "selected");
	});

	$("#modal_accounts_info").on("show.bs.modal", function(e) {
		var source = $(e.relatedTarget).data("source");
		var address = $("#"+source+"_account option:selected").text();
		var account = findAccount(address);

		if(account === false)
		{
			$("#modal_accounts_info_address").val("Account Not Found");
		}
		else
		{
			$("#modal_accounts_info_address").val(account["accountRS"]);
			$("#modal_accounts_info_public_key").val(account["publicKey"]);
		}
	})

	$("#modal_backup").on("show.bs.modal", function(e) {
		if(localStorage["accounts"] && JSON.parse(localStorage["accounts"]).length != 0)
		{
			$("#modal_backup_box").val(localStorage["accounts"]);
		}
		else 
		{
			$("#modal_backup_box").val("No accounts are added.")
		}
	})

	$("#modal_accounts_new_add").click(function() {
		storeAccount(pendingAccount);
		pendingAccount = undefined;
		loadAccounts();
		$("#modal_accounts_new").modal("hide");
		infoModal("Account Successfully Added");
	});
	$("#modal_accounts_new_cancel").click(function() {
		pendingAccount = undefined;
	})

	$("#modal_delete_delete").click(function(e) {
		// actually delete now
		$("#modal_delete").modal("hide");
		var address = $("#accounts_account option:selected").text();
		var data = localStorage["accounts"];
		var accounts = JSON.parse(localStorage["accounts"]);

		for(var a=0;a<accounts.length;a++)
		{
			if(accounts[a]["accountRS"] == address)
			{
				accounts.splice(a, 1);
			}
		}
		localStorage["accounts"] = JSON.stringify(accounts);
		loadAccounts();
		infoModal("Account Deleted");
	});

	$("#modal_import_add").click(function() {
		$("#modal_import").data("import", $("#modal_import_key").val());
		$("#modal_import").modal("hide");
		$("#modal_import_key").val("");
		$("#modal_enter_pin").data("source", "import");
		$("#modal_enter_pin").modal("show");
	})

	$("#token_form").submit(function(e) {
		e.preventDefault();
		$("#modal_enter_pin").data("source", "token");
		$("#modal_enter_pin").modal("show");
	})

	$("#transact_continue").click(function() {
		startTransact();
	})
	$("#transact_form").submit(function() {
		startTransact();
	})

	$("#modal_quicksend_send").click(function() {
		$("#modal_quicksend").modal("hide");
		var amount = $("#modal_quicksend_amount").val();
		$("#modal_quicksend_amount").val("");
		var sender = $("#modal_quicksend").data("sender");
		var recipient = $("#modal_quicksend").data("recipient");
		$("#modal_enter_pin").data("source", "quicksend");
		$("#modal_enter_pin").data("amount", amount);
		$("#modal_enter_pin").data("sender", sender);
		$("#modal_enter_pin").data("recipient", recipient);
		$("#modal_enter_pin").modal("show");
	})

	$("#modal_review_continue").click(function() {
		var bytes = $("#modal_review").data("bytes");
		$("#modal_review").modal("hide");
		$("#modal_enter_pin").data("source", "review");
		$("#modal_enter_pin").data("bytes", bytes);
		$("#modal_enter_pin").modal("show");
	})

	$("#modal_signed_broadcast").click(function() {
		broadcastTransaction(getBroadcastNode(), $("#modal_signed_box").val());
	});

	$("#modal_quick_sure_send").click(function() {
		broadcastTransaction(getBroadCastNode(), $("#modal_quick_sure").data("tx"));
	})

	$("#modal_verify_token").on("show.bs.modal", function() {
		verifyToken();
	})

	$("#modal_verify_token_token").on("input propertychange", function() {
		verifyToken();
	})

	$("#modal_broadcast").on("show.bs.modal", function() {
		var old = localStorage["node"];
		if(localStorage["isTestnet"] == "true") old += " (testnet)";
		else old += " (mainnet)";
		$("#modal_broadcast_old").text(old);
		$("#modal_broadcast_node").text("");
		$("#modal_broadcast_testnet").removeAttr("checked");
	})

	$("#modal_broadcast_save").click(function() {
		var node = $("#modal_broadcast_node").val();
		var isTestnet = $("#modal_broadcast_testnet").is(":checked");
		setBroadcastNode(node, isTestnet);
		$("#modal_broadcast").modal("hide");
	})

}) 