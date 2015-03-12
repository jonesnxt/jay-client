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

function rndstr(len)
{
	var letters = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
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
	return rndstr(30);
}

function encryptSecretPhrase(phrase, key)
{
	var rkey = prepKey(key);
	alert(converters.stringToByteArray(phrase))
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
	$("#decrypt_account").append("<option>"+option+"</option>");
	$("#accounts_account").append("<option>"+option+"</option>");
}

function clearAccountOptions()
{
	$("#transact_account").html("");
	$("#token_account").html("");
	$("#decrypt_account").html("");
	$("#accounts_account").html("");
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
	$("#modal_basic_info").modal("show");
	$("#modal_basic_info_title").text("PIN Change Successful");
}

function exportHandler(pin)
{
	var address = $("#accounts_account option:selected").text();
	account = findAccount(address);
	var data = decryptSecretPhrase(account.cipher, pin, account.checksum);
	if(data === false)
	{
		// incorrect
		$("#modal_basic_info").modal("show");
		$("#modal_basic_info_title").text("Incorrect PIN");
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
		$("#modal_basic_info").modal("show");
		$("#modal_basic_info_title").text("Incorrect PIN");
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
	$("#modal_basic_info").modal("show");
	$("#modal_basic_info_title").text("Account Successfully Imported");
}

function tokenHandler(pin)
{
	var address = $("#token_account option:selected").text();
	var account = findAccount(address);
	var secretPhrase = decryptSecretPhrase(account.cipher, pin, account.checksum);
	var websiteString = $("#token_data").val();

	if(secretPhrase === false)
	{
		$("#modal_basic_info").modal("show");
		$("#modal_basic_info_title").text("Incorrect PIN");
	}
	else
	{
		var token = generateToken(websiteString, secretPhrase);
		$("#modal_token_box").val(token);
		$("#modal_token").modal("show");
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
		$("#modal_basic_info").modal("show");
		$("#modal_basic_info_title").text("Account Successfully Added");
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
		$("#modal_basic_info").modal("show");
		$("#modal_basic_info_title").text("Account Deleted");
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

}) 