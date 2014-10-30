//MIMOS JavaScript SignCryption
//Authur: Sazzad Hossain

//input username and password as string, function returns private key in hexadecimal value
function get_PrivatekeyHex(username,password) {
    
	var sha256 = CryptoJS.algo.SHA256.create();
    sha256.update(username.toString());
    sha256.update(password.toString());
    
    var privKey = sha256.finalize();	
    var intprivKey = new BigInteger(privKey.toString(),10);
   
    return intprivKey.toString(16);
}

//input private key in hexadecimal value, function returns public key in hexadecimal value

function get_PublickeyHex(privatekey) {

	var Privatekey = new BigInteger(privatekey,16);
    var c = getSECCurveByName("secp160r1");
    var G = c.getG();
	
    var q = c.getCurve().getQ();
	var a = c.getCurve().getA().toBigInteger();
	var b = c.getCurve().getB().toBigInteger();
	var curve = new ECCurveFp(q, a, b);
	var publickey = G.multiply(Privatekey);
	var publickeyhex= curve.encodePointHex(publickey);
    return publickeyhex;
}
//internal function 
function get_Timehash() {
	
	var d = new Date();
    var n = d.getTime();
    
    var timeHash = CryptoJS.SHA256(n.toString());
    var intHash = new BigInteger(timeHash.toString(), 10);
    
    return intHash;
}

//internal function 

function calc_Challenge(timehash) {
	
    var c = getSECCurveByName("secp160r1");
    var G = c.getG();
    
    var K = G.multiply(timehash);
    return K;
}

//internal function 

function calc_Response(privatekey,challenge) {
	var Privatekey = new BigInteger(privatekey,16);
    var R=challenge.multiply(Privatekey);
    return R;
}

//input public key in hexadecimal value and function returns public key in BigInteger

function decodepublickeyhex(publickeyhex) {
	
	 var c = getSECCurveByName("secp160r1");
	  var q = c.getCurve().getQ();
	  var a = c.getCurve().getA().toBigInteger();
	  var b = c.getCurve().getB().toBigInteger();
	  var curve = new ECCurveFp(q, a, b);
	  
	  var PublicKey = curve.decodePointHex(publickeyhex);
	  return PublicKey;
}

//input public key in hexadecimal value, username in string and password in string, function returns comparison between given public key and generated public key 

function cmp_Rpubkey(publickey,username,password) {
	
	var privatekey=get_PrivatekeyHex(username,password);
	var PublicKey = decodepublickeyhex(publickey);
	var thash=get_Timehash();
	var challenge=calc_Challenge(thash);
	var response= calc_Response(privatekey,challenge); 
	
	var pubKeymul = PublicKey.multiply(thash);
	
    var sucess = false;
	sucess=(response.equals(pubKeymul));
	return sucess;
	
}

//This is the function for Signing
//input message in string, Sernder's private key in hexadecimal and Reciever's Public Key in Hexadecimal, function returns r in BigInteger, s in BigInteger and cipher text in encrypted form

function do_SignCrypt(message, SenderPrivateKey, RecieverPublicKey ) {
	
	
	  var c = getSECCurveByName("secp160r1");
	  
	  var PublicKey = decodepublickeyhex(RecieverPublicKey);
	  var Privatekey = new BigInteger(SenderPrivateKey,16);
	 
	  var n = c.getN();
	
	  var r = BigInteger.ZERO;
	  var s = BigInteger.ZERO;
    
      var rng = new SecureRandom();
      var k=new BigInteger(160, rng);
      var QPoint= PublicKey.multiply(k);
      
      var  Qx= QPoint.getX().toBigInteger().toString();
     
      var Hash = CryptoJS.SHA256(Qx.toString());
      var QxHash=new Array();
      QxHash =Hash.toString(CryptoJS.enc.Latin1);

      var QxLen = QxHash.length / 2;
      var mu = [QxLen];
	  var v =  [QxLen];
	  
	  for (var i = 0; i < QxLen; i++) {
			 mu[i] = QxHash[i];
			 v[i] = QxHash[mu.length + i];
		}
	  var key = new BigInteger(mu);
	  
	  var cipher = CryptoJS.AES.encrypt(message, v.toString(), { key: key });
	  var rhash=CryptoJS.HmacSHA256(message, key.toString());
	  
	  var rhs= new BigInteger(rhash.toString(), 10);
	  
	  r = rhs.mod(n);
	  s = (k.subtract((r).multiply(Privatekey))).mod(n);
	
	   return {
	        R: r,
	        S: s,
	        cipher: cipher
	    }; 
}

//This is the function for Unsigning
//input r in BigInteger, s in Biginteger, Sender's Public key in hexadecimal, Reciever's Private Key in hexadecimal and encrypted cipher text and function returns sucess status in boolean form
//0 is for fail and 1 for sucessfull signing

function do_unSignCrypt(r, s, SenderPublicKey, RecieverPrivateKey, cipher)
{
	
	 var c = getSECCurveByName("secp160r1");
	 var PublicKey = decodepublickeyhex(SenderPublicKey);
	 var Privatekey = new BigInteger(RecieverPrivateKey,16);
	 var G = c.getG();
	 var n = c.getN();
	
	 sx = new BigInteger();
	 rx = new BigInteger();
	 Gs = new BigInteger();
	 rPA = new BigInteger();
	 QPoint = new BigInteger();
	 Qx = new BigInteger();

	  rx= r.multiply(Privatekey);
	  sx= s.multiply(Privatekey);
	  Gs = G.multiply(sx);
	  rPA = PublicKey.multiply(rx);
	  QPoint = Gs.add(rPA);
	  
	  
      var  Qx= QPoint.getX().toBigInteger().toString();
      var Hash = CryptoJS.SHA256(Qx.toString());
      var QxHash=new Array();
      QxHash =Hash.toString(CryptoJS.enc.Latin1);
	  
      var QxLen = QxHash.length / 2;
      var mu = [QxLen];
	  var v =  [QxLen];
	  
	  for (var i = 0; i < QxLen; i++) {
			 mu[i] = QxHash[i];
			 v[i] = QxHash[mu.length + i];
		}

	  var muHMAC = BigInteger.ZERO;
	  var key = new BigInteger(mu);
 	  var plain = CryptoJS.AES.decrypt(cipher, v.toString(), { key: key }); 
 	  var plaintext= plain.toString(CryptoJS.enc.Latin1);
 	
	  var rhash=CryptoJS.HmacSHA256(plaintext, key.toString());	
	  var rhs= new BigInteger(rhash.toString(), 10);
	  muHMAC = rhs.mod(n);
	  
	 var sucess = false;
	 sucess=(muHMAC.equals(r));
	 return sucess;
	
	}
	