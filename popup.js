var REGISTERED = {}
var currenturl=""
var videourl = ""
var isvideo=false
var tweet;
var hexcase = 0; 
var b64pad  = ""; 
var chrsz   = 8; 
function rol(num, cnt)
{
  return (num << cnt) | (num >>> (32 - cnt));
}
function sha1_ft(t, b, c, d)
{
  if(t < 20) return (b & c) | ((~b) & d);
  if(t < 40) return b ^ c ^ d;
  if(t < 60) return (b & c) | (b & d) | (c & d);
  return b ^ c ^ d;
}
function sha1_kt(t)
{
  return (t < 20) ?  1518500249 : (t < 40) ?  1859775393 :
         (t < 60) ? -1894007588 : -899497514;
}
function safe_add(x, y)
{
  var lsw = (x & 0xFFFF) + (y & 0xFFFF);
  var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
  return (msw << 16) | (lsw & 0xFFFF);
}
function core_sha1(x, len)
{

  x[len >> 5] |= 0x80 << (24 - len % 32);
  x[((len + 64 >> 9) << 4) + 15] = len;

  var w = Array(80);
  var a =  1732584193;
  var b = -271733879;
  var c = -1732584194;
  var d =  271733878;
  var e = -1009589776;

  for(var i = 0; i < x.length; i += 16)
  {
    var olda = a;
    var oldb = b;
    var oldc = c;
    var oldd = d;
    var olde = e;

    for(var j = 0; j < 80; j++)
    {
      if(j < 16) w[j] = x[i + j];
      else w[j] = rol(w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16], 1);
      var t = safe_add(safe_add(rol(a, 5), sha1_ft(j, b, c, d)),
                       safe_add(safe_add(e, w[j]), sha1_kt(j)));
      e = d;
      d = c;
      c = rol(b, 30);
      b = a;
      a = t;
    }

    a = safe_add(a, olda);
    b = safe_add(b, oldb);
    c = safe_add(c, oldc);
    d = safe_add(d, oldd);
    e = safe_add(e, olde);
  }
  return Array(a, b, c, d, e);

}
function str2binb(str)
{
  var bin = Array();
  var mask = (1 << chrsz) - 1;
  for(var i = 0; i < str.length * chrsz; i += chrsz)
    bin[i>>5] |= (str.charCodeAt(i / chrsz) & mask) << (32 - chrsz - i%32);
  return bin;
}
function core_hmac_sha1(key, data)
{
  var bkey = str2binb(key);
  if(bkey.length > 16) bkey = core_sha1(bkey, key.length * chrsz);

  var ipad = Array(16), opad = Array(16);
  for(var i = 0; i < 16; i++)
  {
    ipad[i] = bkey[i] ^ 0x36363636;
    opad[i] = bkey[i] ^ 0x5C5C5C5C;
  }

  var hash = core_sha1(ipad.concat(str2binb(data)), 512 + data.length * chrsz);
  return core_sha1(opad.concat(hash), 512 + 160);
}
function binb2b64(binarray)
{
  var tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  var str = "";
  for(var i = 0; i < binarray.length * 4; i += 3)
  {
    var triplet = (((binarray[i   >> 2] >> 8 * (3 -  i   %4)) & 0xFF) << 16)
                | (((binarray[i+1 >> 2] >> 8 * (3 - (i+1)%4)) & 0xFF) << 8 )
                |  ((binarray[i+2 >> 2] >> 8 * (3 - (i+2)%4)) & 0xFF);
    for(var j = 0; j < 4; j++)
    {
      if(i * 8 + j * 6 > binarray.length * 32) str += b64pad;
      else str += tab.charAt((triplet >> 6*(3-j)) & 0x3F);
    }
  }
  return str;
}
function b64_hmac_sha1(key, data){ return binb2b64(core_hmac_sha1(key, data));}

var exports; if (exports == null) exports = {};

exports.setProperties = function setProperties(into, from) {
    if (into != null && from != null) {
        for (var key in from) {
            into[key] = from[key];
        }
    }
    return into;
}

exports.setProperties(exports, 
{
    percentEncode: function percentEncode(s) {
        if (s == null) {
            return "";
        }
        if (s instanceof Array) {
            var e = "";
            for (var i = 0; i < s.length; ++s) {
                if (e != "") e += '&';
                e += exports.percentEncode(s[i]);
            }
            return e;
        }
        s = encodeURIComponent(s);
        s = s.replace(/\!/g, "%21");
        s = s.replace(/\*/g, "%2A");
        s = s.replace(/\'/g, "%27");
        s = s.replace(/\(/g, "%28");
        s = s.replace(/\)/g, "%29");
        return s;
    }
,
    decodePercent: function decodePercent(s) {
        if (s != null) {
            s = s.replace(/\+/g, " ");
        }
        return decodeURIComponent(s);
    }
,
    getParameterList: function getParameterList(parameters) {
        if (parameters == null) {
            return [];
        }
        if (typeof parameters != "object") {
            return exports.decodeForm(parameters + "");
        }
        if (parameters instanceof Array) {
            return parameters;
        }
        var list = [];
        for (var p in parameters) {
            list.push([p, parameters[p]]);
        }
        return list;
    }
,
    getParameterMap: function getParameterMap(parameters) {
        if (parameters == null) {
            return {};
        }
        if (typeof parameters != "object") {
            return exports.getParameterMap(exports.decodeForm(parameters + ""));
        }
        if (parameters instanceof Array) {
            var map = {};
            for (var p = 0; p < parameters.length; ++p) {
                var key = parameters[p][0];
                if (map[key] === undefined) { // first value wins
                    map[key] = parameters[p][1];
                }
            }
            return map;
        }
        return parameters;
    }
,
    getParameter: function getParameter(parameters, name) {
        if (parameters instanceof Array) {
            for (var p = 0; p < parameters.length; ++p) {
                if (parameters[p][0] == name) {
                    return parameters[p][1];
                }
            }
        } else {
            return exports.getParameterMap(parameters)[name];
        }
        return null;
    }
,
    formEncode: function formEncode(parameters) {
        var form = "";
        var list = exports.getParameterList(parameters);
        for (var p = 0; p < list.length; ++p) {
            var value = list[p][1];
            if (value == null) value = "";
            if (form != "") form += '&';
            form += exports.percentEncode(list[p][0])
              +'='+ exports.percentEncode(value);
        }
        return form;
    }
,
    decodeForm: function decodeForm(form) {
        var list = [];
        var nvps = form.split('&');
        for (var n = 0; n < nvps.length; ++n) {
            var nvp = nvps[n];
            if (nvp == "") {
                continue;
            }
            var equals = nvp.indexOf('=');
            var name;
            var value;
            if (equals < 0) {
                name = exports.decodePercent(nvp);
                value = null;
            } else {
                name = exports.decodePercent(nvp.substring(0, equals));
                value = exports.decodePercent(nvp.substring(equals + 1));
            }
            list.push([name, value]);
        }
        return list;
    }
,
    setParameter: function setParameter(message, name, value) {
        var parameters = message.parameters;
        if (parameters instanceof Array) {
            for (var p = 0; p < parameters.length; ++p) {
                if (parameters[p][0] == name) {
                    if (value === undefined) {
                        parameters.splice(p, 1);
                    } else {
                        parameters[p][1] = value;
                        value = undefined;
                    }
                }
            }
            if (value !== undefined) {
                parameters.push([name, value]);
            }
        } else {
            parameters = exports.getParameterMap(parameters);
            parameters[name] = value;
            message.parameters = parameters;
        }
    }
,
    setParameters: function setParameters(message, parameters) {
        var list = exports.getParameterList(parameters);
        for (var i = 0; i < list.length; ++i) {
            exports.setParameter(message, list[i][0], list[i][1]);
        }
    }
,
    completeRequest: function completeRequest(message, accessor) {
        if (message.method == null) {
            message.method = "GET";
        }
        var map = exports.getParameterMap(message.parameters);
        if (map.oauth_consumer_key == null) {
            exports.setParameter(message, "oauth_consumer_key", accessor.consumerKey || "");
        }
        if (map.oauth_token == null && accessor.token != null) {
            exports.setParameter(message, "oauth_token", accessor.token);
        }
        if (map.oauth_version == null) {
            exports.setParameter(message, "oauth_version", "1.0");
        }
        if (map.oauth_timestamp == null) {
            exports.setParameter(message, "oauth_timestamp", exports.timestamp());
        }
        if (map.oauth_nonce == null) {
            exports.setParameter(message, "oauth_nonce", exports.nonce(6));
        }
        exports.SignatureMethod.sign(message, accessor);
    }
,
    setTimestampAndNonce: function setTimestampAndNonce(message) {
        exports.setParameter(message, "oauth_timestamp", exports.timestamp());
        exports.setParameter(message, "oauth_nonce", exports.nonce(6));
    }
,
    addToURL: function addToURL(url, parameters) {
        newURL = url;
        if (parameters != null) {
            var toAdd = exports.formEncode(parameters);
            if (toAdd.length > 0) {
                var q = url.indexOf('?');
                if (q < 0) newURL += '?';
                else       newURL += '&';
                newURL += toAdd;
            }
        }
        return newURL;
    }
,

    getAuthorizationHeader: function getAuthorizationHeader(realm, parameters) {
        var header = 'exports realm="' + exports.percentEncode(realm) + '"';
        var list = exports.getParameterList(parameters);
        for (var p = 0; p < list.length; ++p) {
            var parameter = list[p];
            var name = parameter[0];
            if (name.indexOf("oauth_") == 0) {
                header += ',' + exports.percentEncode(name) + '="' + exports.percentEncode(parameter[1]) + '"';
            }
        }
        return header;
    }
,
    correctTimestampFromSrc: function correctTimestampFromSrc(parameterName) {
        parameterName = parameterName || "oauth_timestamp";
        var scripts = document.getElementsByTagName('script');
        if (scripts == null || !scripts.length) return;
        var src = scripts[scripts.length-1].src;
        if (!src) return;
        var q = src.indexOf("?");
        if (q < 0) return;
        parameters = exports.getParameterMap(exports.decodeForm(src.substring(q+1)));
        var t = parameters[parameterName];
        if (t == null) return;
        exports.correctTimestamp(t);
    }
,

    correctTimestamp: function correctTimestamp(timestamp) {
        exports.timeCorrectionMsec = (timestamp * 1000) - (new Date()).getTime();
    }
,

    timeCorrectionMsec: 0
,
    timestamp: function timestamp() {
        var t = (new Date()).getTime() + exports.timeCorrectionMsec;
        return Math.floor(t / 1000);
    }
,
    nonce: function nonce(length) {
        var chars = exports.nonce.CHARS;
        var result = "";
        for (var i = 0; i < length; ++i) {
            var rnum = Math.floor(Math.random() * chars.length);
            result += chars.substring(rnum, rnum+1);
        }
        return result;
    }
});

exports.nonce.CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXTZabcdefghiklmnopqrstuvwxyz";


exports.declareClass = function declareClass(parent, name, newConstructor) {
    var previous = parent[name];
    parent[name] = newConstructor;
    if (newConstructor != null && previous != null) {
        for (var key in previous) {
            if (key != "prototype") {
                newConstructor[key] = previous[key];
            }
        }
    }
    return newConstructor;
}


exports.declareClass(exports, "SignatureMethod", function exportsSignatureMethod(){});

exports.setProperties(exports.SignatureMethod.prototype, 
{

    sign: function sign(message) {
        var baseString = exports.SignatureMethod.getBaseString(message);
        var signature = this.getSignature(baseString);
        exports.setParameter(message, "oauth_signature", signature);
        return signature; 
    }
,

    initialize: function initialize(name, accessor) {
        var consumerSecret;
        if (accessor.accessorSecret != null
            && name.length > 9
            && name.substring(name.length-9) == "-Accessor")
        {
            consumerSecret = accessor.accessorSecret;
        } else {
            consumerSecret = accessor.consumerSecret;
        }
        this.key = exports.percentEncode(consumerSecret)
             +"&"+ exports.percentEncode(accessor.tokenSecret);
    }
});


exports.setProperties(exports.SignatureMethod, 
    sign: function sign(message, accessor) {
        var name = exports.getParameterMap(message.parameters).oauth_signature_method;
        if (name == null || name == "") {
            name = "HMAC-SHA1";
            exports.setParameter(message, "oauth_signature_method", name);
        }
        exports.SignatureMethod.newMethod(name, accessor).sign(message);
    }
,

    newMethod: function newMethod(name, accessor) {
        var impl = exports.SignatureMethod.REGISTERED[name];
        if (impl != null) {
            var method = new impl();
            method.initialize(name, accessor);
            return method;
        }
        var err = new Error("signature_method_rejected");
        var acceptable = "";
        for (var r in exports.SignatureMethod.REGISTERED) {
            if (acceptable != "") acceptable += '&';
            acceptable += exports.percentEncode(r);
        }
        err.oauth_acceptable_signature_methods = acceptable;
        throw err;
    }
,
    REGISTERED : {}
,
    registerMethodClass: function registerMethodClass(names, classConstructor) {
        for (var n = 0; n < names.length; ++n) {
            exports.SignatureMethod.REGISTERED[names[n]] = classConstructor;
        }
    }
,

    makeSubclass: function makeSubclass(getSignatureFunction) {
        var superClass = exports.SignatureMethod;
        var subClass = function() {
            superClass.call(this);
        };
        subClass.prototype = new superClass();
        subClass.prototype.getSignature = getSignatureFunction;
        subClass.prototype.constructor = subClass;
        return subClass;
    }
,
    getBaseString: function getBaseString(message) {
        var URL = message.action;
        var q = URL.indexOf('?');
        var parameters;
        if (q < 0) {
            parameters = message.parameters;
        } else {
            parameters = exports.decodeForm(URL.substring(q + 1));
            var toAdd = exports.getParameterList(message.parameters);
            for (var a = 0; a < toAdd.length; ++a) {
                parameters.push(toAdd[a]);
            }
        }
        return exports.percentEncode(message.method.toUpperCase())
         +'&'+ exports.percentEncode(exports.SignatureMethod.normalizeUrl(URL))
         +'&'+ exports.percentEncode(exports.SignatureMethod.normalizeParameters(parameters));
    }
,
    normalizeUrl: function normalizeUrl(url) {
        var uri = exports.SignatureMethod.parseUri(url);
        var scheme = uri.protocol.toLowerCase();
        var authority = uri.authority.toLowerCase();
        var dropPort = (scheme == "http" && uri.port == 80)
                    || (scheme == "https" && uri.port == 443);
        if (dropPort) {
            var index = authority.lastIndexOf(":");
            if (index >= 0) {
                authority = authority.substring(0, index);
            }
        }
        var path = uri.path;
        if (!path) {
            path = "/"; 
        }
        return scheme + "://" + authority + path;
    }
,
    parseUri: function parseUri (str) {

        var o = {key: ["source","protocol","authority","userInfo","user","password","host","port","relative","path","directory","file","query","anchor"],
                 parser: {strict: /^(?:([^:\/?#]+):)?(?:\/\/((?:(([^:@\/]*):?([^:@\/]*))?@)?([^:\/?#]*)(?::(\d*))?))?((((?:[^?#\/]*\/)*)([^?#]*))(?:\?([^#]*))?(?:#(.*))?)/ }};
        var m = o.parser.strict.exec(str);
        var uri = {};
        var i = 14;
        while (i--) uri[o.key[i]] = m[i] || "";
        return uri;
    }
,
    normalizeParameters: function normalizeParameters(parameters) {
        if (parameters == null) {
            return "";
        }
        var list = exports.getParameterList(parameters);
        var sortable = [];
        for (var p = 0; p < list.length; ++p) {
            var nvp = list[p];
            if (nvp[0] != "oauth_signature") {
                sortable.push([ exports.percentEncode(nvp[0])
                              + exports.percentEncode(nvp[1])
                              , nvp]);
            }
        }
        sortable.sort(function(a,b) {
                          if (a[0] < b[0]) return  -1;
                          if (a[0] > b[0]) return 1;
                          return 0;
                      });
        var sorted = [];
        for (var s = 0; s < sortable.length; ++s) {
            sorted.push(sortable[s][1]);
        }
        return exports.formEncode(sorted);
    }
});

exports.SignatureMethod.registerMethodClass(["PLAINTEXT", "PLAINTEXT-Accessor"],
    exports.SignatureMethod.makeSubclass(
        function getSignature(baseString) {
            return this.key;
        }
    ));

exports.SignatureMethod.registerMethodClass(["HMAC-SHA1", "HMAC-SHA1-Accessor"],
    exports.SignatureMethod.makeSubclass(
        function getSignature(baseString) {
            b64pad = '=';
            console.log("Key: "+this.key);
            console.log("BaseString: "+baseString);
            var signature = b64_hmac_sha1(this.key, baseString);
            return signature;
        }
    ));
var rxlook = /^https?:\/\/twitter\.com\/(?:#!\/)?(\w+)\/status(es)?\/(\d+)/
document.addEventListener('DOMContentLoaded',function(){
  var links = document.getElementsByTagName("a");
  links[0].onclick = function(){chrome.tabs.create({url:links[0].href})}  
  chrome.tabs.query({'active': true, 'lastFocusedWindow': true}, function (tabs) {
        currenturl = tabs[0].url;
        if(rxlook.test(currenturl) == true)
        {
            document.getElementById("dwnbutton").innerHTML = "Download";

            var id = currenturl.substring(currenturl.lastIndexOf('/')+1,currenturl.length  );
            console.log(currenturl)
            console.log(id)
            var urlLink = 'https://api.twitter.com/1.1/statuses/show.json?id='+id+"&include_entities=true";
            var oauth_consumer_key = "";
            var consumerSecret = "";

            var oauth_token = "";
            var tokenSecret = "";

            var nonce = noncey(32);
            var ts = Math.floor(new Date().getTime() / 1000);
            var timestamp = ts.toString();

            var accessor = {
                "consumerSecret": consumerSecret,
                "tokenSecret": tokenSecret
            };

            var params = {
                "oauth_consumer_key": oauth_consumer_key,
                "oauth_nonce": nonce,
                "oauth_signature_method": "HMAC-SHA1",
                "oauth_timestamp": timestamp,
                "oauth_token": oauth_token,
                "oauth_version": "1.0"
            };
            var message = {
                "method": "GET",
                "action": urlLink,
                "parameters": params
            };
            
            exports.SignatureMethod.sign(message, accessor);
            var normPar = exports.SignatureMethod.normalizeParameters(message.parameters);
            var baseString = exports.SignatureMethod.getBaseString(message);
            var sig = exports.getParameter(message.parameters, "oauth_signature") + "=";
            var encodedSig = exports.percentEncode(sig);
            console.log(encodedSig)
            $.ajax({
                url: urlLink,
                type: 'GET',
                data: {
                   
                },
                beforeSend: function(xhr){
                    xhr.setRequestHeader("Authorization",'OAuth oauth_consumer_key="'+oauth_consumer_key+'",oauth_signature_method="HMAC-SHA1",oauth_timestamp="' + timestamp + '",oauth_nonce="' + nonce + '",oauth_version="1.0",oauth_token="'+oauth_token+'",oauth_signature="' + encodedSig + '"');  
               },
               success: function(data) { 
                    
                    console.log(data);
                    tweet = data;
                    
                    var maxbitrate = 0;
                    if(tweet.extended_entities != null)
                    {
                        tweet.extended_entities.media.forEach(element => {
                            console.log(element)
                            if(element.type == "video")
                            {
                            isvideo = true;
                            element.video_info.variants.forEach(variant => {
                                console.log(variant)
                                if(variant.content_type == "video/mp4")
                                {
                                    if(parseInt(variant.bitrate)>maxbitrate)
                                    {
                                        videourl=variant.url;
                                        maxbitrate=variant.bitrate;
                                        
                                        document.getElementById("dwnbutton").innerHTML = "Download";
                                    }
                                }
                            });
                            }
                        });
                        if(isvideo==false)
                        {
                            document.getElementById("dwnbutton").disabled = true;
                            document.getElementById("dwnbutton").innerHTML = "No Twitter Video";
                        }
                    }
                    else
                    {
                        document.getElementById("dwnbutton").disabled = true;
                        document.getElementById("dwnbutton").innerHTML = "No Twitter Video";
                    }
               },
               error:function(exception){
                   console.log("Exeption:"+exception.text);
                }
              });

                }
        else
        {
            document.getElementById("dwnbutton").disabled = true;
            document.getElementById("dwnbutton").innerHTML = "No Twitter Video";
        }
    });

})
document.getElementById('dwnbutton').addEventListener('click', function(e) {
    chrome.tabs.create({
        url: videourl
   });
});
