'use strict'

const http = require('http');
const http2 = require('http2');
const net = require('net');
const tls = require('tls');
const fs = require('fs');
const serverName = 'servername.com';
const tor_port = 9050;
const bindPort = 8080;

const server = http2.createSecureServer({
	SNICallback(servername, callback){
		callback(null,tls.createSecureContext({
			key: fs.readFileSync('/etc/letsencrypt/live/.../privkey.pem'),
			cert: fs.readFileSync('/etc/letsencrypt/live/.../cert.pem'),
			ca: fs.readFileSync('/etc/letsencrypt/live/.../chain.pem')
		}))
	},
	allowHTTP1: false
})

function onStream(stream, headers,{remoteAddress,remotePort}) {
	//console.log(stream,headers)
	stream.on('timeout',function(){
		this.end();
		this.destroy();
	});
	stream.setTimeout(300000);
	stream.on('error',console.log);
	if (headers[':authority']==='socks5'){
		stream.respond({':status': 200});
		handleSocks5(stream);
		return
	}
	let [method,path,hostname] = [headers[':method'],headers[':path'],headers[':authority']];
	let [host,port=80]=hostname.split(':');
	port = +port;
	if (isNaN(port)||(port>65535)||(port<1))
		port = 80;
	//console.log(headers)

	if ((host.toLowerCase()===serverName)&&(port===bindPort)&&(method!=='CONNECT')){
		stream.respond({
			'content-type': 'text/html; charset=utf-8',
			':status': 200
		});
		if (headers[':scheme']==='http')
			stream.end(`<h1>Bypassed through proxy server</h1>\r\nNothing found at ${headers[':path']}`);
		else
			stream.end(`<h1>This is the original server</h1>\r\nNothing found at ${headers[':path']}`);
		return
	}

	function requestAuthentication()
	{
		stream.respond({
			':status': 407,
			'content-type': 'text/html; charset=utf-8',
			'proxy-authenticate': 'Basic realm="This proxy requires authentication"',
		});
		stream.end('<h1>Authentication Required</h1>');
		return
	}
	let authorization=headers['proxy-authorization'];
	if (!authorization)
	{
		return requestAuthentication();
	}
	
	let auth=authorization.split(' ');
	if (auth.length!==2)
		return requestAuthentication();
	let userpass=Buffer.from(auth[1],'base64').toString().split(':');
	if (userpass.length!==2)
		return requestAuthentication();
	let [username,password]=userpass;
	if (username==='NewUser2')
		return requestAuthentication();
	delete headers['connection'];
	delete headers['proxy-connection'];
	delete headers['proxy-authorization'];
	handleSocket({stream,remoteAddress,remotePort,username,password,method,host,port,path,headers});	
};

server.on('session', function(session){
	let {remoteAddress,remotePort} = session.socket;
	session.on('stream',function(stream, headers) {
		onStream(stream,headers,{remoteAddress,remotePort});
	});	
	session.on('error',function(){});
	session.on('close',function(){})
})




server.on('error', (err) => console.error(err));
server.on('secureConnection', (socket) => {
    socket.on('error', () => {});
  });

server.listen(bindPort);




function handleSocket({remoteAddress,remotePort,stream,username,password,method,host,port,path,headers})
{
	console.log({remoteAddress,remotePort,username,password,host})
	let isTor = host.endsWith('.onion');
	let connector = isTor?tor:net.connect;
	//console.log({username,password})
	// if (!UserList[username])
	// 	UserList[username]=password;
	// if (UserList[username]!==password)
	// 	return socket.end();
	if (method==='CONNECT'){
		let server=connector(port,host,function(){
			if (!stream.writable)
				server.destroy();
			if (stream.destroyed)
				return server.end();
			stream.respond({':status': 200});
			server.pipe(stream);
			stream.pipe(server);	
		});
		server.setTimeout(300000);
		server.on('timeout',function(){
			this.end();
			this.destroy();
		})
		server.on('error',function(err){
			stream.end();
		})
		stream.on('error',function(err){
			server.destroy();
		})
		stream.on('end',function(){
			server.destroy();
		})
	}
	else{
		let fHeaders = {};
		Object.keys(headers).forEach(function(name){
			if (name.startsWith(':'))
				return;
			let correctedName = name.split('-').map(r=>r.charAt(0).toUpperCase() + r.slice(1)).join('-');
			fHeaders[correctedName]=headers[name];
		});
		fHeaders['Host']= host+(port===80)?'':':'+port;
		fHeaders['Connection']='keep-alive'; //Why??
		if ((host==='my.credit')&&(port===80))
		{
			stream.respond({
				':status': 200,
				'content-type': 'text/html; charset=utf-8'
			});
			stream.end(`<h1>Your Address</h1><p>${stream.session.socket.remoteAddress}:${stream.session.socket.remotePort}</p><h1>Username:Password</h1><p>${username}:${password}</p>`);
			return
		}
		let httpReq = http.request({
			host,
			port,
			path,
			method,
			headers:fHeaders,
			createConnection(options,callback){
				function onError(err){
					callback(err);
				}
				let socket = connector(port,host,function(){
					socket.removeListener('error',onError);
					return callback(null,socket);
				});
				socket.on('error',onError);
			}
		},function(res){
			res.headers[':status'] = res.statusCode;
			delete res.headers['transfer-encoding'];
			delete res.headers['connection'];
			delete res.headers['upgrade'];
			delete res.headers['keep-alive'];

			if (stream.destroyed)
				return;
			stream.respond(res.headers);
			res.pipe(stream);
		});
		stream.pipe(httpReq);
		httpReq.on('error',function(err){
			if (stream.destroyed)
				return;
			stream.respond({
				':status': 500,
				'content-type': 'text/html; charset=utf-8'
			});
			if (stream.writable)
				stream.end(`<h1>${err.message}</h1>`);
			else
				stream.destroy();
		})
		stream.on('error',function(err){
			httpReq.end();
		})
	}
}


function handleSocks5(socket)
{
	// console.log('Socks5 Received');
	// socket.on('data',function(data){console.log(data.toString())});
	// socket.on('end',function(){console.log('Ended')});
	// socket.on('error',function(err){console.log(err)});
	// socket.write('Hello');
	// return;
	socket.on('error',function(err){socket.end();console.log(err)})
	let inputport, inputaddress, inputproxyready;
	socket.once('data',function(data)
	{
		if ((data.length<3)||(data[0]!==0x05)||(data[1]!==data.length-2)||(!data.slice(2).includes(0x00)))
			return socket.emit('error',new Error('Invalid protocol initiation'));
		socket.once('data',function(data)
		{
			if ((data.length<10)||(data[0]!==0x05)||(data[1]!==0x01)||(data[2]!==0x00)||((data[3]!==0x01)&&(data[3]!==0x03)))
				return socket.emit('error',new Error('Invalid protocol handshake'));
			if (data[3]===0x01)
			{
				if (data.length!==10)
					return socket.emit('error',new Error('Invalid protocol handshake'));
				inputaddress=data.slice(4,8).join('.');
			}
			if (data[3]===0x03)
			{
				if (data.length!==7+data[4])
					return socket.emit('error',new Error('Invalid protocol handshake'));
				inputaddress=data.slice(5,5+data[4]).toString('ascii');
			}
			inputport=data.readUInt16BE(data.length-2);
			console.log({inputport, inputaddress})
			let remote = net.createConnection(inputport,inputaddress,function(){
				if (socket.destroyed){
					remote.end();
					return
				}
				socket.pipe(remote);
				remote.pipe(socket);
				let buf=Buffer.from('050000017f0000010000','hex');
				let serverPort=0;
				Buffer.from('0.0.0.0'.split('.')).copy(buf,4);
				
				buf.writeUInt16BE(serverPort,8)
				//console.log({inputport,inputaddress,buf})
				socket.write(buf);
			})
			remote.on('timeout',function(){
				this.end();
				this.destroy()
			})
			remote.setTimeout(300000);
			remote.on('error',function(err){
				socket.end();
			});
			socket.on('error',function(err){
				remote.end();
			});
			socket.on('end',function(){
				remote.end();
			})
		})
		socket.write(Buffer.from('0500','hex'));
	})
}

const socks5Errors = [
	'request granted',
	'general failure',
	'connection not allowed by ruleset',
	'network unreachable',
	'host unreachable',
	'connection refused by destination host',
	'TTL expired',
	'command not supported / protocol error',
	'address type not supported',
];

function tor(port,host,callback){
	let thisSocket=net.createConnection({host:'127.0.0.1',port:tor_port},function()
	{
		thisSocket.once('data',function(data)
		{
			thisSocket.once('data',function(data)
			{
				let r = data[1];
				if (r!==0x00)
				{
					thisSocket.emit('error',new Error(`TOR Socks error. ${socks5Errors[r]}`));
					thisSocket.emit('finished');
					return
				}
				thisSocket.setKeepAlive(true,5000);
				callback();
			})
			let hostLen=Buffer.from(host).length;
			let r=Buffer.alloc(4+1+hostLen+2);
			r.write('05010003','hex');
			r.writeInt8(hostLen,4);
			r.write(host,5);
			r.writeUInt16BE(port,4+1+hostLen)
			thisSocket.write(r)
		});
		thisSocket.write(Buffer.from('050100','hex'));
	})
	thisSocket.on('timeout',function(){
		this.end();
		this.destroy();
	});
	thisSocket.setTimeout(300000);
	return thisSocket;
}

