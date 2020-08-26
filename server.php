#!/usr/bin/php
<?php

const TEXT = 0x1;
const BINARY = 0x2;
const CLOSE = 0x8;
const PING = 0x9;
const PONG = 0xa;
const HOST = 'localhost';
const PORT = 8080;
const SSL = false;
const CERT = '/cert.pem';
const PASS = 'Smokey';


if (SSL) {
    /* This snippet would be used to generate your own pem file for the secure wss:// protocal
    
    $certPath = '/key.pem';
    $pemPassPhrase = 'fdsafsa';

    $certificateData = [
        'countryName' => 'US',
        'stateOrProvinceName' => 'TX',
        'localityName' => 'DALLAS',
        'organizationName' => 'Miles Systems LLC',
        'organizationalUnitName' => 'Miles Systems',
        'commonName' => 'Dick',
        'emailAddress' => 'Richard@Miles.Systems'
    ];

    $privateKey = openssl_pkey_new();
    $certificate = openssl_csr_new($certificateData, $privateKey);
    $certificate = openssl_csr_sign($certificate, null, $privateKey, 365);

    $pem = [];
    openssl_x509_export($certificate, $pem[0]);
    openssl_pkey_export($privateKey, $pem[1], $pemPassPhrase);
    $pem = implode($pem);

    file_put_contents($certPath, $pem);
    */
    $context = stream_context_create([
        'ssl' => [
            'local_cert' => CERT,
            'passphrase' => PASS,
            'verify_peer' => false,
            'verify_peer_name' => false,
            'allow_self_signed' => true,
            'verify_depth' => 0
        ]
    ]);

    $protocol = 'ssl';
} else {
    $context = stream_context_create();
    $protocol = 'tcp';
}

$socket = stream_socket_server("$protocol://".HOST.':'.PORT, $errorNumber, $errorString, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, $context);

if (!$socket) {
    echo "$errorString ($errorNumber)<br />\n";
} else {
    $master[] = $socket;
    while (true) {
        $read = $master;

        $mod_fd = stream_select($read, $_w , $_e , 5);  // returns number of file descriptors modified

        if ($mod_fd === 0) {
            continue;
        }
        foreach ($read as $connection) {

            if ($connection === $socket) { // accepting a new connection?

                $conn = @stream_socket_accept($socket);

                if (!handshake($conn)) {
                    fclose($conn);
                } else {
                    fwrite($conn, encode('Hello! The time is ' . date('n/j/Y g:i a') . "\n"));
                    $master[] = $conn;
                }

            } else {

                $data = decode($connection);

                # var_dump($data);

                switch ($data['opcode']) {
                    case CLOSE:
                        $key_to_del = array_search($connection, $master, false);
                        @fclose($connection);
                        unset($master[$key_to_del]);
                        break;

                    case PING :
                        @fwrite($connection, encode('', PONG));
                        break;

                    case TEXT:
                        print $data['payload']->name . ', has sent :: ' . $data['payload']->message . PHP_EOL;

                        foreach ($master as $user) {
                            //  connection === $user and continue;  // but we dont hav this optimization on the front end

                            @fwrite($user, encode([
                                'type' => 'usermsg',
                                'name' => $data['payload']->name,
                                'message' => $data['payload']->message,
                                'color' => $data['payload']->color
                            ]));
                        }
                        break;
                    default:
                        break;
                }
            }
        }
    }
}

function handshake($socket): bool
{
    $headers = [];

    $lines = preg_split("/\r\n/", @fread($socket, 4096));

    foreach ($lines as $line) {
        $line = rtrim($line);
        if (preg_match('/\A(\S+): (.*)\z/', $line, $matches)) {
            $headers[$matches[1]] = $matches[2];
        }
    }

    if (!isset($headers['Sec-WebSocket-Key'])) {
        return false;
    }

    $secKey = $headers['Sec-WebSocket-Key'];
    $secAccept = base64_encode(pack('H*', sha1($secKey . '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')));

    $response = "HTTP/1.1 101 Web Socket Protocol Handshake\r\n" .
        "Upgrade: websocket\r\n" .
        "Connection: Upgrade\r\n" .
        "WebSocket-Origin: ".HOST."\r\n" .
        "WebSocket-Location: ws://".HOST.":".PORT."/\r\n".
        "Sec-WebSocket-Accept:$secAccept\r\n\r\n";

    try {
        return fwrite($socket, $response);
    } catch (Exception $e) {
        return false;
    }
}

function encode($message, $opCode = TEXT): string
{
    $rsv1 = 0x0;
    $rsv2 = 0x0;
    $rsv3 = 0x0;

    $message = json_encode($message);

    $length = strlen($message);

    $out = chr((0x1 << 7) | ($rsv1 << 6) | ($rsv2 << 5) | ($rsv3 << 4) | $opCode);

    if (0xffff < $length) {
        $out .= chr(0x7f) . pack('NN', 0, $length);
    } elseif (0x7d < $length) {
        $out .= chr(0x7e) . pack('n', $length);
    } else {
        $out .= chr($length);
    }

    return $out . $message;
}

function decode($socket): array
{
    if (!$socket || !is_resource($socket)) {
        return [
            'opcode' => CLOSE,
            'payload' => ''
        ];
    }

    $out = [];
    $read = @fread($socket, 1);

    if (empty($read)) {
        return [
            'opcode' => CLOSE,
            'payload' => ''
        ];
    }

    $handle = ord($read);
    $out['fin'] = ($handle >> 7) & 0x1;
    $out['rsv1'] = ($handle >> 6) & 0x1;
    $out['rsv2'] = ($handle >> 5) & 0x1;
    $out['rsv3'] = ($handle >> 4) & 0x1;
    $out['opcode'] = $handle & 0xf;

    if (!\in_array($out['opcode'], [TEXT, BINARY, CLOSE, PING, PONG], true)) {
        return [
            'opcode' => '',
            'payload' => '',
            'error' => 'unknown opcode (1003)'
        ];
    }

    $handle = ord(fread($socket, 1));
    $out['mask'] = ($handle >> 7) & 0x1;
    $out['length'] = $handle & 0x7f;
    $length = &$out['length'];

    if ($out['rsv1'] !== 0x0 || $out['rsv2'] !== 0x0 || $out['rsv3'] !== 0x0) {
        return [
            'opcode' => $out['opcode'],
            'payload' => '',
            'error' => 'protocol error (1002)'
        ];
    }

    if ($length === 0) {
        $out['payload'] = '';
        return $out;
    }

    if ($length === 0x7e) {
        $handle = unpack('nl', fread($socket, 2));
        $length = $handle['l'];
    } elseif ($length === 0x7f) {
        $handle = unpack('N*l', fread($socket, 8));
        $length = isset($handle['l2']) ? $handle['l2'] : $length;

        if ($length > 0x7fffffffffffffff) {
            return [
                'opcode' => $out['opcode'],
                'payload' => '',
                'error' => 'content length mismatch'
            ];
        }
    }

    if ($out['mask'] === 0x0) {
        $msg = '';
        $readLength = 0;

        while ($readLength < $length) {
            $toRead = $length - $readLength;
            $msg .= fread($socket, $toRead);

            if ($readLength === strlen($msg)) {
                break;
            }

            $readLength = strlen($msg);
        }

        $out['payload'] = $msg;
        return $out;
    }

    $maskN = array_map('ord', str_split(fread($socket, 4)));
    $maskC = 0;

    $bufferLength = 1024;
    $message = '';

    for ($i = 0; $i < $length; $i += $bufferLength) {
        $buffer = min($bufferLength, $length - $i);
        $handle = fread($socket, $buffer);

        for ($j = 0, $_length = strlen($handle); $j < $_length; ++$j) {
            $handle[$j] = chr(ord($handle[$j]) ^ $maskN[$maskC]);
            $maskC = ($maskC + 1) % 4;
        }

        $message .= $handle;
    }

    $out['payload'] = json_decode($message);
    return $out;
}
