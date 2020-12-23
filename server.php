<?php

require_once __DIR__ . DIRECTORY_SEPARATOR . 'colorCodeTerminal.php';

/**
 * @https://www.php.net/manual/en/reserved.variables.argv.php
 * @link https://www.php.net/manual/en/language.oop5.anonymous.php
 * @var array $argv
 */
new class($argv ??= []) {

    public const TEXT = 0x1;
    public const BINARY = 0x2;
    public const CLOSE = 0x8;
    public const PING = 0x9;
    public const PONG = 0xa;
    public const HOST = '0.0.0.0';
    public const PORT = 8888;
    public static bool $SSL = false;
    public const CERT = '/cert.pem';
    public const PASS = 'Smokey';


    public function __construct(array $argv)
    {
        while (!empty($argv)) {
            switch (strtolower(array_shift($argv))) {
                case '-b':
                case '--buildCertificate':
                    self::buildCertificate();
                    exit(0);
                case '-s':
                case '--ssl':
                    colorCode('ssl');
                    break;
                default:

            }
        }

        if (self::$SSL) {
            $context = stream_context_create(['ssl' => ['local_cert' => self::CERT,
                'passphrase' => self::PASS,
                'verify_peer' => false,
                'verify_peer_name' => false,
                'allow_self_signed' => true,
                'verify_depth' => 0]]);

            $protocol = 'ssl';
        } else {
            $context = stream_context_create();
            $protocol = 'tcp';
        }

        $socket = stream_socket_server("$protocol://" . self::HOST . ':' . self::PORT, $errorNumber, $errorString, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, $context);

        if (!$socket) {
            echo "$errorString ($errorNumber)<br />\n";
        } else {
            $master[] = $socket;
            while (true) {
                $read = $master;

                $mod_fd = stream_select($read, $_w, $_e, 5);  // returns number of file descriptors modified

                if ($mod_fd === 0) {
                    colorCode('There are (' . (count($master)-1) . ') Connected Resources. Waiting for a signal.');
                    continue;
                }

                foreach ($read as $connection) {

                    if ($connection === $socket) { // accepting a new connection?
                        colorCode('Accepting new user connection!');

                        if (($new_user_connection = stream_socket_accept($connection, ini_get('default_socket_timeout'), $peerName)) === false) {
                            colorCode('Failed to accept new user connection!');
                            continue;
                        }

                        if (!self::handshake($new_user_connection)) {
                            if (!is_resource($new_user_connection)) {
                                colorCode( 'Connection no longer active resource.' , 'red');
                            } else {
                                if (!fclose($new_user_connection)) {
                                    colorCode( 'Failed to close resource connection.', 'red');
                                };
                            }
                        } else {
                            fwrite($new_user_connection, self::encode('Hello! The time is ' . date('n/j/Y g:i a') . "\n"));
                            $master[] = $new_user_connection;
                        }
                        continue;
                    }

                    $data = self::decode($connection);

                    switch ($data['opcode']) {
                        default:
                        case self::BINARY:
                        case self::CLOSE:
                            $key_to_del = array_search($connection, $master, false);
                            @fclose($connection);
                            unset($master[$key_to_del]);
                            break;

                        case self::PING :
                            @fwrite($connection, self::encode('', self::PONG));
                            break;

                        case self::TEXT:
                            $PrintPayload = print_r($data['payload'], true);
                            colorCode("The following was received ($PrintPayload)");

                            print $data['payload']['name'] . ', has sent :: ' . $data['payload']['message'] . PHP_EOL;

                            foreach ($master as $user) {
                                //  connection === $user and continue;  // but we dont hav this optimization on the front end
                                @fwrite($user, self::encode([
                                    'type' => 'usermsg',
                                    'name' => $data['payload']['name'],
                                    'message' => $data['payload']['message'],
                                    'color' => $data['payload']['color']
                                ]));
                            }
                            break;
                    }
                }
            }
        }
    }


    public static function handshake($socket): bool
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
            'WebSocket-Origin: ' . self::HOST . "\r\n" .
            'WebSocket-Location: ws://' . self::HOST . ':' . self::PORT . "/\r\n" .  // todo - will this fail?
            "Sec-WebSocket-Accept:$secAccept\r\n\r\n";

        try {
            return fwrite($socket, $response);
        } catch (Exception $e) {
            colorCode('Failed to handshake with client', 'red');
            return false;
        }
    }

    public static function encode($message, $opCode = self::TEXT): string
    {
        $rsv1 = 0x0;
        $rsv2 = 0x0;
        $rsv3 = 0x0;

        $message = json_encode($message, JSON_THROW_ON_ERROR);

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

    public static function decode($socket): array
    {
        if (!$socket || !is_resource($socket)) {
            return [
                'opcode' => self::CLOSE,
                'payload' => ''
            ];
        }

        $out = [];
        $read = @fread($socket, 1);
        
        if (empty($read)) {
            return [
                'opcode' => self::CLOSE,
                'payload' => ''
            ];
        }
        
        
        colorCode("\n\n\n$read\n\n\n", 'blue');
        

        $handle = ord($read);
        $out['fin'] = ($handle >> 7) & 0x1;
        $out['rsv1'] = ($handle >> 6) & 0x1;
        $out['rsv2'] = ($handle >> 5) & 0x1;
        $out['rsv3'] = ($handle >> 4) & 0x1;
        $out['opcode'] = $handle & 0xf;

        if (!\in_array($out['opcode'], [self::TEXT, self::BINARY, self::CLOSE, self::PING, self::PONG], true)) {
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
            $length = $handle['l2'] ?? $length;

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

        // arrays are faster than objects
        
        colorCode("About to Json Decode The Message :: ($message)", 'yellow');
        
        $out['payload'] = json_decode($message, true, 512, JSON_THROW_ON_ERROR);
        return $out;
    }

    public static function buildCertificate(): void
    {
        // This snippet would be used to generate your own pem file for the secure wss:// protocol
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
    }

};

