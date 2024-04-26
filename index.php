<?php

session_start();

if (!(str_contains($_SERVER['HTTP_CONNECTION'] ?? '', 'Upgrade')
    && str_contains($_SERVER['HTTP_UPGRADE'] ?? '', 'websocket'))) {

    include 'console.html';

    exit(0);

}


/**
 * @https://www.php.net/manual/en/reserved.variables.argv.php
 * @link https://www.php.net/manual/en/language.oop5.anonymous.php
 * @var array $argv
 */
new class($argv ??= []) {


    public const int CONTINUE = 0x0;
    public const int TEXT = 0x1;
    public const int BINARY = 0x2;
    public const int CLOSE = 0x8;
    public const int PING = 0x9;
    public const int PONG = 0xa;

    public const string HOST = '0.0.0.0';
    public const int PORT = 8888;
    public static bool $SSL = false;
    public const string CERT = '/cert.pem';
    public const string PASS = 'Smokey';


    public function __construct(array $argv)
    {

        if (PHP_SAPI !== 'cli'
            && str_contains($_SERVER['HTTP_CONNECTION'] ?? '', 'Upgrade')
            && str_contains($_SERVER['HTTP_UPGRADE'] ?? '', 'websocket')) {

            // Here you can handle the WebSocket upgrade logic
            self::handleSingleUserConnections();

        }

        while (!empty($argv)) {
            switch (strtolower(array_shift($argv))) {
                case '-b':
                case '--buildCertificate':
                    self::buildCertificate();
                    exit(0);
                case '-s':
                case '--ssl':
                    self::colorCode('ssl');
                    break;
                default:

            }
        }

        if (self::$SSL) {

            $context = stream_context_create([
                'ssl' => [
                    'local_cert' => self::CERT,
                    'passphrase' => self::PASS,
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

        $socket = stream_socket_server("$protocol://" . self::HOST . ':' . self::PORT, $errorNumber, $errorString, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, $context);

        if (!$socket) {
            echo "$errorString ($errorNumber)<br />\n";
        } else {
            $master[] = $socket;
            while (true) {
                $read = $master;

                $mod_fd = stream_select($read, $_w, $_e, 5);  // returns number of file descriptors modified

                if ($mod_fd === 0) {
                    self::colorCode('There are (' . (count($master) - 1) . ') Connected Resources. Waiting for a signal.');
                    continue;
                }

                foreach ($read as $connection) {

                    if ($connection === $socket) { // accepting a new connection?
                        self::colorCode('Accepting new user connection!');

                        if (($new_user_connection = stream_socket_accept($connection, ini_get('default_socket_timeout'), $peerName)) === false) {
                            self::colorCode('Failed to accept new user connection!');
                            continue;
                        }

                        if (!self::handshake($new_user_connection)) {
                            if (!is_resource($new_user_connection)) {
                                self::colorCode('Connection no longer active resource.', self::RED);
                            } else {
                                if (!fclose($new_user_connection)) {
                                    self::colorCode('Failed to close resource connection.', self::RED);
                                }
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
                        case self::CLOSE:
                            $key_to_del = array_search($connection, $master, false);
                            @fclose($connection);
                            unset($master[$key_to_del]);
                            break;

                        case self::PING :
                            @fwrite($connection, self::encode('', self::PONG));
                            break;
                        case self::BINARY:
                        case self::TEXT:
                            $PrintPayload = print_r($data['payload'], true);
                            self::colorCode("The following was received ($PrintPayload)", self::MAGENTA);

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

    public static function clearAllOutputBuffers()
    {
        // @note - https://www.php.net/manual/en/function.ob-get-level.php comments
        // my error handler is set to stop at 1, but here I believe clearing all is the only way.
        // Php may start with an output buffer enabled but we need to clear that to in oder to send real time data.
        while (ob_get_level() > 0) {

            self::colorCode("Clearing Output Buffer Level: " . ob_get_level(), self::BACKGROUND_YELLOW);

            ob_end_clean();

        }
    }

    public static function outputBufferWebSocketEncoder(): callable
    {
        self::clearAllOutputBuffers();

        ob_start(new class(self::class) {

            public static mixed $that;

            public function __construct($that)
            {
                self::$that = $that;
            }

            public function __invoke($part, $flag): string
            {
                $flag_sent = match ($flag) {
                    PHP_OUTPUT_HANDLER_START => "PHP_OUTPUT_HANDLER_START ($flag)",
                    PHP_OUTPUT_HANDLER_CONT => "PHP_OUTPUT_HANDLER_CONT ($flag)",
                    PHP_OUTPUT_HANDLER_END => "PHP_OUTPUT_HANDLER_END ($flag)",
                    9 => "ob_get_flush ($flag)",
                    default => "Flag is not a constant ($flag)",
                };

                self::$that::colorCode("Output Handler Flag: $flag_sent");

                return self::$that::encode($part . PHP_EOL);
            }

            public function __destruct()
            {
                self::$that::colorCode("Ending WebSocket Encoding Buffer.");
            }
        });

        ob_implicit_flush();

        // these function calls are dynamic to whatever the current buffer is.
        return static function (): void {
            if (ob_get_level() === 0) {
                self::outputBufferWebSocketEncoder();
                return;
            }
            if (0 === ob_get_length()) {
                return;
            }
            // this will also remove the buffer, but IS NEEDED.
            // ob_flush will not guarantee the buffer runs through the ob_start callback.
            if (!ob_get_flush()) {
                throw new Error('Failed to flush the output buffer.');
            }
            // my first thought was to return this method call, but it is not needed.
            self::outputBufferWebSocketEncoder();
        };

    }

    public static function handleSingleUserConnections(): void
    {

        if (!defined('STDOUT')) {

            define('STDOUT', fopen('php://stdout', 'wb'));

        }

        // get all headers has a polyfill in our function.php
        $headers = getallheaders();

        // Now we start the buffer and write to it using standard io (print, echo, print_r,..) and encode it as one block until we flush it.
        $flush = self::outputBufferWebSocketEncoder();

        self::handshake(STDOUT, $headers);

        self::colorCode('Handshake complete, starting WebSocket server.');

        print posix_getpid() . PHP_EOL;

        $flush();

        // Here you can handle the WebSocket upgrade logic
        /** @noinspection PhpUndefinedFunctionInspection  - Proposed RFC */
        $websocket = apache_connection_stream();

        stream_set_blocking($websocket, false);

        if (!is_resource($websocket)) {

            throw new Error('INPUT is not a valid resource');

        }

        $myFifo = self::namedPipe();

        $loop = 0;

        while (true) {

            self::colorCode("Loop: $loop");

            try {

                ++$loop;

                print "Loop: $loop\n";

                $flush();

                sleep(1);

                if (!is_resource($websocket)) {

                    throw new Error('STDIN is not a valid resource');

                }

                $flush();

                $read = [$websocket, $myFifo];

                // 3 should be set to a reasonably high value for your application, lower is better for debugging
                $number = stream_select($read, $write, $error, 3);

                if ($number === 0) {

                    self::colorCode("No streams are requesting to be processed. (loop: $loop )", self::CYAN);

                    continue;

                }

                self::colorCode("$number, stream(s) are requesting to be processed.");

                foreach ($read as $connection) {

                    switch ($connection) {
                        case $websocket:
                            $data = self::decode($connection);
                            switch ($data['opcode']) {
                                default:
                                case self::BINARY:
                                case self::CLOSE:
                                    exit(0);

                                case self::PING :
                                    @fwrite($connection, self::encode('', self::PONG));
                                    break;

                                case self::TEXT:
                                    $PrintPayload = print_r($data['payload'], true);

                                    self::colorCode("The following was received ($PrintPayload)");

                                    print $data['payload']['name'] . ', has sent :: ' . $data['payload']['message'] . PHP_EOL;

                                    $flush();

                                    if (!is_string($data)) {
                                        $data = json_encode($data, JSON_THROW_ON_ERROR) . PHP_EOL;
                                        print $data;
                                        $flush();
                                    }

                                    self::sendToEveryone($data);

                                    $flush();

                                    break;
                            }


                            break;
                        case $myFifo:
                            // Read from the FIFO until the buffer is empty
                            $data = fread($myFifo, 4096); // Read up to 4096 bytes at a time
                            echo $data;
                            $flush();
                            break;
                        default:
                            print('Unknown read connection!');
                            exit(1);
                    }

                }

            } catch (Throwable $e) {

                self::colorCode(print_r($e, true), self::BACKGROUND_RED);

            }

        }

    }

    public static function handshake($socket, array &$headers = []): bool
    {
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

        // in the spirit of using actual header values
        // @link https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers
        // well use warning to store general information
        $headers['Warning'] = $lines[0] ?? '';

        $_SERVER['HTTP_COOKIE'] = $headers['Cookie'] ?? [];

        $_SERVER['User_Agent'] = $headers['User-Agent'] ?? '';

        $_SERVER['Host'] = $headers['Host'] ?? '';

        $secKey = $headers['Sec-WebSocket-Key'];

        $secAccept = base64_encode(pack('H*', sha1($secKey . '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')));

        $response = [
            "HTTP/1.1 101 Web Socket Protocol Handshake",
            "Upgrade: websocket",
            "Connection: Upgrade",
            'WebSocket-Origin: ' . $_SERVER['Host'],
            'WebSocket-Location: ws://' . $_SERVER['Host'] . ':' . $_SERVER['SERVER_PORT'] . '/',
            "Sec-WebSocket-Accept:$secAccept",
            // These next two lines are not spec, but through much research and trial and error
            // You can turn off chunked encoding by setting the content length to 0 and application/octet-stream
            "Content-Length: 0",
            "Content-Type: application/octet-stream",
        ];

        try {


            if (STDOUT === $socket) {

                foreach ($response as $line) {

                    header($line);

                }

                flush();

                return true;

            }

            $response = implode("\r\n", $response);

            return fwrite($socket, $response . "\r\n");

        } catch (Exception) {

            return false;

        }

    }

    /**
     *  0                   1                   2                   3
     *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     * +-+-+-+-+-------+-+-------------+-------------------------------+
     * |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
     * |I|S|S|S|  (4)  |A|     (7)     |             (16/63)           |
     * |N|V|V|V|       |S|             |   (if payload len==126/127)   |
     * | |1|2|3|       |K|             |                               |
     * +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
     * |     Extended payload length continued, if payload len == 127  |
     * + - - - - - - - - - - - - - - - +-------------------------------+
     * |                               |Masking-key, if MASK set to 1  |
     * +-------------------------------+-------------------------------+
     * | Masking-key (continued)       |          Payload Data         |
     * +-------------------------------- - - - - - - - - - - - - - - - +
     * :                     Payload Data continued ...                :
     * + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
     * |                     Payload Data continued ...                |
     * +---------------------------------------------------------------+
     * See: https://tools.ietf.org/rfc/rfc6455.txt
     * or:  http://tools.ietf.org/html/draft-ietf-hybi-thewebsocketprotocol-10#section-4.2
     **/
    public static function encode($message, $opCode = self::TEXT): string
    {

        $rsv1 = 0x0;

        $rsv2 = 0x0;

        $rsv3 = 0x0;

        $message = is_string($message) ? $message : json_encode($message);

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

    public static function decode($resource): array
    {

        if (!$resource || !is_resource($resource)) {

            return [
                'error' => 'Resource gone away',
                'opcode' => self::CLOSE,
                'payload' => ''
            ];

        }

        $out = [];

        if (get_resource_type($resource) === 'stream') {

            //$read = fread($socketResource, 1);
            // should things be unexpectedly sending with a length of 0 @link https://stackoverflow.com/questions/64855794/proxy-timeout-with-rewriterule
            // @link https://stackoverflow.com/questions/41115870/is-binary-opcode-encoding-and-decoding-implementation-specific-in-websockets
            $read = stream_get_contents($resource, 1);

        } else {

            $read = fread($resource, 1);

        }

        if (false === $read) {

            $socket = self::ensureConvertToSocket($resource);

            return [
                'socketStatus' => stream_get_meta_data($resource),
                'error' => 'socket read failure',
                'socket_last_error' => $code = socket_last_error($socket),
                'socket_strerror' => socket_strerror($code),
                'opcode' => self::CLOSE,
                'payload' => ''
            ];

        }

        if (empty($read)) {

            self::colorCode('Empty WS Read', self::RED);

            $socket = self::ensureConvertToSocket(self::$socket);

            if (empty($socket)) {

                return [
                    'error' => 'Empty socket read, if your proxying this could be a timeout. @link https://stackoverflow.com/questions/64855794/proxy-timeout-with-rewriterule',
                    'opcode' => self::PING,
                    'payload' => ''
                ];
            }

            return [
                'stream_get_meta_data' => stream_get_meta_data($resource),
                'error' => 'empty socket read, if your proxying this could be a timeout. @link https://stackoverflow.com/questions/64855794/proxy-timeout-with-rewriterule',
                'socket_last_error' => $code = socket_last_error($socket),
                'socket_strerror' => socket_strerror($code),
                'opcode' => self::PING,
                'payload' => ''
            ];

        }

        $handle = ord($read);

        //Get the first byte and & it with 127, the result is your FIN bit
        $out['fin'] = ($handle >> 7) & 0x1; // get the 7th bit in the first byte

        $out['rsv1'] = ($handle >> 6) & 0x1; // get the 6th bit in the first byte

        $out['rsv2'] = ($handle >> 5) & 0x1;

        $out['rsv3'] = ($handle >> 4) & 0x1;

        // Get the first byte and & it with 15, the result is your opcode
        $out['opcode'] = $handle & 0xf; // get the last 4 bits in the first byte

        if (self::CLOSE === $out['opcode']) {

            $out['dataframe'] = $handle & 0xff;

        }

        if (!in_array($out['opcode'], [
            self::CONTINUE,
            self::TEXT,
            self::BINARY,
            self::CLOSE,
            self::PING,
            self::PONG
        ], true)) {
            return $out + [
                    'error' => 'unknown opcode (1003)'
                ];
        }

        $handle = ord(fread($resource, 1));

        // Most significant bit of the 2nd byte, tells you if the payload has been masked. A Server must not mask any frame!
        // Get the second byte and & it with 127, if it is 127 you have a masking key
        $out['mask'] = ($handle >> 7) & 0x1;

        // Payload Length (This is where things can get complicated)
        // Take the 2nd byte and read every bit except the Most significant bit
        $out['length'] = $handle & 0x7f;

        // Byte is 125 or fewer that's your length
        $length = &$out['length'];

        if ($out['rsv1'] !== 0x0 || $out['rsv2'] !== 0x0 || $out['rsv3'] !== 0x0) {
            return [
                'opcode' => $out['opcode'],
                'payload' => '',
                'error' => 'protocol error (1002)'
            ];
        }

        // Byte is 126
        // Your length is an uint16 of byte 3 and 4
        if ($length === 0x7e) {

            $handle = unpack('nl', fread($resource, 2));

            $length = $handle['l'];

        } elseif ($length === 0x7f) {
            // Byte is 127
            // Your length is a uint64 of byte 3 to 8

            $handle = unpack('N*l', fread($resource, 8));

            $length = $handle['l2'] ?? $length;

            if ($length > 0x7fffffffffffffff) {

                self::colorCode('WS Length > 0x7fffffffffffffff', self::BACKGROUND_RED);

                return $out + [
                        'payload' => '',
                        'error' => 'content length mismatch'
                    ];

            }

        }

        // Masking key
        // Only exists if the MASK bit is set
        if ($out['mask'] === 0x0) { // (no mask set)

            // Payload can be decoded either as Text (UTF-8) or Binary (Can be any data)
            // The payload needs to be masked if the MASK bit is set

            $msg = '';

            $readLength = 0;

            // This is not the whole payload if the FIN bit is set
            while ($readLength < $length) {

                $toRead = $length - $readLength;

                $msg .= fread($resource, $toRead);

                if ($readLength === strlen($msg)) {

                    break;

                }

                $readLength = strlen($msg);

            }

            $out['payload'] = $msg;

            self::colorCode(print_r($out, true), self::CYAN);

            return $out;

        }


        // Payload
        // The next 4 bytes is the masking key, this key is used to decode the payload

        $maskN = array_map('ord', str_split(fread($resource, 4)));

        $maskC = 0;

        $bufferLength = 1024;

        $message = '';

        // This is not the whole payload if the FIN bit is set
        for ($i = 0; $i < $length; $i += $bufferLength) {

            $buffer = min($bufferLength, $length - $i);

            $handle = fread($resource, $buffer);

            for ($j = 0, $_length = strlen($handle); $j < $_length; ++$j) {

                $handle[$j] = chr(ord($handle[$j]) ^ $maskN[$maskC]);

                $maskC = ($maskC + 1) % 4;

            }

            $message .= $handle;

        }

        $isJson = json_decode($message, true);

        $out['payload'] = $isJson ?: $message;

        self::colorCode(print_r($out, true), self::BACKGROUND_GREEN);

        return $out;

    }

    public static function ensureConvertToSocket($connection)
    {
        if (get_resource_type($connection) === 'stream') {

            if ((defined('STDIN') && $connection === STDIN)
                || (defined('STDOUT') && $connection === STDOUT)
                || (defined('STDERR') && $connection === STDERR)
                || (defined('INPUT') && $connection === INPUT)
            ) {

                return false;

            }

            return socket_import_stream($connection);

        }

        return $connection;

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


    public const string FIFO_DIRECTORY = __DIR__ . DIRECTORY_SEPARATOR . "tmp" . DIRECTORY_SEPARATOR;

    public static function namedPipe()
    {

        try {

            $fifoPath = self::FIFO_DIRECTORY . session_id() . '.fifo';

            if (file_exists($fifoPath)) {

                unlink($fifoPath);          // We are always the creator

            }

            umask(0000);

            $directory = dirname($fifoPath);

            if (!is_dir($directory) && !mkdir($directory) && !is_dir($directory)) {

                self::colorCode("Failed to create directory ($directory)", self::RED);

                return false;
            }

            if (!posix_mkfifo($fifoPath, 0666)) {

                self::colorCode("Failed to create named pipe ($fifoPath)", self::RED);

                return false;

            }

            // this has to have the +
            $fifoFile = fopen($fifoPath, 'rb+');

            register_shutdown_function(static function () use ($fifoPath, $fifoFile) {
                fclose($fifoFile);
                unlink($fifoPath);
            });

            if (false === $fifoFile) {

                throw new Error('Failed to open FIFO for reading and writing');

            }

            stream_set_blocking($fifoFile, false);    // setting to true (resource heavy) activates the handshake feature, aka timeout

            self::colorCode("Named pipe created ($fifoPath).", self::BLUE);

            return $fifoFile;                                       // File descriptor

        } catch (Throwable $e) {

            /** @noinspection ForgottenDebugOutputInspection - todo - error handler */
            print_r($e);

            exit(1);

        }

    }

    public static function sendToEveryone(string $data): void
    {

        $fifoFiles = glob(self::FIFO_DIRECTORY . '*.fifo');

        foreach ($fifoFiles as $fifoPath) {
            // Process each .fifo file

            if (str_ends_with($fifoPath, session_id() . '.fifo')) {

                // no need to update our own fifo with info we already have
                continue;

            }

            // Open the FIFO for writing
            $fifo = fopen($fifoPath, 'wb');

            if ($fifo === false) {
                print ("Failed to open FIFO for writing");
                return;
            }

            @fwrite($fifo, $data);

            @fclose($fifo);

        }

    }

    public const BOLD = 'bold';
    public const DARK = 'dark';
    public const ITALIC = 'italic';
    public const UNDERLINE = 'underline';
    public const BLINK = 'blink';
    public const REVERSE = 'reverse';
    public const CONCEALED = 'concealed';
    public const BLACK = 'black';
    public const RED = 'red';
    public const GREEN = 'green';
    public const YELLOW = 'yellow';
    public const BLUE = 'blue';
    public const MAGENTA = 'magenta';
    public const CYAN = 'cyan';
    public const WHITE = 'white';
    public const BACKGROUND_BLACK = 'background_black';
    public const BACKGROUND_RED = 'background_red';
    public const BACKGROUND_GREEN = 'background_green';
    public const BACKGROUND_YELLOW = 'background_yellow';
    public const BACKGROUND_BLUE = 'background_blue';
    public const BACKGROUND_MAGENTA = 'background_magenta';
    public const BACKGROUND_CYAN = 'background_cyan';
    public const BACKGROUND_WHITE = 'background_white';


    public const PRINTF_ANSI_COLOR = [
        // styles
        // italic and blink may not work depending of your terminal
        self::BOLD => "\033[1m%s\033[0m",
        self::DARK => "\033[2m%s\033[0m",
        self::ITALIC => "\033[3m%s\033[0m",
        self::UNDERLINE => "\033[4m%s\033[0m",
        self::BLINK => "\033[5m%s\033[0m",
        self::REVERSE => "\033[7m%s\033[0m",
        self::CONCEALED => "\033[8m%s\033[0m",
        // foreground colors
        self::BLACK => "\033[30m%s\033[0m",
        self::RED => "\033[31m%s\033[0m",
        self::GREEN => "\033[32m%s\033[0m",
        self::YELLOW => "\033[33m%s\033[0m",
        self::BLUE => "\033[34m%s\033[0m",
        self::MAGENTA => "\033[35m%s\033[0m",
        self::CYAN => "\033[36m%s\033[0m",
        self::WHITE => "\033[37m%s\033[0m",
        // background colors
        self::BACKGROUND_BLACK => "\033[40m%s\033[0m",
        self::BACKGROUND_RED => "\033[41m%s\033[0m",
        self::BACKGROUND_GREEN => "\033[42m%s\033[0m",
        self::BACKGROUND_YELLOW => "\033[43m%s\033[0m",
        self::BACKGROUND_BLUE => "\033[44m%s\033[0m",
        self::BACKGROUND_MAGENTA => "\033[45m%s\033[0m",
        self::BACKGROUND_CYAN => "\033[46m%s\033[0m",
        self::BACKGROUND_WHITE => "\033[47m%s\033[0m",
    ];


    /**
     * @param string $message
     * @param string $color
     * @param bool $exit
     * @link https://www.php.net/manual/en/function.syslog.php
     * @noinspection ForgottenDebugOutputInspection
     */
    public static function colorCode(string $message, string $color = self::GREEN): void
    {

        static $pidColorCache = [];

        $colors = self::PRINTF_ANSI_COLOR;

        $pid = getmypid(); // this shouldn't be cached

        if (false === $pid) {

            $logLinePrefix = 'The php internal function getmypid() has failed' . PHP_EOL . $message;

        } else {

            $pidColorCache[$pid] ??= array_values($colors)[($pid % (count($colors) - 8)) + 8];

            [$seconds, $nanoseconds] = hrtime();

            $milliseconds = $nanoseconds / 1e+6;

            $logLinePrefix = sprintf($pidColorCache[$pid], "<pid($pid);hrtime(s:$seconds,m:$milliseconds)>") . ' ';

        }

        if (is_string($color) && !array_key_exists($color, $colors)) {

            $message = "Color provided to color code ($color) is invalid, message caught '$message'";

            $color = self::RED;

        }

        $message = $logLinePrefix . sprintf($colors[$color], $message);

        error_log($message);

    }

};



