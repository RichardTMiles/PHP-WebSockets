# PHP-Websockets (Live Chat & Communication)

<img width="1792" alt="Screenshot 2024-04-26 at 12 56 27 AM" src="https://github.com/RichardTMiles/PHP-Websockets/assets/9538357/587aac7e-e345-4d6c-a289-8bd622eb8945">

HTML 5 Websockets written for PHP
This includes the ws:// and wss:// protocol 
Simplistic and to the point. I saved you the run around 
of digging through other repos. This is strictly for the 
order of operations in a procedural script. All Websocket PHP
operations are in the index.php file. 

# PHP-RFC - https://github.com/php/php-src/pull/14047

Historically a websocket request must be setup by running a PHP cli script as a server that accepts connections on a specific port. This repo was used initially develop and test `apache_connection_stream` which would allow websockets though Apache CGI without any server configuartion.

## PHP-CGI apache2handler

Running the full apache version currectly requires you build the PHP interpreter from source, specifically the branch used for [this pull request](https://github.com/php/php-src/pull/14047). As of now PHP's internal server cli `php -S` does not support WebSockets. You will need to add this porject to your Apache web root.

## PHP-CLI
Running the PHP WebSocket server is done using the following commands in two seperate shells.

- `php index.php`
- `php -S localhost:8888 index.php`

This will allow you to visit the chat demo on your local web browser.

### CLI Server caviates 
To setup this process in an Apache WebServer you will need the `mod_proxy` and `mod_proxy_wstunnel` modules installed. You can then add the following directive to your `.htaccess` files. Note: htaccess overrides will need to be enabled.

```
    RewriteCond %{HTTP:Connection} Upgrade [NC]
    RewriteCond %{HTTP:Upgrade} websocket [NC]
    RewriteRule ^/?(.*) ws://127.0.0.1:8888/$1  [P,L,E=noconntimeout:1,E=noabort:1]
```

This will cause apache to proxy all requests to the PHP WebSocket server. If SSL is handled through Apache then it will be handled in the proxy as well, meaning you will not need to configure certificates in you PHP WebSocketserver as HTTPD will translate WSS to WS in the background. 

## navigates to php's built in webserver
`open http://localhost:8888/`   

^ Throw a star up there!


