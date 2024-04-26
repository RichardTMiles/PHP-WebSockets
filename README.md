# PHP-Websockets (Live Chat & Communication)

<img width="1792" alt="Screenshot 2024-04-26 at 12 56 27 AM" src="https://github.com/RichardTMiles/PHP-Websockets/assets/9538357/587aac7e-e345-4d6c-a289-8bd622eb8945">

HTML 5 Websockets written for PHP
This includes the ws:// and wss:// protocol 
Simplistic and to the point. I saved you the run around 
of digging through other repos. This is strictly for the 
order of operations in a procedural script. All Websocket PHP
operations are in the server file. This code is not production 
ready, as input is not validated for XSS attacks. 

To run the demo use the following commands in a shell prompt 

## starts the websocket server on port 8080
>>   sudo php server.php  

Then in a new window navigate to the same folder and start the client server

## starts php's built in webserver 
>>   php -S localhost:8888 index.php

This will allow you to visit the chat demo on your local web browser

## navigates to php's built in webserver
http://localhost:7777/    

^ Throw a star up there!



mkdir -p ./logs/httpd/ && rm /usr/local/var/www && ln -s $(pwd) /usr/local/var/www && brew services restart httpd
