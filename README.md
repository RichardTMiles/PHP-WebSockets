# PHP-Websockets (Live Chat & Communication)

<img width="537" alt="screen shot 2018-01-25 at 4 48 32 am" src="https://user-images.githubusercontent.com/9538357/35384590-67a59d8e-018b-11e8-9d00-30948e91fc13.png">

HTML 5 Websockets written for PHP
This includes the ws:// and wss:// protocol 
Simplistic and to the point. I saved you the run around 
of digging through other repos. This is strictly for the 
order of operations in a procedural script. All Websocket PHP
operations are in the server file. This code is not production 
ready, as input is not validated for XSS attacks. 

To run the demo use the following commands in a shell prompt 

## starts the websocket server on port 8080
>>   sudo ./server.php  

Then in a new window navigate to the same folder and start the client server

## starts php's built in webserver 
>>   php -S localhost:8888 index.php

This will allow you to visit the chat demo on your local web browser

## navigates to php's built in webserver
http://localhost:8888/    

^ Throw a star up there!
