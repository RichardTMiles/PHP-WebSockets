# PHP-Websockets
HTML 5 Websockets written for PHP
This includes the ws:// and wss:// protocol 
Simplistic and to the point. I saved you the run around 
of digging through other repos. This is strictly for the 
order of operations in a procedural script. All Websocket PHP
operations are in the server file. This code is not production 
ready, as input is not validated for XSS attacks. 

To run the demo use the following commands in a shell prompt 

// starts the websocket server
>>   sudo ./server.php  

Then in a new window navigate to the same folder and start the client server

// starts php's built in webserver 
>>   php -S localhost:8080  

This will allow you to visit the chat demo on your local web browser

// navigates to php's built in webserver
http://localhost:8080/    

^ Throw a star up there!
