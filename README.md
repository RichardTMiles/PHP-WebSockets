# PHP-Websockets (Live Chat & Communication)

<img width="1792" alt="Screenshot 2024-04-26 at 12 56 27 AM" src="https://github.com/RichardTMiles/PHP-Websockets/assets/9538357/587aac7e-e345-4d6c-a289-8bd622eb8945">

HTML 5 Websockets written for PHP
This includes the ws:// and wss:// protocol. Simplistic and to the point. I saved you the run around of digging through other repos or learning spec. This is strictly for the order of operations in a procedural script. Complexities are guaranteed to exist for any specific use case.

# PHP-RFC - https://github.com/php/php-src/pull/14047

This repo was used to develop and test `apache_connection_stream()` which would allow websockets though Apache CGI without any server configuartion. Historically a websocket request must be setup by running a PHP-CLI script that starts a server to then accepts connections on a specific port. It contains both what is standard and what is not.

# Starting the WebSocket
## PHP-CGI apache2handler

Running the full apache version currectly requires you build the PHP interpreter from source, specifically the branch used for [this pull request](https://github.com/php/php-src/pull/14047). I have a [2024 Gist for Mac Users](https://gist.github.com/RichardTMiles/ebf6ce2758bf3f11469d25463092465a). Note: many tutorials exist. If the proposal becomes standard compilation will no longer be nessasary. You have two options for running:
- `php -S localhost:8888 index.php`
    - **Note:** When the websocket connects to the server, you must hit enter (new line) explicitly in the terminal with `php -S`. This is considered a small bug, and is yet to be fixed.
- Add this project to your Apache web root. It is assumed that Apache is set to serve `index.php` as the default request, which would be the assumed behavior on an Apache PHP enabled server. Both requests (HTTP GET, and HTTP Upgrate WebSocket) will have the appropriate headers returned. The Upgrade request will persist as expected while the GET request will terminate after the HTML data is served.

**Note:** Both of the CGI implimentations listed above are actually implemted diffrently in PHP-SRC's `C` code. It is much better and more powerful to run this example in `Apache` as the `PHP` server context is single threaded and thus unable to run on multiple browsers at a time.

## PHP-CLI
Running the PHP WebSocket server is done using the following commands in two seperate shells.

- `php index.php`
- `php -S localhost:8888 index.php`

This will allow you to visit the chat demo on your local web browser.

### CLI Server caviates 
To setup this process in an Apache WebServer you will need the `mod_proxy` and `mod_proxy_wstunnel` modules installed. You can then add the following directive to your `.htaccess` files. **Note:** htaccess overrides will need to be enabled.

```
    RewriteCond %{HTTP:Connection} Upgrade [NC]
    RewriteCond %{HTTP:Upgrade} websocket [NC]
    RewriteRule ^/?(.*) ws://127.0.0.1:8888/$1  [P,L,E=noconntimeout:1,E=noabort:1]
```

This will cause apache to proxy all requests to the PHP WebSocket server. If SSL is handled through Apache then it will be handled in the proxy as well, meaning you will not need to configure certificates in you PHP WebSocketserver as HTTPD will translate WSS to WS in the background. 

## navigates to php's built in webserver
`open http://localhost:8888/`   

^ Throw a star up there!

# Complexities 

I've been developing websockets for years and I have a few tips for making informed decision of your implementation. Here's a few complex senarios to ponder.

- Websockets create a single persistent connection to a single server. When auto-scaling is involved, where multiple servers may handle a connection. When a user needs to update everone they may need to communicate across servers.
- Memory managment is critical, you should only process what is needed on the main thread. Forking when actually processing data is a very good idea.
- You can choose wheater to handle all connections in a singel thread `CLI`, or use `CGI` to have a single thread per user. It is currently unclear as to the best implementation, but specific use cases may need to choose one or the other. The immediate trade off is the convience of sending global updates which is easier in CLI, or speed which **could** potentially be faster with `CGI`. This is pretty arbitrary and is most likely dependant on number of connection active vs logic cpu's available.
- There are configurable max limits of various types. One example is file descriptors. Any client connection is a socket (fd). Any running process typically has few file descriptors that are automatically opened: Standard Input (`stdin`): Typically FD `0`, Standard Output (`stdout`): Typically FD `1`, Standard Error (`stderr`): Typically FD `2`. On linux (Mac, Ubuntu, fedora, RHEL,...) systems you can see limits set using `ulimit -a` and specifically file descriptors with `ulimit -n`. Thesse are typicpically desigend to ensure no memory leaks occur, but as load increases, these should be noted.
    - What ulimit Can Limit
        1. File Descriptors (-n): Limits the number of open file descriptors a process may have. This is perhaps the most commonly adjusted limit, especially on systems that run servers or applications that need to handle many simultaneous connections or files.
        2. Stack Size (-s): Sets the maximum stack size that a process may use. This is important for programs that use a lot of stack memory, such as those with deep recursion or large local variables.
        3. CPU Time (-t): Limits the amount of CPU time that a process can consume. If this limit is exceeded, the process is sent a SIGXCPU signal, which can terminate it unless the signal is caught and handled.
        4. Memory Size (-m): In some systems, this limits the maximum resident set size, which is the non-swapped physical memory a task can use.
        5. Core File Size (-c): Controls the maximum size of core files created when a process crashes.
        6. Process Data Segment (-d): Limits the data segment of a process, which includes the heap and dynamically allocated memory.
        7. Max User Processes (-u): Limits the number of processes that can be created for the real user ID of the process. This is essential in multi-user systems to prevent any single user from exhausting all available system processes.
        8. Virtual Memory (-v): Specifies the maximum amount of virtual memory that a process can use. This limit includes all memory the process can access, including memory swapped to disk and memory shared with other processes.
        9. File Size (-f): Determines the maximum size of files that the process can create. This can be used to prevent processes from creating extremely large files that could fill up disk storage.
        10. `locked-in-memory` size (-l): Limits the amount of memory that a process can lock into RAM using the mlock() system call. This prevents a process from locking so much memory that it impacts system performance or stability.
        11. POSIX Message Queues (-q): Sets the maximum number of bytes that can be allocated for POSIX message queues. This is important on systems that heavily use inter-process communication via message queues.
        12. Max `nice` (-e): Limits the maximum nice value that can be set for a process. The nice value affects process scheduling; lower values mean higher priority. Limiting this can prevent a user from setting too high a priorityto a process.
        13. Real-Time Priority (-r): Sets the maximum real-time scheduling priority for a process. This is used on systems where real-time processing is critical, and it ensures that non-privileged processes cannot interfere with real-time tasks by assigning themselves higher priorities.
