# tcp-netx

Synchronous and Asynchronous access to TCP servers using basic TCP sockets or HTTP from Node.js.

Chris Munt <cmunt@mgateway.com>  
22 June 2023, MGateway Ltd [http://www.mgateway.com](http://www.mgateway.com)

* Verified to work with Node.js v4 to v20.
* [Release Notes](#relnotes) can be found at the end of this document.

Contents

* [Acknowledgements](#acknowledgements)
* [Prerequisites](#prereq)
* [Installing tcp-netx](#install)
* [Connecting to the server](#connect)
* [Reading and Writing](#readwrite)
* [HTTP requests](#http)
* [Troubleshooting](#debug)
* [Using Node.js/V8 worker threads](#threads)
* [License](#license)


## <a name="acknowledgements">Acknowledgements</a>

Special thanks to the Ripple Foundation [https://www.ripple.foundation/](https://www.ripple.foundation/) for
support and funding the initial phase of this project.


## <a name="prereq">Prerequisites</a>

**tcp-netx** is a Node.js addon written in C++.  It is distributed as C++ source code and the NPM installation procedure will expect a C++ compiler to be present on the target system.

Linux systems can use the freely available GNU C++ compiler (g++) which can be installed as follows.

Ubuntu:

       apt-get install g++

Red Hat and CentOS:

       yum install gcc-c++

Apple OS X can use the freely available **Xcode** development environment.

There are two options for Windows, both of which are free:

* Microsoft Visual Studio Community: [https://www.visualstudio.com/vs/community/](https://www.visualstudio.com/vs/community/)
* MinGW: [http://www.mingw.org/](http://www.mingw.org/)

If the Windows machine is not set up for systems development, building native Addon modules for this platform from C++ source can be quite arduous.  There is some helpful advice available at:

* [Compiling native Addon modules for Windows](https://github.com/Microsoft/nodejs-guidelines/blob/master/windows-environment.md#compiling-native-addon-modules)

Alternatively there are built Windows x64 binaries available from:

* [https://github.com/chrisemunt/tcp-netx/blob/master/bin/winx64](https://github.com/chrisemunt/tcp-netx/blob/master/bin/winx64)


## <a name="install">Installing tcp-netx</a>

Assuming that Node.js is already installed and a C++ compiler is available to the installation process:

       npm install tcp-netx

This command will create the **tcp-netx** addon (*tcp-netx.node*).


## <a name="connect">Connecting to the server</a>

Most **tcp-netx** methods are capable of operating either synchronously or asynchronously. For an operation to complete asynchronously, simply supply a suitable callback as the last argument in the call.

The first step is to add **tcp-netx** to your Node.js script

       var tcp = require('tcp-netx');


### Create a Server Object

The second step is to create a Server Object.  This method does not actually create a connection; it simply registers the server host name and the TCP port on which it is listening.

       var db = new tcp.server(<server name>, <port>);

For example, create a server connection object for a local web server listening on the *well known port* for HTTP (80).

       var db = new tcp.server("localhost", 80);


#### Return the version of tcp-netx

       var result = db.version();

Example:

       console.log("\nTCP-NETX Version: " + db.version());


#### Modify the default timeout for tcp-netx methods

The default timeout applied to all **tcp-netx** methods is 10 seconds.  The **timeout()** method can be used to modify this value.

       var timeout = db.timeout([modified timeout]);

Timeouts for **tcp-netx** methods are specified in seconds.

Example 1 (returning the existing timeout value):

       var timeout = db.timeout();

Example 2 (resetting the default timeout to 30 seconds):

       var timeout = db.timeout(30);

Several methods allow for the timeout to be modified on a per-operation basis.


### Connect to the Server

Having created a Server Object, a connection can be made.

Optionally, the **connect()** method may be supplied with an object to specify a *timeout* for the connect operation (in seconds).

Synchronous:

       var result = db.connect([{timeout: <timeout>}]);

Asynchronous:

       db.connect([{timeout: <timeout>}, ]callback(<error>, <result>));
      
Result Object:

       {
          ok: <ok flag>
          [, ErrorMessage: <message>]
          [, ErrorCode: <code>]
       }
     
If the operation is successful, the *ok flag* will be set to *true*. Otherwise, the *ok flag* will be set to *false* and error information will be returned in the *ErrorMessage* and *ErrorCode* fields.

Example 1 (connect to the server using the default timeout):

       var result = db.connect();

Example 2 (connect to the server with a timeout of 60 seconds):

       var result = db.connect({timeout: 60});


#### Disconnect from the Server

Synchronous:

       var result = db.disconnect();

Asynchronous:

       db.disconnect(callback(<error>, <result>));

Result Object:

       {
          ok: <ok flag>
          [, ErrorMessage: <message>]
          [, ErrorCode: <code>]
       }
     
If the operation is successful, the *ok flag* will be set to *true*. Otherwise, the *ok flag* will be set to *false* and error information will be returned in the *ErrorMessage* and *ErrorCode* fields.


## <a name="readwrite">Reading and Writing</a>

### Write to the Server

The default character encoding for the **write()** method is UTF8.  To write binary data to the server use the **writebinary()** method instead.

The request object sent to the server must contain the *data* field.

Synchronous:

       var result = db.write({data: <data>});

Asynchronous:

       db.write({data: <data>}, callback(<error>, <result>));
      
Result Object:

       {
          ok: <ok flag>
          [, ErrorMessage: <message>]
          [, ErrorCode: <code>]
       }
     
If the operation is successful, the *ok flag* will be set to *true*. Otherwise, the *ok flag* will be set to *false* and error information will be returned in the *ErrorMessage* and *ErrorCode* fields.

Example: *Send "PING" to the server*

       var result = db.write({data: "PING"});

       
### Read from the Server

The default character encoding for the **read()** method is UTF8.  To read binary data from the server use the **readbinary()** method instead.

Optionally, the **read()** method may be supplied with an object to specify the *length* of the data to be read and a *timeout* may also be specified (in seconds).

Synchronous:

       var result = db.read([{[timeout: <timeout>] [, length: <length>]}]);

Asynchronous:

       db.read([{[timeout: <timeout>] [, length: <length>]}], callback(<error>, <result>));
       
Result Object:

       {
          ok: <ok flag>,
          data: <data>,
          eof: <eof>
          [, ErrorMessage: <message>]
          [, ErrorCode: <code>]
       }
     
If the operation is successful, the *ok flag* will be set to *true* and the response *data* will be returned.  Otherwise, the *ok flag* will be set to *false* and error information will be returned in the *ErrorMessage* and *ErrorCode* fields.

If the *eof* flag is set then it must be assumed that the server closed the connection - either as a result of an error condition or timeout.

If no *length* is specified, the method will return as much data as is currently available.  Otherwise the method will block until it has received the requested amount of *data* from the server.

Example: *Read 4 Bytes from the server with a timeout of 30 seconds*

       var result = db.read({length: 4, timeout: 30});


## <a name="http">HTTP requests</a>

### Sending an HTTP Request to a Web Server

The request object sent to the web server must, at the very least, contain the HTTP request headers in the *headers* field.  Optionally, the request may include a payload in the *content* field and a *timeout* may also be specified (in seconds).

Synchronous:

       var result = db.http({headers: <headers> [, content: <content>] [, timeout: <timeout>]});

Asynchronous:

       db.http({headers: <headers> [, content: <content>]  [, timeout: <timeout>]}, callback(<error>, <result>));
       
Result Object:

       {
          ok: <ok flag>,
          headers: <headers>,
          keepalive: <keepalive flag>
          [, content: <content>]
          [, eof: <eof>]
          [, ErrorMessage: <message>]
          [, ErrorCode: <code>]
       }
     
If the operation is successful, the *ok flag* will be set to *true* and the response *headers* and any *content* (i.e. payload) will be returned.  Otherwise, the *ok flag* will be set to *false* and error information will be returned in the *ErrorMessage* and *ErrorCode* fields.

If the *eof* flag is set then it must be assumed that the server closed the connection - either as a result of an error condition or timeout.

If the HTTP *keepalive* flag is set then it is possible to send a further HTTP request without reconnecting to the web server.

Example: *Request /index.html from the web server*

       var result = db.http({headers: "GET /index.html HTTP/1.1\r\nHost: localhost:80\r\nConnection: close\r\n\r\n"});


## <a name="threads">Using Node.js/V8 worker threads</a>

**tcp-netx** functionality can now be used with Node.js/V8 worker threads.  This enhancement is available with Node.js v12 (and later).

The following scheme illustrates how **tcp-netx** should be used in threaded Node.js applications.


       const { Worker, isMainThread, parentPort, threadId } = require('worker_threads');

       if (isMainThread) {
          // start the threads
          const worker1 = new Worker(__filename);
          const worker2 = new Worker(__filename);

          // process messages received from threads
          worker1.on('message', (message) => {
             console.log(message);
          });
          worker2.on('message', (message) => {
             console.log(message);
          });
       } else {
          var tcp = require('tcp-netx');
          var db = new tcp.server(<server>, <port>);
          var result = db.connect();

          // do some work

          var result = db.disconnect();
          // tell the parent that we're done
          parentPort.postMessage("threadId=" + threadId + " Done");
       }


## <a name="debug">Troubleshooting</a>

**tcp-netx** contains a function call trace and logging facility to help with troubleshooting problems in operation.

To write a running commentary of progress to the console window:

       var result = db.settrace(1);

To write a running commentary of progress to a file:

       var result = db.settrace("/tmp/tcp-netx.log");

To disable the trace facility:

       var result = db.settrace(0);


## <a name="license">License</a>

Copyright (c) 2016-2023 MGateway Ltd,
Surrey UK.                                                      
All rights reserved.
 
http://www.mgateway.com                                                  
Email: cmunt@mgateway.com
 
 
Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.      


## <a name="relnotes">Release Notes</a>

### v1.0.7 (2 December 2016)

* Initial Release

### v1.1.8 (19 July 2019)

* Support for Node.js v8, v10 and v12.
* Support for sending and receiving binary data: **readbinary()** and **writebinary()** methods.

### v1.1.9 (12 September 2019)

* Internal changes to replace V8/Node.js API functionality that was deprecated in Node.js v12.

### v1.1.10 (8 November 2019)

* Correct a fault in the processing of HTTP POST requests in the db.http() method.

### v1.2.11 (6 May 2020)

* Verify that **tcp-netx** will build and work with Node.js v14.x.x.
* Introduce support for Node.js/V8 worker threads (for Node.js v12.x.x. and later).
	* See the section on 'Using Node.js/V8 worker threads'.
* Correct a fault in the processing of error conditions (e.g. 'server not available' etc..).
* Suppress a number of benign 'cast-function-type' compiler warnings when building on the Raspberry Pi.

### v1.2.12 (28 April 2021)

* Verify that **tcp-netx** will build and work with Node.js v16.x.x.
* A number of faults related to the use of **tcp\-netx** functionality in Node.js/v8 worker threads have been corrected.  In particular, it was noticed that callback functions were not being fired correctly for some asynchronous invocations of **tcp\-netx** methods.

### v1.2.12a (25 April 2022)

* Verify that **tcp-netx** will build and work with Node.js v18.x.x.

### v1.3.13 (14 December 2022)

* Correct a fault in the processing of timeouts specified in the **read()** and **http()** methods.
* Allow a timeout to be specified for the **connect()** method.
* Introduce a **timeout()** method to allow the default timeout applied to all **tcp-netx** methods to be changed.  The initial default timeout for all methods is set to 10 seconds.

### v1.2.13a (3 May 2023)

* Verify that **tcp-netx** will build and work with Node.js v20.x.x.

### v1.2.13b (22 June 2023)

* Documentation update.
