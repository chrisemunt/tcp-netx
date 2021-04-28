/*
   ----------------------------------------------------------------------------
   | tcp-netx.node                                                            |
   | Author: Chris Munt cmunt@mgateway.com                                    |
   |                    chris.e.munt@gmail.com                                |
   | Copyright (c) 2016-2021 M/Gateway Developments Ltd,                      |
   | Surrey UK.                                                               |
   | All rights reserved.                                                     |
   |                                                                          |
   | http://www.mgateway.com                                                  |
   |                                                                          |
   | Licensed under the Apache License, Version 2.0 (the "License"); you may  |
   | not use this file except in compliance with the License.                 |
   | You may obtain a copy of the License at                                  |
   |                                                                          |
   | http://www.apache.org/licenses/LICENSE-2.0                               |
   |                                                                          |
   | Unless required by applicable law or agreed to in writing, software      |
   | distributed under the License is distributed on an "AS IS" BASIS,        |
   | WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. |
   | See the License for the specific language governing permissions and      |
   | limitations under the License.                                           |      
   |                                                                          |
   |                                                                          |
   | Special thanks to the Ripple Foundation <http://rippleosi.org> for       |
   | support and funding of this project.                                     |
   ----------------------------------------------------------------------------
*/

/*

Change Log:

Version 1.0.7 2 December 2016:
   First release.

Version 1.1.8 19 July 2019:
   Support for Node.js v8, v10 and v12.
   Support for sending and receiving binary data: **readbinary()** and **writebinary()** methods.

Version 1.1.9 12 September 2019:
   Replace functionality that was deprecated in Node.js/V8 v12.

Version 1.1.10 8 November 2019:
   Correct a fault in the processing of HTTP POST requests in the db.http() method.

Version 1.2.11 6 May 2020:
   Verify that the code base works with Node.js v14.x.x.
   Introduce support for Node.js/V8 worker threads (for Node.js v12.x.x. and later).
   Correct a fault in the processing of error conditions (e.g. 'server not available' etc..).
   Suppress a number of benign 'cast-function-type' compiler warnings when building on the Raspberry Pi.

Version 1.2.12 28 April 2021:
   Verify that the code base works with Node.js v16.x.x.
   Fix A number of faults related to the use of tcp-netx functionality in Node.js/v8 worker threads.
   - Notably, callback functions were not being fired correctly for some asynchronous invocations of tcp-netx methods.

*/


#if defined(_WIN32)
#define BUILDING_NODE_EXTENSION     1
#if defined(_MSC_VER)
#if (_MSC_VER >= 1400)
#define _CRT_SECURE_NO_DEPRECATE    1
#define _CRT_NONSTDC_NO_DEPRECATE   1
#endif
#endif
#elif defined(__linux__) || defined(__linux) || defined(linux)
#define LINUX                       1
#elif defined(__APPLE__)
#define MACOSX                      1
#else
#error "Unknown Compiler"
#endif

#if defined(_WIN32)

#include <string>
#include <stdlib.h>
#define INCL_WINSOCK_API_TYPEDEFS 1
#include <winsock2.h>
#include <ws2tcpip.h>
#include <time.h>

#else

#include <string>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/errno.h>
#include <signal.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/resource.h>
#if !defined(HPUX) && !defined(HPUX10) && !defined(HPUX11)
#include <sys/select.h>
#endif
#if defined(SOLARIS)
#include <sys/filio.h>
#endif
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <dlfcn.h>

#endif /* #if defined(_WIN32) */

#if defined(__GNUC__) && __GNUC__ >= 8
#define DISABLE_WCAST_FUNCTION_TYPE _Pragma("GCC diagnostic push") _Pragma("GCC diagnostic ignored \"-Wcast-function-type\"")
#define DISABLE_WCAST_FUNCTION_TYPE_END _Pragma("GCC diagnostic pop")
#else
#define DISABLE_WCAST_FUNCTION_TYPE
#define DISABLE_WCAST_FUNCTION_TYPE_END
#endif

DISABLE_WCAST_FUNCTION_TYPE

#include <v8.h>
#include <node.h>
#include <node_version.h>

#include <uv.h>
#include <node_object_wrap.h>

#define NETX_VERSION_MAJOR       1
#define NETX_VERSION_MINOR       2
#define NETX_VERSION_BUILD       12

#define NETX_VERSION             NETX_VERSION_MAJOR "." NETX_VERSION_MINOR "." NETX_VERSION_BUILD
#define NETX_NODE_VERSION        (NODE_MAJOR_VERSION * 10000) + (NODE_MINOR_VERSION * 100) + NODE_PATCH_VERSION

#define NETX_TIMEOUT             10
#define NETX_IPV6                1
#define NETX_READ_EOF            0
#define NETX_READ_NOCON          -1
#define NETX_READ_ERROR          -2
#define NETX_READ_TIMEOUT        -3
#define NETX_RECV_BUFFER         32768

#define NETX_STR_HEADERS         "headers"
#define NETX_STR_CONTENT         "content"
#define NETX_STR_KEEPALIVE       "keepalive"
#define NETX_STR_DATA            "data"
#define NETX_STR_LENGTH          "length"
#define NETX_STR_TIMEOUT         "timeout"
#define NETX_STR_EOF             "eof"
#define NETX_STR_OK              "ok"
#define NETX_STR_ERRORMESSAGE    "ErrorMessage"
#define NETX_STR_ERRORCODE       "ErrorCode"
#define NETX_STR_INFORMATION     "Information"


#if defined(LINUX)
#define NETX_MEMCPY(a,b,c)           memmove(a,b,c)
#else
#define NETX_MEMCPY(a,b,c)           memcpy(a,b,c)
#endif


#if defined(_WIN32)

#define NETX_WSASOCKET               netx_so.p_WSASocket
#define NETX_WSAGETLASTERROR         netx_so.p_WSAGetLastError
#define NETX_WSASTARTUP              netx_so.p_WSAStartup
#define NETX_WSACLEANUP              netx_so.p_WSACleanup
#define NETX_WSAFDISET               netx_so.p_WSAFDIsSet
#define NETX_WSARECV                 netx_so.p_WSARecv
#define NETX_WSASEND                 netx_so.p_WSASend

#define NETX_WSASTRINGTOADDRESS      netx_so.p_WSAStringToAddress
#define NETX_WSAADDRESSTOSTRING      netx_so.p_WSAAddressToString
#define NETX_GETADDRINFO             netx_so.p_getaddrinfo
#define NETX_FREEADDRINFO            netx_so.p_freeaddrinfo
#define NETX_GETNAMEINFO             netx_so.p_getnameinfo
#define NETX_GETPEERNAME             netx_so.p_getpeername
#define NETX_INET_NTOP               netx_so.p_inet_ntop
#define NETX_INET_PTON               netx_so.p_inet_pton

#define NETX_CLOSESOCKET             netx_so.p_closesocket
#define NETX_GETHOSTNAME             netx_so.p_gethostname
#define NETX_GETHOSTBYNAME           netx_so.p_gethostbyname
#define NETX_SETSERVBYNAME           netx_so.p_getservbyname
#define NETX_GETHOSTBYADDR           netx_so.p_gethostbyaddr
#define NETX_HTONS                   netx_so.p_htons
#define NETX_HTONL                   netx_so.p_htonl
#define NETX_NTOHL                   netx_so.p_ntohl
#define NETX_NTOHS                   netx_so.p_ntohs
#define NETX_CONNECT                 netx_so.p_connect
#define NETX_INET_ADDR               netx_so.p_inet_addr
#define NETX_INET_NTOA               netx_so.p_inet_ntoa
#define NETX_SOCKET                  netx_so.p_socket
#define NETX_SETSOCKOPT              netx_so.p_setsockopt
#define NETX_GETSOCKOPT              netx_so.p_getsockopt
#define NETX_GETSOCKNAME             netx_so.p_getsockname
#define NETX_SELECT                  netx_so.p_select
#define NETX_RECV                    netx_so.p_recv
#define NETX_SEND                    netx_so.p_send
#define NETX_SHUTDOWN                netx_so.p_shutdown
#define NETX_BIND                    netx_so.p_bind
#define NETX_LISTEN                  netx_so.p_listen
#define NETX_ACCEPT                  netx_so.p_accept

#define  NETX_FD_ISSET(fd, set)              netx_so.p_WSAFDIsSet((SOCKET)(fd), (fd_set *)(set))

typedef int (WINAPI * LPFN_WSAFDISSET)       (SOCKET, fd_set *);

typedef DWORD           NETXTHID;
typedef HINSTANCE       NETXPLIB;
typedef FARPROC         NETXPROC;
typedef LPSOCKADDR      xLPSOCKADDR;
typedef u_long          *xLPIOCTL;
typedef const char      *xLPSENDBUF;
typedef char            *xLPRECVBUF;

#ifdef _WIN64
typedef int             socklen_netx;
#else
typedef size_t          socklen_netx;
#endif

#define SOCK_ERROR(n)   (n == SOCKET_ERROR)
#define INVALID_SOCK(n) (n == INVALID_SOCKET)
#define NOT_BLOCKING(n) (n != WSAEWOULDBLOCK)

#define BZERO(b,len) (memset((b), '\0', (len)), (void) 0)

#else /* #if defined(_WIN32) */

#define NETX_WSASOCKET               WSASocket
#define NETX_WSAGETLASTERROR         WSAGetLastError
#define NETX_WSASTARTUP              WSAStartup
#define NETX_WSACLEANUP              WSACleanup
#define NETX_WSAFDIsSet              WSAFDIsSet
#define NETX_WSARECV                 WSARecv
#define NETX_WSASEND                 WSASend

#define NETX_WSASTRINGTOADDRESS      WSAStringToAddress
#define NETX_WSAADDRESSTOSTRING      WSAAddressToString
#define NETX_GETADDRINFO             getaddrinfo
#define NETX_FREEADDRINFO            freeaddrinfo
#define NETX_GETNAMEINFO             getnameinfo
#define NETX_GETPEERNAME             getpeername
#define NETX_INET_NTOP               inet_ntop
#define NETX_INET_PTON               inet_pton

#define NETX_CLOSESOCKET             closesocket
#define NETX_GETHOSTNAME             gethostname
#define NETX_GETHOSTBYNAME           gethostbyname
#define NETX_SETSERVBYNAME           getservbyname
#define NETX_GETHOSTBYADDR           gethostbyaddr
#define NETX_HTONS                   htons
#define NETX_HTONL                   htonl
#define NETX_NTOHL                   ntohl
#define NETX_NTOHS                   ntohs
#define NETX_CONNECT                 connect
#define NETX_INET_ADDR               inet_addr
#define NETX_INET_NTOA               inet_ntoa
#define NETX_SOCKET                  socket
#define NETX_SETSOCKOPT              setsockopt
#define NETX_GETSOCKOPT              getsockopt
#define NETX_GETSOCKNAME             getsockname
#define NETX_SELECT                  select
#define NETX_RECV                    recv
#define NETX_SEND                    send
#define NETX_SHUTDOWN                shutdown
#define NETX_BIND                    bind
#define NETX_LISTEN                  listen
#define NETX_ACCEPT                  accept

#define NETX_FD_ISSET(fd, set) FD_ISSET(fd, set)

typedef pthread_t       NETXTHID;
typedef void            *NETXPLIB;
typedef void            *NETXPROC;
#if !defined(NODE_ENGINE_CHAKRACORE)
typedef unsigned long   DWORD;
#endif
typedef unsigned long   WORD;
typedef int             WSADATA;
typedef int             SOCKET;
typedef struct sockaddr SOCKADDR;
typedef struct sockaddr * LPSOCKADDR;
typedef struct hostent  HOSTENT;
typedef struct hostent  * LPHOSTENT;
typedef struct servent  SERVENT;
typedef struct servent  * LPSERVENT;

#ifdef NETX_BS_GEN_PTR
typedef const void      * xLPSOCKADDR;
typedef void            * xLPIOCTL;
typedef const void      * xLPSENDBUF;
typedef void            * xLPRECVBUF;
#else
typedef LPSOCKADDR      xLPSOCKADDR;
typedef char            * xLPIOCTL;
typedef const char      * xLPSENDBUF;
typedef char            * xLPRECVBUF;
#endif /* #ifdef NETX_BS_GEN_PTR */

#if defined(OSF1) || defined(HPUX) || defined(HPUX10) || defined(HPUX11)
typedef int             socklen_netx;
#elif defined(LINUX) || defined(AIX) || defined(AIX5) || defined(MACOSX)
typedef socklen_t       socklen_netx;
#else
typedef size_t          socklen_netx;
#endif

#ifndef INADDR_NONE
#define INADDR_NONE     -1
#endif

#define SOCK_ERROR(n)   (n < 0)
#define INVALID_SOCK(n) (n < 0)
#define NOT_BLOCKING(n) (n != EWOULDBLOCK && n != 2)

#define BZERO(b, len)   (bzero(b, len))


#endif /* #if defined(_WIN32) */

#define NETX_METHOD_VERSION      1
#define NETX_METHOD_CONNECT      2
#define NETX_METHOD_READ         3
#define NETX_METHOD_WRITE        4
#define NETX_METHOD_HTTP         5
#define NETX_METHOD_DISCONNECT   6

typedef struct tagNETXSOCK {

   unsigned char                 winsock_ready;
   short                         sock;
   short                         load_attempted;
   short                         nagle_algorithm;
   short                         winsock;
   short                         ipv6;
   NETXPLIB                      plibrary;

   char                          libnam[256];

#if defined(_WIN32)
   WSADATA                       wsadata;
   int                           wsastartup;
   WORD                          version_requested;
   LPFN_WSASOCKET                p_WSASocket;
   LPFN_WSAGETLASTERROR          p_WSAGetLastError; 
   LPFN_WSASTARTUP               p_WSAStartup;
   LPFN_WSACLEANUP               p_WSACleanup;
   LPFN_WSAFDISSET               p_WSAFDIsSet;
   LPFN_WSARECV                  p_WSARecv;
   LPFN_WSASEND                  p_WSASend;

#if defined(NETX_IPV6)
   LPFN_WSASTRINGTOADDRESS       p_WSAStringToAddress;
   LPFN_WSAADDRESSTOSTRING       p_WSAAddressToString;
   LPFN_GETADDRINFO              p_getaddrinfo;
   LPFN_FREEADDRINFO             p_freeaddrinfo;
   LPFN_GETNAMEINFO              p_getnameinfo;
   LPFN_GETPEERNAME              p_getpeername;
   LPFN_INET_NTOP                p_inet_ntop;
   LPFN_INET_PTON                p_inet_pton;
#else
   LPVOID                        p_WSAStringToAddress;
   LPVOID                        p_WSAAddressToString;
   LPVOID                        p_getaddrinfo;
   LPVOID                        p_freeaddrinfo;
   LPVOID                        p_getnameinfo;
   LPVOID                        p_getpeername;
   LPVOID                        p_inet_ntop;
   LPVOID                        p_inet_pton;
#endif

   LPFN_CLOSESOCKET              p_closesocket;
   LPFN_GETHOSTNAME              p_gethostname;
   LPFN_GETHOSTBYNAME            p_gethostbyname;
   LPFN_GETHOSTBYADDR            p_gethostbyaddr;
   LPFN_GETSERVBYNAME            p_getservbyname;

   LPFN_HTONS                    p_htons;
   LPFN_HTONL                    p_htonl;
   LPFN_NTOHL                    p_ntohl;
   LPFN_NTOHS                    p_ntohs;
   LPFN_CONNECT                  p_connect;
   LPFN_INET_ADDR                p_inet_addr;
   LPFN_INET_NTOA                p_inet_ntoa;

   LPFN_SOCKET                   p_socket;
   LPFN_SETSOCKOPT               p_setsockopt;
   LPFN_GETSOCKOPT               p_getsockopt;
   LPFN_GETSOCKNAME              p_getsockname;
   LPFN_SELECT                   p_select;
   LPFN_RECV                     p_recv;
   LPFN_SEND                     p_send;
   LPFN_SHUTDOWN                 p_shutdown;
   LPFN_BIND                     p_bind;
   LPFN_LISTEN                   p_listen;
   LPFN_ACCEPT                   p_accept;
#endif /* #if defined(_WIN32) */

} NETXSOCK, *PNETXSOCK;


typedef struct tagNETXCON {
   short          connected;
   int            port;
   char           ip_address[128];
   int            error_no;
   char           error[512];
   char           info[256];
   int            length;
   int            timeout;
   SOCKET         cli_socket;
   int            method;
   int            hlen;
   int            keepalive;
   int            eof;
   int            send_buf_size;
   int            send_buf_len;
   unsigned char *send_buf;
   int            recv_buf_size;
   int            recv_buf_len;
   unsigned char *recv_buf;
   short          trace;
   FILE *         pftrace;
} NETXCON, *pcon;


#if NETX_NODE_VERSION >= 120000
#define NETX_GET(a,b)                a->Get(icontext,b).ToLocalChecked()
#define NETX_SET(a,b,c)              a->Set(icontext,b,c).FromJust()
#define NETX_TO_OBJECT(a)            a->ToObject(icontext).ToLocalChecked()
#define NETX_TO_STRING(a)            a->ToString(icontext).ToLocalChecked()
#define NETX_NUMBER_VALUE(a)         a->NumberValue(icontext).ToChecked()
#define NETX_INT32_VALUE(a)          a->Int32Value(icontext).FromJust()
#elif NETX_NODE_VERSION >= 100000
#define NETX_GET(a,b)                a->Get(icontext,b).ToLocalChecked()
#define NETX_SET(a,b,c)              a->Set(icontext,b,c).FromJust()
#define NETX_TO_OBJECT(a)            a->ToObject(icontext).ToLocalChecked()
#define NETX_TO_STRING(a)            a->ToString(icontext).ToLocalChecked()
#define NETX_NUMBER_VALUE(a)         a->NumberValue(icontext).ToChecked()
#define NETX_INT32_VALUE(a)          a->Int32Value(icontext).FromJust()
#else
#define NETX_GET(a,b)                a->Get(b)
#define NETX_SET(a,b,c)              a->Set(b,c)
#define NETX_TO_OBJECT(a)            a->ToObject()
#define NETX_TO_STRING(a)            a->ToString()
#define NETX_NUMBER_VALUE(a)         a->NumberValue()
#if NETX_NODE_VERSION >= 70000
#define NETX_INT32_VALUE(a)          a->Int32Value()
#else
#define NETX_INT32_VALUE(a)          a->ToInt32()->Value();
#endif
#endif

/*
#if NETX_NODE_VERSION >= 70000
            s->pcon->length = request->Get(length_name)->Int32Value();
#else
            s->pcon->length = request->Get(length_name)->ToInt32()->Value();
#endif
*/

static NETXSOCK       netx_so        = {0, 0, 0, 0, 0, 0, 0, {'\0'}};

#if defined(_WIN32)
CRITICAL_SECTION  netx_async_mutex;
#else
pthread_mutex_t   netx_async_mutex        = PTHREAD_MUTEX_INITIALIZER;
#endif


using namespace node;
using namespace v8;


int      netx_connect               (NETXCON *pcon);
int      netx_read                  (NETXCON *pcon);
int      netx_write                 (NETXCON *pcon);
int      netx_http                  (NETXCON *pcon);
int      netx_disconnect            (NETXCON *pcon);

int      netx_init_vars             (NETXCON *pcon);
int      netx_format_buffer         (char *obuffer, char *ibuffer, int len, int max);
int      netx_ucase                 (char *string);
int      netx_lcase                 (char *string);
void *   netx_malloc                (int size, short id);
int      netx_free                  (void *p, short id);
int      netx_resize                (NETXCON *pcon, unsigned char **ppbuf, int *psize, int retain, int size);
NETXPLIB netx_dso_load              (char * library);
NETXPROC netx_dso_sym               (NETXPLIB plibrary, char * symbol);
int      netx_dso_unload            (NETXPLIB plibrary);
int      netx_load_winsock          (NETXCON *pcon, int context);
int      netx_tcp_connect           (NETXCON *pcon, int context);
int      netx_tcp_connect_ex        (NETXCON *pcon, xLPSOCKADDR p_srv_addr, socklen_netx srv_addr_len, int timeout);
int      netx_tcp_disconnect        (NETXCON *pcon, int context);
int      netx_tcp_write             (NETXCON *pcon, unsigned char *data, int size);
int      netx_tcp_read              (NETXCON *pcon, unsigned char *data, int size, int timeout, int context);
int      netx_get_last_error        (int context);
int      netx_get_error_message     (int error_code, char *message, int size, int context);
int      netx_get_std_error_message (int error_code, char *message, int size, int context);
int      netx_enter_critical_section(void *p_crit);
int      netx_leave_critical_section(void *p_crit);



#if defined(_WIN32)
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
   switch (fdwReason)
   { 
      case DLL_PROCESS_ATTACH:
         InitializeCriticalSection(&netx_async_mutex);
         break;
      case DLL_THREAD_ATTACH:
         break;
      case DLL_THREAD_DETACH:
         break;
      case DLL_PROCESS_DETACH:
         DeleteCriticalSection(&netx_async_mutex);
         break;
   }
   return TRUE;
}
#endif


class server : public node::ObjectWrap
{

private:

   int         s_count;
   short       binary;

public:

   char        ip_address[64];
   int         port;
   NETXCON     *pcon;
   char        trace_dev[128];
   short       trace;
   FILE        *pftrace;

   static Persistent<Function> s_ct;

#if NETX_NODE_VERSION >= 100000
   static void Init(Local<Object> exports)
#else
   static void Init(Handle<Object> exports)
#endif
   {
      Isolate* isolate = Isolate::GetCurrent();
      Local<FunctionTemplate> t = FunctionTemplate::New(isolate, New);
      t->SetClassName(netx_new_string8(isolate, (char *) "server", 1));
      t->InstanceTemplate()->SetInternalFieldCount(1);

      NODE_SET_PROTOTYPE_METHOD(t, "version", version);
      NODE_SET_PROTOTYPE_METHOD(t, "settrace", settrace);
      NODE_SET_PROTOTYPE_METHOD(t, "connect", connect);
      NODE_SET_PROTOTYPE_METHOD(t, "read", read);
      NODE_SET_PROTOTYPE_METHOD(t, "readbin", readbinary);
      NODE_SET_PROTOTYPE_METHOD(t, "readbinary", readbinary);
      NODE_SET_PROTOTYPE_METHOD(t, "write", write);
      NODE_SET_PROTOTYPE_METHOD(t, "writebin", writebinary);
      NODE_SET_PROTOTYPE_METHOD(t, "writebinary", writebinary);
      NODE_SET_PROTOTYPE_METHOD(t, "http", http);
      NODE_SET_PROTOTYPE_METHOD(t, "disconnect", disconnect);

#if NETX_NODE_VERSION >= 120000
      Local<Context> icontext = isolate->GetCurrentContext();
      s_ct.Reset(isolate, t->GetFunction(icontext).ToLocalChecked());
      exports->Set(icontext, netx_new_string8(isolate, (char *) "server", 1), t->GetFunction(icontext).ToLocalChecked()).FromJust();
#else
      s_ct.Reset(isolate, t->GetFunction());
      exports->Set(netx_new_string8(isolate, (char *) "server", 1), t->GetFunction());
#endif



      return;
   }


   server() :
      s_count(0)
   {
   }


   ~server()
   {
   }


   static void New(const FunctionCallbackInfo<Value>& args)
   {
      int narg;
      Isolate* isolate = Isolate::GetCurrent();
#if NETX_NODE_VERSION >= 100000
      Local<Context> icontext = isolate->GetCurrentContext();
#endif
      HandleScope scope(isolate);

      server *s = new server();
      s->Wrap(args.This());

      narg = args.Length();
      if (narg < 2) {
         isolate->ThrowException(Exception::TypeError(netx_new_string8(isolate, (char *) "Unable to process arguments", 1)));
         return;
      }

      Local<String> ip = NETX_TO_STRING(args[0]);
      netx_write_char8(isolate, ip, s->ip_address, 1);
      s->port = (int) NETX_INT32_VALUE(args[1]);
      s->pcon = NULL;
      s->pftrace = NULL;
      s->trace = 0;
      s->trace_dev[0] = '\0';

      args.GetReturnValue().Set(args.This());

      return;
   }


   struct netx_baton_t {
      server                  *s;
      int                     increment_by;
      Persistent<Function>    cb;
      Isolate                 *isolate;
   };


   static netx_baton_t * netx_make_baton(server *s, int js_narg, const FunctionCallbackInfo<Value>& args)
   {
      netx_baton_t *baton;

      baton = new netx_baton_t();

      if (!baton) {
         netx_destroy_baton(baton);
         return NULL;
      }

      baton->increment_by = 1;
      baton->s = s;

      return baton;
   }


   static int netx_destroy_baton(netx_baton_t *baton)
   {
      if (baton) {
         delete baton;
      }

      return 0;
   }


   /* v1.2.12 */
   static int netx_queue_task(void *work_cb, void *after_work_cb, netx_baton_t *baton, short context)
   {
      uv_work_t *_req = new uv_work_t;
      _req->data = baton;

      /* v1.2.12 */
#if NETX_NODE_VERSION >= 120000
      uv_queue_work(GetCurrentEventLoop(baton->isolate), _req, (uv_work_cb) work_cb, (uv_after_work_cb) after_work_cb);
#else
      uv_queue_work(uv_default_loop(), _req, (uv_work_cb) work_cb, (uv_after_work_cb) after_work_cb);
#endif

      return 0;
   }


   static int netx_string8_length(Isolate * isolate, Local<String> str, int utf8)
   {
      if (utf8) {
#if NETX_NODE_VERSION >= 120000
         return str->Utf8Length(isolate);
#else
         return str->Utf8Length();
#endif
      }
      else {
         return str->Length();
      }
   }


   static Local<String> netx_new_string8(Isolate * isolate, char * buffer, int utf8)
   {
      if (utf8) {
#if NETX_NODE_VERSION >= 120000
         return String::NewFromUtf8(isolate, buffer, NewStringType::kNormal).ToLocalChecked();
#elif NETX_NODE_VERSION >= 1200
         return String::NewFromUtf8(isolate, buffer);
#else
         return String::NewFromUtf8(buffer);
#endif
      }
      else {
#if NETX_NODE_VERSION >= 100000
         return String::NewFromOneByte(isolate, (uint8_t *) buffer, NewStringType::kInternalized).ToLocalChecked();
#elif NETX_NODE_VERSION >= 1200
         return String::NewFromOneByte(isolate, (uint8_t *) buffer);
#else
         return String::New(buffer);
#endif
      }
   }


   static Local<String> netx_new_string8n(Isolate * isolate, char * buffer, unsigned long len, int utf8)
   {
      if (utf8) {
#if NETX_NODE_VERSION >= 120000
         return String::NewFromUtf8(isolate, buffer, NewStringType::kNormal, len).ToLocalChecked();
#elif NETX_NODE_VERSION >= 1200
         return String::NewFromUtf8(isolate, buffer, String::kNormalString, len);
#else
         return String::NewFromUtf8(buffer, len);
#endif
      }
      else {
#if NETX_NODE_VERSION >= 100000
         return String::NewFromOneByte(isolate, (uint8_t *) buffer, NewStringType::kInternalized, len).ToLocalChecked();
#elif NETX_NODE_VERSION >= 1200
         return String::NewFromOneByte(isolate, (uint8_t *) buffer, String::kNormalString, len);
#else
         return String::New(buffer);
#endif
      }
   }


   static int netx_write_char8(v8::Isolate * isolate, Local<String> str, char * buffer, int utf8)
   {
      if (utf8) {
#if NETX_NODE_VERSION >= 120000
         return str->WriteUtf8(isolate, buffer);
#else
         return str->WriteUtf8(buffer);
#endif
      }
      else {
#if NETX_NODE_VERSION >= 120000
         return str->WriteOneByte(isolate, (uint8_t *) buffer);
#elif NETX_NODE_VERSION >= 1200
         return str->WriteOneByte((uint8_t *) buffer);
#else
         return str->WriteAscii((char *) buffer);
#endif
      }
   }


   static void netx_invoke_callback(uv_work_t *req, int status)
   {
      Isolate* isolate = Isolate::GetCurrent();
      HandleScope scope(isolate);

      netx_baton_t *baton = static_cast<netx_baton_t *>(req->data);
      baton->s->Unref();
      Local<Value> argv[2];

      if (baton->s->pcon->error[0]) {
         argv[0] = Integer::New(isolate, true);
      }
      else {
         argv[0] = Integer::New(isolate, false);
      }
      argv[1] = netx_result_object(baton->s, 1);

#if NETX_NODE_VERSION >= 40000
      TryCatch try_catch(isolate);
#else
      TryCatch try_catch;
#endif

      Local<Function> cb = Local<Function>::New(isolate, baton->cb);

#if NETX_NODE_VERSION >= 120000
      /* cb->Call(isolate->GetCurrentContext(), isolate->GetCurrentContext()->Global(), 2, argv); */
      cb->Call(isolate->GetCurrentContext(), Null(isolate), 2, argv).ToLocalChecked();
#else
      cb->Call(isolate->GetCurrentContext()->Global(), 2, argv);
#endif

#if NETX_NODE_VERSION >= 40000
      if (try_catch.HasCaught()) {
         FatalException(isolate, try_catch);
      }
#else
      if (try_catch.HasCaught()) {
         FatalException(isolate, try_catch);
      }
#endif

      baton->cb.Reset();
      netx_destroy_baton(baton);
      delete req;

      return;
   }


   static Local<Object> netx_result_object(server * s, int context)
   {
      Isolate* isolate = Isolate::GetCurrent();
#if NETX_NODE_VERSION >= 100000
      Local<Context> icontext = isolate->GetCurrentContext();
#endif
      EscapableHandleScope handle_scope(isolate);

      Local<String> key;
      Local<String> error;

      Local<Object> result = Object::New(isolate);

      if (s->pcon->error[0]) {
         key = netx_new_string8(isolate, (char *) NETX_STR_OK, 1);
         NETX_SET(result, key, Integer::New(isolate, false));

         error = netx_new_string8(isolate, s->pcon->error, 1);
         key = netx_new_string8(isolate, (char *) NETX_STR_ERRORMESSAGE, 1);
         NETX_SET(result, key, error);

         key = netx_new_string8(isolate, (char *) NETX_STR_ERRORCODE, 1);
         NETX_SET(result, key, Integer::New(isolate, s->pcon->error_no));

         if (s->pcon->method == NETX_METHOD_HTTP || s->pcon->method == NETX_METHOD_READ) {
            s->pcon->eof = 1;
            key = netx_new_string8(isolate, (char *) NETX_STR_EOF, 1);
            NETX_SET(result, key, Integer::New(isolate, s->pcon->eof));
         }
         if (s->pcon->method == NETX_METHOD_HTTP) {
            key = netx_new_string8(isolate, (char *) NETX_STR_CONTENT, 1);
            NETX_SET(result, key, netx_new_string8(isolate, (char *) "", 1));
         }
         else if (s->pcon->method == NETX_METHOD_READ) {
            key = netx_new_string8(isolate, (char *) NETX_STR_DATA, 1);
            NETX_SET(result, key, netx_new_string8(isolate, (char *) "", 1));
         }


      }
      else {
         key = netx_new_string8(isolate, (char *) NETX_STR_OK, 1);
         NETX_SET(result, key, Integer::New(isolate, true));

         if (s->pcon->info[0]) {
            key = netx_new_string8(isolate, (char *) NETX_STR_INFORMATION, 1);
            NETX_SET(result, key, netx_new_string8(isolate, (char *) s->pcon->info, 1));
         }

         if (s->pcon->method == NETX_METHOD_HTTP) {
            key = netx_new_string8(isolate, (char *) NETX_STR_KEEPALIVE, 1);
            NETX_SET(result, key, Integer::New(isolate, s->pcon->keepalive));

            key = netx_new_string8(isolate, (char *) NETX_STR_EOF, 1);
            NETX_SET(result, key, Integer::New(isolate, s->pcon->eof));
            if (s->pcon->hlen) {
               key = netx_new_string8(isolate, (char *) NETX_STR_HEADERS, 1);
               NETX_SET(result, key, netx_new_string8n(isolate, (char *) s->pcon->recv_buf, s->pcon->hlen, 1));
               key = netx_new_string8(isolate, (char *) NETX_STR_CONTENT, 1);
               NETX_SET(result, key, netx_new_string8n(isolate, (char *) (s->pcon->recv_buf + s->pcon->hlen), s->pcon->recv_buf_len- s->pcon->hlen, 1));
            }
            else {
               key = netx_new_string8(isolate, (char *) NETX_STR_CONTENT, 1);
               NETX_SET(result, key, netx_new_string8n(isolate, (char *) s->pcon->recv_buf, s->pcon->recv_buf_len, 1));
            }
         }
         else if (s->pcon->method == NETX_METHOD_READ) {
            key = netx_new_string8(isolate, (char *) NETX_STR_EOF, 1);
            NETX_SET(result, key, Integer::New(isolate, s->pcon->eof));
            key = netx_new_string8(isolate, (char *) NETX_STR_DATA, 1);
            NETX_SET(result, key, netx_new_string8n(isolate, (char *) s->pcon->recv_buf, s->pcon->recv_buf_len, s->binary ? 0 : 1));
         }
      }

      return handle_scope.Escape(result);
   }


   static void version(const FunctionCallbackInfo<Value>& args)
   {
      Isolate* isolate = args.GetIsolate();
      HandleScope scope(isolate);
      int narg;
      char buffer[245];

      server * s = ObjectWrap::Unwrap<server>(args.This());
      s->s_count ++;

      narg = args.Length();
      if (narg > 0) {
         isolate->ThrowException(Exception::TypeError(netx_new_string8(isolate, (char *) "The version method does not take any arguments", 1)));
         return;
      }

      sprintf(buffer, "%d.%d.%d", NETX_VERSION_MAJOR, NETX_VERSION_MINOR, NETX_VERSION_BUILD);
      Local<String> result = netx_new_string8(isolate, buffer, 1);
      args.GetReturnValue().Set(result);

      return;
   }


static void settrace(const FunctionCallbackInfo<Value>& args)
   {
      Isolate* isolate = args.GetIsolate();
#if NETX_NODE_VERSION >= 100000
      Local<Context> icontext = isolate->GetCurrentContext();
#endif
      HandleScope scope(isolate);
      int narg, result;
      char buffer[245];

      server * s = ObjectWrap::Unwrap<server>(args.This());
      s->s_count ++;

      narg = args.Length();
      if (narg < 1) {
         isolate->ThrowException(Exception::TypeError(netx_new_string8(isolate, (char *) "The settrace method takes one argument", 1)));
         return;
      }

      netx_write_char8(isolate, NETX_TO_STRING(args[0]), buffer, 1);

      result = 0;
      if (buffer[0] == '0') {
         if (s->pftrace) {
            fprintf(s->pftrace, "\r\n");
            fflush(s->pftrace);
            fclose(s->pftrace);
         }
         s->trace = 0;
         s->pftrace = NULL;
         s->trace_dev[0] = '\0';
      }
      else {
         if (buffer[0] == '1' || !strcmp(buffer, "stdout")) {
            s->trace = 1;
            s->pftrace = stdout;
         }
         else if (buffer[0] != '0') {
            s->trace = 1;
            s->pftrace = fopen(buffer, "a");
            if (s->pftrace) {
               fprintf(s->pftrace, "\r\n-> fopen(%s, \"a\") (Trace file opened)", buffer);
               fflush(s->pftrace);
               strcpy(s->trace_dev, buffer);
            }
            else {
               result = -1;
               s->pftrace = stdout;
               fprintf(s->pftrace, "\r\n-> fopen(%s, \"a\") (Cannot open trace file specified - using stdout instead)", buffer);
               fflush(s->pftrace);
            }
         }
      }

      if (s->pcon) {
         s->pcon->trace = s->trace;
         s->pcon->pftrace = s->pftrace;
      }

      args.GetReturnValue().Set(Integer::New(isolate, result));

      return;
   }


   static void connect(const FunctionCallbackInfo<Value>& args)
   {
      Isolate* isolate = args.GetIsolate();
      HandleScope scope(isolate);
      short async;
      int narg;

      server * s = ObjectWrap::Unwrap<server>(args.This());
      s->s_count ++;

      if (!s->pcon) {
         s->pcon = (NETXCON *) netx_malloc(sizeof(NETXCON), 0);

         if (!s->pcon) {
            isolate->ThrowException(Exception::TypeError(netx_new_string8(isolate, (char *) "Unable to allocate connection memory block", 1)));
            return;
         }
         memset((void *) s->pcon, 0, sizeof(NETXCON));

         s->pcon->trace = s->trace;
         s->pcon->pftrace = s->pftrace;

         s->pcon->send_buf = (unsigned char *) netx_malloc(sizeof(char) * NETX_RECV_BUFFER, 0);
         if (!s->pcon->send_buf) {
            isolate->ThrowException(Exception::TypeError(netx_new_string8(isolate, (char *) "Unable to allocate memory for send buffer", 1)));
            return;
         }
         s->pcon->send_buf[0] = '\0';
         s->pcon->send_buf_size = NETX_RECV_BUFFER - 1;
         s->pcon->recv_buf = (unsigned char *) netx_malloc(sizeof(char) * NETX_RECV_BUFFER, 0);
         if (!s->pcon->recv_buf) {
            isolate->ThrowException(Exception::TypeError(netx_new_string8(isolate, (char *) "Unable to allocate memory for recv buffer", 1)));
            return;
         }
         s->pcon->recv_buf[0] = '\0';
         s->pcon->recv_buf_size = NETX_RECV_BUFFER - 1;
      }

      s->pcon->timeout = NETX_TIMEOUT;
      s->pcon->method = NETX_METHOD_CONNECT;

      narg = args.Length();
      if (narg < 0) {
         isolate->ThrowException(Exception::TypeError(netx_new_string8(isolate, (char *)"Unable to process arguments", 1)));
         return;
      }
      if (narg > 0 && args[narg - 1]->IsFunction()) {
         async = 1;
         narg --;
      }
      else {
         async = 0;
      }

      strcpy(s->pcon->ip_address, s->ip_address);
      s->pcon->port = s->port;

      if (async) {

         Local<Function> cb = Local<Function>::Cast(args[narg]);
         netx_baton_t *baton = netx_make_baton(s, narg, args);
         baton->isolate = isolate;
         baton->cb.Reset(isolate, cb);

         s->Ref();

         netx_queue_task((void *) EIO_connect, (void *) netx_invoke_callback, baton, 0); /* v1.2.12 */

         return;
      }

      netx_connect(s->pcon);
      Local<Object> result = netx_result_object(s, 0);
      args.GetReturnValue().Set(result);

      return;
   }


   static void EIO_connect(uv_work_t *req)
   {
      netx_baton_t *baton = static_cast<netx_baton_t *>(req->data);

      netx_connect(baton->s->pcon);
      baton->s->s_count += baton->increment_by;

      return;
   }


   static void read(const FunctionCallbackInfo<Value>& args)
   {
      read_ex(args, 0);
      return;
   }


   static void readbinary(const FunctionCallbackInfo<Value>& args)
   {
      read_ex(args, 1);
      return;
   }


   static void read_ex(const FunctionCallbackInfo<Value>& args, short binary)
   {
      Isolate* isolate = args.GetIsolate();
#if NETX_NODE_VERSION >= 100000
      Local<Context> icontext = isolate->GetCurrentContext();
#endif
      HandleScope scope(isolate);
      short async;
      int narg;

      server * s = ObjectWrap::Unwrap<server>(args.This());
      s->s_count ++;
      s->binary = binary;

      if (!s->pcon) {
         isolate->ThrowException(Exception::TypeError(netx_new_string8(isolate, (char *) "No connection to server established", 1)));
         return;
      }

      s->pcon->method = NETX_METHOD_READ;

      narg = args.Length();
      if (narg < 0) {
         isolate->ThrowException(Exception::TypeError(netx_new_string8(isolate, (char *) "Unable to process arguments", 1)));
         return;
      }
      if (narg > 0 && args[narg - 1]->IsFunction()) {
         async = 1;
         narg --;
      }
      else {
         async = 0;
      }

      Local<Object> request;

      Local<String> length_name = netx_new_string8(isolate, (char *) NETX_STR_LENGTH, 1);
      Local<String> timeout_name = netx_new_string8(isolate, (char *) NETX_STR_TIMEOUT, 1);

      netx_init_vars(s->pcon);

      if (narg && args[0]->IsObject()) {
         request = NETX_TO_OBJECT(args[0]);

         if (!NETX_GET(request, length_name)->IsUndefined()) {
            s->pcon->length = NETX_INT32_VALUE(NETX_GET(request, length_name));

         }
         if (!NETX_GET(request, timeout_name)->IsUndefined()) {
            s->pcon->length = NETX_INT32_VALUE(NETX_GET(request, timeout_name));
         }
      }

      if (async) {

         Local<Function> cb = Local<Function>::Cast(args[narg]);
         netx_baton_t *baton = netx_make_baton(s, narg, args);
         baton->isolate = isolate;
         baton->cb.Reset(isolate, cb);

         s->Ref();

         netx_queue_task((void *) EIO_read, (void *) netx_invoke_callback, baton, 0); /* v1.2.12 */

         return;
      }

      netx_read(s->pcon);
      Local<Object> result = netx_result_object(s, 0);
      args.GetReturnValue().Set(result);

      return;
   }


   static void EIO_read(uv_work_t *req)
   {
      netx_baton_t *baton = static_cast<netx_baton_t *>(req->data);

      netx_read(baton->s->pcon);
      baton->s->s_count += baton->increment_by;

      return;
   }


   static void write(const FunctionCallbackInfo<Value>& args)
   {
      write_ex(args, 0);
      return;
   }


   static void writebinary(const FunctionCallbackInfo<Value>& args)
   {
      write_ex(args, 1);
      return;
   }


   static void write_ex(const FunctionCallbackInfo<Value>& args, short binary)   {
      Isolate* isolate = args.GetIsolate();
#if NETX_NODE_VERSION >= 100000
      Local<Context> icontext = isolate->GetCurrentContext();
#endif
      HandleScope scope(isolate);
      short async;
      int narg;

      server * s = ObjectWrap::Unwrap<server>(args.This());
      s->s_count ++;
      s->binary = binary;
      if (!s->pcon) {
         isolate->ThrowException(Exception::TypeError(netx_new_string8(isolate, (char *) "No connection to server established", 1)));
         return;
      }

      s->pcon->method = NETX_METHOD_WRITE;

      narg = args.Length();
      if (narg < 0) {
         isolate->ThrowException(Exception::TypeError(netx_new_string8(isolate, (char *) "Unable to process arguments", 1)));
         return;
      }
      if (narg > 0 && args[narg - 1]->IsFunction()) {
         async = 1;
         narg --;
      }
      else {
         async = 0;
      }

      Local<Object> request;

      Local<String> content_name = netx_new_string8(isolate, (char *) NETX_STR_DATA, 1);
      Local<String> content_value;

      netx_init_vars(s->pcon);

      if (args[0]->IsObject()) {
         request = NETX_TO_OBJECT(args[0]);

         if (!NETX_GET(request, content_name)->IsUndefined()) {
            content_value = NETX_TO_STRING(NETX_GET(request, content_name));
            s->pcon->send_buf_len = content_value->Length();
            if (s->pcon->send_buf_len >= s->pcon->send_buf_size) {
               if (netx_resize(s->pcon, &(s->pcon->send_buf), &(s->pcon->send_buf_size), 0, s->pcon->send_buf_len + 32) < 0) {
                  isolate->ThrowException(Exception::TypeError(netx_new_string8(isolate, (char *) "Unable to allocate memory for send buffer", 1)));
                  return;
               }
            }
            netx_write_char8(isolate, content_value, (char *) s->pcon->send_buf, s->binary ? 0 : 1);
         }
         else {
            isolate->ThrowException(Exception::TypeError(netx_new_string8(isolate, (char *) "Missing 'data' property", 1)));
            return;
         }
      }
      else {
         isolate->ThrowException(Exception::TypeError(netx_new_string8(isolate, (char *) "Missing data object", 1)));
         return;
      }

      if (async) {

         Local<Function> cb = Local<Function>::Cast(args[narg]);
         netx_baton_t *baton = netx_make_baton(s, narg, args);
         baton->isolate = isolate;
         baton->cb.Reset(isolate, cb);

         s->Ref();

         netx_queue_task((void *) EIO_write, (void *) netx_invoke_callback, baton, 0); /* v1.2.12 */

         return;
      }

      netx_write(s->pcon);
      Local<Object> result = netx_result_object(s, 0);
      args.GetReturnValue().Set(result);

      return;
   }


   static void EIO_write(uv_work_t *req)
   {
      netx_baton_t *baton = static_cast<netx_baton_t *>(req->data);

      netx_write(baton->s->pcon);
      baton->s->s_count += baton->increment_by;

      return;
   }


   static void http(const FunctionCallbackInfo<Value>& args)
   {
      Isolate* isolate = args.GetIsolate();
#if NETX_NODE_VERSION >= 100000
      Local<Context> icontext = isolate->GetCurrentContext();
#endif
      HandleScope scope(isolate);

      short async;
      int narg;

      server * s = ObjectWrap::Unwrap<server>(args.This());
      s->s_count ++;
      if (!s->pcon) {
         isolate->ThrowException(Exception::TypeError(netx_new_string8(isolate, (char *) "No connection to server established", 1)));
         return;
      }
      if (s->pcon->connected == 0) {
         isolate->ThrowException(Exception::TypeError(netx_new_string8(isolate, (char *) "Disconnected from server", 1)));
         return;
      }

      s->pcon->method = NETX_METHOD_HTTP;

      narg = args.Length();
      if (narg < 1) {
         isolate->ThrowException(Exception::TypeError(netx_new_string8(isolate, (char *) "Unable to process arguments", 1)));
         return;
      }
      if (narg > 1 && args[narg - 1]->IsFunction()) {
         async = 1;
         narg --;
      }
      else {
         async = 0;
      }

      Local<Object> request;

      Local<String> headers_name = netx_new_string8(isolate, (char *) NETX_STR_HEADERS, 1);
      Local<String> headers_value;

      Local<String> content_name = netx_new_string8(isolate, (char *) NETX_STR_CONTENT, 1);
      Local<String> content_value;

      Local<String> length_name = netx_new_string8(isolate, (char *) NETX_STR_LENGTH, 1);
      Local<String> timeout_name = netx_new_string8(isolate, (char *) NETX_STR_TIMEOUT, 1);

      netx_init_vars(s->pcon);

      if (args[0]->IsObject()) {
         int hlen, clen;

         hlen = 0;
         clen = 0;
         request = NETX_TO_OBJECT(args[0]);
         if (!NETX_GET(request, headers_name)->IsUndefined()) {
            headers_value = NETX_TO_STRING(NETX_GET(request, headers_name));
            hlen = headers_value->Length();
         }
         else {
            isolate->ThrowException(Exception::TypeError(netx_new_string8(isolate, (char *) "Missing 'headers' property", 1)));
            return;
         }

         if (!NETX_GET(request, content_name)->IsUndefined()) {
            content_value = NETX_TO_STRING(NETX_GET(request, content_name));
            clen = content_value->Length();
         }

         if ((hlen + clen) >= s->pcon->send_buf_size) {
            if (netx_resize(s->pcon, &(s->pcon->send_buf), &(s->pcon->send_buf_size), 0, hlen + clen + 32) < 0) {
               isolate->ThrowException(Exception::TypeError(netx_new_string8(isolate, (char *) "Unable to allocate memory for send buffer", 1)));
               return;
            }
         }
         netx_write_char8(isolate, headers_value, (char *) s->pcon->send_buf, 1);

         if (clen) {
            netx_write_char8(isolate, content_value, (char *) s->pcon->send_buf + hlen, 1);
         }
         s->pcon->send_buf_len = hlen + clen;

         if (!NETX_GET(request, length_name)->IsUndefined()) {
            s->pcon->length = NETX_INT32_VALUE(NETX_GET(request, length_name));
         }
         if (!NETX_GET(request, timeout_name)->IsUndefined()) {
            s->pcon->length = NETX_INT32_VALUE(NETX_GET(request, timeout_name));
         }
      }
      else {
         isolate->ThrowException(Exception::TypeError(netx_new_string8(isolate, (char *) "Missing request object", 1)));
         return;
      }

      if (async) {

         Local<Function> cb = Local<Function>::Cast(args[narg]);
         netx_baton_t *baton = netx_make_baton(s, narg, args);
         baton->isolate = isolate;
         baton->cb.Reset(isolate, cb);

         s->Ref();

         netx_queue_task((void *) EIO_http, (void *) netx_invoke_callback, baton, 0); /* v1.2.12 */

         return;
      }

      netx_http(s->pcon);

      Local<Object> result = netx_result_object(s, 0);
      args.GetReturnValue().Set(result);

      return;
   }


   static void EIO_http(uv_work_t *req)
   {
      netx_baton_t *baton = static_cast<netx_baton_t *>(req->data);

      netx_http(baton->s->pcon);
      baton->s->s_count += baton->increment_by;

      return;
   }


   static void disconnect(const FunctionCallbackInfo<Value>& args)
   {
      Isolate* isolate = args.GetIsolate();
      HandleScope scope(isolate);
      short async;
      int narg;

      server * s = ObjectWrap::Unwrap<server>(args.This());
      s->s_count ++;
      if (!s->pcon) {
         isolate->ThrowException(Exception::TypeError(netx_new_string8(isolate, (char *) "No connection to server established", 1)));
         return;
      }

      s->pcon->method = NETX_METHOD_DISCONNECT;

      narg = args.Length();
      if (narg < 0) {
         isolate->ThrowException(Exception::TypeError(netx_new_string8(isolate, (char *) "Unable to process arguments", 1)));
         return;
      }
      if (narg > 0 && args[narg - 1]->IsFunction()) {
         async = 1;
         narg --;
      }
      else {
         async = 0;
      }

      if (async) {

         Local<Function> cb = Local<Function>::Cast(args[narg]);
         netx_baton_t *baton = netx_make_baton(s, narg, args);
         baton->isolate = isolate;
         baton->cb.Reset(isolate, cb);

         s->Ref();

         netx_queue_task((void *) EIO_disconnect, (void *) netx_invoke_callback, baton, 0); /* v1.2.12 */

         return;
      }

      netx_disconnect(s->pcon);

      Local<Object> result = netx_result_object(s, 0);
      args.GetReturnValue().Set(result);

      return;
   }


   static void EIO_disconnect(uv_work_t *req)
   {
      netx_baton_t *baton = static_cast<netx_baton_t *>(req->data);

      netx_disconnect(baton->s->pcon);

      baton->s->s_count += baton->increment_by;

      return;
   }

};


/* v1.2.11 */
#if NETX_NODE_VERSION >= 120000
class netx_addon_data
{

public:

   netx_addon_data(Isolate* isolate, Local<Object> exports):
      call_count(0) {
         /* Link the existence of this object instance to the existence of exports. */
         exports_.Reset(isolate, exports);
         exports_.SetWeak(this, DeleteMe, WeakCallbackType::kParameter);
      }

   ~netx_addon_data() {
      if (!exports_.IsEmpty()) {
         /* Reset the reference to avoid leaking data. */
         exports_.ClearWeak();
         exports_.Reset();
      }
   }

   /* Per-addon data. */
   int call_count;

private:

   /* Method to call when "exports" is about to be garbage-collected. */
   static void DeleteMe(const WeakCallbackInfo<netx_addon_data>& info) {
      delete info.GetParameter();
   }

   /*
   Weak handle to the "exports" object. An instance of this class will be
   destroyed along with the exports object to which it is weakly bound.
   */
   v8::Persistent<v8::Object> exports_;
};
#endif


Persistent<Function> server::s_ct;


extern "C" {
#if defined(_WIN32)
#if NETX_NODE_VERSION >= 100000
void __declspec(dllexport) init (Local<Object> exports)
#else
void __declspec(dllexport) init (Handle<Object> exports)
#endif
#else
#if NETX_NODE_VERSION >= 100000
static void init (Local<Object> exports)
#else
static void init (Handle<Object> exports)
#endif
#endif
 {
   server::Init(exports);
 }

#if NETX_NODE_VERSION >= 120000

/* exports, module, context */
extern "C" NODE_MODULE_EXPORT void
NODE_MODULE_INITIALIZER(Local<Object> exports,
                        Local<Value> module,
                        Local<Context> context) {
   Isolate* isolate = context->GetIsolate();

   /* Create a new instance of netx_addon_data for this instance of the addon. */
   netx_addon_data * data = new netx_addon_data(isolate, exports);
   /* Wrap the data in a v8::External so we can pass it to the method we expose. */
   /* Local<External> external = External::New(isolate, data); */
   External::New(isolate, data);

   init(exports);

   /*
   Expose the method "Method" to JavaScript, and make sure it receives the
   per-addon-instance data we created above by passing `external` as the
   third parameter to the FunctionTemplate constructor.
   exports->Set(context, String::NewFromUtf8(isolate, "method", NewStringType::kNormal).ToLocalChecked(), FunctionTemplate::New(isolate, Method, external)->GetFunction(context).ToLocalChecked()).FromJust();
   */

}

#else

  NODE_MODULE(server, init)

#endif
}


int netx_connect(NETXCON *pcon)
{
   int rc;

   if (pcon->trace == 1) {
      fprintf(pcon->pftrace, "\r\n-> netx_connect");
      fflush(pcon->pftrace);
   }

#if defined(_WIN32)
   netx_enter_critical_section((void *) &netx_async_mutex);
   if (netx_so.winsock_ready == 0) {

      rc = netx_load_winsock(pcon, 0);
      if (rc) {
         netx_leave_critical_section((void *) &netx_async_mutex);
         return 0;
      }
   }
   netx_leave_critical_section((void *) &netx_async_mutex);
#endif
   if (pcon->connected) {
      rc = 0;
      strcpy(pcon->info, "Already connected to server");
   }
   else {
      rc = netx_tcp_connect(pcon, 0);
   }

   if (rc) {
      return 0;
   }

   return rc;
}


int netx_read(NETXCON *pcon)
{
   int rc, block;

   if (pcon->trace == 1) {
      fprintf(pcon->pftrace, "\r\n-> netx_read");
      fflush(pcon->pftrace);
   }

   if (pcon->connected == 0) {
      strcpy(pcon->error, "Disconnected from server");
      return -1;
   }

   if (pcon->length) {
      block = 0;
      pcon->recv_buf_len = pcon->length;
      if (pcon->recv_buf_len >= pcon->recv_buf_size) {
         if (netx_resize(pcon, &(pcon->recv_buf), &(pcon->recv_buf_size), 0, pcon->recv_buf_len + 32) < 0)
            return -1;
      }
   }
   else {
      block = 0;
      pcon->recv_buf_len = pcon->recv_buf_size - 2;
   }

   rc = netx_tcp_read(pcon, (unsigned char *) pcon->recv_buf, (int)  pcon->recv_buf_len,  pcon->timeout, block);
   if (rc < 0) {
      return rc;
   } 

   if (rc > 0) {
      pcon->recv_buf_len = rc;
      pcon->recv_buf[pcon->recv_buf_len] = '\0';
   }
   else {
      pcon->recv_buf_len = 0;
      pcon->recv_buf[0] = '\0';
   }

   return rc;
}


int netx_write(NETXCON *pcon)
{
   int rc;

   if (pcon->trace == 1) {
      fprintf(pcon->pftrace, "\r\n-> netx_write");
      fflush(pcon->pftrace);
   }

   if (pcon->connected == 0) {
      strcpy(pcon->error, "Disconnected from server");
      return -1;
   }

   rc = netx_tcp_write(pcon, (unsigned char *) pcon->send_buf, (int) pcon->send_buf_len);

   return rc;
}


int netx_http(NETXCON *pcon)
{
   int rc, size, clen, chunked, total, n, bsize, blen, bptr, bptrcz, avail, chunk_size, eof;
   char headers[2048], buffer[NETX_RECV_BUFFER];
   unsigned char *p, *p1;

   if (pcon->trace == 1) {
      fprintf(pcon->pftrace, "\r\n-> netx_http");
      fflush(pcon->pftrace);
   }

   if (pcon->connected == 0) {
      strcpy(pcon->error, "Disconnected from server");
      return -1;
   }

   rc = netx_tcp_write(pcon, (unsigned char *) pcon->send_buf, (int) pcon->send_buf_len);
   if (rc < 0) {
      return rc;
   }

   pcon->eof = 0;
   pcon->hlen = 0;
   pcon->keepalive = 1;

   p = NULL;
   headers[0] = '\0';
   clen = 0;
   chunked = 0;
   eof = 0;
   size = NETX_RECV_BUFFER - 2;
   pcon->recv_buf_len = 0;
   for (;;) {
      rc = netx_tcp_read(pcon, (unsigned char *) (pcon->recv_buf + pcon->recv_buf_len), (int) (size - pcon->recv_buf_len), pcon->timeout, 0);
      if (rc < 1) {
         eof = 1;
         break;
      }

      pcon->recv_buf_len += rc;
      pcon->recv_buf[pcon->recv_buf_len] = '\0';

      p = (unsigned char *) strstr((char *) pcon->recv_buf, "\r\n\r\n");
      if (p) {
         pcon->hlen = (int) (p - pcon->recv_buf) + 4;
         if (pcon->hlen > 2040)
            pcon->hlen = 2040;
         strncpy(headers, (char *) pcon->recv_buf, pcon->hlen);
         headers[pcon->hlen] = '\0';
         break;
      }
      if (pcon->recv_buf_len == size) {
         break;
      }
   }

   if (eof || pcon->recv_buf_len == 0) {
      strcpy(pcon->error, "No response from server.  Previous request may have closed the connection (check 'HTTP keepalive' status)");
      rc = -1;
      goto netx_http_exit;
   }

   if (headers[0]) {
      netx_lcase(headers);

      p = (unsigned char *) strstr(headers, "content-length");
      if (p) {
         p = (unsigned char *) strstr((char *) p, ":");
         if (p) {
            while (*(++ p) == ' ')
               ;
            clen = (int) strtol((char *) p, NULL, 10);
         }
      }
      p = (unsigned char *) strstr(headers, "transfer-encoding");
      if (p) {
         p = (unsigned char *) strstr((char *) p, ":");
         if (p) {
            while (*(++ p) == ' ')
               ;
            p1 = (unsigned char *) strstr((char *) p, "\r\n");
            if (p1) {
               *p1 = '\0';
               if (strstr((char *) p, "chunked")) {
                  chunked = 1;
               }
               *p1 = '\r';
            }
         }
      }
      p = (unsigned char *) strstr(headers, "connection");
      if (p) {
         p = (unsigned char *) strstr((char *) p, ":");
         if (p) {
            while (*(++ p) == ' ')
               ;
            p1 = (unsigned char *) strstr((char *) p, "\r\n");
            if (p1) {
               *p1 = '\0';
               if (strstr((char *) p, "close")) {
                  pcon->keepalive = 0;
               }
               *p1 = '\r';
            }
         }
      }
   }

   if (clen) {
      total = pcon->hlen + clen;
      if (total >= pcon->recv_buf_size) {
         if (netx_resize(pcon, &(pcon->recv_buf), &(pcon->recv_buf_size), pcon->recv_buf_len, total + 32) < 0) {
            eof = 1;
            rc = -1;
            goto netx_http_exit;
         }
      }
      if (total > pcon->recv_buf_len) {
         rc = netx_tcp_read(pcon, (unsigned char *) (pcon->recv_buf + pcon->recv_buf_len), (int) (total - pcon->recv_buf_len), pcon->timeout, 1);
         if (rc < 1) {
            eof = 1;
            goto netx_http_exit;
         }
         pcon->recv_buf_len += rc;
      }
   }

   else if (chunked) {
      bsize = NETX_RECV_BUFFER - 2;
      blen = pcon->recv_buf_len - pcon->hlen;
      bptr = 0;
      memcpy((void *) buffer, (void *) (pcon->recv_buf + pcon->hlen), blen);
      buffer[blen] = '\0';

      pcon->recv_buf_len = pcon->hlen; /* reset to end of header */

      for (;;) {
         if (bptr >= blen) {
            bptr = 0;
            blen = 0;
         }
         else if (bptr > (bsize - 32)) {
            n = 0;
            avail = (blen - bptr);
            while (bptr < blen) {
               buffer[n ++] = buffer[bptr ++];
            }
            bptr = 0;
            blen = avail;
         }
         bptrcz = 0;
         for (;;) {
            if (bptr < blen) {
               while (buffer[bptr] == '\r' || buffer[bptr] == '\n')
                  bptr ++;
               for (n = bptr; n < blen; n ++) {
                  if (n > 1 &&  buffer[n - 1] == '\r' && buffer[n] == '\n') {
                     bptrcz = (n - 1);
                     break;
                  }
               }
               if (bptrcz) {
                  break;
               }
            }
            rc = netx_tcp_read(pcon, (unsigned char *) buffer + blen, (int) bsize - blen, pcon->timeout, 0);
            if (rc < 1) {
               eof = 1;
               break;
            }
            blen += rc;
         }

         if (eof && blen == 0) {
            break;
         }

         if (bptrcz) {
            buffer[bptrcz] = '\0';
            chunk_size = (int) strtol((char *) (buffer + bptr), NULL, 16);
            if (chunk_size == 0) {
               break;
            }
            bptr = bptrcz + 2;
            total = pcon->recv_buf_len + chunk_size;
            if (total >= pcon->recv_buf_size) {
               if (netx_resize(pcon, &(pcon->recv_buf), &(pcon->recv_buf_size), pcon->recv_buf_len, total + 32) < 0) {
                  eof = 1;
                  rc = -1;
                  break;
               }
            }
            for (;;) {
               avail = (blen - bptr);
               if (avail < chunk_size) {
                  memcpy((void *) (pcon->recv_buf + pcon->recv_buf_len), (void *) (buffer + bptr), avail);
                  pcon->recv_buf_len += avail;
                  bptr += avail;
                  chunk_size -= avail;
               }
               else {
                  memcpy((void *) (pcon->recv_buf + pcon->recv_buf_len), (void *) (buffer + bptr), chunk_size);
                  pcon->recv_buf_len += chunk_size;
                  bptr += chunk_size;
                  chunk_size = 0;
                  break;
               }
               if (bptr >= blen) {
                  rc = netx_tcp_read(pcon, (unsigned char *) buffer, (int) bsize, pcon->timeout, 0);
                  if (rc < 1) {
                     eof = 1;
                     break;
                  }
                  blen = rc;
                  bptr = 0;
               } 
            }
            if (eof) {
               break;
            }
         }
      }
   }

   else if (!eof) {
      total = 4096;
      while (eof == 0) {
         if ((pcon->recv_buf_len + total) >= pcon->recv_buf_size) {
            if (netx_resize(pcon, &(pcon->recv_buf), &(pcon->recv_buf_size), pcon->recv_buf_len, pcon->recv_buf_size + total + 32) < 0) {
               eof = 1;
               rc = -1;
               break;
            }
         }
         rc = netx_tcp_read(pcon, (unsigned char *) (pcon->recv_buf + pcon->recv_buf_len), (int) total, pcon->timeout, 0);
         if (rc < 1) {
            eof = 1;
            break;
         }
         pcon->recv_buf_len += rc;
      }
   }

netx_http_exit:

/*
   printf("\r\n *** eof=%d; clen=%d; chunked=%d; hlen=%d; pcon->recv_buf_len=%d; %d\r\n\r\n", eof, clen, chunked, pcon->hlen, pcon->recv_buf_len, clen + pcon->hlen);
*/
   return rc;
}


int netx_disconnect(NETXCON *pcon)
{
   int rc;

   if (pcon->trace == 1) {
      fprintf(pcon->pftrace, "\r\n-> netx_disconnect");
      fflush(pcon->pftrace);
   }

   rc = netx_tcp_disconnect(pcon, 0); 

   if (pcon->trace == 1) {
      fprintf(pcon->pftrace, "\r\n\r\n");
      fflush(pcon->pftrace);
   }

   return rc;
}


int netx_init_vars(NETXCON *pcon)
{
   pcon->timeout = NETX_TIMEOUT;
   pcon->length = 0;
   pcon->eof = 0;
   pcon->hlen = 0;
   pcon->keepalive = 0;
   pcon->send_buf[0] = '\0';
   pcon->send_buf_len = 0;
   pcon->recv_buf[0] = '\0';
   pcon->recv_buf_len = 0;
   pcon->error[0] = '\0';
   pcon->info[0] = '\0';
   pcon->error_no = 0;

   return 0;
}


int netx_format_buffer(char *obuffer, char *ibuffer, int len, int max)
{
   int ni, no;
   unsigned int c;
   char buffer[32];

   if (len < 0)
      len = 0;

   obuffer[0] = '\0';
   no = 0;
   for (ni = 0; ni < len; ni ++) {
      c = (unsigned int) ibuffer[ni];
      if ((c < 32) || (c > 126)) {
         sprintf(buffer, "\\x%02x", c);
         strcpy(obuffer + no, buffer);
         no += (int) strlen(buffer);
      }
      else {
         obuffer[no ++] = (char) c;
      }
   }
   obuffer[no] = '\0';

   return no;
}


int netx_ucase(char *string)
{
   int n, chr;

   n = 0;
   while (string[n] != '\0') {
      chr = (int) string[n];
      if (chr >= 97 && chr <= 122)
         string[n] = (char) (chr - 32);
      n ++;
   }
   return 1;
}


int netx_lcase(char *string)
{
   int n, chr;

   n = 0;
   while (string[n] != '\0') {
      chr = (int) string[n];
      if (chr >= 65 && chr <= 90)
         string[n] = (char) (chr + 32);
      n ++;
   }
   return 1;
}


void * netx_malloc(int size, short id)
{
   void *p;

   p = (void *) malloc(size);

   return p;
}


int netx_free(void *p, short id)
{
   free((void *) p);

   return 0;
}


NETXPLIB netx_dso_load(char * library)
{
   NETXPLIB plibrary;

#if defined(_WIN32)
   plibrary = LoadLibraryA(library);
#else
   plibrary = dlopen(library, RTLD_NOW);
#endif

   return plibrary;
}


int netx_resize(NETXCON *pcon, unsigned char **ppbuf, int *psize, int retain, int size)
{
   int rc;
   unsigned char *p;
   p = *ppbuf;

   *ppbuf = (unsigned char *) netx_malloc(sizeof(char) * (size + 32), 0);
   if (*ppbuf) {
      if (retain) {
         memcpy((void *) *ppbuf, (void *) p, retain);
      }
      netx_free((void *) p, 0);
      *psize = size;
      rc = 0;
   }
   else {
      *ppbuf = p;
      if (pcon) {
         strcpy(pcon->error, "No Memory");
      }
      rc = -1;
   }
   return rc;
}


NETXPROC netx_dso_sym(NETXPLIB plibrary, char * symbol)
{
   NETXPROC pproc;

#if defined(_WIN32)
   pproc = GetProcAddress(plibrary, symbol);
#else
   pproc  = (void *) dlsym(plibrary, symbol);
#endif

   return pproc;
}



int netx_dso_unload(NETXPLIB plibrary)
{

#if defined(_WIN32)
   FreeLibrary(plibrary);
#else
   dlclose(plibrary); 
#endif

   return 1;
}


int netx_load_winsock(NETXCON *pcon, int context)
{
#if defined(_WIN32)
   int result, mem_locked;
   char buffer[1024];

   result = 0;
   mem_locked = 0;
   *buffer = '\0';
   netx_so.version_requested = 0;

   if (netx_so.load_attempted)
      return result;

   if (netx_so.load_attempted)
      goto netx_load_winsock_no_so;

   netx_so.sock = 0;

   /* Try to Load the Winsock 2 library */

   netx_so.winsock = 2;
   strcpy(netx_so.libnam, "WS2_32.DLL");

   netx_so.plibrary = netx_dso_load(netx_so.libnam);

   if (pcon->trace == 1) {
      fprintf(pcon->pftrace, "\r\n       >>> %p==netx_dso_load(%s)", netx_so.plibrary, netx_so.libnam);
      fflush(pcon->pftrace);
   }

   if (!netx_so.plibrary) {
      netx_so.winsock = 1;
      strcpy(netx_so.libnam, "WSOCK32.DLL");
      netx_so.plibrary = netx_dso_load(netx_so.libnam);

      if (pcon->trace == 1) {
         fprintf(pcon->pftrace, "\r\n       >>> %p==netx_dso_load(%s)", netx_so.plibrary, netx_so.libnam);
         fflush(pcon->pftrace);
      }

      if (!netx_so.plibrary) {
         goto netx_load_winsock_no_so;
      }
   }

   netx_so.p_WSASocket             = (LPFN_WSASOCKET)              netx_dso_sym(netx_so.plibrary, "WSASocketA");
   netx_so.p_WSAGetLastError       = (LPFN_WSAGETLASTERROR)        netx_dso_sym(netx_so.plibrary, "WSAGetLastError");
   netx_so.p_WSAStartup            = (LPFN_WSASTARTUP)             netx_dso_sym(netx_so.plibrary, "WSAStartup");
   netx_so.p_WSACleanup            = (LPFN_WSACLEANUP)             netx_dso_sym(netx_so.plibrary, "WSACleanup");
   netx_so.p_WSAFDIsSet            = (LPFN_WSAFDISSET)             netx_dso_sym(netx_so.plibrary, "__WSAFDIsSet");
   netx_so.p_WSARecv               = (LPFN_WSARECV)                netx_dso_sym(netx_so.plibrary, "WSARecv");
   netx_so.p_WSASend               = (LPFN_WSASEND)                netx_dso_sym(netx_so.plibrary, "WSASend");

#if defined(NETX_IPV6)
   netx_so.p_WSAStringToAddress    = (LPFN_WSASTRINGTOADDRESS)     netx_dso_sym(netx_so.plibrary, "WSAStringToAddressA");
   netx_so.p_WSAAddressToString    = (LPFN_WSAADDRESSTOSTRING)     netx_dso_sym(netx_so.plibrary, "WSAAddressToStringA");
   netx_so.p_getaddrinfo           = (LPFN_GETADDRINFO)            netx_dso_sym(netx_so.plibrary, "getaddrinfo");
   netx_so.p_freeaddrinfo          = (LPFN_FREEADDRINFO)           netx_dso_sym(netx_so.plibrary, "freeaddrinfo");
   netx_so.p_getnameinfo           = (LPFN_GETNAMEINFO)            netx_dso_sym(netx_so.plibrary, "getnameinfo");
   netx_so.p_getpeername           = (LPFN_GETPEERNAME)            netx_dso_sym(netx_so.plibrary, "getpeername");
   netx_so.p_inet_ntop             = (LPFN_INET_NTOP)              netx_dso_sym(netx_so.plibrary, "InetNtop");
   netx_so.p_inet_pton             = (LPFN_INET_PTON)              netx_dso_sym(netx_so.plibrary, "InetPton");
#else
   netx_so.p_WSAStringToAddress    = NULL;
   netx_so.p_WSAAddressToString    = NULL;
   netx_so.p_getaddrinfo           = NULL;
   netx_so.p_freeaddrinfo          = NULL;
   netx_so.p_getnameinfo           = NULL;
   netx_so.p_getpeername           = NULL;
   netx_so.p_inet_ntop             = NULL;
   netx_so.p_inet_pton             = NULL;
#endif

   netx_so.p_closesocket           = (LPFN_CLOSESOCKET)            netx_dso_sym(netx_so.plibrary, "closesocket");
   netx_so.p_gethostname           = (LPFN_GETHOSTNAME)            netx_dso_sym(netx_so.plibrary, "gethostname");
   netx_so.p_gethostbyname         = (LPFN_GETHOSTBYNAME)          netx_dso_sym(netx_so.plibrary, "gethostbyname");
   netx_so.p_getservbyname         = (LPFN_GETSERVBYNAME)          netx_dso_sym(netx_so.plibrary, "getservbyname");
   netx_so.p_gethostbyaddr         = (LPFN_GETHOSTBYADDR)          netx_dso_sym(netx_so.plibrary, "gethostbyaddr");
   netx_so.p_htons                 = (LPFN_HTONS)                  netx_dso_sym(netx_so.plibrary, "htons");
   netx_so.p_htonl                 = (LPFN_HTONL)                  netx_dso_sym(netx_so.plibrary, "htonl");
   netx_so.p_ntohl                 = (LPFN_NTOHL)                  netx_dso_sym(netx_so.plibrary, "ntohl");
   netx_so.p_ntohs                 = (LPFN_NTOHS)                  netx_dso_sym(netx_so.plibrary, "ntohs");
   netx_so.p_connect               = (LPFN_CONNECT)                netx_dso_sym(netx_so.plibrary, "connect");
   netx_so.p_inet_addr             = (LPFN_INET_ADDR)              netx_dso_sym(netx_so.plibrary, "inet_addr");
   netx_so.p_inet_ntoa             = (LPFN_INET_NTOA)              netx_dso_sym(netx_so.plibrary, "inet_ntoa");

   netx_so.p_socket                = (LPFN_SOCKET)                 netx_dso_sym(netx_so.plibrary, "socket");
   netx_so.p_setsockopt            = (LPFN_SETSOCKOPT)             netx_dso_sym(netx_so.plibrary, "setsockopt");
   netx_so.p_getsockopt            = (LPFN_GETSOCKOPT)             netx_dso_sym(netx_so.plibrary, "getsockopt");
   netx_so.p_getsockname           = (LPFN_GETSOCKNAME)            netx_dso_sym(netx_so.plibrary, "getsockname");

   netx_so.p_select                = (LPFN_SELECT)                 netx_dso_sym(netx_so.plibrary, "select");
   netx_so.p_recv                  = (LPFN_RECV)                   netx_dso_sym(netx_so.plibrary, "recv");
   netx_so.p_send                  = (LPFN_SEND)                   netx_dso_sym(netx_so.plibrary, "send");
   netx_so.p_shutdown              = (LPFN_SHUTDOWN)               netx_dso_sym(netx_so.plibrary, "shutdown");
   netx_so.p_bind                  = (LPFN_BIND)                   netx_dso_sym(netx_so.plibrary, "bind");
   netx_so.p_listen                = (LPFN_LISTEN)                 netx_dso_sym(netx_so.plibrary, "listen");
   netx_so.p_accept                = (LPFN_ACCEPT)                 netx_dso_sym(netx_so.plibrary, "accept");

   if (   (netx_so.p_WSASocket              == NULL && netx_so.winsock == 2)
       ||  netx_so.p_WSAGetLastError        == NULL
       ||  netx_so.p_WSAStartup             == NULL
       ||  netx_so.p_WSACleanup             == NULL
       ||  netx_so.p_WSAFDIsSet             == NULL
       || (netx_so.p_WSARecv                == NULL && netx_so.winsock == 2)
       || (netx_so.p_WSASend                == NULL && netx_so.winsock == 2)

#if defined(NETX_IPV6)
       || (netx_so.p_WSAStringToAddress     == NULL && netx_so.winsock == 2)
       || (netx_so.p_WSAAddressToString     == NULL && netx_so.winsock == 2)
       ||  netx_so.p_getpeername            == NULL
#endif

       ||  netx_so.p_closesocket            == NULL
       ||  netx_so.p_gethostname            == NULL
       ||  netx_so.p_gethostbyname          == NULL
       ||  netx_so.p_getservbyname          == NULL
       ||  netx_so.p_gethostbyaddr          == NULL
       ||  netx_so.p_htons                  == NULL
       ||  netx_so.p_htonl                  == NULL
       ||  netx_so.p_ntohl                  == NULL
       ||  netx_so.p_ntohs                  == NULL
       ||  netx_so.p_connect                == NULL
       ||  netx_so.p_inet_addr              == NULL
       ||  netx_so.p_inet_ntoa              == NULL
       ||  netx_so.p_socket                 == NULL
       ||  netx_so.p_setsockopt             == NULL
       ||  netx_so.p_getsockopt             == NULL
       ||  netx_so.p_getsockname            == NULL
       ||  netx_so.p_select                 == NULL
       ||  netx_so.p_recv                   == NULL
       ||  netx_so.p_send                   == NULL
       ||  netx_so.p_shutdown               == NULL
       ||  netx_so.p_bind                   == NULL
       ||  netx_so.p_listen                 == NULL
       ||  netx_so.p_accept                 == NULL
      ) {

      sprintf(buffer, "Cannot use Winsock library (WSASocket=%p; WSAGetLastError=%p; WSAStartup=%p; WSACleanup=%p; WSAFDIsSet=%p; WSARecv=%p; WSASend=%p; WSAStringToAddress=%p; WSAAddressToString=%p; closesocket=%p; gethostname=%p; gethostbyname=%p; getservbyname=%p; gethostbyaddr=%p; getaddrinfo=%p; freeaddrinfo=%p; getnameinfo=%p; getpeername=%p; htons=%p; htonl=%p; ntohl=%p; ntohs=%p; connect=%p; inet_addr=%p; inet_ntoa=%p; socket=%p; setsockopt=%p; getsockopt=%p; getsockname=%p; select=%p; recv=%p; p_send=%p; shutdown=%p; bind=%p; listen=%p; accept=%p;)",
            netx_so.p_WSASocket,
            netx_so.p_WSAGetLastError,
            netx_so.p_WSAStartup,
            netx_so.p_WSACleanup,
            netx_so.p_WSAFDIsSet,
            netx_so.p_WSARecv,
            netx_so.p_WSASend,

            netx_so.p_WSAStringToAddress,
            netx_so.p_WSAAddressToString,

            netx_so.p_closesocket,
            netx_so.p_gethostname,
            netx_so.p_gethostbyname,
            netx_so.p_getservbyname,
            netx_so.p_gethostbyaddr,

            netx_so.p_getaddrinfo,
            netx_so.p_freeaddrinfo,
            netx_so.p_getnameinfo,
            netx_so.p_getpeername,

            netx_so.p_htons,
            netx_so.p_htonl,
            netx_so.p_ntohl,
            netx_so.p_ntohs,
            netx_so.p_connect,
            netx_so.p_inet_addr,
            netx_so.p_inet_ntoa,
            netx_so.p_socket,
            netx_so.p_setsockopt,
            netx_so.p_getsockopt,
            netx_so.p_getsockname,
            netx_so.p_select,
            netx_so.p_recv,
            netx_so.p_send,
            netx_so.p_shutdown,
            netx_so.p_bind,
            netx_so.p_listen,
            netx_so.p_accept
            );
      netx_dso_unload((NETXPLIB) netx_so.plibrary);
   }
   else {
      netx_so.sock = 1;
   }

   if (netx_so.sock)
      result = 0;
   else
      result = -1;

   netx_so.load_attempted = 1;

   if (netx_so.p_getaddrinfo == NULL ||  netx_so.p_freeaddrinfo == NULL ||  netx_so.p_getnameinfo == NULL)
      netx_so.ipv6 = 0;

netx_load_winsock_no_so:

   if (result == 0) {

      if (netx_so.winsock == 2)
         netx_so.version_requested = MAKEWORD(2, 2);
      else
         netx_so.version_requested = MAKEWORD(1, 1);

      netx_so.wsastartup = NETX_WSASTARTUP(netx_so.version_requested, &(netx_so.wsadata));
      if (pcon->trace == 1) {
         fprintf(pcon->pftrace, "\r\n      -> %d<=WSAStartup(%d, %p)", netx_so.wsastartup, netx_so.version_requested, &(netx_so.wsadata));
         fflush(pcon->pftrace);
      }

      if (netx_so.wsastartup != 0 && netx_so.winsock == 2) {
         netx_so.version_requested = MAKEWORD(2, 0);
         netx_so.wsastartup = NETX_WSASTARTUP(netx_so.version_requested, &(netx_so.wsadata));
         if (netx_so.wsastartup != 0) {
            netx_so.winsock = 1;
            netx_so.version_requested = MAKEWORD(1, 1);
            netx_so.wsastartup = NETX_WSASTARTUP(netx_so.version_requested, &(netx_so.wsadata));
         }
      }
      if (netx_so.wsastartup == 0) {
         if ((netx_so.winsock == 2 && LOBYTE(netx_so.wsadata.wVersion) != 2)
               || (netx_so.winsock == 1 && (LOBYTE(netx_so.wsadata.wVersion) != 1 || HIBYTE(netx_so.wsadata.wVersion) != 1))) {
  
            sprintf(pcon->error, "Initialization Error: Wrong version of Winsock library (%s) (%d.%d)", netx_so.libnam, LOBYTE(netx_so.wsadata.wVersion), HIBYTE(netx_so.wsadata.wVersion));
            NETX_WSACLEANUP();
            netx_so.wsastartup = -1;
         }
         else {
            if (strlen(netx_so.libnam))
               sprintf(pcon->info, "Initialization: Windows Sockets library loaded (%s) Version: %d.%d", netx_so.libnam, LOBYTE(netx_so.wsadata.wVersion), HIBYTE(netx_so.wsadata.wVersion));
            else
               sprintf(pcon->info, "Initialization: Windows Sockets library Version: %d.%d", LOBYTE(netx_so.wsadata.wVersion), HIBYTE(netx_so.wsadata.wVersion));
            netx_so.winsock_ready = 1;
         }
      }
      else {
         strcpy(pcon->error, "Initialization Error: Unusable Winsock library");
      }
   }

   return result;

#else

   return 0;

#endif /* #if defined(_WIN32) */

}


int netx_tcp_connect(NETXCON *pcon, int context)
{
   short physical_ip, ipv6, connected, getaddrinfo_ok;
   int n, errorno;
   unsigned long inetaddr;
   DWORD spin_count;
   char ansi_ip_address[64];
   struct sockaddr_in srv_addr, cli_addr;
   struct hostent *hp;
   struct in_addr **pptr;

   pcon->connected = 0;
   pcon->error_no = 0;
   connected = 0;
   getaddrinfo_ok = 0;
   spin_count = 0;

   ipv6 = 1;
#if !defined(NETX_IPV6)
   ipv6 = 0;
#endif

   if (pcon->trace == 1) {
      fprintf(pcon->pftrace, "\r\n   -> netx_tcp_connect(ip=%s, port=%d)", pcon->ip_address, pcon->port);
      fflush(pcon->pftrace);
   }

   strcpy(ansi_ip_address, (char *) pcon->ip_address);

#if defined(_WIN32)

   n = netx_so.wsastartup;
   if (n != 0) {
      strcpy(pcon->error, (char *) "DLL Load Error: Unusable Winsock Library");
      return n;
   }

#endif /* #if defined(_WIN32) */

#if defined(NETX_IPV6)

   if (ipv6) {
      short mode;
      struct addrinfo hints, *res;
      struct addrinfo *ai;
      char port_str[32];

      res = NULL;
      sprintf(port_str, "%d", pcon->port);
      connected = 0;
      pcon->error_no = 0;

      for (mode = 0; mode < 3; mode ++) {

         if (res) {
            NETX_FREEADDRINFO(res);
            if (pcon->trace == 1) {
               fprintf(pcon->pftrace, "\r\n      -> (void)<=freeaddrinfo(%p)", res);
               fflush(pcon->pftrace);
            }
            res = NULL;
         }

         memset(&hints, 0, sizeof hints);
         hints.ai_family = AF_UNSPEC;     /* Use IPv4 or IPv6 */
         hints.ai_socktype = SOCK_STREAM;
         /* hints.ai_flags = AI_PASSIVE; */
         if (mode == 0)
            hints.ai_flags = AI_NUMERICHOST | AI_CANONNAME;
         else if (mode == 1)
            hints.ai_flags = AI_CANONNAME;
         else if (mode == 2) {
            /* Apparently an error can occur with AF_UNSPEC (See RJW1564) */
            /* This iteration will return IPV6 addresses if any */
            hints.ai_flags = AI_CANONNAME;
            hints.ai_family = AF_INET6;
         }
         else
            break;

         n = NETX_GETADDRINFO(ansi_ip_address, port_str, &hints, &res);
         if (pcon->trace == 1) {
            fprintf(pcon->pftrace, "\r\n      -> %d<=getaddrinfo(%s, %s, %p, %p)", n, ansi_ip_address, port_str, &hints, &res);
            fflush(pcon->pftrace);
         }

         if (n != 0) {
            continue;
         }

         getaddrinfo_ok = 1;
         spin_count = 0;
         for (ai = res; ai != NULL; ai = ai->ai_next) {

            spin_count ++;

	         if (ai->ai_family != AF_INET && ai->ai_family != AF_INET6) {
               continue;
            }

	         /* Open a socket with the correct address family for this address. */
	         pcon->cli_socket = NETX_SOCKET(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
            if (pcon->trace == 1) {
               fprintf(pcon->pftrace, "\r\n      -> %d<=socket(%d, %d, %d)", (int) pcon->cli_socket, ai->ai_family, ai->ai_socktype, ai->ai_protocol);
               fflush(pcon->pftrace);
            }

            /* NETX_BIND(pcon->cli_socket, ai->ai_addr, (int) (ai->ai_addrlen)); */
            /* NETX_CONNECT(pcon->cli_socket, ai->ai_addr, (int) (ai->ai_addrlen)); */

            if (netx_so.nagle_algorithm == 0) {

               int flag = 1;
               int result;

               result = NETX_SETSOCKOPT(pcon->cli_socket, IPPROTO_TCP, TCP_NODELAY, (const char *) &flag, sizeof(int));
               if (pcon->trace == 1) {
                  fprintf(pcon->pftrace, "\r\n      -> %d<=setsockopt(%d, %d, %d, %p, %d)", result, (int) pcon->cli_socket, IPPROTO_TCP, TCP_NODELAY, (const char *) &flag, (int) sizeof(int));
                  fflush(pcon->pftrace);
               }

               if (result < 0) {
                  strcpy(pcon->error, "Connection Error: Unable to disable the Nagle Algorithm");
               }

            }

            pcon->error_no = 0;
            n = netx_tcp_connect_ex(pcon, (xLPSOCKADDR) ai->ai_addr, (socklen_netx) (ai->ai_addrlen), pcon->timeout);
            if (n == -2) {
               pcon->error_no = n;
               n = -737;
               continue;
            }
            if (SOCK_ERROR(n)) {
               errorno = (int) netx_get_last_error(0);
               pcon->error_no = errorno;
               netx_tcp_disconnect(pcon, 0);
               continue;
            }
            else {
               connected = 1;
               break;
            }
         }
         if (connected)
            break;
      }

      if (pcon->error_no) {
         char message[256];
         netx_get_error_message(pcon->error_no, message, 250, 0);
         sprintf(pcon->error, "Connection Error: Cannot Connect to Server (%s:%d): Error Code: %d (%s)", (char *) pcon->ip_address, pcon->port, pcon->error_no, message);
         n = -5;
      }

      if (res) {
         NETX_FREEADDRINFO(res);
         res = NULL;
      }
   }
#endif

   if (ipv6) {
      if (connected) {
         pcon->connected = 1;
         return 0;
      }
      else {
         if (getaddrinfo_ok) {
            netx_tcp_disconnect(pcon, 0);
            return -5;
         }
         else {
            char message[256];

            errorno = (int) netx_get_last_error(0);
            netx_get_error_message(errorno, message, 250, 0);
            sprintf(pcon->error, "Connection Error: Cannot identify Server: Error Code: %d (%s)", errorno, message);
            netx_tcp_disconnect(pcon, 0);
            return -5;
         }
      }
   }

   ipv6 = 0;
   inetaddr = NETX_INET_ADDR(ansi_ip_address);
   if (pcon->trace == 1) {
      fprintf(pcon->pftrace, "\r\n      -> %lu<=inet_addr(%s)", inetaddr, ansi_ip_address);
      fflush(pcon->pftrace);
   }

   physical_ip = 0;
   if (isdigit(ansi_ip_address[0])) {
      char *p;

      if ((p = strstr(ansi_ip_address, "."))) {
         if (isdigit(*(++ p))) {
            if ((p = strstr(p, "."))) {
               if (isdigit(*(++ p))) {
                  if ((p = strstr(p, "."))) {
                     if (isdigit(*(++ p))) {
                        physical_ip = 1;
                     }
                  }
               }
            }
         }
      }
   }

   if (inetaddr == INADDR_NONE || !physical_ip) {

      hp = NETX_GETHOSTBYNAME((const char *) ansi_ip_address);
      if (pcon->trace == 1) {
         fprintf(pcon->pftrace, "\r\n      -> %p<=gethostbyname(%s)", hp, ansi_ip_address);
         fflush(pcon->pftrace);
      }
      if (hp == NULL) {
         n = -2;
         strcpy(pcon->error, "Connection Error: Invalid Host");
         return n;
      }

      pptr = (struct in_addr **) hp->h_addr_list;
      connected = 0;

      spin_count = 0;

      for (; *pptr != NULL; pptr ++) {

         spin_count ++;

         pcon->cli_socket = NETX_SOCKET(AF_INET, SOCK_STREAM, 0);
         if (pcon->trace == 1) {
            fprintf(pcon->pftrace, "\r\n      -> %d<=socket(%d, %d, %d)", (int) pcon->cli_socket, AF_INET, SOCK_STREAM, 0);
            fflush(pcon->pftrace);
         }

         if (INVALID_SOCK(pcon->cli_socket)) {
            char message[256];

            n = -2;
            errorno = (int) netx_get_last_error(0);
            netx_get_error_message(errorno, message, 250, 0);
            sprintf(pcon->error, "Connection Error: Invalid Socket: Context=1: Error Code: %d (%s)", errorno, message);
            break;
         }

#if !defined(_WIN32)
         BZERO((char *) &cli_addr, sizeof(cli_addr));
         BZERO((char *) &srv_addr, sizeof(srv_addr));
#endif

         cli_addr.sin_family = AF_INET;
         srv_addr.sin_port = NETX_HTONS((unsigned short) pcon->port);
         if (pcon->trace == 1) {
            fprintf(pcon->pftrace, "\r\n      -> %d<=htons(%d)", (int) srv_addr.sin_port, (int) pcon->port);
            fflush(pcon->pftrace);
         }

         cli_addr.sin_addr.s_addr = NETX_HTONL(INADDR_ANY);
         cli_addr.sin_port = NETX_HTONS(0);

         n = NETX_BIND(pcon->cli_socket, (xLPSOCKADDR) &cli_addr, sizeof(cli_addr));
         if (pcon->trace == 1) {
            fprintf(pcon->pftrace, "\r\n      -> %d<=bind(%d, %p, %lu)", n, (int) pcon->cli_socket, &cli_addr, (unsigned long) sizeof(cli_addr));
            fflush(pcon->pftrace);
         }

         if (SOCK_ERROR(n)) {
            char message[256];

            n = -3;
            errorno = (int) netx_get_last_error(0);
            netx_get_error_message(errorno, message, 250, 0);
            sprintf(pcon->error, "Connection Error: Cannot bind to Socket: Error Code: %d (%s)", errorno, message);

            break;
         }

         if (netx_so.nagle_algorithm == 0) {

            int flag = 1;
            int result;

            result = NETX_SETSOCKOPT(pcon->cli_socket, IPPROTO_TCP, TCP_NODELAY, (const char *) &flag, sizeof(int));
            if (result < 0) {
               strcpy(pcon->error, "Connection Error: Unable to disable the Nagle Algorithm");
            }
         }

         srv_addr.sin_family = AF_INET;
         srv_addr.sin_port = NETX_HTONS((unsigned short) pcon->port);
         if (pcon->trace == 1) {
            fprintf(pcon->pftrace, "\r\n      -> %d<=htons(%d)", (int) srv_addr.sin_port, (int) pcon->port);
            fflush(pcon->pftrace);
         }

         NETX_MEMCPY(&srv_addr.sin_addr, *pptr, sizeof(struct in_addr));

         n = netx_tcp_connect_ex(pcon, (xLPSOCKADDR) &srv_addr, sizeof(srv_addr), pcon->timeout);

         if (n == -2) {
            pcon->error_no = n;
            n = -737;

            continue;
         }

         if (SOCK_ERROR(n)) {
            char message[256];

            errorno = (int) netx_get_last_error(0);
            netx_get_error_message(errorno, message, 250, 0);

            pcon->error_no = errorno;
            sprintf(pcon->error, "Connection Error: Cannot Connect to Server (%s:%d): Error Code: %d (%s)", (char *) pcon->ip_address, pcon->port, errorno, message);
            n = -5;
            netx_tcp_disconnect(pcon, 0);
            continue;
         }
         else {
            connected = 1;
            break;
         }
      }
      if (!connected) {

         netx_tcp_disconnect(pcon, 0);

         strcpy(pcon->error, "Connection Error: Failed to find the Server via a DNS Lookup");

         return n;
      }
   }
   else {

      pcon->cli_socket = NETX_SOCKET(AF_INET, SOCK_STREAM, 0);
      if (pcon->trace == 1) {
         fprintf(pcon->pftrace, "\r\n      -> %d<=socket(%d, %d, %d)", (int) pcon->cli_socket, AF_INET, SOCK_STREAM, 0);
         fflush(pcon->pftrace);
      }

      if (INVALID_SOCK(pcon->cli_socket)) {
         char message[256];

         n = -2;
         errorno = (int) netx_get_last_error(0);
         netx_get_error_message(errorno, message, 250, 0);
         sprintf(pcon->error, "Connection Error: Invalid Socket: Context=2: Error Code: %d (%s)", errorno, message);

         return n;
      }

#if !defined(_WIN32)
      BZERO((char *) &cli_addr, sizeof(cli_addr));
      BZERO((char *) &srv_addr, sizeof(srv_addr));
#endif

      cli_addr.sin_family = AF_INET;
      cli_addr.sin_addr.s_addr = NETX_HTONL(INADDR_ANY);
      cli_addr.sin_port = NETX_HTONS(0);

      n = NETX_BIND(pcon->cli_socket, (xLPSOCKADDR) &cli_addr, sizeof(cli_addr));
      if (pcon->trace == 1) {
         fprintf(pcon->pftrace, "\r\n      -> %d<=bind(%d, %p, %lu)", n, (int) pcon->cli_socket, &cli_addr, (unsigned long) sizeof(cli_addr));
         fflush(pcon->pftrace);
      }

      if (SOCK_ERROR(n)) {
         char message[256];

         n = -3;

         errorno = (int) netx_get_last_error(0);
         netx_get_error_message(errorno, message, 250, 0);

         sprintf(pcon->error, "Connection Error: Cannot bind to Socket: Error Code: %d (%s)", errorno, message);

         netx_tcp_disconnect(pcon, 0);

         return n;
      }

      if (netx_so.nagle_algorithm == 0) {

         int flag = 1;
         int result;

         result = NETX_SETSOCKOPT(pcon->cli_socket, IPPROTO_TCP, TCP_NODELAY, (const char *) &flag, sizeof(int));
         if (pcon->trace == 1) {
            fprintf(pcon->pftrace, "\r\n      -> %d<=setsockopt(%d, %d, %d, %p, %lu)", result, (int) pcon->cli_socket, IPPROTO_TCP, TCP_NODELAY, &flag, (unsigned long) sizeof(int));
            fflush(pcon->pftrace);
         }
         if (result < 0) {
            strcpy(pcon->error, "Connection Error: Unable to disable the Nagle Algorithm");

         }
      }

      srv_addr.sin_port = NETX_HTONS((unsigned short) pcon->port);
      srv_addr.sin_family = AF_INET;
      srv_addr.sin_addr.s_addr = NETX_INET_ADDR(ansi_ip_address);

      n = netx_tcp_connect_ex(pcon, (xLPSOCKADDR) &srv_addr, sizeof(srv_addr), pcon->timeout);
      if (n == -2) {
         pcon->error_no = n;
         n = -737;

         netx_tcp_disconnect(pcon, 0);

         return n;
      }

      if (SOCK_ERROR(n)) {
         char message[256];

         errorno = (int) netx_get_last_error(0);
         netx_get_error_message(errorno, message, 250, 0);
         pcon->error_no = errorno;
         sprintf(pcon->error, "Connection Error: Cannot Connect to Server (%s:%d): Error Code: %d (%s)", (char *) pcon->ip_address, pcon->port, errorno, message);
         n = -5;
         netx_tcp_disconnect(pcon, 0);
         return n;
      }
   }

   pcon->connected = 1;

   return 0;
}


int netx_tcp_connect_ex(NETXCON *pcon, xLPSOCKADDR p_srv_addr, socklen_netx srv_addr_len, int timeout)
{
#if defined(_WIN32)
   int n;
#else
   int flags, n, error;
   socklen_netx len;
   fd_set rset, wset;
   struct timeval tval;
#endif

#if defined(SOLARIS) && BIT64PLAT
   timeout = 0;
#endif

   /* It seems that BIT64PLAT is set to 0 for 64-bit Solaris:  So, to be safe .... */

#if defined(SOLARIS)
   timeout = 0;
#endif

   if (timeout != 0) {

#if defined(_WIN32)

      n = NETX_CONNECT(pcon->cli_socket, (xLPSOCKADDR) p_srv_addr, (socklen_netx) srv_addr_len);
      if (pcon->trace == 1) {
         fprintf(pcon->pftrace, "\r\n      -> %d<=connect(%d, %p, %d)", n, (int) pcon->cli_socket, p_srv_addr, (int) srv_addr_len);
         fflush(pcon->pftrace);
      }

      return n;

#else
      flags = fcntl(pcon->cli_socket, F_GETFL, 0);
      n = fcntl(pcon->cli_socket, F_SETFL, flags | O_NONBLOCK);
      if (pcon->trace == 1) {
         fprintf(pcon->pftrace, "\r\n      -> %d<=fnctl(%d, %d, %d)", n, (int) pcon->cli_socket, F_SETFL, flags | O_NONBLOCK);
         fflush(pcon->pftrace);
      }

      error = 0;

      n = NETX_CONNECT(pcon->cli_socket, (xLPSOCKADDR) p_srv_addr, (socklen_netx) srv_addr_len);
      if (pcon->trace == 1) {
         fprintf(pcon->pftrace, "\r\n      -> %d<=connect(%d, %p, %d)", n, (int) pcon->cli_socket, p_srv_addr, (int) srv_addr_len);
         fflush(pcon->pftrace);
      }

      if (n < 0) {

         if (errno != EINPROGRESS) {

#if defined(SOLARIS)

            if (errno != 2 && errno != 146) {
               sprintf((char *) pcon->error, "Diagnostic: Solaris: Initial Connection Error errno=%d; EINPROGRESS=%d", errno, EINPROGRESS);
               return -1;
            }
#else
            return -1;
#endif

         }
      }

      if (n != 0) {

         FD_ZERO(&rset);
         FD_SET(pcon->cli_socket, &rset);

         wset = rset;
         tval.tv_sec = timeout;
         tval.tv_usec = timeout;

         n = NETX_SELECT((int) (pcon->cli_socket + 1), &rset, &wset, NULL, &tval);

         if (n == 0) {
            close(pcon->cli_socket);
            errno = ETIMEDOUT;

            return (-2);
         }
         if (NETX_FD_ISSET(pcon->cli_socket, &rset) || NETX_FD_ISSET(pcon->cli_socket, &wset)) {

            len = sizeof(error);
            if (NETX_GETSOCKOPT(pcon->cli_socket, SOL_SOCKET, SO_ERROR, (void *) &error, &len) < 0) {

               sprintf((char *) pcon->error, "Diagnostic: Solaris: Pending Error %d", errno);

               return (-1);   /* Solaris pending error */
            }
         }
         else {
            ;
         }
      }

      fcntl(pcon->cli_socket, F_SETFL, flags);      /* Restore file status flags */

      if (error) {

         close(pcon->cli_socket);
         errno = error;
         return (-1);
      }

      return 1;

#endif

   }
   else {

      n = NETX_CONNECT(pcon->cli_socket, (xLPSOCKADDR) p_srv_addr, (socklen_netx) srv_addr_len);

      return n;
   }

}


int netx_tcp_disconnect(NETXCON *pcon, int context)
{
   int n;

   if (!pcon) {
      return 0;
   }

   if (pcon->cli_socket != (SOCKET) 0) {

#if defined(_WIN32)
      n = NETX_CLOSESOCKET(pcon->cli_socket);
/*
      NETX_WSACLEANUP();
*/
      if (pcon->trace == 1) {
         fprintf(pcon->pftrace, "\r\n      -> %d<=closesocket(%d)", n, (int) pcon->cli_socket);
         fflush(pcon->pftrace);
      }
#else
      n = close(pcon->cli_socket);
      if (pcon->trace == 1) {
         fprintf(pcon->pftrace, "\r\n      -> %d<=close(%d)", n, (int) pcon->cli_socket);
         fflush(pcon->pftrace);
      }
#endif

   }

   pcon->connected = 0;

   return 0;

}


int netx_tcp_write(NETXCON *pcon, unsigned char *data, int size)
{
   int n = 0, errorno = 0, char_sent = 0;
   int total;
   char errormessage[512];

   *errormessage = '\0';

   if (pcon->trace == 1) {
      fprintf(pcon->pftrace, "\r\n   -> netx_tcp_write(data=%p, size=%d)", data, size);
      fflush(pcon->pftrace);
   }

   if (pcon->connected == 0) {
      strcpy(pcon->error, "TCP Write Error: Socket is Closed");
      return -1;
   }

   total = 0;
   for (;;) {
      n = NETX_SEND(pcon->cli_socket, (xLPSENDBUF) (data + total), size - total, 0);

      if (pcon->trace == 1) {
         fprintf(pcon->pftrace, "\r\n      -> %d<=send(%d, %p, %d)", n, (int) pcon->cli_socket, data + total, size - total);
         fflush(pcon->pftrace);
         if (n > 0) {
            char buffer[256];
            netx_format_buffer(buffer, (char *) (data + total), n, 250);
            fprintf(pcon->pftrace, "\r\n         -> %s", buffer);
         }
      }

      if (SOCK_ERROR(n)) {

         errorno = (int) netx_get_last_error(0);

         if (NOT_BLOCKING(errorno) && errorno != 0) {

            char message[256];

            netx_get_error_message(errorno, message, 250, 0);
            sprintf(pcon->error, "TCP Write Error: Cannot Write Data: Error Code: %d (%s)", errorno, message);

            char_sent = -1;
            break;
         }
      }
      else {

         total += n;
         if (total == size) {
            break;
         }
      }
   }

   if (char_sent < 0)
      return char_sent;
   else
      return size;

}



int netx_tcp_read(NETXCON *pcon, unsigned char *data, int size, int timeout, int context)
{
   int result, n;
   int len;
   fd_set rset, eset;
   struct timeval tval;
   unsigned long spin_count;


   if (!pcon) {
      return NETX_READ_ERROR;
   }

   if (pcon->trace == 1) {
      fprintf(pcon->pftrace, "\r\n   -> netx_tcp_read(data=%p, size=%d, timeout=%d)", data, size, timeout);
      fflush(pcon->pftrace);
   }

   result = 0;

   tval.tv_sec = timeout;
   tval.tv_usec = 0;

   spin_count = 0;
   len = 0;
   for (;;) {
      spin_count ++;

      FD_ZERO(&rset);
      FD_ZERO(&eset);
      FD_SET(pcon->cli_socket, &rset);
      FD_SET(pcon->cli_socket, &eset);

      n = NETX_SELECT((int) (pcon->cli_socket + 1), &rset, NULL, &eset, &tval);

      if (pcon->trace == 1) {
         fprintf(pcon->pftrace, "\r\n      -> %d<=select(%d, %p, %p, %p, %p{tv_sec=%d; tv_usec=%d})", n, (int) pcon->cli_socket + 1, &rset, (void *) 0, &eset, &tval, (int) tval.tv_sec, (int) tval.tv_usec);
         fflush(pcon->pftrace);
      }

      if (n == 0) {
         sprintf(pcon->error, "TCP Read Error: Server did not respond within the timeout period (%d seconds)", timeout);
         result = NETX_READ_TIMEOUT;
         break;
      }

      if (n < 0 || !NETX_FD_ISSET(pcon->cli_socket, &rset)) {
          strcpy(pcon->error, "TCP Read Error: Server closed the connection without having returned any data");
          result = NETX_READ_ERROR;
         break;
      }

      n = NETX_RECV(pcon->cli_socket, (char *) data + len, size - len, 0);

      if (pcon->trace == 1) {
         fprintf(pcon->pftrace, "\r\n      -> %d<=recv(%d, %p, %d, 0)", n, (int) pcon->cli_socket, data + len, size - len);
         if (n > 0) {
            char buffer[256];
            netx_format_buffer(buffer, (char *) (data + len), n, 250);
            fprintf(pcon->pftrace, "\r\n         -> %s", buffer);
         }
         fflush(pcon->pftrace);
      }

      if (n < 1) {
         if (n == 0) {
            result = NETX_READ_EOF;
            pcon->connected = 0;
            pcon->eof = 1;
         }
         else {
            result = NETX_READ_ERROR;
            len = 0;
            pcon->connected = 0;
         }
         break;
      }

      len += n;
      if (context) { /* Must read length requested v1.1.10 */
         if (len == size) {
            break;
         }
      }
      else {
         break;
      }
   }

   if (len) {
      result = len;
   }
   return result;
}



int netx_get_last_error(int context)
{
   int error_code;

#if defined(_WIN32)
   if (context)
      error_code = (int) GetLastError();
   else
      error_code = (int) NETX_WSAGETLASTERROR();
#else
   error_code = (int) errno;
#endif

   return error_code;
}


int netx_get_error_message(int error_code, char *message, int size, int context)
{
   *message = '\0';

#if defined(_WIN32)

   if (context == 0) {
      short ok;
      int len;
      char *p;
      LPVOID lpMsgBuf;

      ok = 0;
      lpMsgBuf = NULL;
      len = FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                           NULL,
                           error_code,
                           /* MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), */
                           MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US),
                           (LPTSTR) &lpMsgBuf,
                           0,
                           NULL 
                           );
      if (len && lpMsgBuf) {
         strncpy(message, (const char *) lpMsgBuf, size);
         p = strstr(message, "\r\n");
         if (p)
            *p = '\0';
         ok = 1;
      }
      if (lpMsgBuf)
         LocalFree(lpMsgBuf);

      if (!ok) {
         switch (error_code) {
            case EXCEPTION_ACCESS_VIOLATION:
               strncpy(message, "The thread attempted to read from or write to a virtual address for which it does not have the appropriate access.", size);
               break;
            case EXCEPTION_BREAKPOINT:
               strncpy(message, "A breakpoint was encountered.", size); 
               break;
            case EXCEPTION_DATATYPE_MISALIGNMENT:
               strncpy(message, "The thread attempted to read or write data that is misaligned on hardware that does not provide alignment. For example, 16-bit values must be aligned on 2-byte boundaries, 32-bit values on 4-byte boundaries, and so on.", size);
               break;
            case EXCEPTION_SINGLE_STEP:
               strncpy(message, "A trace trap or other single-instruction mechanism signaled that one instruction has been executed.", size);
               break;
            case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
               strncpy(message, "The thread attempted to access an array element that is out of bounds, and the underlying hardware supports bounds checking.", size);
               break;
            case EXCEPTION_FLT_DENORMAL_OPERAND:
               strncpy(message, "One of the operands in a floating-point operation is denormal. A denormal value is one that is too small to represent as a standard floating-point value.", size);
               break;
            case EXCEPTION_FLT_DIVIDE_BY_ZERO:
               strncpy(message, "The thread attempted to divide a floating-point value by a floating-point divisor of zero.", size);
               break;
            case EXCEPTION_FLT_INEXACT_RESULT:
               strncpy(message, "The result of a floating-point operation cannot be represented exactly as a decimal fraction.", size);
               break;
            case EXCEPTION_FLT_INVALID_OPERATION:
               strncpy(message, "This exception represents any floating-point exception not included in this list.", size);
               break;
            case EXCEPTION_FLT_OVERFLOW:
               strncpy(message, "The exponent of a floating-point operation is greater than the magnitude allowed by the corresponding type.", size);
               break;
            case EXCEPTION_FLT_STACK_CHECK:
               strncpy(message, "The stack overflowed or underflowed as the result of a floating-point operation.", size);
               break;
            case EXCEPTION_FLT_UNDERFLOW:
               strncpy(message, "The exponent of a floating-point operation is less than the magnitude allowed by the corresponding type.", size);
               break;
            case EXCEPTION_INT_DIVIDE_BY_ZERO:
               strncpy(message, "The thread attempted to divide an integer value by an integer divisor of zero.", size);
               break;
            case EXCEPTION_INT_OVERFLOW:
               strncpy(message, "The result of an integer operation caused a carry out of the most significant bit of the result.", size);
               break;
            case EXCEPTION_PRIV_INSTRUCTION:
               strncpy(message, "The thread attempted to execute an instruction whose operation is not allowed in the current machine mode.", size);
               break;
            case EXCEPTION_NONCONTINUABLE_EXCEPTION:
               strncpy(message, "The thread attempted to continue execution after a noncontinuable exception occurred.", size);
               break;
            default:
               strncpy(message, "Unrecognised system or hardware error.", size);
            break;
         }
      }
   }

#else

   if (context == 0) {
#if defined(_GNU_SOURCE)
      char *p;
#endif
      strcpy(message, "");
#if defined(LINUX) || defined(AIX) || defined(OSF1) || defined(MACOSX)
#if defined(_GNU_SOURCE)
      p = strerror_r(error_code, message, (size_t) size);
      if (p && p != message) {
         strncpy(message, p, size - 1);
         message[size - 1] = '\0';
      }
#else
      strerror_r(error_code, message, (size_t) size);
#endif
      size = (int) strlen(message);
#else
      netx_get_std_error_message(error_code, message, size, context);
      size = (int) strlen(message);
#endif
   }

#endif

   message[size - 1] = '\0';

   return (int) strlen(message);
}


int netx_get_std_error_message(int error_code, char *message, int size, int context)
{

   strcpy(message, "");

#if !defined(_WIN32)
   switch (error_code) {
      case E2BIG:
         strncpy(message, "Argument list too long.", size);
         break;
      case EACCES:
         strncpy(message, "Permission denied.", size);
         break;
      case EADDRINUSE:
         strncpy(message, "Address in use.", size);
         break;
      case EADDRNOTAVAIL:
         strncpy(message, "Address not available.", size);
         break;
      case EAFNOSUPPORT:
         strncpy(message, "Address family not supported.", size);
         break;
      case EAGAIN:
         strncpy(message, "Resource unavailable, try again.", size);
         break;
      case EALREADY:
         strncpy(message, "Connection already in progress.", size);
         break;
      case EBADF:
         strncpy(message, "Bad file descriptor.", size);
         break;
#if !defined(MACOSX) && !defined(FREEBSD)
      case EBADMSG:
         strncpy(message, "Bad message.", size);
         break;
#endif
      case EBUSY:
         strncpy(message, "Device or resource busy.", size);
         break;
      case ECANCELED:
         strncpy(message, "Operation canceled.", size);
         break;
      case ECHILD:
         strncpy(message, "No child processes.", size);
         break;
      case ECONNABORTED:
         strncpy(message, "Connection aborted.", size);
         break;
      case ECONNREFUSED:
         strncpy(message, "Connection refused.", size);
         break;
      case ECONNRESET:
         strncpy(message, "Connection reset.", size);
         break;
      case EDEADLK:
         strncpy(message, "Resource deadlock would occur.", size);
         break;
      case EDESTADDRREQ:
         strncpy(message, "Destination address required.", size);
         break;
      case EDOM:
         strncpy(message, "Mathematics argument out of domain of function.", size);
         break;
      case EDQUOT:
         strncpy(message, "Reserved.", size);
         break;
      case EEXIST:
         strncpy(message, "File exists.", size);
         break;
      case EFAULT:
         strncpy(message, "Bad address.", size);
         break;
      case EFBIG:
         strncpy(message, "File too large.", size);
         break;
      case EHOSTUNREACH:
         strncpy(message, "Host is unreachable.", size);
         break;
      case EIDRM:
         strncpy(message, "Identifier removed.", size);
         break;
      case EILSEQ:
         strncpy(message, "Illegal byte sequence.", size);
         break;
      case EINPROGRESS:
         strncpy(message, "Operation in progress.", size);
         break;
      case EINTR:
         strncpy(message, "Interrupted function.", size);
         break;
      case EINVAL:
         strncpy(message, "Invalid argument.", size);
         break;
      case EIO:
         strncpy(message, "I/O error.", size);
         break;
      case EISCONN:
         strncpy(message, "Socket is connected.", size);
         break;
      case EISDIR:
         strncpy(message, "Is a directory.", size);
         break;
      case ELOOP:
         strncpy(message, "Too many levels of symbolic links.", size);
         break;
      case EMFILE:
         strncpy(message, "Too many open files.", size);
         break;
      case EMLINK:
         strncpy(message, "Too many links.", size);
         break;
      case EMSGSIZE:
         strncpy(message, "Message too large.", size);
         break;
#if !defined(MACOSX) && !defined(OSF1) && !defined(FREEBSD)
      case EMULTIHOP:
         strncpy(message, "Reserved.", size);
         break;
#endif
      case ENAMETOOLONG:
         strncpy(message, "Filename too long.", size);
         break;
      case ENETDOWN:
         strncpy(message, "Network is down.", size);
         break;
      case ENETRESET:
         strncpy(message, "Connection aborted by network.", size);
         break;
      case ENETUNREACH:
         strncpy(message, "Network unreachable.", size);
         break;
      case ENFILE:
         strncpy(message, "Too many files open in system.", size);
         break;
      case ENOBUFS:
         strncpy(message, "No buffer space available.", size);
         break;
#if !defined(MACOSX) && !defined(FREEBSD)
      case ENODATA:
         strncpy(message, "[XSR] [Option Start] No message is available on the STREAM head read queue. [Option End]", size);
         break;
#endif
      case ENODEV:
         strncpy(message, "No such device.", size);
         break;
      case ENOENT:
         strncpy(message, "No such file or directory.", size);
         break;
      case ENOEXEC:
         strncpy(message, "Executable file format error.", size);
         break;
      case ENOLCK:
         strncpy(message, "No locks available.", size);
         break;
#if !defined(MACOSX) && !defined(OSF1) && !defined(FREEBSD)
      case ENOLINK:
         strncpy(message, "Reserved.", size);
         break;
#endif
      case ENOMEM:
         strncpy(message, "Not enough space.", size);
         break;
      case ENOMSG:
         strncpy(message, "No message of the desired type.", size);
         break;
      case ENOPROTOOPT:
         strncpy(message, "Protocol not available.", size);
         break;
      case ENOSPC:
         strncpy(message, "No space left on device.", size);
         break;
#if !defined(MACOSX) && !defined(FREEBSD)
      case ENOSR:
         strncpy(message, "[XSR] [Option Start] No STREAM resources. [Option End]", size);
         break;
#endif
#if !defined(MACOSX) && !defined(FREEBSD)
      case ENOSTR:
         strncpy(message, "[XSR] [Option Start] Not a STREAM. [Option End]", size);
         break;
#endif
      case ENOSYS:
         strncpy(message, "Function not supported.", size);
         break;
      case ENOTCONN:
         strncpy(message, "The socket is not connected.", size);
         break;
      case ENOTDIR:
         strncpy(message, "Not a directory.", size);
         break;
#if !defined(AIX) && !defined(AIX5)
      case ENOTEMPTY:
         strncpy(message, "Directory not empty.", size);
         break;
#endif
      case ENOTSOCK:
         strncpy(message, "Not a socket.", size);
         break;
      case ENOTSUP:
         strncpy(message, "Not supported.", size);
         break;
      case ENOTTY:
         strncpy(message, "Inappropriate I/O control operation.", size);
         break;
      case ENXIO:
         strncpy(message, "No such device or address.", size);
         break;
#if !defined(LINUX) && !defined(MACOSX) && !defined(FREEBSD)
      case EOPNOTSUPP:
         strncpy(message, "Operation not supported on socket.", size);
         break;
#endif
#if !defined(OSF1)
      case EOVERFLOW:
         strncpy(message, "Value too large to be stored in data type.", size);
         break;
#endif
      case EPERM:
         strncpy(message, "Operation not permitted.", size);
         break;
      case EPIPE:
         strncpy(message, "Broken pipe.", size);
         break;
#if !defined(MACOSX) && !defined(FREEBSD)
      case EPROTO:
         strncpy(message, "Protocol error.", size);
         break;
#endif
      case EPROTONOSUPPORT:
         strncpy(message, "Protocol not supported.", size);
         break;
      case EPROTOTYPE:
         strncpy(message, "Protocol wrong type for socket.", size);
         break;
      case ERANGE:
         strncpy(message, "Result too large.", size);
         break;
      case EROFS:
         strncpy(message, "Read-only file system.", size);
         break;
      case ESPIPE:
         strncpy(message, "Invalid seek.", size);
         break;
      case ESRCH:
         strncpy(message, "No such process.", size);
         break;
      case ESTALE:
         strncpy(message, "Reserved.", size);
         break;
#if !defined(MACOSX) && !defined(FREEBSD)
      case ETIME:
         strncpy(message, "[XSR] [Option Start] Stream ioctl() timeout. [Option End]", size);
         break;
#endif
      case ETIMEDOUT:
         strncpy(message, "Connection timed out.", size);
         break;
      case ETXTBSY:
         strncpy(message, "Text file busy.", size);
         break;
#if !defined(LINUX) && !defined(AIX) && !defined(AIX5) && !defined(MACOSX) && !defined(OSF1) && !defined(SOLARIS) && !defined(FREEBSD)
      case EWOULDBLOCK:
         strncpy(message, "Operation would block.", size);
         break;
#endif
      case EXDEV:
         strncpy(message, "Cross-device link.", size);
         break;
      default:
         strcpy(message, "");
      break;
   }
#endif

   return (int) strlen(message);
}


int netx_enter_critical_section(void *p_crit)
{
   int result;

#if defined(_WIN32)
   EnterCriticalSection((LPCRITICAL_SECTION) p_crit);
   result = 0;
#else
   result = pthread_mutex_lock((pthread_mutex_t *) p_crit);
#endif
   return result;
}


int netx_leave_critical_section(void *p_crit)
{
   int result;

#if defined(_WIN32)
   LeaveCriticalSection((LPCRITICAL_SECTION) p_crit);
   result = 0;
#else
   result = pthread_mutex_unlock((pthread_mutex_t *) p_crit);
#endif
   return result;
}