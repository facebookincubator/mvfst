# I/O Model
Mvfst is, at its core, an [IO
library](https://en.wikipedia.org/wiki/Input/output). It allows an
application to setup a QUIC connection to a peer and read/write data on that
connection using the QUIC semantics of streams and datagrams. When doing I/O
to a device/network/whatever there is one main design choice which needs to
be made: should the reads and writes be "blocking" or not?

## Blocking I/O
Blocking I/O, also known as "synchronous I/O", is perhaps the easier model to
understand. Suppose, for example, we have a QUIC stream and we want to write
some data to it. That may look like the following in pseudo code:
```
quicStream = createBidirectionalStream()
message = "hello my friend"
quicStream.write(message) // Blocks until the message is fully written to the network.
print("I have successfully written the message!")
```
In a blocking I/O model the call to write will not return (i.e. "block")
until it has written "hello my friend" into QUIC packets and into the
network. The case of reading in a blocking fashion is similar:
```
message = quicStream.readAll() // Blocks until the entire stream is available.
print("here is the message: " + message)
```
The call to `read` will block until it has 15 bytes to return. This is all
pretty straightforward, and indeed blocking I/O makes it very easy to write
traditional programs; I/O functions are really no different from any other
function besides the fact that the time it takes to return isn't solely a
function of CPU time.

There are, however, significant practical disadvantages to using blocking
I/O. Consider for example a web server which handles multiple concurrent
connections from clients. Using only a single thread of execution this server
would only be able to serve one client at a time, as every I/O call will
block execution until its completion. One way to get around this is to
instead have a [thread](https://en.wikipedia.org/wiki/Thread_(computing)) per
client connection. This enables the server to service multiple clients
without any connection delaying the servicing of any other connection.
However, in order to achieve this concurrency the server needs many threads.
It is not unusual for modern web servers to have to service tens to hundreds
of thousands of connections concurrently, leading to the so-called
[C10k](https://en.wikipedia.org/wiki/C10k_problem) problem. Threads are not
free, and their management, whether done by the operating system or in the
userspace runtime via [green
threads](https://en.wikipedia.org/wiki/Green_threads), cannot feasibly scale
to support this model.

An alternative approach is to use so-called "asynchronous", i.e.
non-blocking, I/O. The basic idea of asynchronous I/O is to make it so that
I/O operations return in a bounded amount of time, just like any other
non-I/O function call. Let's consider our write example again:
```
quicStream = createBidirectionalStream()
message = "hello my friend"
quicStream.write(message) // Returns after copying message into a buffer to be sent later.
print("I have successfully written the message!")
```
Our message from the print statement is no longer true, since write will
return much sooner than in the blocking I/O case. In order to handle this
problem (i.e., taking an action after some previous event), we need some
notion of [continuation
semantics](https://en.wikipedia.org/wiki/Continuation). There are many ways
to achieve continuation, but the simplest and most relevant to mvfst
presently is [asynchronous
callbacks](https://en.wikipedia.org/wiki/Callback_(computer_programming)).
The basic idea is very simple. In the above example we want to take some
action when message has been written to the underlying network. To achieve
this we pass the function to write:
```
quicStream = createBidirectionalStream()
message = "hello my friend"
myCallback = (){print("I have successfully written the message!")}
quicStream.write(message, myCallback) // Returns after copying message into a buffer to be sent later.
```
As before `write` still returns immediately, but now we have a way to execute
some code at the same point as the synchronous case, when the message is
written to the network. If we consider the `read` case we see the same
problem. We want to only print the message once we've actually received it,
without blocking on a function call. To achieve this we would have a similar
callback:
```
myCallback = (quicStream){print("here is the message: " + quicStream.readAll())}
quicStream.setReadCallback(myCallback)
```
Now we are telling the QUIC implementation to call `myCallback` when it has
read data from the stream. The callback is provided the stream which has had
all of its data read, and the readAll function simply copies it out of the
connection.

Callbacks are perhaps the most primitive form of achieving continuation in
asynchronous code, and they can be very difficult to get right. C++ (and many
other languages) now has support for a different semantic,
[coroutines](https://en.wikipedia.org/wiki/Coroutine), which objectively
allow for much more fluid programming than callbacks.

In general mvfst only offers completely asynchronous APIs that use callbacks
for continuation. Next we will discuss the basics of how this is implemented.

## Folly and the EventBase

Like most C++ libraries and services at Facebook, mvfst makes extensive use
of folly, our collection of high quality C++ code and abstractions. Of
particular interest is the
[EventBase](https://github.com/facebook/folly/blob/master/folly/io/async/README.md)
and other related classes. This is an abstraction on top of an asynchronous
[event loop](https://en.wikipedia.org/wiki/Event_loop) which drives mvfst's
state machine. The EventBase, much like mvfst itself, heavily utilizes
callback-based continuation and provides an easy way to integrate with
asynchronous I/O events presented by the OS on [file
descriptors](https://en.wikipedia.org/wiki/File_descriptor) like network
sockets and real files. Said another way, most operating systems provide
their own APIs for asynchronous I/O and events, and the EventBase is an
abstraction that lets us integrate with these APIs using C++.

## Server Threading Example

![Thread Model](/quic/thread.png)

In a server such as Proxygen, our reverse proxy at Facebook, we ill have
CPU-many "worker threads" servicing connections. To support this in mvfst we
have a QuicServerWorker abstraction, which itself has a 1:1 correspondence
with an underlying OS thread. This also corresponds to exactly one EventBase
object per worker. Each QuicServerWorker stores a table of active
connections, each of which is a QuicServerTransport. The QuicServerTransport
objects share the same EventBase object with the worker, and use it to queue
up callbacks to drive their own connection state forward.

An important thing to note from this diagram is that a single mvfst
connection is only ever modified by a single thread. This allows mvfst to
completely eschew any sort of locking to prevent concurrent access to its
data. Only one thread ever has access to any given connection, and a thread
can only ever be modifying a single connection at a time.

We can also see very clearly here that, unlike the thread-per-connection
model described earlier, we are able to service many connections per-thread
and thus minimize threading and scheduling overhead.
