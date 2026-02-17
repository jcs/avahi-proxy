# avahi-proxy

This acts as a DNS server listening on a given port (and optional IP, otherwise
defaulting to `127.0.0.1`) and passes each `A` and `AAAA` query received for
the `local` domain to `avahi-resolve`.
If it gets an answer, it passes it back as a proper DNS reply, otherwise
returning `NXDOMAIN`.

## Compiling

	$ git clone https://github.com/jcs/avahi-proxy
	$ cd avahi-proxy
	avahi-proxy$ make

## Installing

	avahi-proxy$ doas make install
	avahi-proxy$ doas rcctl enable avahi_proxy
	avahi-proxy$ doas rcctl start avahi_proxy

## Use with `unwind`

When using OpenBSD's `unwind`, configure a `force` block for `local.` and a
`forwarder` to `avahi-proxy`, assuming its default port of 5300:

	preference { autoconf }
	forwarder { 127.0.0.1 port 5300 }
	force forwarder { local }

Now queries for `local.` hosts will forward to `avahi-proxy`, which will proxy
them to `avahi-resolve`:

	$ dig @127.0.0.1 giraffe.local. a
	[...]
	;; QUESTION SECTION:
	;giraffe.local.			IN	A

	;; ANSWER SECTION:
	giraffe.local.		9	IN	A	192.168.1.3

To directly query `avahi-daemon`, just supply the port it's running on:

	$ dig @127.0.0.1 -p 5300 giraffe.local. a
