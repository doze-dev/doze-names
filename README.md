# doze-names

`.doze` — the local naming zone shared by every doze binary.

```
go get github.com/doze-dev/doze-names
```

**No binary owns the zone.** The doze CLI, `doze-aws` and `doze-kafka` each
write their names into a registry under the shared home, and whichever process
binds the resolver socket first answers for **all** of them — its own names and
its peers'. Install order does not matter, none of the three is a prerequisite
for the others, and if the serving process exits the next one takes over.

Install only `doze-kafka` and `kafka.doze` works. Add `doze-aws` later and
`aws.doze` works too — answered by the kafka process, because it happens to hold
the socket. Add the CLI and nothing changes.

Zero dependencies: standard library only.

## Two tiers of name

| Tier | Form | Who | Contested |
|---|---|---|---|
| **Apex** | `aws.doze`, `kafka.doze` | anyone — standalone or a stack | yes, first-come |
| **Qualified** | `<service>.<stack>.doze` | doze CLI stacks | never |

An apex name means *"the one on this machine"*. It needs no stack, which is what
makes it the right name for a standalone `doze-aws` — there is nothing to
disambiguate. It is claimed first-come, and a second claimant is **told who holds
it** rather than silently winning or losing:

```go
lease, err := reg.Claim(names.Apex("aws"))
if held, ok := names.Held(err); ok {
    log.Printf("%s is held by pid %d (%s); using the configured address",
        held.Host, held.PID, held.Owner)
}
```

A stack that loses the apex race still has its qualified name, so losing costs
it nothing functional.

## Every name gets its own address

Names resolve to an address of their own rather than a shared `127.0.0.1`.
That is what lets each service hold its **canonical** port — every Kafka on
9092, every Postgres on 5432 — instead of a hand-picked high one, and it means
`http://aws.doze` is the same URL whether a standalone process or a stack
instance is behind it.

An address is a block plus an offset. The offset belongs to the name and is
the same on every system; the block is the machine's.

```
offset 2        aws.doze          reserved, fixed
offset 3        kafka.doze        reserved, fixed
offset 4-9      held for future apex names
offset 10 up    qualified names, hashed by host — about 32,000 of them
```

| | Block | How a service gets its address |
|---|---|---|
| Linux, Windows | `127.0.0.0/17` | It binds it. All of `127.0.0.0/8` is local, and nothing has to run. |
| macOS | `198.19.0.0/17` | It never binds it. Setup installs a small network daemon; the service listens on a private port and the daemon translates. |

macOS is different because a loopback address exists there only once it has
been aliased onto `lo0`, and aliasing them in bulk is not survivable. Measured
on macOS 27: 250 more aliases took `mDNSResponder` to 100% of a core and a name
lookup from 10 ms to over a second; 4,000 took a lookup to 150 seconds and
`configd` was killed by its watchdog. So instead of an address per service
there is one interface with the whole block routed to it, held by the daemon.
It opens the interface and adds the route as root, then drops to the user who
ran setup and does nothing but rewrite packets between a service's public
address and its private port. It keeps no connection state, so restarting it
loses nothing. CI runs it for real on macOS 14, 15 and 26: 2,000 services on
one port, `mDNSResponder` idle throughout, 2.6 to 4 Gbit/s through it.

The daemon is a copy of whichever doze program ran setup, started with a
private argument. Every program's `main` therefore begins with
`names.Helper()`, which is where that copy becomes the daemon.

### Listening

```go
lease, _ := reg.Claim(names.Qualified("db", "shop"))
ln, err := lease.Listen(5432)        // db.shop.doze:5432, on either system
```

`Listen` binds the address where it can and registers a private port where it
cannot; the listener reports the public address either way. For a server the
program starts but does not run in-process, `lease.BindAddr()` is the address
to have it listen on and `lease.Forward(public, private)` registers the port.

`Claim` is the one allocator for the machine. It runs under the registry's
lock, so two programs cannot be given one address, and releasing a name gives
its address back at once. `ClaimAt` is for a caller that needs a particular
address; it is refused if another live name already resolves there.
`127.0.0.1` is the exception: on a machine with no setup everything listens
there, so it is shared by design. `PoolUsable` says which of the two a machine
is.

Apex addresses are **fixed rather than allocated**, because on Linux they are
written into `/etc/hosts` once at setup, before anything is running. A static
block never needs rewriting as services come and go — and when nothing is
listening the name still resolves and the connection is *refused*, a truthful
error rather than "no such host", which is what makes people suspect their DNS.

Adding an entry to the apex table is a compatibility commitment: it ends up in
people's `/etc/hosts`.

## Usage

```go
reg := names.Open(home, "doze-aws")

lease, err := reg.Claim(names.Apex("aws"))   // → 127.0.0.2, or 198.19.0.2 on a Mac
defer lease.Release()

srv := names.Serve(ctx, reg, log.Printf)     // binds if free, stands by if not
defer srv.Close()
```

`Serve` never fails. Not holding the socket is the normal case for every peer
but one, and it is indistinguishable to callers from holding it: the names
resolve either way, because whoever holds it answers from the same registry.

## Where the zone lives

| Platform | Resolver listens | Routed by |
|---|---|---|
| macOS | `127.0.0.1:5323` | `/etc/resolver/doze` |
| Linux | `192.0.2.53:5323` | systemd-resolved or dnsmasq drop-in, plus `/etc/hosts` for apex names |

Both use a high port: 53 is held on the wildcard by whatever already serves
DNS, which takes every address with it. On Linux the resolver is not on
loopback at all, because systemd-resolved refuses a loopback address as a DNS
server; setup gives it an address of its own on a dummy interface. The
`sysctl` drop-in in setup is for the front door on port 80.

Registry: `<home>/names.json`. Liveness is by PID rather than clean shutdown,
because a crashed process cannot run a shutdown hook — every read prunes entries
whose process is gone, so the file self-heals and `kill -9` costs nothing.

The file carries a **format version** (`names.FormatVersion`), stamped on every
write. Three separately released programs share it, so a build that meets a
file from a newer format stops and says so rather than rewriting names it does
not understand. The stamp is an entry of its own, not a wrapper around the
names, so a build from before the version existed still reads the file.

A stack name is claimed here too (`ClaimStack`): every name in a stack is
`<service>.<stack>.doze`, so two projects with one stack name would answer for
each other's services. `ReservedStack` says which names a stack may not take,
because they are a standalone tool's.

## The front door answers this machine only

The shared HTTP front door (`:80`, routing by `Host`) binds the IPv4 wildcard on
purpose: a name's address is not one a Mac can bind, and on Linux an unprivileged process
cannot be given `:80` on each of them. So it is reachable from the network
the machine is plugged into, and what sits behind it (development consoles, no
authentication) must not be. It answers peers on this machine — loopback, and on a Mac the block the daemon
translates — and refuses every other with
`403`, before looking at the route, so a refused peer learns nothing about what is
registered.

## One switch, and a check

`DOZE_ZONE=off` (`names.Disabled()`) switches the zone off for every doze binary at
once. `names.Reachable(host, port)` reports whether something answers, so a caller
prints a by-name address only if it works.

## A private zone

`DOZE_ZONE_RESOLVER` and `DOZE_ZONE_INGRESS` move the zone's DNS server and its
front door to addresses of your choosing. With `DOZE_HOME` they give a set of
programs a zone of their own — its own registry and its own two sockets — that
touches nothing of the machine's real one. Every program in it has to be given
the same three values. It is how the tools are tested together on a machine
where the real zone is in use; the operating system's resolver knows nothing
of it, so its names resolve only for a client that asks its DNS server.

## Windows

The registry, resolver and front door build for Windows (the registry lock uses
`LockFileEx`). Machine setup does not exist there yet: `Check` reports one step that
is not done, and `Install` and `Uninstall` say so rather than succeeding.

## Status

Pre-1.0. The wire handling is ported from doze core's resolver rather than
rewritten, so the awkward parts — notably compressed QNAMEs, which macOS's
mDNSResponder produces — are the versions that have been in service.

## License

Apache 2.0 — see [LICENSE](LICENSE).
