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

Names resolve to their own loopback address rather than a shared `127.0.0.1`.
That is what lets each service hold its **canonical** port — every Kafka on
9092, every local AWS on 80 — instead of a hand-picked high one, and it means
`http://aws.doze` is the same URL whether a standalone process or a stack
instance is behind it.

```
127.0.0.2      aws.doze          reserved, fixed
127.0.0.3      kafka.doze        reserved, fixed
127.0.0.4-9    held for future apex names
127.0.0.10-65  qualified names, hashed by host
127.0.0.54     the resolver on Linux — never allocated
```

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

lease, err := reg.Claim(names.Apex("aws"))   // → 127.0.0.2
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
| Linux | `127.0.0.54:53` | systemd-resolved or dnsmasq drop-in, plus `/etc/hosts` for apex names |

Linux takes port 53 on an address of its own so the resolver config needs no
port syntax, which removes a systemd version floor. Binding 53 unprivileged is
what the `sysctl` drop-in in setup is for.

Registry: `<home>/names.json`. Liveness is by PID rather than clean shutdown,
because a crashed process cannot run a shutdown hook — every read prunes entries
whose process is gone, so the file self-heals and `kill -9` costs nothing.

## Status

Pre-1.0. The wire handling is ported from doze core's resolver rather than
rewritten, so the awkward parts — notably compressed QNAMEs, which macOS's
mDNSResponder produces — are the versions that have been in service.

## License

Apache 2.0 — see [LICENSE](LICENSE).
