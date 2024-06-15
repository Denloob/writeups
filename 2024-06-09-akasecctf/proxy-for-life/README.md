# proxy-for-life \[100 Points] (56 Solves)
```
Proxyying for life, IYKWIM

link: http://172.206.89.197:9090/
```
Attached are [source files](./attachments).
---

TL;DR 

## Writeup

Opening the attached `main.go` we first see
```go
import (
    "os"
    "io"
    "fmt"
    "net/http"
    _ "net/http/pprof"
    "html/template"
    "github.com/doyensec/safeurl"
)
```
Let's zoom in
```go
_ "net/http/pprof"
```
Yep, it's include of `pprof` \
Reading the [go.dev docs](https://pkg.go.dev/net/http/pprof) of pprof we see
> Package pprof serves via its HTTP server runtime profiling data in the format expected by the pprof visualization tool 
We basically got debugging mode!

Before that, where's the flag?
Looking at the attached `Dockerfile` we see
```dockerfile
CMD ["./main", "--FLAG=AKASEC{REDACTED}"]
```
Alright, so the flag is in the params.

Visitng the pprof endpoint from the docs, `http://172.206.89.197:9090/debug/pprof/`
we see
```
 Profile Descriptions:

    allocs: A sampling of all past memory allocations
    block: Stack traces that led to blocking on synchronization primitives
    cmdline: The command line invocation of the current program
    goroutine: Stack traces of all current goroutines. Use debug=2 as a query parameter to export in the same format as an unrecovered panic.
    heap: A sampling of memory allocations of live objects. You can specify the gc GET parameter to run GC before taking the heap sample.
    mutex: Stack traces of holders of contended mutexes
    profile: CPU profile. You can specify the duration in the seconds GET parameter. After you get the profile file, use the go tool pprof command to investigate the profile.
    threadcreate: Stack traces that led to the creation of new OS threads
    trace: A trace of execution of the current program. You can specify the duration in the seconds GET parameter. After you get the trace file, use the go tool trace command to investigate the trace.
```

Wait, `cmdline`? That's wehere the flag is!

Let's visit `http://172.206.89.197:9090/debug/pprof/cmdline` then
```
./main�--FLAG=AKASEC{r0t4t3d_p20x1n9_f002_11f3_15n7_92347_4f732_411____}
```

**Flag:** `AKASEC{p20x1n9_f002_11f3_15n7_92347_4f732_411}`

## Intended solution
Of course the intended solution was to do with the proxy, which we completely skipped. \
The challenge author forgot to repoint pprof to only work with request from `localhost`
which would make us use the proxy, bypass the `github.com/doyensec/safeurl` and get to pprof.

To be fair, forgetting `pprof` in production I would guess is a more common thing than
having a website viewer proxy with the same issue but on localhost. So it's not a bug, it's a feature :)
