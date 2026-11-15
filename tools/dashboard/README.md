# Dashboard

A single-file telemetry view for a running gate: total and per-client throughput, the guard's state
over time, and the exit address. No dependencies, no build step, canvas only.

```bash
# served by the daemon itself, so it is same-origin and needs no configuration
cp index.html /path/to/served/ui/dashboard.html     # then open http://<phone>:8081/dashboard.html

# or open it straight off disk — the API answers with CORS open on purpose
xdg-open index.html                                  # targets http://127.0.0.1:8081

# or point it at another host
index.html?api=http://192.0.2.10:8081
```

Counters are the gate's own accounting: two samples differenced over elapsed time. Traffic that does
not go through the proxy is invisible here, and a client that never uses the proxy never appears.
