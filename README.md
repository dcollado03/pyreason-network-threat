# pyreason-network-threat

Small project using [PyReason](https://pyreason.syracuse.edu) to model how a cyber breach spreads across a network. Basically a hello-world but with a security twist.

## the idea

You have 4 hosts on a network. An attacker compromises the web server, and from there PyReason figures out which other hosts get hit based on the connections and whether they have known vulnerabilities.

```
web_server --> app_server --> db_server
                  |
                  v
              workstation
```

There's one rule: if a compromised host is connected to a vulnerable host, that host gets compromised one timestep later. PyReason chains this across the graph automatically.

db_server isn't marked vulnerable, so it doesn't get compromised even though app_server connects to it. This is kind of the whole point - the reasoning actually respects the conditions you set.

## how to run

```
pip install pyreason networkx
python network_threat_propagation.py
```

needs python 3.10 (pyreason has numba compatibility issues on 3.11+)

## references

- [PyReason docs](https://pyreason.readthedocs.io)
- [lab-v2/pyreason on github](https://github.com/lab-v2/pyreason)


