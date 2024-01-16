# vc5ng

A library to manage load balanced services. The balancer is
implemented by an interface passed to the `Director`, and configured
with a list of services which include health check definitions.

Backend servers are added and removed from the balancer's pool by the
`Director` according to the status of the health checks.

A BGP implementation is included and may be used to advertise healthy
virtual IP address to the network.

[A sample application](cmd/) is included which uses an [XDP/eBPF load
balancer implementation](https://github.com/davidcoles/xvs) to provide
a layer 2 Direct Server Return (DSR) service.




