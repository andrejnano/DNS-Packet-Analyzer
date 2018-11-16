

**Example of a IPv4 and IPv6 address testing**

```c
const char *u_ntop_src(packetinfo *pi, char *dest)
{
    if (pi->af == AF_INET) {
        if (!inet_ntop(AF_INET, &pi->ip4->ip_src, dest, INET_ADDRSTRLEN + 1)) {
            perror("Something died in inet_ntop");
            return NULL;
        }
    }
    else if (pi->af == AF_INET6) {
        if (!inet_ntop(AF_INET6, &pi->ip6->ip_src, dest,
            INET6_ADDRSTRLEN + 1)) {
            perror("Something died in inet_ntop");
            return NULL;
        }
    }
    return dest;
}
```


**types to catch**

- A
- AAAA
- CNAME
- MX
- NS
- SOA
- TXT
- SPF
- DNSSEC
- PTR

**header files required**

```c

    #include <stdio.h>
    #include <stdlib.h>
    #include <pcap.h>
    #include <errno.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <netinet/ip.h>
    #include <netinet/tcp.h>
    #include <netinet/udp.h>
    #include <arpa/inet.h>
    #include <netinet/if_ether.h> 
    #include <err.h>

    #ifdef __linux__            // for Linux
    #include <netinet/ether.h> 
    #include <time.h>
    #include <pcap/pcap.h>
    #endif

```

