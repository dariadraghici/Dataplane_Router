# Dataplane Router

A software implementation of a router's dataplane in C, built to receive raw Ethernet frames on multiple interfaces, make a forwarding decision for each one, and send them back out toward their destination: the same logic that real routers run millions of times a second, stripped down to its essential steps and built from the wire up.

## The Story

Every packet that crosses the internet passes through a chain of routers, and each one makes the same small, fast decision: given this packet, which interface should it leave on, and who should receive it next. That decision looks trivial from the outside (check an address, pick a port) but it hides a surprising amount of machinery: parsing raw bytes into meaningful headers, validating that a frame is even meant for you, deciding whether you're the final destination or just a waypoint, finding the most specific matching route among possibly thousands, discovering the physical address of a neighbor you've never talked to before, and reporting back when something goes wrong along the way.

This project builds that machinery from scratch. It starts from nothing but a stream of bytes arriving on a network interface and, step by step, reconstructs the Ethernet, IPv4, ARP, and ICMP logic needed to behave like a real router's dataplane: the part of a router that actually moves packets, as opposed to the control plane, which would be responsible for computing the routing table in the first place (that part is assumed to already be done, delivered as a static file). The implementation is tested inside a virtual network built with Mininet, connecting real hosts to the router across a small topology, so that its behavior can be observed with the same tools (ping, arping, traceroute, Wireshark) used to diagnose real networks.

The router was built on top of the skeleton and forwarding groundwork from an earlier networking lab, then extended in four layers: correct IPv4 forwarding, an efficient longest-prefix-match lookup, dynamic ARP resolution with caching, and full ICMP error reporting.

## Features

### Packet Parsing and L2 Validation
- Reads raw frames directly from the network interfaces and reconstructs the Ethernet header to determine what protocol follows.
- Accepts only frames addressed to the router's own MAC address or to the broadcast address, discarding anything else at the earliest possible stage.
- Distinguishes between IPv4 and ARP payloads via the EtherType field and dispatches to the corresponding handling logic; any other EtherType is ignored.

### IPv4 Forwarding
- Verifies the IP header checksum and drops corrupted packets before doing any further processing.
- Rejects packets whose TTL has already expired and decrements the TTL of everything else, recomputing the checksum afterward to reflect the change.
- Looks up the destination address in the routing table to determine the next hop and outgoing interface, forwarding the packet only once a valid route is found.
- Rewrites the Ethernet source and destination addresses before retransmission: the source becomes the router's own outgoing interface, and the destination becomes the resolved MAC address of the next hop.

### Efficient Longest Prefix Match
- Replaces the linear scan through the routing table by checking every entry's prefix and mask against the destination address  with a binary trie built over the prefix bits.
- Each trie node holds up to two children, one per bit value, plus a pointer to a routing table entry when a valid prefix terminates there.
- Table entries are inserted by walking their prefix bit by bit, from the most significant bit down to the mask length, allocating nodes along the path as needed.
- A lookup walks the trie according to the bits of the destination address, keeping track of the most specific (longest) matching entry seen so far, which turns route resolution from a scan over the whole table into a walk bounded by address length.

### Dynamic ARP Resolution
- Builds the ARP table dynamically at runtime rather than relying on a static file, resolving each next hop's MAC address the first time it's needed.
- Generates ARP requests as broadcast Ethernet frames carrying an ARP header that asks for the hardware address behind a given IP, using the router's own outgoing interface address as the sender.
- Answers incoming ARP requests addressed to the router with a properly constructed ARP reply, targeting the original requester's hardware address.
- Caches every resolved address as it arrives, so that a given neighbor is only queried once.
- Queues any IP packet that is waiting on an unresolved MAC address rather than dropping it, and drains that queue whenever a matching ARP reply comes in, rewriting the queued packet's L2 header and sending it on immediately, while any entries still waiting on a different address are preserved for later.

### ICMP Error Reporting and Echo
- Responds to ICMP echo requests addressed to the router itself with a proper echo reply, preserving the identifier and sequence number fields exactly as required by the protocol.
- Generates a Time Exceeded message whenever a packet's TTL reaches zero in transit, carrying the dropped packet's original IP header and the first bytes of its payload back to the sender, as specified by the ICMP error format.
- Generates a Destination Unreachable message whenever the routing table has no matching entry for a packet not addressed to the router, following the same error-payload structure.
- Recomputes both the IP and ICMP checksums for every generated message before it is sent.

## Design Notes

- **Built as a layered extension of a working baseline.** Rather than starting from an empty file, the implementation grew out of an earlier lab's forwarding skeleton, replacing its static MAC table with dynamic ARP resolution and its linear route lookup with a trie, one concern at a time.
- **No component depends on ICMP or dynamic ARP to be correct.** Basic forwarding works with a static ARP table and no ICMP support at all, which made it possible to validate each layer (forwarding, then LPM, then ARP, then ICMP) independently before combining them.
- **Endianness handled deliberately at every boundary.** Every multi-byte field read from or written to the wire is explicitly converted between host and network byte order, since a router that forgets this will silently mis-load bugs into every peer that receives its packets.
- **Verified against packet captures, not just pass/fail output.** Every stage of development was checked with Wireshark or tcpdump on the relevant interfaces, confirming destination MACs, checksums, TTLs, and total lengths directly against the bytes actually placed on the wire, rather than trusting the checker alone.

## Testing

The router runs inside a virtual topology built with Mininet: two routers connected to each other, each with two directly attached hosts. A Python setup script spins up the topology and opens a terminal for each host and each router, from which ordinary Linux networking tools: `ping`, `arping`, `netcat`, `traceroute`, and packet captures via Wireshark or tcpdump can be used to exercise the implementation directly.

Verified behaviors include:
- Correct end-to-end forwarding between hosts on the same router and across both routers, with TTL properly decremented at each hop.
- ARP resolution both for the router's directly attached hosts and confirmation that ARP does not cross router boundaries.
- Caching behavior, confirmed by observing that a second packet to an already-resolved host triggers no additional ARP exchange.
- ICMP echo replies when pinging the router itself.
- ICMP Time Exceeded messages when sending packets with an artificially low TTL, and Destination Unreachable messages when targeting an unknown network.
- A full `traceroute` run, showing the expected alternation of UDP probes and ICMP responses across both hops.

An automated checker suite is also available, exercising the same behaviors: ARP requests and replies, forwarding with and without cached ARP entries, checksum validation, TTL handling, and multi-hop delivery, and producing per-router packet captures for any failing test.

## Background

This project was built as coursework for a computer networking course, implementing the dataplane half of a router (the packet-moving logic) while treating the routing table itself as a static input, as would normally be produced by a separate control-plane routing protocol. The four feature areas above (basic forwarding, efficient lookup, dynamic ARP, ICMP) were developed and scored as incremental layers over the same codebase, each one verified against both manual testing in Wireshark and an automated test suite before moving to the next.
