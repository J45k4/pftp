# Puppy File Transfer Protocol (PFTP) – Specification

**Version:** 0.1-draft  
**Date:** 1 August 2025  
**Status:** For community review  
**License:** MIT

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Design Goals & Principles](#2-design-goals--principles)
3. [Terminology & Conformance](#3-terminology--conformance)
4. [Transport Assumptions](#4-transport-assumptions)
5. [Packet Format](#5-packet-format)
   - 5.1 [Common Header](#51-common-header-16-bytes)
   - 5.2 [Packet Types](#52-packet-types)
6. [State Machine & Message Flow](#6-state-machine--message-flow)
7. [Congestion Control (PFTP-CC)](#7-congestion-control-pftp-cc)
8. [Forward Error Correction](#8-forward-error-correction)
9. [Resumption & Resume Tokens](#9-resumption--resume-tokens)
10. [Security Considerations](#10-security-considerations)
11. [IANA Considerations](#11-iana-considerations)
12. [Implementation Guidance](#12-implementation-guidance)
13. [References](#13-references)

---

## 1. Introduction

PFTP is a lightweight, UDP-based file-transfer protocol optimized for high-latency or lossy links. It transmits fixed-size encrypted blocks, relies on selective retransmission and optional forward-error-correction (FEC), and offers built-in resume capability.

## 2. Design Goals & Principles

- **Resilience** – tolerate packet loss and intermittent connectivity.
- **Efficiency** – maintain high throughput with minimal overhead.
- **Security-by-default** – mandatory AES-256-GCM encryption and ECDH key exchange.
- **Simplicity** – minimal state, no persistent TCP-style connection.
- **Extensibility** – packet TLV space reserved for future options.

## 3. Terminology & Conformance

The key words MUST, SHOULD, and MAY are to be interpreted as described in [RFC 2119]. A compliant implementation MUST implement all mandatory elements of this specification.

## 4. Transport Assumptions

- Underlying transport is IPv4 or IPv6 UDP.
- Packets SHOULD NOT exceed 1 400 bytes to avoid IP fragmentation on common 1 500-byte MTUs. A larger Jumbo size MAY be negotiated during the Handshake.
- The sender SHOULD pace packets according to Section 7 to remain TCP-friendly.

## 5. Packet Format

### 5.1 Common Header (16 bytes)

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 1 | Version | Protocol version (current 0x01). |
| 1 | 1 | Type | Packet type – see §5.2. |
| 2 | 4 | Session ID | Random, unique per file transfer. |
| 6 | 4 | Sequence Number | Increases per packet, wraps mod 2³². |
| 10 | 4 | Timestamp | Sender UNIX epoch ms. |
| 14 | 2 | Checksum | CRC-16-CCITT of full packet (optional, see §10). |

All multi-byte integers are big-endian (network byte order).

### 5.2 Packet Types

#### 5.2.1 Handshake (0x00)

| Field | Size | Notes |
|-------|------|-------|
| Flags | 1 | Bit 0 = Encryption, Bit 1 = FEC, Bit 2 = Resume. |
| PubKey Len | 1 | Length in bytes. |
| Public Key | var | ECDH public key (e.g. X25519 = 32 bytes). |
| MTU Hint | 2 | Maximum packet length the sender can receive. |
| Payload | var | Optional authentication challenge. |

#### 5.2.2 Manifest (0x01)

- **File Size** (8 B) – octets.
- **Block Size** (4 B) – bytes; MUST be ≥ 512 B and a power of 2.
- **Block Count** (4 B).
- **Hash Alg** (1 B) – 0x01 = SHA-256.
- **Hash List** (variable) – one 32-byte digest per block.
- Payload is encrypted with the session key.

#### 5.2.3 Data Block (0x02)

- **Block ID** (4 B) – zero-based.
- **Offset** (4 B) – byte offset within the block (for fragmentation).
- **Data Len** (2 B).
- **Payload** (variable).
- **Optional FEC Parity** (see §8).

#### 5.2.4 ACK/SACK (0x03)

- **Window Size** (2 B) – receiver free buffer in packets.
- **Bitmap Len** (2 B).
- **SACK Bitmap** (var) – contiguous missing/received bits.
- **Cum ACK** (4 B) – highest contiguous received Block ID.

#### 5.2.5 NAK (0x04)

List of missing Block IDs or ranges.

#### 5.2.6 Close (0x05)

- **Final ACK** (4 B).
- **Reason** (1 B) – 0x00 = normal, 0x01 = error.

#### 5.2.7 Resume Request (0x06)

- **Session ID** (4 B).
- **Last Block ID** (4 B).
- **Resume Token** (var) – MAC of (Session ID, File Hash, Offset).

---

## 6. State Machine & Message Flow

```
 Client                           Server
  |-- Handshake (0x00) --------->|
  |<-- Handshake-Resp -----------|
  |-- Manifest    (0x01) --------|
  |<-- ACK (0x03) ---------------|
  |-- Data Blocks (0x02) ----\   |
  |<-- SACK/NAK    (0x03|04) |<--/
  ... retransmit gaps ...
  |-- Close (0x05) --------------|
  |<-- Close-ACK (0x05) ---------|
```

A transfer MAY transition to Paused on timeout, after which either side can issue a Resume Request.

---

## 7. Congestion Control (PFTP-CC)

PFTP-CC is a TCP-friendly AIMD algorithm inspired by RFC 9002 (QUIC Reno profile).

### 7.1 Variables

- **cwnd** – congestion window, in packets.
- **ssthresh** – slow-start threshold.
- **srtt** – smoothed RTT.
- **pace_rate** – packets per second (= cwnd / srtt).

### 7.2 Algorithm

```
Init: cwnd = 10 * MSS, ssthresh = ∞
On ACK:
    if cwnd < ssthresh:      # Slow-start
        cwnd += 1 packet
    else:                    # Congestion-avoidance
        cwnd += MSS * MSS / cwnd
    Update pace_rate
On loss or ECN:
    ssthresh = cwnd / 2
    cwnd = ssthresh
On 3 consecutive timeouts:
    cwnd = 1 packet
Pacing:
    Transmit packets uniformly at pace_rate within each RTT.
```

An implementation MAY substitute BBRv2 provided that long-term throughput over a shared bottleneck does not exceed 1.25 × that of a Reno flow (RFC 9743 §4).

---

## 8. Forward Error Correction

- Sender MAY group k Data packets with n parity packets using RaptorQ (RFC 6330) or XOR parity.
- FEC parameters are advertised in Handshake flags Extension #0x01.
- Receiver decodes as soon as any k of (k + n) symbols arrive; missing source packets are then logically ACKed.

---

## 9. Resumption & Resume Tokens

A Resume Token is a 96-bit AEAD tag computed over (Session ID ∥ File Hash ∥ Offset) with the session key. Tokens permit stateless recovery by a new sender instance.

---

## 10. Security Considerations

- **Encryption:** Every Data, Manifest, and Resume packet payload MUST be encrypted with AES-256-GCM; header bytes SHOULD be authenticated as AEAD AAD.
- **Key Exchange:** ECDH (X25519) with HKDF-SHA-256 derives distinct enc and hp keys.
- **Replay Protection:** Receiver keeps a sliding window of 2³² sequence numbers per Block ID.
- **Re-keying:** Implementations SHOULD rotate keys every 2³¹ packets or 1 h, whichever is sooner.
- **DoS Mitigation:** Servers SHOULD require a QUIC-style retry cookie before allocating per-session state.

---

## 11. IANA Considerations

This document requests assignment of:

- **UDP port 4444** – PFTP service (temporary). A future version may register 443/DTLS encapsulation.
- **PFTP Packet Type Registry** – values 0x00–0x7F (public), 0x80–0xFF (experimental).

---

## 12. Implementation Guidance

- Use `sendmmsg()`/`recvmmsg()` for batch I/O on Linux.
- Batch crypto: pre-allocate AEAD contexts per thread.
- For Rust, combine Tokio for I/O and rayon for FEC workers.
- Keep-alive: send a 1-byte Ping every 20 s of silence to hold NAT bindings.

---

## 13. References

- RFC 8085 – UDP Usage Guidelines.
- RFC 9002 – QUIC Loss Detection and Congestion Control.
- RFC 9743 – Specifying New Congestion-Control Algorithms.
- Floyd et al. – Equation-Based Congestion Control.
- Lubbers & Dovrolis – UDT: UDP-based Data Transfer.
- RFC 6330 – RaptorQ Forward Error Correction.

---

*End of Document*