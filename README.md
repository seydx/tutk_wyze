# Wyze TUTK/IOTC Protocol - Reverse Engineering Summary

This document summarizes the complete reverse engineering of the Wyze camera TUTK/IOTC protocol with DTLS encryption.

---

## Table of Contents

1. [Overview](#overview)
2. [Connection Flow](#connection-flow)
3. [Phase 1: Discovery](#phase-1-discovery)
4. [Phase 2: Session Setup](#phase-2-session-setup)
5. [Phase 3: DTLS Handshake](#phase-3-dtls-handshake)
6. [Phase 4: AV Login](#phase-4-av-login)
7. [Phase 5: IOCTL Authentication (K10000-K10003)](#phase-5-ioctl-authentication-k10000-k10003)
8. [Phase 6: Video Stream](#phase-6-video-stream)
9. [Frame Formats](#frame-formats)
10. [Cryptography](#cryptography)
11. [Key Findings & Fixes](#key-findings--fixes)

---

## Overview

Wyze cameras use the TUTK (ThroughTek) IOTC SDK for P2P communication. The protocol consists of:

- **Transport Layer**: UDP with custom framing (0x0402 protocol)
- **Security Layer**: DTLS 1.2 with PSK (Pre-Shared Key)
- **Cipher Suite**: `TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256` (0xCCAC)
- **Application Layer**: IOCTL commands with "HL" (Header-Length) framing

### Required Credentials

| Parameter | Description | Example |
|-----------|-------------|---------|
| UID | Device unique identifier | `HSBJYB5HSETGCDWD111A` |
| AuthKey | 8-byte authentication key | `qZwi9FaB` |
| ENR | 16-byte encryption key (base64) | `aKzdqckqZ8HUHFe5` |

---

## Connection Flow

```
┌─────────┐                              ┌─────────┐
│  Client │                              │ Camera  │
└────┬────┘                              └────┬────┘
     │                                        │
     │ ──── Phase 1: Discovery ────           │
     │                                        │
     │  DISCO Stage 1 (broadcast)             │
     │ ────────────────────────────────────►  │
     │                                        │
     │  DISCO Response (camera IP/port)       │
     │ ◄────────────────────────────────────  │
     │                                        │
     │  DISCO Stage 2 (direct)                │
     │ ────────────────────────────────────►  │
     │                                        │
     │ ──── Phase 2: Session Setup ────       │
     │                                        │
     │  0x0402 Session Request                │
     │ ────────────────────────────────────►  │
     │                                        │
     │  0x0404 Session Response               │
     │ ◄────────────────────────────────────  │
     │                                        │
     │ ──── Phase 3: DTLS Handshake ────      │
     │                                        │
     │  ClientHello (ECDHE-PSK-CHACHA20)      │
     │ ────────────────────────────────────►  │
     │                                        │
     │  ServerHello + ServerKeyExchange       │
     │ ◄────────────────────────────────────  │
     │                                        │
     │  ClientKeyExchange + Finished          │
     │ ────────────────────────────────────►  │
     │                                        │
     │  Finished                              │
     │ ◄────────────────────────────────────  │
     │                                        │
     │ ──── Phase 4: AV Login ────            │
     │                                        │
     │  AV Login #1 (magic=0x0000)            │
     │ ────────────────────────────────────►  │
     │                                        │
     │  AV Login #2 (magic=0x2000)            │
     │ ────────────────────────────────────►  │
     │                                        │
     │  AV Login Response (0x2100)            │
     │ ◄────────────────────────────────────  │
     │                                        │
     │ ──── Phase 5: IOCTL Auth ────          │
     │                                        │
     │  K10000 (Auth Request)                 │
     │ ────────────────────────────────────►  │
     │                                        │
     │  K10001 (Challenge)                    │
     │ ◄────────────────────────────────────  │
     │                                        │
     │  0x09 ACK                              │
     │ ────────────────────────────────────►  │
     │                                        │
     │  K10002 (Challenge Response)           │
     │ ────────────────────────────────────►  │
     │                                        │
     │  K10003 (Auth Result + Camera Info)    │
     │ ◄────────────────────────────────────  │
     │                                        │
     │ ──── Phase 6: Video Stream ────        │
     │                                        │
     │  0x0508/0x0500 Video Frames            │
     │ ◄────────────────────────────────────  │
     │                                        │
```

---

## Phase 1: Discovery

Discovery uses UDP broadcast to find cameras on the local network.

### DISCO Packet Structure (88 bytes)

```
Offset  Size  Field               Value/Description
──────────────────────────────────────────────────────
0-1     2     Protocol Version    0x0402
2-3     2     Header Length       0x021a (little-endian)
4-5     2     Payload Length      0x0048 (72 bytes)
6-7     2     Reserved            0x0000
8-9     2     Command             0x0601 (DISCO request)
10-11   2     Sub-command         0x0021
12-15   4     Reserved            0x00000000
16-35   20    UID                 Null-padded device UID
36-47   12    Reserved            0x00...
48-51   4     Flags               0x01010204
52-59   8     RandomID            8 random bytes (session identifier)
60-63   4     Stage               0x01 (broadcast) or 0x02 (direct)
64-71   8     Reserved            0x00...
72-79   8     AuthKey             8-byte auth key (null-padded)
80-87   8     Reserved            0x00...
```

### DISCO Encryption

DISCO packets are encrypted using a simple XOR-based cipher:

```go
func EncryptDisco(plain []byte) []byte {
    encrypted := make([]byte, len(plain))
    for i := 0; i < len(plain); i++ {
        encrypted[i] = plain[i] ^ discoKey[i%len(discoKey)]
    }
    return encrypted
}
```

### DISCO Flow

1. **Stage 1 (Broadcast)**: Send to `255.255.255.255:32761`
2. **Camera Response**: Contains camera's actual IP and port
3. **Stage 2 (Direct)**: Send directly to camera's IP/port

---

## Phase 2: Session Setup

After discovery, establish a session with the camera.

### Session Request (0x0402) - 52 bytes

```
Offset  Size  Field               Value
──────────────────────────────────────────
0-1     2     Protocol Version    0x0402
2-3     2     Header Length       0x021a
4-5     2     Payload Length      0x0024 (36 bytes)
6-7     2     Reserved            0x0000
8-9     2     Command             0x0402 (Session Request)
10-11   2     Sub-command         0x0033
12-15   4     Reserved            0x00000000
16-35   20    UID                 Device UID
36-43   8     RandomID            Same as DISCO
44-47   4     Reserved            0x00000000
48-51   4     Checksum            CRC32-like checksum
```

### Session Response (0x0404)

Camera responds with command `0x0404` confirming session establishment.

---

## Phase 3: DTLS Handshake

After session setup, establish encrypted DTLS connection.

### PSK Derivation

The PSK (Pre-Shared Key) is derived from AuthKey and ENR:

```go
func DerivePSK(authKey, enr string) [32]byte {
    // Combine authKey + ENR
    combined := authKey + enr

    // SHA256 hash
    return sha256.Sum256([]byte(combined))
}
```

### DTLS Parameters

| Parameter | Value |
|-----------|-------|
| Version | DTLS 1.2 |
| Cipher Suite | `TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256` (0xCCAC) |
| PSK Identity | `AUTHPWD_admin` |
| PSK | SHA256(AuthKey + ENR) |
| Curve | X25519 |

### DTLS Transport Framing

DTLS records are wrapped in TUTK transport frames:

```
Offset  Size  Field               Description
──────────────────────────────────────────────────
0-1     2     Protocol Version    0x0402
2-3     2     Header Length       0x0b1a (little-endian)
4-5     2     Payload Length      Variable
6-7     2     Sequence            Packet sequence number
8-9     2     Command             0x0704 (TX) or 0x0408 (RX)
10-11   2     Sub-command         0x0021
12-13   2     RandomID prefix     First 2 bytes of RandomID
14-15   2     Flags               0x0001
16-17   2     Reserved            0x000c
18-21   4     Reserved            0x00000000
22-29   8     RandomID            Full 8-byte RandomID
30-31   2     DTLS Content Type   0x16 (handshake), 0x17 (app data)
32-33   2     DTLS Version        0xfefd (DTLS 1.2)
34-35   2     DTLS Epoch          0x0000 or 0x0001
36-41   6     DTLS Sequence       48-bit sequence number
42-43   2     DTLS Length         Payload length
44+     var   DTLS Payload        Encrypted DTLS record
```

---

## Phase 4: AV Login

After DTLS handshake, send AV (Audio/Video) login packets.

### AV Login Packet Structure (570 bytes)

The SDK sends **two** AV login packets:

#### AV Login #1 (magic=0x0000, flag=0x0001)

```
Offset  Size  Field               Value
──────────────────────────────────────────
0-1     2     Magic               0x0000
2-3     2     Version             0x000b (11)
4-15    12    Reserved            0x00...
16-17   2     Payload Size        0x0222 (546)
18-19   2     Flags               0x0001
20-23   4     Random ID           4 random bytes
24-279  256   Username            "admin" (null-padded)
280-535 256   Password            "888888" (null-padded) ← IMPORTANT!
536-569 34    Config              SDK configuration
```

#### AV Login #2 (magic=0x2000, flag=0x0000)

Same structure but:
- Magic = `0x2000`
- Flags = `0x0000`
- Random ID = incremented by 1

### Config Section (34 bytes at offset 536)

```
Offset  Size  Field               Value
──────────────────────────────────────────
546-549 4     Resend              0x00000001
550-553 4     Auth Type           0x00000004
554-557 4     SDK Version         0x001f07fb
558-565 8     Reserved            0x00...
566-567 2     Channel Count       0x0003
568-569 2     Reserved            0x0000
```

### Critical Finding: Password

> **The password for AV Login is `"888888"`, NOT the ENR value!**
>
> ENR is only used for PSK derivation in DTLS. The AV Login password is always the fixed string `"888888"`.

### AV Login Response (0x2100)

Camera responds with magic `0x2100` containing session confirmation.

---

## Phase 5: IOCTL Authentication (K10000-K10003)

After AV Login, perform IOCTL-based authentication using challenge-response.

### K10000: Auth Request

Requests authentication challenge from camera.

#### HL Header Structure (16 bytes)

```
Offset  Size  Field               Value
──────────────────────────────────────────
0-1     2     Magic               "HL" (0x484c)
2-3     2     Protocol Version    0x0005
4-5     2     Command Code        0x2710 (10000)
6-7     2     Text Length         0x0000
8-15    8     Reserved            0x00...
```

### K10001: Challenge Response

Camera sends a 16-byte challenge.

#### K10001 Structure (33 bytes)

```
Offset  Size  Field               Value
──────────────────────────────────────────
0-1     2     Magic               "HL" (0x484c)
2-3     2     Protocol Version    0x0025 (37) or 0x0005
4-5     2     Command Code        0x2711 (10001)
6-7     2     Text Length         0x0011 (17)
8-15    8     Reserved            0x00...
16      1     Status              0x03 (challenge ready)
17-32   16    Challenge           16 random bytes
```

### Challenge Response Generation (XXTEA)

The challenge response is computed using XXTEA encryption:

```go
func GenerateChallengeResponse(challenge []byte, enr string, status byte) []byte {
    // Key is derived from ENR (first 16 bytes, padded if needed)
    key := make([]byte, 16)
    copy(key, []byte(enr))

    // XXTEA encrypt the challenge
    response := xxteaEncrypt(challenge, key)

    return response
}
```

### 0x09 ACK Message

> **CRITICAL: An 0x09 ACK must be sent AFTER receiving K10001 and BEFORE sending K10002!**

#### 0x09 ACK Structure (24 bytes)

```
Offset  Size  Field               Value
──────────────────────────────────────────
0-1     2     Magic               0x0009
2-3     2     Version             0x000b
4-7     4     AV Sequence         Global sequence counter
8-11    4     Marker              0xffffffff
12-13   2     Counter             0x0002 ← MUST be 0x02!
14-19   6     Reserved            0x00...
20-21   2     Field               0x062e
22-23   2     Reserved            0x0000
```

### K10002: Auth Response

Send the computed challenge response.

#### K10002 Structure (38 bytes)

```
Offset  Size  Field               Value
──────────────────────────────────────────
0-1     2     Magic               "HL" (0x484c)
2-3     2     Protocol Version    0x0005 ← Always use 5!
4-5     2     Command Code        0x2712 (10002)
6-7     2     Text Length         0x0016 (22)
8-15    8     Reserved            0x00...
16-31   16    Response            XXTEA-encrypted challenge
32-35   4     MAC Prefix          First 4 bytes of UID
36      1     Wake Lock           0x01
37      1     App Type            0x01
```

### K10003: Auth Result

Camera sends authentication result with JSON payload.

#### K10003 Structure (variable)

```
Offset  Size  Field               Value
──────────────────────────────────────────
0-1     2     Magic               "HL" (0x484c)
2-3     2     Protocol Version    0x0025
4-5     2     Command Code        0x2713 (10003)
6-7     2     Text Length         JSON length (e.g., 0x02b0 = 688)
8-15    8     Reserved            0x00...
16+     var   JSON Payload        Connection info
```

#### K10003 JSON Response Example

```json
{
  "connectionRes": "1",
  "cameraInfo": {
    "videoParm": {
      "type": "H264",
      "bitRate": "30",
      "resolution": "2",
      "fps": "20"
    },
    "audioParm": {
      "type": "AAC"
    }
  }
}
```

---

## Phase 6: Video Stream

After successful K10003, camera starts streaming video.

### Video Frame Types

| Magic | Description |
|-------|-------------|
| 0x0508 | Video I-Frame (keyframe) header |
| 0x0500 | Video P-Frame (delta) data |
| 0x0501 | Audio frame |

### Video Frame Header (0x0508)

```
Offset  Size  Field               Description
──────────────────────────────────────────────────
0-1     2     Magic               0x0508
2-3     2     Version             0x000b
4-5     2     Sequence            Frame sequence
6-7     2     Timestamp Low       Timestamp (low 16 bits)
8-11    4     Timestamp           Full timestamp
12-15   4     Frame Size          Total frame size
16-19   4     Fragment Count      Number of fragments
20-23   4     Fragment Index      Current fragment
24-27   4     Codec Info          0x00040000 (H264)
28-31   4     Reserved            0x00000000
32+     var   H264 NAL Units      Video data
```

---

## Frame Formats

### 0x0c IOCTL Frame (40-byte header)

All IOCTL commands (K10000, K10002) are wrapped in 0x0c frames:

```
Offset  Size  Field               Value/Description
──────────────────────────────────────────────────────
0-1     2     Magic               0x000c
2-3     2     Version             0x000b
4-7     4     AV Sequence         Global sequence (increments)
8-15    8     Reserved            0x00...
16-17   2     Channel Type        0x7000
18-19   2     Sub-Channel         0x0000 (K10000) or 0x0001 (K10002)
20-23   4     IOCTL Sequence      Always 0x00000001
24-27   4     Payload Size        HL payload size + 4
28-31   4     Flag                0x00000000 (K10000) or 0x00000001 (K10002)
32-35   4     Reserved            0x00...
36-37   2     IO Type             0x0100
38-39   2     Reserved            0x0000
40+     var   HL Payload          The actual IOCTL command
```

### 0x09 Poll/ACK Message (24 bytes)

```
Offset  Size  Field               Value
──────────────────────────────────────────
0-1     2     Magic               0x0009
2-3     2     Version             0x000b
4-7     4     AV Sequence         Global sequence
8-11    4     Marker              0xffffffff
12-13   2     Counter             0x0002
14-19   6     Reserved            0x00...
20-21   2     Field               0x062e
22-23   2     Reserved            0x0000
```

### 0x0b Status/Keepalive (20 bytes)

```
Offset  Size  Field               Value
──────────────────────────────────────────
0-1     2     Magic               0x000b
2-3     2     Version             0x000b
4-7     4     AV Sequence         Global sequence
8-9     2     Field 1             0x03b4
10-11   2     Field 2             0x0002
12-13   2     Field 3             0x0003
14-19   6     Reserved            0x00...
```

### 0x1000 Channel Message / 0x1100 Channel ACK (36 bytes)

```
Offset  Size  Field               Value
──────────────────────────────────────────
0-1     2     Magic               0x1000 (msg) or 0x1100 (ack)
2-3     2     Version             0x000b
4-7     4     Sequence            Message sequence
8       1     Channel ID          Channel number
9       1     Reserved            0x00
10      1     Subtype             Message subtype
11      1     Reserved            0x00
12-35   24    Data                Channel-specific data
```

### 0x7000 IOCTL Response Frame

Camera wraps IOCTL responses (like K10001, K10003) in 0x7000 frames:

```
Offset  Size  Field               Description
──────────────────────────────────────────────────
0-1     2     Magic               0x0070 (little-endian 0x7000)
2-3     2     Version             0x000b
4-7     4     Sequence            Response sequence
8-31    24    Header              Frame header info
32+     var   HL Payload          The IOCTL response
```

---

## Cryptography

### PSK Derivation

```go
// PSK = SHA256(AuthKey + ENR)
psk := sha256.Sum256([]byte(authKey + enr))
```

### DTLS Cipher

- **Cipher Suite**: TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 (0xCCAC)
- **Key Exchange**: ECDHE with X25519 curve
- **Authentication**: PSK (Pre-Shared Key)
- **Encryption**: ChaCha20-Poly1305 (AEAD)

### XXTEA for Challenge Response

```go
func xxteaEncrypt(data, key []byte) []byte {
    // Convert to uint32 arrays
    v := bytesToUint32(data)
    k := bytesToUint32(key)

    n := len(v)
    delta := uint32(0x9e3779b9)
    rounds := 6 + 52/n

    sum := uint32(0)
    for i := 0; i < rounds; i++ {
        sum += delta
        e := (sum >> 2) & 3
        for p := 0; p < n; p++ {
            // XXTEA mixing function
            ...
        }
    }

    return uint32ToBytes(v)
}
```

---

## Key Findings & Fixes

### Critical Discoveries

| Issue | Wrong Value | Correct Value | Impact |
|-------|-------------|---------------|--------|
| AV Login Password | ENR | `"888888"` | Login fails |
| K10002 Sub-Channel | 0 | 1 | Auth ignored |
| K10002 Flag | 0 | 1 | Auth ignored |
| 0x09 ACK Counter | 0x01 | 0x02 | K10002 rejected |
| 0x09 ACK Timing | Not sent | After K10001 | K10002 rejected |

### AV Sequence Counter

The `GlobalAVSeq` counter increments for every control message:

```
Message         AVSeq
─────────────────────
K10000          0
0x09 ACK        1
K10002          2
```

### Protocol Versions

| Context | Version |
|---------|---------|
| K10000 HL Protocol | 0x0005 |
| K10001 HL Protocol | 0x0025 (37) |
| K10002 HL Protocol | 0x0005 (always!) |
| K10003 HL Protocol | 0x0025 |
| Frame Version | 0x000b |

---

## Quick Reference

### Message Sequence

```
1. DISCO broadcast → 255.255.255.255:32761
2. DISCO response ← Camera IP:Port
3. DISCO direct → Camera
4. Session 0x0402 → Camera
5. Session 0x0404 ← Camera
6. DTLS Handshake ↔ Camera
7. AV Login #1 (0x0000) → Camera
8. AV Login #2 (0x2000) → Camera
9. AV Login Response (0x2100) ← Camera
10. K10000 in 0x0c frame → Camera
11. K10001 in 0x7000 frame ← Camera
12. 0x09 ACK → Camera (IMPORTANT!)
13. K10002 in 0x0c frame → Camera
14. K10003 in 0x7000 frame ← Camera
15. Video frames (0x0508/0x0500) ← Camera
```

### Important Constants

```go
const (
    // Discovery
    DiscoBroadcastPort = 32761

    // Commands
    CmdK10000 = 0x2710  // 10000
    CmdK10001 = 0x2711  // 10001
    CmdK10002 = 0x2712  // 10002
    CmdK10003 = 0x2713  // 10003

    // AV Login
    AVLoginMagic1 = 0x0000
    AVLoginMagic2 = 0x2000
    AVLoginResponse = 0x2100
    AVLoginPassword = "888888"

    // Frame Types
    FrameIOCTL = 0x000c
    FrameACK   = 0x0009
    FrameStatus = 0x000b
    FrameChannel = 0x1000
    FrameChannelAck = 0x1100
    FrameIOCTLResponse = 0x7000

    // Video
    VideoIFrame = 0x0508
    VideoPFrame = 0x0500
    AudioFrame  = 0x0501
)
```

---

## Tools Used

- **GDB Python Scripts**: Traced SDK function calls (`IOTC_sCHL_write`, `avSendIOCtrl`)
- **tcpdump/Wireshark**: Captured network traffic
- **strings/objdump**: Analyzed SDK library symbols
- **Custom CLI**: Go implementation for testing

---

## References

- ThroughTek TUTK SDK Documentation
- pion/dtls - Go DTLS implementation
- Wyze camera firmware analysis

---

*Document generated from reverse engineering session, December 2025*
