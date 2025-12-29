# TUTK/IOTC Protocol Reference for Wyze Cameras

This document provides detailed technical specifications for implementing native Wyze camera streaming without relying on ThroughTek's proprietary TUTK SDK. It covers the complete protocol stack from cloud authentication through encrypted P2P streaming, enabling direct access to Wyze camera video and audio feeds.

## Table of Contents

1. [Overview](#1-overview)
2. [Architecture](#2-architecture)
3. [Cloud API](#3-cloud-api)
4. [IOTC Discovery & Session](#4-iotc-discovery--session)
5. [DTLS Encryption](#5-dtls-encryption)
6. [AV Login](#6-av-login)
7. [K-Command Authentication](#7-k-command-authentication)
8. [AV Streaming Protocol](#8-av-streaming-protocol)
9. [FRAMEINFO Structure](#9-frameinfo-structure)
10. [Codec IDs & Sample Rates](#10-codec-ids--sample-rates)
11. [RTP Timestamp Calculation](#11-rtp-timestamp-calculation)
12. [Intercom](#12-intercom)
13. [Error Codes](#13-error-codes)
14. [IOTYPE Constants](#14-iotype-constants)
15. [Cryptography](#15-cryptography)
16. [SDK Constants Reference](#16-sdk-constants-reference)
17. [Low-Level Frame Formats](#17-low-level-frame-formats)

---

## 1. Overview

Wyze cameras use ThroughTek's TUTK/IOTC SDK for P2P communication. This documentation reverse-engineers the protocol to enable streaming video/audio without the proprietary native SDK library.

### Protocol Stack

```
+----------------------------------------------------------+
|                   Wyze Cloud API                         |
|  Authentication, camera info (UID, ENR, MAC)             |
+----------------------------------------------------------+
                          |
+----------------------------------------------------------+
|                  K-Command Auth (K10000-K10003)          |
|  Proprietary XXTEA challenge-response                    |
+----------------------------------------------------------+
                          |
+----------------------------------------------------------+
|                    AV Streaming                          |
|  Video (H.264/H.265), Audio (AAC/G.711/Opus)             |
+----------------------------------------------------------+
                          |
+----------------------------------------------------------+
|              DTLS 1.2 (ChaCha20-Poly1305)                |
|  PSK = SHA256(ENR)                                       |
+----------------------------------------------------------+
                          |
+----------------------------------------------------------+
|                     IOTC Session                         |
|  Discovery (0x0601), Session (0x0402)                    |
+----------------------------------------------------------+
                          |
+----------------------------------------------------------+
|             TransCode ("Charlie") Cipher                 |
|  Obfuscation for IOTC packets                            |
+----------------------------------------------------------+
                          |
+----------------------------------------------------------+
|                        UDP                               |
|  Port 32761 (default)                                    |
+----------------------------------------------------------+
```

### Required Credentials

| Parameter | Description | Source |
|-----------|-------------|--------|
| UID | Device P2P ID | Wyze Cloud API |
| ENR | 16+ byte encryption key | Wyze Cloud API |
| MAC | Device MAC address | Wyze Cloud API |
| AuthKey | SHA256(ENR + MAC)[:6] in Base64 | Calculated |

### Supported Camera Models

All Wyze cameras using TUTK/IOTC SDK with DTLS support (current firmware).

---

## 2. Architecture

### Connection Flow

```
Client                                             Camera
   |                                                  |
   |  ================ IOTC Discovery =============== |
   |                                                  |
   |  DISCO broadcast (0x0601) ---------------------> |
   |  <---------------------- DISCO response (0x0602) |
   |  DISCO direct (0x0601) ------------------------> |
   |                                                  |
   |  ================= IOTC Session ================ |
   |                                                  |
   |  Session Request (0x0402) ---------------------> |
   |  <-------------------- Session Response (0x0404) |
   |                                                  |
   |  ================ DTLS Handshake =============== |
   |                                                  |
   |  ClientHello (wrapped in DATA_TX) -------------> |
   |  <------------------------ ServerHello + KeyExch |
   |  ClientKeyExchange + Finished -----------------> |
   |  <------------------------------ DTLS Finished   |
   |                                                  |
   |  =================== AV Login ================== |
   |                                                  |
   |  AV Login #1 (magic=0x0000) -------------------> |
   |  AV Login #2 (magic=0x2000) -------------------> |
   |  <----------------------- AV Login Resp (0x2100) |
   |  ACK (0x0009) ---------------------------------> |
   |                                                  |
   |  ==================== K-Auth =================== |
   |                                                  |
   |  K10000 (Auth Request) ------------------------> |
   |  <--------------------------- K10001 (Challenge) |
   |  ACK (0x0009) ---------------------------------> |
   |  K10002 (Challenge Response) ------------------> |
   |  <------------------------- K10003 (Auth Result) |
   |  ACK (0x0009) ---------------------------------> |
   |                                                  |
   |  ================== Streaming ================== |
   |                                                  |
   |  <--------------------------- Video/Audio frames |
   |  <--------------------------- Video/Audio frames |
   |                       ...                        |
```

### Implementation Mapping

| SDK Function | Implementation |
|--------------|----------------|
| `IOTC_Connect_ByUID` | Discovery + Session setup |
| `avClientStartEx` | AV Login sequence |
| `avSendIOCtrl` | Send IOCTL command |
| `avRecvIOCtrl` | Receive IOCTL response |
| `avRecvFrameData2` | Read AV packet |
| K-Auth sequence | K10000-K10003 exchange |

---

## 3. Cloud API

### Authentication

Wyze uses triple-MD5 password hashing:

```go
func hashPassword(password string) string {
    encoded := password
    for i := 0; i < 3; i++ {
        hash := md5.Sum([]byte(encoded))
        encoded = hex.EncodeToString(hash[:])
    }
    return encoded
}
```

### Endpoints

| Endpoint | Purpose |
|----------|---------|
| `https://auth-prod.api.wyze.com/api/user/login` | Authentication |
| `https://api.wyzecam.com/app/v2/home_page/get_object_list` | Device list |
| `https://api.wyzecam.com/app/v2/device/get_iotc_info` | P2P connection info |

### Camera Info Response

```json
{
  "mac": "80482C4CF472",
  "enr": "aKzdqckqZ8HUHFe5...",
  "p2p_id": "HSBJYB5HSETGCDWD111A",
  "ip": "192.168.1.100",
  "dtls": 1
}
```

---

## 4. IOTC Discovery & Session

### Discovery Protocol

Discovery uses UDP broadcast on port 32761.

#### DISCO Request (0x0601)

```
Offset  Size  Field           Description
------  ----  -----           -----------
0-3     4     Header          0x04 0x02 0x1a 0x02
4-5     2     BodySize        72 (0x0048)
8-9     2     Command         0x0601 (CmdDiscoReq)
10-11   2     SubCommand      0x0021
16-35   20    UID             Device UID (null-padded)
52-59   8     RandomID        8 random bytes
60      1     Stage           1=broadcast, 2=direct
72-79   8     AuthKey         8-byte auth key
```

#### Discovery Encryption (TransCode)

All IOTC packets are obfuscated using the "Charlie" cipher:

```go
const charlie = "Charlie is the designer of P2P!!"

func TransCodePartial(src []byte) []byte {
    // XOR with charlie string
    // Bit rotations
    // Byte swapping
}
```

### Session Setup (0x0402)

After discovery, establish a session:

```
Offset  Size  Field           Description
------  ----  -----           -----------
0-3     4     Header          0x04 0x02 0x1a 0x02
4-5     2     BodySize        36 (0x0024)
8-9     2     Command         0x0402 (CmdSessionReq)
16-35   20    UID             Device UID
36-43   8     RandomID        Same as DISCO
48-51   4     Timestamp       Unix timestamp
```

Camera responds with 0x0404 confirming session.

---

## 5. DTLS Encryption

### PSK Derivation

```go
// PSK = SHA256(ENR)
func CalculatePSK(enr string) []byte {
    hash := sha256.Sum256([]byte(enr))
    return hash[:]
}
```

### DTLS Parameters

| Parameter | Value |
|-----------|-------|
| Version | DTLS 1.2 |
| Cipher Suite | TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 (0xCCAC) |
| PSK Identity | `AUTHPWD_admin` |
| PSK | SHA256(ENR) - 32 bytes |
| Curve | X25519 |

### DTLS Transport Wrapping

DTLS records are wrapped in IOTC DATA_TX (0x0407) packets:

```
Offset  Size  Field           Description
------  ----  -----           -----------
0-15    16    IOTC Header     Standard IOTC frame header
16-27   12    SubHeader       Session info
28+     var   DTLS Record     Encrypted DTLS data
```

The transport layer strips this wrapper before passing to the DTLS implementation.

---

## 6. AV Login

After DTLS handshake, send AV login packets.

### AV Login Packet #1 (570 bytes)

```
Offset   Size  Field           Value
------   ----  -----           -----
0-1      2     Magic           0x0000
2-3      2     Version         0x000c (12)
16-17    2     PayloadSize     0x0222 (546)
18-19    2     Flags           0x0001
20-23    4     RandomID        Random bytes
24-279   256   Username        "admin" (null-padded)
280-535  256   Password        ENR
546-549  4     Resend          0x00000001
550-553  4     SecurityMode    0x00000004 (DTLS)
554-557  4     Capabilities    0x001f07fb
```

### AV Login Packet #2 (572 bytes)

Same structure but:
- Magic = 0x2000
- Flags = 0x0000
- PayloadSize = 0x0224 (548)

### AV Login Response (0x2100)

Camera responds with magic 0x2100 confirming login.

---

## 7. K-Command Authentication

### K-Command Flow

```
K10000 → Client sends auth request
K10001 ← Camera sends 16-byte challenge + status byte
ACK    → Client acknowledges
K10002 → Client sends XXTEA-encrypted response
K10003 ← Camera sends auth result (JSON with camera info)
ACK    → Client acknowledges
         ↓
      Streaming begins automatically!
```

### K10000 Structure (16 bytes)

```
Offset  Size  Field           Value
------  ----  -----           -----
0-1     2     Magic           "HL"
2       1     Version         5
4-5     2     CmdID           10000 (0x2710)
```

### K10001 Structure (33+ bytes)

```
Offset  Size  Field           Description
------  ----  -----           -----------
0-1     2     Magic           "HL"
4-5     2     CmdID           10001 (0x2711)
16      1     Status          1, 3, or 6 (key selection)
17-32   16    Challenge       Random bytes to decrypt
```

### Status Byte Interpretation

| Status | Key Derivation |
|--------|----------------|
| 1 | Use "FFFFFFFFFFFFFFFF" (default) |
| 3 | Use ENR[0:16] |
| 6 | Double decryption: ENR[0:16] then ENR[16:32] |

### K10002 Structure (38 bytes)

```
Offset  Size  Field           Value
------  ----  -----           -----
0-1     2     Magic           "HL"
2       1     Version         5
4-5     2     CmdID           10002 (0x2712)
6       1     PayloadLen      22
16-31   16    Response        XXTEA-decrypted challenge
32-35   4     UIDPrefix       First 4 bytes of UID
36      1     VideoFlag       1 = enable video
37      1     AudioFlag       1 = enable audio
```

### K10003 Response

Contains JSON with camera capabilities:

```json
{
    "connectionRes": "1",
    "cameraInfo": {
        "apartalarmParm": {
            "heightY": "50",
            "longX": "50",
            "startX": "25",
            "startY": "25",
            "type": "0"
        },
        "basicInfo": {
            "firmware": "4.52.9.4188",
            "hardware": "0.0.0.0",
            "mac": "123456789ABC",
            "model": "HL_CAM4",
            "type": "camera",
            "wifidb": "70"
        },
        "channelResquestResult": {
            "audio": "1",
            "video": "1"
        },
        "recordType": {
            "type": "1"
        },
        "sdParm": {
            "capacity": "0",
            "detail": "0",
            "free": "0",
            "status": "2"
        },
        "settingParm": {
            "logSd": "1",
            "logUdisk": "1",
            "nightVision": "3",
            "osd": "1",
            "stateVision": "1",
            "telnet": "2",
            "tz": "1"
        },
        "uDiskParm": {
            "capacity": "0",
            "free": "0",
            "status": "2"
        },
        "videoParm": {
            "bitRate": "30",
            "fps": "20",
            "horizontalFlip": "1",
            "logo": "1",
            "resolution": "2",
            "time": "1",
            "type": "H264",
            "verticalFlip": "1"
        }
    }
}
```

---

## 8. AV Streaming Protocol

After K-Auth, the camera sends AV data packets with channel-based routing.

### Channels

| Channel | Type | Description |
|---------|------|-------------|
| 0x03 | Audio | Single-packet frames (always pkt_total=1) |
| 0x05 | I-Video | Keyframes (can be multi-packet) |
| 0x07 | P-Video | Delta frames (can be multi-packet) |

### Frame Types (Complete)

| Type | Name | Header | FrameInfo | Description |
|------|------|--------|-----------|-------------|
| 0x00 | Cont | 28 | No | Continuation (middle packet) |
| 0x01 | EndSingle | 28 | 40 bytes | Single-packet frame |
| 0x04 | ContAlt | 28 | No | Alternative continuation |
| 0x05 | EndMulti | 28 | 40 bytes | Last packet of multi-packet frame |
| 0x08 | Start | 36 | No | First packet of multi-packet I-frame |
| 0x09 | StartAlt | 36 | 40 bytes* | Single-packet OR multi-packet start |
| 0x0d | EndExt | 36 | 40 bytes | Extended end (commonly used for Audio) |

*0x09 has FrameInfo only when pkt_total == 1 (single-packet frame)

### Header Size Detection

**IMPORTANT**: Header size is determined by FrameType

```go
switch frameType {
case 0x08, 0x09, 0x0d:  // Start, StartAlt, EndExt
    headerSize = 36
default:                // Cont, ContAlt, EndSingle, EndMulti
    headerSize = 28
}
```

### 28-Byte Header Layout

Used by: Cont (0x00), ContAlt (0x04), EndSingle (0x01), EndMulti (0x05)

```
Offset  Size  Field                   Description
──────────────────────────────────────────────────────────────────────────
[0]     1     Channel                 0x03=Audio, 0x05=I-Video, 0x07=P-Video
[1]     1     FrameType               0x00/0x01/0x04/0x05
[2-3]   2     Version                 Always 0x000b (11)
[4-5]   2     TX Sequence             Global incrementing (uint16 LE)
[6-7]   2     Magic                   Always 0x507e (LE) - "P~"
[8]     1     Channel                 Duplicate of [0]
[9]     1     Stream Index            0x00 normal, 0x01 for End packets
[10-11] 2     Running Packet Counter  Global counter (does NOT reset per frame)
[12-13] 2     pkt_total               Total packets in this frame
[14-15] 2     pkt_idx OR 0x0028       See "FrameInfo Marker" below
[16-17] 2     Payload Size            Usually 0x0400 (1024) for video
[18-19] 2     Reserved                Always 0x0000
[20-23] 4     Previous Frame          Previous frame number (or 0)
[24-27] 4     Frame Number            Current frame number (uint32 LE) → USE FOR REASSEMBLY
```

### 36-Byte Header Layout

Used by: Start (0x08), StartAlt (0x09), EndExt (0x0d)

```
Offset  Size  Field                   Description
──────────────────────────────────────────────────────────────────────────
[0]     1     Channel                 0x03=Audio, 0x05=I-Video, 0x07=P-Video
[1]     1     FrameType               0x08/0x09/0x0d
[2-3]   2     Version                 Always 0x000b (11)
[4-5]   2     TX Sequence             Global incrementing (uint16 LE)
[6-7]   2     Magic                   Always 0x507e (LE) - "P~"
[8-11]  4     Timestamp/ID            Variable - NOT reliable!
[12-15] 4     Variable                NOT reliable for header detection!
[16]    1     Channel                 Duplicate of [0]
[17]    1     Stream Index            0x00 normal, 0x01 for End/Audio
[18-19] 2     Channel Frame Index     Per-channel index - NOT for reassembly!
[20-21] 2     pkt_total               Total packets in this frame
[22-23] 2     pkt_idx OR 0x0028       See "FrameInfo Marker" below
[24-25] 2     Payload Size            Usually 0x0400 (1024) for video
[26-27] 2     Reserved                Always 0x0000
[28-31] 4     Previous Frame          Previous global frame number
[32-35] 4     Frame Number            Current global frame (uint32 LE) → USE FOR REASSEMBLY
```

**CRITICAL**: [18-19] is channel-specific index (starts at 0 per channel).
For frame reassembly, use [32-35] which matches the [24-27] position in 28-byte headers.

### FrameInfo Marker (0x0028)

The value at [14-15] (28-byte) or [22-23] (36-byte) has dual meaning:

| Condition | Interpretation |
|-----------|----------------|
| End packet (0x01, 0x05, 0x0d) AND value == 0x0028 | FrameInfo marker - 40 bytes at payload end |
| Otherwise | pkt_idx (0-based packet index within frame) |

**IMPORTANT**: 0x0028 (hex) = 40 (decimal). For non-End packets, this is simply pkt_idx=40!

```go
if IsEndFrame(frameType) && pktIdxOrMarker == 0x0028 {
    hasFrameInfo = true
    pktIdx = pktTotal - 1  // Last packet
} else {
    pktIdx = pktIdxOrMarker  // Actual packet index
}
```

### Frame Reassembly Algorithm

```
1. Parse PacketHeader to get: channel, frameType, pkt_idx, pkt_total, frame_no

2. On frame number change:
   - Emit previous frame if complete (all packets + FrameInfo)
   - Otherwise log as incomplete

3. Store packet:
   - Key: pkt_idx
   - Value: payload (MUST be copied - buffer is reused!)

4. Store FrameInfo if present (End packets)

5. When all packets received AND FrameInfo present:
   - Assemble in order: packets[0] + packets[1] + ... + packets[pkt_total-1]
   - Validate size against FrameInfo.PayloadSize
   - Emit complete frame
```

### Example: Multi-Packet I-Frame (14 packets)

```
[WIRE] ch=0x05 type=0x08 pkt=0/14 frame=1    ← Start (36-byte header)
[WIRE] ch=0x05 type=0x00 pkt=1/14 frame=1    ← Cont (28-byte header)
[WIRE] ch=0x05 type=0x00 pkt=2/14 frame=1    ← Cont
...
[WIRE] ch=0x05 type=0x00 pkt=12/14 frame=1   ← Cont
[WIRE] ch=0x05 type=0x05 pkt=13/14 frame=1   ← EndMulti + FrameInfo (28-byte header)
```

### Example: Single-Packet P-Frame

```
[WIRE] ch=0x07 type=0x05 pkt=0/1 frame=42    ← EndSingle + FrameInfo
```

### Audio Specifics

- Always single-packet frames (pkt_total=1)
- Commonly uses EndExt (0x0d) with 36-byte header
- Payload size at [24-27] is uint32 (not uint16 like video)

---

## 9. FRAMEINFO Structure

### Location

FrameInfo is appended to the **end** of End packets (types 0x01, 0x05, 0x0d, and 0x09 when pkt_total=1).

```
[Header: 28 or 36 bytes][Payload: variable][FrameInfo: 40 bytes]
```

The FrameInfo marker (0x0028 at [14-15] or [22-23]) indicates its presence.

### Wire Format (40 bytes - Wyze Extension)

```
Offset  Size  Field           Description
──────────────────────────────────────────────────────────────────────────
[0-1]   2     codec_id        Video: 0x004e (H.264), 0x0050 (H.265)
                              Audio: 0x0090 (AAC-ELD), 0x0089 (G.711u), etc.
[2]     1     flags           Video: 0x00=P-frame, 0x01=I-frame (keyframe)
                              Audio: (sr_idx<<2) | (bits16<<1) | channels
[3]     1     cam_index       Camera index (usually 0)
[4]     1     online_num      Online viewer count
[5]     1     tags            Bit flags (commonly 0x14 for video)
[6-7]   2     reserved        Always 0x0000
[8-11]  4     timestamp_us    Microseconds within second (0-999999)
[12-15] 4     timestamp_sec   Unix timestamp in SECONDS
[16-19] 4     payload_size    Total payload size (for validation)
[20-23] 4     frame_no        Absolute frame counter (since camera boot)
[24-39] 16    device_id       MAC address as ASCII (e.g., "80482C4CF472")
```

**SDK vs Wire Format**: The official SDK FRAMEINFO_t is only 16 bytes. Wyze extends it to 40 bytes with additional fields.

### Frame Number Note

The `frame_no` in FrameInfo is the **absolute** counter since camera boot (e.g., 1610082).
This differs from the header's `Frame Number` field which is relative to the session.

### Audio Flags Encoding

```
flags = (sample_rate_index << 2) | (bits16 << 1) | channels

Example: 16kHz, 16-bit, Mono
(3 << 2) | (1 << 1) | 0 = 0x0E
```

### Parsing Implementation

```go
func ParseFrameInfo(data []byte) *FrameInfo {
    offset := len(data) - 40  // FRAMEINFO at END of packet
    fi := data[offset:]

    return &FrameInfo{
        CodecID:     binary.LittleEndian.Uint16(fi[0:2]),
        Flags:       fi[2],
        CamIndex:    fi[3],
        OnlineNum:   fi[4],
        Tags:        fi[5],
        TimestampUS: binary.LittleEndian.Uint32(fi[8:12]),
        Timestamp:   binary.LittleEndian.Uint32(fi[12:16]),
        PayloadSize: binary.LittleEndian.Uint32(fi[16:20]),
        FrameNo:     binary.LittleEndian.Uint32(fi[20:24]),
    }
}
```

---

## 10. Codec IDs & Sample Rates

### Video Codecs

| Name | ID | Hex | Description |
|------|-----|-----|-------------|
| MPEG4 | 76 | 0x4C | MPEG-4 |
| H.263 | 77 | 0x4D | H.263 |
| H.264 | 78 | 0x4E | H.264/AVC |
| MJPEG | 79 | 0x4F | Motion JPEG |
| H.265 | 80 | 0x50 | H.265/HEVC |

### Audio Codecs

| Name | ID | Hex | Description |
|------|-----|-----|-------------|
| AAC Raw | 134 | 0x86 | AAC raw |
| AAC ADTS | 135 | 0x87 | AAC with ADTS header |
| AAC LATM | 136 | 0x88 | AAC with LATM |
| G.711 u-law | 137 | 0x89 | PCMU |
| G.711 A-law | 138 | 0x8A | PCMA |
| ADPCM | 139 | 0x8B | ADPCM |
| PCM | 140 | 0x8C | PCM 16-bit |
| Speex | 141 | 0x8D | Speex |
| MP3 | 142 | 0x8E | MP3 |
| G.726 | 143 | 0x8F | G.726 |
| AAC-ELD | 144 | 0x90 | AAC Enhanced Low Delay |
| Opus | 146 | 0x92 | Opus |

### Sample Rates

| Index | Frequency |
|-------|-----------|
| 0x00 | 8000 Hz |
| 0x01 | 11025 Hz |
| 0x02 | 12000 Hz |
| 0x03 | 16000 Hz |
| 0x04 | 22050 Hz |
| 0x05 | 24000 Hz |
| 0x06 | 32000 Hz |
| 0x07 | 44100 Hz |
| 0x08 | 48000 Hz |

---

## 11. RTP Timestamp Calculation

### Combining Timestamp Fields

FRAMEINFO contains split timestamps that must be combined:

```go
// Combine for absolute timestamp in microseconds
absoluteTS := uint64(fi.Timestamp) * 1000000 + uint64(fi.TimestampUS)

// Convert to RTP timestamp (90kHz for video)
rtpTS := uint32(absoluteTS * 90000 / 1000000)

// For audio, use codec-specific clock rate
clockRate := fi.SampleRate()  // e.g., 16000 for 16kHz
rtpTS := uint32(absoluteTS * clockRate / 1000000)
```

### Example

```
timestamp_sec=1766928018, timestamp_us=980266
  → absolute = 1766928018980266 µs
  → rtp_video = (absolute * 90000 / 1000000) = wrapped to uint32

At 20fps: delta between frames ≈ 50000 µs (50ms)
```

---

## 12. Intercom

### Two-Way Audio (K10010)

Wyze cameras support intercom via the K10010 ControlChannel command.

```go
// K10010 structure
buf := make([]byte, 21)
buf[0], buf[1] = 'H', 'L'
buf[2] = 5  // Version
binary.LittleEndian.PutUint16(buf[4:6], 10010)
buf[6] = 5  // Payload length
buf[16] = mediaType  // 1=Video, 2=Audio, 3=ReturnAudio
buf[17] = enabled    // 1=Enable, 2=Disable
```

### Media Types

| Value | Type |
|-------|------|
| 1 | Video stream |
| 2 | Audio stream (from camera) |
| 3 | Return audio (to camera, intercom) |
| 4 | RDT channel |

### Audio Format

- Detected from incoming audio FRAMEINFO
- Default: AAC 16kHz Mono (codec=0x90, flags=0x0E)

**Note**: SPEAKERSTART/SPEAKERSTOP IOCTRLs are NOT required. Only K10010 is needed.

---

## 13. Error Codes

### AV Error Codes

| Code | Constant | Description |
|------|----------|-------------|
| 0 | AV_ER_NoERROR | Success |
| -20000 | AV_ER_INVALID_ARG | Invalid argument |
| -20006 | AV_ER_INVALID_SID | Invalid session ID |
| -20011 | AV_ER_TIMEOUT | Operation timeout |
| -20013 | AV_ER_INCOMPLETE_FRAME | Incomplete frame |
| -20014 | AV_ER_LOSED_THIS_FRAME | Frame lost |
| -20015 | AV_ER_SESSION_CLOSE_BY_REMOTE | Remote closed |
| -20040 | AV_ER_DTLS_WRONG_PASSWORD | Wrong PSK |
| -20041 | AV_ER_DTLS_AUTH_FAIL | DTLS auth failed |

### IOTC Error Codes

| Code | Constant | Description |
|------|----------|-------------|
| -1 | IOTC_ER_SERVER_NOT_RESPONSE | Server not responding |
| -13 | IOTC_ER_TIMEOUT | Connection timeout |
| -19 | IOTC_ER_CAN_NOT_FIND_DEVICE | Device not found |
| -22 | IOTC_ER_SESSION_CLOSE_BY_REMOTE | Remote closed session |
| -68 | IOTC_ER_DEVICE_REJECT_BY_WRONG_AUTH_KEY | Wrong auth key |

---

## 14. IOTYPE Constants

### Streaming Control

| Constant | Value | Description |
|----------|-------|-------------|
| IOTYPE_USER_IPCAM_START | 0x01FF | Start video |
| IOTYPE_USER_IPCAM_STOP | 0x02FF | Stop video |
| IOTYPE_USER_IPCAM_AUDIOSTART | 0x0300 | Start audio |
| IOTYPE_USER_IPCAM_AUDIOSTOP | 0x0301 | Stop audio |

### Intercom

| Constant | Value | Description |
|----------|-------|-------------|
| IOTYPE_USER_IPCAM_SPEAKERSTART | 0x0350 | Start intercom |
| IOTYPE_USER_IPCAM_SPEAKERSTOP | 0x0351 | Stop intercom |

### Device Control

| Constant | Value | Description |
|----------|-------|-------------|
| IOTYPE_USER_IPCAM_PTZ_COMMAND | 0x1001 | PTZ control |
| IOTYPE_USER_IPCAM_RECEIVE_FIRST_IFRAME | 0x1002 | Request keyframe |
| IOTYPE_USER_IPCAM_DEVINFO_REQ | 0x0340 | Device info request |

### Wyze K-Commands

| CmdID | Name | Description |
|-------|------|-------------|
| 10000 | KCmdAuth | Auth request |
| 10001 | KCmdChallenge | Challenge from camera |
| 10002 | KCmdChallengeResp | Challenge response |
| 10003 | KCmdAuthResult | Auth result |
| 10010 | KCmdControlChannel | Start/stop media |
| 10056 | KCmdSetResolution | Set resolution/bitrate |
| 10057 | KCmdSetResolutionResp | Set resolution response |

---

## 15. Cryptography

### XXTEA Algorithm

Used for K-Auth challenge-response:

```go
const delta = 0x9e3779b9

func XXTEADecrypt(data, key []byte) []byte {
    // Convert to uint32 arrays
    k := toUint32Array(key)  // 4 x uint32
    v := toUint32Array(data) // n x uint32

    n := len(v)
    rounds := 6 + 52/n
    sum := uint32(rounds) * delta

    for rounds > 0 {
        e := (sum >> 2) & 3
        for p := n - 1; p > 0; p-- {
            z := v[p-1]
            v[p] -= mx(sum, y, z, p, e, k)
            y = v[p]
        }
        // ... (full algorithm in crypto/xxtea.go)
        sum -= delta
        rounds--
    }
    return toBytes(v)
}
```

### TransCode ("Charlie") Cipher

Obfuscates IOTC packets:

```go
const charlie = "Charlie is the designer of P2P!!"

// XOR with charlie string + bit rotations + byte swapping
func TransCodePartial(src []byte) []byte {
    // Process in 16-byte blocks
    // XOR with charlie
    // Bit rotate uint32s
    // Swap bytes
}
```

### AuthKey Calculation

```go
func CalculateAuthKey(enr, mac string) []byte {
    data := enr + strings.ToUpper(mac)
    hash := sha256.Sum256([]byte(data))
    b64 := base64.StdEncoding.EncodeToString(hash[:6])
    // Replace +/= with Z/9/A
    return []byte(b64)
}
```

---

## 16. SDK Constants Reference

### Essential Constants (from TUTK SDK)

```go
// Video Codecs
const (
    CodecH264 uint16 = 0x4E  // H.264/AVC
    CodecH265 uint16 = 0x50  // H.265/HEVC
)

// Audio Codecs
const (
    AudioCodecAACADTS uint16 = 0x87  // AAC with ADTS
    AudioCodecAACELD  uint16 = 0x90  // AAC-ELD (Wyze)
    AudioCodecG711U   uint16 = 0x89  // PCMU
    AudioCodecOpus    uint16 = 0x92  // Opus
)

// IOTC Commands
const (
    CmdDiscoReq     uint16 = 0x0601
    CmdDiscoRes     uint16 = 0x0602
    CmdSessionReq   uint16 = 0x0402
    CmdSessionRes   uint16 = 0x0404
    CmdDataTX       uint16 = 0x0407
    CmdDataRX       uint16 = 0x0408
)

// K-Commands
const (
    KCmdAuth           = 10000
    KCmdChallenge      = 10001
    KCmdChallengeResp  = 10002
    KCmdAuthResult     = 10003
    KCmdControlChannel = 10010
)
```

---

## 17. Low-Level Frame Formats

### 0x0c IOCTL Frame (40-byte header)

All IOCTL commands (K10000, K10002) are wrapped in 0x0c frames:

```
Offset  Size  Field           Value/Description
------  ----  -----           -----------------
0-1     2     Magic           0x000c
2-3     2     Version         0x000b
4-7     4     AVSequence      Global sequence (increments)
8-15    8     Reserved        0x00...
16-17   2     ChannelType     0x7000
18-19   2     SubChannel      0x0000 (K10000) or 0x0001 (K10002)
20-23   4     IOCTLSequence   Always 0x00000001
24-27   4     PayloadSize     HL payload size + 4
28-31   4     Flag            0x00000000 (K10000) or 0x00000001 (K10002)
32-35   4     Reserved        0x00...
36-37   2     IOType          0x0100
38-39   2     Reserved        0x0000
40+     var   HLPayload       The actual IOCTL command (HL header + data)
```

### 0x09 ACK/Poll Message (24 bytes)

```
Offset  Size  Field           Value
------  ----  -----           -----
0-1     2     Magic           0x0009
2-3     2     Version         0x000b
4-7     4     AVSequence      Global sequence
8-11    4     Marker          0xffffffff
12-13   2     Counter         0x0002
14-19   6     Reserved        0x00...
20-21   2     Field           0x062e
22-23   2     Reserved        0x0000
```

### 0x0b Status/Keepalive (20 bytes)

```
Offset  Size  Field           Value
------  ----  -----           -----
0-1     2     Magic           0x000b
2-3     2     Version         0x000b
4-7     4     AVSequence      Global sequence
8-9     2     Field1          0x03b4
10-11   2     Field2          0x0002
12-13   2     Field3          0x0003
14-19   6     Reserved        0x00...
```

### 0x1000 Channel Message / 0x1100 Channel ACK (36 bytes)

```
Offset  Size  Field           Value
------  ----  -----           -----
0-1     2     Magic           0x1000 (msg) or 0x1100 (ack)
2-3     2     Version         0x000b
4-7     4     Sequence        Message sequence
8       1     ChannelID       Channel number
9       1     Reserved        0x00
10      1     Subtype         Message subtype
11      1     Reserved        0x00
12-35   24    Data            Channel-specific data
```

### 0x7000 IOCTL Response Frame

Camera wraps IOCTL responses (K10001, K10003) in 0x7000 frames:

```
Offset  Size  Field           Description
------  ----  -----           -----------
0-1     2     Magic           0x0070 (little-endian = 0x7000)
2-3     2     Version         0x000b
4-7     4     Sequence        Response sequence
8-31    24    Header          Frame header info
32+     var   HLPayload       The IOCTL response (HL header + data)
```
