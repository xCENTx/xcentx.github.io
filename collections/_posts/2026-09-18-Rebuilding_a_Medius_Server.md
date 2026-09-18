# REBUILDING A SOCOM 1 MEDIUS SERVER

*From the first encrypted packet to a working multiplayer game*

> This post documents how I reconstructed enough of the original SOCOM 1 online service to register an account, log in, enter the lobby, create or join a game and exchange live gameplay traffic between multiple PlayStation 2 clients.
>
> This is not an official Sony server and it is not a complete implementation of every Medius feature. It is a research server built from packet captures, open-source references, reverse engineering and a LOT of trial and error.

## OVERVIEW

SOCOM does not connect to one magical "game server" which handles everything. The online flow is split across several services and each service is responsible for a different part of the process.

The server currently implements the following:

- SCE-RT packet framing
- The RSA authentication handshake
- The modified RC4 cipher used by the client
- Medius SessionBegin
- Account registration and login
- Persistent SQLite accounts
- Session and access-key reservation
- Lobby and channel requests
- Game creation and game joining
- DME game connections
- World-local player identifiers
- Broadcast and single-recipient gameplay routing
- Player join and disconnect notifications
- Basic player statistics and server logging

The following areas are still being researched:

- The complete NAT service behavior
- Every DME message and field layout
- Some ladder, statistics and reporting messages
- Password-protected briefing rooms
- Production-grade account security and administration

The important distinction here is that the game is no longer stopping at a fake login response. Two PCSX2 clients can authenticate independently, create and join the same game world, connect to the DME and have traffic forwarded between them. That was the point where this stopped being a packet-replay experiment and started behaving like an actual server.

## HOW THIS PROJECT STARTED

I originally approached this from the same direction as my SOCOM and PCSX2 reversal work: start at the first thing I can prove, inspect what consumes it and continue moving forward one structure at a time.

The first useful information I had was the hostname used by the retail game and the port it attempted to connect to. By redirecting the hostname to a machine I controlled I could get the game to connect to a very basic TCP listener.

```text
socom2002-prod.pdonline.scea.com -> <SERVER IP>

MAS TCP : 10075
MLS TCP : 10077
DME TCP : 10078
NAT UDP : 10070
```

At first the server did nothing more than accept a connection and print the bytes it received. That does not sound like much but it immediately gave me a fixed starting point. Every fresh connection began with the same type of SCE-RT packet.

The first packet was 71 bytes in total:

- 3-byte RT header
- 4-byte SCERT hash
- 64-byte encrypted payload

The wire message identifier was **0x92**. The upper bit indicates that the payload is encrypted, so the underlying RT message identifier is **0x12**, or CLIENT_CRYPTKEY_PUBLIC.

That was our first real foothold.

## NETWORK SETUP

I performed the initial research with PCSX2 and a Linux virtual machine. PCSX2 used the pcap-bridged DEV9 adapter so the emulated PS2 network stack could appear as its own device on the network.

The basic layout looked like this:

```text
PCSX2 / PS2 Client
        |
        | DNS lookup and TCP/UDP traffic
        v
Linux VM or VPS
        |
        +-- MAS :10075/TCP
        +-- MLS :10077/TCP
        +-- DME :10078/TCP
        +-- NAT :10070/UDP
```

For local testing I pointed the PS2 network configuration at a DNS server which returned my VM address for the original SOCOM hostname. A public server can perform the same redirect to a VPS address.

One thing that tripped me up during testing was the PS2 network state after a failed connection. SOCOM does not always recover cleanly when a handshake dies halfway through. In several cases the network adapter appeared dead until the game was restarted. If your next test produces no traffic at all after a bad packet, restart SOCOM before assuming the latest code change broke the socket listener.

## THE FOUR SERVICES

### MAS - Authentication

The Medius Authentication Server handles the initial cryptographic handshake, begins the Medius session and processes account registration or login. A successful login returns credentials which are used when connecting to the next service.

### MLS - Lobby

The Medius Lobby Server handles briefing rooms, game lists, player information, chat, game creation and game joining. The MLS is where most of the menus visible to the player obtain their data.

### DME - Gameplay Routing

The Distributed Memory Engine connection carries the live game traffic. The DME assigns each client a player identifier and routes broadcast or direct packets between clients in the same world.

The server does not need to understand every byte of a gameplay packet before it can forward it. This is important. Once the outer RT routing rules were understood I could preserve the inner game payload as opaque data and pass it to the correct recipient.

### NAT - Network Discovery

SOCOM also sends UDP traffic to the NAT service. The current server records this traffic but does not yet generate a response. It remains a research endpoint and should not be represented as complete.

## SCE-RT FRAMING

Before touching Medius messages I needed to parse the outer transport correctly. The RT frame has a very small header:

```text
Offset  Size  Description
0x00    1     Wire message identifier
0x01    2     Payload length, little endian
0x03    4     SCERT hash (encrypted frames only)
0x07    N     Payload (encrypted frames)

Plain frames do not contain the 4-byte hash, so their payload begins at 0x03.
```

The high bit of the wire identifier is an encryption flag.

```text
encrypted = (wire_id & 0x80) != 0
message_id = wire_id & 0x7F
```

An early mistake would be treating the length as the number of bytes remaining after the header. On an encrypted frame the length describes the encrypted payload only. It does **not** include the additional 4-byte hash.

TCP is also a stream and not a packet queue. One call to recv() is not guaranteed to return one full RT frame. It may return half a header, one frame, or several frames depending on timing. I used a helper which continues reading until an exact number of bytes has been received.

```text
def recv_exact(sock, count):
    data = bytearray()

    while len(data) < count:
        chunk = sock.recv(count - len(data))

        if not chunk:
            raise ConnectionError("Socket closed")

        data += chunk

    return bytes(data)
```

The frame reader then becomes very easy to reason about.

```text
def recv_rt_frame(sock):
    header = recv_exact(sock, 3)

    wire_id = header[0]
    length = int.from_bytes(header[1:3], "little")

    encrypted = bool(wire_id & 0x80)
    message_id = wire_id & 0x7F

    hash_value = recv_exact(sock, 4) if encrypted else None
    payload = recv_exact(sock, length)

    return {
        "wire_id": wire_id,
        "id": message_id,
        "length": length,
        "encrypted": encrypted,
        "hash": hash_value,
        "payload": payload,
    }
```

I later represented this with ctypes structures to make the code easier to read, but the framing rules stay the same. The class does not need to become a second copy of the structure. Its job is simply to validate the input, cast the header and expose the payload.

## THE SCERT HASH

Encrypted RT frames contain a 4-byte hash in front of the encrypted payload. The full SHA-1 result is not transmitted.

The algorithm used by the server is:

- Calculate SHA-1 over the plaintext
- Place the 3-bit cipher context in the upper bits of digest byte 3
- Return the first 4 bytes

```text
def scert_hash(data, context):
    digest = bytearray(hashlib.sha1(data).digest())

    digest[3] = (
        (digest[3] & 0x1F)
        | ((context & 7) << 5)
    )

    return bytes(digest[:4])
```

The context can therefore be recovered from a received hash with:

```text
context = hash_value[3] >> 5
```

The initial RSA packet uses context **7**, which I refer to as RSA_AUTH. Normal client session traffic uses context **3**.

This hash is one of the best debugging tools in the entire protocol. A decrypted packet which merely looks readable is not enough. Recalculate the hash over the result and compare it against the received value. If the hash does not match then the key, byte order, cipher context or cipher implementation is wrong.

## THE RSA HANDSHAKE

The first CLIENT_CRYPTKEY_PUBLIC payload contains the client's 64-byte public modulus encrypted with the global Medius RSA key.

The important details are:

- The integer byte order is reversed compared with what Python's integer helpers normally expect
- The original Java implementation used signed BigInteger behavior
- A leading zero byte may be required when the high bit is set
- The plaintext integer may require the Medius modulus fallback

Python can perform the raw modular exponent operation directly:

```text
value = int.from_bytes(ciphertext[::-1], "big")
plain_int = pow(value, GLOBAL_D, GLOBAL_N)
```

The result then has to be converted back into the exact 64-byte little-endian representation expected by the PS2 client. I wrote a Java-compatible conversion helper because a normal to_bytes() conversion was not enough for every value.

```text
def java_bigint_to_little_endian(value, target_length):
    if value == 0:
        big = b"\x00"
    else:
        size = (value.bit_length() + 7) // 8
        big = value.to_bytes(size, "big")

        if big[0] & 0x80:
            big = b"\x00" + big

    little = big[::-1]
    return little.ljust(target_length, b"\x00")[:target_length]
```

After decryption I calculate the context-7 SCERT hash. If it fails I add the global modulus to the plaintext integer, convert it again and retest the hash. This fallback was necessary to reproduce the Medius behavior for values which exceed the modulus representation.

Once the client modulus is recovered, the server sends SERVER_CRYPTKEY_PEER. Its 64-byte plaintext is the session key which will be used for the modified RC4 traffic that follows. The server can RSA-encrypt this key using the client's modulus and exponent 17.

```text
CLIENT_CRYPTKEY_PUBLIC  -> decrypt with global private key
                         -> recover client modulus

SERVER_CRYPTKEY_PEER   -> encrypt 64-byte session key
                         -> use client modulus and exponent 17
```

Do not publish the real private key or a deployment's session secrets in a tutorial or repository configuration. Load those values from a protected configuration source. The fixed values used during research made captures reproducible, but they should not be confused with good production key management.

## THIS IS NOT STANDARD RC4

This part cost a fair amount of time because calling a normal RC4 library does not produce the stream SOCOM expects.

The Medius implementation changes several parts of the key setup and stream generation:

- The S-box begins in descending order from 255 to 0
- Signed byte behavior is reproduced
- The hash can participate in an initial shuffle
- The main key setup advances through the state using a stride of 3
- The stream generator follows the PS2/Medius routine rather than a stock library

This is why I treated the open-source Java implementation as behavior to reproduce instead of simply looking at the word RC4 and importing a package.

The send path is always:

```text
plaintext
    -> calculate SCERT hash with context 3
    -> initialize modified RC4 using key and hash
    -> encrypt plaintext
    -> set high bit on RT message ID
    -> write RT header + hash + ciphertext
```

The receive path performs the reverse operation and then verifies the hash against the resulting plaintext.

```text
def decrypt_client_frame(frame):
    context = frame["hash"][3] >> 5

    plaintext, valid = rc4_decrypt_ps2(
        frame["payload"],
        frame["hash"],
        RC4_SESSION_KEY,
        context,
    )

    if not valid:
        raise ValueError("RC4 hash validation failed")

    return plaintext
```

When the implementation finally decrypted CLIENT_CONNECT_TCP and the calculated hash matched, the plaintext contained recognizable version, IP and connection fields. That was the confirmation that both the key exchange and the custom cipher were correct.

## MAS CONNECTION FLOW

The complete authentication flow observed from retail SOCOM is:

```text
CLIENT -> CLIENT_CRYPTKEY_PUBLIC
SERVER -> SERVER_CRYPTKEY_PEER

CLIENT -> CLIENT_CONNECT_TCP
SERVER -> SERVER_CONNECT_ACCEPT_TCP

CLIENT -> Medius SessionBegin
SERVER -> Medius SessionBeginResponse

CLIENT -> Medius VersionServer
SERVER -> no response for the observed retail flow

CLIENT -> Medius AccountLogin or AccountRegistration
SERVER -> matching response
```

CLIENT_CONNECT_TCP is encrypted on the MAS connection. After decrypting it I extract the target world, application identifier, session/access credentials and the small connect byte sequence which the client expects the server to echo in its acceptance packet.

SOCOM 1 retail uses AppId **97134**. I validate this value rather than allowing one service connection to silently cross into another game's state.

The connection acceptance is a plain RT packet. Immediately after it, the client sends RT_CLIENT_APP_TOSERVER containing a Medius message.

## MEDIUS INSIDE SCE-RT

This is where the layers can become confusing.

SCE-RT determines how bytes are framed, encrypted and routed. Medius is the application message contained inside that frame. A packet may therefore have an RT identifier of CLIENT_APP_TOSERVER while the decrypted payload begins with the two-byte Medius identifier for SessionBegin.

```text
RT layer:
    CLIENT_APP_TOSERVER (0x0B)

Decrypted Medius payload:
    01 03 ... = SessionBegin (0x0301 little endian)
```

The two bytes look backwards in a hex dump because the value is little endian.

Most lobby request structures also begin with a 21-byte MessageID after the 2-byte message type. That MessageID must be copied into the corresponding response. It is how the client matches an asynchronous response to the request which created it.

```text
Offset  Size  Description
0x00    2     Medius message type
0x02    21    MessageID
0x17    ...   Message-specific fields
```

Ignoring the MessageID can produce a response which looks perfect in a packet dump but which the game never accepts.

## SESSIONBEGIN AND VERSION SERVER

SessionBegin was the first Medius request I successfully answered. The server copies the request MessageID, adds the expected padding and reports MediusSuccess.

The connection class stored in SessionBegin is retained with the pending authenticated session because later services may need to know how the client connected.

SOCOM then sends VersionServer. In the working retail sequence this request does not need a response. This was another place where blindly replying to every request could have moved the client away from the observed behavior. The implementation logs it and continues waiting for AccountLogin or AccountRegistration.

## PERSISTENT ACCOUNTS

The first version of the server only needed to convince one client that a login succeeded. That is useful for packet research but it is not an account system.

I added a SQLite database containing accounts and player statistics.

```text
CREATE TABLE IF NOT EXISTS accounts (
    account_id INTEGER PRIMARY KEY,
    app_id INTEGER NOT NULL,
    username TEXT NOT NULL COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    created_utc TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(app_id, username)
);

CREATE TABLE IF NOT EXISTS player_stats (
    account_id INTEGER PRIMARY KEY,
    kills INTEGER NOT NULL DEFAULT 0,
    deaths INTEGER NOT NULL DEFAULT 0,
    wins INTEGER NOT NULL DEFAULT 0,
    losses INTEGER NOT NULL DEFAULT 0,
    shots_fired INTEGER NOT NULL DEFAULT 0,
    shots_hit INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY(account_id) REFERENCES accounts(account_id)
        ON DELETE CASCADE
);
```

Account names are unique per AppId and are compared without case sensitivity. Password comparisons use compare_digest() so the comparison itself is not an obvious early-exit string comparison.

The research server currently hashes passwords with SHA-256. That is enough to avoid storing plaintext during protocol development, but it is **not** the correct design for a public production account database. A deployed service should use a slow password hash such as Argon2id, scrypt or bcrypt with a unique salt and sensible rate limits.

## RESERVING A SESSION

A successful MAS login cannot be treated as a boolean attached only to the MAS socket. SOCOM closes that connection and opens a new connection to the MLS. The next service needs a secure way to determine which account is connecting.

The login response therefore includes two important strings:

- SessionKey
- AccessKey

The server stores a reservation indexed by AppId, SessionKey and AccessKey.

```text
@dataclass
class ReservedSession:
    account_id: int
    username: str
    app_id: int
    source_ip: str
    session_key: str
    access_key: str
    connection_class: int = 0
```

The access key is generated with secrets.token_hex(). A fresh login replaces only the previous reservation for that exact account. It does **not** remove every reservation originating from the same IP.

That detail matters because two consoles or PCSX2 instances may be behind the same router. Using the source IP as the identity would cause one player to overwrite another player's login.

The response also tells SOCOM where to find the MLS. I represented the Medius 1.40 connection data with small serialization classes so the exact packet size can be asserted.

```text
@dataclass
class NetAddress140:
    address_type: int
    address: str
    port: int

@dataclass
class NetConnectionInfo140:
    connection_type: int
    addresses: list
    world_id: int
    server_key: bytes
    session_key: str
    access_key: str
```

Fixed-size strings are null-terminated and padded to the protocol's field length. These are C-style buffers, not variable-length Python strings. One missing padding byte shifts every field after it and will usually result in the client quietly rejecting the entire response.

## MLS CONNECTION AND LOBBY STATE

The MLS begins with another CLIENT_CONNECT_TCP. This connection can be resolved against the session reservation created during MAS login.

```text
reservation = find_reserved_session_by_credentials(
    connect["app_id"],
    connect["session_key"],
    connect["access_key"],
)
```

If the credentials do not match a reservation, the connection is not allowed to become an authenticated lobby client.

Once accepted, SOCOM sends a collection of lobby requests. The implemented server handles or intentionally records requests including:

- UpdateUserState
- SetGameListFilter0
- PlayerInfo
- ChannelList
- CreateChannel
- JoinChannel
- ChannelInfo
- GameList
- CreateGame
- JoinGame
- GameInfo0
- WorldSecurity
- Lobby player names
- Chat messages
- Ladder requests
- PlayerReport, WorldReport0 and EndGameReport
- SessionEnd and Policy

Not every recognized request needs a reply. The dispatcher distinguishes three outcomes:

```text
None = unknown or not implemented
[]   = understood and intentionally no response
list = one or more response packets
```

That small distinction made the log output far more useful. "I understood this and chose not to reply" is very different from "I have no idea what this is."

## RECONSTRUCTING PACKET STRUCTURES

I did not begin with perfect Python structures for every Medius message. The practical process was:

1. Capture the full packet and its length.
2. Identify the two-byte Medius message type.
3. Mark the 21-byte MessageID.
4. Compare multiple captures while changing one visible value in the game.
5. Match strings, AppId, world identifiers and counts to byte offsets.
6. Build the smallest response which preserves every confirmed field.
7. Assert the final serialized length.
8. Only then convert the proven layout into a named structure.

For example, AccountLogin became very easy to follow once its fixed-width fields were named.

```text
@dataclass
class AccountLoginRequest:
    message_id: bytes
    session_key: str
    username: str
    password: str

    @classmethod
    def parse(cls, payload):
        return cls(
            payload[2:23],
            decode_fixed_ascii(payload[23:40]),
            decode_fixed_ascii(payload[40:72]),
            decode_fixed_ascii(payload[72:104]),
        )
```

This is much easier to work with than scattering unexplained slices throughout the handler. It also makes errors obvious. If AccountLogin is expected to be 104 bytes and the client sends 103, the parser should report it instead of quietly borrowing one byte from the next logical field.

I followed the same approach with ctypes for RTFrameHeader and selected Medius structures. You do not need to force every packet into a class immediately. Use a structure when the layout is understood and it improves readability. Keep raw payloads when the inner format is still being researched.

## BRIEFING ROOMS AND GAME WORLDS

Medius uses several identifiers which can sound interchangeable until the server needs to route them.

- AppId identifies the game/application.
- AccountId identifies a registered player.
- Channel or room WorldId identifies a lobby/briefing room.
- Game WorldId identifies a created match.
- DME ID identifies one player inside a game-world connection.

The server maintains room and game state behind a lock because several client threads may create, join or leave at the same time.

A game record contains the information required by both the MLS and DME:

```text
game = {
    "world_id": world_id,
    "app_id": app_id,
    "game_name": game_name,
    "host_account_id": reservation.account_id,
    "max_players": max_players,
    "players": set(),
    "clients": {},
    "dme_ip": SERVER_IP,
    "dme_port": DME_PORT,
}
```

CreateGame allocates a unique game WorldId and records the host. JoinGame validates that the requested game exists, belongs to the same AppId and has space available.

The response does not carry the player into the match by itself. It gives the client the DME endpoint and the same session credentials established during login. SOCOM then creates a separate TCP connection to the DME for that game world.

## THE DME HANDOFF

The DME connection begins with a **plaintext** CLIENT_CONNECT_TCP. This was different from the encrypted MAS connect and is a good example of why encryption should be determined by the wire flag instead of assumed from the message type.

The DME connect supplies:

- Target game WorldId
- AppId
- SessionKey
- AccessKey

The server first resolves the reserved session. It then verifies that the requested game exists and belongs to the correct AppId.

Each connected client receives a world-local DME identifier. The first free identifier is selected, beginning at zero.

```text
used_dme_ids = {
    info["dme_id"]
    for info in clients.values()
}

dme_id = 0

while dme_id in used_dme_ids:
    dme_id += 1
```

SERVER_CONNECT_ACCEPT_TCP returns that DME ID and the current player count. At this point the client is attached to the live game rather than merely listed as a lobby member.

The DME client record also stores the receive flags sent by the game:

```text
client_info = {
    "sock": sock,
    "reservation": reservation,
    "dme_id": dme_id,
    "remote_ip": peer_ip,
    "recv_single": True,
    "recv_list": True,
    "recv_broadcast": False,
    "recv_notification": False,
    "send_lock": threading.Lock(),
}
```

Those flags are not decorative. A client which has not enabled broadcast or notifications should not automatically receive those packet classes.

## PLAYER CONNECT NOTIFICATIONS

When another player joins an existing DME world, clients which requested notifications receive SERVER_CONNECT_NOTIFY.

The payload used by the current PRE8 implementation contains:

```text
uint16  world-local DME player ID
char    IP address[16]
byte    public key field[64]
```

The public-key field is currently zeroed because a per-client DME RSA key has not been established in this path. The field still has to exist because removing 64 "unused" bytes changes the structure size and breaks the packet layout.

This is another recurring lesson with old network protocols: an unknown or zero-filled field is still part of the structure.

## FORWARDING BROADCAST TRAFFIC

The client sends RT_CLIENT_APP_BROADCAST with an opaque DME/game payload. The server does not echo that same RT message to every socket.

It converts the packet into RT_CLIENT_APP_SINGLE for each eligible recipient and prefixes the sender's DME ID.

```text
Incoming from player:
    RT_CLIENT_APP_BROADCAST
    [opaque payload]

Outgoing to each other player:
    RT_CLIENT_APP_SINGLE
    [uint16 sender DME ID]
    [opaque payload]
```

The core transformation is therefore very small.

```text
outgoing_payload = (
    pack_u16(sender_info["dme_id"])
    + payload
)

outgoing_frame = build_plain_rt_frame(
    RT_CLIENT_APP_SINGLE,
    outgoing_payload,
)
```

Recipients are limited to other clients in the same game world which enabled broadcast reception.

This was the moment the two-client test became especially useful. One client could enter a match and continuously send broadcasts even when the second client's socket was already dead. The server log showed repeated broken pipes because the stale client was still recorded as a target. The packet routing was working; the cleanup was not.

## FORWARDING SINGLE-RECIPIENT TRAFFIC

CLIENT_APP_SINGLE already contains a destination DME ID. The server removes that destination, finds the matching client and replaces it with the sender's DME ID before forwarding.

```text
Client -> server:
    [uint16 destination DME ID]
    [opaque payload]

Server -> destination:
    [uint16 sender DME ID]
    [opaque payload]
```

It is important not to pass the original destination prefix through unchanged. From the receiving client's point of view that prefix identifies who sent the packet.

Every write to a client socket uses a per-client send lock. Multiple DME threads may attempt to forward traffic to the same player at the same time. Without serialized writes, bytes from two RT frames could be interleaved on the TCP stream.

```text
def dme_send(client_info, frame):
    with client_info["send_lock"]:
        client_info["sock"].sendall(frame)
```

## DISCONNECTS AND DIRTY CLIENT EXITS

A clean client sends RT_CLIENT_DISCONNECT. Real testing does not always end cleanly. PCSX2 may be closed, the game may crash or the network connection may disappear while a match is active.

The server therefore performs cleanup in the connection worker's finally path as well as the explicit disconnect path.

Cleanup performs the following:

- Remove the socket from the game client table
- Remove the account from the game player set
- Notify remaining clients with SERVER_DISCONNECT_NOTIFY
- Prune an empty game when appropriate
- Remove stale MAS or MLS socket state

The cleanup routine accepts the expected socket. This prevents an older dead socket from removing a newer connection if the same account reconnects quickly.

```text
if expected_sock is not None and (
    current is None
    or current["sock"] is not expected_sock
):
    return
```

That comparison looks minor but it closes a nasty race condition: socket A dies, the account reconnects as socket B, and socket A's delayed cleanup removes socket B's fresh membership.

The broken-pipe test taught us something else as well. A dirty client exit is not an exotic error condition. For a game server it is a normal part of connection lifecycle and has to be treated as such.

## THREADING THE SERVICES

The Python research server runs one listening thread per service and one worker thread per accepted TCP client.

```text
MAS -> TCP listener on 10075
MLS -> TCP listener on 10077
DME -> TCP listener on 10078
NAT -> UDP listener on 10070
```

Shared dictionaries are protected with locks. Socket writes have their own per-client locks so the global room lock is not held during a potentially blocking send.

The listener itself is intentionally simple:

```text
def run_listener(name, port, handler):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, port))
        server.listen(32)

        while True:
            client, address = server.accept()

            threading.Thread(
                target=client_worker,
                args=(name, handler, client, address),
                daemon=True,
            ).start()
```

Python is perfectly adequate for this phase of the project. The difficult problem is not raw packet throughput. It is learning the protocol, validating structures and being able to adjust the implementation quickly as new packets are understood.

## LOGGING FOR PROTOCOL RESEARCH

Printing every packet as an unlabeled hex dump becomes useless surprisingly fast. I split the logging into a compact summary and optional targeted hexdumps.

A useful log line includes:

- Service: MAS, MLS, DME or NAT
- Direction: RX, TX or forwarded
- RT or Medius message name
- Message identifier
- Account or player name when known
- World and DME IDs when relevant
- Packet length

```text
[MAS] (RX) CLIENT_CRYPTKEY_PUBLIC | RSA fallback=NO
[MAS] (TX) SERVER_CRYPTKEY_PEER | RSA encrypted
[MAS] (RX) CLIENT_CONNECT_TCP | world=1 app=97134
[MAS] (RX) SessionBegin (0x0301)
[MAS] (RX) AccountLogin (0x0701) | user='NightFyrePS2'

[MLS] (AUTH) Reserved session resolved | user='NightFyrePS2'
[MLS] (RX) CreateGame (0x1A01)

[DME] (GAME) Client attached | user='NightFyrePS2' world=2 dme_id=0
[DME] (FWD) CLIENT_APP_BROADCAST -> CLIENT_APP_SINGLE
```

Hexdumps are enabled only for selected message types or unhandled packets. This keeps normal server activity readable while preserving the raw evidence required for the next reverse-engineering step.

Player-controlled strings are also sanitized before they are sent to Discord notifications. Webhook payloads use fields for account/game information and disable mentions so an account named @everyone cannot ping an entire server.

## WHAT OPEN-SOURCE REFERENCES PROVIDED

Existing Medius projects were extremely valuable, particularly for naming RT messages, understanding the general handshake order and reproducing the cipher behavior.

They were not a drop-in SOCOM 1 server.

Different games and Medius revisions use different message layouts, field sizes and flow decisions. SOCOM identifies itself as Medius **1.40.PRE8**. A structure from another game can be an excellent hypothesis while still being the wrong number of bytes for retail SOCOM.

The safest workflow was:

- Use the reference implementation to understand intent.
- Use SOCOM captures to confirm the actual wire layout.
- Use the retail client's next action as the final test.

If the game advances to the next request, that proves more than a comment or enum name in another repository.

## COMMON FAILURE POINTS

### Incorrect encrypted-frame length

The RT length excludes the 4-byte hash. Including it causes every read after the first encrypted packet to become misaligned.

### Assuming recv() returns a frame

TCP does not preserve application message boundaries. Always read the exact header and payload lengths.

### Using stock RC4

SOCOM's Medius cipher behavior is not reproduced by a normal RC4 call.

### Ignoring Java BigInteger behavior

The byte reversal, sign-padding behavior and modulus fallback matter during the RSA exchange.

### Trusting readable plaintext without checking the hash

Readable strings can appear by accident or after a partially correct decrypt. The SCERT hash is the real validation.

### Dropping the Medius MessageID

The response must carry the identifier from its request.

### Treating fixed buffers as normal strings

Null termination and padding are part of the wire structure.

### Authenticating by IP address

Several clients can share one public IP. Use the session and access credentials.

### Holding a global lock during socket sends

A slow or dead client can block unrelated room operations. Snapshot recipients under the state lock, release it and then send using per-client locks.

### Only handling polite disconnects

Closing PCSX2 is enough to prove why cleanup must happen after any socket failure.

## CURRENT STARTUP LAYOUT

The main routine initializes the database and launches each service independently.

```text
def main():
    init_database()

    mas = Thread(target=run_listener,
                 args=("MAS", 10075, handle_mas_client))
    mls = Thread(target=run_listener,
                 args=("MLS", 10077, handle_mls_client))
    dme = Thread(target=run_listener,
                 args=("DME", 10078, handle_dme_client))
    nat = Thread(target=run_nat_listener)

    mas.start()
    mls.start()
    dme.start()
    nat.start()
```

Configuration such as the advertised public IP, database location and cryptographic material should come from environment variables or a configuration file. The server may listen on 0.0.0.0 while advertising a completely different address to the PS2 clients.

If this is hosted publicly, the TCP and UDP ports must also be allowed through the VPS firewall and any upstream provider firewall.

## HOW I WOULD BUILD THIS AGAIN

If I had to restart the project from nothing, I would build it in this order:

1. Redirect the retail hostname to a controlled machine.
2. Accept TCP port 10075 and save the first packet exactly as received.
3. Implement an exact RT frame reader.
4. Implement SCERT hashing and expose the context in logs.
5. Reproduce RSA BigInteger behavior until CLIENT_CRYPTKEY_PUBLIC validates.
6. Send SERVER_CRYPTKEY_PEER and implement the modified RC4 routine.
7. Do not continue until CLIENT_CONNECT_TCP decrypts and its hash validates.
8. Answer SERVER_CONNECT_ACCEPT_TCP.
9. Parse CLIENT_APP_TOSERVER as a Medius message.
10. Implement SessionBegin and the observed VersionServer behavior.
11. Add registration, login and a persistent account database.
12. Reserve SessionKey and AccessKey credentials across sockets.
13. Open the MLS and implement requests in the order the retail client sends them.
14. Create game-world state and return a DME endpoint.
15. Authenticate the DME connection against the same reservation.
16. Assign DME IDs and implement receive flags.
17. Forward broadcast and single packets without interpreting unknown inner data.
18. Add notifications and cleanup for dirty disconnects.
19. Only then expand statistics, ladders, NAT and administrative features.

The big lesson is to never skip the validation point between stages. If the RSA result is questionable, do not start debugging AccountLogin. If the DME connect is not associated with the correct game, do not start decoding movement packets. Each proven layer removes an entire category of possible errors from the next one.

## WHERE THE SERVER STANDS

At the time of writing the server can carry a retail SOCOM client through the following path:

```text
DNS redirect
    -> MAS cryptographic handshake
    -> SessionBegin
    -> account registration/login
    -> MLS authentication
    -> lobby/briefing room
    -> CreateGame / JoinGame
    -> DME connection
    -> player assignment
    -> gameplay packet forwarding
```

The server also handles the ugly real-world cases we encountered during testing, including multiple clients behind one address, concurrent writes and PCSX2 instances being closed without leaving the match.

There is still plenty left to reverse. FieldUpdate serialization is not fully understood, NAT is currently observation-only and a number of Medius reports need better structure definitions. But those unknowns no longer block the basic online path.

## FINAL THOUGHTS

When I started this I did not have a clean specification for SOCOM 1's server. I had a hostname, a port and an encrypted 71-byte packet.

From there the process was the same one I have used throughout my SOCOM reversal work: follow the evidence, name what can be proven, preserve what is still unknown and do not mistake a plausible structure for a confirmed one.

The most surprising part is how quickly the wall starts to come down once the layers are separated. RSA gets you the session key. The session key gets you readable RT traffic. RT traffic exposes Medius. Medius gets you through the menus. The DME routing rules finally get two consoles talking to one another.

Anywho ... that is how a basic socket listener became a functioning SOCOM 1 Medius research server.

I hope this proves useful to somebody attempting to understand an older PlayStation 2 network title. Even if the target game uses a different Medius revision, the method remains the same: capture, validate, reproduce and let the retail client tell you what comes next.
