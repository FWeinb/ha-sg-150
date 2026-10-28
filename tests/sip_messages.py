"""Raw SIP messages as the Smart Gateway sends them, for driving MiniSIPServer."""

import re

from custom_components.sg_150.sip.minisip import MiniSIPServer, md5_hex

GATEWAY = ("192.168.1.10", 5060)
HA_HOST = "127.0.0.1"
SIP_USER = "gateway"
SIP_PASSWORD = "secret"  # noqa: S105
HA_NUMBER = "*2620"

INVITE_SDP = (
    "v=0\r\n"
    "o=- 1 1 IN IP4 192.168.1.10\r\n"
    "s=Siedle\r\n"
    "c=IN IP4 192.168.1.10\r\n"
    "t=0 0\r\n"
    "m=audio 4000 RTP/AVP 8\r\n"
    "a=rtpmap:8 PCMA/8000"
)


def sip(start_line: str, headers: dict[str, str], body: str = "") -> bytes:
    """Build a SIP datagram."""
    lines = [start_line, *(f"{k}: {v}" for k, v in headers.items())]
    lines.append(f"Content-Length: {len(body)}")
    return ("\r\n".join(lines) + "\r\n\r\n" + body).encode()


def invite(call_id: str, from_user: str, to_user: str) -> bytes:
    """Build an INVITE from the gateway."""
    return sip(
        f"INVITE sip:{to_user}@{HA_HOST} SIP/2.0",
        {
            "Via": f"SIP/2.0/UDP {GATEWAY[0]}:{GATEWAY[1]};branch=z1",
            "From": f"<sip:{from_user}@{GATEWAY[0]}>;tag=gw",
            "To": f"<sip:{to_user}@{HA_HOST}>",
            "Call-ID": call_id,
            "CSeq": "1 INVITE",
            "Contact": f"<sip:{from_user}@{GATEWAY[0]}>",
            "Content-Type": "application/sdp",
        },
        INVITE_SDP,
    )


def ack(call_id: str) -> bytes:
    """Build the ACK the gateway sends after our 200 OK."""
    return sip(
        f"ACK sip:{HA_NUMBER}@{HA_HOST} SIP/2.0",
        {
            "Via": f"SIP/2.0/UDP {GATEWAY[0]}:{GATEWAY[1]};branch=z4",
            "From": f"<sip:*111@{GATEWAY[0]}>;tag=gw",
            "To": f"<sip:{HA_NUMBER}@{HA_HOST}>;tag=minisip",
            "Call-ID": call_id,
            "CSeq": "1 ACK",
        },
    )


def bye(call_id: str) -> bytes:
    """Build a BYE from the gateway."""
    return sip(
        f"BYE sip:{SIP_USER}@{HA_HOST} SIP/2.0",
        {
            "Via": f"SIP/2.0/UDP {GATEWAY[0]}:{GATEWAY[1]};branch=z2",
            "From": f"<sip:*111@{GATEWAY[0]}>;tag=gw",
            "To": f"<sip:{HA_NUMBER}@{HA_HOST}>;tag=minisip",
            "Call-ID": call_id,
            "CSeq": "2 BYE",
        },
    )


async def register(server: MiniSIPServer) -> None:
    """Register the gateway with digest auth through raw datagrams."""
    headers = {
        "Via": f"SIP/2.0/UDP {GATEWAY[0]}:{GATEWAY[1]};branch=z0",
        "From": f"<sip:{SIP_USER}@{HA_HOST}>;tag=r",
        "To": f"<sip:{SIP_USER}@{HA_HOST}>",
        "Call-ID": "register-1",
        "CSeq": "1 REGISTER",
        "Expires": "300",
    }
    await server.handle_datagram(
        sip(f"REGISTER sip:{HA_HOST} SIP/2.0", headers), GATEWAY
    )
    challenge = server.transport.sent[-1][0].decode()
    nonce = re.search(r'nonce="([^"]+)"', challenge).group(1)
    opaque = re.search(r'opaque="([^"]+)"', challenge).group(1)

    uri = f"sip:{HA_HOST}"
    ha1 = md5_hex(f"{SIP_USER}::{SIP_PASSWORD}")
    ha2 = md5_hex(f"REGISTER:{uri}")
    response = md5_hex(f"{ha1}:{nonce}:00000001:c:auth:{ha2}")
    headers["CSeq"] = "2 REGISTER"
    headers["Authorization"] = (
        f'Digest username="{SIP_USER}", realm="", nonce="{nonce}", '
        f'uri="{uri}", response="{response}", algorithm=MD5, '
        f'qop=auth, nc=00000001, cnonce="c", opaque="{opaque}"'
    )
    await server.handle_datagram(
        sip(f"REGISTER sip:{HA_HOST} SIP/2.0", headers), GATEWAY
    )


def cancel(call_id: str) -> bytes:
    """Build the CANCEL the gateway sends when a handset answered first."""
    return sip(
        f"CANCEL sip:{HA_NUMBER}@{HA_HOST} SIP/2.0",
        {
            "Via": f"SIP/2.0/UDP {GATEWAY[0]}:{GATEWAY[1]};branch=z1",
            "From": f"<sip:*111@{GATEWAY[0]}>;tag=gw",
            "To": f"<sip:{HA_NUMBER}@{HA_HOST}>",
            "Call-ID": call_id,
            "CSeq": "1 CANCEL",
        },
    )
