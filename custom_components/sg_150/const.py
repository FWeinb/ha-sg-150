"""Constants for ha-sg-150."""

from logging import Logger, getLogger

LOGGER: Logger = getLogger(__package__)

CONF_HOST_ADDRESS = "host-address"
CONF_SIP_CALLER_IP = "sip-caller-ip"
CONF_SIP_USER = "sip-user"
CONF_SIP_PASSWORD = "sip-password"  # noqa: S105, no password leak
CONF_SIP_PORT = "sip-port"
CONF_SIP_NUMBER = "sip-number"
CONF_SIP_AUTO_ANSWER = "sip-auto-answer"
CONF_TWO_WAY_AUDIO = "two-way-audio"
CONF_RTP_PORT_MIN = "rtp-port-min"
CONF_RTP_PORT_MAX = "rtp-port-max"

DEFAULT_RTP_PORT_MIN = 5004
DEFAULT_RTP_PORT_MAX = 5013

API_PORT = 8080
DOMAIN = "sg_150"
MANUFACTURER = "Siedle"
