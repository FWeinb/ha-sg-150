"""Tests for validating the integration options."""

import unittest

from custom_components.sg_150.config_flow import validate_options
from custom_components.sg_150.const import (
    CONF_RTP_PORT_MAX,
    CONF_RTP_PORT_MIN,
    CONF_SIP_CALLER_IP,
    CONF_SIP_NUMBER,
    CONF_SIP_PORT,
    CONF_SIP_USER,
)

VALID = {
    CONF_SIP_CALLER_IP: "192.168.1.20",
    CONF_SIP_USER: "gateway",
    CONF_SIP_NUMBER: "*2620",
    CONF_SIP_PORT: "5060",
}


class ValidateOptionsTests(unittest.TestCase):
    """The RTP port range must be a sensible range."""

    def test_default_and_valid_ranges_pass(self) -> None:
        """Missing values fall back to 5004-5013; a single port is fine."""
        assert validate_options({}) == {}
        assert (
            validate_options({CONF_RTP_PORT_MIN: "6000", CONF_RTP_PORT_MAX: "6000"})
            == {}
        )

    def test_bad_ranges_fail(self) -> None:
        """Non-numbers, reversed ranges and privileged ports are refused."""
        for low, high in (
            ("abc", "5013"),
            ("5013", "5004"),
            ("80", "90"),
            ("5004", "70000"),
        ):
            assert validate_options(
                {CONF_RTP_PORT_MIN: low, CONF_RTP_PORT_MAX: high}
            ) == {"base": "rtp_ports"}

    def test_valid_sip_options_pass(self) -> None:
        """Typical SIP options produce no errors."""
        assert validate_options(VALID) == {}

    def test_bad_sip_port_fails(self) -> None:
        """The SIP port must be a valid port outside the RTP range."""
        for port in ("abc", "0", "70000", ""):
            assert validate_options(VALID | {CONF_SIP_PORT: port}) == {
                CONF_SIP_PORT: "sip_port"
            }
        assert validate_options(VALID | {CONF_SIP_PORT: "5010"}) == {
            CONF_SIP_PORT: "sip_port_in_rtp_range"
        }

    def test_caller_ip_must_be_ipv4(self) -> None:
        """The SDP announces the caller IP as IN IP4."""
        for value in ("homeassistant.local", "fe80::1", "192.168.1", ""):
            assert validate_options(VALID | {CONF_SIP_CALLER_IP: value}) == {
                CONF_SIP_CALLER_IP: "caller_ip"
            }

    def test_user_and_number_must_not_be_blank(self) -> None:
        """Whitespace-only values are refused, field by field."""
        assert validate_options(VALID | {CONF_SIP_USER: " ", CONF_SIP_NUMBER: ""}) == {
            CONF_SIP_USER: "required",
            CONF_SIP_NUMBER: "required",
        }

    def test_errors_are_collected_for_every_field(self) -> None:
        """Several problems are reported at once."""
        assert validate_options(
            VALID | {CONF_RTP_PORT_MIN: "x", CONF_SIP_CALLER_IP: "?"}
        ) == {"base": "rtp_ports", CONF_SIP_CALLER_IP: "caller_ip"}


if __name__ == "__main__":
    unittest.main()
