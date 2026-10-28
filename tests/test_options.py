"""Tests for validating the integration options."""

import unittest

from custom_components.sg_150.config_flow import validate_options
from custom_components.sg_150.const import CONF_RTP_PORT_MAX, CONF_RTP_PORT_MIN


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


if __name__ == "__main__":
    unittest.main()
