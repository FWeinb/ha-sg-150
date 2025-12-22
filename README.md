# Siedle Gateway 150 Integration

This Home Assistant custom integration allowing integration with Siedle Gateway 150 (SG-150) via a local connection. It is developed to integrate a Siedle Door Camera with Home Assistant.

This integration will run a minimal SIP Server that can be configured in the SG-150 as a telephone device.

Currently the integration exposes:

- Gateway Information (Mac Adresse, SIP Connection Status)
- All phone devices know to the SG-150
  - Phone number sensor
- All video extractors
  - Camera for the live stream
- Services:
  - start_call: Start a phone call within the In-Home system
  - stop_call: Stop a phone call within the In-Home system

# Disclaimer:

⚠️ This custom component is an independent project and is not affiliated with Siedle. It has been developed for my own needs. Any trademarks or product names mentioned are the property of their respective owners. ⚠️

# Configuration

To get the most of this integration it is mandatory to configure the SG-150 to connect to the SIP-Server provided by this extension.

## Configure the SG-150 to connect to the SIP-Gateway

TODO

## Create a Softphone connected to the SIP-Gateway

TODO
