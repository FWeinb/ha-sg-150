# Contribution guidelines

Contributing to this project should be as easy and transparent as possible, whether it's:

- Reporting a bug
- Discussing the current state of the code
- Submitting a fix
- Proposing new features

## Github is used for everything

Github is used to host code, to track issues and feature requests, as well as accept pull requests.

Pull requests are the best way to propose changes to the codebase.

1. Fork the repo and create your branch from `main`.
2. If you've changed something, update the documentation.
3. Make sure your code lints (using `scripts/lint`).
4. Test you contribution.
5. Issue that pull request!

## Testing two-way audio on a real gateway

The tests cover the SIP, RTP and WebRTC code on fake transports and an in-process WebRTC peer, but not the real SG-150 or a real browser. Before releasing a change to call audio, go through this with a gateway:

1. Prepare:
   - Home Assistant opened over HTTPS.
   - **Two-way audio** turned on under Settings → System → Labs.
   - **Two-way audio** turned on in the integration options.
   - The RTP port range reachable from the gateway. In the devcontainer, 5004–5013/udp are forwarded.
2. With **SIP Auto Answer** off:
   - Ring the door station. Every handset rings, and the camera's live view shows the talk button.
   - Open the live view without pressing talk. The call keeps ringing.
   - Press talk. The handsets stop ringing, and you hear the door station and it hears you.
   - Close the live view. The call ends at the door station.
3. Ring again, and answer on a Siedle handset first. Pressing talk afterwards must not take over the call.
4. Ring again, and let nobody answer. After a minute the call is left to the handsets.
5. With **SIP Auto Answer** on, ring the door station:
   - Audio from the door station plays in the live view.
   - Closing the live view without having talked leaves the call up.
   - The **Hang Up** button next to the camera ends it.
6. Run `play_audio` during a call. The clip plays at normal speed, without gaps.

## Any contributions you make will be under the MIT Software License

In short, when you submit code changes, your submissions are understood to be under the same [MIT License](http://choosealicense.com/licenses/mit/) that covers the project.

## Report bugs using Github's [issues](../../issues)

GitHub issues are used to track public bugs.
Report a bug by [opening a new issue](../../issues/new/choose); it's that easy!

## Write bug reports with detail, background, and sample code

**Great Bug Reports** tend to have:

- A quick summary and/or background
- Steps to reproduce
  - Be specific!
  - Give sample code if you can.
- What you expected would happen
- What actually happens
- Notes (possibly including why you think this might be happening, or stuff you tried that didn't work)

## License

By contributing, you agree that your contributions will be licensed under its MIT License.
