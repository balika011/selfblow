Selfblow exploit, when nvtboot blows a hole in itself

This is an untethered coldboot exploit and as far as i can tell it affects every single Tegra device released so far. (Except the Nintendo Switch since it uses a custom bootloader.)
Completely defeats secure boot even on latest firmware.

TL;DR: nvtboot (NVC) loads nvtboot-cpu (TBC) without validating the load address first, leading to arbitrary memory write.

Long writeup:
After checking the magic in the header, the nvtboot reads the entire TBC partition (size stored in the GPT) where LoadAddressInsecure points to.
If that points to nvtboot in the memory, it's possible to overwrite it, leading to unsigned code execution on the BPMP.
This can be used to load the rest of the bootchain without checking the signatures.
The attached proof of concept is using blobs from the Shield TV r30 release.
In this example, running the flash_exploit.sh it can be flashed to the a Jetson TX1.
After booting the TX1 it will print a "Secure boot is broken!\n" message to the uart0 before going into an infinite loop.

The issue was reported to NVIDIA on March 9 with June 15 disclosure day. That's more then the usual 90 days already.
They promised to fix it in May then asking multiple delays going till the end of July, but no real progress.
NVIDIA seems to be ignoring the issue. They did not even assigned a CVE Identifier.
After 4 months I decided to give this to the public in good faith that will encourage them in fixing it so we can have a better, more secure devices.

UPDATE: On July 18 NVIDIA released L4T 32.2, but they left selfblow out in the release notes. (It's still not there!) 
The other day they released the July 2019 Security Bulletin with a single CVE identifier: CVE‑2019‑5680.
Got the score of 7.7. This is wrong, since the exploit doesn't requiters user interaction, so the correct one is 8.1.
