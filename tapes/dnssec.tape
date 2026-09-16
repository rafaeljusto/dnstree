# A chain of trust that holds, link by link, from the root down to the answer.
# Not --live: the [secure] tags are the point, and they want to be read rather
# than watched arriving.

Output docs/demo-dnssec.gif
Output docs/demo-dnssec.mp4

# The [secure] tags ride on the end of the longest lines, so this is the
# widest frame of the four bar the bogus one.
Set Width 1338
Set Height 664

Source tapes/common.tape

Sleep 400ms
Type "dnstree --dnssec --no-asn cloudflare.com A"
Sleep 400ms
Enter

Wait+Screen@45s /22 more not queried/
Sleep 3s
