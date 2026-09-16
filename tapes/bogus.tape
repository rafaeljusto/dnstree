# A chain that does not hold. bogus.nlnetlabs.nl is NLnet Labs' standing test
# name: the zone answers, and the signature over the answer does not verify.
# The exit code is asked for afterwards because 3 is the contract for it.

Output docs/demo-bogus.gif
Output docs/demo-bogus.mp4

# A row taller than the rest: the exit code is asked for under the tree.
Set Width 1356
Set Height 686

Source tapes/common.tape

Sleep 400ms
Type "dnstree --dnssec --no-asn bogus.nlnetlabs.nl A"
Sleep 400ms
Enter

Wait+Screen@45s /22 more not queried/
Sleep 2s
Type "echo $?"
Sleep 400ms
Enter
Sleep 3s
