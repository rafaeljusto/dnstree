# The walk drawing itself. --live is the one thing a pasted block cannot show,
# so this is the recording the README and the page both lead with.

Output docs/demo-hero.gif
Output docs/demo-hero.mp4

# 104 columns holds the widest hop of this walk, 24 rows the command, the
# finished tree and the line that says how it went, with room for the footer
# the live frames carry while the walk is still running.
Set Width 1056
Set Height 642

Source tapes/common.tape

Sleep 400ms
Type "dnstree --live www.example.com A"
Sleep 400ms
Enter

Wait+Screen@45s /answered in/
Sleep 3s
