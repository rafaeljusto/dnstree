# The same walk in --format emoji. Emoji are drawn two cells wide, so this
# frame is wider than the hero for a tree of the same shape.

Output docs/demo-emoji.gif
Output docs/demo-emoji.mp4

# Wider than the hero for a tree of the same shape: every emoji takes two
# cells.
Set Width 1202
Set Height 642

Source tapes/common.tape

Sleep 400ms
Type "dnstree --format emoji --live www.example.com A"
Sleep 400ms
Enter

Wait+Screen@45s /answered in/
Sleep 3s
