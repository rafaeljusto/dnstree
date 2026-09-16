# Everything the four demo tapes agree on: the look of the terminal, and the
# shell they all start from. A scene sets its own Output, Width and Height and
# then sources this, so the frame is sized to the tree it has to hold while the
# type on it stays the same size everywhere.

Require dnstree

# Each scene sets its own Width and Height. Keep both even: the margin adds an
# even number to each, and libx264 refuses an odd frame, so an odd width loses
# the .mp4 while still writing the .gif.

Set Shell "bash"

# IBM Plex Mono at this size is what docs/index.html draws its terminals in, so
# a recording and the hand written blocks around it read as the same machine.
Set FontFamily "IBM Plex Mono"
Set FontSize 14
Set LineHeight 1.2
Set Padding 22

# The window furniture matches the .term block on the site: three rings, a
# rounded corner, and the page background showing around it.
Set WindowBar Rings
Set WindowBarSize 36
Set BorderRadius 10
Set Margin 24
Set MarginFill "#12181C"

Set Framerate 24
Set TypingSpeed 40ms

# The --term-* custom properties from docs/index.html, which are the colours
# the site keeps for a terminal in either theme. dnstree paints dim text with
# SGR 90, so brightBlack carries --term-dim rather than a washed out grey.
Set Theme { "background": "#0F1519", "foreground": "#DCE4E7", "cursor": "#72B4D3", "selection": "#1B3240", "black": "#0F1519", "red": "#E06B6B", "green": "#63C08A", "yellow": "#E0B04A", "blue": "#72B4D3", "magenta": "#A996E0", "cyan": "#72B4D3", "white": "#DCE4E7", "brightBlack": "#6B767E", "brightRed": "#E06B6B", "brightGreen": "#63C08A", "brightYellow": "#E0B04A", "brightBlue": "#72B4D3", "brightMagenta": "#A996E0", "brightCyan": "#72B4D3", "brightWhite": "#FFFFFF" }

# A bare prompt, and the freshly built binary ahead of any installed one. None
# of this belongs in the recording, so it happens behind Hide.
Hide
Type "export PATH=$PWD/build:$PATH PS1='$ ' TERM=xterm-256color" Enter
Type "clear" Enter
Sleep 500ms
Show
