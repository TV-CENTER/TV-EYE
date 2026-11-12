"""ASCII logo engine for TV-EYE.

Glyphs are built from keyboard characters only ( # . / \\ | etc. ) so the logo
renders identically inside cmd.exe, PowerShell, Windows Terminal, bash, zsh,
tmux and every remote SSH session.
"""

# 6 row block font. Every glyph is exactly 7 columns wide.
FONT = {
    "A": [
        "  ###  ",
        " #   # ",
        "#     #",
        "#######",
        "#     #",
        "#     #",
    ],
    "B": [
        "###### ",
        "#     #",
        "###### ",
        "#     #",
        "#     #",
        "###### ",
    ],
    "C": [
        " ######",
        "#      ",
        "#      ",
        "#      ",
        "#      ",
        " ######",
    ],
    "D": [
        "###### ",
        "#     #",
        "#     #",
        "#     #",
        "#     #",
        "###### ",
    ],
    "E": [
        "#######",
        "#      ",
        "#####  ",
        "#      ",
        "#      ",
        "#######",
    ],
    "F": [
        "#######",
        "#      ",
        "#####  ",
        "#      ",
        "#      ",
        "#      ",
    ],
    "G": [
        " ######",
        "#      ",
        "#   ###",
        "#    ##",
        "#     #",
        " ##### ",
    ],
    "H": [
        "#     #",
        "#     #",
        "#######",
        "#     #",
        "#     #",
        "#     #",
    ],
    "I": [
        "#######",
        "   #   ",
        "   #   ",
        "   #   ",
        "   #   ",
        "#######",
    ],
    "J": [
        "     ##",
        "      #",
        "      #",
        "#     #",
        "#     #",
        " ##### ",
    ],
    "K": [
        "#    ##",
        "#   #  ",
        "####   ",
        "#   #  ",
        "#    ##",
        "#     #",
    ],
    "L": [
        "#      ",
        "#      ",
        "#      ",
        "#      ",
        "#      ",
        "#######",
    ],
    "M": [
        "#     #",
        "##   ##",
        "# # # #",
        "#  #  #",
        "#     #",
        "#     #",
    ],
    "N": [
        "#     #",
        "##    #",
        "# #   #",
        "#  #  #",
        "#   # #",
        "#    ##",
    ],
    "O": [
        " ##### ",
        "#     #",
        "#     #",
        "#     #",
        "#     #",
        " ##### ",
    ],
    "P": [
        "###### ",
        "#     #",
        "###### ",
        "#      ",
        "#      ",
        "#      ",
    ],
    "Q": [
        " ##### ",
        "#     #",
        "#     #",
        "#  #  #",
        "#   # #",
        " ##### ",
    ],
    "R": [
        "###### ",
        "#     #",
        "###### ",
        "#   #  ",
        "#    # ",
        "#     #",
    ],
    "S": [
        " ######",
        "#      ",
        " ##### ",
        "      #",
        "      #",
        "###### ",
    ],
    "T": [
        "#######",
        "   #   ",
        "   #   ",
        "   #   ",
        "   #   ",
        "   #   ",
    ],
    "U": [
        "#     #",
        "#     #",
        "#     #",
        "#     #",
        " #   # ",
        "  ###  ",
    ],
    "V": [
        "#     #",
        "#     #",
        "#     #",
        " #   # ",
        "  # #  ",
        "   #   ",
    ],
    "W": [
        "#     #",
        "#     #",
        "#  #  #",
        "# # # #",
        "##   ##",
        "#     #",
    ],
    "X": [
        "#     #",
        " #   # ",
        "  # #  ",
        "   #   ",
        "  # #  ",
        "#     #",
    ],
    "Y": [
        "#     #",
        "#     #",
        " #   # ",
        "  ###  ",
        "   #   ",
        "   #   ",
    ],
    "Z": [
        "#######",
        "     # ",
        "    #  ",
        "   #   ",
        "  #    ",
        "#######",
    ],
    "0": [
        " ##### ",
        "#    ##",
        "#   # #",
        "#  #  #",
        "##    #",
        " ##### ",
    ],
    "1": [
        "   #   ",
        "  ##   ",
        " # #   ",
        "   #   ",
        "   #   ",
        " ##### ",
    ],
    "2": [
        " ##### ",
        "#     #",
        "    ## ",
        "  ##   ",
        " #     ",
        "#######",
    ],
    "3": [
        "###### ",
        "     # ",
        "  #### ",
        "     # ",
        "     # ",
        "###### ",
    ],
    "4": [
        "    ## ",
        "   # # ",
        "  #  # ",
        "#######",
        "     # ",
        "     # ",
    ],
    "5": [
        "#######",
        "#      ",
        "###### ",
        "      #",
        "#     #",
        " ##### ",
    ],
    "6": [
        " ##### ",
        "#      ",
        "###### ",
        "#     #",
        "#     #",
        " ##### ",
    ],
    "7": [
        "#######",
        "     # ",
        "    #  ",
        "   #   ",
        "  #    ",
        "  #    ",
    ],
    "8": [
        " ##### ",
        "#     #",
        " ##### ",
        "#     #",
        "#     #",
        " ##### ",
    ],
    "9": [
        " ##### ",
        "#     #",
        " ######",
        "      #",
        "      #",
        " ##### ",
    ],
    "-": [
        "       ",
        "       ",
        " ##### ",
        "       ",
        "       ",
        "       ",
    ],
    ".": [
        "       ",
        "       ",
        "       ",
        "       ",
        "  ###  ",
        "  ###  ",
    ],
    ":": [
        "  #    ",
        "  #    ",
        "       ",
        "       ",
        "  #    ",
        "  #    ",
    ],
    "!": [
        "  ###  ",
        "  ###  ",
        "  ###  ",
        "  ###  ",
        "       ",
        "  ###  ",
    ],
    "/": [
        "     ##",
        "    #  ",
        "   #   ",
        "  #    ",
        " #     ",
        "##     ",
    ],
    " ": [
        "   ",
        "   ",
        "   ",
        "   ",
        "   ",
        "   ",
    ],
}

HEIGHT = 6


def render(text):
    """Render text into a list of rows made of '#' and spaces."""
    rows = [""] * HEIGHT
    for idx, ch in enumerate(text.upper()):
        glyph = FONT.get(ch)
        if glyph is None:
            glyph = [" ##### ", "#     #", "#     #", "#     #", "#     #", " ##### "]
        for i in range(HEIGHT):
            rows[i] += glyph[i]
            if idx != len(text) - 1:
                rows[i] += " "
    return rows


def shadowed(text):
    """Glyph rows plus a subtle bottom shadow row (clean, no clutter)."""
    rows = render(text)
    width = max(len(r) for r in rows)
    out = [r.ljust(width) for r in rows]
    shade = []
    for y in range(HEIGHT):
        line = []
        for x in range(width):
            if out[y][x] == "#":
                line.append("#")
            else:
                line.append(" ")
        shade.append("".join(line))
    base = [" "] * width
    for x in range(width):
        if any(shade[y][x] == "#" for y in range(HEIGHT)):
            base[x] = "."
    out.append("".join(base))
    return out


def frame(width=78, char="!@#$%^&*()_+={}[]|:;\"'<>,.?/\\~"):
    """Decorative symbol frame line."""
    out = []
    i = 0
    while len(out) < width:
        out.append(char[i % len(char)])
        i += 1
    return "".join(out)


def big_text(text):
    """Plain block text used for section headers inside menus (6 rows)."""
    return render(text.upper())
