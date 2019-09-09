# Public project by Walter
#
# Custom printing library for debugging


# Enable developer print statements
traceActive = True

# Class containing colors i copied from somewhere
class color:
    pink = '\033[95m'
    blue = '\033[94m'
    green = '\033[92m'
    yellow = '\033[93m'
    red = '\033[91m'
    stopColor = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# Colors for divisions
division_palette = {
    "debug" : color.yellow,
    "warn"  : color.red,
    "info"  : color.blue,
}

# Custom printing function
def trace(division, message, devOnly=True):
    if traceActive or not devOnly:
        # Get corresponding color for division, if not found then pink.
        textColor = division_palette.get(division, color.pink)
        print("%s[%s]%s %s%s"%(textColor,
                            division,
                            " "*(8-len(division)),
                            message.replace("\n"," "),
                             color.stopColor))