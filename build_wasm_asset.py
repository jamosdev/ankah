"""Convert a built WebAssembly module into a C header for the gateway."""

import pathlib
import sys

source, output = map(pathlib.Path, sys.argv[1:3])
data = source.read_bytes()
with output.open("w", encoding="ascii") as stream:
    stream.write("#ifndef ANKAH_BROWSER_POW_DATA_H\n#define ANKAH_BROWSER_POW_DATA_H\n")
    stream.write("static const unsigned char ankah_browser_pow_data[] = {\n")
    for start in range(0, len(data), 16):
        stream.write("    " + ", ".join(str(byte) for byte in data[start:start + 16]) + ",\n")
    stream.write("};\n#endif\n")
