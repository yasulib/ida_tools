import ida_bytes
import ida_kernwin

def valid_check(ea, xor_key):
    if ea == BADADDR:
        exit("invalid address")
    if xor_key < 0x00 or xor_key > 0xff:
        exit("invalid xor_key : "+ str(xor_key))
    return 1

def main():
    print("[*] Start patching to XOR encoded blocks")
    ea      = ida_kernwin.ask_addr(BADADDR, "What address is encoded block by xor?")
    xor_key = ida_kernwin.ask_long(0x00,    "Waht is key for xor?(0-255)")

    valid_check(ea, xor_key)

    print hex(ea)
    print hex(xor_key)

    while True:
      b = ida_bytes.get_byte(ea)
      if b == 0:
        break
      ida_bytes.patch_byte(ea, b ^ xor_key)
      ea += 1

    print("[*] Finished patching to XOR encoded blocks")


if __name__ == '__main__':
    main()

# TODO: condition of xor block end
# TODO: some bytes of xor key

