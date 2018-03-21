import idc, idautils

color = 0xffd0d0

def main():
    print("[*] Start Set Color JMP or CALL")
    for start in idautils.Segments():
        ea  = start
        end = idc.get_segm_end(start)
        while ea < end:
            ea = idc.next_head(ea, end)
            op = idc.print_insn_mnem(ea)
            if(op.find("j") == 0 or op == "call"):
                set_color(ea, 1, color)

    print("[*] Finished Set Color JMP or CALL")

if __name__ == '__main__':
    main()

