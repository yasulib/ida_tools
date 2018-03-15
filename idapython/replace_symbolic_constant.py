import idc, idautils
import ida_bytes
import ida_enum

api_list = {
        "CopyFileExA":{
            6:{ # 6th argument
                0x0001:"COPY_FILE_FAIL_IF_EXISTS",
                0x0002:"COPY_FILE_RESTARTABLE",
                0x0004:"COPY_FILE_OPEN_SOURCE_FOR_WRITE",
                0x0008:"COPY_FILE_ALLOW_DECRYPTED_DESTINATION",
                0x0800:"COPY_FILE_COPY_SYMLINK",
                0x1000:"COPY_FILE_NO_BUFFERING"
                },
            }
        }

def is_replace_api(ea):
    func_name = idc.print_operand(ea, 0)
    for api in api_list.keys():
        if(func_name.find(api) > 0):
            return api
    return False

def replace_sym_const(ea, api):
    for arg_n in api_list[api].keys():
        # Calling Convention: cdecl, stdcall
        push_cnt  = 0
        ea_search = ea
        while push_cnt < arg_n:
            ea_search = idc.prev_head(ea_search)
            op = idc.print_insn_mnem(ea_search)
            if op == "push":
                push_cnt += 1

        operand   = int(idc.print_operand(ea_search, 0))
        enum_name = api + "_" + str(arg_n)
        const     = api_list[api][arg_n][operand]

        enum_id   = ida_enum.get_enum(enum_name)
        if enum_id == 0xffffffff:
            # add new enum
            enum_qty  = ida_enum.get_enum_qty()
            enum_id   = ida_enum.add_enum(enum_qty, enum_name, 0)

        symbolic_id = ida_enum.get_enum_member_by_name(const)
        if symbolic_id == 0xffffffff:
            # add new enum member
            ida_enum.add_enum_member(enum_id, const, operand, 0xffffffff)

        ida_bytes.op_enum(ea_search, 0, enum_id, 0)


def main():
    print("[*] Start Replace Symbolic Constant")

    for start in idautils.Segments():
        #if idc.get_segm_name(start) != '.text':
        #    continue
        ea  = start
        end = idc.get_segm_end(start)
        while ea < end:
            ea = idc.next_head(ea, end)
            op = idc.print_insn_mnem(ea)
            if op == "call":
                api = is_replace_api(ea)
                if api == False:
                    continue
                replace_sym_const(ea, api)

    print("[*] Finished Replace Symbolic Constant")

if __name__ == '__main__':
    main()

