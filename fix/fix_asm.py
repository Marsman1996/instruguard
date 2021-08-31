import random
import json
import sys
import os
import re

import argparse

MAP_SIZE = 1 << 16

def dump_to_file(outf, list_code):
    if(len(list_code) > 0):
        outf.writelines(list_code)
        del list_code[:]

def insert_AFL_ins(temp_line_list, list_edgeid):
    edgeid = random.randint(0, MAP_SIZE)
    while (edgeid in list_edgeid):
        edgeid = random.randint(0, MAP_SIZE)
    list_edgeid.append(edgeid)
    instru = "\n" \
    "/* --- AFL TRAMPOLINE (64-BIT) --- */\n" \
    "\n" \
    ".align 4\n" \
    "\n" \
    "leaq -(128+24)(%%rsp), %%rsp\n" \
    "movq %%rdx,  0(%%rsp)\n" \
    "movq %%rcx,  8(%%rsp)\n" \
    "movq %%rax, 16(%%rsp)\n" \
    "movq $0x%08x, %%rcx\n" \
    "call __afl_maybe_log\n" \
    "movq 16(%%rsp), %%rax\n" \
    "movq  8(%%rsp), %%rcx\n" \
    "movq  0(%%rsp), %%rdx\n" \
    "leaq (128+24)(%%rsp), %%rsp\n" \
    "\n" \
    "/* --- END --- */\n" \
    "\n" % (edgeid)
    temp_line_list.insert(-1, instru)

def fix_asm(asm_file, instru_info, output):
    af = open(asm_file, "r")
    with open(instru_info, "r") as f_ins:
        dict_ins = json.load(f_ins)
    list_ins = dict_ins["list_ins"] # [xor_addr, add_addr, mov_addr, prev_loc]
    list_MIL = dict_ins["list_MIL"]
    list_RIL = dict_ins["list_RIL"]
    list_edgeid = dict_ins["list_edgeid"]

    afo = open(output, "w")

    temp_line_list = []
    instr_ok = 0
    _cout = 0
    MIL_num = 0
    RIL_num = 0

    lines = af.readlines()
    for line in lines:
        _cout += 1
        if (not _cout % 100000):
            sys.stdout.write("\r %d in %d" % (_cout, len(lines)))
            sys.stdout.flush()
        if (instr_ok == 0 and len(temp_line_list) > 100000):
            dump_to_file(afo, temp_line_list)

        # change __afl_area_ptr_2020e0 to __afl_area_ptr
        if (line.find("__afl_area_ptr") >= 0):
            line = re.sub("__afl_area_ptr_[a-z0-9]+", "__afl_area_ptr", line)

        # afo.write(line)
        temp_line_list.append(line)

        if (line[0] == '\t' and line[1] == '.'):
            if (line.find("text\n") == 2 or
            line.find("section\t.text") == 2 or
            line.find("section\t__TEXT,__text") == 2 or
            line.find("section __TEXT,__text") == 2):
                instr_ok = 1
                dump_to_file(afo, temp_line_list)
                continue
            if (line.find("section\t") == 2 or
            line.find("section ") == 2 or
            line.find("bss\n") == 2 or
            line.find("data\n") == 2):
                instr_ok = 0
                dump_to_file(afo, temp_line_list)
                continue
        
        if (instr_ok == 0):
            continue

        if (line[0:3] == ".LC"):
            # temp_line_list.append(line)
            prefix = int(line.lstrip(".LC").rstrip(":\n"), 16)
        elif (line[0:1] == "\t"):
            # match IL
            if (len(list_ins) > 0 and prefix in list_ins[0][0:3]):
                if (prefix == list_ins[0][0]):
                    _prev_reg = temp_line_list[-1].split(", ")[1].rstrip("\n")
                    if(_prev_reg.find("(%") >= 0):
                        temp_line_list.insert(-1, "\tmovq %rax, 0(%rsp)\n")
                        temp_line_list.insert(-1, "\tmovq __afl_prev_loc(%rip), %rax\n")
                        temp_line_list.insert(-1, "\tmovq %%rax, %s\n" % (_prev_reg))
                        temp_line_list.insert(-1, "\tmovq 0(%rsp), %rax\n")
                    else:
                        temp_line_list.insert(-1, "\tmovq __afl_prev_loc(%%rip), %s\n" % (_prev_reg))
                if (prefix == list_ins[0][2]):
                    temp_line_list[-1] = "\tmovq $%s, __afl_prev_loc(%%rip)\n" % (hex(list_ins[0][3]))
                    list_ins.pop(0)
                    dump_to_file(afo, temp_line_list)
            # match MIL
            elif (len(list_MIL) > 0 and prefix == list_MIL[0]):
                MIL_num += 1
                insert_AFL_ins(temp_line_list, list_edgeid)
                list_MIL.pop(0)
                dump_to_file(afo, temp_line_list)
            # match RIL
            elif (len(list_RIL) > 0 and prefix in list_RIL[0][0:3]):
                temp_line_list[-1] = "# " + temp_line_list[-1].rstrip("\n") + " # RIL del\n"
                if (prefix == list_RIL[0][1]):
                    list_RIL.pop(0)
                    dump_to_file(afo, temp_line_list)

    dump_to_file(afo, temp_line_list)
    af.close()
    afo.close()
    sys.stdout.write("\r finished                              \n")
    sys.stdout.flush()
    print("MIL: %d" % MIL_num)
    print("RIL: %d" % RIL_num)
    if (len(list_ins) > 0 or len(list_RIL) > 0 or len(list_MIL) > 0):
        print("[ERROR]: something went wrong?")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Fix the instrumentation errors of assembly code by the collected instrumentation infomation.")
    parser.add_argument("--asm_file",
                        help="Assembly code file.", required=True)
    parser.add_argument("--instru_info",
                        help="Json file which contains the instrumentation infomation.", required=True)
    parser.add_argument(
        "-O", "--output", help="The output assembly code.", required=True)

    args = parser.parse_args()
    path_asm_file = args.asm_file
    path_instru_info = args.instru_info
    path_out = args.output

    fix_asm(path_asm_file, path_instru_info, path_out)
