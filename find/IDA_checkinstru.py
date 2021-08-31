import idc
import idaapi
import idautils

import json


# We do not detect these fucntions.
pass_functions = [
    "_start",
    "deregister_tm_clones",
    "register_tm_clones",
    "__do_global_dtors_aux",
    "frame_dummy",
    "__libc_csu_init",
    "__libc_csu_fini",
    "__afl_maybe_log",

    "__frame_dummy_init_array_entry",
    "__init_array_start",
    "__do_global_dtors_aux_fini_array_entry",
    "__init_array_end",
    "__afl_persistent_loop",
    "__afl_manual_init",
    "__afl_auto_init",
    "__sanitizer_cov_trace_pc_guard_init",
    "__sanitizer_cov_trace_pc_guard",

    "update_mem_peak",
    "traceBegin",
    "traceEnd",
    "instr_Call",
    "instr_Return",
    "instr_Free",
    "instr_MallocAndSize",
    "instr_CallocAndSize",
    "instr_ReallocAhead",
    "instr_ReallocAndSize",
    "instr_Exit",
    "stat_0",
    "fstat",
    "lstat",
    "__afl_log_loc",
]


def check_instru(path_log_instru, path_json_instru):
    count_allBB = 0
    count_uninstrumented = 0
    count_instrumented = 0
    moreIns_count = 0
    f_log_instru = open(path_log_instru, "wb")

    all_segs = idautils.Segments()
    for seg_addr in all_segs:
        if(idc.SegName(seg_addr) == ".text"):
            text_start = idc.SegStart(seg_addr)
            text_end = idc.SegEnd(seg_addr)
    all_funcs = idautils.Functions(text_start, text_end)

    dict_ins = {"list_ins": [], "list_MIL": [], "list_RIL": [], "list_edgeid": []}

    for aFunc in all_funcs:
        fflags = idc.GetFunctionFlags(aFunc)
        if(fflags & FUNC_LIB) or (fflags & FUNC_THUNK):
            continue
        func = idaapi.get_func(aFunc)
        flowchart = idaapi.FlowChart(func, flags=idaapi.FC_PREDS)

        wrong_label_mark = 0
        for bb in flowchart:
            # We skip the basic blocks which are empty, 
            if (bb.startEA == bb.endEA):
                continue
            # not in the .text, 
            if (idc.SegName(bb.startEA) != ".text"):
                continue
            # in the function list we do not want to detect, 
            if (idc.GetFunctionName(bb.startEA)) in pass_functions:
                continue
            # or in the instrumentation function.
            if (idc.GetFunctionName(bb.startEA).find("__afl_maybe_log_") == 0):
                continue

            # IDA sometimes uncorrectly splits the basic blocks with weird labels, 
            # and these labels do not have any refs.
            if wrong_label_mark:
                wrong_label_mark = 0
            else:
                count_allBB = count_allBB+1
                instru_cnt = 0
                pre_xor = 0
                pre_add = 0
                IL_start_temp = 0
                list_ins_temp = []

            currentAddr = bb.startEA
            while currentAddr < bb.endEA:  # endEA is the startEA of the next BasicBlock
                menm = idc.GetMnem(currentAddr)
                opd1 = idc.GetOpnd(currentAddr, 0)
                opd2 = idc.GetOpnd(currentAddr, 1)

                # Instrumentation of afl-gcc, we simply detect the call __afl_maybe_log* operation
                if (menm == "call" and opd1[0:15] == "__afl_maybe_log"):
                    count_instrumented += 1
                    instru_cnt += 1
                    list_ins_temp.append([currentAddr, currentAddr, currentAddr, -1])

                # Matching the instrumentation pattern of afl-clang-fast
                # xor reg_prev_loc, imm_cur_loc
                if (menm == "xor"):
                    try:
                        cur_loc_temp = int(opd2.strip("h"), 16)
                    except:
                        pass
                    else:
                        pre_xor = 1
                        IL_start_temp = currentAddr

                # add/inc afl_map[reg], 1
                if ((menm == "add" and opd2 == "1" and pre_xor == 1) or
                        (menm == "inc" and pre_xor == 1)):
                    cur_loc = cur_loc_temp
                    IL_start = IL_start_temp
                    IL_add = currentAddr
                    pre_add = 1

                # mov reg, (imm_cur_loc >> 1)
                if (pre_add == 1 and pre_xor == 1 and menm == "mov"):
                    prev_loc = opd2.strip("h")
                    try:
                        prev_loc = int(prev_loc, 16)
                    except:
                        prev_loc = -1

                    if (prev_loc != -1 and prev_loc == cur_loc >> 1):
                        pre_add = 0
                        pre_xor = 0
                        count_instrumented += 1
                        instru_cnt += 1
                        list_ins_temp.append(
                            [IL_start, IL_add, currentAddr, prev_loc])
                        dict_ins["list_edgeid"].append(cur_loc)

                currentAddr = idc.NextHead(currentAddr)
                continue

            # Identify labels without refs.
            if (currentAddr < func.endEA):
                refs = idautils.CodeRefsTo(currentAddr, 0)
                has_ref = 0
                for _ in refs:
                    has_ref += 1
                prev_addr = idc.PrevHead(currentAddr)
                prev_menm = idc.GetMnem(prev_addr)
                if (has_ref > 0 or bb.endEA == func.endEA or prev_menm[0] == "j" or prev_menm[0:3] == "ret"):
                    pass
                else:
                    wrong_label_mark = 1
                    continue

            if (instru_cnt > 0 and len(list_ins_temp) > 0):
                IL_start = list_ins_temp[-1][0]
            else:
                IL_start = 0

            # MIL error
            if instru_cnt == 0 and currentAddr >= bb.endEA:
                if (idc.GetFunctionName(bb.startEA)) not in pass_functions:
                    count_uninstrumented = count_uninstrumented+1
                    f_log_instru.write("BB_unInstrumented: \n"+str(idc.GetFunctionName(bb.startEA)) +
                             ":"+str(hex(int(bb.startEA)))+"\n")
                    f_log_instru.write("\n")
                    dict_ins["list_MIL"].append(bb.startEA)
                    continue
            # RIL error
            if instru_cnt > 1 and currentAddr >= bb.endEA:
                moreIns_count = moreIns_count+1
                if len(list_ins_temp) > 0:
                    dict_ins["list_ins"].append(list_ins_temp.pop())
                    dict_ins["list_RIL"] += list_ins_temp
                f_log_instru.write("BB_Instrumented %d times: \n" % instru_cnt +
                         str(idc.GetFunctionName(bb.startEA))+"\n")
                f_log_instru.write("\n")
                continue
            # Normal Instrumentation.
            if len(list_ins_temp) == 1:
                dict_ins["list_ins"].append(list_ins_temp[0])
            elif len(list_ins_temp) > 1:
                dict_ins["list_ins"].append("ERROR")
                print("[ERROR]: Something wrong happened.")
                exit(-1)

    with open(path_json_instru, "w") as f_json_instru:
        json.dump(dict_ins, f_json_instru)

    f_log_instru.write("count_allBB: "+str(count_allBB)+"\n")
    f_log_instru.write("count_insBB: "+str(count_instrumented)+"\n")
    f_log_instru.write("count_uninsBB: " + str(count_uninstrumented) + "\n")
    f_log_instru.write("moreIns_count: "+str(moreIns_count)+"\n")
    f_log_instru.close()


if __name__ == '__main__':
    idc.Wait()

    path_log_instru = idc.GetInputFilePath()+"_instru.log"
    path_json_instru = idc.GetInputFilePath()+"_instru.json"
    check_instru(path_log_instru, path_json_instru)

    # idc.Exit(0)
