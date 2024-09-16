import json

# from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.block import BasicBlockModel
from ghidra.util.task import TaskMonitor

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

list_check_seq = [["XOR"], ["ADD", "INC"], ["MOV"]]


def check_instru():
    cnt_BBs = 0
    cnt_MIL = 0
    cnt_IL = 0
    cnt_RIL = 0

    prog = getCurrentProgram()
    bbm = BasicBlockModel(prog)
    base_addr = prog.getImageBase().getAddressableWordOffset()

    path_IL_log = prog.getExecutablePath() + "_instru.log"
    f_IL_log = open(path_IL_log, "wb")

    prog_mem = prog.getMemory()
    text_seg = prog_mem.getBlock(".text")
    if text_seg == None:
        return

    text_seg_start = text_seg.getStart()
    text_seg_end = text_seg.getEnd()
    text_seg_addrset = prog.getAddressFactory().getAddressSet(
        text_seg_start, text_seg_end
    )
    int_text_seg_start = text_seg_start.getAddressableWordOffset() - base_addr
    int_text_seg_end = text_seg_end.getAddressableWordOffset() - base_addr

    dict_ins = {
        "list_ins": [],
        "list_MIL": [],
        "list_RIL": [],
        "list_edgeid": [],
        "list_optins": [],
    }

    # Iter functions in the .text segment
    listing = prog.getListing()
    # func_manager = prog.getFunctionManager()
    functionIterator = listing.getFunctions(text_seg_addrset, True)
    for func in functionIterator:
        func_name = func.getName()
        if func_name in pass_functions or func_name.find("__afl_maybe_log_") == 0:
            continue
        func_start_addr = func.getEntryPoint()
        func_end_addr = func.getBody().getMaxAddress()
        int_func_addr = func_start_addr.getAddressableWordOffset() - base_addr
        bb_iter = bbm.getCodeBlocksContaining(func.getBody(), TaskMonitor.DUMMY)
        list_BB_IL = []

        unwanted_label_mark = False
        for bb in bb_iter:
            bb_start_addr = bb.getMinAddress()
            bb_end_addr = bb.getMaxAddress()
            int_bb_addr = bb_start_addr.getAddressableWordOffset() - base_addr

            if unwanted_label_mark:
                unwanted_label_mark = False
            else:
                cnt_BBs += 1
                seq_idx = 0
                cnt_BB_IL = 0
                list_BB_IL = []
                prev_cnt = 0
                succ_cnt = 0
                # opt_BB_addr = 0

            if unwanted_label_mark == False:
                # opt_BB_addr = bb_start_addr
                predecessors = bb.getSources(TaskMonitor.DUMMY)
                while predecessors.hasNext():
                    predecessor_bb_ref = predecessors.next()
                    predecessor_bb = predecessor_bb_ref.getSourceBlock()
                    # print(predecessor_bb_ref.getFlowType().getName())
                    if (
                        prog_mem.getBlock(predecessor_bb.getMinAddress()).getName()
                        != ".text"
                    ):
                        continue
                    prev_cnt += 1
                # print("source of " + hex(int_bb_addr) + ": " + str(prev_cnt))

            for ins in listing.getInstructions(bb, True):
                mnem = ins.getMnemonicString()
                opd1 = ins.getDefaultOperandRepresentation(0)
                opd2 = ins.getDefaultOperandRepresentation(1)
                ins_addr = ins.getAddress()
                int_ins_addr = ins_addr.getAddressableWordOffset() - base_addr

                if mnem == list_check_seq[0][0]:  # xor reg_prev_loc, imm_cur_loc
                    try:
                        imm_cur_loc = int(opd2, 16)
                    except:
                        continue
                    seq_xor_addr = int_ins_addr
                    seq_idx = 1
                elif seq_idx < len(list_check_seq) and mnem in list_check_seq[seq_idx]:
                    if seq_idx == 1:  # add afl_map[reg], 1 / inc
                        if opd2 != "0x1" and opd2 != "<UNSUPPORTED>":
                            # seq_idx = 0
                            continue
                        seq_add_addr = int_ins_addr
                        seq_idx += 1
                    elif seq_idx == 2:  # mov reg, (imm_cur_loc >> 1)
                        try:
                            imm_prev_loc = int(opd2, 16)
                        except:
                            # seq_idx = 0
                            continue
                        if imm_prev_loc != imm_cur_loc >> 1:
                            # seq_idx = 0
                            continue
                        cnt_IL += 1
                        cnt_BB_IL += 1
                        seq_idx = 0
                        list_BB_IL.append(
                            [seq_xor_addr, seq_add_addr, int_ins_addr, imm_prev_loc]
                        )
                        dict_ins["list_edgeid"].append(imm_cur_loc)

            ins = ins.getNext()
            ins_addr = ins.getAddress()

            refs = getReferencesTo(ins_addr)
            cnt_ref = 0
            if ins_addr < func_end_addr:
                for ref in refs:
                    if ref.getReferenceType().getName() == "DATA":
                        continue
                    cnt_ref += 1
                if (
                    cnt_ref > 0
                    or func_end_addr == bb_end_addr
                    or mnem[0] == "J"
                    or mnem == "RET"
                ):
                    pass
                else:
                    # print(hex(int_bb_addr), cnt_ref)
                    unwanted_label_mark = True
                    continue
            if unwanted_label_mark == False:
                successors = bb.getDestinations(TaskMonitor.DUMMY)
                while successors.hasNext():
                    successor_bb_ref = successors.next()
                    successor_bb = successor_bb_ref.getDestinationBlock()
                    # print(successor_bb_ref.getFlowType().getName())
                    if (
                        prog_mem.getBlock(successor_bb.getMinAddress()).getName()
                        != ".text"
                    ):
                        continue
                    succ_cnt += 1
                # print("dest of " + hex(int_bb_addr) + ": " + str(succ_cnt))

            if prev_cnt == 1 and succ_cnt > 1:
                if len(list_BB_IL) > 0:
                    dict_ins["list_optins"].append([int_bb_addr, list_BB_IL[0]])
                else:
                    dict_ins["list_optins"].append([int_bb_addr, [0, 0, 0, 0]])
            if cnt_BB_IL == 0:  # MIL error
                cnt_MIL += 1
                f_IL_log.write(
                    "BB_unInstrumented: \n"
                    + func_name
                    + ":"
                    + hex(int_bb_addr).rstrip("L")
                    + "\n\n"
                )
                dict_ins["list_MIL"].append(int_bb_addr)
            elif cnt_BB_IL > 1:  # RIL error
                cnt_RIL += 1
                f_IL_log.write(
                    "BB_Instrumented %d times: \n" % cnt_BB_IL
                    + func_name
                    + ":"
                    + hex(int_bb_addr).rstrip("L")
                    + "\n\n"
                )
                dict_ins["list_ins"].append(list_BB_IL.pop())
                dict_ins["list_RIL"] += list_BB_IL
            elif cnt_BB_IL == 1:  # Normal Instrumentation
                dict_ins["list_ins"].append(list_BB_IL[0])

    path_IL_json = prog.getExecutablePath() + "_instru.json"
    with open(path_IL_json, "w") as f_IL_json:
        json.dump(dict_ins, f_IL_json)

    f_IL_log.write("count_allBB: " + str(cnt_BBs) + "\n")
    f_IL_log.write("count_insBB: " + str(cnt_IL) + "\n")
    f_IL_log.write("count_uninsBB: " + str(cnt_MIL) + "\n")
    f_IL_log.write("moreIns_count: " + str(cnt_RIL) + "\n")
    f_IL_log.close()


if __name__ == "__main__":
    check_instru()
