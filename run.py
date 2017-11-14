"""
Run idat.exe along with the idapython script (sideable.py)
which retrieves every basic block in a specified function
from the given ELF binary file.
"""

import os
import subprocess
import cPickle

class BasicBlock():
    bid = None              # basic block's id
    start_ea = None         # starting address
    end_ea = None           # ending address
    # pred_blocks = []        # list of predecessor blocks' id
    succ_blocks = []        # list of successor blocks' id
    addr_inst_map = {}      # map of address to instruction
    addr_inst_abs_map = {}  # map of address to abstract instruction
    inst_str = ""           # instructions as joined string
    inst_hash = ""          # md5 hash of the string
    inst_abs_str = ""       # abstract instructions as joined string
    inst_abs_hash = ""      # md5 hash of the abstract string


def analyze(target):
    # cmd = 'idat.exe -c -A -P- -S"sideable.py ' + target + '" ' + target
    cmd = 'idat.exe -c -A -P- -S"sideable.py" ' + target
    os.system(cmd)

    bb_list = []

    with open("log-" + target, "rb") as fp:
        # lst = fp.read().rstrip().split(" ")
        # lst = list(set(lst))
        while True:
            try:
                bb = cPickle.load(fp)
                bb_list.append(bb)
            except EOFError:
                break

    return bb_list


def main():
    bb_list1 = analyze("date-822")
    # bb_list2 = analyze("date-823")

    for bb1 in bb_list1:
        print bb1.bid, bb1.succ_blocks, bb1.addr_inst_abs_map

    # print len(bb_list1), "elements in list1"
    # print len(bb_list2), "elements in list2"

    # match_cnt = 0
    # match_list_bb1 = []
    # for bb1 in bb_list1:
    #     print bb1.addr_inst_map
    #     match = 0
    #     for bb2 in bb_list2:
    #         if bb1.inst_hash == bb2.inst_hash:
    #             print "match @", bb1.bid, bb2.bid
    #             match = 1
    #     if match:
    #         match_list_bb1.append(bb1.bid)
    #         match_cnt += 1

    # print match_cnt, "matches"
    # for bb1 in bb_list1:
    #     if bb1.bid not in match_list_bb1:
    #         print bb1.bid

if __name__ == "__main__":
    main()
