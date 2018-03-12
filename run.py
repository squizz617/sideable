"""
Run idat.exe along with the idapython script (sideable.py)
which retrieves every basic block in a specified function
from the given ELF binary file.
"""

import os
import sys
import subprocess
import cPickle
import Levenshtein

bin_dir = "binaries"
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), bin_dir))

# from anytree import Node, RenderTree

class BasicBlock():
    bid = None              # basic block's id
    start_ea = None         # starting address
    end_ea = None           # ending address
    pred_blocks = []        # list of predecessor blocks' id
    succ_blocks = []        # list of successor blocks' id
    addr_inst_map = {}      # map of address to instruction
    addr_inst_abs_map = {}  # map of address to abstract instruction
    inst_str = ""           # instructions as joined string
    inst_hash = ""          # md5 hash of the string
    inst_abs_str = ""       # abstract instructions as joined string
    inst_abs_hash = ""      # md5 hash of the abstract string


def analyze(target, function):
    # cmd = 'idat.exe -c -A -P- -S"sideable.py ' + target + '" ' + target
    cmd = 'idat.exe -c -A -P -S"sideable.py ' + function + '" ' + os.path.join(bin_dir, target)
    print cmd
    os.system(cmd)

    bb_dict = {} # {"func_name": bb_list}

    if function == "FORALLFUNC":
        for func_name in os.listdir(os.path.join(bin_dir, "allfunc-"+target)):
            bb_list = []
            with open(os.path.join(bin_dir, "allfunc-"+target, func_name), "rb") as fp:
                while True:
                    try:
                        bb = cPickle.load(fp)
                        bb_list.append(bb)
                    except EOFError:
                        break
            bb_dict[func_name] = bb_list

    else:
        bb_list = []
        with open(target + ".dcm", "rb") as fp:
            while True:
                try:
                    bb = cPickle.load(fp)
                    bb_list.append(bb)
                except EOFError:
                    break
        bb_dict[function] = bb_list
    
    return bb_dict


def find_all_paths(graph, start, end, path=[]):
    path = path + [start]
    if start == end:
        return [path]
    if not graph.has_key(start):
        return []
    paths = []
    for node in graph[start]:
        if node not in path:
            newpaths = find_all_paths(graph, node, end, path)
            for newpath in newpaths:
                paths.append(newpath)
    return paths


def get_preds(cfg, bid):
    preds_list = []
    for node in cfg:
        for succ in cfg[node]:
            if succ == bid:
                preds_list.append(node)
    return list(set(preds_list))


def print_inst(bb):
    for addr in sorted(bb.addr_inst_map):
        print addr, bb.addr_inst_map[addr]


def print_abs_inst(bb):
    for addr in sorted(bb.addr_inst_abs_map):
        print addr, bb.addr_inst_abs_map[addr]


def main():
    vuln_func = "make_device"
    bb_list1 = analyze("busybox_mdev_old", vuln_func)[vuln_func]
    bb_list2 = analyze("busybox_mdev_new", vuln_func)[vuln_func]

    # vuln_func = "xmalloc_optname_optval"
    # bb_list1 = analyze("busybox_1.24.2_armeabi5", vuln_func)[vuln_func]
    # bb_list2 = analyze("busybox_1.25.0_armeabi5", vuln_func)[vuln_func]

    cfg1 = {}
    cfg2 = {}

    for bb1 in bb_list1:
        # print bb1.bid, bb1.succ_blocks
        # for addr in sorted(bb1.addr_inst_map):
        #     print addr, bb1.addr_inst_map[addr]
        cfg1[bb1.bid] = bb1.succ_blocks
    #     # print bb1.pred_blocks, bb1.succ_blocks
    #     if bb1.bid not in bbTree:
    #         bbTree[bb1.bid] = Node(str(bb1.bid))
    #     for succ in bb1.succ_blocks:
    #         if succ not in bbTree:
    #             bbTree[succ] = Node(str(succ), parent=bbTree[bb1.bid])
    # print bbTree
    # print RenderTree(bbTree[0])
    entry = 0
    exit = len(bb_list1) - 1

    for bb2 in bb_list2:
        cfg2[bb2.bid] = bb2.succ_blocks

    match_cnt = 0
    match_list_bb1 = []
    match_list_bb2 = []
    for bb1 in bb_list1:
        # print bb1.addr_inst_map
        match = 0
        for bb2 in bb_list2:
            # if bb1.inst_hash == bb2.inst_hash:
            if bb1.inst_abs_hash == bb2.inst_abs_hash:
                # print "match @", bb1.bid, bb2.bid
                match_list_bb2.append(bb2.bid)
                match = 1
        if match:
            match_list_bb1.append(bb1.bid)
            match_cnt += 1

    vuln_ptrace_list = []

    missing_bb_list1 = []
    print match_cnt, "/", len(bb_list1), "matches"
    for bb1 in bb_list1:
        if bb1.bid not in match_list_bb1:
            missing_bb_list1.append(bb1)
            print "candidate bb in 1st binary:", bb1.bid
            # for addr in sorted(bb1.addr_inst_map):
                # print addr, bb1.addr_inst_map[addr]
            # print_inst(bb1)

            bb1.pred_blocks = get_preds(cfg1, bb1.bid)
            # print "preds:", bb1.pred_blocks
            # print "succs:", bb1.succ_blocks

            print "POSSIBLE VULN TRACES:"
            for pred in bb1.pred_blocks:
                for succ in bb1.succ_blocks:
                    vuln_ptrace_list.append([pred, bb1.bid, succ])

                    print "{}-{}-{}".format(pred, bb1.bid, succ)
                    print "({})".format(pred)
                    print_inst(bb_list1[pred])
                    print "({})".format(bb1.bid)
                    print_inst(bb1)
                    print "({})".format(succ)
                    print_inst(bb_list1[succ])
                    print ""

            print "---------------------"

            # for parent in bb1_preds:
            #     for child in bb1_succs:
            #         print find_all_paths(cfg1, parent, child)
#    for bb1 in missing_bb_list1:

    # I can think of three cases in which blocks are patched:
    # 1. a single block is changed
    # 2. blocks of parent-child relationship are changed
    # 3. blocks that have no direct relationship are changed
    # Need to take different actions for each case.

    if len(missing_bb_list1) == 1: # CASE SingleBlock
        pass
    else: # CASE MultipleBlock
        # make a mapping of each bb and its preds and succs
        for bb1 in missing_bb_list1:
            for block in bb1.pred_blocks:
                if block in missing_bb_list1:
                    print "block in missing bb list1:", block #


    print "======================================================"

    for bb2 in bb_list2:
        if bb2.bid not in match_list_bb2:
            print "bb2.bid:", bb2.bid
            for addr in sorted(bb2.addr_inst_map):
                print addr, bb2.addr_inst_map[addr]
            print "or,"
            print bb2.inst_str

            bb2_preds = get_preds(cfg2, bb2.bid)
            bb2_succs = cfg2[bb2.bid]
            print "preds:", bb2_preds
            print "succs:", bb2_succs

            print "---------------------"

            # for bb_pred in bb2_preds:
            #     for bb in bb_list1:
            #         if bb_list2[bb_pred].inst_abs_hash == bb.inst_abs_hash:
            #             print "pred match:", bb_pred
            #             print "in cfg1:", bb.bid, bb_list1[bb.bid].addr_inst_map
            #             print "its succs:", cfg1[bb.bid]
            #             for bb1 in cfg1[bb.bid]:
            #                 print bb1, bb_list1[bb1].addr_inst_map

    print cfg1

    print "LIST OF VULN PTRACES:", vuln_ptrace_list

    # bb_dict3 = analyze("busybox-iptime-a3004ns", "FORALLFUNC")
    bb_dict3 = analyze("busybox-RT-AC58U", "FORALLFUNC")

    for function in bb_dict3:
        cfg3 = {}
        for bb3 in bb_dict3[function]:
            cfg3[bb3.bid] = bb3.succ_blocks
        # bb_abs_hash_list = []
        for bb3 in bb_dict3[function]:
            for vuln_ptrace in vuln_ptrace_list:
                # print "looking for ptrace", vuln_ptrace
                for vuln_bb in vuln_ptrace:
                    if bb3.inst_abs_hash == bb_list1[vuln_bb].inst_abs_hash:
                        print "[+] found {0}:\t{1}\t{2:#x}\t{3}".format(vuln_bb, function, bb3.start_ea, vuln_ptrace)



        #     bb_abs_hash_list.append(bb.inst_abs_hash)
        # bb_abs_hash_list = list(set(bb_abs_hash_list))

        # cnt = 0
        # for hashval in vuln_ptrace_abs_hash:
        #     if hashval in bb_abs_hash_list:
        #         cnt += 1
        
        # if cnt > 1:

        #     print function, cnt




if __name__ == "__main__":
    main()
