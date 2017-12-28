"""
Run idat.exe along with the idapython script (sideable.py)
which retrieves every basic block in a specified function
from the given ELF binary file.
"""

import os
import subprocess
import cPickle
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

cfg1 = {}
cfg2 = {}

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


def main():
    bb_list1 = analyze("date-822")
    bb_list2 = analyze("date-823")

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
                print "match @", bb1.bid, bb2.bid
                match_list_bb2.append(bb2.bid)
                match = 1
        if match:
            match_list_bb1.append(bb1.bid)
            match_cnt += 1

    print match_cnt, "matches"
    for bb1 in bb_list1:
        if bb1.bid not in match_list_bb1:
            print "candidate bb in B0:", bb1.bid
            for addr in sorted(bb1.addr_inst_map):
                print addr, bb1.addr_inst_map[addr]
            target = bb1.bid

            bb1_preds = get_preds(cfg1, bb1.bid)
            bb1_succs = cfg1[bb1.bid]
            print "preds:", bb1_preds
            print "succs:", bb1_succs

            # for parent in bb1_preds:
            #     for child in bb1_succs:
            #         print find_all_paths(cfg1, parent, child)

    for bb2 in bb_list2:
        if bb2.bid not in match_list_bb2:
            print bb2.bid
            for addr in sorted(bb2.addr_inst_map):
                print addr, bb2.addr_inst_map[addr]

            bb2_preds = get_preds(cfg2, bb2.bid)
            bb2_succs = cfg2[bb2.bid]
            print "preds:", bb2_preds
            print "succs:", bb2_succs

    # we need to look for an old-new pair

if __name__ == "__main__":
    main()
