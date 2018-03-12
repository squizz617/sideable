"""
Retrieve basic blocks and its metadata.
http://magiclantern.wikia.com/wiki/IDAPython/intro
https://www.hex-rays.com/products/ida/support/idapython_docs/
"""

import hashlib
import cPickle
import inspect
import os
import sys
import logger
import idautils
import idaapi
import idc

bin_dir = "binaries"
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), bin_dir))

# bb_table = {}


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

    # def __init__(self, bb_id, startEA, endEA, pred_blocks, succ_blocks):
    def __init__(self, bb_id, startEA, endEA, pred_blocks, succ_blocks):
        self.bid = bb_id
        self.start_ea = startEA
        self.end_ea = endEA
        self.pred_blocks = pred_blocks
        self.succ_blocks = succ_blocks
        self.addr_inst_map = {}
        self.addr_inst_abs_map = {}
        self.inst_str = ""
        self.inst_abs_str = ""

        for head in idautils.Heads(self.start_ea, self.end_ea):
            idc.OpHex(head, -1) # print everything in Hex
            addr = "%08X" % head
            mnem = idc.GetMnem(head)

            if mnem.startswith("j"):
                continue # WARNING: experimental feature to filter jmp's at the end of blocks

            op1 = idc.GetOpnd(head, 0)
            op1_type = idc.GetOpType(head, 0)
            # op1_val = idc.GetOperandValue(head, 0)
            op2 = idc.GetOpnd(head, 1)
            op2_type = idc.GetOpType(head, 1)
            # op2_val = idc.GetOperandValue(head, 1)

            if op1_type == idc.o_far or op1_type == idc.o_near:
                op1 = "addr"
            if op2_type == idc.o_far or op2_type == idc.o_near:
                op2 = "addr"

            self.inst_str += mnem + op1 + op2
            self.addr_inst_map[addr] = [mnem, op1, op2]

            if op1_type == idc.o_void: # 0
                op1 = ""
            elif op1_type == idc.o_reg: # 1
                op1 = "reg"
            elif op1_type == idc.o_mem: # 2
                op1 = "mem"
            elif op1_type == idc.o_phrase: # 3
                op1 = "phr"
            elif op1_type == idc.o_displ: # 4
                op1 = "dis"
            elif op1_type == idc.o_imm: # 5
                op1 = "val"
            elif op1_type == idc.o_far or op1_type == idc.o_near: # 6 7
                op1 = "addr"

            if op2_type == idc.o_void:
                op2 = ""
            elif op2_type == idc.o_reg:
                op2 = "reg"
            elif op2_type == idc.o_mem:
                op2 = "mem"
            elif op2_type == idc.o_phrase:
                op2 = "phr"
            elif op2_type == idc.o_displ:
                op2 = "dis"
            elif op2_type == idc.o_imm:
                op2 = "val"
            elif op2_type == idc.o_far or op2_type == idc.o_near:
                op2 = "addr"

            self.inst_abs_str += mnem + op1 + op2
            self.addr_inst_abs_map[addr] = [mnem, op1, op2]

        self.inst_hash = hashlib.md5(self.inst_str).hexdigest()
        self.inst_abs_hash = hashlib.md5(self.inst_abs_str).hexdigest()

    def __getstate__(self):
        self.addr_inst_map = self.addr_inst_map
        self.addr_inst_abs_map = self.addr_inst_abs_map
        return self.__dict__


if __name__ == "__main__":
    idaapi.autoWait()

    fp_log = open("logger", "a")

    flag_allfunc = 0
    target_binary_name = idaapi.get_root_filename()
    
    if len(idc.ARGV) == 2:
        func_target = idc.ARGV[1]
        if func_target == "FORALLFUNC":
            flag_allfunc = 1
            dir_name = os.path.join(bin_dir, "allfunc-"+target_binary_name)
            try:
                os.mkdir(dir_name)
            except:
                pass
        else:
            fp_onefunc = open(os.path.join(bin_dir, "func-"+target_binary_name + ".dcm"), "wb")

    else:
        func_target = "FORALLFUNC"
        flag_allfunc = 1
        dir_name = os.path.join(bin_dir, "allfunc-"+target_binary_name)
        try:
            os.mkdir(dir_name)
        except:
            pass
        # fp_log.write(target_binary_name + "\n" + str(flag_allfunc) + "\n" + func_target)

    funcs = idautils.Functions()
    for f in funcs:
        func_name = idc.GetFunctionName(f)
        # print >> fp_log, func_name
        if flag_allfunc:
            try:
                fp_allfunc = open(os.path.join(dir_name, "func-"+func_name+".dcm"), "wb")
            except IOError:
                continue
            bb_list = []
            
            flowchart = idaapi.FlowChart(idaapi.get_func(f))
            for block in flowchart:
                pred_block_list = []  # doesn't work.. always empty
                for pred_block in block.preds():
                    print pred_block.id
                    pred_block_list.append(pred_block.id)

                succ_block_list = []
                for succ_block in block.succs():
                    succ_block_list.append(succ_block.id)

                bb = BasicBlock(block.id, block.startEA, block.endEA, pred_block_list, succ_block_list)
                cPickle.dump(bb, fp_allfunc)
            
            fp_allfunc.close()
        
        elif func_target in func_name:
            bb_list = []

            flowchart = idaapi.FlowChart(idaapi.get_func(f))
            for block in flowchart:
                pred_block_list = []  # doesn't work.. always empty
                for pred_block in block.preds():
                    print pred_block.id
                    pred_block_list.append(pred_block.id)

                succ_block_list = []
                for succ_block in block.succs():
                    succ_block_list.append(succ_block.id)

                bb = BasicBlock(block.id, block.startEA, block.endEA, pred_block_list, succ_block_list)
                cPickle.dump(bb, fp_onefunc)

    if flag_allfunc == 0:
        fp_onefunc.close()
    print >> fp_log, "closing logger"
    fp_log.close()

    idc.Exit(0)
