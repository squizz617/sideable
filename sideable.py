"""
Retrieve basic blocks and its metadata.
http://magiclantern.wikia.com/wiki/IDAPython/intro
https://www.hex-rays.com/products/ida/support/idapython_docs/
"""

import hashlib
import cPickle
import inspect
import idautils
import idaapi
import idc

# bb_table = {}


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

    # def __init__(self, bb_id, startEA, endEA, pred_blocks, succ_blocks):
    def __init__(self, bb_id, startEA, endEA, succ_blocks):
        self.bid = bb_id
        self.start_ea = startEA
        self.end_ea = endEA
        # self.pred_blocks = pred_blocks
        self.succ_blocks = succ_blocks

        # bb_table[self.bid] = "%08X" % (self.start_ea)
        for head in idautils.Heads(self.start_ea, self.end_ea):
            idc.OpHex(head, -1) # print everything in Hex
            addr = "%08X" % head
            mnem = idc.GetMnem(head)
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

    fp_log = open("logger", "w")
    func_target = "parse_datetime"


    fp = open("log-"+idaapi.get_root_filename(), "wb")
    # if len(idc.ARGV) == 0: # in case we run this script in IDA Pro
    #     fp = open("log-"+idaapi.get_root_filename(), "wb")
    # else: # in case this script is called from run.py with arguments
    #     fp = open("log-"+idc.ARGV[1], "wb")

    funcs = idautils.Functions()
    for f in funcs:
        func_name = idc.GetFunctionName(f)
        if func_name == func_target:
            # print hex(f), GetFunctionName(f)
            # fp.write(func_name + "\n")
            # print >> fp, func_name

            # for (startea, endea) in idautils.Chunks(f):
            #     E = list(idautils.FuncItems(f))
            #     for e in E:
            #         fp.write("%X" % e)
            #         fp.write(" ")
            #         fp.write(GetDisasm(e))
            #         fp.write("\n")
            bb_list = []

            flowchart = idaapi.FlowChart(idaapi.get_func(f))
            for block in flowchart:
                succ_block_list = []
                for succ_block in block.succs():
                    succ_block_list.append(succ_block.id)

                # pred_block_list = []  # doesn't work.. always empty
                # for pred_block in block.preds():
                #     pred_block_list.append(pred_block.id)

                bb = BasicBlock(block.id, block.startEA, block.endEA, succ_block_list)
                # bb_list.append(bb)
                # split_block(block.startEA, block.endEA)
                # print >> fp, "%x - %x [%d]:" % (block.startEA, block.endEA, block.id)
                # for head in idautils.Heads(block.startEA, block.endEA):
                #     print >> fp, "%08X\t" % head + idc.GetDisasm(head)
                # block_instructions(block.startEA, block.endEA)
                # bb.get_instructions()

                cPickle.dump(bb, fp)

                # for succ_block in block.succs():
                #     print >> fp, "S: %x - %x [%d]:" % (succ_block.startEA, succ_block.endEA, succ_block.id)
                #     # block_instructions(succ_block.startEA, succ_block.endEA)

                # for pred_block in block.preds():
                #     print >> fp, "P: %x - %x [%d]:" % (pred_block.startEA, pred_block.endEA, pred_block.id)
                #     # block_instructions(pred_block.startEA, pred_block.endEA)

                # fp.write(GetDisasm(block) + "\n")

            # print >> fp, bb_list

    # # print >> fp, bb_table
    # bb_hash_list = []
    # bb_hash_list_str = ""
    # for bb in bb_list:
    #     # bb_hash_list.append(bb.inst_hash)
    #     bb_hash_list_str += bb.inst_hash + " "

    # print >> fp, bb_hash_list_str


    fp.close()
    fp_log.close()

    idc.Exit(0)
