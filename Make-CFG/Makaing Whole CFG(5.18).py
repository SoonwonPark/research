import idc
import idautils
import idaapi
from graphviz import Digraph
import sark
import pygraphviz as pgv



class Analysis:

    def __init__(self):
        self.function_dic = {}
        self.api_dic = {}
        self.entryaddress = 0
        self.entryname = ""
        self.mygraph = Digraph(filename='basicblock.gv', format="pdf")
        self.nodelist = []
        self.nodeforpath = []
        self.targetfunction = []

    def find_entrypoint(self):

        ordinal = 0
        number_entry = idaapi.get_entry_qty()
        print("Number of Entry point: " + str(number_entry))

        ordinal = idaapi.get_entry_ordinal(number_entry - 1)
        print("Entry ordinals: " + str(ordinal))

        self.entryaddress = idaapi.get_entry(ordinal)
        self.entryname = idaapi.get_entry_name(ordinal)
        print("Entry : " + self.entryname + " " + str(self.entryaddress))

    def make_func_dic(self):

        for func in idautils.Functions():
            addr = func
            name = idc.GetFunctionName(func)
            self.function_dic[addr] = name

        print("--- Number of Function:" + str(len(self.function_dic)))

    def make_api_dic(self):

        def get_api_list(ea, name, ord):
            self.api_dic[ea] = name
            # print ea, name
            return True

        import_number = idaapi.get_import_module_qty()
        print("--- Number of Import Modules:" + str(import_number))

        for i in range(0, import_number):
            idaapi.enum_import_names(i, get_api_list)

        print("--- Number of APIs:" + str(len(self.api_dic)))


    def make_flowchart(self, func):
        for key, value in self.function_dic.iteritems():
            # if value == "StartAddress":
            if value == func:
                function = idaapi.get_func(key)
                flowchart = idaapi.FlowChart(function)
                self.make_path(key)

            for (startea, endea) in Chunks(key):
                for head in Heads(startea, endea):
                    headValue = GetDisasm(head)
                    if headValue.startswith("call"):
                        splited = headValue.split()
                        tomake = splited[1]
                        if tomake not in self.targetfunction:
                            self.targetfunction.append(tomake)


    def make_flowchart_whole(self):
        for each in self.targetfunction:
            self.make_flowchart(each)


    def make_path(self, key):
        function = idaapi.get_func(key)
        flowchart = idaapi.FlowChart(function)
        functionname = idc.GetFunctionName(key)
        # graph = Digraph(name =functionname, filename='basicblock.gv', format="pdf")
        with self.mygraph.subgraph(name=functionname) as sub:
            title = idc.GetFunctionName(key)
            bblist = []
            bblistlength = 0

            for basicblock in flowchart:
                bblist.append(basicblock)

            bblistlength = len(bblist)

            if bblistlength == 1:
                # graph.edge(title, title)
                first = self.make_node(basicblock)
                sub.edge(title, first, color="blue")

            else:
            # iterate basicblocks in flowchart
                for basicblock in flowchart:
                    #  the first basicblock
                    if basicblock.id == 0:
                        for succ in basicblock.succs():
                            first = self.make_node(basicblock)
                            second = self.make_node(succ)
                            # function call in
                            sub.edge(title, str(second), color='blue')
                    #  last basicblock
                    elif basicblock.id == basicblock._fc.size-1:
                        first = self.make_node(basicblock)
                        second = self.make_node(succ)

                        splited = second.split()
                        splited_size = len(splited)

                        # function call out(return)
                        if splited[splited_size-2].startswith("retn"):
                            sub.edge(str(second), title, color="red")

                    else:
                        for succ in basicblock.succs():
                            first = self.make_node(basicblock)
                            second = self.make_node(succ)
                            sub.edge(str(first), str(second))



    def make_node(self, basicblock):
        startaddr = basicblock.startEA
        endaddr = basicblock.endEA
        message = ""

        for head in Heads(startaddr, endaddr):
            headValue = GetDisasm(head)
            if headValue.startswith("call"):
                message = message + headValue + "\n"
            if headValue.startswith("retn"):
                message = message + headValue + "\n"
            if headValue.startswith("j"):
                message = message + headValue + "\n"

            if "ds" in message:
                if ":" in message:
                    message = message.replace(":", " ")

        if len(message) > 0:
            return message
        else:
            return basicblock.id


    def save_graph(self):
        self.mygraph.save(filename="revised-CFG.dot", directory=None)


    def link_subgraph(self):
        newgraph = pgv.AGraph("revised-CFG.dot")
        subgraph_name = []
        for key, value in self.function_dic.iteritems():
            for each in newgraph.subgraphs():
                if each.get_name() == value:
                    print(each.get_name())
                    subgraph_name.append(each.get_name())

        for each in newgraph.subgraphs():
            for node in each.nodes():
                node_string = str(node)
                for name in subgraph_name:
                    if name in node_string:
                        if name != node_string:
                            newgraph.add_edge(node_string, name, color="purple")
                        if "ds" in node_string:
                            if "imp" in node_string:
                                if name in node_string:
                                    newgraph.delete_edge(node_string, name)

        newgraph.write('CFG.dot')
        





def main():
    myAnalysis = Analysis()
    myAnalysis.find_entrypoint()
    myAnalysis.make_func_dic()
    myAnalysis.make_api_dic()
    myAnalysis.make_flowchart("StartAddress")
    myAnalysis.make_flowchart_whole()
    myAnalysis.save_graph()
    myAnalysis.link_subgraph()



if __name__ == '__main__':
    main()



