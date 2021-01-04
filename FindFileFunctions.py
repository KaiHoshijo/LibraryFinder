#Finds all functions that are in the script 
#@author Kai Hoshijo
#@category Library_finder
#@keybinding 
#@menupath 
#@toolbar 

#library_function = askFile("FILE", "Choose file:")

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from difflib import SequenceMatcher
import re
import math
from collections import Counter
import LibraryFinder

def getFileFunctions(file_path):
    # gets all the functions given in a file
    file_functions = {}

    # getting the file
    with open(file_path, "r") as file:
        # finding functions
        for line in file:
            commands = line.split(" ")
            function = ""
            function_name = ""
            # check if words end with () and that the next index has {\n
            if (len(commands) >= 3 and "{\n" in commands[-1]):
                    arg_index = 0
                    for command in commands: 
                        if ("(" in command and command[0] != "("):
                            arg_index = commands.index(command)
                            function_name = command[:command.index("(")]
                            break
                    if (commands[arg_index - 1] not in ["class", "{\n"] and len(commands[arg_index - 1]) > 0):
                        function += line
                        for line2 in file:
                            # to find the end of the function find }\n
                            commands2 = line2.split(" ")
                            function += line2
                            if (len(commands2) == 1 and commands2[0] == "}\n"):
                                break 
                        file_functions[function_name] = function
    print(len(file_functions))
    return file_functions

file_functions = getFileFunctions("C:/Users/kaiho/ghidra_scripts/stl.cpp")
# file_functions = getFileFunctions("C:/Users/kaiho/source/repos/Test Solution/Test/hello.cpp")

# getting a list of all the ghidra functions
ghidra_functions = []
ghidra_names = []

# initalizing the decompiler
program = getCurrentProgram()
ifc = DecompInterface()
ifc.openProgram(program)

# getting each decompiled function
func_iter = program.getListing().getFunctions(True)

while (func_iter.hasNext()):
    func = func_iter.next()
    name = func.getName()

    if ('.' == name[0]): continue

    ghidra_names.append(name)

    results = ifc.decompileFunction(func, 0, monitor)
    c_func = results.getDecompiledFunction().getC()
    while ("\0" in c_func): c_func = c_func[:c_func.index('\0')] + '0' + c_func[c_func('\0') + 1:]
    ghidra_functions.append(c_func)

# closing the decompiler
ifc.closeProgram()

for file_func in file_functions:
    file_function = file_functions[file_func]
    potential_functions = {}
    print(file_func)

    for index in range(len(ghidra_functions)):
        ghidra_func = ghidra_functions[index]
        ghidra_name = ghidra_names[index]

        finder = LibraryFinder.LibraryFinder(file_function, ghidra_func)

        ratio = finder.getSimilarity()

        if (finder.isSimilarFunctions()):
            potential_functions[ratio] = [ghidra_func, ghidra_name] 
    if (len(potential_functions.keys()) > 0):
        max_ratio = max(potential_functions.keys())
        final_function = potential_functions[max_ratio]

        print("{}% with {}".format(max_ratio, file_func))
        print(len(file_functions[file_func]), len(final_function[0]))
        print(final_function[1])

        for ratio in potential_functions:
            if (ratio == max_ratio): continue
            other_function = potential_functions[ratio]
            
            finder_2 = LibraryFinder.LibraryFinder(final_function[0], other_function[0])

            similarity = finder_2.getSimilarity()
            similar_functions = finder_2.isSimilarFunctions(False)

            if (similarity > .75):
                print(other_function[1])







