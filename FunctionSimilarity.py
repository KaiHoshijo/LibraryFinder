from difflib import SequenceMatcher
import re
import math
from collections import Counter

def getRidOfComments(function):
    '''
    Gets rid of all the comments in the user function

        Parameters:
            function(string): the function to remove comments from 

        Returns:
            function (string): the function without comments in it
    '''
    # gets rid of the one line comments
    no_oneline_comments = re.sub(r'//.*', r'', function)
    # gets rid of the multi line comments and the white space that preceeds it 
    function = re.sub(r'(?s)[^\S\r\n]*\/\*.*?\*\/', r'', no_oneline_comments)

    return function

class LibraryFinder:
    def __init__(self, function_1, function_2):
        '''
            Determines if two functions are similar through parameters, keywords, function calls, and constants

            Parameters:

                function_1 (string): The first function to be examined (normally the file function)

                function_2 (string): The second function to be examined (normally the ghidra function)
        '''  
        self.function_1 = function_1
        self.function_2 = function_2 

        self.function_1 = getRidOfComments(self.function_1).strip()
        self.function_2 = getRidOfComments(self.function_2).strip()

        self.func1_parameters = self.getParameters(self.function_1)
        self.func2_parameters = self.getParameters(self.function_2)

        self.func1_keywords_and_func_calls = self.getKeyWordsAndFunctionCalls(self.function_1)
        self.func2_keywords_and_func_calls = self.getKeyWordsAndFunctionCalls(self.function_2)
        
        self.func2_calls = [[value, '(' in value] for value in self.func2_keywords_and_func_calls]
        self.func1_calls = [[value, '(' in value] for value in self.func1_keywords_and_func_calls] 

        self.func1_keywords = [value for value, func_call in self.func1_calls if not func_call]
        self.func2_keywords = [value for value, func_call in self.func2_calls if not func_call]
    
    def get_function_1_information(self):
        return [self.function1, self.func1_parameters, self.func1_keywords_and_func_calls]

    def get_function_2_information(self):
        return [self.function2, self.func2_parameters, self.func2_keywords_and_func_calls]

    def getParameters(self, function):
        ''' 
        Returns the parameter names of the function

            Parameters:
                function (string): The function as a string
            
            Returns:
                The amount of parameters for a function 
        '''
        function_declaration = function[:function.index("{")]
        function_body = function[function.index("{")+1:]
        parameters = re.findall(r'(?s)\(.*\)', function_declaration) 
        parameter_values = {}
        # gets the parameters if there are 
        if (len(parameters) > 0 and parameters[0][1:-1] != ''):
            parameters = re.sub(r'<.*>', r'', parameters[0][1:-1])
            parameter_names = re.split(r',+', parameters)
            parameter_names = [parameter.split(" ")[-1].replace("*","") for parameter in parameter_names]
            if (parameter_names[0] != 'void'):
                parameter_uses = [function_body.count(parameter_name) for parameter_name in parameter_names]
                parameter_values = {parameter_names[i]: parameter_uses[i] for i in range(len(parameter_names))}
        return parameter_values

    def getKeyWordsAndFunctionCalls(self, function):
        ''' 
        Return all c key words found and function calls within the funciton

            Parameters: 
                function (string): The function as a string
        '''
        function = function[function.index('{'):]
        # print(function)
        total_calls = re.findall(r'\bbreak\b|\bcontinue\b|\belse\b|\bfor\b|\bswitch\b|\bcase\b|\bdefault\b|\bgoto\b|\bdo\b|\bif\b|\bwhile\b|[a-zA-Z1-9<>_]+\(.*?\)', function)
        # print(total_calls)

        total_calls.append('d')
        total_calls.append('d')
        for index in range(len(total_calls)-3, -1, -1):
            keyword = total_calls[index]
            if (keyword == 'while' and total_calls[index+1] != 'if' and total_calls[index+2] != 'break'):
                total_calls.insert(index+1, 'if')
                total_calls.insert(index+2, 'break')
        total_calls.pop()
        total_calls.pop()

        # print(total_calls)

        # getting rid of some key words that don't show in ghidra functions
        while ('for' in total_calls):
            index = total_calls.index('for')
            total_calls.remove('for')
            total_calls.insert(index, 'while')
            total_calls.insert(index + 1, 'if')
            total_calls.insert(index + 2, 'break')

        # print(total_calls)

        return total_calls

    def getSimilarity(self):
        WORD = re.compile(r"\w+")
        
        function_1_text = WORD.findall(self.function_1)
        function_1_vector = Counter(function_1_text)

        function_2_text = WORD.findall(self.function_2)
        function_2_vector = Counter(function_2_text)

        intersection = set(function_1_vector.keys()) & set(function_2_vector.keys())
        numerator = sum([function_1_vector[x] * function_2_vector[x] for x in intersection])

        sum1 = sum([function_1_vector[x] ** 2 for x in list(function_1_vector.keys())])
        sum2 = sum([function_2_vector[x] ** 2 for x in list(function_2_vector.keys())])
        denominator = math.sqrt(sum1) * math.sqrt(sum2)

        if not denominator:
            ratio = 0.0
        else:
            ratio =  float(numerator) / denominator

        sequence = SequenceMatcher(None, self.function_1, self.function_2)
        ratio += sequence.ratio()

        return ratio

    def isSimilarParameters(self):
        '''
        Determines if the parameters are similar
        Compares use cases and number of parameters

            Returns:
                isSimilar (bool): returns true if the two functions use parameters in a similar way
        '''

        func1_sum = sum(self.func1_parameters.values())
        func2_sum = sum(self.func2_parameters.values())
        if (func1_sum <= 1):
            func1_sum = 2
        else:
            func1_sum = math.ceil(func1_sum * 5 / 3.0)

        return func2_sum <= func1_sum
    
    def isSimilarKeywords(self):
        '''
        Determines if the keyword structure is similar through matching the order and amount of each keyword used

            Returns:
                isSimilar (boolean): If the use of keywords is similar
        '''

        # compares if the keywords are used in the same order

        func1_len = len(self.func1_keywords)
        func2_len = len(self.func2_keywords)

        shorter_len = func1_len if func1_len < func2_len else func2_len 
        longer_len = func2_len if func2_len > func1_len else func1_len

        for index in range(shorter_len):
            func2_keyword = self.func2_keywords[index]
            func1_keyword = self.func1_keywords[index]
            if (func2_keyword != func1_keyword or self.func2_keywords.count(func1_keyword) < self.func1_keywords.count(func1_keyword)):
                return False
        for index in range(longer_len - shorter_len):
            func2_keyword = self.func2_keywords[index]
            # print(func2_keyword)
            if (func2_keyword in ['if', 'else', 'switch'] and self.func2_keywords.count(func2_keyword) > 0 and self.func1_keywords.count(func2_keyword) == 0):
                if (index != longer_len-1):
                    if (self.func2_keywords[index+1] == 'break' and self.func2_keywords[index-1] == 'while'): continue
                return False
        return True

    def isSimilarFunctionCalls(self):
        '''
        Determines if the function calls are used in a similar manner
        Called only after similar parameters is true

            Returns:
                isSimilar (boolean): true if the two functions have similar function calls
        '''

        # print(func2_calls)
        func2_final_calls = self.func2_calls
        if (self.func2_calls[0][0] == 'while' and len(self.func2_calls) > 3 and self.func1_calls[0][0] != 'while'):
            func2_final_calls = self.func2_calls[3:]

        for index in range(len(self.func1_calls)):
            func2_call = func2_final_calls[index]
            func1_call = self.func1_calls[index]
            if (func2_call[1] != func1_call[1]):
                keywords = sum([1 for value in func2_final_calls if value[1] != True]) >= sum([1 for value in self.func1_calls if value[1] != True])
                if (len(self.func2_calls) != len(func2_final_calls)):
                    keywords = keywords or sum([1 for value in self.func2_calls if value[1] != True]) >= sum([1 for value in self.func1_calls if value[1] != True])
                function_calls = sum([1 for value in func2_final_calls if value[1] == True]) >= sum([1 for value in self.func1_calls if value[1] == True])
                return keywords and function_calls

        return True



    def isSimilarFunctions(self, check_calls=True):
        '''
        Checks if the two functions are truly similar

            Parameters:
                check_calls (boolean): A boolean to determine if the function should check function calls

            Returns:
                isSimilar (boolean): returns true if the function is similar or returns false if the function is not simiar
        '''

        if ((len(self.function_2) > len(self.function_1) and len(self.func2_calls) >= len(self.func1_calls) and len(self.func2_keywords) >= len(self.func1_keywords)) or not check_calls):
            # print("TEST 2")
            if (self.isSimilarParameters()):
                # print("TEST 3")
                if(self.isSimilarKeywords()): 
                    # print("TEST 4") 
                    if (check_calls):
                        return self.isSimilarFunctionCalls()
                    # print("TEST 5")
                    return abs(len(self.func2_keywords_and_func_calls) - len(self.func1_keywords_and_func_calls)) <= 3
        return False



