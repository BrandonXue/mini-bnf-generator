# NOTE: The name of nonterminals cannot contain any special characters.
# Special characters are found in the SPECIAL set below.

import os
import re
from types import *

from reader import Reader

# This line must be included before the BNF rules in the source file.
# Everything before this line in the source file should be comma separated
# literals.
END_OF_LITERAL_MARKER = "***** END OF LITERAL DEFINITION *****"

# These are the terminals/literals that appear in the BNF on the right hand side.
# Since the code may generate an epsilon, this is defined by default.
# Since BNF uses ::= and | in its syntax, these are included in the set
# Other literals read from the file will be added to this set.
LITERALS = {"ε", "::=", "|"}

# Python's regex meta characters. These need to be escaped if they appear
# in the BNF and need to be added to a regex expression
SPECIAL = {
    "\\", "^", "$", ".", "|", "?", "*", "+", "(", ")", "[", "]", "{", "}"
}

# Looks for commas separated literals at the beginning of infile's stream.
# This function should be called before infile's cursor has been advanced.
# The literals will have their leading and trailing whitespace removed,
# and will be stored in the global set LITERALS
def fetch_literals(infile):
    line = infile.readline()
    while line.strip() != END_OF_LITERAL_MARKER:
        if line == "":
            print("\tError: No end of literal definition marker found.")
            print("\tAt the start of your file, please define all literals appearing in your BNF.")
            print("\tLiterals should be comma separated. Multiple lines OK.")
            print("\tMark the end of your literal definition with this line:")
            print(END_OF_LITERAL_MARKER + "\n")
            exit()
        literals = line.split(",")
        for literal in literals:
            lit_str = literal.strip()
            if lit_str != "":
                LITERALS.add(lit_str)
        line = infile.readline()

# Compresses all sequences of the space character into a single space
# e.g. t h   i        s --> t h i s
def compress_space(production):
    compressed = ""
    space = False
    for char in production:
        if space:
            if char != " ":
                space = False
                compressed += char
        else:
            if char == " ":
                space = True
            compressed += char
    return compressed

# Takes a compressed production and renames all nonterminals,
# replacing spaces in the name with underscores
# The spaces directly after < and directly before > are trimmed,
# e.g. < th is > --> <th_is>
def rename_nonterminals(production):
    renamed = ""
    # . matches any character, ? after the kleene makes it match minimal characters rather than maximal
    matches = re.finditer("<.*?>", production)
    prev = 0
    for match in matches:
        renamed += production[prev:match.start()] # append the part between the previous match and this match
        nt = match.group()[1:-1].strip()
        nt = "<" + nt + ">"
        nt = nt.replace(" ", "_")
        renamed += nt # append the renamed nonterminal
        prev = match.end() # set the new ending index of the last match
    renamed += production[prev:] # append the part after the last match
    return renamed

def tokenize_production(production, line_num):
    tokenized = []
    regex_buffer = "^" # Used to construct a regex expression to match with LITERALS
    token_buffer = "" # Used to construct the actual token that will be stored
    appending = False
    length = len(production)
    i = 0
    while i < length:
        # Eat whitespace as long as we're not in appending mode
        while (production[i] == " ") and (i < length) and (not appending):
            i += 1

        # If the incoming character is special, add a backslash to escape it in the regex
        # This part is only used to find literals
        if production[i] in SPECIAL:
            regex_buffer += "\\"
        regex_buffer += production[i]
        token_buffer += production[i]
        r = re.compile(regex_buffer)
        front_matches = list(filter(r.match, LITERALS))

        # If the incoming pattern resembles a nonterminal, set nt_token to that pattern
        # Else set nt_token to an empty string so it can still be used as an operand without issue
        # This part is only used to find potential nonterminals
        nt = re.match("^<.*?>", production[i:])
        nt_token = nt.group() if nt else ""

        # If we find a nonterminal-like pattern at the beginning, we aren't in appending mode yet,
        # and the pattern isn't a literal, then it ust be a nonterminal
        if nt and (nt_token not in LITERALS) and not appending:
            tokenized.append(nt_token)
            i += len(nt_token)
            # Reset buffers
            regex_buffer = "^"
            token_buffer = ""
        # Otherwise, if we find potential literal matches, go into appending mode
        elif len(front_matches) > 0:
            appending = True
            # If there's only one match, we know exactly which literal it is
            if len(front_matches) == 1:
                tokenized.append(front_matches[0])
                # Increment the remaining characters
                i += (len(front_matches[0]) - len(token_buffer)) + 1
                # Reset buffers and flags
                appending = False
                regex_buffer = "^"
                token_buffer = ""
            # If there are multiple matches then it's ambiguous so keep advancing cursor
            elif len(front_matches) > 1:
                i += 1
        # Otherwise, if there are no matches but we were previously in appending mode
        # that means the buffer without the last character must have been the valid literal
        elif appending:
            tokenized.append(token_buffer[:-1])
            # Reset buffers and flags
            appending = False
            regex_buffer = "^"
            token_buffer = ""
            # Don't advance the cursor because the last character should be part of the next token  
        # Otherwise if it's not a nonterminal or literal, notify error
        else:
            print(f"\tError: Line {line_num}: Unrecognized symbol at the beginning of:\n\t{production[i:]}\n")
            exit()

    # If the loop ended but the buffer wasn't empty
    if token_buffer != "":
        tokenized.append(token_buffer)
    
    return tokenized

# Takes a file in BNF form and refines it to a cleaner format,
# trimming unnecessary whitespace and replacing spaces in nonterminal
# names with underscores. The output will be a List of Lists of tokens.
def reformat_source(infile):
    tokenized = []
    line = infile.readline()
    line_num = infile.line_num()
    while line != "":
        line = line.strip() # remove the leading and trailing whitespace
        line = compress_space(line) # compress inner whitespace
                                    # (necessary for reformatting nonterminals)
        line = rename_nonterminals(line) # reformat the nonterminal names
        line_toks = tokenize_production(line, line_num)
        tokenized.append(line_toks)
        line = infile.readline()
        line_num = infile.line_num()
    
    return tokenized

# Takes a production with multiple options and returns a tuple.
# The first value in the tuple will be the lhs of the production.
# The second value in the tuple will be an array of rhs options.
# Each option itself will be an array of string tokens.
def split_rules(multirule, line_num):
    # Make sure the leftmost tokens is a nonterminal
    nt = re.match("^<.*?>$", multirule[0])
    if not nt:
        print(f"\tError: Line {line_num}: The first symbol was not a nonterminal.\n")
        exit()

    # Make sure there is only one left-right separator (::=)
    lr_sep = [i for i in range(len(multirule)) if multirule[i] == "::="]
    if len(lr_sep) > 1:
        print(f"\tError: Line {line_num}: Multiple LR separator (::=) on same line.\n")
        exit()

    # Make sure that the left-right separator is the second item in the list.
    if lr_sep[0] != 1:
        print(f"\tError: Line {line_num}: LR separator (::=) must be second item in line.\n")
        exit()

    # Make sure there is a rhs
    if len(multirule) < 3:
        print(f"\tError: Line {line_num}: Missing right-hand side.\n")
        exit()

    # Create lhs by copying the first token
    lhs = multirule[0]

    # Create the rhs by separating by | tokens
    opt_sep = [i for i in range(len(multirule)) if multirule[i] == "|"]
    rhs = []
    after_prev_sep = 2 # start collecting rhs tokens from the index after the sep
    for sep_index in opt_sep:
        # The option will begin one index after the previous separator, and end on
        # The index of the current separator
        option = multirule[after_prev_sep:sep_index]

        # If there was no symbol for this option, there is probably an extra |
        if len(option) == 0:
            print(f"\tError: Line {line_num}: Either an option is empty, or there is an extra |.\n")
            exit()

        rhs.append(option)
        # Update the index of the last separator (current sep index + 1)
        after_prev_sep = sep_index + 1

    # If the last separator was not the last element in the array,
    # Then there is one more option to be added
    if after_prev_sep < len(multirule):
        option = multirule[after_prev_sep:]
        rhs.append(option)

    return lhs, rhs

def fix_left_recursions(rules, nonterminals, rules_list):
    # iterate through each lhs in the rules_list
    for nonterm in rules_list:
        # Go through all of the options for this lhs and separate into lists of
        # left recursive and non-left recursive
        options = rules[nonterm]
        left_recursive = []
        non_left_recursive = []
        for option in options:
            # see if the first symbol is a nonterminal
            if option[0] in nonterminals:
                # if it is a nonterminal, see if it is left recursive
                if option[0] == nonterm:
                # If it is left recursive, add it to the left_recursive list
                    left_recursive.append(option)
                else:
                # If it isn't left recursive, add it to the non_left_recursive list
                    non_left_recursive.append(option)
            else:
                # Else if the first symbol is not a nonterminal, it can't be left recursive
                non_left_recursive.append(option)

        # If there are no left recursions, continue looping
        if len(left_recursive) == 0:
            continue

        new_options = []
        # Now that all the alternatives for this lhs are categorized, perform the fix by 
        # introducing a new prime nonterminal.
        # First we will add the prime nonterminal after the non-recursive alternatives
        for option in non_left_recursive:
            new_option = []
            new_option.extend(option) # first add the non-left-recursive symbols
            # Create the new prime symbol <this> --> <this_prime>
            new_option.append(nonterm[:-1] + "_prime>")
            new_options.append(new_option)
        # These will be the new rules for the nonterminal
        rules[nonterm] = new_options
        new_options = []
        # Now we will make the new rules for the prime nonterminal. This includes
        # a new rule for each left-recursive rule where the left recursion is removed
        # and the prime symbol is added to the end. An epsilon option should also be created.
        for option in left_recursive:
            del option[0] # remove the left recursive nonterminal from the front
            # Create the new prime symbol <this> --> <this_prime>
            option.append(nonterm[:-1] + "_prime>")
            new_options.append(option)
        new_options.append(["ε"])
        # These will be the rules for the prime nonterminal
        rules[nonterm[:-1] + "_prime>"] = new_options
    return rules
         

# Go through the list of all rules
# For each rule, for each option, if the first symbol is a nonterminal with a lower index
# Then perform substitutions on that
def perform_substitutions(rules, nonterminals, rules_list):
    while True:
        changed = False
        # iterate through each lhs in the rules_list
        for nonterm in rules_list:
            new_options = []
            # For each lhs, iterate through its rhs alternatives and perform single depth
            # substitutions as necessary, adding them to new_options. After all substitutions
            # have been made, set the rhs of the current lhs to new_options
            options = rules[nonterm]
            for option in options:
                # see if the first symbol is a nonterminal
                if option[0] in nonterminals:
                    # if it is a nonterminal, see if it is higher on the list compared to lhs
                    if nonterminals[option[0]] < nonterminals[nonterm]:
                        # if it is, then we need to substitute
                        changed = True
                        nt = option[0] # store the nonterminal symbol in question in a temp
                        del option[0] # truncate the nonterminal from the option
                        # find all the alternatives to be substituted in the symbol's place
                        # for each alternative to be substituted, create a new array, put the replacement in
                        # the put the rest of the old symbol string in, now this new option array should be
                        # added to the new_options for the lhs that we are fixing
                        for recursive_rule in rules[nt]:
                            new_option = []
                            new_option.extend(recursive_rule)
                            new_option.extend(option)
                            new_options.append(new_option)
                    # Else if it is not higher on the list than lhs, no replacements needed.
                    # Just put the old option directly into new_options
                    else:
                        new_options.append(option)
                # Else if the first symbol is not a nonterminal, no replacements needed.
                # Just put the old option directly into new_options
                else:
                    new_options.append(option)
            # now that all the new options for the current lhs have been created, set them into
            # the rule dict
            rules[nonterm] = new_options
        # Keep repeating this process as long as no changes are being made
        if not changed:
            break

    return rules
        
# Takes a list of rules and attempts to resolve any direct and indirect
# left recursions, creating new nonterminal symbols in the process.
# Each rule itself should be a list of tokens. There should be a nonterminal
# as the first token, followed by the left-right separator (::=). The right
# side may use option separator tokens (|) to specify multiple alternatives.
def resolve(tok_prods, line_num):
    rules_list = [] # Make an array of lhs nonterminals for going through rules in order
    rules = {} # Make a dictionary for each rule's lhs to an array of rhs alternatives.
    # Each alternative is a tokenized array as well, so the value of the dict
    # is an array of arrays.
    nonterminals = {} # Make a dictionary for looking up a nonterminal's index

    nt_index = 0
    for prod in tok_prods:
        line_num += 1
        # Split a rule from one list into a tuple of the left and right hand sides.
        # The lhs will be a string, and the rhs will be a list of lists, where each
        # of those inner lists represents an option for the production. 
        lhs, rhs = split_rules(prod, line_num)

        # The left hand side of the rule becomes the key to the dictionary
        # The right hand side will be the value
        rules[lhs] = rhs

        # in the same loop, create the nonterminal search dict and the rules list
        nts = re.match("^<.*?>", lhs)
        if not nts:
            print(f"\tError: Line {line_num}: Left-hand side is not a nonterminal:", lhs + "\n")
            exit()
        if nts.group() not in nonterminals:
            rules_list.append(nts.group())
            nonterminals[nts.group()] = nt_index
            nt_index += 1

    rules = fix_left_recursions(rules, nonterminals, rules_list)
    rules = perform_substitutions(rules, nonterminals, rules_list)
    rules = fix_left_recursions(rules, nonterminals, rules_list)

    return rules, nonterminals, rules_list


# Takes one rule with multiple alternatives and factors it. This function will only
# factor the first common prefix it encounters, and will maximize the length of
# the common prefix it factors out.
# IMPORTANT: The input for options must be a list of lists, not a list of tokens!
def factor_one(lhs, options, rules):
    # If there is only one option, then there cannot be a redundancy, so no
    # refactoring is needed
    if len(options) == 1:
        return False, []

    # Use a nested loop to compare each option with each other option
    for i in range(len(options)):
        # Keep an index of options which have a matching beginning with the current option
        matched_options = [i]
        unchanged_options = []
        for j in range(i+1, len(options)):
            if options[i][0] != "ε" and options[i][0] == options[j][0]:
                matched_options.append(j)
            else:
                unchanged_options.append(j)

        # If we found matches then these are the ones we will factor.
        num_options = len(matched_options)
        if num_options > 1:
            # try to match the next item of other options with that of the first option in
            # matched_options
            common_len = 1
            done = False
            while True:
                if common_len == len(options[matched_options[0]]):
                    break
                next_item = options[matched_options[0]][common_len]
                for op_index in matched_options:
                    # If we've reached the maximum length for one of the options, stop
                    if common_len == len(options[op_index]):
                        done = True
                        break
                    # If we've found a part where the options no longer match, stop
                    if options[op_index][common_len] != next_item:
                        done = True
                        break
                # If we should stop, don't increment common_len, and just exit the loop
                if done:
                    break
                # Otherwise, increment common_len and keep trying to increase it
                else:
                    common_len += 1
            
            # Now we have a list of indices for options to factor, and the length to factor
            # Start by creating a new nonterminal name

            num = 2
            lhs_renamed = lhs[:-1] # Remove the closing angle bracket of the nonterminal
            lhs_renamed += "_split>" # Create a new name for the nonterminal we append
            while lhs_renamed in rules:
                lhs_renamed = lhs[:-1] + "_split" + str(num) + ">"
                num += 1

            # Now creat the new rules
            new_rules = []

            # Start with the current rule
            # Start by factoring out the common prefix
            new_rule = []
            new_option = []
            new_option.extend(options[matched_options[0]][:common_len])
            new_option.append(lhs_renamed)
            new_rule.append(new_option)
            # Now add the unchanged options
            num_unchanged = len(unchanged_options)
            for j in range(num_unchanged):
                new_rule.append(options[unchanged_options[j]])

            common_prefix_rule = (lhs, new_rule)
            new_rules.append(common_prefix_rule)

            # Now create the rule for the new nonterminal, add all the options
            new_rule = []
            for j in range(num_options):
                new_option = []
                curr_option = options[matched_options[j]][common_len:]
                # If one of the options is empty, make it epsilon
                if len(curr_option) == 0:
                    new_option.append("ε")
                else:
                    new_option.extend(curr_option)
                new_rule.append(new_option)
            split_rule = (lhs_renamed, new_rule)
            new_rules.append(split_rule)

            return True, new_rules

    # If we never end up finding matching prefixes, return no changes
    return False, []

# Takes a rule set dictionary, where the key is the lhs of a rule, and the value
# is the rhs of a rule. The lhs is a string, and the rhs is an array of options.
# Each option is an array of strings.
# These rules will be factored, and the new rule set will be returned.
def factor(rules):
    # Keep performing this factorization process until no changes are made
    while True:
        pending_changes = []
        pending_deletions = []

        changed = False
        # Go through each rule in the rules
        for lhs in rules:
            # Try to factor this lhs and its options.
            # one_changed will indicate whether or not any factoring was performed
            # new_rules will contain an array of tuples, where the first element is the
            # nonterminal and the second element is an array of options for that nonterminal.
            # Each option is an array of string tokens
            one_changed, new_rules = factor_one(lhs, rules[lhs], rules)

            # If this rule changed, then push it to the pending changes, and push
            # the old rule's lhs to pending deletions
            if one_changed:
                changed = True
                pending_changes.extend(new_rules)
                pending_deletions.append(lhs)

        if changed:
            # Delete the old rules that were modified
            for to_del in pending_deletions:
                rules.pop(to_del)

            # Add the new rules that have been factored
            for rule in pending_changes:
                rules[rule[0]] = rule[1]

            # Clear the pending buffers
            pending_changes = []
            pending_deletions = []
        else:
            break

    return rules # Return the modified rule set


def find_first_set(lhs, rules, first_sets):
    # See if the first_set already exists. If it does, return that
    if lhs in first_sets:
        return first_sets[lhs]
    # If it doesn't, create a set for all options
    first_set = set()
    
    # For each option of the given nonterminal
    options = rules[lhs]
    for option in options:
        # create a set for this option
        option_first_set = set()
        num_tokens = len(option)
        for i in range(num_tokens):
            token = option[i]
            # If the first item is a nonterminal with a production
            if token in rules:
                # Check if it's a self-reference. If it's not self-referencing, make a recursive call.
                if token != lhs:
                    option_first_set = option_first_set.union(find_first_set(token, rules, first_sets))
            # Else if the first item is a literal (including epsilon), add it to set
            elif token in LITERALS:
                option_first_set.add(token)
            # Else if not a literal or nonterminal, something went wrong
            else:
                print("\tError: Something went wrong during find_first_set():")
                print("\t" + lhs + " ::=", option, "\n")
                exit()
            # If epsilon is in the set and there are more options left
            # remove epsilon from the set and let the loop continue to next item
            if i < num_tokens-1 and "ε" in option_first_set:
                option_first_set.remove("ε")
                option_first_set = option_first_set.union(option_first_set)
            else:
                break
        first_set = first_set.union(option_first_set)
    return first_set


def create_first_sets(rules):
    first_sets = {}
    for rule in rules:
        first_sets[rule] = find_first_set(rule, rules, first_sets)
    return first_sets

# Outputs a list of (lists of strings) into a file
#
# Each list of strings should represent a rule, with lhs and rhs separated by
# the separator ::= and options separated by a |
#
# For the output, everything will be space separated, with a new line after each line.
def lls_to_file(tokenized, fname, ext, name_mod=""):
    outfile = open(fname + name_mod + ext, "w")
    # Loop through the array of arrays
    num_lines = len(tokenized)
    for i in range(num_lines):
        # Loop through the array of tokens
        num_tokens = len(tokenized[i])
        for j in range(num_tokens):
            # Write the token to file
            outfile.write(tokenized[i][j])
            # Add a space if there's another token coming in this line
            if j < num_tokens-1:
                outfile.write(" ")
        # Add a newline character if there's another line coming after this line
        if i < num_lines-1:
            outfile.write("\n")
    outfile.close()

# Output to a file a dictionary where the key is a nonterminal and
# the value is the productions for that nonterminal.
# The value will be an list of lists. Each inner list represents an
# alternative, and should be a list of string tokens.
def nonterm_prod_dict_to_file(rules, fname, ext, name_mod=""):
    outfile = open(fname + name_mod + ext, "w")
    first = True
    for lhs in rules:
        # Print newline before all but the first line
        if first:
            first = False
        else:
            outfile.write("\n")

        # Print the lhs and then the left-right separator
        outfile.write(lhs + " ::= ")

        # Iterate over the rhs options
        rhs = rules[lhs]
        num_options = len(rhs)
        for i in range(num_options):
            # Print all tokens for the option
            option = rhs[i]
            num_symbols = len(option)
            for j in range(num_symbols):
                outfile.write(option[j])
                # Separate the tokens with a space
                if j < num_symbols - 1:
                    outfile.write(" ")
            # Separate the options with a vertical bar
            if i < num_options - 1:
                outfile.write(" | ")
    outfile.close()

# Output to a file a dictionary where the key is a nonterminal and
# the value is the first set for that nonterminal.
# The value will be an list of string. Each string represents a
# terminal symbol or an epsilon.
def dict_first_set_to_file(first_sets, fname, ext, name_mod=""):
    outfile = open(fname + name_mod + ext, "w")
    first_line = True
    for nonterm in first_sets:
        # Print newline before all but the first line
        if first_line:
            first_line = False
        else:
            outfile.write("\n")

        # Print First(nonterminal) = { 
        outfile.write("First(" + nonterm + ") = {")

        # Iterate over the first set symbols and write them, comma separated
        first = first_sets[nonterm]
        first_sym = True
        for symbol in first:
            if first_sym:
                first_sym = False
            else:
                outfile.write(", ")
            outfile.write(symbol)
        
        # Write the closing brace and newline
        outfile.write("}")
    outfile.close()

def main():
    # Get the user input for the file name, separate the extension from the name
    fname = input("Input the source file name: ")
    ext_index = fname.rfind(".")
    ext = fname[ext_index:]
    fname = fname[:ext_index]

    # Make sure the file actually exists
    if not os.path.isfile(fname + ext):
        print("\tError: File not found.\n")
        exit()

    # See if the directory exists
    if os.path.isdir(fname):
        choice = input("Directory exists, over-write? (y)es / (n)o\n")
        if choice.lower() not in {"yes", "y", "ye"}:
            exit()
    else:
        os.mkdir(fname)

    # Open the file.
    # Find all the literals used in this BNF file as defined by the user
    src_file = Reader(fname + ext, "r")
    fetch_literals(src_file)
    line_num = src_file.line_num()
    tokenized = reformat_source(src_file) # Reformat the source and output
    src_file.close() # Close the file

    # Change the output path
    fname = fname + "/" + fname

    # Output the reformatted source into a file, and notify user of completion
    lls_to_file(tokenized, fname, ext, "-reformatted")
    print("SUCCESS: Reformatted output: ./", fname + "-reformatted" + ext)

    # Take the reformatted source and resolve left recursions
    rules, nonterminals, rules_list = resolve(tokenized, line_num)
    del tokenized # Delete the non-resolved form to free memory since it's no longer used

    # Output the resolved source into a file, and notify user of completion
    nonterm_prod_dict_to_file(rules, fname, ext, "-resolved")
    print("SUCCESS: Resolved recursions output: ./", fname + "-resolved" + ext)

    # Factor the rules
    rules = factor(rules)
    
    # Output the factored source into a file, and notify user of completion
    nonterm_prod_dict_to_file(rules, fname, ext, "-factored")
    print("SUCCESS: Factored output: ./", fname + "-factored" + ext)

    # Create the first sets
    first_sets = create_first_sets(rules)

    # Output first sets into a file, and notify user of completion
    dict_first_set_to_file(first_sets, fname, ext, "-firsts")
    print("SUCCESS: Created first sets: ./", fname + "-factored" + ext)
    

if __name__ == "__main__":
    main()