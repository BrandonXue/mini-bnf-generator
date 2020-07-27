## Introduction
A simple Backus Naur Form (BNF) recursion recognizer that can fix left recursions and perform factoring.

## Usage
Rules should follow the template:
\<nonterminal lhs\> ::= \<nonterminals\> | literals

There can only be one nonterminal on the left hand side. The right hand side can
be a string of any number of terminal and nonterminal symbols. Whitespace can be
used to separate symbols, but will otherwise be ignored. Multiple alternatives
or options can be specified for a single nonterminal. These options should be
specified on the right hand side and separated by a |.

Terminal symbols are treated as literals, and must be defined at the top of
the source file. These literals should be comma separated, and may be defined
over multiple lines. At the end of the literals definition section, a single
line containing only
`***** END OF LITERAL DEFINITION *****`
must be present in the source file.

## Errors
Multiple LR separator (::=) on same line.
  - If one of the ::= was meant to be a nonterminal, enclose it in angled brackets.
  - If one of the ::= was meant to be a literal, enclose it in double quotes

LR separator (::=) must be second item in line.
  - The left-hand side of that production is either missing, or has too many tokens.

Left-hand side is not a nonterminal:...
  - The left-hand side must be a single nonterminal symbol. Check to make sure the
    left-hand side is properly enclosed in angled brackets.

File not found.
  - Check that the file is in the correct location, and check spelling.

No end of literal definition marker found...
  - Make sure to add ***** END OF LITERAL DEFINITION ***** after literal definitions.
  - See the usage information above.

Unrecognized symbol at the beginning of:...
  - A symbol that could not be interpreted as a nonterminal was found, but it was not
    defined as a literal.
  - Check to make sure the symbol was defined at the top of the file if it was meant
    to be a literal.
  - Check to make sure spelling is correct.
  - Since the program reformats the input file, the exact line from the source cannot
    be reproduced. But a reformatted equivalent will be displayed to help locate the
    error.
