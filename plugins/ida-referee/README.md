# Referee

This is a python port of James Koppel's Referee IDA plugin with some updates:  
https://github.com/jkoppel/project-ironfist/tree/master/tools/Revitalize/Referee


## What it is

It's much easier to reverse-engineer a structure when you can find every place its members are used. If you wish to reengineer the binary and modify a structure, finding every use is essential. Referee makes both of these tasks easier by marking accesses of structures in decompiled functions.

## Requirements

 * IDA 6.2 or higher
 * Hex-Rays Decompiler 1.6 or higher

## Installation

Copy the plugin into the IDA "plugins" folder

## Usage

Referee will automatically run whenever a function is decompiled. It is recommended that you decompile the entire binary for maximum information. You can see the cross-references that Referee adds by opening a structure in the Structures window, highlighting a field of a structure, and pressing "X."

Referee does not do type inference; you will still need to give types to your functions for it to find structure uses.

## Notes

 * If you annotate a function to remove a struct-member usage, decompiling the function again will remove the corresponding xrefs.
 * Referee only tracks accesses to structure members, not pointer-passing.
 * Configuring debug output: `logging.getLogger('referee').setLevel(logging.DEBUG)`

## Related
- http://reverseengineering.stackexchange.com/questions/2139/is-it-possible-to-create-data-xrefs-manually
