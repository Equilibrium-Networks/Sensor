/*
** Copyright (C) 2014 Equilibrium Networks, Incorporated

** This program is free software: you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation, either version 3 of the License, or
** (at your option) any later version.

** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.

** You should have received a copy of the GNU General Public License
** along with this program.  If not, see <http://www.gnu.org/licenses/>
*/

/* node.h
 *   @author cc, gt
 *   Version 0.9
 */

// Load once and C++ safety definitions.
#ifndef _NODE_H_
#define _NODE_H_

#ifdef __cplusplus
extern "C" {
#endif

// Include files.
#include <stdlib.h>

// Convenience definitions.
#define node struct NODE

// Node structure definition.
struct NODE
{
    int id;
    char name[255];
    int (*func)(const u_char *, int);
    int leafCount;
    node **leafs;
};

// Function prototypes.
node* newTreeNode(int (*function)(const u_char *, int), int newID, char *newName);
node* newInternalNode(int (*function)(const u_char *, int), char *name);
node* newTerminalNode(int newID);
node** newNodeArray(int arraySize);

#ifdef __cplusplus
}
#endif

#endif /* _NODE_H_ */
