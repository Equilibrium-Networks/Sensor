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

/* node.c
 *   @author cc, gt
 *   Version 0.9
 */

// Include files.
#include <string.h>
#include "node.h"

/*
 * Creates and returns a new tree node. Two types of nodes may be created:
 * internal nodes and terminal leaf nodes. Internal nodes contain a processing
 * function which is used during tree traversal. Terminal leaf nodes do not
 * contain a processing function (NULL is passed in as the function pointer) and
 * signify that tree traversal has resulted in a successful completion.
 *
 * Leaf nodes can be easily identified as having a positive ID value, as well as
 * a NULL function pointer. Internal nodes can be identified in the opposite
 * manner: they have an ID of -1 and a valid function pointer. A node with both
 * an ID of -1 and a NULL function pointer, after it has been fully initialized,
 * indicates an internal node which was initialized with a missing or otherwise
 * unavailable function.
 */
node* newTreeNode(int (*function)(const u_char *, int), int newID, char *newName)
{
    // Create pointer.
    node *newNode;

    // Allocate new memory.
    newNode = (node*)malloc(sizeof(node));

    // Set fields.
    newNode->id = newID;
    strcpy(newNode->name, newName);
    newNode->func = function;
    newNode->leafCount = 0;
    newNode->leafs = NULL;

    // Return new node.
    return newNode;
}

/*
 * Creates and returns an internal node. This node uses the specified evaluation
 * function for tree traversals. The node ID is set to -1 for internal nodes.
 */
node* newInternalNode(int (*function)(const u_char *, int), char *name)
{
    // Return new node.
    return newTreeNode(function, -1, name);
}

/*
 * Creates and returns a terminal leaf node. This node uses the specified ID for
 * tree traversals. The node function is set to NULL for terminal leaf nodes.
 */
node* newTerminalNode(int newID)
{
    // Return new node.
    return newTreeNode(NULL, newID, "leaf");
}

/*
 * Returns an allocated array of node pointers, using the passed in array size.
 * Only the array is allocated by this function. Actual nodes must be allocated
 * individually.
 */
node** newNodeArray(int arraySize)
{
    if(arraySize > 0)
    {
        return (node**)malloc(arraySize * sizeof(node*));
    }
    else
    {
        return NULL;
    }
}
