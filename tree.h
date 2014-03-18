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

/* tree.h
 *   @author cc, gt
 *   Version 0.9
 */

// Load once and C++ safety definitions.
#ifndef _TREE_H_
#define _TREE_H_

#ifdef __cplusplus
extern "C" {
#endif

// Include files.
#include "node.h"

// Convenience definitions.
#define tree struct TREE
#define listNode struct LISTNODE
#define treeListNode struct TREELISTNODE
#define treeCollection struct TREECOLLECTION

// Structure definition for an internal node list element.
struct LISTNODE
{
    char line[255];
    listNode *next;
};

// Structure definition for an internal tree list element.
struct TREELISTNODE
{
    char name[255];
    listNode *listHead;
    treeListNode *next;
};

// Structure definition for a collection of trees.
struct TREECOLLECTION
{
    int count;
    tree** elements;
};

// Structure definition for a tree.
struct TREE
{
    char name[255];
    node *root;
};

// Function prototypes.
int processTree(node *treeNode, const u_char *p, int /* (boolean) */ source);
treeCollection* loadFile(char *fileName, int *_n_leaves);

// Internal function prototypes.
// Note: these functions should never need to be called directly.
tree** populateTrees(treeListNode* treeList, int treeCount);
int countNodes(treeListNode *treePtr);
int countChild(char *nodeString);
void freeList(treeListNode* treeList);

#ifdef __cplusplus
}
#endif

#endif /* _TREE_H_ */
