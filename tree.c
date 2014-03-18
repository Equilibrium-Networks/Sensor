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

/* tree.c
 *   @author cc, gt
 *   Version 0.9
 */

// Include files.
#include <stdio.h>
#include <string.h>
#include "tree.h"
#include "treeFunctions.h"

/*
 * Processes a tree node using the provided function parameters. This recursive
 * function first evaluates whether the passed in node has a function associated
 * with it. If a function exists, then this is an internal node and the function
 * is recursively evaluated with the specified parameters. If the function does
 * exist for the node (terminal leaf node), then the ID of that node is used for
 * the return value. Note that all node functions must be identically
 * prototyped. Each parameter must be passed into this function in order to be
 * used for the individual node function calls.
 *
 * The recursive function assumes a correctly constructed tree, such that the
 * function associated with current node evaluates to a zero-based index of
 * child nodes for recursive transversal. Functions should return a closed,
 * consecutive set of values corresponding to the index of the child nodes to
 * prevent tree traversal pointer errors. A node may contain more child nodes
 * than the associated function can return an index for, but such child nodes
 * could never be transversed.
 *
 * Due to the recursive nature of this function, it must be assumed that the
 * same node can never be processed in the same recursive chain more than once.
 * Such occurrences would create a circular traversal error and prevent this
 * function from returning if encountered. While the same node can appear
 * multiple times in a tree, care must be taken to ensure that circular
 * traversals cannot occur.
 *
 * Example:
 * The root node for a tree contains a function which can return 0, 1 or 2,
 * depending on the processing parameters. This node should also contain exactly
 * 3 child nodes to be able to traverse the tree correctly for all possible
 * values. If the node only contained two child nodes, then function calls
 * returning a value of 2 (the third array index) would result in a null pointer
 * error. If the node contained more than 3 nodes, the tree would function
 * correctly, but the additional nodes would be unreachable.
 */
int processTree(node *treeNode, const u_char *p, int /* (boolean) */ source)
{
    if(treeNode->func == NULL)
    {
        // Return node ID for terminal leaf nodes.
        return treeNode->id;
    }
    else
    {
        // Recursively process child node.
        return processTree(treeNode->leafs[treeNode->func(p, source)], p, source);
    }
}

/*
 * Returns an collection of trees loaded from the specified file. This function
 * returns NULL if the tree definition file could not be properly parsed.
 * Parsing errors could occur if the tree structure is impossible, function
 * names are not defined internally, child node references are missing a node
 * definition entry, node definition entries are invalid (e.g. leading
 * whitespace or out of order components) or the file could not be read, among
 * others.
 */
int __n_leaves = 0;
treeCollection* loadFile(char *fileName, int *_n_leaves)
{
    // Convenience variables.
    char tempString[255];
    int currentLine = 0;
    int lastTreeStart = -1;
    int lastTreeEnd = -1;
    int treeCount = 0;

    // Traversal pointers.
    treeListNode *treePtr = NULL;
    treeListNode *treeHead = NULL;
    listNode *nodePtr = NULL;

    // Open file.
    FILE *file = fopen(fileName, "rt");

    // Read in entire file.
    if(file != NULL)
    {
        while(fgets(tempString, 255, file) != NULL)
        {
            // Increment line counter.
            currentLine++;

            // Check for line start type.
            switch(tempString[0])
            {
                case '\0':
                    // Null terminator.
                    break;
                case '\n':
                    // Blank line.
                    break;
                case '/':
                    // Comment line.
                    break;
                case '<':
                    // Add node definition to existing tree.
                    if(treePtr != NULL)
                    {
                        // Create new node.
                        if(treePtr->listHead == NULL)
                        {
                            // Create new node list if necessary.
                            treePtr->listHead = (listNode*)malloc(sizeof(listNode));
                            treePtr->listHead->next = NULL;
                            nodePtr = treePtr->listHead;
                        }
                        else
                        {
                            // Add node to list.
                            nodePtr->next = (listNode*)malloc(sizeof(listNode));
                            nodePtr = nodePtr->next;
                            nodePtr->next = NULL;
                        }

                        // Copy line, minus any appended comments.
                        strncpy(nodePtr->line, tempString, strcspn(tempString, "//"));
                    }
                    break;
                default:
                    // Check for tree definition start.
                    if(strstr(tempString, "Tree") != NULL || strstr(tempString, "TREE") != NULL)
                    {
                        // New tree definition.
                        if(lastTreeStart > lastTreeEnd)
                        {
                            // Attempted to define new tree before closing the old one.
                            return NULL;
                        }
                        else
                        {
                            // Update line numbers.
                            lastTreeStart = currentLine;
                            treeCount++;

                            // Create new tree.
                            if(treePtr == NULL)
                            {
                                // Create first tree.
                                treePtr = (treeListNode*)malloc(sizeof(treeListNode));
                                treePtr->next = NULL;
                                treeHead = treePtr;
                            }
                            else
                            {
                                // Create additional tree.
                                treePtr->next = (treeListNode*)malloc(sizeof(treeListNode));
                                treePtr = treePtr->next;
                            }

                            // Nullify new node list.
                            treePtr->listHead = NULL;

                            // Copy name, excluding leading space or tab and trailing new line.
                            strncpy(treePtr->name, &tempString[5], strcspn(&tempString[5], "\n"));
                        }
                    }
                    else if(strstr(tempString, "End") != NULL || strstr(tempString, "END") != NULL)
                    {
                        // Tree definition completed.
                        if(lastTreeEnd > lastTreeStart)
                        {
                            // Attempted to close tree before opening it.
                            return NULL;
                        }
                        else
                        {
                            // Update line numbers
                            lastTreeEnd = currentLine;
                        }
                    }
                    break;
            }
        }

        // Close the file.
        fclose(file);
    }
    else
    {
        // No file.
        return NULL;
    }

    // Return if no trees were found or parsed.
    if(treeCount == 0)
    {
        return NULL;
    }

    // Create final tree collection.
    treeCollection* trees = malloc(sizeof(treeCollection));
    trees->count = treeCount;
    trees->elements = populateTrees(treeHead, treeCount);

    // Free temporary memory.
    freeList(treeHead);
*_n_leaves = __n_leaves;
    // Return tree collection.
    return trees;
}

/*
 * Creates and returns a tree array from the specified tree list data.
 */
tree** populateTrees(treeListNode* treeList, int treeCount)
{
    // Convenience variables.
    char tempString[255];
    char *token;
    int stringLength;
    int nodeCount;
    int treeLoop;
    int nodeLoop;
    int childLoop;
    int nodePtrLoop;

    // Traversal pointers.
    treeListNode *treePtr = treeList;
    listNode *nodePtr = NULL;

    // Create tree final array.
    tree** treeArray = (tree**)malloc(treeCount * sizeof(tree*));

    // Initialize individual trees.
    for(treeLoop = 0; treeLoop < treeCount; treeLoop++)
    {
        // Loop variable reset.
        nodePtr = treePtr->listHead;
        stringLength = 0;

        // Allocate new tree.
        treeArray[treeLoop] = (tree*)malloc(sizeof(tree));

        // Copy tree name.
        strcpy(treeArray[treeLoop]->name, treePtr->name);

        // Count tree nodes.
        nodeCount = countNodes(treePtr);

        // Create tree node array.
        node** nodeArray = (node**)malloc(nodeCount * sizeof(node*));

        // [First pass] Populate basic node data
        for(nodeLoop = 0; nodeLoop < nodeCount; nodeLoop++)
        {
            // Create new node.
            nodeArray[nodeLoop] = (node*)malloc(sizeof(node));
            nodeArray[nodeLoop]->leafs = NULL;

            // Set node name and ID.
            stringLength = strcspn(&nodePtr->line[1], ">");
            strncpy(nodeArray[nodeLoop]->name, &nodePtr->line[1], stringLength);
            nodeArray[nodeLoop]->name[stringLength] = '\0';
            nodeArray[nodeLoop]->id = -1;

            // Set node function.
            stringLength = strcspn((strchr(nodePtr->line, '{') + 1), "}");
            strncpy(tempString, (strchr(nodePtr->line, '{') + 1), stringLength);
            tempString[stringLength] = '\0';
            nodeArray[nodeLoop]->func = findFunction(tempString);

            // Increment node pointer.
            nodePtr = nodePtr->next;
        }

        // Reset node pointer for second pass.
        nodePtr = treePtr->listHead;

        // [Second pass] Populate child and leaf pointers
        for(nodeLoop = 0; nodeLoop < nodeCount; nodeLoop++)
        {
            // Count child and leaf nodes.
            nodeArray[nodeLoop]->leafCount = countChild(nodePtr->line);

            // Create new child list.
            nodeArray[nodeLoop]->leafs = newNodeArray(nodeArray[nodeLoop]->leafCount);

            // Prepare for tokenization.
            token = nodePtr->line;

            // Process tokens for each child/leaf node.
            for(childLoop = 0; childLoop < nodeArray[nodeLoop]->leafCount; childLoop++)
            {
                // Set new pointer to NULL.
                nodeArray[nodeLoop]->leafs[childLoop] = NULL;

                // Node type check.
                if(strcspn(token, "[") > strcspn(token, "("))
                {
                    // Store child node name.
                    stringLength = strcspn((strchr(token, '(') + 1), ")");
                    strncpy(tempString, (strchr(token, '(') + 1), stringLength);
                    tempString[stringLength] = '\0';

                    // Find and store reference to existing node.
                    for(nodePtrLoop = 0; nodePtrLoop < nodeCount; nodePtrLoop++)
                    {
                        if(stringLength == strlen(nodeArray[nodePtrLoop]->name) && strstr(nodeArray[nodePtrLoop]->name, tempString) != NULL)
                        {
                            nodeArray[nodeLoop]->leafs[childLoop] = nodeArray[nodePtrLoop];
                            break;
                        }
                    }

                    // Increment token pointer.
                    token = strchr(token, ')') + 1;
                }
                else
                {
                    // Store reference to new leaf node.
                    nodeArray[nodeLoop]->leafs[childLoop] = newTerminalNode(atoi(strchr(token, '[') + 1));
__n_leaves++;

                    // Increment token pointer.
                    token = strchr(token, ']') + 1;
                }

                // Safety check for missing/invalid node name.
                if(nodeArray[nodeLoop]->leafs[childLoop] == NULL)
                {
                    return NULL;
                }
            }

            // Increment node pointer.
            nodePtr = nodePtr->next;
        }

        // Store tree root node reference.
        if(nodeArray[0] != NULL)
        {
            treeArray[treeLoop]->root = nodeArray[0];
        }
        else
        {
            return NULL;
        }

        // Increment tree pointer.
        treePtr = treePtr->next;
    }

    return treeArray;
}

/*
 * Helper function to count the number of nodes in a tree.
 */
int countNodes(treeListNode *treePtr)
{
    // Start count.
    int count = 0;

    // Store traversal pointer.
    listNode *nodePtr = treePtr->listHead;

    // Count nodes.
    while(nodePtr != NULL)
    {
        // Increment count.
        count++;

        // Increment node pointer.
        nodePtr = nodePtr->next;
    }

    // Return count.
    return count;
}

/*
 * Helper function to count the number of child/leaf nodes listed in a node
 * definition entry.
 */
int countChild(char *nodeString)
{
    // Start count.
    int count = 0;

    // Store traversal pointer.
    char *stringPtr = nodeString;

    // Count nodes.
    while(stringPtr != NULL && *stringPtr != '\0')
    {
        // Check for child and leaf node delimiters.
        if(*stringPtr == '(' || *stringPtr == '[')
        {
            // Increment count.
            count++;
        }

        // Increment string pointer.
        stringPtr++;
    }

    // Return count.
    return count;
}
/*
 * Helper function to free memory allocated to a temporary tree definition list
 * by freeing each node list and tree list element.
 */
void freeList(treeListNode* treeList)
{
    // Traversal pointer.
    treeListNode *treePtr = treeList;
    listNode *nodePtr = NULL;

    // Traverse each tree.
    while(treePtr != NULL)
    {
        // Increment list.
        treeList = treeList->next;

        // Traverse each node.
        nodePtr = treePtr->listHead;
        while(nodePtr != NULL)
        {
            // Increment list.
            treePtr->listHead = treePtr->listHead->next;

            // Free current node.
            free(nodePtr);

            // Increment traversal pointer.
            nodePtr = treePtr->listHead;
        }
        nodePtr = NULL;

        // Free current node.
        free(treePtr);

        // Increment traversal pointer.
        treePtr = treeList;
    }

    free(treePtr);
    treePtr = NULL;
}
