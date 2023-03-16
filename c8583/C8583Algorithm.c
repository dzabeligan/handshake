
#include "C8583Algorithm.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void SortedInsert(struct DataElement** headRef,
                         struct DataElement* newNode) {
  if (*headRef == NULL || (*headRef)->field >= newNode->field) {
    newNode->next = *headRef;
    *headRef = newNode;
  } else {
    struct DataElement* current = *headRef;
    while (current->next != NULL && current->next->field < newNode->field) {
      current = current->next;
    }
    newNode->next = current->next;
    current->next = newNode;
  }
}

void pushElement(struct DataElement** head_ref, const int field,
                 const void* datum, const int size) {
  struct DataElement* new_node =
      (struct DataElement*)malloc(sizeof(struct DataElement));

  new_node->field = field;
  new_node->size = size;
  new_node->datum = (unsigned char*)malloc(size * sizeof(char));
  memcpy(new_node->datum, datum, size);

  SortedInsert(head_ref, new_node);
}

short getElement(const struct DataElement* head_ref, const int field,
                 void* datum, const int size) {
  const struct DataElement* node = head_ref;

  while (node != NULL) {
    if (node->field == field) {
      if (size < node->size) return 0;
      memcpy(datum, node->datum, node->size);
      return node->size;
    }
    node = node->next;
  }

  return 0;
}

void freeDataElement(struct DataElement** headRef) {
  struct DataElement* current = *headRef;
  struct DataElement* next;

  while (current != NULL) {
    next = current->next;
    free(current->datum);
    free(current);
    current = next;
  }

  *headRef = NULL;
}
