/**
 * File: C8583Algorithm.h
 * ----------------------
 * Defines new interface for C8583 algorithm.
 */

#ifndef C8583_ALGORITHM_INCLUDED
#define C8583_ALGORITHM_INCLUDED

struct DataElement {
    int field;
    unsigned char* datum;
    int size;
    struct DataElement* next;
};

void pushElement(struct DataElement** head_ref, const int field,
    const void* datum, const int size);
short getElement(const struct DataElement* head_ref, const int field,
    void* datum, const int size);
void freeDataElement(struct DataElement** headRef);

#endif
