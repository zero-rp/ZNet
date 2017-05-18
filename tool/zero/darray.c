#include "darray.h"


DArray *darray_create()
{
    int i = 0;
    DArray *darray = (DArray *)malloc(sizeof(DArray));
    if (darray != NULL)
    {
        darray->count = 0;
        darray->size = 0;
        darray->data = (void **)malloc(sizeof(void *) * DEFAULT_A_SIZE);

        if (darray->data != NULL)
        {
            darray->size = DEFAULT_A_SIZE;
            for (i = 0; i < darray->size; i++)
            {
                darray->data[i] = NULL;
            }
        }
        return darray;
    }

    return NULL;
}
int darray_append(DArray *darray, void * data)
{
    if (darray == NULL || data == NULL)
    {
        return 0;
    }

    if ((darray->count + 1) >= darray->size)
    {
        darray_expand(darray, 2);

    }

    darray->data[darray->count] = data;

    darray->count++;

    return 1;

}
int darray_set_by_index(DArray *darray, int index, void *data)
{
    if (darray == NULL || data == NULL)
    {
        return 0;
    }
    if (index < 0 || index >= darray->count)
    {
        return 0;
    }

    darray->data[index] = data;
    return 1;

}
static int darray_expand(DArray *darray, int needone)
{
    int newallocsize = 0;

    if (needone == 2)
    {
        newallocsize = darray->count + (darray->count >> 1) + DEFAULT_A_SIZE;
    }
    else
    {
        newallocsize = darray->count + 1;
    }
    void **data = (void **)realloc(darray->data, sizeof(void *) * newallocsize);
    if (data != NULL)
    {
        darray->data = data;
        darray->size = newallocsize;

    }
    return 1;

}
int darray_shrink(DArray *darray)
{
    if ((darray->count >> 1) < darray->size && (darray->size > DEFAULT_A_SIZE))
    {
        int newallocsize = darray->count + darray->count >> 1;
        void **data = (void **)realloc(darray->data, sizeof(void *) * newallocsize);
        if (data != NULL)
        {
            darray->data = data;
            darray->size = newallocsize;
        }
        return 1;
    }
    return 0;
}
int darray_delete(DArray *darray, int index)
{
    int i = 0;

    for (i = index; (i + 1) < darray->count; i++)
    {
        darray->data[i] = darray->data[i + 1];
    }

    darray->count--;

    darray_shrink(darray);

    return 1;
}
int darray_preappend(DArray *darray, void * data)
{
    if (darray == NULL || data == NULL)
    {
        return 0;
    }

    if (darray->count + 1 > darray->size)
    {
        darray_expand(darray, 2);
    }
    int i = 0;
    for (i = darray->count; i > 0; )
    {
        darray->data[i] = darray->data[i - 1];
        i--;
    }
    darray->data[0] = data;
    darray->count++;

    return 1;
}
int darray_insert(DArray *darray, int index, void * data)
{
    if (darray == NULL || data == NULL)
    {
        return 0;
    }

    if (darray->count + 1 > darray->size)
    {
        darray_expand(darray, 1);
    }
    int i = 0;
    for (i = darray->count; i > index; )
    {
        darray->data[i] = darray->data[i - 1];
        i--;
    }
    darray->data[index] = data;
    darray->count++;

    return 1;
}
int darray_foreach(DArray *darray, VisitFunc visitfunc, void *ctx)
{
    int index = 0;

    while (index < darray->count)
    {
        visitfunc(ctx, darray->data[index]);
        index++;
    }

    return 1;
}
int darray_len(DArray * darray)
{
    return darray->count;
}
int darray_find(DArray * darray, void * data) {
    size_t i;
    for (i = 0; i < darray->count; i++)
    {
        if (darray->data[i] == data)
            return i;
    }
    return -1;
}
int darray_isempty(DArray * darray) {
    return darray->count == 0;
}
void darray_empty(DArray * darray) {
    darray->count = 0;
    darray_shrink(darray);
}
void *darray_getat(DArray * darray, int index) {
    if (index < 0 || index >= darray->count) return NULL;
    return darray->data[index];
}
int darray_destroy(DArray *darray)
{
    if (darray == NULL)
    {
        return 1;
    }

    free(darray->data);
    darray->data = NULL;

    free(darray);
    darray = NULL;
    return 1;
}
