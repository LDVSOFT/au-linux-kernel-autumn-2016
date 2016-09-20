#include "stack.h"

#include <linux/slab.h>
#include <linux/gfp.h>

stack_entry_t* create_stack_entry(void *data)
{
    stack_entry_t *node = kzalloc(sizeof(stack_entry_t), GFP_KERNEL);
    if (node == NULL) {
        return NULL;
    }
    node->data = data;
    return node;
}

void delete_stack_entry(stack_entry_t *entry)
{
    kfree(entry);
}

void stack_push(struct list_head *stack, stack_entry_t *entry)
{
    list_add(&entry->lh, stack);
}

stack_entry_t* stack_pop(struct list_head *stack)
{
    stack_entry_t *top = list_first_entry(stack, stack_entry_t, lh);
    list_del(&top->lh);
    return top;
}
