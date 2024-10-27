#include "queue.h"
#include "list.h"
#include <stdlib.h>
#include <assert.h>

struct queue
{
	list head;
	list tail;
};


void* return_head(queue q)
{
	void* element_void = q->head->element;
	return element_void;
}
int is_head_null(queue q){
	return q->head==NULL;
}
void next_head(queue q)
{
	q->head = q->head->next;
}
void* return_second(queue q)
{
	void* element_void = q->head->next->element;
	return element_void;
}


queue queue_create(void)
{
	queue q = malloc(sizeof(struct queue));
	q->head = q->tail = NULL;
	return q;
}

int queue_empty(queue q)
{
	return q->head == NULL;
}



void queue_enq(queue q, void *element)
{
	if(queue_empty(q)) {
		q->head = q->tail = cons(element, NULL);
	} else {
		q->tail->next = cons(element, NULL);
		q->tail = q->tail->next;
	}
}

void *queue_deq(queue q)
{
	assert(!queue_empty(q));
	{
		void *temp = q->head->element;
		q->head = cdr_and_free(q->head);
		return temp;
	}
}
