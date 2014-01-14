#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
struct node{
  u_char* data;
  int data_len;
  struct node *next;
};

typedef struct node node;
static list_size=0;

int beg_add_element(node ** p_head ,u_char *blob,int blob_size)
{
  struct node * element= (struct node *) malloc (sizeof(struct node));
  memset(element, 0, sizeof(element));
  element->data = malloc(blob_size);
  
  if (element->data ==NULL){
    printf("malloc failed in beg_add_element()\n");
    return -1;
  }
  element->data_len=blob_size;
  memcpy(element->data,blob,blob_size);
  if (*p_head ==NULL)
    {
      *p_head =element;
      (*p_head)->next = NULL;
    }
  else
    {
      element->next =*p_head;
      *p_head = element;
    }
  list_size++;
}
/*
Adds the packet buffer and the packet buffer length to the linked 
list.
*/
int end_add_element(node **p_head , u_char * blob, int blob_size)
{  
  node * temp;

  node * element= (node *) malloc (sizeof(struct node));
  memset(element, 0, sizeof(element));
  element->data = malloc(blob_size);
  if (element->data ==NULL){
    printf("malloc failed\n");
    return -1;
  }
  element->data_len = blob_size;
  memcpy(element->data,blob,blob_size);
  temp = *p_head ;
  if (*p_head ==NULL)
    {
      *p_head = element;
      (*p_head)->next = NULL;
    }
  else
    {
      while (temp->next !=NULL)
	temp=temp->next;
      element->next =NULL;
      temp->next=element;
    }

  list_size++;
  return 0;
}
/*
Prints the contents of the linked list starting from head pointer
*/
int print_list(node *p)
{
  printf("in print list\n");
  node * start ;
  start= p ;
  int idx =0;
  while (start !=NULL)
    {
      printf("(%d) %d: %s\n",idx++, start->data_len, start->data);
      start = start->next;
    }
  return 0;
}
/*
  Fetches the packet buffer and the packet len from the linked list 
*/
int beg_del_element( node **p_head, u_char** fetch_data, int *fetch_data_len )
{
  node * fetch_node;
  fetch_node = *p_head ;
  if (fetch_node ==NULL && list_size==0)
    {
      printf("list is empty\n");
      return -1; //empty list
    }
  *p_head=fetch_node->next;
  *fetch_data = malloc(fetch_node->data_len);
  memset(*fetch_data,0, fetch_node->data_len);
  memcpy(*fetch_data,fetch_node->data,fetch_node->data_len);
  *fetch_data_len =fetch_node->data_len;
  list_size--;
}

int test_suit()
{
  node * head =NULL;
  beg_add_element(&head, "abhinav", sizeof("abhinav"));
  beg_add_element(&head," narain", sizeof(" narain"));
  beg_add_element(&head,"this is a test suit",sizeof("this is a test suit"));
  //  end_add_element(&head,"this is another line in the test suite",sizeof("this is another line in the test suite"));
  //end_add_element(&head, "the last line that is ever going to be written in the test suite", \
  //		  sizeof("the last line that is ever going to be written in the test suite"));
  printf("done with adding elements\n");
  if (head ==NULL)
    printf("head is null ");
  print_list(head);
  u_char * d1;
  u_char * d2;
  int l1,l2;
  beg_del_element(&head, &d1, &l1);
  printf("the stuff that we got: %s %d\n",d1,l1);
  print_list(head );
  printf("==\n");
  beg_del_element(&head, &d2, &l2);
  printf("the stuff that we got: %s %d\n",d2,l2);
  print_list(head);
  printf("@@\n");
  beg_del_element(&head, &d2, &l2);
  printf("the stuff that we got: %s %d\n",d2,l2);
  print_list(head);
  printf("$$\n");
  beg_del_element(&head, &d2, &l2);
  print_list(head);

}
