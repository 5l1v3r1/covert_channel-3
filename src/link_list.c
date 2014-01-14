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
node * head =NULL;
int beg_add_element(u_char *blob,int blob_size)
{
  struct node * element= (struct node *) malloc (sizeof(struct node));
  memset(element, 0, sizeof(element));
  element->data = malloc(blob_size);

  if (element->data ==NULL)
    return -1;

  element->data_len=blob_size;
  memcpy(element->data,blob,blob_size);
  if (head ==NULL)
    {
      head =element;
      head->next = NULL;
    }
  else
    {
      element->next =head;
      head = element;
    }
  list_size++;
}
/*
Adds the packet buffer and the packet buffer length to the linked 
list.
*/
int end_add_element(u_char * blob, int blob_size)
{
  node * temp;
  node * element= (node *) malloc (sizeof(struct node));
  memset(element, 0, sizeof(element));
  element->data = malloc(blob_size);
  if (element->data ==NULL)
    return -1;
  element->data_len = blob_size;
  memcpy(element->data,blob,blob_size);
  temp = head ;
  if (head ==NULL)
    {
      head = element;
      head->next = NULL;
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
int print_list()
{
  node * start ;
  start= head ; 
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
int delete_element( u_char** fetch_data, int *fetch_data_len )
{
  node * fetch_node;
  fetch_node = head ;
  if (fetch_node->next == NULL && list_size==0)
    {
      return -1; //empty list
    }
  head=head->next;
  *fetch_data = malloc(fetch_node->data_len);
  memset(*fetch_data,0, fetch_node->data_len);
  memcpy(*fetch_data,fetch_node->data,fetch_node->data_len);
  *fetch_data_len =fetch_node->data_len;
  list_size--;
}

static int test_suit()
{
  end_add_element((u_char*)"abhinav", sizeof("abhinav"));
  end_add_element((u_char*)" narain", sizeof(" narain"));
  end_add_element((u_char*)"this is a test suit",sizeof("this is a test suit"));
  end_add_element((u_char*)"this is another line in the test suite",sizeof("this is another line in the test suite"));
  end_add_element((u_char*)"the last line that is ever going to be written in the test suite",\
		  sizeof("the last line that is ever going to be written in the test suite"));
  printf("done with adding elements\n");
  print_list();
  u_char * d1;
  u_char * d2;
  int l1,l2;
  printf("%p",d1);
  delete_element(&d1,&l1);
  printf("the stuff that we got: %s %d\n",d1,l1);
  printf("==\n");
  print_list();
  delete_element(&d2,&l2);
  printf("the stuff that we got: %s %d\n",d2,l2);
  printf("@@\n");
  print_list();
}
