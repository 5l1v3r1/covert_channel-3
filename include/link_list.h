#ifndef _LINK_LIST_H_
#define _LINK_LIST_H_
int beg_add_element(node **p_head, u_char *blob, int blob_size);
int end_add_element(node **p_head, u_char * blob, int blob_size);
int print_list(node *p_head);
int beg_del_element(node **p_head, u_char** fetch_data, int *fetch_data_len );
#endif /*_LINK_LIST_H_*/
