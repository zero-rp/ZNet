#ifndef __TREE_H__
#define __TREE_H__

#include <stdlib.h>

#ifdef __cplusplus
	extern "C" {
#endif

	typedef int key_t;
	typedef void *data_t;

	typedef struct rb_node_
	{
		struct rb_node_ *rb_right;
		struct rb_node_ *rb_left;
		size_t  rb_parent_color;
		key_t key;
		data_t data;
	}rb_node;

	typedef struct rb_root_
	{
		rb_node *rb_node;
	}rb_root;


	typedef void(*TreeVisitFunc)(void *data);

	/*操作函数*/

	/*初始化*/
	rb_root *rb_new();
	/*插入*/
	int rb_insert(key_t key, data_t data, rb_root *root);
	/*搜索*/
	rb_node *rb_search(key_t key, rb_root*root);
	/*删除*/
	void rb_delete(key_t key, rb_root*root);
	/*释放树*/
	void rb_free(rb_root*root);
	/*遍历树*/
	void rb_foreach(rb_root *root, TreeVisitFunc visitfunc);
    rb_node *rb_minkey(rb_root *root);



#ifdef __cplusplus
	}
#endif

#endif //__TREE_H__