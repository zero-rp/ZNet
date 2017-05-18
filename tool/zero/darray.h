#ifndef __DARRAY_H__
#define __DARRAY_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>

#define DEFAULT_A_SIZE 10

	/**动态数组结构*/
	typedef struct _DArray
	{
		int size;
		int count;
		void **data;

	}DArray;


	typedef void(*VisitFunc)(void *ctx, void *data);

	DArray *darray_create();		//创建动态数组
	static int darray_expand(DArray *darray, int needone);	//增加指定数组的容量
	int darray_shrink(DArray *darray);	//缩减指定数组的容量
	int darray_preappend(DArray *darray, void * data);//添加（头）元素
	int darray_append(DArray *darray, void * data);	//添加（尾）元素
	int darray_insert(DArray *darray, int index, void * data);	//插入元素
	int darray_delete(DArray *darray, int index);	//删除元素
	int darray_len(DArray * darray);			//数组长度
	int darray_find(DArray * darray, void * data);			//查找成员第一次出现的索引
	int darray_isempty(DArray * darray);		//数组是否为空
	void darray_empty(DArray * darray);		//清空数组
	void *darray_getat(DArray * darray, int index);		//取指定下标数据
	int darray_set_by_index(DArray *darray, int index, void *data);//替换数组指定位置的值
	int darray_foreach(DArray *darray, VisitFunc visitfunc, void *ctx);//遍历数组
	int darray_destroy(DArray *darray);//释放指定数组内存

#ifdef __cplusplus
	}
#endif

#endif //__CARRAY_H__
