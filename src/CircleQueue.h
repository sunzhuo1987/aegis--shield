#ifndef CIRCLE_QUEUE_H
#define CIRCLE_QUEUE_H

//队列类型表示:Queue_元素类型(如元素为整形的队列类型为:Queue_int)
//_ET:元素类型
#define Q_TYPE(ET) Queue_##ET

//队列变量定义:每个队列对应一个数组,用于存放元素,数组名表示成:qBuf##queue
//在定义队列变量时需指定队列长度:由len指定
//ET: 元素类型
//queue: 队列变量名
//len: 队列长度
#define Q_DEFINE(ET,queue,len) \
	ET qBuf##queue[len]; \
	int qBufLen##queue=/*sizeof(ET)**/len; \
	Q_TYPE(ET) queue 

//队列类型(结构体)定义:
//ET: 元素类型
//Queue_##ET: 具体化后的队列类型,由不同的元素类型决定
#define Q_TYPE_DEFINE(ET) \
	typedef struct			\
{						\
	ET*           pElems;		\
	int             front,rear;		\
	int             maxSize;		\
}Queue_##ET

//队列变量声明表示: 用于声明外部全局变量
//ET: 元素类型
//queue: 队列变量名
#define Q_EXTERN(ET, queue)			\
	extern ET qBuf##queue[];			\
	extern int qBufLen##queue;			\
	extern Q_TYPE(ET) queue

//队列初始化
#define Q_INIT(queue, len)		do{				\
	memset(qBuf##queue, 0, qBufLen##queue);		\
	queue.pElems  = qBuf##queue;	\
	queue.front = queue.rear = 0;	\
	queue.maxSize = len;			\
}while(0)

//队空
#define Q_EMPTY(queue) (queue.front == queue.rear)

//队满
#define Q_FULL(queue) ((queue.rear + 1) % queue.maxSize == queue.front)

//入队
#define Q_PUT(queue, pput) do{		\
	if(Q_FULL(queue))				\
	{								\
	sleep(1);	\
	}								\
	else							\
	{								\
	queue.pElems[queue.rear] = *(pput);			\
	queue.rear = (queue.rear + 1) % queue.maxSize;			\
	}								\
}while(0)									

//出队
#define Q_GET(queue, pget)  do{		\
	if(queue.front == queue.rear)	\
	{								\
	pget = NULL;				\
	}								\
	else							\
	{								\
	int head = queue.front;		\
	queue.front = (queue.front +1) % queue.maxSize;			\
	pget = &queue.pElems[head];								\
	}								\
}while(0)


#endif