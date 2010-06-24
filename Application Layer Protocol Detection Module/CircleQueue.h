#ifndef CIRCLE_QUEUE_H
#define CIRCLE_QUEUE_H

//�������ͱ�ʾ:Queue_Ԫ������(��Ԫ��Ϊ���εĶ�������Ϊ:Queue_int)
//_ET:Ԫ������
#define Q_TYPE(ET) Queue_##ET

//���б�������:ÿ�����ж�Ӧһ������,���ڴ��Ԫ��,��������ʾ��:qBuf##queue
//�ڶ�����б���ʱ��ָ�����г���:��lenָ��
//ET: Ԫ������
//queue: ���б�����
//len: ���г���
#define Q_DEFINE(ET,queue,len) \
	ET qBuf##queue[len]; \
	int qBufLen##queue=/*sizeof(ET)**/len; \
	Q_TYPE(ET) queue 

//��������(�ṹ��)����:
//ET: Ԫ������
//Queue_##ET: ���廯��Ķ�������,�ɲ�ͬ��Ԫ�����;���
#define Q_TYPE_DEFINE(ET) \
	typedef struct			\
{						\
	ET*           pElems;		\
	int             front,rear;		\
	int             maxSize;		\
}Queue_##ET

//���б���������ʾ: ���������ⲿȫ�ֱ���
//ET: Ԫ������
//queue: ���б�����
#define Q_EXTERN(ET, queue)			\
	extern ET qBuf##queue[];			\
	extern int qBufLen##queue;			\
	extern Q_TYPE(ET) queue

//���г�ʼ��
#define Q_INIT(queue, len)		do{				\
	memset(qBuf##queue, 0, qBufLen##queue);		\
	queue.pElems  = qBuf##queue;	\
	queue.front = queue.rear = 0;	\
	queue.maxSize = len;			\
}while(0)

//�ӿ�
#define Q_EMPTY(queue) (queue.front == queue.rear)

//����
#define Q_FULL(queue) ((queue.rear + 1) % queue.maxSize == queue.front)

//���
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

//����
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