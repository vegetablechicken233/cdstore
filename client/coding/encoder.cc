/*
 * encoder.cc
 *
 */

#include "encoder.hh"
#include "uploader.hh"
using namespace std;

/*
 * thread handler for encoding each chunkObj.chunk_header into shares
 *
 * @param param - parameters for encode thread
 */
void* Encoder::thread_handler(void* param){//此处的param拥有一个index和obj，即指向encoder自身的指针，在构造中读取的是一个index循环改变的变量。

    /* parse parameters */
    int index = ((param_encoder*)param)->index;
    Encoder* obj = ((param_encoder*)param)->obj;//初始化 index为开头 传递指针
    free(param);

    /* main loop for getting secrets and encode them into shares*/
    while(true){//线程的主要循环

        /* get an object from input buffer */
        Uploader::Item_t tempENCODEchunk;
        Uploader::Item_t input;
        obj->inputbuffer_[index]->Extract(&tempENCODEchunk);//从ADD函数中提取出当前线程对应循环buffer中的secret_item放到tempchunk文件中（即小的chunks）
        //在这个局部中的temp即为
        /* get the object type */
        int type = tempENCODEchunk.type;//读取chunk类型
        input.type = type;//放到share中

        /* copy content into input object */
        if(type == FILE_OBJECT){
            /* if it's file header */
            memcpy(&input.fileObj.file_header, &tempENCODEchunk.fileObj.file_header, sizeof(Uploader::fileHeaderObj_t));//如果是则将头文件大小的数据copy到sharechunk_item input中 union结构相同
        }
        else
        {


            /* if it's share object */
            //obj->encodeObj_[index]->encoding(tempENCODEchunk.chunkObj.data, tempENCODEchunk.chunkObj.chunk_header.secretSize, input.chunkObj.data, &(input.chunkObj.chunk_header.shareSize));
            //encodeObj为CDCodec模块 这是第INDEX个线程 在CDcodec.hh中默认将加密方式设为CANT-OS。

            memcpy(&input.chunkObj.data,&tempENCODEchunk.fileObj.data,tempENCODEchunk.chunkObj.chunk_header.secretSize);

            input.chunkObj.chunk_header.secretID = tempENCODEchunk.chunkObj.chunk_header.secretID;
            input.chunkObj.chunk_header.secretSize = tempENCODEchunk.chunkObj.chunk_header.secretSize;//多了一个share文件的大小shareSize 同时data转变为了n份的
            //sharesize表示的是每个share的大小，共n个
            //encoding方法在CDCode.cc中
            input.chunkObj.chunk_header.end = tempENCODEchunk.chunkObj.chunk_header.end;//这四步将属于源secret转变为share文件
            //可以从这里修改成为普通的加密，不需要秘密共享
        }

        /* add the object to output buffer */
        obj->outputbuffer_[index]->Insert(&input,sizeof(input));//将index线程的outbuffer循环数组更新，插入最新的share文件
    }
    return NULL;
}

/*
 * collect thread for getting share object in order
 *
 * @param param - parameters for collect thread
 */
void* Encoder::collect(void* param){//传参为此encoder的指针
    /* index for sequencially collect shares */
    int nextBufferIndex = 0;

    /* parse parameters */
    Encoder* obj = (Encoder*)param;

    /* main loop for collecting shares */
    while(true){//循环

        /* extract an object from a certain ringbuffer */
        Uploader::Item_t temp;
        obj->outputbuffer_[nextBufferIndex]->Extract(&temp);//将thread Encode完成的秘密chunk导出到temp
        nextBufferIndex = (nextBufferIndex + 1)%NUM_THREADS;//轮流从每一个encode线程的output中取出一个chunk

        /* get the object type */
        int type = temp.type;//获取该chunk类型

        Uploader::Item_t input;//需要把原来的share文件转化为uploader需要的格式item
        //item中的union在作为headerobj时 具有一个fileheader即 share文件MDhead 和存储数据的data
        if(type == FILE_OBJECT){

            /* if it's file header, directly transform the object to uploader */
            input.type =FILE_HEADER;// -9

            /* copy file header information */
            input.fileObj.file_header.fullNameSize=temp.fileObj.file_header.fullNameSize;
            input.fileObj.file_header.fileSize = temp.fileObj.file_header.fileSize;
            input.fileObj.file_header.numOfPastSecrets = 0;
            input.fileObj.file_header.sizeOfPastSecrets = 0;
            input.fileObj.file_header.numOfComingSecrets = 0;
            input.fileObj.file_header.sizeOfComingSecrets = 0;
            
            //unsigned char tmp[temp.fileObj.file_header.fullNameSize*32];
            //int tmp_s;

            //encode pathname into shares for privacy


            //obj->encodeObj_[0]->encoding(temp.fileObj.data, temp.fileObj.file_header.fullNameSize, tmp, &(tmp_s));//用pid=0的线程加密
            
            //cdcodec


            //input.fileObj.file_header.fullNameSize = tmp_s;//保存加密后的文件名大小

            /* copy file name 如果直接使用复制不加密 */


            memcpy(input.fileObj.data, temp.fileObj.data, temp.fileObj.file_header.fullNameSize);

            //just copy

#ifndef ENCODE_ONLY_MODE
            /* add the object to each cloud's uploader buffer */
           

                //copy the corresponding share as file name
                //memcpy(input.fileObj.data, tmp, input.fileObj.file_header.fullNameSize);//从tmp开始 给每个i服务器相对应的第i个share 里面是加密后的名字



                obj->uploadObj_->add(&input, sizeof(input));




                
            
#endif
        }else{

            /* if it's share object */
            
                input.type = CHUNK_OBJECT;

                /* copy share info */	
                int shareSize = temp.chunkObj.chunk_header.secretSize;

                //权宜之计，之后可以改正。
                //sharesize变为sf的空间。

                input.chunkObj.chunk_header.secretID = temp.chunkObj.chunk_header.secretID;
                input.chunkObj.chunk_header.secretSize = temp.chunkObj.chunk_header.secretSize;
                input.chunkObj.chunk_header.shareSize = shareSize;

                memcpy(input.chunkObj.data, temp.chunkObj.data, shareSize);//从share_chunk.data+(i*shareSize)中每隔sharesize取出一个share储存到chunkObj.data中
#ifndef ENCODE_ONLY_MODE
#endif
                /* see if it's the last chunkObj.chunk_header of a file */
                if (temp.chunkObj.chunk_header.end == 1) input.type = CHUNK_END;
#ifdef ENCODE_ONLY_MODE
                if (temp.chunkObj.chunk_header.end == 1) pthread_exit(NULL);
#else 
                /* add the share object to targeting cloud uploader buffer */







                
                obj->uploadObj_->add(&input, sizeof(input));





#endif
            }
        
    }
    return NULL;
}


/*
 * see if it's end of encoding file
 *
 */
void Encoder::indicateEnd(){//维持 看是否线程已经运行完毕
    pthread_join(tid_[NUM_THREADS],NULL);
}

/*
 * constructor
 *    
 * @param type - convergent dispersal type
 * @param n - total number of shares generated from a chunkObj.chunk_header
 * @param m - reliability degree
 * @param r - confidentiality degree
 * @param securetype - encryption and hash type
 * @param uploaderObj - pointer link to uploader object
 *
 */
Encoder::Encoder(int type, int n, int m, int r, int securetype, Uploader* uploaderObj){

    /* initialization of variables */
    int i;
    n_ = n;
    nextAddIndex_ = 0;
    cryptoObj_ = (CryptoPrimitive**)malloc(sizeof(CryptoPrimitive*)*NUM_THREADS);
    inputbuffer_ = (RingBuffer<Uploader::Item_t>**)malloc(sizeof(RingBuffer<Uploader::Item_t>*)*NUM_THREADS);
    outputbuffer_ = (RingBuffer<Uploader::Item_t>**)malloc(sizeof(RingBuffer<Uploader::Item_t>*)*NUM_THREADS);

    /* initialization of objects */
    for (i = 0; i < NUM_THREADS; i++){//以i为循环NUM_THEARDS个线程 从0到NUM-1
        inputbuffer_[i] = new RingBuffer<Uploader::Item_t>(RB_SIZE, true, 1);
        outputbuffer_[i] = new RingBuffer<Uploader::Item_t>(RB_SIZE, true, 1);



        cryptoObj_[i] = new CryptoPrimitive(securetype);//加密模块生成
        encodeObj_[i] = new CDCodec(type,n,m,r, cryptoObj_[i]);//编码模块初始化



        //在这里生成了函数中需要的encodeObj 是CDCodec类
        param_encoder* temp = (param_encoder*)malloc(sizeof(param_encoder));
        temp->index = i;
        temp->obj = this;//用于在

        /* create encoding threads */
        pthread_create(&tid_[i],0,&thread_handler,(void*)temp);
    }

    uploadObj_ = uploaderObj;

    /* create collect thread */
    pthread_create(&tid_[NUM_THREADS],0,&collect,(void*)this);//只开了一个序列号为NUM_THERADS的线程来collect
}

/*
 * destructor
 *
 */
Encoder::~Encoder(){
    for (int i = 0; i < NUM_THREADS; i++){
        delete(cryptoObj_[i]);
        delete(encodeObj_[i]);
        delete(inputbuffer_[i]);
        delete(outputbuffer_[i]);
    }
    free(inputbuffer_);
    free(outputbuffer_);
    free(cryptoObj_);
}

/*
 * add function for sequencially add items to each encode buffer
 *
 * @param item - input object
 *
 */
int Encoder::add(Uploader::Item_t* item){
    /* add item */
    inputbuffer_[nextAddIndex_]->Insert(item, sizeof(Uploader::Item_t));//向循环buffer区中添加新部分供线程使用

    /* increment the index */
    nextAddIndex_ = (nextAddIndex_+1)%NUM_THREADS;
    return 1;
}


