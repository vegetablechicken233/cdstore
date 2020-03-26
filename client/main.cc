/*
 * main test program
 */
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <sys/time.h>

#include "chunker.hh"
#include "encoder.hh"
#include "decoder.hh"
#include "CDCodec.hh"
#include "uploader.hh"
#include "downloader.hh"
#include "CryptoPrimitive.hh"
#include "conf.hh"


#define MAIN_CHUNK

using namespace std;

Chunker* chunkerObj;
Decoder* decoderObj;
Encoder* encoderObj;
Uploader* uploaderObj;
CryptoPrimitive* cryptoObj;
CDCodec* cdCodecObj;
Downloader* downloaderObj;
Configuration* confObj;


void usage(char *s){
    printf("usage: ./CLIENT [filename] [userID] [action] [secutiyType]\n- [filename]: full path of the file;\n- [userID]: use ID of current client;\n- [action]: [-u] upload; [-d] download;\n- [securityType]: [HIGH] AES-256 & SHA-256; [LOW] AES-128 & SHA-1\n");
    exit(1);
}

int main(int argc, char *argv[]){
    /* argument test 测试是否满参数 */
    if (argc != 5) usage(NULL);

    /* get options 将参数导入 */
    int userID = atoi(argv[2]);
    char* opt = argv[3];
    char* securesetting = argv[4];

    /* read file 读取 */

    unsigned char * buffer;
    int *chunkEndIndexList;
    int numOfChunks;
    int n, m, k, r, *kShareIDList;

    int i;

    /* initialize openssl locks */
    if (!CryptoPrimitive::opensslLockSetup()) {
        printf("fail to set up OpenSSL locks\n");

        return 0;
    }

    confObj = new Configuration();
    /* fix parameters here */
    /* TO DO: load from config file 读取conf.hh中的默认配置 */
    n = confObj->getN();
    m = confObj->getM();
    k = confObj->getK();
    r = confObj->getR();

    /* initialize buffers 生成缓冲区 */
    int bufferSize = confObj->getBufferSize();
    int chunkEndIndexListSize = confObj->getListSize();
    int secretBufferSize = confObj->getSecretBufferSize();
    int shareBufferSize = confObj->getShareBufferSize();

    unsigned char *secretBuffer, *shareBuffer;
    unsigned char tmp[secretBufferSize];
    memset(tmp,0,secretBufferSize);
    long zero = 0;
    buffer = (unsigned char*) malloc (sizeof(unsigned char)*bufferSize);
    chunkEndIndexList = (int*)malloc(sizeof(int)*chunkEndIndexListSize);
    secretBuffer = (unsigned char*)malloc(sizeof(unsigned char) * secretBufferSize);
    shareBuffer = (unsigned char*)malloc(sizeof(unsigned char) * shareBufferSize);//分配内存空间

    /* initialize share ID list 生成share ID 的列表 */
    kShareIDList = (int*)malloc(sizeof(int)*k);
    for (i = 0; i < k; i++) kShareIDList[i] = i;

    /* full file name process 检测文件名长度 */
    int namesize = 0;
    while(argv[1][namesize] != '\0'){
        namesize++;
    }
    namesize++;

    /* parse secure parameters */
    int securetype = LOW_SEC_PAIR_TYPE;
    if(strncmp(securesetting,"HIGH", 4) == 0) securetype = HIGH_SEC_PAIR_TYPE;//根据参数选择加密方式

    if (strncmp(opt,"-u",2) == 0 || strncmp(opt, "-a", 2) == 0){//如果方式是upload或者a的话

        FILE * fin = fopen(argv[1],"r");

        /* get file size 取得文件大小 */
        fseek(fin,0,SEEK_END);
        long size = ftell(fin);	
        fseek(fin,0,SEEK_SET);
        uploaderObj = new Uploader(n,n,userID);
        encoderObj = new Encoder(CAONT_RS_TYPE, n, m, r, securetype, uploaderObj);
        chunkerObj = new Chunker(VAR_SIZE_TYPE);
        //chunking
        //
        Encoder::Secret_Item_t header;//生成secret头
        header.type = 1;
        memcpy(header.file_header.data, argv[1], namesize);
        header.file_header.fullNameSize = namesize;
        header.file_header.fileSize = size;


        // do encode
        encoderObj->add(&header);//将header部分加入encoder
        //uploaderObj->generateMDHead(0,size,(unsigned char*) argv[1],namesize,n,0,0,0,0);

        long total = 0;
        int totalChunks = 0;
        while (total < size){
            int ret = fread(buffer,1,bufferSize,fin);//由文件读取buffersize字节数的字节 保存到buffer中 返回ret为读取的字节数
            chunkerObj->chunking(buffer,ret,chunkEndIndexList,&numOfChunks);//将ret大小的 buffer切割为 numofchunks 个chunk （大小在chunker.hh）并把尾部索引放到chunkENDindexlist

            int count = 0;
            int preEnd = -1;//以上为切割为固定大小的buffer
            while(count < numOfChunks){
                Encoder::Secret_Item_t input;
                input.type = 0;
                input.secret.secretID = totalChunks;
                input.secret.secretSize = chunkEndIndexList[count] - preEnd;//将输入的chunks每一次循环的信息载入input这个item
                memcpy(input.secret.data, buffer+preEnd+1, input.secret.secretSize);//将buffer按当前chunk读取到secretdata中
                if(memcmp(input.secret.data, tmp, input.secret.secretSize) == 0){
                    zero += input.secret.secretSize;
                }

                input.secret.end = 0;
                if(total+ret == size && count+1 == numOfChunks) input.secret.end = 1;//如果chunks全部输入完毕则 end=1
                encoderObj->add(&input);//将当前input 加入到encoder模组
                totalChunks++;
                preEnd = chunkEndIndexList[count];
                count++;
            }//以上为将buffer的每个chunk用input输入到encoder中
            total+=ret;//total是所有buffer加起来 即文件大小
        }
        long long tt = 0, unique = 0;
        uploaderObj->indicateEnd(&tt, &unique);

        delete uploaderObj;
        delete chunkerObj;
        delete encoderObj;

        fclose(fin);    
    }



    if (strncmp(opt,"-d",2) == 0 || strncmp(opt, "-a", 2) == 0){//如果是download下载
        //cdCodecObj = new CDCodec(CAONT_RS_TYPE, n, m, r, cryptoObj);
        decoderObj = new Decoder(CAONT_RS_TYPE, n, m, r, securetype);
        downloaderObj = new Downloader(k,k,userID,decoderObj);
        char nameBuffer[256];
        sprintf(nameBuffer,"%s.d",argv[1]);
        FILE * fw = fopen(nameBuffer,"wb");

        decoderObj->setFilePointer(fw);
        decoderObj->setShareIDList(kShareIDList);

        downloaderObj->downloadFile(argv[1], namesize, k);
        decoderObj->indicateEnd();

        fclose(fw);
        delete downloaderObj;
        delete decoderObj;
    }


    free(buffer);
    free(chunkEndIndexList);
    free(secretBuffer);
    free(shareBuffer);
    free(kShareIDList);
    CryptoPrimitive::opensslLockCleanup();
    return 0;	


}

