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
    /* argument test �����Ƿ������� */
    if (argc != 5) usage(NULL);

    /* get options ���������� */
    int userID = atoi(argv[2]);
    char* opt = argv[3];
    char* securesetting = argv[4];

    /* read file ��ȡ */

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
    /* TO DO: load from config file ��ȡconf.hh�е�Ĭ������ */
    n = confObj->getN();
    m = confObj->getM();
    k = confObj->getK();
    r = confObj->getR();

    /* initialize buffers ���ɻ����� */
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
    shareBuffer = (unsigned char*)malloc(sizeof(unsigned char) * shareBufferSize);//�����ڴ�ռ�

    /* initialize share ID list ����share ID ���б� */
    kShareIDList = (int*)malloc(sizeof(int)*k);
    for (i = 0; i < k; i++) kShareIDList[i] = i;

    /* full file name process ����ļ������� */
    int namesize = 0;
    while(argv[1][namesize] != '\0'){
        namesize++;
    }
    namesize++;

    /* parse secure parameters */
    int securetype = LOW_SEC_PAIR_TYPE;
    if(strncmp(securesetting,"HIGH", 4) == 0) securetype = HIGH_SEC_PAIR_TYPE;//���ݲ���ѡ����ܷ�ʽ

    if (strncmp(opt,"-u",2) == 0 || strncmp(opt, "-a", 2) == 0){//�����ʽ��upload����a�Ļ�

        FILE * fin = fopen(argv[1],"r");

        /* get file size ȡ���ļ���С */
        fseek(fin,0,SEEK_END);
        long size = ftell(fin);	
        fseek(fin,0,SEEK_SET);
        uploaderObj = new Uploader(n,n,userID);
        encoderObj = new Encoder(CAONT_RS_TYPE, n, m, r, securetype, uploaderObj);
        chunkerObj = new Chunker(VAR_SIZE_TYPE);
        //chunking
        //
        Encoder::Secret_Item_t header;//����secretͷ
        header.type = 1;
        memcpy(header.file_header.data, argv[1], namesize);
        header.file_header.fullNameSize = namesize;
        header.file_header.fileSize = size;


        // do encode
        encoderObj->add(&header);//��header���ּ���encoder
        //uploaderObj->generateMDHead(0,size,(unsigned char*) argv[1],namesize,n,0,0,0,0);

        long total = 0;
        int totalChunks = 0;
        while (total < size){
            int ret = fread(buffer,1,bufferSize,fin);//���ļ���ȡbuffersize�ֽ������ֽ� ���浽buffer�� ����retΪ��ȡ���ֽ���
            chunkerObj->chunking(buffer,ret,chunkEndIndexList,&numOfChunks);//��ret��С�� buffer�и�Ϊ numofchunks ��chunk ����С��chunker.hh������β�������ŵ�chunkENDindexlist

            int count = 0;
            int preEnd = -1;//����Ϊ�и�Ϊ�̶���С��buffer
            while(count < numOfChunks){
                Encoder::Secret_Item_t input;
                input.type = 0;
                input.secret.secretID = totalChunks;
                input.secret.secretSize = chunkEndIndexList[count] - preEnd;//�������chunksÿһ��ѭ������Ϣ����input���item
                memcpy(input.secret.data, buffer+preEnd+1, input.secret.secretSize);//��buffer����ǰchunk��ȡ��secretdata��
                if(memcmp(input.secret.data, tmp, input.secret.secretSize) == 0){
                    zero += input.secret.secretSize;
                }

                input.secret.end = 0;
                if(total+ret == size && count+1 == numOfChunks) input.secret.end = 1;//���chunksȫ����������� end=1
                encoderObj->add(&input);//����ǰinput ���뵽encoderģ��
                totalChunks++;
                preEnd = chunkEndIndexList[count];
                count++;
            }//����Ϊ��buffer��ÿ��chunk��input���뵽encoder��
            total+=ret;//total������buffer������ ���ļ���С
        }
        long long tt = 0, unique = 0;
        uploaderObj->indicateEnd(&tt, &unique);

        delete uploaderObj;
        delete chunkerObj;
        delete encoderObj;

        fclose(fin);    
    }



    if (strncmp(opt,"-d",2) == 0 || strncmp(opt, "-a", 2) == 0){//�����download����
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

