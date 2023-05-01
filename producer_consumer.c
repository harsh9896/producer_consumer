#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include <pthread.h>

#define SECONDS_IN_TEN_YEARS         315532800
#define NANOS_IN_A_SECOND            1000000000
#define TIMEZONE_IST_GMT_DIFF        19800
#define EPOCH_OFFSET                 SECONDS_IN_TEN_YEARS
#define BIT_KEY_128                  128
#define BIT_KEY_256                  256
#define MAX_NMBR_ARGS                6
#define NO_OF_SAMPLES                1000
#define ONLY_ENCRYPT                 1
#define ONLY_DECRYPT                 2
#define ENCRYPT_DECRYPT_BOTH         3

long t1 = 0;
long t2 = 0;
long lTotalTime = 0;



static int GetCurrentTime(struct timespec *psTimeSpec, int iEpochDiff)
{
   int iReturn;
   struct timespec stTimeSpec = {0, 0};
   if (clock_gettime(CLOCK_REALTIME, &stTimeSpec) == 0)
   {
      psTimeSpec->tv_sec = (int)stTimeSpec.tv_sec - iEpochDiff +
                                                         TIMEZONE_IST_GMT_DIFF;
      psTimeSpec->tv_nsec = (long)stTimeSpec.tv_nsec;
      iReturn = 0;
   }
   else
   {
      iReturn = 1;
   }

   return iReturn;
}

int TimeLibGetUnAdjstdCrrntTimeNano(long *lRetNanoSec)
{
   int iReturn;
   struct timespec stTimeSpec = {0, 0};

   if (GetCurrentTime(&stTimeSpec, EPOCH_OFFSET) == 0)
   {
      *lRetNanoSec = (long)stTimeSpec.tv_nsec +
                     ((long)stTimeSpec.tv_sec) *
                      NANOS_IN_A_SECOND;
      iReturn = 0;
   }
   else
   {
      iReturn = 1;
   }

   return iReturn;
}

void TimeLibSleepNano(int nsec)
{
   struct timespec    stTimeSpec;
   stTimeSpec.tv_sec = 0;
   stTimeSpec.tv_nsec = nsec;
   nanosleep(&stTimeSpec, NULL);
}

void NanoSleep(int nsec)
{
    struct timespec res;
    res.tv_sec = 0;
    res.tv_nsec = nsec;
    clock_nanosleep(CLOCK_MONOTONIC, 0, &res, NULL);
}

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

void encrypt_EVP_aes_256_gcm_init(EVP_CIPHER_CTX **ctx, 
                                  unsigned char *key, unsigned char *iv,
                                  unsigned char *aad, int aad_len,
                                  EVP_CIPHER_CTX **copy_ctx)
{
    int len;

    if(!(*ctx = EVP_CIPHER_CTX_new()))
        handleErrors();
#if 0
    if(1 != EVP_EncryptInit_ex(*ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        handleErrors();

    if(1 != EVP_CIPHER_CTX_ctrl(*ctx, EVP_CTRL_GCM_SET_IVLEN, strlen(iv), NULL))
        handleErrors();

    if(1 != EVP_EncryptInit_ex(*ctx, NULL, NULL, key, iv))
        handleErrors();
#endif
#if 1
    if(1 != EVP_EncryptInit_ex(*ctx, EVP_aes_256_gcm(), NULL, key, iv))
        handleErrors();
    if(1 != EVP_CIPHER_CTX_ctrl(*ctx, EVP_CTRL_GCM_SET_IVLEN, strlen(iv), NULL))
        handleErrors();
#endif
/*
    if(1 != EVP_EncryptUpdate(*ctx, NULL, &len, aad, aad_len))
        handleErrors();
*/
}

void encrypt_EVP_aes_128_gcm_init(EVP_CIPHER_CTX **ctx, 
                                  unsigned char *key, unsigned char *iv,
                                  unsigned char *aad, int aad_len,
                                  EVP_CIPHER_CTX **copy_ctx)
{
    int len;

    if(!(*ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    if(1 != EVP_EncryptInit_ex(*ctx, EVP_aes_128_gcm(), NULL, NULL, NULL))
        handleErrors();

    if(1 != EVP_CIPHER_CTX_ctrl(*ctx, EVP_CTRL_GCM_SET_IVLEN, strlen(iv), NULL))
        handleErrors();

    if(1 != EVP_EncryptInit_ex(*ctx, NULL, NULL, key, iv))
        handleErrors();
/*
    if(1 != EVP_EncryptUpdate(*ctx, NULL, &len, aad, aad_len))
        handleErrors();
*/
}

void encrypt(EVP_CIPHER_CTX *ctx, 
             unsigned char *plaintext, int plaintext_len, 
             unsigned char *ciphertext, int *ciphertext_len,
             unsigned char *aad, int aad_len,
             unsigned char *tag)
{
    int len;

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    *ciphertext_len = len;

    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    *ciphertext_len += len;

    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
        handleErrors();
}

void encrypt_cleanup(EVP_CIPHER_CTX *ctx)
{
    EVP_CIPHER_CTX_free(ctx);
}

void encrypt_reset(EVP_CIPHER_CTX *ctx, unsigned char *key, unsigned char *iv)
{
    //EVP_CIPHER_CTX_cleanup(ctx);
    //EVP_CIPHER_CTX_reset(ctx);
    //EVP_CIPHER_CTX_init(ctx);
#if 0
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
       handleErrors();

    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, strlen(iv), NULL))
       handleErrors();

    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
       handleErrors();
#endif
#if 1
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv))
        handleErrors();
//    TimeLibGetUnAdjstdCrrntTimeNano(&t1);
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, strlen(iv), NULL))
        handleErrors();
//    TimeLibGetUnAdjstdCrrntTimeNano(&t2);
//    lTotalTime += (t2-t1);
#endif
}

void decrypt_EVP_aes_256_gcm_init(EVP_CIPHER_CTX **ctx, 
                                  unsigned char *key, unsigned char *iv,
                                  unsigned char *aad, int aad_len,
                                  EVP_CIPHER_CTX **copy_ctx)
{
    int len;
    if(!(*ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    if(!EVP_DecryptInit_ex(*ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        handleErrors();

    if(!EVP_CIPHER_CTX_ctrl(*ctx, EVP_CTRL_GCM_SET_IVLEN, strlen(iv), NULL))
        handleErrors();

    if(!EVP_DecryptInit_ex(*ctx, NULL, NULL, key, iv))
        handleErrors(); 

    if(!EVP_DecryptUpdate(*ctx, NULL, &len, aad, aad_len))
        handleErrors();
}

void decrypt_EVP_aes_128_gcm_init(EVP_CIPHER_CTX **ctx, 
                                  unsigned char *key, unsigned char *iv,
                                  unsigned char *aad, int aad_len,
                                  EVP_CIPHER_CTX **copy_ctx)
{
    int len;
    if(!(*ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    if(!EVP_DecryptInit_ex(*ctx, EVP_aes_128_gcm(), NULL, NULL, NULL))
        handleErrors();

    if(!EVP_CIPHER_CTX_ctrl(*ctx, EVP_CTRL_GCM_SET_IVLEN, strlen(iv), NULL))
        handleErrors();

    if(!EVP_DecryptInit_ex(*ctx, NULL, NULL, key, iv))
        handleErrors();
    
     if(!EVP_DecryptUpdate(*ctx, NULL, &len, aad, aad_len))
        handleErrors();
}

int decrypt(EVP_CIPHER_CTX *ctx, 
            unsigned char *ciphertext, int ciphertext_len, 
            unsigned char *plaintext, int *plaintext_len,
            unsigned char *aad, int aad_len,
            unsigned char *tag)
{
    int len;
    int ret;

    if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    *plaintext_len = len;

    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
        handleErrors();

    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
#if 0
    if(1 != EVP_CIPHER_CTX_reset(ctx))
        handleErrors();
#endif
    if(ret > 0) {
        /* Success */
        *plaintext_len += len;
        return 0;
    } else {
        /* Verify failed */
        printf("---------------- Decryption Verification Failed --------------------- !!!!! \n");
        return -1;
    }
}

void decrypt_cleanup(EVP_CIPHER_CTX *ctx)
{
    EVP_CIPHER_CTX_free(ctx);
}

unsigned char *key, *iv;
EVP_CIPHER_CTX *encrypt_ctx[10001];
unsigned char *aad = (unsigned char *)"swapnil";
int aad_len;
char caEncryptMessage [1024];
int iMessageSize = 0;
int iNoOfMessages = 0;
unsigned char i_tag[16];
int iNoOfMessages,iNoOfUsers;
int decryptedtext_len, ciphertext_len;
char caMessage [NO_OF_SAMPLES][1024];
int  BUFFER_SIZE;
int count=0;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond_var_producer = PTHREAD_COND_INITIALIZER;
pthread_cond_t cond_var_consumer = PTHREAD_COND_INITIALIZER;

void *producer(void *arg)
{
    EVP_CIPHER_CTX * ctx, *copy_ctx;
    for(int iCount=0;iCount<iNoOfMessages;iCount++) {
        encrypt_EVP_aes_256_gcm_init(&ctx,key, iv, aad, aad_len, &copy_ctx);
        pthread_mutex_lock(&mutex);
        while (count == BUFFER_SIZE) {
            pthread_cond_wait(&cond_var_producer, &mutex);
        }
        encrypt_ctx[count] = ctx;
        //printf("Produced\n");
        count++;
        pthread_cond_signal(&cond_var_consumer);
        pthread_mutex_unlock(&mutex);
    }
}

void *consumer(void *arg)
{
    for(int iCount=0;iCount<iNoOfMessages;iCount++) {
        pthread_mutex_lock(&mutex);
        while (count == 0) {
            pthread_cond_wait(&cond_var_consumer, &mutex);
        }
        EVP_CIPHER_CTX * ctx = encrypt_ctx[count-1];
        //printf("Consumed\n");
        count--;
        pthread_cond_signal(&cond_var_producer);
        pthread_mutex_unlock(&mutex);
        encrypt(ctx, caMessage[iCount%NO_OF_SAMPLES], iMessageSize, caEncryptMessage, &ciphertext_len, aad, aad_len, i_tag);
    }
}

int main (int argc,char* argv[])
{
    //EVP_CIPHER_CTX *encrypt_ctx[10001];
    EVP_CIPHER_CTX *decrypt_ctx[10001];
    EVP_CIPHER_CTX *copy_encrypt_ctx[10001];
    EVP_CIPHER_CTX *copy_decrypt_ctx[10001];
   
    
    char caDecryptMessage [1024];
    int  iCount = 0;
    int  iChar = 0;
    long lStartTime = 0;
    long lEndTime = 0;
    int iMode = 0;
    
    int iKeyLength = 0;
    unsigned char key_128[17];
    unsigned char key_256[33];
    char chMemsetChar;
    aad_len = strlen(aad);
    
  

    /* A 256 bit key */
    key = (unsigned char *)"01234567890123456789012345678901";
    /* A 128 bit IV */
    iv = (unsigned char *)"0123456789012345";
    /* Message to be encrypted */

    

    if ( argc != MAX_NMBR_ARGS )
    {
       printf("Usage : EncryptDecryptPerfTest <iNoOfUsers> <iMode ONLY_ENCRYPT-1 /ONLY_DECRYPT-2 /ENCRYPT_DECRYPT_BOTH - 3> <iMessageSize> <iNoOfMessages> <iKeyLength 128/256>\n");
    }
    iNoOfUsers = atoi(argv[1]);    
    iMode = atoi(argv[2]);    
    iMessageSize = atoi(argv[3]);    
    iNoOfMessages = atoi(argv[4]);    
    iKeyLength = atoi(argv[5]);
    BUFFER_SIZE= iNoOfMessages;    

    memset(caMessage, '\0', sizeof(caMessage));
    memset(caEncryptMessage, '\0', sizeof(caEncryptMessage));
    memset(caDecryptMessage, '\0', sizeof(caDecryptMessage));
#if 0
    for (iCount = 0; iCount < NO_OF_SAMPLES; iCount++)
    {
       chMemsetChar = (char) (iCount % 128);
       memset(caMessage[iCount], chMemsetChar, iMessageSize);
    }
#endif
#if 1
    for (iCount = 0; iCount < NO_OF_SAMPLES; iCount++)
    {
       for (iChar = 0; iChar < iMessageSize; iChar++)
       {
          chMemsetChar = (char) ((iChar+iCount) % 128);
          caMessage[iCount][iChar] = chMemsetChar;
       }
    }
#endif

    pthread_t producer_thread, consumer_thread;
    TimeLibGetUnAdjstdCrrntTimeNano(&lStartTime);
    pthread_create(&producer_thread, NULL, producer, NULL);
    pthread_create(&consumer_thread, NULL, consumer, NULL);
    pthread_join(producer_thread, NULL);
    pthread_join(consumer_thread, NULL);
    TimeLibGetUnAdjstdCrrntTimeNano(&lEndTime);

    // for (iCount = 0; iCount < iNoOfUsers; iCount++)
    // {
    //    if (iKeyLength == BIT_KEY_128)
    //    {
    //       sprintf(key_128,"%s%05d","01234567890",iCount);
    //       //printf("Key is => %s\n",key_128);
    //       encrypt_EVP_aes_128_gcm_init(&encrypt_ctx[iCount],key_128, iv, aad, aad_len, &copy_encrypt_ctx[iCount]);
    //       decrypt_EVP_aes_128_gcm_init(&decrypt_ctx[iCount],key_128, iv, aad, aad_len, &copy_decrypt_ctx[iCount]);
    //    }
    //    else if (iKeyLength == BIT_KEY_256)
    //    {
    //       sprintf(key_256,"%s%05d","012345678901234567890123456",iCount);
    //       //printf("Key is => %s\n",key_256);
    //       encrypt_EVP_aes_256_gcm_init(&encrypt_ctx[iCount],key_256, iv, aad, aad_len, &copy_encrypt_ctx[iCount]);
    //       decrypt_EVP_aes_256_gcm_init(&decrypt_ctx[iCount],key_256, iv, aad, aad_len, &copy_decrypt_ctx[iCount]);
    //    }
    // }

    // if (iMode == ONLY_DECRYPT)
    // {
    //    encrypt (encrypt_ctx[0], caMessage[0], iMessageSize, caEncryptMessage, &ciphertext_len, aad, aad_len, i_tag);
    //    //memcpy(o_tag,i_tag,16);
    // }
    // TimeLibGetUnAdjstdCrrntTimeNano(&lStartTime);
    // for (iCount = 0; iCount < iNoOfMessages; iCount++)
    // {
    //    if (iMode == ENCRYPT_DECRYPT_BOTH)
    //    {
    //       encrypt(encrypt_ctx[iCount%iNoOfUsers], caMessage[iCount%NO_OF_SAMPLES], iMessageSize, caEncryptMessage, &ciphertext_len, aad, aad_len, i_tag);
    //       decrypt(decrypt_ctx[iCount%iNoOfUsers], caEncryptMessage, ciphertext_len, caDecryptMessage, &decryptedtext_len, aad, aad_len, i_tag);
    //    }
    //    else if (iMode == ONLY_ENCRYPT)
    //    {
    //       //TimeLibGetUnAdjstdCrrntTimeNano(&t1);
    //       encrypt (encrypt_ctx[iCount%iNoOfUsers], caMessage[iCount%NO_OF_SAMPLES], iMessageSize, caEncryptMessage, &ciphertext_len, aad, aad_len, i_tag);
    //       //TimeLibGetUnAdjstdCrrntTimeNano(&t2);
    //       //lTotalTime += (t2-t1);
    //       #if 1
    //       //TimeLibGetUnAdjstdCrrntTimeNano(&t1);
    //       encrypt_reset(encrypt_ctx[iCount%iNoOfUsers],key_256, iv);
    //       //encrypt_EVP_aes_256_gcm_init(&encrypt_ctx[iCount%iNoOfUsers],key_256, iv, aad, aad_len);
    //       //TimeLibGetUnAdjstdCrrntTimeNano(&t2);
    //       //lTotalTime += (t2-t1);
    //       #endif
    //    }
    //    else
    //    {
    //       decrypt(decrypt_ctx[0], caEncryptMessage, ciphertext_len, caDecryptMessage, &decryptedtext_len, aad, aad_len, i_tag);
    //    }
    //    //printf("Before Ecrypt Text: [%s] Len :%d\n",caMessage[iCount%NO_OF_SAMPLES],iMessageSize);
    //    //printf("Ecrypt Text: [%s] Len: %d\n",caEncryptMessage,ciphertext_len);
    //    //printf("Decrypted Text: [%s] Len :%d\n", caDecryptMessage, decryptedtext_len);
    // }
    // TimeLibGetUnAdjstdCrrntTimeNano(&lEndTime);
    printf("Time Taken To Complete [%d] transaction is [%ld] nano seconds\n",iNoOfMessages,lEndTime-lStartTime);
    printf("Nanoseconds per transaction => [%d]\n",(lEndTime-lStartTime)/iNoOfMessages);
    printf("Time per encrypt operation is [%d]\n",lTotalTime/iNoOfMessages);
    return 0;
}


