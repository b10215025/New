#include <iostream>
#include <vector>
#include<stdio.h>
#include<stdlib.h>
#include<math.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
using namespace std;

void product_encry(char* plaintext,int* e,char* result,int k){
    for(int i=0;i<k ;i++){
        result[i] = plaintext[e[i]-1];
    }
}
void func(char* cipher_l,char* cipher_r,char* expand_cipher,char* key,int sbox[8][64]){
    char tmp_sbox[8][6],tmp[32],permu[32];
    int sum=0,a;
    int tmp_xor[48];
    int Permutation[64] = {
        16,  7, 20, 21,
        29, 12, 28, 17,
        1, 15, 23, 26,
        5, 18, 31, 10,
        2,  8, 24, 14,
        32, 27,  3,  9,
        19, 13, 30,  6,
        22, 11,  4, 25
    };
    
    //xor key and expandcipher
    for(int i=0;i<48;i++){
        tmp_xor[i] = expand_cipher[i]-'0' xor key[i]-'0';
    }
    //do sbox
    for (int i=0; i<8; i++) {
        sum=0;
        sum += tmp_xor[i*6] *32 +tmp_xor[i*6+5]*16 +tmp_xor[i*6+1]*8 +tmp_xor[i*6+2]*4 +tmp_xor[i*6+3]*2 + tmp_xor[i*6+4]*1  ;
        sum = sbox[i][sum];
        
        for(int j=0;j<4;j++){
            tmp[i*4+(3-j)] = (sum % 2)+'0';
            sum = sum /2;
        }
    }
    //permutaion
    product_encry(tmp, Permutation, permu, 32);
    //xor with cipher_right
    for(int j=0;j<32;j++){
        tmp[j] = (permu[j] xor cipher_r[j] )+'0';
    }
    //exchange L and R
    for(int i=0;i<32;i++){
        cipher_r[i] = cipher_l[i];
    }
    for(int i=0;i<32;i++){
        cipher_l[i] = tmp[i];
    }
}

int main(void){
    
    char plaintext[]= "1000100101001100101101110011001011011111100111011110000100000011" ;
    char ciphertext[64]  ;
    char key[]= "0110001101101111011011010111000001110101011101000110010101110010";
    char tmp[64],cipher_r[32],cipher_l[32],expand_cipher[48],key_56[56],key_r[28],key_l[28],key_48[48],tmp_key[2];
    //pc-1
    int offset =1;

    int pc1[56] ={
        57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2,  59, 51, 43, 35, 27,
        19, 11,  3, 60, 52, 44, 36,
        63, 55,  47,  39, 31, 23, 15,
        7, 62,  54,  46, 38, 30, 22,
        14, 6,  61,  53, 45, 37, 29,
        21, 13,  5,  28, 20, 12, 4
    };
    //pc-2
    int pc2[48]= {
        14, 17, 11,  24, 1, 5,  3, 28,
        15, 6,  21, 10,  23, 19, 12,  4,
        26, 8,  16,  7, 27, 20,  13, 2,
        41, 52, 31, 37, 47, 55, 30, 40,
        51, 45, 33, 48, 44, 49, 39, 56,
        34, 53, 46, 42, 50, 36, 29, 32
    };
    //permutation 64bit
    int p[64]= {
        58, 50, 42, 34, 26, 18,  10,  2,
        60, 52, 44, 36, 28, 20, 12,  4,
        62, 54, 46, 38, 30, 22, 14,  6,
        64, 56, 48, 40, 32, 24, 16,  8,
        57, 49, 41, 33, 25, 17,  9,  1,
        59, 51, 43, 35, 27, 19, 11,  3,
        61, 53, 45, 37, 29, 21, 13,  5,
        63, 55, 47, 39, 31, 23, 15,  7
    };
    //final
    int FinalPermutation[]= {
        40,  8, 48, 16, 56, 24, 64, 32,
        39,  7, 47, 15, 55, 23, 63, 31,
        38,  6, 46, 14, 54, 22, 62, 30,
        37,  5, 45, 13, 53, 21, 61, 29,
        36,  4, 44, 12, 52, 20, 60, 28,
        35,  3, 43, 11, 51, 19, 59, 27,
        34,  2, 42, 10, 50, 18, 58, 26,
        33,  1, 41,  9, 49, 17, 57, 25
    };
    //expand 32bit to 48bit
    int e[48] = {
        32,  1,  2,  3,  4,  5,  4,  5,
        6,  7,  8,  9,  8,  9,  10, 11,
        12, 13, 12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21, 20, 21,
        22, 23, 24, 25, 24, 25, 26, 27,
        28, 29, 28, 29, 30, 31, 32, 1
    };
    //s-box
    
    int sbox[8][64] = { {
        14, 4,  13, 1,  2,  15, 11, 8,  3,  10, 6,  12, 5,  9,  0,  7,
        0,  15, 7,  4,  14, 2,  13, 1,  10, 6,  12, 11, 9,  5,  3,  8,
        4,  1,  14, 8,  13, 6,  2,  11, 15, 12, 9,  7,  3,  10, 5,  0,
        15, 12, 8,  2,  4,  9,  1,  7,  5,  11, 3,  14, 10, 0,  6,  13
    }, {
        15, 1,  8,  14, 6,  11, 3,  4,  9,  7,  2,  13, 12, 0,  5,  10,
        3,  13, 4,  7,  15, 2,  8,  14, 12, 0,  1,  10, 6,  9,  11, 5,
        0,  14, 7,  11, 10, 4,  13, 1,  5,  8,  12, 6,  9,  3,  2,  15,
        13, 8,  10, 1,  3,  15, 4,  2,  11, 6,  7,  12, 0,  5,  14, 9
    }, {
        10, 0,  9,  14, 6,  3,  15, 5,  1,  13, 12, 7,  11, 4,  2,  8,
        13, 7,  0,  9,  3,  4,  6,  10, 2,  8,  5,  14, 12, 11, 15, 1,
        13, 6,  4,  9,  8,  15, 3,  0,  11, 1,  2,  12, 5,  10, 14, 7,
        1,  10, 13, 0,  6,  9,  8,  7,  4,  15, 14, 3,  11, 5,  2,  12
    }, {
        7,  13, 14, 3,  0,  6,  9,  10, 1,  2,  8,  5,  11, 12, 4,  15,
        13, 8,  11, 5,  6,  15, 0,  3,  4,  7,  2,  12, 1,  10, 14, 9,
        10, 6,  9,  0,  12, 11, 7,  13, 15, 1,  3,  14, 5,  2,  8,  4,
        3,  15, 0,  6,  10, 1,  13, 8,  9,  4,  5,  11, 12, 7,  2,  14
    }, {
        2,  12, 4,  1,  7,  10, 11, 6,  8,  5,  3,  15, 13, 0,  14, 9,
        14, 11, 2,  12, 4,  7,  13, 1,  5,  0,  15, 10, 3,  9,  8,  6,
        4,  2,  1,  11, 10, 13, 7,  8,  15, 9,  12, 5,  6,  3,  0,  14,
        11, 8,  12, 7,  1,  14, 2,  13, 6,  15, 0,  9,  10, 4,  5,  3
    }, {
        12, 1,  10, 15, 9,  2,  6,  8,  0,  13, 3,  4,  14, 7,  5,  11,
        10, 15, 4,  2,  7,  12, 9,  5,  6,  1,  13, 14, 0,  11, 3,  8,
        9,  14, 15, 5,  2,  8,  12, 3,  7,  0,  4,  10, 1,  13, 11, 6,
        4,  3,  2,  12, 9,  5,  15, 10, 11, 14, 1,  7,  6,  0,  8,  13
    }, {
        4,  11, 2,  14, 15, 0,  8,  13, 3,  12, 9,  7,  5,  10, 6,  1,
        13, 0,  11, 7,  4,  9,  1,  10, 14, 3,  5,  12, 2,  15, 8,  6,
        1,  4,  11, 13, 12, 3,  7,  14, 10, 15, 6,  8,  0,  5,  9,  2,
        6,  11, 13, 8,  1,  4,  10, 7,  9,  5,  0,  15, 14, 2,  3,  12
    }, {
        13, 2,  8,  4,  6,  15, 11, 1,  10, 9,  3,  14, 5,  0,  12, 7,
        1,  15, 13, 8,  10, 3,  7,  4,  12, 5,  6,  11, 0,  14, 9,  2,
        7,  11, 4,  1,  9,  12, 14, 2,  0,  6,  10, 13, 15, 3,  5,  8,
        2,  1,  14, 7,  4,  10, 8,  13, 15, 12, 9,  0,  3,  5,  6,  11
    } };
    //start des
    //enter data
    printf("ciphertext:\n");
    for(int i=0;i<64;i++)
        printf("%c",plaintext[i]);
    printf("\n");
    printf("key:\n");
    for(int i=0;i<64;i++)
        printf("%c",key[i]);
    printf("\n");
    
    //start
    //fisrt permutation
    product_encry(plaintext, p,tmp,64);
    
    strncpy(cipher_r, tmp, 32);
    strncpy(cipher_l,&tmp[32],32);
    
    // process key
    product_encry(key ,pc1,key_56 , 56);
    
    for (int round=1; round<=16; round++) {
        // expand cipher_r 32bit to 48bit
        product_encry(cipher_l, e, expand_cipher, 48);
        //separate key rightside and leftside
        for(int i=0;i<28;i++){
            key_l[i] = key_56[i];
        }
        for(int i=0;i<28;i++)
            key_r[i] = key_56[i+28];
        //set offset
        if (round==2||round==9||round==16)
            offset =1;
        else
            offset = 2;
        
        // rotation and  make key 56bit to 48bits

        //rotation
        if(round !=1 ){
            if (offset ==1) {
                //rotation key_l
                tmp_key[0]=key_l[27];
                for(int i=27;i>0;i--)
                    key_l[i]=key_l[i-1];
                key_l[0]=tmp_key[0];
                //rotation key_r
                tmp_key[0]=key_r[27];
                for(int i=27;i>0;i--)
                    key_r[i]=key_r[i-1];
                key_r[0] =tmp_key[0];
            }
            else if (offset == 2) {
                //rotation key_l
                tmp_key[0] = key_l[26];
                tmp_key[1] = key_l[27];
                for(int i=27;i>1;i--)
                    key_l[i]=key_l[i-2];
                key_l[0] = tmp_key[0];
                key_l[1] = tmp_key[1];
                //rotation key_r
                tmp_key[0] = key_r[26];
                tmp_key[1] = key_r[27];
                for(int i=27;i>1;i--)
                    key_r[i]=key_r[i-2];
                key_r[0] = tmp_key[0];
                key_r[1] = tmp_key[1];
            }
        }
        //united key
        for(int i=0;i<28;i++)
            key_56[i]= key_l[i];
        for(int i=0;i<28;i++)
            key_56[i+28]=key_r[i];
        //make key 56bit to 48bit
        product_encry(key_56, pc2, key_48, 48);
        
        func(cipher_l, cipher_r, expand_cipher, key_48,sbox);
    }
    for(int i=0;i<32;i++){
        plaintext[i] = cipher_l[i];
        plaintext[i+32] = cipher_r[i];
    }

    /*
    for(int i=0;i<32;i++){
        plaintext[i] = cipher_r[i];
        plaintext[i+32] = cipher_l[i];
    }
    */
    product_encry(plaintext, FinalPermutation, ciphertext, 64);
    
    printf("plaintext:");
    for(int i=0;i<64;i++)
        printf("%c",ciphertext[i]);
    printf("\n");
    
    return 0;
}
