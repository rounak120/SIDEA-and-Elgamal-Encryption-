/*
    Name:    Rounak Kumar Gupta
    Roll:    20BCS185

*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <bits/stdc++.h>
using namespace std;

#include "elgamal.h"
#include "idea.h"
#define ll long long


int main()
{
	//Setup for Server-Client Connection of Server Side
    ll c_sock, s_sock;
    char msg[25] = "Hello Client";
    char buf[100]; 
    s_sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server, other;
    memset(&server, 0, sizeof(server));
    memset(&other, 0, sizeof(other));
    server.sin_family = AF_INET;
    server.sin_port = htons(9009);
    server.sin_addr.s_addr = INADDR_ANY;
    socklen_t add;
    bind(s_sock, (struct sockaddr *)&server, sizeof(server));
    listen(s_sock, 10);
    add = sizeof(other);
    c_sock = accept(s_sock, (struct sockaddr *)&other, &add);
    if (c_sock)
    {
        printf("A connection is established");
        cout << endl;
    }
    send(c_sock, msg, sizeof(msg), 0);
    recv(c_sock, buf, sizeof(buf), 0);

    //*********************************************************************************************

	//Generation of Elgamal KEYS (Public and Private Key) of the Server 
    ll prime;
    cout<<"Enter the public and private key parameters(Large prime number): ";
    cin>>prime;
    cout<<"\n\n";
    vector<ll>  Elgamal_Key=elgamal_key_generation(prime);            //function for generating  public key parameters
    ll public_Key[3]={Elgamal_Key[0],Elgamal_Key[1],Elgamal_Key[2]};  //public key array contains the public key parameters e1,e2,p
    ll private_key[2]={Elgamal_Key[3],Elgamal_Key[2]};                //private key array contains the private key parameters d,p;
    
    send(c_sock,&public_Key,sizeof(public_Key),0);    //sending public key parameters to the client              
    
    // //*********************************************************************************************

	//Receive the Encrypted Secret Key(Cipher_Key)
    ll sk[8]; 
    recv(c_sock,&sk,sizeof(sk),0);
    //32 bits secret key is splitted into four 8 bits secret key.
    ll secret_key1[2]={sk[0],sk[1]},secret_key2[2]={sk[2],sk[3]},secret_key3[2]={sk[4],sk[5]},secret_key4[2]={sk[6],sk[7]};
	// //Decryption Cipher Key to Secret Key by elgamal Decryption
    ll sec_key1,sec_key2,sec_key3,sec_key4;  
	sec_key1=elgamal_decryption(secret_key1,private_key); 
    sec_key2=elgamal_decryption(secret_key2,private_key); 
    sec_key3=elgamal_decryption(secret_key3,private_key);
    sec_key4=elgamal_decryption(secret_key4,private_key);
    string s1=bitset<8>(sec_key1).to_string();
    string s2=bitset<8>(sec_key2).to_string();
    string s3=bitset<8>(sec_key3).to_string();
    string s4=bitset<8>(sec_key4).to_string();
    string s=s1+s2+s3+s4;
    
    ll sec_key=binaryToDecimal(s);
    cout<<"Decrypted secret Key: "<<sec_key<<"\n\n";

	//*********************************************************************************************

	// Receive the Message from Client
	bzero(buf,sizeof(buf));
    recv(c_sock,buf,sizeof(buf)+1,0); 

	string cipher_text="";
    int i=0;
    while(buf[i]!='\0'){
        cipher_text+=buf[i];
        i++;
    }
	
    
    //*********************************************************************************************

	//Decryption Key Generation from Secret Key
    vector<ll>keys=decryptionKey(sec_key);
	
	//Symmetric Decryption of Client's Message
    string Source_Code="";
    for(int i=0;i<cipher_text.size();i+=16){
        string ct=cipher_text.substr(i,16);
        string binary=decodeMessage(ct,keys);
        string a=binary.substr(0,8),b=binary.substr(8,8);

        char a1=bitset<8>(binary.substr(0,8)).to_ulong();
        char b1=bitset<8>(binary.substr(8,8)).to_ulong();
        cout<<ct<<" decrypted to "<<a<<b<<" ->> "<<a1<<b1<<endl<<endl;
        Source_Code+=a1; Source_Code+=b1;
    }
cout<<"Decrypted Message: "<<Source_Code<<"\n\n";
    printf("Disconnected with client\n");
    cout<<endl<<endl;
    cout<<"<<-- Rounak Kumar Gupta -->>"<<endl;
    cout<<"<<-- 20BCS185 -->>"<<endl;
    close(s_sock);
    return 0;
}