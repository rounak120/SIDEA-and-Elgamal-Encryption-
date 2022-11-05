/*
    Name:    Rounak Kumar Gupta
    Roll:    20BCS185

*/
#include<stdio.h>
#include<stdlib.h>
#include <unistd.h>
#include<string.h>
#include<sys/socket.h>
#include<sys/types.h>
#include<netinet/in.h>
#include<bits/stdc++.h>
using namespace std;

#include "elgamal.h"
#include "idea.h"
#define ll long long 

int main(){
	//Setup for Server-Client Connection of Client Side
    ll c_sock;
    char msg[20]="Hello server\n";
    char buf[200];
    c_sock = socket(AF_INET,SOCK_STREAM,0);
    struct sockaddr_in  client;
    memset(&client,0,sizeof(client));
    client.sin_family=AF_INET;
    client.sin_port=htons(9009);
    client.sin_addr.s_addr=INADDR_ANY;
    if(connect(c_sock,(struct sockaddr*)&client,sizeof(client))==-1){
        printf("\nServer busy/down");
        return 0;
    }
    recv(c_sock,buf,sizeof(buf),0);
    send(c_sock,msg,sizeof(msg),0);

    //*********************************************************************************************

	//Receive the Server's Public Key
	ll server_public_key[3];
	recv(c_sock,&server_public_key,sizeof(server_public_key),0);
    
	
	//*********************************************************************************************
	//Input from client about message and Secret Key for Symmetric Encryption
    cout<<"Enter message: ";
    string s;
    getline(cin,s);
    cout<<"\n\n";
    cout<<"Enter secret key: ";
    ll secret_key;
    cin>>secret_key;
    cout<<"\n\n";
    cout<<"Server public key(e1,e2,p): "<<server_public_key[0]<<" "<<server_public_key[1]<<" "<<server_public_key[2]<<endl<<endl;

    //Generating public and private key for the client.
    ll cprime;
    cout<<"Enter the public and private key parameter(Large prime number): ";
    cin>>cprime;
    vector<ll>  Elgamal_Key=elgamal_key_generation(cprime);            //function for generating  public key parameters
    ll public_Key[3]={Elgamal_Key[0],Elgamal_Key[1],Elgamal_Key[2]};  //public key array contains the public key parameters e1,e2,p
    ll private_key[2]={Elgamal_Key[3],Elgamal_Key[2]};                //private key array contains the private key parameters d,p;
    cout<<"\n\n";
	vector<ll>keys=keyGeneration(secret_key);  //Keys Generation for each round of S-IDEA 
    string source_code=s;
    if(source_code.size()&1){source_code+' ';}
	string cipher_text="";
	for(int i=0;i<source_code.size();i+=2){
		string m=bitset<8>(source_code[i]).to_string();
		m+=bitset<8>(source_code[i+1]).to_string();
		string c=encodeMessage(m,keys);
        cout<<source_code[i]<<source_code[i+1]<<" ->> "<<m<<" encrypted to "<<c<<endl<<endl;
        cipher_text+=c;
	}
	cipher_text+='\0';
    cout<<"Cipher text: "<<cipher_text<<endl;
	// Asymmetric Encryption of Secret Key
    string tk=bitset<32>(secret_key).to_string();
    string s1=tk.substr(0,8);
    string s2=tk.substr(8,8);
    string s3=tk.substr(16,8);
    string s4=tk.substr(24,8);
    ll n1=stoi(s1,0,2);
    ll n2=stoi(s2,0,2);
    ll n3=stoi(s3,0,2);
    ll n4=stoi(s4,0,2);
	vector<ll> cipher_key1=elgamal_encryption(n1,server_public_key);
    vector<ll> cipher_key2=elgamal_encryption(n2,server_public_key);
    vector<ll> cipher_key3=elgamal_encryption(n3,server_public_key);
    vector<ll> cipher_key4=elgamal_encryption(n4,server_public_key); 
    ll cip_key[8]={cipher_key1[0],cipher_key1[1],cipher_key2[0],cipher_key2[1],cipher_key3[0],cipher_key3[1],cipher_key4[0],cipher_key4[1]};
     s1=bitset<4>(cipher_key1[0]).to_string();
     s2=bitset<4>(cipher_key2[0]).to_string();
     s3=bitset<4>(cipher_key3[0]).to_string();
     s4=bitset<4>(cipher_key4[0]).to_string();
    string sx=s1+s2+s3+s4;
    s1=bitset<4>(cipher_key1[0]).to_string();
    s2=bitset<4>(cipher_key2[0]).to_string();
    s3=bitset<4>(cipher_key3[0]).to_string();
    s4=bitset<4>(cipher_key4[0]).to_string();
    sx+=(s1+s2+s3+s4);
    cout<<"Encrypted secret key: "<<sx<<endl<<endl;

	//*********************************************************************************************
	
	//Sending Of Encrypted Secret Key to Server
	send(c_sock,&cip_key,sizeof(cip_key),0);

	//Sending Of Encrypted Message to Server
	bzero(buf,sizeof(buf));
	for (ll i = 0; i < cipher_text.size(); i++){buf[i] = cipher_text[i];} 
	send(c_sock,buf,sizeof(buf),0);

	printf("Disconnected with server\n");
    cout<<endl<<endl;
    cout<<"<<-- Rounak Kumar Gupta -->>"<<endl;
    cout<<"<<-- 20BCS185 -->>"<<endl;
    close(c_sock);
    return 0;
}