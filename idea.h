/*
    Name:    Rounak Kumar Gupta
    Roll:    20BCS185

*/
#define ll long long
#define addMod 16
#define mulMod 17

//calculating multiplicative inverse
ll mulInv(ll num){
	if(num==0)return 16;
	for(ll i=1;i<16;i++){
		if((num*i)%mulMod==1)return i;
	}
	return 0;
}
//calculation additive inverse
ll addInv(ll num){
	if(num==0)return 0;
	return (addMod-num);
}

//cyclic left shift the given string by 6 bit 
string leftShift(string key){
	string second_part=key.substr(0,6);
	string first_part=key.substr(6,key.size()-6);
	return (first_part+second_part);
}

//generating the 28 subkeys for rounds the given 32-bit secret key 
vector<ll>keyGeneration(ll secret_key){
	vector<ll>keys;
	string ans=bitset<32>(secret_key).to_string();
	string temp=ans; 
	while(ans.size()<28*4){
		temp=leftShift(temp);
		ans+=temp;
	}
	//nibbles from long binary string(size>28*4) and converting to integer and storing in key vector
	for(ll i=0;i<28;i++){
		string key=ans.substr(i*4,4);
		ll k=stoi(key,0,2);
		keys.push_back(k);
	}
	//printing the each round keys
	cout<<"Symmetric Encryption Keys for each rounds\n";
	ll c=1;
	for(ll i=0;i<keys.size();i++){
		if(i%6==0){cout<<"Round "<<c<<" Keys: "; c++;}
		cout<<bitset<4>(keys[i]).to_string()<<" "; if(i%6==5)cout<<"\n";
	} 
	cout<<"\n\n";
	return keys;
}
string encodeMessage(string message,vector<ll>keys){
	
	string mssg=message; 
	vector<ll>message_part;
	//splitting the 16-bit message into nibbles and store in message_part as integer
	for(ll i=0;i<4;i++){
		string mp=mssg.substr(i*4,4);
		ll m=stoi(mp,0,2);
		message_part.push_back(m);
	}
	// implementing 4 full-round encryption on split message blok
	ll p1=message_part[0],p2=message_part[1],p3=message_part[2],p4=message_part[3];
	for(ll i=0;i<4;i++){
		ll k1=keys[i*6],k2=keys[i*6+1],k3=keys[i*6+2];
		ll k4=keys[i*6+3],k5=keys[i*6+4],k6=keys[i*6+5];

		ll s1=((p1?p1:16)*k1)%mulMod; if(s1==16)s1=0;
		ll s2=(p2+k2)%addMod;
		ll s3=(p3+k3)%addMod;
		ll s4=((p4?p4:16)*k4)%mulMod; if(s4==16)s4=0;
		ll s5=s1^s3;
		ll s6=s2^s4;
		ll s7=((s5?s5:16)*k5)%mulMod; if(s7==16)s7=0;
		ll s8=(s6+s7)%addMod;
		ll s9=((s8?s8:16)*k6)%mulMod; if(s9==16)s9=0;
		ll s10=(s7+s9)%addMod;
		ll s11=(s1^s9);
		ll s12=(s3^s9);
		ll s13=(s2^s10);
		ll s14=(s4^s10);

		p1=s11; p2=s13; p3=s12; p4=s14;
	}
	//final transformation
	ll c1=((p1?p1:16)*keys[24])%mulMod; if(c1==0)c1=16;
	ll c2=(p2+keys[25])%addMod;
	ll c3=(p3+keys[26])%addMod;
	ll c4=((p4?p4:16)*keys[27])%mulMod; if(c4==0)c4=16;

	string cipher_text="",a;
	a=bitset<4>(c1).to_string(); cipher_text+=a;
	a=bitset<4>(c2).to_string(); cipher_text+=a;
	a=bitset<4>(c3).to_string(); cipher_text+=a;
	a=bitset<4>(c4).to_string(); cipher_text+=a;
	return cipher_text;
}

//generating 28 decryption subkeys from the given secret key
vector<ll>decryptionKey(ll secret_key){
	//subkey generation from secret key
	vector<ll>keys;
	string ans=bitset<32>(secret_key).to_string();
	string temp=ans; 
	while(ans.size()<28*4){
		temp=leftShift(temp);
		ans+=temp;
	}
	for(ll i=0;i<28;i++){
		string key=ans.substr(i*4,4);
		ll k=stoi(key,0,2);
		keys.push_back(k);
	}
	//calculating decryption subkeys according to decryption sidea key handling
	vector<ll>deKeys;
	for(ll i=4;i>0;i--){
		deKeys.push_back(mulInv(keys[6*i]));
		deKeys.push_back(addInv(keys[6*i+1]));
		deKeys.push_back(addInv(keys[6*i+2]));
		deKeys.push_back(mulInv(keys[6*i+3]));
		deKeys.push_back(keys[6*i-2]);
		deKeys.push_back(keys[6*i-1]);
	}
	deKeys.push_back(mulInv(keys[0]));
	deKeys.push_back(addInv(keys[1]));
	deKeys.push_back(addInv(keys[2]));
	deKeys.push_back(mulInv(keys[3]));

	cout<<"Symmetric Decryption Keys for each rounds\n";
	ll c=1;
	for(ll i=0;i<keys.size();i++){
		if(i%6==0){cout<<"Round "<<c<<"  Keys: "; c++;}
		cout<<bitset<4>(deKeys[i]).to_string()<<" "; if(i%6==5)cout<<"\n";
	} 
	cout<<"\n\n";

	return deKeys;
}
string decodeMessage(string cipher_text,vector<ll>keys){
	//splitting the 16-bit message into nibbles and store in message_part as integer
	vector<ll>cipher_part;
	for(ll i=0;i<16;i+=4){
        string tmp=cipher_text.substr(i,4); 
        ll cp=stoi(tmp,0,2);
        cipher_part.push_back(cp);
    }
	// implementing 4 full-round decryption on split cipher block
	ll c1=cipher_part[0],c2=cipher_part[1],c3=cipher_part[2],c4=cipher_part[3];
	for(ll i=0;i<4;i++){
		ll k1=keys[i*6],k2=keys[i*6+1],k3=keys[i*6+2];
		ll k4=keys[i*6+3],k5=keys[i*6+4],k6=keys[i*6+5];

		ll s1=((c1?c1:16)*k1)%mulMod; if(s1==16)s1=0;
		ll s2=(c2+k2)%addMod;
		ll s3=(c3+k3)%addMod;
		ll s4=((c4?c4:16)*k4)%mulMod; if(s4==16)s4=0;
		ll s5=s1^s3;
		ll s6=s2^s4;
		ll s7=((s5?s5:16)*k5)%mulMod; if(s7==16)s7=0;
		ll s8=(s6+s7)%addMod;
		ll s9=((s8?s8:16)*k6)%mulMod; if(s9==16)s9=0;
		ll s10=(s7+s9)%addMod;
		ll s11=s1^s9;
		ll s12=s3^s9;
		ll s13=s2^s10;
		ll s14=s4^s10;

		c1=s11; c2=s13; c3=s12; c4=s14;
	}
	// final decryption
	ll p1=(c1*keys[24])%mulMod; if(c1==0)c1=16;
	ll p2=(c2+keys[25])%addMod;
	ll p3=(c3+keys[26])%addMod;
	ll p4=(c4*keys[27])%mulMod; if(c4==0)c4=16;

	string a,message="";
	a=bitset<4>(p1).to_string(); message+=a;
	a=bitset<4>(p2).to_string(); message+=a;
	a=bitset<4>(p3).to_string(); message+=a;
	a=bitset<4>(p4).to_string(); message+=a; 
	return message;
}
