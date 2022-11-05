/*
    Name:    Rounak Kumar Gupta
    Roll:    20BCS185

*/
/*----->>>>>>>>Elgamal header file<<<<<<<<<--------*/

#define ll long long
using namespace std;

/*----->>>>>>>> To check if a number is prime or not <<<<<<<<<--------*/
bool isPrime(ll n){        
    
    for(ll i=2;i<n;i++){
        if(n%i==0) return 0;
    }
    return 1;
}

/*----->>>>>>>> For calculating the public key parameter 'e1' <<<<<<<<<--------*/
ll primitiveRoot(ll p,ll d){
    ll n=0;
    while(1){
        n=rand()%p;
        if(__gcd(n,d)==1 && n!=0){
            return n;
        }
    }
    return 0;
}

/*----->>>>>>>> For fast exponentiation <<<<<<<<<--------*/
ll FastExponention(ll bit, ll n, ll* y, ll* a)
{
    if (bit == 1) {
        *y = (*y * (*a)) % n;
    }
 
    *a = (*a) * (*a) % n;
    return 0;
}
/*----->>>>>>>> For calculating public key parameter 'e2' <<<<<<<<<--------*/
ll power(ll a, ll m, ll n)
{
    ll r;
    ll y = 1;
 
    while (m > 0)
    {
        r = m % 2;
        FastExponention(r, n, &y, &a);
        m = m / 2;
    }
 
    return y;
}
/*----->>>>>>>> For generating the public key(e1,e2,p) and private key(d) <<<<<<<<<--------*/
vector<ll> elgamal_key_generation(ll p){
    
    ll d=0;
    while(d==0){
        d=rand()%(p-1);
    }
    ll e1=primitiveRoot(p,d);
    ll e2=power(e1,d,p);
    vector<ll> v={e1,e2,p,d};
    return v;

}
/*----->>>>>>>> For decrypting the cypher text(C1,C2) using private key 'd'  <<<<<<<<<--------*/
ll elgamal_decryption(ll secret_key[],ll private_key[]){
    ll C1=secret_key[0];
    ll C2=secret_key[1];
    ll d=private_key[0];
    ll p=private_key[1];
    ll decipher = C2 * power(C1, p - 1 - d, p) % p;
    return decipher;
}
/*----->>>>>>>> For converting a binary string to decimal number <<<<<<<<<--------*/
ll binaryToDecimal(string n)
{
    string num = n;
    ll dec_value = 0;
 
    ll base = 1;
 
    ll len = num.length();
    for (ll i = len - 1; i >= 0; i--) {
        if (num[i] == '1')
            dec_value += base;
        base = base * 2;
    }
 
    return dec_value;
}
/*----->>>>>>>> For calculating power(a,m)%n <<<<<<<<<--------*/
ll FindT(ll a, ll m, ll n)
{
    ll r;
    ll y = 1;
 
    while (m > 0)
    {
        r = m % 2;
        FastExponention(r, n, &y, &a);
        m = m / 2;
    }
 
    return y;
}
/*----->>>>>>>> For encrypting the secret key <<<<<<<<<--------*/
vector<ll> elgamal_encryption(ll secret_key,ll server_public_key[]){
	ll e1,e2,p;                //public key 
	e1=server_public_key[0];
	e2=server_public_key[1];
	p=server_public_key[2];
	ll r;
    do {
        r = rand() % (p - 1) + 1;        // 1 < r < p
    }
    while (gcd(r, p) != 1);
    ll C1 = FindT(e1, r, p);    //power(e1,r)%p
    ll C2 = FindT(e2, r, p) * secret_key % p;  //power(e2,r)%p
	vector<ll> cipher_key={C1,C2};
	return cipher_key;
}
