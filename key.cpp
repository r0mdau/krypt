#include "key.h"

/**
 * @brief Génére la suite supercroissante T
 * @param key : la clé à modifier
 * @param sumOfT : pointeur pour récupérer la somme des valeurs du tableau
 */
static void generateT(privateKey& key, unsigned int* sumOfT);

/**
 * @brief Génére les nombres a et b, b plus grand que la somme du tableau T
 * @param key : la clé à modifier
 * @param sumOfT : la somme du tableau T utilisée pour calculer B
 */
static void generateAB(privateKey& key, unsigned int sumOfT);

/**
 * @brief -
 * @param key : la clé à modifier
 * @todo : Clarifier et expliquer clairement ce bordel et son rôle.
 */
static void generateM(privateKey& key);

/*-------------------------------------------------------------------------------------------------*/

#ifdef TEST
static void testGenerateT() {

    /**--TEST 1 : sumOfT == somme(T) **/
    {
        privateKey keyContainer;
        unsigned int sumContainer = 0;

        unsigned int sumOfValues = 0;
        generateT(keyContainer, &sumContainer);
        for(auto const i : keyContainer.pub.t) {
            sumOfValues += i;
        }
        assert(sumOfValues == sumContainer);
    }

    /**--TEST 2 : T est supercroissante **/
    {
        privateKey keyContainer;
        unsigned int sumContainer = 0;

        unsigned int sumOfValues = 0;
        generateT(keyContainer, &sumContainer);
        for(auto const i : keyContainer.pub.t) {
            assert(i > sumOfValues);
            sumOfValues += i;
        }
    }

    /**--TEST 3 : T ne vaut pas les valeurs d'origine **/
    {
        privateKey keyContainer;
        std::array<unsigned int, 8> originTable;
        for(unsigned int i = 0; i < 8; ++i){
            originTable[i] = keyContainer.pub.t[i];
        }
        unsigned int sumContainer = 0;
        unsigned short matches = 0;

        generateT(keyContainer, &sumContainer);
        for(unsigned int i = 0; i < 8; ++i){
            if(keyContainer.pub.t[i] == originTable[i]) matches++;
        }
        assert(matches < 3);
    }
}

static void testGenerateAB() {
    privateKey key;
    unsigned const int sumOfT = 15677;
    generateAB(key, sumOfT);

    assert(key.pub.b > sumOfT);
    assert(pgcd(key.a, key.pub.b) == 1);
    assert(key.a < key.pub.b);
}

static void testGenerateM() {
    privateKey key;
    key.a = 204;
    key.pub.b = 709;
    generateM(key);

    assert(key.pub.m == 497);
    assert((key.pub.m * key.a) % key.pub.b == 1);
}

static void testSerialization() {
    privateKey prk;
    publicKey pub = getPublic(prk);

    privateKey newPrk = unserializePrivateKey(serializeKey(prk));
    publicKey newPub = unserializePublicKey(serializeKey(pub));
    assert(newPrk.a == prk.a);

    assert(newPrk.pub.b == prk.pub.b);
    assert(newPrk.pub.m == prk.pub.m);
    assert(newPub.b == pub.b);
    assert(newPub.m == pub.m);

    for(unsigned int i = 0; i < 8; ++i){
        assert(newPrk.pub.t[i] == prk.pub.t[i]);
        assert(newPub.t[i] == pub.t[i]);
    }
}

#endif

privateKey generateKey() {
    privateKey key;
    unsigned int* sumOfT = new unsigned int(0);

    generateT(key, sumOfT);
    generateAB(key, *sumOfT);
    delete sumOfT;

    generateM(key);
    return key;
}

publicKey getPublic(privateKey const& key) {
    return key.pub;
}

static void generateT(privateKey& key, unsigned int* sumOfT) {
    *sumOfT = 0;
    unsigned const int limit = INT_MAX / 64;
    for(unsigned int i = 0; i < 8; i++){
        #ifdef USE_RANDOM
            key.pub.t[i] = random(*sumOfT + 1, (i+1) * limit);
        #else
            key.pub.t[i] = *sumOfT + TEST_PAS_T;
        #endif
        *sumOfT += key.pub.t[i];
    }
}

static void generateAB(privateKey& key, unsigned int sumOfT) {
    #ifdef USE_RANDOM
        key.pub.b = random(sumOfT, (unsigned int)2 * INT_MAX);
        key.a = random((unsigned int)0, key.pub.b - 1);
    #else
        key.pub.b = sumOfT + TEST_PAS_T;
        key.a = key.pub.b - 1;
    #endif
    while(pgcd(key.a, key.pub.b) > 1 && key.a > 0) {
        key.a --;
    }
    if(key.a == 0) {
        //On ajoute 1 à sumOfT si on est pas en mode random. Sinon la boucle serait infinie.
        #ifdef USE_RANDOM
            generateAB(key, sumOfT);
        #else
            generateAB(key, sumOfT + 1);
        #endif
    } else return;
}

static void generateM(privateKey& key) {
    long int no = key.pub.b, bo = key.a, to = 0, t = 1, temp;
    long int q = no / bo;
    long int r = no - q * bo;
    while(r > 0){
        temp = to - q * t;

        if(temp >= 0) {
            temp %= key.pub.b;
        } else {
            temp = key.pub.b - ((-temp) % key.pub.b);
        }

        to = t;
        t = temp;
        no = bo;
        bo = r;
        q = no / bo;
        r = no - q * bo;
    }
    if(bo != 1) throw int(ERREUR_MODULAR_INVERSE);
    else key.pub.m = t;
}


intArray serializeKey(privateKey const& key) {
    intArray array;
    array.push_back(key.a);
    array.push_back(key.pub.b);
    array.push_back(key.pub.m);
    for(unsigned int i = 0; i < 8; ++i)
        array.push_back(key.pub.t[i]);
    return array;
}

intArray serializeKey(publicKey const& key) {
    intArray array;
    array.push_back(key.b);
    array.push_back(key.m);
    for(unsigned int i = 0; i < 8; ++i)
        array.push_back(key.t[i]);
    return array;
}

privateKey unserializePrivateKey(intArray const& orig) {
    privateKey key;
    key.a = orig[0];
    key.pub.b = orig[1];
    key.pub.m = orig[2];
    for(unsigned int i = 0; i < 8; ++i)
        key.pub.t[i] = orig[i + 3];
    return key;
}

publicKey unserializePublicKey(intArray const& orig) {
    publicKey key;
    key.b = orig[0];
    key.m = orig[1];
    for(unsigned int i = 0; i < 8; ++i)
        key.t[i] = orig[i + 2];
    return key;
}

#ifdef TEST
void testKey() {
    testGenerateT();
    testGenerateAB();
    testGenerateM();
    testSerialization();
}
#endif
