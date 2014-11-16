/**
 *  Projet Krypt : Cryptage, Decryptage, Hashage de fichiers
 *  Projet de cours EPSI : Sylvain Labasse
 *  @author Enzo SANDRE <esandre@epsi.fr>
 *  @author Romain DAUBY <rdauby@epsi.fr>
 *  @author Thomas LORENZATO <tlorenzato@epsi.fr>
 */

#include "crypt.h"

/**
 * @brief Génére le tableau u
 * @param u : le tableau à remplir
 * @param t : le tableau de valeurs t
 * @param a
 * @param b
 */
static void generateUTab(int u[], std::array<unsigned int, 8> t, unsigned int const a, unsigned int const b);

/**
 * @brief Renvoie un octet encrypté
 * @param u : le tableau d'encryption
 * @param byte : l'octet à encrypter
 * @return int : l'entier correspondant a l'octet encrypté
 */
static int getEncryptOctet(int const u[], byte octet);

intArray crypt(byteArray const& mainBuffer, privateKey const& key){
    intArray cryptedArray;
    int u[] = {0};
    generateUTab(u, key.pub.t, key.a, key.pub.b);
    for(auto const& octet : mainBuffer){
        cryptedArray.push_back(getEncryptOctet(u, octet));
    }
    return cryptedArray;
}

static void generateUTab(int u[], std::array<unsigned int, 8> t, unsigned int const a, unsigned int const b){
    for(unsigned int i = 0; i < 8; ++i){
        u[i] = (t[i] * a ) % b;
    }
}

static int getEncryptOctet(int const u[], byte const octet) {
    unsigned int i = 0;
    int s = 0;
    for(byte mask = 1 << 7; mask != 0; mask = mask >> 1){
        if(octet & mask) s+=u[i++];
    }
    return s;
}

#ifdef TEST
void testCrypt() {
}
#endif
