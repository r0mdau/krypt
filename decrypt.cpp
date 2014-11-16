/**
 *  Projet Krypt : Cryptage, Decryptage, Hashage de fichiers
 *  Projet de cours EPSI : Sylvain Labasse
 *  @author Enzo SANDRE <esandre@epsi.fr>
 *  @author Romain DAUBY <rdauby@epsi.fr>
 *  @author Thomas LORENZATO <tlorenzato@epsi.fr>
 */

#include "decrypt.h"

static void decryptOctet(int sum, std::array<unsigned int, 8> t, int index, std::array<bool, 8>);

/**
 * @brief Concaténe un tableau de bits dans un bitArray
 * @param Le tableau d'origine
 * @return Le bitArray correspondant
 */
static bitArray concatenateBit(std::array<bool, 8> octet);

static void testConcatenateBit() {
    bitArray toTest;
    std::array<bool, 8> origin;
    origin[0] = 0; origin[1] = 1; origin[2] = 1; origin[3] = 0;
    origin[4] = 1; origin[5] = 1; origin[6] = 0; origin[7] = 1;
    toTest = concatenateBit(origin);
    for(unsigned int i = 0; i < 8; ++i) assert(origin[i] == toTest[i]);
}

byteArray decryptIntArray(intArray const& cryptedBuffer, publicKey const& key){
    byteArray decryptedArray;
    for(auto const& val : cryptedBuffer){
        unsigned int s = (val * key.m) % key.b;
        std::array<bool, 8> octet;
        decryptOctet(s, key.t, 7, octet);
        decryptedArray.push_back(*(fromBitArray<byte>(concatenateBit(octet)).begin()));
    }
    return decryptedArray;
}

static void decryptOctet(int sum, std::array<unsigned int, 8> t, int index, std::array<bool, 8> octet){
    if((signed int)(sum - t[index]) >= 0 && sum > 0){
        sum -= t[index];
        octet[index] = 1;
        decryptOctet(sum, t, --index, octet);
    }else if ((signed int)(sum - t[index]) < 0 && sum > 0){
        decryptOctet(sum, t, --index, octet);
    }
}

static bitArray concatenateBit(std::array<bool, 8> octet){
    bitArray byte;
    for(unsigned int i : octet) byte.push_back(i);
    return byte;
}

#ifdef TEST
void testDecrypt() {
    testConcatenateBit();
}
#endif
