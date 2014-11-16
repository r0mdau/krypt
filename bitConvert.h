/**
 *  Projet Krypt : Cryptage, Decryptage, Hashage de fichiers
 *  Projet de cours EPSI : Sylvain Labasse
 *  @author Enzo SANDRE <esandre@epsi.fr>
 *  @author Romain DAUBY <rdauby@epsi.fr>
 *  @author Thomas LORENZATO <tlorenzato@epsi.fr>
 */

#ifndef BITCONVERT_H
#define BITCONVERT_H

#ifdef TEST
#include <cassert>
#endif

#include <vector>
#include <cmath>

typedef bool bit;
typedef unsigned char byte;
typedef std::vector<byte> byteArray;
typedef std::vector<bit> bitArray;
typedef std::vector<unsigned int> intArray;

enum ErrMsg_BitConvert {
    INVALID_BIT_ARRAY_LENGHT = 201
};

/**
 * @brief Découpe un tableau en tableau de bits
 * @param array : le tableau template
 * @return bitArray : le tableau de bits correspondant
 */
template <typename T>
bitArray toBitArray(std::vector<T> const& array) {
    bitArray newArray;
    T const initialMask = pow(2, (sizeof(T) * 8) -1);
    for(auto const& i : array) {
        for(T mask = initialMask; mask >= 0x1; mask /= 2)
            newArray.push_back(i & mask);
    }
    return newArray;
}

/**
 * @brief Concaténe un tableau de bits en tableau de variables
 * @param array : le tableau de bits
 * @return byteArray : le tableau template
 */
template <typename T>
std::vector<T> fromBitArray(bitArray const& array) {
    unsigned int const bitLenght = sizeof(T) * 8;
    int const nbOfFinalValues = array.size()/bitLenght;
    T const initialMask = pow(2, bitLenght-1);

    if(array.size() % 8 || !nbOfFinalValues) throw int(INVALID_BIT_ARRAY_LENGHT);

    std::vector<T> newArray;
    newArray.assign(nbOfFinalValues, 0);

    bitArray::const_iterator _bit = array.begin();
    for(auto& i : newArray) {
        for(T mask = initialMask; mask >= 0x1; mask /= 2) {
            i += (*_bit++) * mask;
        }
    }

    return newArray;
}

#ifdef TEST
void testBitConvert();
#endif

#endif
