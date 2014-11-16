/**
 *  Projet Krypt : Cryptage, Decryptage, Hashage de fichiers
 *  Projet de cours EPSI : Sylvain Labasse
 *  @author Enzo SANDRE <esandre@epsi.fr>
 *  @author Romain DAUBY <rdauby@epsi.fr>
 *  @author Thomas LORENZATO <tlorenzato@epsi.fr>
 */

#include "hash.h"

/**
 * @brief Décale une chaîne de x octets vers la gauche en reportant les octets du début à la fin
 * @param origin : la chaîne à décaler
 * @param decalage : le nombre de bits de décalage
 */
static void rotateLeft(byteArray& origin, unsigned int const shift);

/**
 * @brief Effectue un XOR entre le dernier octet d'un chaîne et un second octet de taille équivalente
 * @param str : la chaîne d'origine
 * @param chr : l'octet servant de second opérande
 */
static void XORLastByte(byteArray& str, byte const& chr);

#ifdef TEST
static void testXORLastByte() {
    /**--TEST 1 : aucune modification autre que le dernier byte ( mais dernier byte modifié )**/
    {
        byteArray string;
        for(unsigned int i = 0; i < 8; ++i) string.push_back(random(0, 255));
        byteArray origin(string);

        XORLastByte(string, 212);
        for(unsigned int i = 0; i < 7; ++i) assert(origin[i] == string[i]);
        assert(origin[8] != string[8]);
    }

    /**--TEST 2 : Test du XOR lui même ( valeurs spéciales ) **/
    {
        byteArray string;
        string.assign(8, 0);

        string[8] = 143;
        XORLastByte(string, 212);
        assert(string[8] == 91);

        string[8] = 75;
        XORLastByte(string, 2);
        assert(string[8] == 73);

        string[8] = 0;
        XORLastByte(string, 66);
        assert(string[8] == 66);

        string[8] = 112;
        XORLastByte(string, 0);
        assert(string[8] == 112);

        string[8] = 200;
        XORLastByte(string, 1);
        assert(string[8] == 201);
    }
}

static void testRotateLeft() {
    /**--TEST 1 : Un octet**/
    {
        bitArray octet({1,0,0,1, 1,1,0,1});
        bitArray needle({1,0,1,1, 0,0,1,1});

        byteArray buffer = fromBitArray<byte>(octet);
        rotateLeft(buffer, 5);
        octet = toBitArray(buffer);

        for(unsigned int i = 0; i < 8; ++i) assert(octet[i] == needle[i]);
    }

    /**--TEST 2 : Une chaine**/
    {
        bitArray chaine({1,0,1,1, 1,1,1,1,
                        1,0,0,1, 1,1,0,1,
                        0,1,1,1, 0,0,0,1,
                        1,0,1,0, 1,0,0,0,
                        1,0,1,1, 0,1,0,1});
        bitArray needle({1,1,0,0, 1,1,1,0,
                        1,0,1,1, 1,0,0,0,
                        1,1,0,1, 0,1,0,0,
                        0,1,0,1, 1,0,1,0,
                        1,1,0,1, 1,1,1,1});

        byteArray buffer = fromBitArray<byte>(chaine);
        rotateLeft(buffer, 7);
        chaine = toBitArray(buffer);

        for(unsigned int i = 0; i < chaine.size(); ++i) assert(chaine[i] == needle[i]);
    }
}
#endif

void hashByteArray(byteArray& str) {
    unsigned int size = str.size();
    if(size < 1) throw int(STRING_TOO_SHORT);

    for(unsigned int i = 0; i != size; ++i) {
        byte const lastByte = *(str.end());
        rotateLeft(str, 5);
        XORLastByte(str, lastByte);
    }
}

static void rotateLeft(byteArray& origin, unsigned int const shift) {
    unsigned int const shift_mod_8 = shift % 8;
    unsigned int const shift_on_8 = shift / 8;

    //On dégrossit en décalant d'un coup les octets entiers
    for(unsigned int i=0; i!= shift_on_8; ++i) {
        origin.push_back(origin[0]);
        origin.erase(origin.begin());
    }

    //On finit en bit à bit
    if(shift_mod_8) {
        bitArray array = toBitArray(origin);
        for(unsigned int i=0; i != shift_mod_8; ++i) {
            array.push_back(array[0]);
            array.erase(array.begin());
        }
        origin = fromBitArray<byte>(array);
    }
}

static void XORLastByte(byteArray& str, byte const& chr) {
    *str.end() ^= chr;
}

#ifdef TEST
void testHash() {
    testXORLastByte();
    testRotateLeft();
}
#endif
