/**
 *  Projet Krypt : Cryptage, Decryptage, Hashage de fichiers
 *  Projet de cours EPSI : Sylvain Labasse
 *  @author Enzo SANDRE <esandre@epsi.fr>
 *  @author Romain DAUBY <rdauby@epsi.fr>
 *  @author Thomas LORENZATO <tlorenzato@epsi.fr>
 */

#ifndef HASH_H
#define HASH_H

#ifdef TEST
#include <cassert>
#include "random.h"
#endif

#include "bitConvert.h"

enum ErrMsg_Hash {
    STRING_TOO_SHORT = 100
};

/**
 * @brief Hashe une chaîne d'octets
 * @param str : La chaîne à hasher
 */
void hashByteArray(byteArray& str);

#ifdef TEST
void testHash();
#endif

#endif // HASH_H
