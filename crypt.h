/**
 *  Projet Krypt : Cryptage, Decryptage, Hashage de fichiers
 *  Projet de cours EPSI : Sylvain Labasse
 *  @author Enzo SANDRE <esandre@epsi.fr>
 *  @author Romain DAUBY <rdauby@epsi.fr>
 *  @author Thomas LORENZATO <tlorenzato@epsi.fr>
 */

#ifndef CRYPT_H
#define CRYPT_H

#ifdef TEST
#include <cassert>
#endif

#include "bitConvert.h"
#include "key.h"

/**
 * @brief Crypte une chaine d'octets
 * @param input : la chaîne d'octets
 * @return un tableau d'entiers correspondant aux octets encryptés.
 */
intArray crypt(byteArray const& input, privateKey const& key);

#ifdef TEST
void testCrypt();
#endif


#endif // CRYPT_H
