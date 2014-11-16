/**
 *  Projet Krypt : Cryptage, Decryptage, Hashage de fichiers
 *  Projet de cours EPSI : Sylvain Labasse
 *  @author Enzo SANDRE <esandre@epsi.fr>
 *  @author Romain DAUBY <rdauby@epsi.fr>
 *  @author Thomas LORENZATO <tlorenzato@epsi.fr>
 */

#ifndef DECRYPT_H
#define DECRYPT_H

#ifdef TEST
#include <cassert>
#endif
#include <array>

#include "bitConvert.h"
#include "key.h"

/**
 * @brief Décrypte un tableau d'entier grace à une clé publique.
 * @param cryptedBuffer : Le tableau crypté
 * @param key : la clé publique
 * @return le tableau d'octets décryptés.
 */
byteArray decryptIntArray(intArray const& cryptedBuffer, publicKey const& key);

#ifdef TEST
void testDecrypt();
#endif

#endif // DECRYPT_H
