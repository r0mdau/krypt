/**
 *  Projet Krypt : Cryptage, Decryptage, Hashage de fichiers
 *  Projet de cours EPSI : Sylvain Labasse
 *  @author Enzo SANDRE <esandre@epsi.fr>
 *  @author Romain DAUBY <rdauby@epsi.fr>
 *  @author Thomas LORENZATO <tlorenzato@epsi.fr>
 */

#ifndef KEY_H
#define KEY_H

#define USE_RANDOM
#define TEST_PAS_T 5

#ifdef TEST
#include <cassert>
#endif

#include <array>
#include <climits>
#include "bitConvert.h"
#include "random.h"
#include "pgcd.h"

enum ErrMsg_Key {
    ERREUR_MODULAR_INVERSE
};

struct publicKey {
    unsigned int b;
    unsigned int m;
    std::array<unsigned int, 8> t;
};

struct privateKey {
    unsigned int a;
    publicKey pub;
};

/**
 * @brief Génére une clé privée aléatoire
 * @return la clé
 */
privateKey generateKey();

/**
 * @brief Extrait la partie publique d'une clé privée
 * @param key : la clé privée
 * @return la clé publique
 */
publicKey getPublic(privateKey const& key);

/**
 * @brief Sérialise une clé privée
 * @param key : La clé privée à sérialiser
 * @return La clé sérialisée en un tableau d'entiers
 */
intArray serializeKey(privateKey const& key);

/**
 * @brief Sérialise une clé publique
 * @param key : La clé publique à sérialiser
 * @return La clé sérialisée en un tableau d'entiers
 */
intArray serializeKey(publicKey const& key);

/**
 * @brief Déserialise une clé privée
 * @param orig : Le tableau d'entiers représentant la clé
 * @return La clé désérialisée
 */
privateKey unserializePrivateKey(intArray const& orig);

/**
 * @brief Déserialise une clé publique
 * @param orig : Le tableau d'entiers représentant la clé
 * @return La clé désérialisée
 */
publicKey unserializePublicKey(intArray const& orig);

#ifdef TEST
void testKey();
#endif

#endif // KEY_H
