/**
 *  Projet Krypt : Cryptage, Decryptage, Hashage de fichiers
 *  Projet de cours EPSI : Sylvain Labasse
 *  @author Enzo SANDRE <esandre@epsi.fr>
 *  @author Romain DAUBY <rdauby@epsi.fr>
 *  @author Thomas LORENZATO <tlorenzato@epsi.fr>
 */

#ifndef RANDOM_H
#define RANDOM_H

#include <random>

inline int random(int min, int max) {
    static std::default_random_engine generator;
    std::uniform_int_distribution<int> distribution(min, max);
    return distribution(generator);
}

#endif // RANDOM_H
