/**
 *  Projet Krypt : Cryptage, Decryptage, Hashage de fichiers
 *  Projet de cours EPSI : Sylvain Labasse
 *  @author Enzo SANDRE <esandre@epsi.fr>
 *  @author Romain DAUBY <rdauby@epsi.fr>
 *  @author Thomas LORENZATO <tlorenzato@epsi.fr>
 */

#ifndef PGCD_H
#define PGCD_H

/**
 * @brief Calcule le PGCD de deux nombres
 * @param a
 * @param b
 * @return PGCD
 */
inline int pgcd(int a,int b){
    return a%b ? pgcd(b, a%b) : b;
}
#endif // PGCD_H
