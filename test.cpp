/**
 *  Projet Krypt : Cryptage, Decryptage, Hashage de fichiers
 *  Projet de cours EPSI : Sylvain Labasse
 *  @author Enzo SANDRE <esandre@epsi.fr>
 *  @author Romain DAUBY <rdauby@epsi.fr>
 *  @author Thomas LORENZATO <tlorenzato@epsi.fr>
 */

#ifndef TEST_CPP
#define TEST_CPP
    #ifdef TEST
        #include <iostream>
        #include "bitConvert.h"
        #include "key.h"
        #include "hash.h"
        #include "crypt.h"
        #include "decrypt.h"

        void testMain(){
            std::cerr << "Test bitConvert ..." << std::endl;
            testBitConvert();
            std::cerr << "Test key ..." << std::endl;
            testKey();
            std::cerr << "Test hash ..." << std::endl;
            testHash();
            std::cerr << "Test crypt ..." << std::endl;
            testCrypt();
            std::cerr << "Test decrypt ..." << std::endl;
            testDecrypt();
            std::cerr << "Tous les tests ont réussi !" << std::endl;
        }
    #endif
#endif
