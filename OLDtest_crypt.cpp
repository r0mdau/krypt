/**
 *  Projet Krypt : Cryptage, Decryptage, Hashage de fichiers
 *  Projet de cours EPSI : Sylvain Labasse
 *  @author Enzo SANDRE <esandre@epsi.fr>
 *  @author Romain DAUBY <rdauby@epsi.fr>
 *  @author Thomas LORENZATO <tlorenzato@epsi.fr>
 */


#include "assert.h"
#include "crypt.h"

int main(){
    //BEGIN test function generateSortTable
        int t[8];
        generateSortTable(t);
        assert(t[1] == t[0] + 1);
        assert(t[2] == t[0] + t[1] + 1);
        assert(t[3] == t[0] + t[1] + t[2] + 1);
        assert(t[4] == t[0] + t[1] + t[2] + t[3] + 1);
        assert(t[5] == t[0] + t[1] + t[2] + t[3] + t[4] + 1);
        assert(t[6] == t[0] + t[1] + t[2] + t[3] + t[4] + t[5] + 1);
        assert(t[7] == t[0] + t[1] + t[2] + t[3] + t[4] + t[5] + t[6] + 1);
    //END
   
    //BEGIN test function computeModularInverse
        int a = 204, b = 709;
        assert(computeModularInverse(a, b) == 497);
        assert((computeModularInverse(a, b) * a) % b == 1);
    //END
    
    //BEGIN test function generateUTab
        int u[8];
        generateUTab(u, t, a, b);
        for(int i = 0; i < 8; ++i)
            assert(u[i] == (t[i] * a ) % b);
    //END
    
    //BEGIN test function pgcd
    // sources for verification http://trucsmaths.free.fr/js_pgcd.htm    
        assert(pgcd(a, b) == 1);
        assert(pgcd(5, 1) == 1);
        assert(pgcd(498, 90) == 6);
        assert(pgcd(90, 498) == 6);
        assert(pgcd(2797, 498) == 1);
    //END
    
    //BEGIN test function sumIntegersOfTable
        int k[90] = {0};
        assert(sumIntegersOfTable(k, 90) == 0);
        k[8] = 100; k[56] = 67;
        assert(sumIntegersOfTable(k, 90) == 167);
        k[80] = 10; k[40] = -10;
        assert(sumIntegersOfTable(k, 90) == 167);
    //END
    
    //BEGIN test function chooseAandB
        b = sumIntegersOfTable(t, 8) + 1;
        chooseAandB(a, b, t);
        assert(pgcd(a, b) == 1);
        assert(a < b);
    //END
    
    //BEGIN test function getEncryptOctet
    /// source for conversion http://home.paulschou.net/tools/xlate/
    /// Y is related to 01011001 as in example for the project
        int te[8] = {612, 311, 622, 30, 60, 625, 143, 286};
        assert(getEncryptOctet(te, 'Y') == 687);
    //END
}
