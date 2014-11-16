/**
 *  Projet Krypt : Cryptage, Decryptage, Hashage de fichiers
 *  Projet de cours EPSI : Sylvain Labasse
 *  @author Enzo SANDRE <esandre@epsi.fr>
 *  @author Romain DAUBY <rdauby@epsi.fr>
 *  @author Thomas LORENZATO <tlorenzato@epsi.fr>
 */

#include <iostream>
#include <string>
#include <argp.h>
#include <fstream>
#include <map>

#include "test.cpp"

#include "crypt.h"
#include "decrypt.h"
#include "hash.h"
#include "key.h"

using namespace std;

/**
 * @brief Structure globale ( oui c'est trop pas bien, mais avec ArgP je peux pas faire beaucoup mieux )
 *  Résume l'etat du programme et les paramétres d'entrée.
 */
static struct krypt_status {
    std::map<int, std::string> parsed_opts;
    union {
        struct {
            std::ofstream* prkOutput;
            std::ofstream* pubOutput;
        };
        struct {
            union {
                std::ifstream* prkInput;
                std::ifstream* pubInput;
            };
            union {
                std::ofstream* outputFile;
                std::ifstream* footprintFile;
            };
            std::ifstream* inputFile;
        };
    };
} status;

/**
 * @brief Codes d'erreur globaux, on ne fait ni cout, ni cerr dans les modules, le main se réserve ce droit.
 *  A la place les modules renvoient des codes d'erreur si ils n'ont pas réussi à gérer la couille en interne.
 *  Codes d'erreurs propres aux modules à ajouter dans les modules mêmes via un enum
 */
enum ErrMsg {
    NO_ERROR = 0,
    UNKNOWN_ERROR = 1,
    NOTHING_TO_DO = 2,
    MORE_THAN_1_COMMAND = 3,
    FILE_PATH_EMPTY = 4,
    FILE_ACCESS_ERROR = 5,
    FILE_IS_EMPTY = 6,
    NO_PRK_OUTPUT = 7,
    NO_PUB_OUTPUT = 8,
    PRK_OUTPUT_EMPTY = 9,
    PUB_OUTPUT_EMPTY = 10,
    PRK_OUTPUT_OPEN_ERR = 11,
    PUB_OUTPUT_OPEN_ERR = 12,
    OUTPUT_PATH_EMPTY = 13,
    OUTPUT_FILE_ERR = 14,
    INPUT_PATH_EMPTY = 15,
    INPUT_FILE_ERR = 16,
    INPUT_FILE_EMPTY = 17,
    PUB_INPUT_PATH_EMPTY = 18,
    PUB_INPUT_OPEN_ERR = 19,
    PUB_INPUT_FILE_EMPTY = 20,
    PRK_INPUT_PATH_EMPTY = 21,
    PRK_INPUT_OPEN_ERR = 22,
    PRK_INPUT_FILE_EMPTY = 23,
    NO_PUB_INPUT = 24,
    NO_PRK_INPUT = 25,
    NO_FOOTPRINT_INPUT = 26,
    FOOTPRINT_INPUT_PATH_EMPTY = 27,
    FOOTPRINT_INPUT_OPEN_ERR = 28,
    FOOTPRINT_INPUT_FILE_EMPTY = 29
};

/**
 * @brief Renvoie un massage d'erreur selon le code.
 * @param errorCode : le code d'erreur
 * @return string : le message d'erreur
 */
std::string getErrMsg(int errorCode) {
    switch (errorCode) {
    case NO_ERROR:
        return "Aucune Erreur";
        break;
    case NOTHING_TO_DO:
        return "Aucune action à exécuter";
        break;
    case MORE_THAN_1_COMMAND:
        return "Plus d'une commande spécifiée dans les arguments";
        break;
    case FILE_PATH_EMPTY:
        return "Chemin du fichier vide";
        break;
    case FILE_ACCESS_ERROR:
        return "Erreur d'accés au fichier";
        break;
    case FILE_IS_EMPTY:
        return "Fichier vide en lecture seule";
        break;
    case NO_PRK_OUTPUT:
        return "Pas de chemin spécifié pour la sortie de la clé privée";
        break;
    case NO_PUB_OUTPUT:
        return "Pas de chemin spécifié pour la sortie de la clé publique";
        break;
    case PRK_OUTPUT_EMPTY:
        return "Chemin spécifié pour la sortie de la clé privée vide";
        break;
    case PUB_OUTPUT_EMPTY:
        return "Chemin spécifié pour la sortie de la clé publique vide";
        break;
    case PRK_OUTPUT_OPEN_ERR:
        return "Erreur d'accés à la sortie de la clé privée";
        break;
    case PUB_OUTPUT_OPEN_ERR:
        return "Erreur d'accés à la sortie de la clé publique";
        break;
    case OUTPUT_PATH_EMPTY:
        return "Chemin du fichier de sortie vide";
        break;
    case OUTPUT_FILE_ERR:
        return "Erreur d'accés au fichier de sortie";
        break;
    case INPUT_PATH_EMPTY:
        return "Chemin du fichier d'entrée vide";
        break;
    case INPUT_FILE_ERR:
        return "Erreur d'accés au fichier d'entrée";
        break;
    case INPUT_FILE_EMPTY:
        return "Fichier d'entrée vide";
        break;
    case PUB_INPUT_PATH_EMPTY:
        return "Chemin spécifié pour l'entrée de la clé publique vide";
        break;
    case PUB_INPUT_OPEN_ERR:
        return "Erreur d'accés au fichier d'entrée de la clé publique";
        break;
    case PUB_INPUT_FILE_EMPTY:
        return "Clé publique vide";
        break;
    case PRK_INPUT_PATH_EMPTY:
        return "Chemin spécifié pour l'entrée de la clé privée vide";
        break;
    case PRK_INPUT_OPEN_ERR:
        return "Erreur d'accés au fichier d'entrée de la clé privée";
        break;
    case PRK_INPUT_FILE_EMPTY:
        return "Clé privée vide";
        break;
    case NO_PUB_INPUT:
        return "Pas de clé publique spécifiée";
        break;
    case NO_PRK_INPUT:
        return "Pas de clé privée spécifiée";
        break;
    case NO_FOOTPRINT_INPUT:
        return "Pas de fichier empreinte spécifiée";
        break;
    case FOOTPRINT_INPUT_PATH_EMPTY:
        return "Chemin spécifié pour l'entrée de l'empreinte vide";
        break;
    case FOOTPRINT_INPUT_OPEN_ERR:
        return "Erreur d'accés au fichier d'empreinte";
        break;
    case FOOTPRINT_INPUT_FILE_EMPTY:
        return "Fichier d'empreinte vide";
        break;
    case UNKNOWN_ERROR:
    default:
        return "Erreur inconnue";
        break;
    }
}

/**
 * @brief Callback de argp, les options sont parsées séquentiellement et mises dans la structure globale.
 */
int parse_opt (int key, char *arg, struct argp_state *state)
{   state++;state --;
    status.parsed_opts[key] = std::string(arg != NULL ? arg : "");
    return 0;
}

void openReadFile(
        std::string const& path,
        std::ifstream** stream,
        int emptyFilePathErrCode = FILE_PATH_EMPTY,
        int fileAccessErrCode = FILE_ACCESS_ERROR,
        int fileEmptyErrCode = FILE_IS_EMPTY
        ) throw(int) {
    if(path.empty()) throw int(emptyFilePathErrCode);
    if(*stream != NULL) delete *stream;
    *stream = new std::ifstream(path.c_str(), std::ios::binary);
    if(!(*stream)->is_open()) throw int(fileAccessErrCode);
    if(!(*stream)->good()) throw int(fileEmptyErrCode);
}

void openWriteFile(
        std::string const& path,
        std::ofstream** stream,
        int emptyFilePathErrCode = FILE_PATH_EMPTY,
        int fileAccessErrCode = FILE_ACCESS_ERROR
        ) throw(int) {
    if(path.empty()) throw int(emptyFilePathErrCode);
    if(*stream != NULL) delete *stream;
    *stream = new std::ofstream(path.c_str(), std::ios::trunc | std::ios::binary);
    if(!(*stream)->is_open()) throw int(fileAccessErrCode);
}

int main(int argc, char** argv) {
    #ifdef TEST
        testMain();
    #endif
    try {
        /**
         *  Réglages de ARGP
         */
        try {
            struct argp_option options[] = {
                {"crypt", 'c', "INPUT_FILE", 0, "Crypte le fichier", 0},
                {"decrypt", 'd', "INPUT_FILE", 0, "Décrypte le fichier", 0},
                {"hash", 'h', "INPUT_FILE", 0, "Renvoie l'empreinte du fichier", 0},
                {"generate", 'g', 0, 0, "Génére un paire clés aléatoires", 0},
                {0, 'i', "INPUT_FILE", OPTION_HIDDEN, "Génere l'empreinte d'un fichier", 0},
                {"sign", 0, 0, OPTION_ALIAS, 0, 0},
                {0, 'j', "INPUT_FILE", OPTION_HIDDEN, "Vérifie l'empreinte d'un fichier", 0},
                {"check", 0, 0, OPTION_ALIAS, 0, 0},
                {"footprint", 'f', "FILE", 0, "Spécifie ou trouver l'empreinte pour vérification", 0},
                {0, 'a', "PATH", OPTION_HIDDEN, "Chemin de la clé privée", 0},
                {"prk", 0, 0, OPTION_ALIAS, 0, 0},
                {0, 'b', "PATH", OPTION_HIDDEN, "Chemin de la clé publique", 0},
                {"pub", 0, 0, OPTION_ALIAS, 0, 0},
                {"output", 'o', "OUTPUT_FILE", 0, "Indique le fichier de sortie. stdout si ignoré.", 0},
                {0, 0, 0, 0, 0, 0}
            };

            struct argp argp = {options, parse_opt, 0, 0, 0, 0, 0};
            argp_parse (&argp, argc, argv, 0, 0, 0);
        } catch(int errorCode) {
            cerr << "Le parsage des arguments à échoué." << endl << getErrMsg(errorCode) << endl;
            return errorCode;
        }

        try{
            int nbOfOpts = status.parsed_opts.count('c')
                    + status.parsed_opts.count('d')
                    + status.parsed_opts.count('h')
                    + status.parsed_opts.count('g')
                    + status.parsed_opts.count('i')
                    + status.parsed_opts.count('j');
            if(nbOfOpts == 0) throw int(NOTHING_TO_DO);
            if(nbOfOpts > 1) throw int(MORE_THAN_1_COMMAND);

            if(status.parsed_opts.count('g')) {
/**********************************************************************************************************************
 *  Generation des clés  **********************************************************************************************
 *********************************************************************************************************************/
                if(!status.parsed_opts.count('a')) throw int(NO_PRK_OUTPUT);
                if(!status.parsed_opts.count('b')) throw int(NO_PUB_OUTPUT);

                openWriteFile(status.parsed_opts['a'], &status.prkOutput, PRK_OUTPUT_EMPTY, PRK_OUTPUT_OPEN_ERR);
                openWriteFile(status.parsed_opts['b'], &status.pubOutput, PUB_OUTPUT_EMPTY, PUB_OUTPUT_OPEN_ERR);

                privateKey prKey = generateKey();
                byteArray prk = fromBitArray<byte>(toBitArray<unsigned int>(serializeKey(prKey)));
                byteArray pub = fromBitArray<byte>(toBitArray<unsigned int>(serializeKey(getPublic(prKey))));

                for(auto const& octet : prk) status.prkOutput->put(octet);
                for(auto const& octet : pub) status.pubOutput->put(octet);

                delete status.prkOutput;
                delete status.pubOutput;
            } else if(status.parsed_opts.count('d')) {
/**********************************************************************************************************************
 *  Decryptage  *******************************************************************************************************
 *********************************************************************************************************************/
                if(!status.parsed_opts.count('b')) throw int(NO_PUB_INPUT);
                if(status.parsed_opts.count('o')) openWriteFile(status.parsed_opts['o'], &status.outputFile, OUTPUT_PATH_EMPTY, OUTPUT_FILE_ERR);

                openReadFile(status.parsed_opts['d'], &status.inputFile, INPUT_PATH_EMPTY, INPUT_FILE_ERR, INPUT_FILE_EMPTY);
                openReadFile(status.parsed_opts['b'], &status.pubInput, PUB_INPUT_PATH_EMPTY, PUB_INPUT_OPEN_ERR, PUB_INPUT_FILE_EMPTY);

                byteArray keyBuffer, inputBuffer;

                while(status.inputFile->good()) inputBuffer.push_back(status.inputFile->get());
                while(status.pubInput->good()) keyBuffer.push_back(status.pubInput->get());

                byteArray outputBuffer = decryptIntArray(
                            fromBitArray<unsigned int>(toBitArray<byte>(inputBuffer)),
                            unserializePublicKey(fromBitArray<unsigned int>(toBitArray<byte>(keyBuffer)))
                );

                if(status.outputFile != NULL) {
                    for(auto const& octet : outputBuffer) status.outputFile->put(octet);
                    delete status.outputFile;
                } else {
                    for(auto const& octet : outputBuffer) cout << octet;
                }

                delete status.inputFile;
                delete status.pubInput;
            } else if(status.parsed_opts.count('c')) {
/**********************************************************************************************************************
 *  Cryptage  *********************************************************************************************************
 *********************************************************************************************************************/
                if(!status.parsed_opts.count('a')) throw int(NO_PRK_INPUT);
                if(status.parsed_opts.count('o')) openWriteFile(status.parsed_opts['o'], &status.outputFile, OUTPUT_PATH_EMPTY, OUTPUT_FILE_ERR);

                openReadFile(status.parsed_opts['c'], &status.inputFile, INPUT_PATH_EMPTY, INPUT_FILE_ERR, INPUT_FILE_EMPTY);
                openReadFile(status.parsed_opts['a'], &status.prkInput, PRK_INPUT_PATH_EMPTY, PRK_INPUT_OPEN_ERR, PRK_INPUT_FILE_EMPTY);

                byteArray keyBuffer, inputBuffer;

                while(status.inputFile->good()) inputBuffer.push_back(status.inputFile->get());
                while(status.prkInput->good()) keyBuffer.push_back(status.prkInput->get());

                byteArray outputBuffer = fromBitArray<byte>(toBitArray<unsigned int>(crypt(
                            inputBuffer,
                            unserializePrivateKey(fromBitArray<unsigned int>(toBitArray<byte>(keyBuffer)))
                )));

                if(status.outputFile != NULL) {
                    for(auto const& octet : outputBuffer) status.outputFile->put(octet);
                    delete status.outputFile;
                } else {
                    for(auto const& octet : outputBuffer) cout << octet;
                }

                delete status.inputFile;
                delete status.prkInput;
            } else if(status.parsed_opts.count('h')) {
/**********************************************************************************************************************
 *  Hashage  **********************************************************************************************************
 *********************************************************************************************************************/
                if(status.parsed_opts.count('o')) openWriteFile(status.parsed_opts['o'], &status.outputFile, OUTPUT_PATH_EMPTY, OUTPUT_FILE_ERR);
                openReadFile(status.parsed_opts['h'], &status.inputFile, INPUT_PATH_EMPTY, INPUT_FILE_ERR, INPUT_FILE_EMPTY);

                byteArray buffer;
                while(status.inputFile->good()) buffer.push_back(status.inputFile->get());
                delete status.inputFile;

                hashByteArray(buffer);

                if(status.outputFile != NULL) {
                    for(auto const& octet : buffer) status.outputFile->put(octet);
                    delete status.outputFile;
                } else {
                    for(auto const& octet : buffer) cout << octet;
                }
            } else if(status.parsed_opts.count('i')) {
/**********************************************************************************************************************
 *  Signature  ********************************************************************************************************
 *********************************************************************************************************************/
                if(!status.parsed_opts.count('a')) throw int(NO_PRK_INPUT);
                if(status.parsed_opts.count('o')) openWriteFile(status.parsed_opts['o'], &status.outputFile, OUTPUT_PATH_EMPTY, OUTPUT_FILE_ERR);

                openReadFile(status.parsed_opts['i'], &status.inputFile, INPUT_PATH_EMPTY, INPUT_FILE_ERR, INPUT_FILE_EMPTY);
                openReadFile(status.parsed_opts['a'], &status.prkInput, PRK_INPUT_PATH_EMPTY, PRK_INPUT_OPEN_ERR, PRK_INPUT_FILE_EMPTY);

                byteArray keyBuffer, inputBuffer;

                while(status.inputFile->good()) inputBuffer.push_back(status.inputFile->get());
                while(status.prkInput->good()) keyBuffer.push_back(status.prkInput->get());

                hashByteArray(inputBuffer);
                byteArray outputBuffer = fromBitArray<byte>(toBitArray<unsigned int>(crypt(
                            inputBuffer,
                            unserializePrivateKey(fromBitArray<unsigned int>(toBitArray<byte>(keyBuffer)))
                )));

                if(status.outputFile != NULL) {
                    for(auto const& octet : outputBuffer) status.outputFile->put(octet);
                    delete status.outputFile;
                } else {
                    for(auto const& octet : outputBuffer) cout << octet;
                }

                delete status.inputFile;
                delete status.prkInput;
            } else if(status.parsed_opts.count('j')) {
/**********************************************************************************************************************
 *  Vérification  *****************************************************************************************************
 *********************************************************************************************************************/
                if(!status.parsed_opts.count('b')) throw int(NO_PUB_INPUT);
                if(!status.parsed_opts.count('f')) throw int(NO_FOOTPRINT_INPUT);

                openReadFile(status.parsed_opts['j'], &status.inputFile, INPUT_PATH_EMPTY, INPUT_FILE_ERR, INPUT_FILE_EMPTY);
                openReadFile(status.parsed_opts['b'], &status.pubInput, PUB_INPUT_PATH_EMPTY, PUB_INPUT_OPEN_ERR, PUB_INPUT_FILE_EMPTY);
                openReadFile(status.parsed_opts['f'], &status.footprintFile, FOOTPRINT_INPUT_PATH_EMPTY, FOOTPRINT_INPUT_OPEN_ERR, FOOTPRINT_INPUT_FILE_EMPTY);

                byteArray keyBuffer, inputBuffer, footprintBuffer;

                while(status.inputFile->good()) inputBuffer.push_back(status.inputFile->get());
                while(status.pubInput->good()) keyBuffer.push_back(status.pubInput->get());
                while(status.footprintFile->good()) footprintBuffer.push_back(status.footprintFile->get());

                hashByteArray(inputBuffer);
                byteArray decryptedFootprint = decryptIntArray(
                            fromBitArray<unsigned int>(toBitArray<byte>(footprintBuffer)),
                            unserializePublicKey(fromBitArray<unsigned int>(toBitArray<byte>(keyBuffer)))
                );

                cout << (std::string)((decryptedFootprint == inputBuffer) ? "Empreintes identiques" : "Empreintes différentes");

                delete status.inputFile;
                delete status.pubInput;
                delete status.footprintFile;
            }
/**********************************************************************************************************************
 **********************************************************************************************************************
 *********************************************************************************************************************/
        } catch(int errorCode) {
            cerr << "Mauvais arguments renseignés" << endl << getErrMsg(errorCode) << endl;
            return errorCode;
        }
    } catch(int errorCode) {
        cerr << "Erreur non rattrapée !" << endl << getErrMsg(errorCode) << endl;
        return errorCode;
    }
}
