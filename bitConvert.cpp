#include "bitConvert.h"

#ifdef TEST

static void testToBitArray() {
    intArray array1({15295635});
    bitArray needle1({0,0,0,0, 0,0,0,0, 1,1,1,0, 1,0,0,1, 0,1,1,0, 0,1,0,0, 1,0,0,1, 0,0,1,1});
    assert(toBitArray(array1) == needle1);

    intArray array2({15295635, 65603, 0, 13663});
    bitArray needle2({0,0,0,0, 0,0,0,0, 1,1,1,0, 1,0,0,1, 0,1,1,0, 0,1,0,0, 1,0,0,1, 0,0,1,1,
                     0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1, 0,0,0,0, 0,0,0,0, 0,1,0,0, 0,0,1,1,
                     0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
                     0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,1,1, 0,1,0,1, 0,1,0,1, 1,1,1,1});
    assert(toBitArray(array2) == needle2);
}

static void testFromBitArray() {
    intArray const needle1({15295635});
    bitArray const array1({0,0,0,0, 0,0,0,0, 1,1,1,0, 1,0,0,1, 0,1,1,0, 0,1,0,0, 1,0,0,1, 0,0,1,1});
    intArray const array1_ = fromBitArray<unsigned int>(array1);
    assert(array1_ == needle1);

    intArray const needle2({15295635, 65603, 0, 13663});
    bitArray const array2({0,0,0,0, 0,0,0,0, 1,1,1,0, 1,0,0,1, 0,1,1,0, 0,1,0,0, 1,0,0,1, 0,0,1,1,
                     0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1, 0,0,0,0, 0,0,0,0, 0,1,0,0, 0,0,1,1,
                     0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
                     0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,1,1, 0,1,0,1, 0,1,0,1, 1,1,1,1});
    assert(fromBitArray<unsigned int>(array2) == needle2);
}

void testBitConvert() {
    testToBitArray();
    testFromBitArray();

    std::vector<unsigned char> const needle({'t', 'o', 't', 'o'});
    assert(fromBitArray<unsigned char>(toBitArray<unsigned char>(needle)) == needle);
}
#endif
