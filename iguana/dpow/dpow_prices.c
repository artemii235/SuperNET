/******************************************************************************
 * Copyright © 2014-2018 The SuperNET Developers.                             *
 *                                                                            *
 * See the AUTHORS, DEVELOPER-AGREEMENT and LICENSE files at                  *
 * the top-level directory of this distribution for the individual copyright  *
 * holder information and the developer policies on copyright and licensing.  *
 *                                                                            *
 * Unless otherwise agreed in a custom licensing agreement, no part of the    *
 * SuperNET software, including this file may be copied, modified, propagated *
 * or distributed except according to the terms contained in the LICENSE file *
 *                                                                            *
 * Removal or modification of this copyright notice is prohibited.            *
 *                                                                            *
 ******************************************************************************/

#include "../exchanges777.h"

#define USD 0
#define EUR 1
#define JPY 2
#define GBP 3
#define AUD 4
#define CAD 5
#define CHF 6
#define NZD 7
#define CNY 8
#define RUB 9

#define NZDUSD 0
#define NZDCHF 1
#define NZDCAD 2
#define NZDJPY 3
#define GBPNZD 4
#define EURNZD 5
#define AUDNZD 6
#define CADJPY 7
#define CADCHF 8
#define USDCAD 9
#define EURCAD 10
#define GBPCAD 11
#define AUDCAD 12
#define USDCHF 13
#define CHFJPY 14
#define EURCHF 15
#define GBPCHF 16
#define AUDCHF 17
#define EURUSD 18
#define EURAUD 19
#define EURJPY 20
#define EURGBP 21
#define GBPUSD 22
#define GBPJPY 23
#define GBPAUD 24
#define USDJPY 25
#define AUDJPY 26
#define AUDUSD 27

#define USDNUM 28
#define EURNUM 29
#define JPYNUM 30
#define GBPNUM 31
#define AUDNUM 32
#define CADNUM 33
#define CHFNUM 34
#define NZDNUM 35

#define NUM_CONTRACTS 28
#define NUM_CURRENCIES 8
#define NUM_COMBINED (NUM_CONTRACTS + NUM_CURRENCIES)
#define MAX_SPLINES 64
#define MAX_LOOKAHEAD 72
#define MAX_CURRENCIES 32

#define SATOSHIDEN ((uint64_t)100000000L)
#define dstr(x) ((double)(x) / SATOSHIDEN)
#define SMALLVAL 0.000000000000001
#define PRICE_RESOLUTION_ROOT ((int64_t)3163)
#define PRICE_RESOLUTION (PRICE_RESOLUTION_ROOT * PRICE_RESOLUTION_ROOT) // 10004569
#define PRICE_RESOLUTION2 (PRICE_RESOLUTION * PRICE_RESOLUTION) // 100091400875761
#define PRICE_RESOLUTION_MAXPVAL ((int64_t)3037000500u)  // 303.5613528178975 vs 64 bits: 4294967295  429.30058206405493,
#define PRICE_RESOLUTION_MAXUNITS ((int16_t)((int64_t)0x7fffffffffffffffLLu / (SATOSHIDEN * PRICE_RESOLUTION)))  // 9219
#define SCALED_PRICE(val,scale) (((scale) * (val)) / PRICE_RESOLUTION)
#define Pval(r) ((double)(r)->Pval / PRICE_RESOLUTION)  // for display only!
#define PERCENTAGE(perc) (((perc) * PRICE_RESOLUTION) / 100)

#ifndef MAX
#define MAX(a,b) ((a) >= (b) ? (a) : (b))
#endif
#ifndef MIN
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#endif

struct price_resolution { int64_t Pval; };

struct PAX_spline { char name[64]; int32_t splineid,lasti,basenum,num,firstx,dispincr,spline32[MAX_SPLINES][4]; uint32_t utc32[MAX_SPLINES]; int64_t spline64[MAX_SPLINES][4]; double dSplines[MAX_SPLINES][4],pricevals[MAX_SPLINES+MAX_LOOKAHEAD],lastutc,lastval,aveslopeabs; };

struct PAX_data
{
    uint32_t ttimestamps[128]; double tbids[128],tasks[128];
    uint32_t ftimestamps[128]; double fbids[128],fasks[128];
    uint32_t itimestamps[128]; double ibids[128],iasks[128];
    char edate[128]; double ecbmatrix[MAX_CURRENCIES][MAX_CURRENCIES],dailyprices[MAX_CURRENCIES * MAX_CURRENCIES],metals[4];
    uint32_t lastupdate;
    int32_t ecbdatenum,ecbyear,ecbmonth,ecbday; double RTmatrix[MAX_CURRENCIES][MAX_CURRENCIES],RTprices[128],RTmetals[4];
    double basevals[MAX_CURRENCIES],cryptovols[2][9][2],BTCDBTC,BTCUSD,KMDBTC,CNYUSD,btcusd,kmdbtc,cryptos[8];
    struct PAX_spline splines[128];
};

#define _extrapolate_Spline(Splines,gap) ((double)(Splines)[0] + ((gap) * ((double)(Splines)[1] + ((gap) * ((double)(Splines)[2] + ((gap) * (double)(Splines)[3]))))))
#define _extrapolate_Slope(Splines,gap) ((double)(Splines)[1] + ((gap) * ((double)(Splines)[2] + ((gap) * (double)(Splines)[3]))))

#define PRICE_BLEND(oldval,newval,decay,oppodecay) ((oldval == 0.) ? newval : ((oldval * decay) + (oppodecay * newval)))
#define PRICE_BLEND64(oldval,newval,decay,oppodecay) ((oldval == 0) ? newval : ((oldval * decay) + (oppodecay * newval) + 0.499))

#define dto64(x) ((int64_t)((x) * (double)SATOSHIDEN * SATOSHIDEN))
#define dto32(x) ((int32_t)((x) * (double)SATOSHIDEN))
#define i64tod(x) ((double)(x) / ((double)SATOSHIDEN * SATOSHIDEN))
#define i32tod(x) ((double)(x) / (double)SATOSHIDEN)
#define _extrapolate_spline64(spline64,gap) ((double)i64tod((spline64)[0]) + ((gap) * ((double)i64tod(.001*.001*(spline64)[1]) + ((gap) * ((double)i64tod(.001*.001*.001*.001*(spline64)[2]) + ((gap) * (double)i64tod(.001*.001*.001*.001*.001*.001*(spline64)[3])))))))
#define _extrapolate_spline32(spline32,gap) ((double)i32tod((spline32)[0]) + ((gap) * ((double)i32tod(.001*.001*(spline32)[1]) + ((gap) * ((double)i32tod(.001*.001*.001*.001*(spline32)[2]) + ((gap) * (double)i32tod(.001*.001*.001*.001*.001*.001*(spline32)[3])))))))

int32_t sprimes[168] =
{
	2,      3,      5,      7,     11,     13,     17,     19,     23,     29,
	31,     37,     41,     43,     47,     53,     59,     61,     67,     71,
	73,     79,     83,     89,     97,    101,    103,    107,    109,    113,
	127,    131,    137,    139,    149,    151,    157,    163,    167,    173,
	179,    181,    191,    193,    197,    199,    211,    223,    227,    229,
	233,    239,    241,    251,    257,    263,    269,    271,    277,    281,
	283,    293,    307,    311,    313,    317,    331,    337,    347,    349,
	353,    359,    367,    373,    379,    383,    389,    397,    401,    409,
	419,    421,    431,    433,    439,    443,    449,    457,    461,    463,
	467,    479,    487,    491,    499,    503,    509,    521,    523,    541,
	547,    557,    563,    569,    571,    577,    587,    593,    599,    601,
	607,    613,    617,    619,    631,    641,    643,    647,    653,    659,
	661,    673,    677,    683,    691,    701,    709,    719,    727,    733,
	739,    743,    751,    757,    761,    769,    773,    787,    797,    809,
	811,    821,    823,    827,    829,    839,    853,    857,    859,    863,
	877,    881,    883,    887,    907,    911,    919,    929,    937,    941,
	947,    953,    967,    971,    977,    983,    991,    997
};

int32_t Peggy_inds[539] = {289, 404, 50, 490, 59, 208, 87, 508, 366, 288, 13, 38, 159, 440, 120, 480, 361, 104, 534, 195, 300, 362, 489, 108, 143, 220, 131, 244, 133, 473, 315, 439, 210, 456, 219, 352, 153, 444, 397, 491, 286, 479, 519, 384, 126, 369, 155, 427, 373, 360, 135, 297, 256, 506, 322, 425, 501, 251, 75, 18, 420, 537, 443, 438, 407, 145, 173, 78, 340, 240, 422, 160, 329, 32, 127, 128, 415, 495, 372, 522, 60, 238, 129, 364, 471, 140, 171, 215, 378, 292, 432, 526, 252, 389, 459, 350, 233, 408, 433, 51, 423, 19, 62, 115, 211, 22, 247, 197, 530, 7, 492, 5, 53, 318, 313, 283, 169, 464, 224, 282, 514, 385, 228, 175, 494, 237, 446, 105, 150, 338, 346, 510, 6, 348, 89, 63, 536, 442, 414, 209, 216, 227, 380, 72, 319, 259, 305, 334, 236, 103, 400, 176, 267, 355, 429, 134, 257, 527, 111, 287, 386, 15, 392, 535, 405, 23, 447, 399, 291, 112, 74, 36, 435, 434, 330, 520, 335, 201, 478, 17, 162, 483, 33, 130, 436, 395, 93, 298, 498, 511, 66, 487, 218, 65, 309, 419, 48, 214, 377, 409, 462, 139, 349, 4, 513, 497, 394, 170, 307, 241, 185, 454, 29, 367, 465, 194, 398, 301, 229, 212, 477, 303, 39, 524, 451, 116, 532, 30, 344, 85, 186, 202, 517, 531, 515, 230, 331, 466, 147, 426, 234, 304, 64, 100, 416, 336, 199, 383, 200, 166, 258, 95, 188, 246, 136, 90, 68, 45, 312, 354, 184, 314, 518, 326, 401, 269, 217, 512, 81, 88, 272, 14, 413, 328, 393, 198, 226, 381, 161, 474, 353, 337, 294, 295, 302, 505, 137, 207, 249, 46, 98, 27, 458, 482, 262, 253, 71, 25, 0, 40, 525, 122, 341, 107, 80, 165, 243, 168, 250, 375, 151, 503, 124, 52, 343, 371, 206, 178, 528, 232, 424, 163, 273, 191, 149, 493, 177, 144, 193, 388, 1, 412, 265, 457, 255, 475, 223, 41, 430, 76, 102, 132, 96, 97, 316, 472, 213, 263, 3, 317, 324, 274, 396, 486, 254, 205, 285, 101, 21, 279, 58, 467, 271, 92, 538, 516, 235, 332, 117, 500, 529, 113, 445, 390, 358, 79, 34, 488, 245, 83, 509, 203, 476, 496, 347, 280, 12, 84, 485, 323, 452, 10, 146, 391, 293, 86, 94, 523, 299, 91, 164, 363, 402, 110, 321, 181, 138, 192, 469, 351, 276, 308, 277, 428, 182, 260, 55, 152, 157, 382, 121, 507, 225, 61, 431, 31, 106, 327, 154, 16, 49, 499, 73, 70, 449, 460, 187, 24, 248, 311, 275, 158, 387, 125, 67, 284, 35, 463, 190, 179, 266, 376, 221, 42, 26, 290, 357, 268, 43, 167, 99, 374, 242, 156, 239, 403, 339, 183, 320, 180, 306, 379, 441, 20, 481, 141, 77, 484, 69, 410, 502, 172, 417, 118, 461, 261, 47, 333, 450, 296, 453, 368, 359, 437, 421, 264, 504, 281, 270, 114, 278, 56, 406, 448, 411, 521, 418, 470, 123, 455, 148, 356, 468, 109, 204, 533, 365, 8, 345, 174, 370, 28, 57, 11, 2, 231, 310, 196, 119, 82, 325, 44, 342, 37, 189, 142, 222, 9, 54, };

uint64_t Currencymasks[NUM_CURRENCIES+1];

short Contract_base[NUM_COMBINED+1] = { 7, 7, 7, 7, 3, 1, 4, 5, 5, 0, 1, 3, 4, 0, 6, 1, 3, 4, 1, 1, 1, 1, 3, 3, 3, 0, 4, 4, 0,1,2,3,4,5,6,7, 8 };// Contract_base };
short  Contract_rel[NUM_COMBINED+1] = { 0, 6, 5, 2, 7, 7, 7, 2, 6, 5, 5, 5, 5, 6, 2, 6, 6, 6, 0, 4, 2, 3, 0, 2, 4, 2, 2, 0, 0,1,2,3,4,5,6,7,8 };// Contract_rel

short Baserel_contractdir[NUM_CURRENCIES+1][NUM_CURRENCIES+1] =
{
	{  1, -1,  1, -1, -1,  1,  1, -1, -1 },
	{  1,  1,  1,  1,  1,  1,  1,  1, -1 },
	{ -1, -1,  1, -1, -1, -1, -1, -1,  0 },
	{  1, -1,  1,  1,  1,  1,  1,  1, -1 },
	{  1, -1,  1, -1,  1,  1,  1,  1, -1 },
	{ -1, -1,  1, -1, -1,  1,  1, -1,  0 },
	{ -1, -1,  1, -1, -1, -1,  1, -1, -1 },
	{  1, -1,  1, -1, -1,  1,  1,  1,  0 },
	{ -1, -1,  0, -1, -1,  0, -1,  0,  1 },
};

short Currency_contracts[NUM_CURRENCIES+1][NUM_CURRENCIES] =
{
	{  0,  9, 13, 18, 22, 25, 27, 28, },
	{  5, 10, 15, 18, 19, 20, 21, 29, },
	{  3,  7, 14, 20, 23, 25, 26, 30, },
	{  4, 11, 16, 21, 22, 23, 24, 31, },
	{  6, 12, 17, 19, 24, 26, 27, 32, },
	{  2,  7,  8,  9, 10, 11, 12, 33, },
	{  1,  8, 13, 14, 15, 16, 17, 34, },
	{  0,  1,  2,  3,  4,  5,  6, 35, },
	{ 36, 37, -1, 38, 39, -1, 40, 41, },
};

short Currency_contractothers[NUM_CURRENCIES+1][NUM_CURRENCIES] =	// buggy!
{
	{ 7, 5, 6, 1, 3, 2, 4, 0, },
	{ 7, 5, 6, 0, 4, 2, 3, 1, },
	{ 7, 5, 6, 1, 3, 0, 4, 2, },
	{ 7, 5, 6, 1, 0, 2, 4, 3, },
	{ 7, 5, 6, 1, 3, 2, 0, 4, },
	{ 7, 2, 6, 0, 1, 3, 4, 5, },
	{ 7, 5, 0, 2, 1, 3, 4, 6, },
	{ 0, 6, 5, 2, 1, 3, 4, 7, },
	{ 0, 1,-1, 3, 4,-1, 5,-1, },
};

short Baserel_contractnum[NUM_CURRENCIES+1][NUM_CURRENCIES+1] =
{
	{ 28, 18, 25, 22, 27,  9, 13,  0, 36 },
	{ 18, 29, 20, 21, 19, 10, 15,  5, 37 },
	{ 25, 20, 30, 23, 26,  7, 14,  3, -1 },
	{ 22, 21, 23, 31, 24, 11, 16,  4, 38 },
	{ 27, 19, 26, 24, 32, 12, 17,  6, 39 },
	{  9, 10,  7, 11, 12, 33,  8,  2, -1 },
	{ 13, 15, 14, 16, 17,  8, 34,  1, 40 },
	{  0,  5,  3,  4,  6,  2,  1, 35, -1 },
	{ 36, 37, -1, 38, 39, -1, 40, -1, 74 },
};

short Currency_contractdirs[NUM_CURRENCIES+1][NUM_CURRENCIES] =
{
	{ -1,  1,  1, -1, -1,  1, -1,  1 },
	{  1,  1,  1,  1,  1,  1,  1,  1 },
	{ -1, -1, -1, -1, -1, -1, -1,  1 },
	{  1,  1,  1, -1,  1,  1,  1,  1 },
	{  1,  1,  1, -1, -1,  1,  1,  1 },
	{ -1,  1,  1, -1, -1, -1, -1,  1 },
	{ -1, -1, -1,  1, -1, -1, -1,  1 },
	{  1,  1,  1,  1, -1, -1, -1,  1 },
	{  1,  1,  1,  1,  1,  1,  1,  1 },
};

char *PAX_bases[64] =
{
    "KMD", "USD", "EUR", "JPY", "GBP", "AUD", "CAD", "CHF", "NZD", // major currencies
    "CNY", "RUB", "MXN", "BRL", "INR", "HKD", "TRY", "ZAR", "PLN", "NOK", "SEK", "DKK", "CZK", "HUF", "ILS", "KRW", "MYR", "PHP", "RON", "SGD", "THB", "BGN", "IDR", "HRK",
    "BTCUSD", "NXTBTC", "SuperNET", "ETHBTC", "ETCBTC", "XMRBTC", "KMDBTC", "XCPBTC",  // BTC priced
    "XAUUSD", "XAGUSD", "XPTUSD", "XPDUSD", "COPPER", "NGAS", "UKOIL", "USOIL", // USD priced
    "BUND", "NAS100", "SPX500", "US30", "EUSTX50", "UK100", "JPN225", "GER30", "SUI30", "AUS200", "HKG33", "XAUUSD", "BTCRUB", "BTCCNY", "BTCUSD" // abstract
};

uint64_t M1SUPPLY[] = { 3317900000000, 6991604000000, 667780000000000, 1616854000000, 331000000000, 861909000000, 584629000000, 46530000000, // major currencies
    45434000000000, 16827000000000, 3473357229000, 306435000000, 27139000000000, 2150641000000, 347724099000, 1469583000000, 749543000000, 1826110000000, 2400434000000, 1123925000000, 3125276000000, 13975000000000, 317657000000, 759706000000000, 354902000000, 2797061000000, 162189000000, 163745000000, 1712000000000, 39093000000, 1135490000000000, 80317000000,
    100000000 };

#define MIND 1000
uint32_t MINDENOMS[] = { MIND, MIND, 100*MIND, MIND, MIND, MIND, MIND, MIND, // major currencies
    10*MIND, 100*MIND, 10*MIND, MIND, 100*MIND, 10*MIND, MIND, 10*MIND, MIND, 10*MIND, 10*MIND, 10*MIND, 10*MIND, 100*MIND, MIND, 1000*MIND, MIND, 10*MIND, MIND, MIND, 10*MIND, MIND, 10000*MIND, 10*MIND, // end of currencies
    10*MIND,
};

uint64_t komodo_paxvol(uint64_t volume,uint64_t price)
{
    if ( volume < 10000000000 )
        return((volume * price) / 1000000000);
    else if ( volume < (uint64_t)10 * 10000000000 )
        return((volume * (price / 10)) / 100000000);
    else if ( volume < (uint64_t)100 * 10000000000 )
        return(((volume / 10) * (price / 10)) / 10000000);
    else if ( volume < (uint64_t)1000 * 10000000000 )
        return(((volume / 10) * (price / 100)) / 1000000);
    else if ( volume < (uint64_t)10000 * 10000000000 )
        return(((volume / 100) * (price / 100)) / 100000);
    else if ( volume < (uint64_t)100000 * 10000000000 )
        return(((volume / 100) * (price / 1000)) / 10000);
    else if ( volume < (uint64_t)1000000 * 10000000000 )
        return(((volume / 1000) * (price / 1000)) / 1000);
    else if ( volume < (uint64_t)10000000 * 10000000000 )
        return(((volume / 1000) * (price / 10000)) / 100);
    else return(((volume / 10000) * (price / 10000)) / 10);
}

void pax_rank(uint64_t *ranked,uint32_t *pvals)
{
    int32_t i; uint64_t vals[32],sum = 0;
    for (i=0; i<32; i++)
    {
        vals[i] = komodo_paxvol(M1SUPPLY[i] / MINDENOMS[i],pvals[i]);
        sum += vals[i];
    }
    for (i=0; i<32; i++)
    {
        ranked[i] = (vals[i] * 1000000000) / sum;
        printf("%.6f ",(double)ranked[i]/1000000000.);
    }
};

#define YAHOO_METALS "XAU", "XAG", "XPT", "XPD"
static char *Yahoo_metals[] = { YAHOO_METALS };

char CURRENCIES[][65] = { "USD", "EUR", "JPY", "GBP", "AUD", "CAD", "CHF", "NZD", // major currencies
    "CNY", "RUB", "MXN", "BRL", "INR", "HKD", "TRY", "ZAR", "PLN", "NOK", "SEK", "DKK", "CZK", "HUF", "ILS", "KRW", "MYR", "PHP", "RON", "SGD", "THB", "BGN", "IDR", "HRK", // end of currencies
    "XAU", "XAG", "XPT", "XPD", // metals, gold must be first
    "BTCD", "BTC", "NXT", "ETC", "ETH", "KMD", "BTS", "MAID", "XCP",  "XMR" // cryptos
};

char CONTRACTS[][16] = {  "NZDUSD", "NZDCHF", "NZDCAD", "NZDJPY", "GBPNZD", "EURNZD", "AUDNZD", "CADJPY", "CADCHF", "USDCAD", "EURCAD", "GBPCAD", "AUDCAD", "USDCHF", "CHFJPY", "EURCHF", "GBPCHF", "AUDCHF", "EURUSD", "EURAUD", "EURJPY", "EURGBP", "GBPUSD", "GBPJPY", "GBPAUD", "USDJPY", "AUDJPY", "AUDUSD", "USDCNY", "USDHKD", "USDMXN", "USDZAR", "USDTRY", "EURTRY", "TRYJPY", "USDSGD", "EURNOK", "USDNOK","USDSEK","USDDKK","EURSEK","EURDKK","NOKJPY","SEKJPY","USDPLN","EURPLN","USDILS", // no more currencies
    "XAUUSD", "XAGUSD", "XPTUSD", "XPDUSD", "COPPER", "NGAS", "UKOIL", "USOIL", // commodities
    // cryptos
    "NAS100", "SPX500", "US30", "BUND", "EUSTX50", "UK100", "JPN225", "GER30", "SUI30", "AUS200", "HKG33", "FRA40", "ESP35", "ITA40", "USDOLLAR", // indices
    "SuperNET" // assets
};

int32_t isdecimalstr(char *str)
{
    int32_t i;
    if ( str == 0 || str[0] == 0 )
        return(0);
    for (i=0; str[i]!=0; i++)
        if ( str[i] < '0' || str[i] > '9' )
            return(0);
    return(i);
}

int32_t PAX_ispair(char *base,char *rel,char *contract)
{
    int32_t i,j;
    base[0] = rel[0] = 0;
    for (i=0; i<sizeof(CURRENCIES)/sizeof(*CURRENCIES); i++)
    {
        if ( strncmp(CURRENCIES[i],contract,strlen(CURRENCIES[i])) == 0 )
        {
            for (j=0; j<sizeof(CURRENCIES)/sizeof(*CURRENCIES); j++)
                if ( strcmp(CURRENCIES[j],contract+strlen(CURRENCIES[i])) == 0 )
                {
                    strcpy(base,CURRENCIES[i]);
                    strcpy(rel,CURRENCIES[j]);
                    /*USDCNY 6.209700 -> 0.655564
                     USDCNY 6.204146 -> 0.652686
                     USDHKD 7.753400 -> 0.749321
                     USDHKD 7.746396 -> 0.746445
                     USDZAR 12.694000 -> 1.101688
                     USDZAR 12.682408 -> 1.098811
                     USDTRY 2.779700 -> 0.341327
                     EURTRY 3.048500 -> 0.386351
                     TRYJPY 44.724000 -> 0.690171
                     TRYJPY 44.679966 -> 0.687290
                     USDSGD 1.375200 -> 0.239415*/
                    //if ( strcmp(contract,"USDCNY") == 0 || strcmp(contract,"TRYJPY") == 0 || strcmp(contract,"USDZAR") == 0 )
                    //    printf("i.%d j.%d base.%s rel.%s\n",i,j,base,rel);
                    return((i<<8) | j);
                }
            break;
        }
    }
    return(-1);
}

int32_t PAX_basenum(char *_base)
{
    int32_t i,j; char base[65];
    strcpy(base,_base);
    touppercase(base);
    if ( 1 )
    {
        for (i=0; i<sizeof(CURRENCIES)/sizeof(*CURRENCIES); i++)
            for (j=0; j<sizeof(CURRENCIES)/sizeof(*CURRENCIES); j++)
                if ( i != j && strcmp(CURRENCIES[i],CURRENCIES[j]) == 0 )
                    printf("duplicate.(%s)\n",CURRENCIES[i]);//, getchar();
    }
    for (i=0; i<sizeof(CURRENCIES)/sizeof(*CURRENCIES); i++)
        if ( strcmp(CURRENCIES[i],base) == 0 )
            return(i);
    return(-1);
}

int32_t PAX_contractnum(char *base,char *rel)
{
    int32_t i,j,c; char contractstr[16],*contract = 0;
    if ( 0 )
    {
        for (i=0; i<sizeof(CONTRACTS)/sizeof(*CONTRACTS); i++)
            for (j=0; j<sizeof(CONTRACTS)/sizeof(*CONTRACTS); j++)
                if ( i != j && strcmp(CONTRACTS[i],CONTRACTS[j]) == 0 )
                    printf("duplicate.(%s)\n",CONTRACTS[i]);//, getchar();
    }
    if ( base != 0 && base[0] != 0 && rel != 0 && rel[0] != 0 )
    {
        for (i=0; i<NUM_CURRENCIES; i++)
            if ( strcmp(base,CURRENCIES[i]) == 0 )
            {
                for (j=0; j<NUM_CURRENCIES; j++)
                    if ( strcmp(rel,CURRENCIES[j]) == 0 )
                        return(Baserel_contractnum[i][j]);
                break;
            }
        sprintf(contractstr,"%s%s",base,rel);
        contract = contractstr;
    } else contract = base;
    if ( contract != 0 && contract[0] != 0 )
    {
        for (c=0; c<sizeof(CONTRACTS)/sizeof(*CONTRACTS); c++)
            if ( strcmp(CONTRACTS[c],contract) == 0 )
                return(c);
    }
    return(-1);
}

int32_t PAX_mindenomination(int32_t base)
{
    return(MINDENOMS[base]);
}

struct price_resolution peggy_scaleprice(struct price_resolution price,int64_t peggymils)
{
    price.Pval = (10000 * price.Pval) / peggymils;
    return(price);
}

void norm_smooth_wts(int32_t j,double *smoothwts,int32_t n,int32_t numiters)
{
	double wt; int32_t iter,i;
	for (iter=0; iter<numiters; iter++)
	{
		wt = 0.;
		for (i=0; i<n; i++)
			wt += smoothwts[i];
		//printf("wtsum.j%d %.40f ",j,wt);
		for (i=0; i<n; i++)
			smoothwts[i] /= wt;
	}
	//printf("\n");
}

void calc_smooth_code(int32_t smoothwidth,int32_t _maxprimes)
{
	double _coeffs[5000],sum,coeffs[60][10000],smoothbuf[10000]; int32_t x,p,prime,numprimes; uint64_t val,isum = 0;
	_maxprimes = MIN((int32_t)(sizeof(coeffs)/(sizeof(double)*10000))-1,_maxprimes);
	smoothwidth = MIN((int32_t)(sizeof(_coeffs)/sizeof(*_coeffs)),smoothwidth);
	x = 5000;
    memset(smoothbuf,0,sizeof(smoothbuf));
	coeffs[0][x-2] = coeffs[0][x] = coeffs[0][x+2] = 1./3.;
	for (numprimes=_maxprimes; numprimes>=3; numprimes--)
	{
		for (p=1; p<numprimes; p++)
		{
			memcpy(coeffs[p],coeffs[p-1],sizeof(coeffs[p]));
			prime = sprimes[p];
			for (x=0; x<10000; x++)
			{
				coeffs[p][x] += (coeffs[p-1][x - prime] / 3.);
				coeffs[p][x] += (coeffs[p-1][x] / 3.);
				coeffs[p][x] += (coeffs[p-1][x + prime] / 3.);
			}
		}
		memcpy(smoothbuf,coeffs[numprimes-1],sizeof(smoothbuf));
		memset(coeffs,0,sizeof(coeffs));
		sum = 0.;
		for (x=0; x<10000; x++)
		{
			if ( smoothbuf[x] != 0. )
			{
				sum += smoothbuf[x];
				//printf("(%d %f) ",x-5000,smoothbuf[x]);
			}
		}
		//printf("maxprimes.%d\n",maxprimes);
		for (x=0; x<10000; x++)
			coeffs[0][x] = (smoothbuf[x] / sum);
	}
	sum = 0.;
	for (x=0; x<10000; x++)
		sum += smoothbuf[x];
	memset(coeffs,0,sizeof(coeffs));
	if ( sum != 0. )
	{
		printf("double Smooth_coeffs[%d] =	// numprimes.%d\n{\n",smoothwidth,_maxprimes);
		for (x=0; x<10000; x++)
		{
			if ( smoothbuf[x] != 0. )
			{
				smoothbuf[x] = (1000000. * 1000000. * smoothbuf[x]) / sum;
				//printf("(%d %f) ",x-5000,smoothbuf[x]);
			}
		}
		_coeffs[0] = smoothbuf[5000];
		for (x=1; x<=smoothwidth; x++)
		{
			if ( fabs(smoothbuf[5000 - x] - smoothbuf[5000 + x]) > SMALLVAL )
				printf("x.%d error %.20f != %.20f [%.20f]\n",x,smoothbuf[5000 - x],smoothbuf[5000 + x],smoothbuf[5000 - x] - smoothbuf[5000 + x]);
			_coeffs[x-1] = (smoothbuf[5000 - x] + smoothbuf[5000 + x]) / 2.;
		}
		sum = 0.;
		for (x=0; x<smoothwidth; x++)
			sum += _coeffs[x];
		if ( sum != 0. )
		{
			for (x=0; x<smoothwidth; x++)
			{
                val = ((SATOSHIDEN * 1000. * _coeffs[x] + sum*.4825) / sum);
                printf("%lld, ",(long long)val);
                isum += val;
				//printf("%.0f, ",SATOSHIDEN*1000*_coeffs[x]/sum);
				if ( (x%9) == 8 )
					printf("// x.%d\n",x);
			}
            printf("// isum %lld\n",(long long)isum);
		}
	}
	printf("\n}; // %llu\n",(long long)isum);
	//printf("_Constants size %d\n",(int)__constant_size);
}

uint32_t peggy_mils(int32_t i)
{
    uint32_t minmils = 0;
    if ( i == 0 )
        return(1000000);
    else if ( i <= MAX_CURRENCIES )
        minmils = 10 * PAX_mindenomination(i-1);
    else if ( i >= 64 )
        return(10000);
    else if ( PAX_bases[i] != 0 )
    {
        if ( isdecimalstr(PAX_bases[i]+strlen(PAX_bases[i])-2) != 0 || strcmp(PAX_bases[i],"BTCRUB") == 0 )
            minmils = 1;
        else if ( strncmp(PAX_bases[i],"XAU",3) == 0 || strcmp(PAX_bases[i],"BTCCNY") == 0 || strcmp(PAX_bases[i],"BTCUSD") == 0 || strncmp(PAX_bases[i],"XPD",3) == 0 || strncmp(PAX_bases[i],"XPT",3) == 0 )
            minmils = 10;
        else if ( strcmp(PAX_bases[i],"BUND") == 0 || strcmp(PAX_bases[i],"UKOIL") == 0 || strcmp(PAX_bases[i],"USOIL") == 0 )
            minmils = 100;
        else if ( strncmp(PAX_bases[i],"ETC",3) == 0 || strcmp(PAX_bases[i],"SuperNET") == 0 || strncmp(PAX_bases[i],"XAG",3) == 0 || strncmp(PAX_bases[i],"ETH",3) == 0 || strncmp(PAX_bases[i],"XCP",3) == 0 )
            minmils = 1000;
        else if ( strncmp(PAX_bases[i],"XMR",3) == 0 )
            minmils = 10000;
        else if ( strncmp(PAX_bases[i],"NXT",3) == 0 || strncmp(PAX_bases[i],"BTS",3) == 0 )
            minmils = 1000000;
        else if ( strncmp(PAX_bases[i],"KMD",5) == 0 )
            minmils = 1000;
        else minmils = 10000;
    }
    return(minmils);
}

int32_t peggy_prices(struct price_resolution prices[64],double btcusd,double kmdbtc,char *contracts[],int32_t num,double *cprices,double *basevals)
{
    double kmdusd,price_in_kmd,dprice,usdcny,usdrub,btccny,btcrub,xauusd,usdprice=0.,usdval,btcprice=0.; int32_t contractnum,base,nonz = 0;
    if ( btcusd > SMALLVAL && (usdval= basevals[0]) > SMALLVAL )
    {
        xauusd = usdcny = usdrub = btccny = btcrub = 0.;
        for (contractnum=0; contractnum<num; contractnum++)
            if ( strcmp(contracts[contractnum],"XAUUSD") == 0 )
            {
                xauusd = cprices[contractnum];
                break;
            }
        if (  basevals[8] > SMALLVAL )
        {
            usdcny = (basevals[0] * peggy_mils(8)) / (basevals[8] * peggy_mils(0));
            btccny = 1000 * btcusd * usdcny;
        }
        if ( basevals[9] > SMALLVAL )
        {
            usdrub = (basevals[0] * peggy_mils(9)) / (basevals[9] * peggy_mils(0));
            btcrub = 1000 * btcusd * usdrub;
        }
        if ( kmdbtc < SMALLVAL )
            kmdbtc = 0.0001;
        kmdusd = (btcusd * kmdbtc);
        printf("xauusd %f usdval %f %f %f usdcny %f usdrub %f btcusd %f kmdbtc %f kmdusd %f btccny %f btcrub %f\n",xauusd,usdval,basevals[8],basevals[9],usdcny,usdrub,btcusd,kmdbtc,kmdusd,btccny,btcrub);
        prices[0].Pval = (PRICE_RESOLUTION * 100. * kmdbtc);
        for (base=0,contractnum=1; base<32; base++,contractnum++)
        {
            if ( strcmp(contracts[contractnum],CURRENCIES[base]) == 0 )
            {
                if ( (dprice= basevals[base]) > SMALLVAL )
                {
                    nonz++;
                    if ( base == 0 )
                        usdprice = price_in_kmd = (1. / kmdusd);
                    else price_in_kmd = (dprice / (kmdusd * usdval));
                    prices[contractnum].Pval = (PRICE_RESOLUTION * price_in_kmd);
                }
            } else printf("unexpected list entry %s vs %s at %d\n",contracts[contractnum],CURRENCIES[base],contractnum);
        }
        if ( strcmp(contracts[contractnum],"BTCUSD") != 0 )
            printf("unexpected contract (%s) at %d\n",contracts[contractnum],contractnum);
        btcprice = (1. / kmdbtc);
        prices[contractnum++].Pval = (PRICE_RESOLUTION / kmdbtc) / 1000.;
        printf("btcprice %f = 1/%f %llu\n",btcprice,1./kmdbtc,(long long)prices[contractnum-1].Pval);
        for (; contractnum<64; contractnum++)
        {
            //dprice = 0;
            if ( contractnum == 63 && strcmp(contracts[contractnum],"BTCUSD") == 0 )
                dprice = btcusd;
            else if ( contractnum == 62 && strcmp(contracts[contractnum],"BTCCNY") == 0 )
                dprice = btccny;
            else if ( contractnum == 61 && strcmp(contracts[contractnum],"BTCRUB") == 0 )
                dprice = btcrub;
            else if ( contractnum == 60 && strcmp(contracts[contractnum],"XAUUSD") == 0 )
                dprice = xauusd;
            else
            {
                dprice = cprices[contractnum];
                if ( dprice > SMALLVAL && strlen(contracts[contractnum]) > 3 )
                {
                    if ( strcmp(contracts[contractnum]+strlen(contracts[contractnum])-3,"USD") == 0 || strcmp(contracts[contractnum],"COPPER") == 0 || strcmp(contracts[contractnum],"NGAS") == 0 || strcmp(contracts[contractnum],"UKOIL") == 0 || strcmp(contracts[contractnum],"USOIL") == 0 )
                        dprice *= usdprice;
                    else if ( strcmp(contracts[contractnum],"SuperNET") == 0 )
                    {
                        printf("SuperNET %f -> %f\n",dprice,dprice*btcprice);
                        dprice *= btcprice;
                    }
                    else if ( strcmp(contracts[contractnum]+strlen(contracts[contractnum])-3,"BTC") == 0 )
                        dprice *= btcprice;
                }
            }
            prices[contractnum].Pval = (uint64_t)((PRICE_RESOLUTION * dprice) * ((double)peggy_mils(contractnum) / 10000.));
            //if ( Debuglevel > 2 )
            {
                struct price_resolution tmp;
                tmp = peggy_scaleprice(prices[contractnum],peggy_mils(contractnum));
                printf("%.8f btcprice %.6f %f -->>> %s %.6f -> %llu %.6f mils.%d\n",cprices[contractnum],btcprice,cprices[contractnum]*btcprice,contracts[contractnum],Pval(&tmp),(long long)prices[contractnum].Pval,Pval(&prices[contractnum]),peggy_mils(contractnum));
            }
        }
    }
    return(nonz);
}

void init_Currencymasks()
{
	int32_t base,j,c; uint64_t basemask;
	for (base=0; base<NUM_CURRENCIES; base++)
	{
		basemask = 0L;
		for (j=0; j<7; j++)
		{
			if ( (c= Currency_contracts[base][j]) >= 0 )
			{
				basemask |= (1L << c);
				//printf("(%s %lx) ",CONTRACTS[c],1L<<c);
			}
		}
		Currencymasks[base] = basemask;
		printf("0x%llx, ",(long long)basemask);
	}
}

double calc_primary_currencies(double logmatrix[8][8],double *bids,double *asks)
{
	uint64_t nonzmask; int32_t c,base,rel; double bid,ask;
	memset(logmatrix,0,sizeof(double)*8*8);
	nonzmask = 0;
	for (c=0; c<28; c++)
	{
		bid = bids[c];
		ask = asks[c];
		if ( bid != 0 && ask != 0 )
		{
			base = Contract_base[c];
			rel = Contract_rel[c];
			nonzmask |= (1L << c);
			logmatrix[base][rel] = log(bid);
			logmatrix[rel][base] = -log(ask);
			//printf("[%f %f] ",bid,ask);
		}
	}
	//printf("%07lx\n",nonzmask);
	if ( nonzmask != 0 )
	{
		bids[USDNUM] = (logmatrix[USD][EUR] + logmatrix[USD][JPY] + logmatrix[USD][GBP] + logmatrix[USD][AUD] + logmatrix[USD][CAD] + logmatrix[USD][CHF] + logmatrix[USD][NZD]) / 8.;
		asks[USDNUM] = -(logmatrix[EUR][USD] + logmatrix[JPY][USD] + logmatrix[GBP][USD] + logmatrix[AUD][USD] + logmatrix[CAD][USD] + logmatrix[CHF][USD] + logmatrix[NZD][USD]) / 8.;
        
		bids[EURNUM] = (logmatrix[EUR][USD] + logmatrix[EUR][JPY] + logmatrix[EUR][GBP] + logmatrix[EUR][AUD] + logmatrix[EUR][CAD] + logmatrix[EUR][CHF] + logmatrix[EUR][NZD]) / 8.;
		asks[EURNUM] = -(logmatrix[USD][EUR] + logmatrix[JPY][EUR] + logmatrix[GBP][EUR] + logmatrix[AUD][EUR] + logmatrix[CAD][EUR] + logmatrix[CHF][EUR] + logmatrix[NZD][EUR]) / 8.;
        
		bids[JPYNUM] = (logmatrix[JPY][USD] + logmatrix[JPY][EUR] + logmatrix[JPY][GBP] + logmatrix[JPY][AUD] + logmatrix[JPY][CAD] + logmatrix[JPY][CHF] + logmatrix[JPY][NZD]) / 8.;
		asks[JPYNUM] = -(logmatrix[USD][JPY] + logmatrix[EUR][JPY] + logmatrix[GBP][JPY] + logmatrix[AUD][JPY] + logmatrix[CAD][JPY] + logmatrix[CHF][JPY] + logmatrix[NZD][JPY]) / 8.;
        
		bids[GBPNUM] = (logmatrix[GBP][USD] + logmatrix[GBP][EUR] + logmatrix[GBP][JPY] + logmatrix[GBP][AUD] + logmatrix[GBP][CAD] + logmatrix[GBP][CHF] + logmatrix[GBP][NZD]) / 8.;
		asks[GBPNUM] = -(logmatrix[USD][GBP] + logmatrix[EUR][GBP] + logmatrix[JPY][GBP] + logmatrix[AUD][GBP] + logmatrix[CAD][GBP] + logmatrix[CHF][GBP] + logmatrix[NZD][GBP]) / 8.;
        
		bids[AUDNUM] = (logmatrix[AUD][USD] + logmatrix[AUD][EUR] + logmatrix[AUD][JPY] + logmatrix[AUD][GBP] + logmatrix[AUD][CAD] + logmatrix[AUD][CHF] + logmatrix[AUD][NZD]) / 8.;
		asks[AUDNUM] = -(logmatrix[USD][AUD] + logmatrix[EUR][AUD] + logmatrix[JPY][AUD] + logmatrix[GBP][AUD] + logmatrix[CAD][AUD] + logmatrix[CHF][AUD] + logmatrix[NZD][AUD]) / 8.;
        
		bids[CADNUM] = (logmatrix[CAD][USD] + logmatrix[CAD][EUR] + logmatrix[CAD][JPY] + logmatrix[CAD][GBP] + logmatrix[CAD][AUD] + logmatrix[CAD][CHF] + logmatrix[CAD][NZD]) / 8.;
		asks[CADNUM] = -(logmatrix[USD][CAD] + logmatrix[EUR][CAD] + logmatrix[JPY][CAD] + logmatrix[GBP][CAD] + logmatrix[AUD][CAD] + logmatrix[CHF][CAD] + logmatrix[NZD][CAD]) / 8.;
        
		bids[CHFNUM] = (logmatrix[CHF][USD] + logmatrix[CHF][EUR] + logmatrix[CHF][JPY] + logmatrix[CHF][GBP] + logmatrix[CHF][AUD] + logmatrix[CHF][CAD] + logmatrix[CHF][NZD]) / 8.;
		asks[CHFNUM] = -(logmatrix[USD][CHF] + logmatrix[EUR][CHF] + logmatrix[JPY][CHF] + logmatrix[GBP][CHF] + logmatrix[AUD][CHF] + logmatrix[CAD][CHF] + logmatrix[NZD][CHF]) / 8.;
        
		bids[NZDNUM] = (logmatrix[NZD][USD] + logmatrix[NZD][EUR] + logmatrix[NZD][JPY] + logmatrix[NZD][GBP] + logmatrix[NZD][AUD] + logmatrix[NZD][CAD] + logmatrix[NZD][CHF]) / 8.;
		asks[NZDNUM] = -(logmatrix[USD][NZD] + logmatrix[EUR][NZD] + logmatrix[JPY][NZD] + logmatrix[GBP][NZD] + logmatrix[AUD][NZD] + logmatrix[CAD][NZD] + logmatrix[CHF][NZD]) / 8.;
		if ( nonzmask != ((1<<28)-1) )
		{
			for (base=0; base<8; base++)
			{
				if ( (nonzmask & Currencymasks[base]) != Currencymasks[base] )
					bids[base+28] = asks[base+28] = 0;
				//else printf("%s %9.6f | ",CONTRACTS[base+28],_pairaved(bids[base+28],asks[base+28]));
			}
			//printf("keep.%07lx\n",nonzmask);
			return(0);
		}
		if ( 0 && nonzmask != 0 )
		{
			for (base=0; base<8; base++)
				printf("%9.6f | ",_pairaved(bids[base+28],asks[base+28]));
			printf("%07llx\n",(long long)nonzmask);
		}
	}
	return(0);
}

double PAX_splineval(struct PAX_spline *spline,uint32_t timestamp,int32_t lookahead)
{
    int32_t i,gap,ind = (spline->num - 1);
    if ( timestamp >= spline->utc32[ind] )
    {
        gap = (timestamp - spline->utc32[ind]);
        if ( gap < lookahead )
            return(_extrapolate_spline64(spline->spline64[ind],gap));
        else return(0.);
    }
    else if ( timestamp <= spline->utc32[0] )
    {
        gap = (spline->utc32[0] - timestamp);
        if ( gap < lookahead )
            return(_extrapolate_spline64(spline->spline64[0],gap));
        else return(0.);
    }
    for (i=0; i<spline->num-1; i++)
    {
        ind = (i + spline->lasti) % (spline->num - 1);
        if ( timestamp >= spline->utc32[ind] && timestamp < spline->utc32[ind+1] )
        {
            spline->lasti = ind;
            return(_extrapolate_spline64(spline->spline64[ind],timestamp - spline->utc32[ind]));
        }
    }
    return(0.);
}

double PAX_calcspline(struct PAX_spline *spline,double *outputs,double *slopes,int32_t dispwidth,uint32_t *utc32,double *splinevals,int32_t num)
{
    static double errsums[3]; static int errcount;
	double c[MAX_SPLINES],f[MAX_SPLINES],dd[MAX_SPLINES],dl[MAX_SPLINES],du[MAX_SPLINES],gaps[MAX_SPLINES];
	int32_t n,i,lasti,x,numsplines,nonz; double vx,vy,vw,vz,gap,sum,xval,yval,abssum,lastval,lastxval,yval64,yval32,yval3; uint32_t gap32;
	sum = lastxval = n = lasti = nonz = 0;
	for (i=0; i<MAX_SPLINES&&i<num; i++)
	{
		if ( (f[n]= splinevals[i]) != 0. && utc32[i] != 0 )
		{
			//printf("i%d.(%u %f) ",i,utc32[i],splinevals[i]);
            //printf("%f ",splinevals[i]);
			if ( n > 0 )
			{
				if ( (gaps[n-1]= utc32[i] - lastxval) < 0 )
				{
					printf("illegal gap %f to t%d\n",lastxval,utc32[i]);
					return(0);
				}
			}
			spline->utc32[n] = lastxval = utc32[i];
            n++;
		}
	}
	if ( (numsplines= n) < 4 )
		return(0);
	for (i=0; i<n-3; i++)
		dl[i] = du[i] = gaps[i+1];
	for (i=0; i<n-2; i++)
	{
		dd[i] = 2.0 * (gaps[i] + gaps[i+1]);
		c[i]  = (3.0 / (double)gaps[i+1]) * (f[i+2] - f[i+1]) - (3.0 / (double)gaps[i]) * (f[i+1] - f[i]);
	}
	//for (i=0; i<n; i++)
    //    printf("%f ",f[i]);
	//printf("F2[%d]\n",n);
	dd[0] += (gaps[0] + (double)gaps[0]*gaps[0] / gaps[1]);
	du[0] -= ((double)gaps[0]*gaps[0] / gaps[1]);
	dd[n-3] += (gaps[n-2] + (double)gaps[n-2]*gaps[n-2] / gaps[n-3]);
	dl[n-4] -= ((double)gaps[n-2]*gaps[n-2] / gaps[n-3]);
	
	//tridiagonal(n-2, dl, dd, du, c);
	for (i=0; i<n-1-2; i++)
	{
		du[i] /= dd[i];
		dd[i+1] -= dl[i]*du[i];
	}
	c[0] /= dd[0];
	for (i=1; i<n-2; i++)
		c[i] = (c[i] - dl[i-1] * c[i-1]) / dd[i];
	for (i=n-2-4; i>=0; i--)
		c[i] -= c[i+1] * du[i];
	//tridiagonal(n-2, dl, dd, du, c);
	
	for (i=n-3; i>=0; i--)
		c[i+1] = c[i];
	c[0] = (1.0 + (double)gaps[0] / gaps[1]) * c[1] - ((double)gaps[0] / gaps[1] * c[2]);
	c[n-1] = (1.0 + (double)gaps[n-2] / gaps[n-3] ) * c[n-2] - ((double)gaps[n-2] / gaps[n-3] * c[n-3]);
    //printf("c[n-1] %f, n-2 %f, n-3 %f\n",c[n-1],c[n-2],c[n-3]);
	abssum = nonz = lastval = 0;
    outputs[spline->firstx] = f[0];
    spline->num = numsplines;
    for (i=0; i<n; i++)
	{
        vx = f[i];
        vz = c[i];
        if ( i < n-1 )
        {
     		gap = gaps[i];
            vy = ((f[i+1] - f[i]) / gap) - (gap * (c[i+1] + 2.*c[i]) / 3.);
            vw = (c[i+1] - c[i]) / (3. * gap);
        }
        else
        {
            vy = 0;
            vw = 0;
        }
		//printf("%3d: t%u [%14.11f %14.11f %14.11f %14.11f] gap %f | %d\n",i,spline->utc32[i],(vx),vy*1000*1000,vz*1000*1000*1000*1000,vw*1000*1000*1000*1000*1000*1000,gap,conv_unixtime(&tmp,spline->utc32[i]));
		spline->dSplines[i][0] = vx, spline->dSplines[i][1] = vy, spline->dSplines[i][2] = vz, spline->dSplines[i][3] = vw;
		spline->spline64[i][0] = dto64(vx), spline->spline64[i][1] = dto64(vy*1000*1000), spline->spline64[i][2] = dto64(vz*1000*1000*1000*1000), spline->spline64[i][3] = dto64(vw*1000*1000*1000*1000*1000*1000);
		spline->spline32[i][0] = dto32(vx), spline->spline32[i][1] = dto32(vy*1000*1000), spline->spline32[i][2] = dto32(vz*1000*1000*1000*1000), spline->spline32[i][3] = dto32(vw*1000*1000*1000*1000*1000*1000);
		gap32 = gap = spline->dispincr;
		xval = spline->utc32[i] + gap;
		lastval = vx;
		while ( i < n-1 )
		{
			x = spline->firstx + ((xval - spline->utc32[0]) / spline->dispincr);
			if ( x > dispwidth-1 ) x = dispwidth-1;
			if ( x < 0 ) x = 0;
			if ( (i < n-2 && gap > gaps[i] + spline->dispincr) )
				break;
            if ( i == n-2 && xval > spline->utc32[n-1] + MAX_LOOKAHEAD*spline->dispincr )
            {
                //printf("x.%d dispwidth.%d xval %f > utc[n-1] %f + %f\n",x,dispwidth,xval,utc[n-1],MAX_LOOKAHEAD*incr);
                break;
            }
            if ( x >= 0 )
			{
				yval = _extrapolate_Spline(spline->dSplines[i],gap);
				yval64 = _extrapolate_spline64(spline->spline64[i],gap32);
                if ( (yval3 = PAX_splineval(spline,gap32 + spline->utc32[i],MAX_LOOKAHEAD*spline->dispincr)) != 0 )
                {
                    yval32 = _extrapolate_spline32(spline->spline32[i],gap32);
                    errsums[0] += fabs(yval - yval64), errsums[1] += fabs(yval - yval32), errsums[2] += fabs(yval - yval3), errcount++;
                    if ( fabs(yval - yval3) > SMALLVAL )
                        printf("(%.10f vs %.10f %.10f %.10f [%.16f %.16f %.16f]) ",yval,yval64,yval32,yval3, errsums[0]/errcount,errsums[1]/errcount,errsums[2]/errcount);
                }
				if ( yval > 5000. ) yval = 5000.;
				else if ( yval < -5000. ) yval = -5000.;
				if ( isnan(yval) == 0 )
				{
					outputs[x] = yval;
                    spline->lastval = outputs[x], spline->lastutc = xval;
                    if ( 1 && fabs(lastval) > SMALLVAL )
					{
						if ( lastval != 0 && outputs[x] != 0 )
						{
                            if ( slopes != 0 )
                                slopes[x] = (outputs[x] - lastval), abssum += fabs(slopes[x]);
							nonz++;
						}
					}
				}
				//else outputs[x] = 0.;
				//printf("x.%-4d %d %f %f %f i%-4d: gap %9.6f %9.6f last %9.6f slope %9.6f | %9.1f [%9.1f %9.6f %9.6f %9.6f %9.6f]\n",x,firstx,xval,utc[0],incr,i,gap,yval,lastval,slopes[x],xval,utc[i+1],dSplines[i][0],dSplines[i][1]*1000*1000,dSplines[i][2]*1000*1000*1000*1000,dSplines[i][3]*1000*1000*1000*1000*1000*1000);
			}
			gap32 += spline->dispincr, gap += spline->dispincr, xval += spline->dispincr;
		}
		//double pred = (i>0) ? _extrapolate_Spline(dSplines[i-1],gaps[i-1]) : 0.;
		//printf("%2d: w%8.1f [gap %f -> %9.6f | %9.6f %9.6f %9.6f %9.6f %9.6f]\n",i,weekinds[i],gap,pred,f[i],dSplines[i].x,1000000*dSplines[i].y,1000000*1000000*dSplines[i].z,1000000*1000000*1000*dSplines[i].w);
	}
	if ( nonz != 0 )
		abssum /= nonz;
	spline->aveslopeabs = abssum;
	return(lastval);
}

int32_t PAX_genspline(struct PAX_spline *spline,int32_t splineid,char *name,uint32_t *utc32,double *splinevals,int32_t maxsplines,double *refvals)
{
    int32_t i; double output[2048],slopes[2048],origvals[MAX_SPLINES];
    memset(spline,0,sizeof(*spline)), memset(output,0,sizeof(output)), memset(slopes,0,sizeof(slopes));
    spline->dispincr = 3600, spline->basenum = splineid, strcpy(spline->name,name);
    memcpy(origvals,splinevals,sizeof(*splinevals) * MAX_SPLINES);
    spline->lastval = PAX_calcspline(spline,output,slopes,sizeof(output)/sizeof(*output),utc32,splinevals,maxsplines);
    for (i=0; i<spline->num; i++)
    {
        if ( i < spline->num )
        {
            if ( 0 && refvals[i] != 0 && output[i * 24] != refvals[i] )
                printf("{%.8f != %.8f}.%d ",output[i * 24],refvals[i],i);
            spline->pricevals[i] = output[i * 24];
        }
    }
    //printf("spline.%s num.%d\n",name,spline->num);
    return(spline->num);
}

int32_t PAX_calcmatrix(double matrix[MAX_CURRENCIES][MAX_CURRENCIES])
{
    int32_t basenum,relnum,nonz,vnum,iter,numbase,numerrs = 0; double sum,vsum,price,price2,basevals[32],errsum=0;
    memset(basevals,0,sizeof(basevals));
    for (iter=0; iter<2; iter++)
    {
        numbase = MAX_CURRENCIES;
        for (basenum=0; basenum<numbase; basenum++)
        {
            for (vsum=sum=vnum=nonz=relnum=0; relnum<numbase; relnum++)
            {
                if ( basenum != relnum )
                {
                    if ( (price= matrix[basenum][relnum]) != 0. )
                    {
                        price /= (MINDENOMS[relnum] * .001);
                        price *= (MINDENOMS[basenum] * .001);
                        if ( iter == 0 )
                            sum += (price), nonz++;//, printf("%.8f ",price);
                        else sum += fabs((price) - (basevals[basenum] / basevals[relnum])), nonz++;
                    }
                    if ( (price2= matrix[relnum][basenum]) != 0. )
                    {
                        price2 *= (MINDENOMS[relnum] * .001);
                        price2 /= (MINDENOMS[basenum] * .001);
                        if ( iter == 0 )
                            vsum += (price2), vnum++;
                        else vsum += fabs(price2 - (basevals[relnum] / basevals[basenum])), vnum++;
                    }
                    //if ( iter == 0 && 1/price2 > price )
                    //    printf("base.%d rel.%d price2 %f vs %f\n",basenum,relnum,1/price2,price);
                }
            }
            if ( iter == 0 )
                sum += 1., vsum += 1.;
            if ( nonz != 0 )
                sum /= nonz;
            if ( vnum != 0 )
                vsum /= vnum;
            if ( iter == 0 )
                basevals[basenum] = (sum + 1./vsum) / 2.;
            else errsum += (sum + vsum)/2, numerrs++;//, printf("(%.8f %.8f) ",sum,vsum);
            //printf("date.%d (%.8f/%d %.8f/%d).%02d -> %.8f\n",i,sum,nonz,vsum,vnum,basenum,basevals[basenum]);
        }
        if ( iter == 0 )
        {
            for (sum=relnum=0; relnum<numbase; relnum++)
                sum += (basevals[relnum]);//, printf("%.8f ",(basevals[relnum]));
            //printf("date.%d sums %.8f and vsums iter.%d\n",relnum,sum/7,iter);
            sum /= (numbase - 1);
            for (relnum=0; relnum<numbase; relnum++)
                basevals[relnum] /= sum;//, printf("%.8f ",basevals[relnum]);
            //printf("date.%d sums %.8f and vsums iter.%d\n",i,sum,iter);
        }
        else
        {
            for (basenum=0; basenum<numbase; basenum++)
                matrix[basenum][basenum] = basevals[basenum];
        }
    }
    if ( numerrs != 0 )
        errsum /= numerrs;
    return(errsum);
}

int32_t PAX_getmatrix(double *basevals,struct PAX_data *dp,double Hmatrix[32][32],double *RTprices,char *contracts[],int32_t num)
{
    int32_t i,j,c; char name[65]; double btcusd,kmdbtc;
    memcpy(Hmatrix,dp->ecbmatrix,sizeof(dp->ecbmatrix));
    PAX_calcmatrix(Hmatrix);
    /*for (i=0; i<32; i++)
    {
        for (j=0; j<32; j++)
            printf("%.6f ",Hmatrix[i][j]);
        printf("%s\n",CURRENCIES[i]);
    }*/
    btcusd = dp->btcusd;
    kmdbtc = dp->kmdbtc;
    if ( btcusd > SMALLVAL )
        dxblend(&dp->BTCUSD,btcusd,.9);
    if ( kmdbtc > SMALLVAL )
        dxblend(&dp->KMDBTC,kmdbtc,.9);
    // char *cryptostrs[8] = { "btc", "nxt", "unity", "eth", "ltc", "xmr", "bts", "xcp" };
    // "BTCUSD", "NXTBTC", "SuperNET", "ETHBTC", "ETCBTC", "XMRBTC", "KMDBTC", "XCPBTC",  // BTC priced
    for (i=0; i<num; i++)
    {
        if ( contracts[i] == 0 )
            continue;
        if ( i == num-1 && strcmp(contracts[i],"BTCUSD") == 0 )
        {
            RTprices[i] = dp->BTCUSD;
            continue;
        }
        else if ( i == num-2 && strcmp(contracts[i],"BTCCNY") == 0 )
        {
            continue;
        }
        else if ( i == num-3 && strcmp(contracts[i],"BTCRUB") == 0 )
        {
            continue;
        }
        else if ( i == num-4 && strcmp(contracts[i],"XAUUSD") == 0 )
        {
            continue;
        }
        if ( strcmp(contracts[i],"NXTBTC") == 0 )
            RTprices[i] = dp->cryptos[1];
        else if ( strcmp(contracts[i],"SuperNET") == 0 )
            RTprices[i] = dp->cryptos[2];
        else if ( strcmp(contracts[i],"ETHBTC") == 0 )
            RTprices[i] = dp->cryptos[3];
        else if ( strcmp(contracts[i],"ETCBTC") == 0 )
            RTprices[i] = dp->cryptos[4];
        else if ( strcmp(contracts[i],"XMRBTC") == 0 )
            RTprices[i] = dp->cryptos[5];
        else if ( strcmp(contracts[i],"KMDBTC") == 0 )
            RTprices[i] = dp->cryptos[6];
        else if ( strcmp(contracts[i],"XCPBTC") == 0 )
            RTprices[i] = dp->cryptos[7];
        else if ( i < MAX_CURRENCIES )
        {
            dp->RTmatrix[i][i] = basevals[i] = Hmatrix[i][i];
            //if ( Debuglevel > 2 )
            //printf("(%s %f).%d ",CURRENCIES[i],basevals[i],i);
        }
        else if ( (c= PAX_contractnum(contracts[i],0)) >= 0 )
        {
            RTprices[i] = dp->RTprices[c];
            //if ( isdecimalstr(contracts[i]+strlen(contracts[i])-2) != 0 )
            //    cprices[i] *= .0001;
        }
        else
        {
            for (j=0; j<sizeof(Yahoo_metals)/sizeof(*Yahoo_metals); j++)
            {
                sprintf(name,"%sUSD",Yahoo_metals[j]);
                if ( contracts[i] != 0 && strcmp(name,contracts[i]) == 0 )
                {
                    RTprices[i] = dp->RTmetals[j];
                    break;
                }
            }
        }
        if ( Debuglevel > 2 )
            printf("(%f %f) i.%d num.%d %s %f\n",dp->BTCUSD,dp->KMDBTC,i,num,contracts[i],RTprices[i]);
        //printf("RT.(%s %f) ",contracts[i],RTprices[i]);
    }
    return(dp->ecbdatenum);
}

int32_t PAX_emitprices(uint32_t pvals[32],struct PAX_data *dp)
{
    double matrix[MAX_CURRENCIES][MAX_CURRENCIES],RTmatrix[MAX_CURRENCIES][MAX_CURRENCIES],cprices[64],basevals[64]; struct price_resolution prices[256]; int32_t i,nonz = 0;
    memset(cprices,0,sizeof(cprices));
    if ( PAX_getmatrix(basevals,dp,matrix,cprices+1,PAX_bases+1,sizeof(PAX_bases)/sizeof(*PAX_bases)-1) > 0 )
    {
        cprices[0] = dp->KMDBTC;
        /*for (i=0; i<32; i++)
            dp->RTmatrix[i][i] = basevals[i];
        for (i=0; i<32; i++)
            printf("%.6f ",basevals[i]);
        printf("basevals\n");
        for (i=0; i<64; i++)
            printf("%.6f ",cprices[i]);
        printf("cprices\n");*/
        memset(prices,0,sizeof(prices));
        memset(matrix,0,sizeof(matrix));
        memset(RTmatrix,0,sizeof(RTmatrix));
        //peggy_prices(prices,dp->BTCUSD,dp->KMDBTC,PAX_bases,sizeof(PAX_bases)/sizeof(*PAX_bases),cprices,basevals);
        for (i=0; i<sizeof(PAX_bases)/sizeof(*PAX_bases); i++)
        {
            pvals[i] = 0;
            if ( (prices[i].Pval= basevals[i]*1000000000) != 0 )
            {
                nonz++;
                if ( prices[i].Pval > 0xffffffff )
                    printf("Pval[%d] overflow error %lld\n",i,(long long)prices[i].Pval);
                else pvals[i] = (uint32_t)prices[i].Pval;
            }
            if ( Debuglevel > 2 )
                printf("{%s %.6f %u}.%d ",PAX_bases[i],Pval(&prices[i]),(uint32_t)prices[i].Pval,peggy_mils(i));
        }
    } else printf("pricematrix returned null\n");
    //printf("nonz.%d\n",nonz);
    return(nonz);
}

double PAX_baseprice(struct PAX_spline splines[],uint32_t timestamp,int32_t basenum)
{
    double btc,kmd,kmdusd,usdval;
    btc = 1000. * _pairaved(PAX_splineval(&splines[MAX_CURRENCIES+0],timestamp,0),PAX_splineval(&splines[MAX_CURRENCIES+1],timestamp,0));
    kmd = .01 * PAX_splineval(&splines[MAX_CURRENCIES+2],timestamp,0);
    if ( btc != 0. && kmd != 0. )
    {
        kmdusd = (btc * kmd);
        usdval = PAX_splineval(&splines[USD],timestamp,0);
        if ( basenum == USD )
            return(1. / kmdusd);
        else return(PAX_splineval(&splines[basenum],timestamp,0) / (kmdusd * usdval));
    }
    return(0.);
}

double PAX_getprice(char *retbuf,char *base,char *rel,char *contract,struct PAX_data *dp)
{
    int32_t i,c,basenum,relnum,n = 0; double yprice,daily,revdaily,price;
    price = yprice = daily = revdaily = 0.;
    PAX_ispair(base,rel,contract);
    if ( base[0] != 0 && rel[0] != 0 )
    {
        basenum = PAX_basenum(base), relnum = PAX_basenum(rel);
        if ( basenum >= 0 && relnum >= 0 && basenum < MAX_CURRENCIES && relnum < MAX_CURRENCIES )
            daily = dp->dailyprices[basenum*MAX_CURRENCIES + relnum], revdaily = dp->dailyprices[relnum*MAX_CURRENCIES + basenum];
    }
    for (i=0; i<sizeof(Yahoo_metals)/sizeof(*Yahoo_metals); i++)
        if ( strncmp(Yahoo_metals[i],contract,3) == 0 && strcmp(contract+3,"USD") == 0 )
        {
            yprice = dp->metals[i];
            break;
        }
    sprintf(retbuf,"{\"result\":\"success\",\"contract\":\"%s\",\"base\":\"%s\",\"rel\":\"%s\"",contract,base,rel);
    if ( (c= PAX_contractnum(contract,0)) >= 0 )
    {
        if ( dp->tbids[c] != 0. && dp->tasks[c] != 0. )
        {
            price += (dp->tbids[c] + dp->tasks[c]), n += 2;
            sprintf(retbuf+strlen(retbuf),",\"truefx\":{\"timestamp\":\"%u\",\"bid\":%.8f,\"ask\":%.8f}",dp->ttimestamps[c],dp->tbids[c],dp->tasks[c]);
        }
        if ( dp->fbids[c] != 0. && dp->fasks[c] != 0. )
        {
            price += (dp->fbids[c] + dp->fasks[c]), n += 2;
            sprintf(retbuf+strlen(retbuf),",\"fxcm\":{\"bid\":%.8f,\"ask\":%.8f}",dp->fbids[c],dp->fasks[c]);
        }
        /*if ( dp->ibids[c] != 0. && dp->iasks[c] != 0. )
        {
            price += (dp->ibids[c] + dp->iasks[c]), n += 2;
            sprintf(retbuf+strlen(retbuf),",\"instaforex\":{\"timestamp\":%u,\"bid\":%.8f,\"ask\":%.8f}",dp->itimestamps[c],dp->ibids[c],dp->iasks[c]);
        }*/
        if ( yprice != 0. )
            sprintf(retbuf+strlen(retbuf),",\"yahoo\":{\"price\":%.8f}",yprice);
        if ( daily != 0. || revdaily != 0. )
            sprintf(retbuf+strlen(retbuf),",\"ecb\":{\"date\":\"%s\",\"daily\":%.8f,\"reverse\":%.8f}",dp->edate,daily,revdaily);
    }
    if ( n > 0 )
        price /= n;
    sprintf(retbuf+strlen(retbuf),",\"aveprice\":%.8f,\"n\":%d}",price,n);
    return(price);
}

/*double PAX_aveprice(struct supernet_info *myinfo,char *base)
{
    struct peggy_info *PEGS; int32_t basenum;
    if ( (PEGS= myinfo->PEGS) != 0 && (basenum= PAX_basenum(base)) >= 0 )
    {
        return(PEGS->data.RTmatrix[basenum][basenum]);
    }
    return(0.);
}*/
cJSON *url_json(char *url)
{
    char *jsonstr; cJSON *json = 0;
    if ( (jsonstr= issue_curl(url)) != 0 )
    {
        //printf("(%s) -> (%s)\n",url,jsonstr);
        json = cJSON_Parse(jsonstr);
        free(jsonstr);
    }
    return(json);
}

cJSON *url_json2(char *url)
{
    char *jsonstr; cJSON *json = 0;
    if ( (jsonstr= issue_curl(url)) != 0 )
    {
        //printf("(%s) -> (%s)\n",url,jsonstr);
        json = cJSON_Parse(jsonstr);
        free(jsonstr);
    }
    return(json);
}

double PAX_yahoo(char *metal)
{
    // http://finance.yahoo.com/webservice/v1/symbols/allcurrencies/quote?format=json
    // http://finance.yahoo.com/webservice/v1/symbols/EUR=USD/quote?format=json
    // http://finance.yahoo.com/webservice/v1/symbols/XAU=X/quote?format=json
    // http://finance.yahoo.com/webservice/v1/symbols/XAG=X/quote?format=json
    // http://finance.yahoo.com/webservice/v1/symbols/XPT=X/quote?format=json
    // http://finance.yahoo.com/webservice/v1/symbols/XPD=X/quote?format=json
    char url[1024],*jsonstr; cJSON *json,*obj,*robj,*item,*field; double price = 0.;
    sprintf(url,"http://finance.yahoo.com/webservice/v1/symbols/%s=X/quote?&format=json",metal);
    if ( (jsonstr= issue_curl(url)) != 0 )
    {
        //printf("(%s)\n",jsonstr);
        if ( (json= cJSON_Parse(jsonstr)) != 0 )
        {
            if ( (obj= jobj(json,"list")) != 0 && (robj= jobj(obj,"resources")) != 0 && (item= jitem(robj,0)) != 0 )
            {
                if ( (robj= jobj(item,"resource")) != 0 && (field= jobj(robj,"fields")) != 0 && (price= jdouble(field,"price")) != 0 )
                    price = 1. / price;
            }
            free_json(json);
        }
        free(jsonstr);
    }
    if ( Debuglevel > 2 )
        printf("(%s %f) ",metal,price);
    dpow_price("yahoo",metal,price,price);
    return(price);
}

void PAX_btcprices(struct PAX_data *dp,int32_t enddatenum,int32_t numdates)
{
    int32_t i,n,year,month,day,seconds,datenum; char url[1024],url2[1024],date[64],*dstr,*str;
    uint32_t timestamp,utc32[MAX_SPLINES]; struct tai t;
    cJSON *coindesk,*quandl,*kmdhist,*bpi,*array,*item;
    double kmddaily[MAX_SPLINES],cdaily[MAX_SPLINES],qdaily[MAX_SPLINES],ask,high,low,bid,close,vol,quotevol,open,price = 0.;
    coindesk = url_json("http://api.coindesk.com/v1/bpi/historical/close.json");
    sprintf(url,"https://poloniex.com/public?command=returnChartData&currencyPair=BTC_KMD&start=%ld&end=9999999999&period=86400",(long)(time(NULL)-numdates*3600*24));
    sprintf(url2,"https://poloniex.com/public?command=returnChartData&currencyPair=BTC_BTCD&start=%ld&end=9999999999&period=86400",(long)(time(NULL)-numdates*3600*24));
    if ( (bpi= jobj(coindesk,"bpi")) != 0 )
    {
        datenum = enddatenum;
        memset(utc32,0,sizeof(utc32));
        memset(cdaily,0,sizeof(cdaily));
        if ( datenum == 0 )
        {
            datenum = OS_conv_unixtime(&t,&seconds,(uint32_t)time(NULL));
            printf("got datenum.%d %d %d %d\n",datenum,seconds/3600,(seconds/60)%24,seconds%60);
        }
        for (i=0; i<numdates; i++)
        {
            expand_datenum(date,datenum);
            if ( (price= jdouble(bpi,date)) != 0 )
            {
                utc32[numdates - 1 - i] = OS_conv_datenum(datenum,12,0,0);
                cdaily[numdates - 1 - i] = price * .001;
                if ( i == 0 )
                    dpow_price("bpi","BTCUSD",price,price);
                //printf("(%s %u %f) ",date,utc32[numdates - 1 - i],price);
            }
            datenum = ecb_decrdate(&year,&month,&day,date,datenum);
        }
        PAX_genspline(&dp->splines[MAX_CURRENCIES],MAX_CURRENCIES,"coindesk",utc32,cdaily,numdates,cdaily);
        
    } else printf("no bpi\n");
    quandl = url_json("https://www.quandl.com/api/v1/datasets/BAVERAGE/USD.json?rows=64");
    if ( 0 && (str= jstr(quandl,"updated_at")) != 0 && (datenum= conv_date(&seconds,str)) > 0 && (array= jarray(&n,quandl,"data")) != 0 )
    {
        printf("datenum.%d data.%d %d\n",datenum,n,cJSON_GetArraySize(array));
        memset(utc32,0,sizeof(utc32)), memset(qdaily,0,sizeof(qdaily));
        for (i=0; i<n&&i<MAX_SPLINES; i++)
        {
            // ["Date","24h Average","Ask","Bid","Last","Total Volume"]
            // ["2015-07-25",289.27,288.84,288.68,288.87,44978.61]
            item = jitem(array,i);
            if ( Debuglevel > 2 )
                printf("(%s) ",cJSON_Print(item));
            if ( (dstr= jstr(jitem(item,0),0)) != 0 && (datenum= conv_date(&seconds,dstr)) > 0 )
            {
                price = jdouble(jitem(item,1),0), ask = jdouble(jitem(item,2),0), bid = jdouble(jitem(item,3),0);
                close = jdouble(jitem(item,4),0), vol = jdouble(jitem(item,5),0);
                if ( Debuglevel > 2 )
                    fprintf(stderr,"%d.[%d %f %f %f %f %f].%d ",i,datenum,price,ask,bid,close,vol,n);
                utc32[numdates - 1 - i] = OS_conv_datenum(datenum,12,0,0), qdaily[numdates - 1 - i] = price * .001;
                if ( i == n-1 )
                    dpow_price("quandl","BTCUSD",bid,ask);
            }
        }
        PAX_genspline(&dp->splines[MAX_CURRENCIES+1],MAX_CURRENCIES+1,"quandl",utc32,qdaily,n<MAX_SPLINES?n:MAX_SPLINES,qdaily);
    }
    kmdhist = url_json(url);
    //{"date":1406160000,"high":0.01,"low":0.00125,"open":0.01,"close":0.001375,"volume":1.50179994,"quoteVolume":903.58818412,"weightedAverage":0.00166204},
    if ( (array= jarray(&n,kmdhist,0)) != 0 )
    {
        memset(utc32,0,sizeof(utc32)), memset(kmddaily,0,sizeof(kmddaily));
        for (i=0; i<MAX_SPLINES; i++)
            kmddaily[i] = 0.0001 * 100.;
        //printf("GOT.(%s)\n",cJSON_Print(array));
        for (i=0; i<n; i++)
        {
            item = jitem(array,i);
            timestamp = juint(item,"date"), high = jdouble(item,"high"), low = jdouble(item,"low"), open = jdouble(item,"open");
            close = jdouble(item,"close"), vol = jdouble(item,"volume"), quotevol = jdouble(item,"quoteVolume"), price = jdouble(item,"weightedAverage");
            //printf("[%u %f %f %f %f %f %f %f]",timestamp,high,low,open,close,vol,quotevol,price);
            if ( Debuglevel > 2 )
                printf("[%u %d %f]",timestamp,OS_conv_unixtime(&t,&seconds,timestamp),price);
            utc32[i] = timestamp - 12*3600, kmddaily[i] = price * 100.;
        }
        if ( Debuglevel > 2 )
            printf("poloniex.%d\n",n);
        PAX_genspline(&dp->splines[MAX_CURRENCIES+2],MAX_CURRENCIES+2,"kmdhist",utc32,kmddaily,n<MAX_SPLINES?n:MAX_SPLINES,kmddaily);
    }
    // https://poloniex.com/public?command=returnChartData&currencyPair=BTC_KMD&start=1405699200&end=9999999999&period=86400
}

int32_t PAX_ecbparse(char *date,double *prices,char *url,int32_t basenum)
{
    char *jsonstr,*relstr,*basestr,name[16]; int32_t count=0,i,relnum; cJSON *json,*ratesobj,*item; struct destbuf tmp;
    if ( (jsonstr= issue_curl(url)) != 0 )
    {
        if ( Debuglevel > 2 )
            printf("(%s)\n",jsonstr);
        if ( (json= cJSON_Parse(jsonstr)) != 0 )
        {
            if ( jobj(json,"error") != 0 || jobj(json,"date") == 0 )
            {
                printf("Got error from fixer.io (%s)\n",jsonstr);
                sleep(10);
            }
            else
            {
                copy_cJSON(&tmp,jobj(json,"date")), safecopy(date,tmp.buf,64);
                if ( (basestr= jstr(json,"base")) != 0 && strcmp(basestr,CURRENCIES[basenum]) == 0 && (ratesobj= jobj(json,"rates")) != 0 && (item= ratesobj->child) != 0 )
                {
                    while ( item != 0 )
                    {
                        if ( (relstr= get_cJSON_fieldname(item)) != 0 && (relnum= PAX_basenum(relstr)) >= 0 )
                        {
                            i = basenum*MAX_CURRENCIES + relnum;
                            prices[i] = item->valuedouble;
                            //if ( basenum == JPYNUM )
                            //    prices[i] *= 100.;
                            // else if ( relnum == JPYNUM )
                            //     prices[i] /= 100.;
                            count++;
                            if ( Debuglevel > 2 )
                                printf("(%02d:%02d %f) ",basenum,relnum,prices[i]);
                            sprintf(name,"%s%s",CURRENCIES[basenum],CURRENCIES[relnum]);
                        } else printf("cant find.(%s)\n",relstr);//, getchar();
                        item = item->next;
                    }
                }
            }
            free_json(json);
        }
        free(jsonstr);
    }
    return(count);
}

int32_t PAX_ecbprices(char *date,double *prices,int32_t year,int32_t month,int32_t day)
{
    // http://api.fixer.io/latest?base=CNH
    // http://api.fixer.io/2000-01-03?base=USD
    // "USD", "EUR", "JPY", "GBP", "AUD", "CAD", "CHF", "NZD"
    char baseurl[512],tmpdate[64],url[512],checkdate[16]; int32_t basenum,count,i,iter,nonz;
    checkdate[0] = 0;
    if ( year == 0 )
        strcpy(baseurl,"http://api.fixer.io/latest?base=");
    else
    {
        sprintf(checkdate,"%d-%02d-%02d",year,month,day);
        sprintf(baseurl,"http://api.fixer.io/%s?base=",checkdate);
    }
    count = 0;
    for (iter=0; iter<2; iter++)
    {
        for (basenum=0; basenum<sizeof(CURRENCIES)/sizeof(*CURRENCIES); basenum++)
        {
            if ( strcmp(CURRENCIES[basenum],"XAU") == 0 || basenum >= MAX_CURRENCIES )
                break;
            if ( iter == 0 )
            {
                sprintf(url,"%s%s",baseurl,CURRENCIES[basenum]);
                count += PAX_ecbparse(basenum == 0 ? date : tmpdate,prices,url,basenum);
                usleep(100000);
                if ( (basenum != 0 && strcmp(tmpdate,date) != 0) || (checkdate[0] != 0 && strcmp(checkdate,date) != 0) )
                {
                    //printf("date mismatch (%s) != (%s) or checkdate.(%s)\n",tmpdate,date,checkdate);
                    return(-1);
                }
            }
            else
            {
                for (nonz=i=0; i<sizeof(CURRENCIES)/sizeof(*CURRENCIES); i++)
                {
                    if ( strcmp(CURRENCIES[i],"XAU") == 0 || i >= MAX_CURRENCIES )
                        break;
                    if ( prices[MAX_CURRENCIES*basenum + i] != 0. )
                        nonz++;
                    if ( Debuglevel > 2 )
                        printf("%8.5f ",prices[MAX_CURRENCIES*basenum + i]);
                }
                if ( Debuglevel > 2 )
                    printf("%s.%d %d\n",CURRENCIES[basenum],basenum,nonz);
            }
        }
    }
    return(count);
}

int32_t ecb_matrix(double basevals[MAX_CURRENCIES],double matrix[MAX_CURRENCIES][MAX_CURRENCIES],char *date)
{
    FILE *fp=0; double price,bid,ask; int32_t n=0,datenum,relid,baseid,year=0,seconds,month=0,day=0,loaded = 0; char name[16],fname[64],_date[64];
    if ( date == 0 )
        date = _date, memset(_date,0,sizeof(_date));
    //printf("ecb_matrix(%s)\n",date);
    sprintf(fname,"%s/ECB/%s",GLOBAL_DBDIR,date), OS_compatible_path(fname);
    if ( date[0] != 0 && (fp= fopen(fname,"rb")) != 0 )
    {
        if ( fread(matrix,1,sizeof(matrix[0][0])*MAX_CURRENCIES*MAX_CURRENCIES,fp) == sizeof(matrix[0][0])*MAX_CURRENCIES*MAX_CURRENCIES )
            loaded = 1;
        else printf("fread error\n");
        fclose(fp);
    } else printf("ecb_matrix.(%s) load error fp.%p\n",fname,fp);
    datenum = conv_date(&seconds,date);
    year = datenum / 10000, month = (datenum / 100) % 100, day = (datenum % 100);
    if ( loaded == 0 )
    {
        if ( (n= PAX_ecbprices(date,&matrix[0][0],year,month,day)) > 0 )
        {
            sprintf(fname,"%s/ECB/%s",GLOBAL_DBDIR,date), OS_compatible_path(fname);
            if ( (fp= fopen(fname,"wb")) != 0 )
            {
                if ( fwrite(matrix,1,sizeof(matrix[0][0])*MAX_CURRENCIES*MAX_CURRENCIES,fp) == sizeof(matrix[0][0])*MAX_CURRENCIES*MAX_CURRENCIES )
                    loaded = 1;
                fclose(fp);
            }
        } //else printf("peggy_matrix error loading %d.%d.%d\n",year,month,day);
    }
    else
    {
        PAX_calcmatrix(matrix);
        for (baseid=0; baseid<MAX_CURRENCIES-1; baseid++)
            for (relid=baseid+1; relid<MAX_CURRENCIES; relid++)
            {
                bid = ask = 0.;
                sprintf(name,"%s%s",CURRENCIES[baseid],CURRENCIES[relid]);
                if ( (price= matrix[relid][baseid]) > SMALLVAL )
                    price = 1. / price;
                if ( matrix[baseid][relid] > SMALLVAL && matrix[baseid][relid] < price )
                    bid = matrix[baseid][relid], ask = price;
                else bid = price, ask = matrix[baseid][relid];
                if ( bid > SMALLVAL && ask > SMALLVAL )
                {
                    dpow_price("ecb",name,bid,ask);
                    n++;
                }
            }
        for (baseid=0; baseid<MAX_CURRENCIES; baseid++)
            basevals[baseid] = matrix[baseid][baseid];
    }
    if ( loaded == 0 && n == 0 )
    {
        printf("peggy_matrix couldnt process loaded.%d n.%d\n",loaded,n);
        return(-1);
    }
    //"2000-01-03"
    if ( (datenum= conv_date(&seconds,date)) < 0 )
        return(-1);
    //printf("loaded.(%s) nonz.%d (%d %d %d) datenum.%d\n",date,n,year,month,day,datenum);
    return(datenum);
}

void PAX_update(struct PAX_data *dp,double *btcusdp,double *kmdbtcp)
{
    int32_t i,n,iter,seconds,datenum; uint32_t timestamp; char url[1024],url2[1024],*dstr,*str;
    double kmddaily=0.,btcusd=0.,ask,high,low,bid,close,vol,quotevol,open,price = 0.;
    //cJSON *kmdtrades,*kmdtrades2,*,*bitcoincharts,;
    cJSON *quandl,*kmdhist,*array,*item,*bitcoinave,*blockchaininfo,*btctrades,*coindesk=0;
    sprintf(url,"https://poloniex.com/public?command=returnTradeHistory&currencyPair=USDT_BTC&start=%u&end=%u",(uint32_t)time(NULL)-60,(uint32_t)time(NULL));
    btctrades = url_json(url);
    //kmdtrades = url_json("https://poloniex.com/public?command=returnTradeHistory&currencyPair=USDT_BTC");
    //kmdtrades2 = url_json("https://bittrex.com/api/v1.1/public/getmarkethistory?market=BTC-KMD&count=50");
    *kmdbtcp = 0;
    bitcoinave = 0;//url_json("https://api.bitcoinaverage.com/ticker/USD/");
    //bitcoincharts = url_json("http://api.bitcoincharts.com/v1/weighted_prices.json");
    blockchaininfo = url_json("https://blockchain.info/ticker");
    coindesk = 0;//url_json("http://api.coindesk.com/v1/bpi/historical/close.json");
    sprintf(url,"https://poloniex.com/public?command=returnChartData&currencyPair=BTC_KMD&start=%ld&end=9999999999&period=86400",(long)(time(NULL)-3600*24));
    sprintf(url2,"https://poloniex.com/public?command=returnChartData&currencyPair=BTC_BTCD&start=%ld&end=9999999999&period=86400",(long)(time(NULL)-3600*24));
    quandl = 0;//url_json("https://www.quandl.com/api/v1/datasets/BAVERAGE/USD.json?rows=1");
    if ( 0 && (str= jstr(quandl,"updated_at")) != 0 && (datenum= conv_date(&seconds,str)) > 0 && (array= jarray(&n,quandl,"data")) != 0 )
    {
        //printf("datenum.%d data.%d %d\n",datenum,n,cJSON_GetArraySize(array));
        for (i=0; i<1; i++)
        {
            // ["Date","24h Average","Ask","Bid","Last","Total Volume"]
            // ["2015-07-25",289.27,288.84,288.68,288.87,44978.61]
            item = jitem(array,i);
            if ( (dstr= jstr(jitem(item,0),0)) != 0 && (datenum= conv_date(&seconds,dstr)) > 0 )
            {
                btcusd = price = jdouble(jitem(item,1),0), ask = jdouble(jitem(item,2),0), bid = jdouble(jitem(item,3),0);
                close = jdouble(jitem(item,4),0), vol = jdouble(jitem(item,5),0);
                //fprintf(stderr,"%d.[%d %f %f %f %f %f].%d ",i,datenum,price,ask,bid,close,vol,n);
            }
        }
    }
    if ( 1 )
    {
        double USD_average,avebid,aveask,bidvol,askvol,highbid,lowask,CMC_average,changes[3]; //struct exchange_quote sortbuf[512]; struct supernet_info *myinfo = SuperNET_MYINFO(0); cJSON *argjson = cJSON_Parse("{}");
        //aveask = instantdex_aveprice(myinfo,sortbuf,(int32_t)(sizeof(sortbuf)/sizeof(*sortbuf)),&askvol,"KMD","BTC",1,argjson);
        //avebid = instantdex_aveprice(myinfo,sortbuf,(int32_t)(sizeof(sortbuf)/sizeof(*sortbuf)),&bidvol,"KMD","BTC",-1,argjson);
        if ( 0 && avebid > SMALLVAL && aveask > SMALLVAL )
        {
            price = (avebid*bidvol + aveask*askvol) / (bidvol + askvol);
            *kmdbtcp = price;
            printf("set KMD price %f\n",price);
            dp->KMDBTC = price;
        }
        else if ( (dp->KMDBTC= get_theoretical(&avebid,&aveask,&highbid,&lowask,&CMC_average,changes,"komodo","KMD","BTC",&USD_average)) > SMALLVAL )
            *kmdbtcp = dp->KMDBTC;
        else
        {
            for (iter=1; iter<2; iter++)
            {
                kmdhist = url_json(iter == 0 ? url : url2);
                //{"date":1406160000,"high":0.01,"low":0.00125,"open":0.01,"close":0.001375,"volume":1.50179994,"quoteVolume":903.58818412,"weightedAverage":0.00166204},
                if ( kmdhist != 0 && (array= jarray(&n,kmdhist,0)) != 0 )
                {
                    //printf("GOT.(%s)\n",cJSON_Print(array));
                    for (i=0; i<1; i++)
                    {
                        item = jitem(array,i);
                        timestamp = juint(item,"date"), high = jdouble(item,"high"), low = jdouble(item,"low"), open = jdouble(item,"open");
                        close = jdouble(item,"close"), vol = jdouble(item,"volume"), quotevol = jdouble(item,"quoteVolume"), price = jdouble(item,"weightedAverage");
                        //printf("[%u %f %f %f %f %f %f %f]",timestamp,high,low,open,close,vol,quotevol,price);
                        //printf("[%u %d %f]",timestamp,OS_conv_unixtime(&seconds,timestamp),price);
                        if ( price != 0 )
                        {
                            if ( iter == 0 )
                                dp->KMDBTC = *kmdbtcp = kmddaily;
                            else dp->BTCDBTC = price;
                        }
                    }
                    //printf("poloniex.%d\n",n);
                }
                if ( kmdhist != 0 )
                    free_json(kmdhist);
            }
        }
    }
    if ( (*kmdbtcp= dp->KMDBTC) == 0. )
        *kmdbtcp = dp->BTCDBTC / 50.22;
    if ( (rand() % 100) == 0 )
        printf("KMD/BTC %.8f\n",*kmdbtcp);
    if ( btctrades != 0 && (array= jarray(&n,btctrades,0)) != 0 )
    {
        //printf("GOT.(%s)\n",cJSON_Print(array));
        for (i=0; i<1; i++)
        {
            item = jitem(array,i);
            timestamp = juint(item,"date");
            //printf("[%u %f %f %f %f %f %f %f]",timestamp,high,low,open,close,vol,quotevol,price);
            //printf("[%u %d %f]",timestamp,OS_conv_unixtime(&seconds,timestamp),price);
            *btcusdp = jdouble(item,"rate");
            //printf("(%s) -> %f\n",jprint(item,0),btcusd);
        }
        free(btctrades);
        //printf("poloniex.%d\n",n);
    }
    if ( 0 && bitcoinave != 0 )
    {
        if ( (price= jdouble(bitcoinave,"24h_avg")) > SMALLVAL )
        {
            //printf("bitcoinave %f %f\n",btcusd,price);
            dpow_price("bitcoinave","BTCUSD",price,price);
            dxblend(&btcusd,price,0.5);
        }
        free_json(bitcoinave);
    }
    if ( quandl != 0 )
        free_json(quandl);
    if ( coindesk != 0 )
        free_json(coindesk);
    if ( blockchaininfo != 0 )
    {
        if ( (item= jobj(blockchaininfo,"USD")) != 0 && item != 0 && (price= jdouble(item,"15m")) > SMALLVAL )
        {
            dpow_price("blockchain.info","BTCUSD",price,price);
            printf("blockchaininfo %f %f\n",btcusd,price);
            dxblend(&btcusd,price,0.5);
        }
        free_json(blockchaininfo);
    }
}

double blend_price(double *volp,double wtA,cJSON *jsonA,double wtB,cJSON *jsonB)
{
    //A.{"ticker":{"base":"BTS","target":"CNY","price":"0.02958291","volume":"3128008.39295500","change":"0.00019513","markets":[{"market":"BTC38","price":"0.02960000","volume":3051650.682955},{"market":"Bter","price":"0.02890000","volume":76357.71}]},"timestamp":1438490881,"success":true,"error":""}
    // B.{"id":"bts\/cny","price":"0.02940000","price_before_24h":"0.02990000","volume_first":"3048457.6857147217","volume_second":"90629.45859575272","volume_btc":"52.74","best_market":"btc38","latest_trade":"2015-08-02 03:57:38","coin1":"BitShares","coin2":"CNY","markets":[{"market":"btc38","price":"0.02940000","volume":"3048457.6857147217","volume_btc":"52.738317962865"},{"market":"bter","price":"0.04350000","volume":"0","volume_btc":"0"}]}
    double priceA,priceB,priceB24,price,volA,volB; cJSON *obj;
    priceA = priceB = priceB24= price = volA = volB = 0.;
    if ( jsonA != 0 && (obj= jobj(jsonA,"ticker")) != 0 )
    {
        priceA = jdouble(obj,"price");
        volA = jdouble(obj,"volume");
    }
    if ( jsonB != 0 )
    {
        priceB = jdouble(jsonB,"price");
        priceB24 = jdouble(jsonB,"price_before_24h");
        volB = jdouble(jsonB,"volume_first");
    }
    //printf("priceA %f volA %f, priceB %f %f volB %f\n",priceA,volA,priceB,priceB24,volB);
    if ( priceB > SMALLVAL && priceB24 > SMALLVAL )
        priceB = (priceB * .1) + (priceB24 * .9);
    else if ( priceB < SMALLVAL )
        priceB = priceB24;
    if ( priceA*volA < SMALLVAL )
        price = priceB;
    else if ( priceB*volB < SMALLVAL )
        price = priceA;
    else price = (wtA * priceA) + (wtB * priceB);
    *volp = (volA + volB);
    return(price);
}

void _crypto_update(double cryptovols[2][9][2],struct PAX_data *dp,int32_t selector)
{
    char *cryptonatorA = "https://www.cryptonator.com/api/full/%s-%s"; //unity-btc
    char *cryptocoinchartsB = "http://api.cryptocoincharts.info/tradingPair/%s_%s"; //bts_btc
    char *cryptostrs[9] = { "btc", "nxt", "unity", "eth", "kmd", "xmr", "bts", "xcp", "etc" };
    int32_t iter,i,j; double btcusd,kmdbtc,cnyusd,prices[9][2],volumes[9][2];
    char base[16],rel[16],url[512],name[16],*str; cJSON *jsonA,*jsonB;
    cnyusd = dp->CNYUSD;
    btcusd = dp->BTCUSD;
    if ( (kmdbtc= dp->KMDBTC) == 0. )
        ;//kmdbtc = dp->BTCDBTC / 50.22;
    printf("DEPRECATED: update with btcusd %f kmd %f cnyusd %f cnybtc %f\n",btcusd,kmdbtc,cnyusd,cnyusd/btcusd);
    return;
    if ( btcusd < SMALLVAL || kmdbtc < SMALLVAL )
    {
        PAX_update(dp,&btcusd,&kmdbtc);
        //printf("PAX_update with btcusd %f kmd %f\n",btcusd,kmdbtc);
    }
    memset(prices,0,sizeof(prices));
    memset(volumes,0,sizeof(volumes));
    for (j=0; j<sizeof(cryptostrs)/sizeof(*cryptostrs); j++)
    {
        str = cryptostrs[j];
        /*if ( strcmp(str,"etc") == 0 )
         {
         if ( prices[3][0] > SMALLVAL )
         break;
         i = 3;
         } else*/
        i = j;
        for (iter=0; iter<1; iter++)
        {
            if ( i == 0 && iter == 0 )
                strcpy(base,"kmd"), strcpy(rel,"btc");
            else strcpy(base,str), strcpy(rel,iter==0?"btc":"cny");
            sprintf(name,"%s%s",base,rel);
            //if ( selector == 0 )
            {
                sprintf(url,cryptonatorA,base,rel);
                jsonA = url_json(url);
            }
            //else
            {
                sprintf(url,cryptocoinchartsB,base,rel);
                jsonB = url_json(url);
            }
            prices[i][iter] = blend_price(&volumes[i][iter],0.4,jsonA,0.6,jsonB);
            if ( iter == 1 )
            {
                if ( btcusd > SMALLVAL )
                {
                    prices[i][iter] *= cnyusd / btcusd;
                    volumes[i][iter] *= cnyusd / btcusd;
                } else prices[i][iter] = volumes[i][iter] = 0.;
            }
            cryptovols[0][i][iter] = _pairaved(cryptovols[0][i][iter],prices[i][iter]);
            //cryptovols[1][i][iter] = _pairaved(cryptovols[1][i][iter],volumes[i][iter]);
            dpow_price("cryptonator",name,prices[i][iter],prices[i][iter]);
            if ( Debuglevel > 2 )
                printf("(%f %f).%d:%d ",cryptovols[0][i][iter],cryptovols[1][i][iter],i,iter);
            //if ( cnyusd < SMALLVAL || btcusd < SMALLVAL )
            //    break;
        }
    }
}

void PAX_RTupdate(double cryptovols[2][9][2],double RTmetals[4],double *RTprices,struct PAX_data *dp)
{
    char *cryptostrs[9] = { "btc", "nxt", "unity", "eth", "etc", "kmd", "xmr", "bts", "xcp" };
    int32_t iter,i,c,baserel,basenum,relnum; double cnyusd,btcusd,kmdbtc,bid=0.,ask=0.,price,vol,prices[8][2],volumes[8][2];
    char base[16],rel[16];
    PAX_update(dp,&btcusd,&kmdbtc);
    memset(prices,0,sizeof(prices));
    memset(volumes,0,sizeof(volumes));
    for (i=0; i<sizeof(cryptostrs)/sizeof(*cryptostrs); i++)
        for (iter=0; iter<2; iter++)
        {
            prices[i][iter] = cryptovols[0][i][iter];
            volumes[i][iter] = cryptovols[1][i][iter];
        }
    if ( prices[0][0] > SMALLVAL )
        dxblend(&kmdbtc,prices[0][0],.9);
    dxblend(&dp->kmdbtc,kmdbtc,.995);
    if ( dp->KMDBTC < SMALLVAL )
        dp->KMDBTC = dp->kmdbtc;
    if ( (cnyusd= dp->CNYUSD) > SMALLVAL )
    {
        if ( prices[0][1] > SMALLVAL )
        {
            //printf("cnyusd %f, btccny %f -> btcusd %f %f\n",cnyusd,prices[0][1],prices[0][1]*cnyusd,btcusd);
            btcusd = prices[0][1] * cnyusd;
            if ( dp->btcusd < SMALLVAL )
                dp->btcusd = btcusd;
            else dxblend(&dp->btcusd,btcusd,.995);
            if ( dp->BTCUSD < SMALLVAL )
                dp->BTCUSD = dp->btcusd;
            printf("cnyusd %f, btccny %f -> btcusd %f %f -> %f %f %f\n",cnyusd,prices[0][1],prices[0][1]*cnyusd,btcusd,dp->btcusd,dp->btcusd,dp->BTCUSD);
        }
    }
    for (i=1; i<sizeof(cryptostrs)/sizeof(*cryptostrs); i++)
    {
        vol = volumes[i][0];
        vol += volumes[i][1];
        if ( vol > SMALLVAL )
        {
            price = ((prices[i][0] * volumes[i][0]) + (prices[i][1] * volumes[i][1])) / vol;
            if ( Debuglevel > 2 )
                printf("%s %f v%f + %f v%f -> %f %f\n",cryptostrs[i],prices[i][0],volumes[i][0],prices[i][1],volumes[i][1],price,dp->cryptos[i]);
            dxblend(&dp->cryptos[i],price,.995);
        }
    }
    btcusd = dp->BTCUSD;
    kmdbtc = dp->KMDBTC;
    if ( Debuglevel > 2 )
        printf("    update with btcusd %f kmd %f\n",btcusd,kmdbtc);
    if ( btcusd < SMALLVAL || kmdbtc < SMALLVAL )
    {
        PAX_update(dp,&btcusd,&kmdbtc);
        if ( Debuglevel > 2 )
            printf("     price777_update with btcusd %f kmd %f\n",btcusd,kmdbtc);
    } else dp->BTCUSD = btcusd, dp->KMDBTC = kmdbtc;
    for (c=0; c<sizeof(CONTRACTS)/sizeof(*CONTRACTS); c++)
    {
        for (iter=0; iter<3; iter++)
        {
            switch ( iter )
            {
                case 0: bid = dp->tbids[c], ask = dp->tasks[c]; break;
                case 1: bid = dp->fbids[c], ask = dp->fasks[c]; break;
                case 2: bid = dp->ibids[c], ask = dp->iasks[c]; break;
            }
            if ( (price= _pairaved(bid,ask)) > SMALLVAL )
            {
                if ( Debuglevel > 2 )
                    printf("%.6f ",price);
                dxblend(&RTprices[c],price,.995);
                if ( 0 && (baserel= PAX_ispair(base,rel,CONTRACTS[c])) >= 0 )
                {
                    basenum = (baserel >> 8) & 0xff, relnum = baserel & 0xff;
                    if ( basenum < 32 && relnum < 32 )
                    {
                        //printf("%s.%d %f <- %f\n",CONTRACTS[c],c,RTmatrix[basenum][relnum],RTprices[c]);
                        //dxblend(&RTmatrix[basenum][relnum],RTprices[c],.999);
                    }
                }
                if ( strcmp(CONTRACTS[c],"XAUUSD") == 0 )
                    dxblend(&RTmetals[0],price,.995);
            }
        }
    }
    for (i=0; i<sizeof(Yahoo_metals)/sizeof(*Yahoo_metals); i++)
        if ( dp->metals[i] != 0 )
            dxblend(&RTmetals[i],dp->metals[i],.995);
}

void PAX_bidask(struct exchange_info *exchange,uint32_t *timestamps,double *bids,double *asks,int32_t baseid,int32_t relid)
{
    int32_t contractnum; struct exchange_quote bidasks[2];
    contractnum = Baserel_contractnum[baseid][relid];
    (*exchange->issue.price)(exchange,CURRENCIES[baseid],CURRENCIES[relid],bidasks,1,0.,0,0);
    //bids[contractnum] = bidasks[0].price;
    //asks[contractnum] = bidasks[1].price;
    //timestamps[contractnum] = bidasks[0].timestamp;
    //printf("%s%s.(%s %.6f) %s\n",CURRENCIES[baseid],CURRENCIES[relid],CONTRACTS[contractnum],_pairaved(bids[contractnum],asks[contractnum]),exchange->name);
}

struct exchange_info *PAX_bidasks(char *exchangestr,uint32_t *timestamps,double *bids,double *asks)
{
    int32_t baseid,relid; struct exchange_info *exchange;
    if ( (exchange= exchanges777_find(exchangestr)) != 0 )
    {
        for (baseid=0; baseid<8; baseid++)
        {
            for (relid=0; relid<8; relid++)
            {
                if ( Currency_contractdirs[baseid][relid] > 0 )
                    PAX_bidask(exchange,timestamps,bids,asks,baseid,relid);
            }
        }
    } else printf("cant find (%s) exchange\n",exchangestr);
    return(exchange);
}

void dpow_price(char *exchange,char *name,double bid,double ask)
{
    // adjust MAX_CURRENCIES, btcusd, btccny
    //printf("%-12s %16.8f %16.8f %s\n",name,bid,ask,exchange);
}

uint32_t PAX_val32(double val)
{
    uint32_t val32 = 0; struct price_resolution price;
    if ( (price.Pval= val*1000000000) != 0 )
    {
        if ( price.Pval > 0xffffffff )
            printf("Pval overflow error %lld\n",(long long)price.Pval);
        else val32 = (uint32_t)price.Pval;
    }
    return(val32);
}

double PAX_val(uint32_t pval,int32_t baseid)
{
    if ( baseid >= 0 && baseid < MAX_CURRENCIES )
        return(((double)pval / 1000000000.) / MINDENOMS[baseid]);
    return(0.);
}

void PAX_genecbsplines(struct PAX_data *dp)
{
    static portable_mutex_t mutex; static int32_t initflag;
    int32_t i,j,datenum,seconds,numsamples; double prices[128][MAX_SPLINES],splineval,diff; uint32_t pvals[MAX_CURRENCIES],utc32[MAX_SPLINES],timestamp; struct tai t;
    if ( initflag == 0 )
    {
        portable_mutex_init(&mutex);
        initflag = 1;
    }
    portable_mutex_lock(&mutex);
    for (i=numsamples=0; i<28; i++)
    {
        datenum = OS_conv_unixtime(&t,&seconds,(uint32_t)time(NULL)-(28-i+1)*24*3600);
        expand_datenum(dp->edate,datenum);
        timestamp = OS_conv_datenum(datenum,12,0,0);
        printf("i.%d datenum.%d %s t%u\n",i,datenum,dp->edate,timestamp);
        if ( (datenum= ecb_matrix(dp->basevals,dp->ecbmatrix,dp->edate)) > 0 )
        {
            utc32[numsamples] = timestamp;
            for (j=0; j<MAX_CURRENCIES; j++)
            {
                pvals[j] = PAX_val32(dp->basevals[j]);
                prices[j][numsamples] = dp->basevals[j];
            }
            numsamples++;
        }
    }
    for (j=0; j<3; j++)
        utc32[numsamples + j] = utc32[numsamples + j - 1] + (24 * 3600);
    for (j=0; j<MAX_CURRENCIES; j++)
    {
        PAX_genspline(&dp->splines[j],j,CURRENCIES[j],utc32,prices[j],numsamples,prices[j]);
        splineval = PAX_splineval(&dp->splines[j],utc32[numsamples-1]- 8*3600,1);
        diff = (prices[j][numsamples-1] - splineval);
        prices[j][numsamples] = prices[j][numsamples-1] + diff;
        diff += prices[j][numsamples-1] - PAX_splineval(&dp->splines[j],utc32[numsamples-1] - 12*3600,1);
        prices[j][numsamples+1] = prices[j][numsamples-1] + diff;
        diff += prices[j][numsamples-1] - PAX_splineval(&dp->splines[j],utc32[numsamples-1] - 16*3600,1);
        prices[j][numsamples+2] = prices[j][numsamples-1] + diff;
        //printf("%s splineval %f vs %f %f %f\n",CURRENCIES[j],prices[j][numsamples-1],prices[j][numsamples],prices[j][numsamples+1],prices[j][numsamples+2]);
        PAX_genspline(&dp->splines[j],j,CURRENCIES[j],utc32,prices[j],numsamples+3,prices[j]);
    }
    portable_mutex_unlock(&mutex);
}

#define BTCFACTOR_TIMESTAMP 1503746319
#define BTCFACTOR_HEIGHT 466266

int32_t PAX_idle(struct supernet_info *myinfo)//struct PAX_data *argdp,int32_t idlegap)
{
    static double lastupdate,lastdayupdate; static uint32_t didinit; static char *userhome; int32_t idlegap = 10;
    FILE *fp; long filesize; char fname[512]; double splineval; uint32_t pvals[128],timestamp; int32_t i,datenum,seconds,c; struct tai t; struct PAX_data *dp; uint8_t data[512];
    if ( 1 || Currencymasks[0] == 0 ) // disable pax price gatherings
        return(0);
    if ( time(NULL) > didinit+12*3600 )
    {
        if ( (userhome= OS_filestr(&filesize,"userhome.txt")) == 0 )
            userhome = "root";
        else
        {
            while ( (c= userhome[strlen(userhome)-1]) == '\r' || c == '\n' || c == ' ' || c == '\t' )
            {
                userhome[strlen(userhome)-1] = 0;
            }
        }
        if ( myinfo->PAXDATA == 0 )
            myinfo->PAXDATA = calloc(1,sizeof(*dp));
        dp = myinfo->PAXDATA;
        PAX_genecbsplines(dp);
        printf("generated splines\n");
        didinit = (uint32_t)time(NULL);
        datenum = OS_conv_unixtime(&t,&seconds,didinit);
        expand_datenum(dp->edate,datenum);
    }
    dp = myinfo->PAXDATA;
    /*if ( 0 && time(NULL) > dp->lastupdate+10 )
    {
        _crypto_update(dp->cryptovols,dp,1);
        dp->lastupdate = (uint32_t)time(NULL);
    }*/
    if ( OS_milliseconds() > lastupdate + (1000*idlegap) )
    {
        lastupdate = OS_milliseconds();
        if ( OS_milliseconds() > lastdayupdate + 60000*60 )
        {
            lastdayupdate = OS_milliseconds();
            datenum = OS_conv_unixtime(&t,&seconds,(uint32_t)time(NULL));
            expand_datenum(dp->edate,datenum);
            if ( (datenum= ecb_matrix(dp->basevals,dp->ecbmatrix,dp->edate)) > 0 && datenum != dp->ecbdatenum )
            {
                dp->ecbdatenum = datenum;
                dp->ecbyear = dp->ecbdatenum / 10000,  dp->ecbmonth = (dp->ecbdatenum / 100) % 100,  dp->ecbday = (dp->ecbdatenum % 100);
                expand_datenum(dp->edate,datenum);
                memcpy(dp->RTmatrix,dp->ecbmatrix,sizeof(dp->RTmatrix));
                PAX_genecbsplines(dp);
            }
        }
        if ( 0 )
        {
            for (i=0; i<sizeof(Yahoo_metals)/sizeof(*Yahoo_metals); i++)
                dp->metals[i] = PAX_yahoo(Yahoo_metals[i]);
            PAX_bidasks("truefx",dp->ttimestamps,dp->tbids,dp->tasks);
            PAX_bidasks("fxcm",dp->ftimestamps,dp->fbids,dp->fasks);
            /*if ( (exchange= PAX_bidasks("instaforex",dp->itimestamps,dp->ibids,dp->iasks)) != 0 )
             {
             if ( (contractnum= PAX_contractnum("XAU","USD")) >= 0 )
             {
             (*exchange->issue.price)(exchange,"XAU","USD",bidasks,1,0.,0,0);
             dp->ibids[contractnum] = bidasks[0].price;
             dp->iasks[contractnum] = bidasks[1].price;
             dp->itimestamps[contractnum] = bidasks[0].timestamp;
             }
             }*/
            //printf("BTCUSD %f %f %f\n",btcusd,dp->btcusd,dp->BTCUSD);
            if ( dp->ecbmatrix[USD][USD] > SMALLVAL && dp->ecbmatrix[CNY][CNY] > SMALLVAL )
                dp->CNYUSD = (dp->ecbmatrix[CNY][CNY] / dp->ecbmatrix[USD][USD]);
            PAX_RTupdate(dp->cryptovols,dp->RTmetals,dp->RTprices,dp);
            PAX_emitprices(pvals,dp);
        }
        timestamp = (uint32_t)time(NULL);
        int32_t dispflag = ((rand() % 6) == 0);
        //printf("PAX_IDLE.%d %.8f %.8f\n",dispflag,dp->kmdbtc,dp->btcusd);
        if ( dp->kmdbtc == 0 || dp->btcusd == 0 || dispflag != 0 )
        {
            PAX_update(dp,&dp->btcusd,&dp->kmdbtc);
            for (i=0; i<MAX_CURRENCIES; i++)
            {
                splineval = PAX_splineval(&dp->splines[i],timestamp,0);
                pvals[6+i] = PAX_val32(splineval);
                if ( dispflag != 0 )
                    printf("%u ",pvals[6+i]);
            }
            if ( pvals[6+CNY] != 0 && pvals[6+USD] != 0 )
                dp->CNYUSD = ((double)pvals[6 + CNY] / pvals[6 + USD]) * MINDENOMS[USD] / MINDENOMS[CNY];
            pvals[1] = timestamp;
            pvals[2] = MAX_CURRENCIES + 3;
            pvals[3] = PAX_val32(dp->kmdbtc * 1000);
            double btcfactor;
            //if ( time(NULL) > BTCFACTOR_TIMESTAMP )
                btcfactor = .00001;
            //else btcfactor = .001;
            pvals[4] = PAX_val32(dp->btcusd * btcfactor);
            pvals[5] = PAX_val32(dp->CNYUSD);
            sprintf(fname,"/%s/.komodo/komodofeed",userhome);
            if ( (fp= fopen(fname,"wb")) != 0 )
            {
                for (i=1; i<MAX_CURRENCIES+6; i++)
                    iguana_rwnum(1,&data[i*sizeof(uint32_t)],sizeof(*pvals),(void *)&pvals[i]);
                pvals[0] = calc_crc32(0,(void *)&data[sizeof(uint32_t)],(MAX_CURRENCIES+5)*sizeof(*pvals));
                iguana_rwnum(1,data,sizeof(*pvals),(void *)&pvals[0]);
                if ( fwrite(data,sizeof(*pvals),MAX_CURRENCIES+6,fp) != MAX_CURRENCIES+6 )
                    printf("error writing pvals to (%s)\n",fname);
                fclose(fp);
            }
            if ( dispflag != 0 )
            {
                for (i=0; i<6; i++)
                    printf("%u ",pvals[i]);
                printf("KMD %.8f BTC %f CNY %f (%f) btcusd pval.%u\n",dp->kmdbtc,dp->btcusd,dp->CNYUSD,1./dp->CNYUSD,pvals[4]);
            }
        }
    }
    return(0);
}

void PAX_init()
{
    static int32_t didinit; //double commission = 0.;
    if ( didinit == 0 )
    {
        init_Currencymasks();
        //calc_smooth_code(127,7);
        //tradebot_monitorall(0,0,0,0,"fxcm",commission);
        //tradebot_monitorall(0,0,0,0,"truefx",commission);
        //tradebot_monitorall(0,0,0,0,"instaforex",commission);
        exchange_create("PAX",0);
        didinit = 1;
    }
}
