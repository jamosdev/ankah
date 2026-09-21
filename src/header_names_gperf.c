/* ANSI-C code produced by gperf version 3.1 */
/* Generated from src/header_names.gperf. */
/* Computed positions: -k'2' */

#if !((' ' == 32) && ('!' == 33) && ('"' == 34) && ('#' == 35) \
      && ('%' == 37) && ('&' == 38) && ('\'' == 39) && ('(' == 40) \
      && (')' == 41) && ('*' == 42) && ('+' == 43) && (',' == 44) \
      && ('-' == 45) && ('.' == 46) && ('/' == 47) && ('0' == 48) \
      && ('1' == 49) && ('2' == 50) && ('3' == 51) && ('4' == 52) \
      && ('5' == 53) && ('6' == 54) && ('7' == 55) && ('8' == 56) \
      && ('9' == 57) && (':' == 58) && (';' == 59) && ('<' == 60) \
      && ('=' == 61) && ('>' == 62) && ('?' == 63) && ('A' == 65) \
      && ('B' == 66) && ('C' == 67) && ('D' == 68) && ('E' == 69) \
      && ('F' == 70) && ('G' == 71) && ('H' == 72) && ('I' == 73) \
      && ('J' == 74) && ('K' == 75) && ('L' == 76) && ('M' == 77) \
      && ('N' == 78) && ('O' == 79) && ('P' == 80) && ('Q' == 81) \
      && ('R' == 82) && ('S' == 83) && ('T' == 84) && ('U' == 85) \
      && ('V' == 86) && ('W' == 87) && ('X' == 88) && ('Y' == 89) \
      && ('Z' == 90) && ('[' == 91) && ('\\' == 92) && (']' == 93) \
      && ('^' == 94) && ('_' == 95) && ('a' == 97) && ('b' == 98) \
      && ('c' == 99) && ('d' == 100) && ('e' == 101) && ('f' == 102) \
      && ('g' == 103) && ('h' == 104) && ('i' == 105) && ('j' == 106) \
      && ('k' == 107) && ('l' == 108) && ('m' == 109) && ('n' == 110) \
      && ('o' == 111) && ('p' == 112) && ('q' == 113) && ('r' == 114) \
      && ('s' == 115) && ('t' == 116) && ('u' == 117) && ('v' == 118) \
      && ('w' == 119) && ('x' == 120) && ('y' == 121) && ('z' == 122) \
      && ('{' == 123) && ('|' == 124) && ('}' == 125) && ('~' == 126))
/* The character set is not based on ISO-646.  */
#error "gperf generated tables don't work with this execution character set. Please report a bug to <bug-gperf@gnu.org>."
#endif

#line 13 "src/header_names.gperf"

#include "header_names.h"

#define TOTAL_KEYWORDS 30
#define MIN_WORD_LENGTH 2
#define MAX_WORD_LENGTH 21
#define MIN_HASH_VALUE 4
#define MAX_HASH_VALUE 40
/* maximum key range = 37, duplicates = 0 */

#ifndef GPERF_DOWNCASE
#define GPERF_DOWNCASE 1
static unsigned char gperf_downcase[256] =
  {
      0,   1,   2,   3,   4,   5,   6,   7,   8,   9,  10,  11,  12,  13,  14,
     15,  16,  17,  18,  19,  20,  21,  22,  23,  24,  25,  26,  27,  28,  29,
     30,  31,  32,  33,  34,  35,  36,  37,  38,  39,  40,  41,  42,  43,  44,
     45,  46,  47,  48,  49,  50,  51,  52,  53,  54,  55,  56,  57,  58,  59,
     60,  61,  62,  63,  64,  97,  98,  99, 100, 101, 102, 103, 104, 105, 106,
    107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121,
    122,  91,  92,  93,  94,  95,  96,  97,  98,  99, 100, 101, 102, 103, 104,
    105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119,
    120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134,
    135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149,
    150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164,
    165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179,
    180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194,
    195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209,
    210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224,
    225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239,
    240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254,
    255
  };
#endif

#ifndef GPERF_CASE_MEMCMP
#define GPERF_CASE_MEMCMP 1
static int
gperf_case_memcmp (register const char *s1, register const char *s2, register size_t n)
{
  for (; n > 0;)
    {
      unsigned char c1 = gperf_downcase[(unsigned char)*s1++];
      unsigned char c2 = gperf_downcase[(unsigned char)*s2++];
      if (c1 == c2)
        {
          n--;
          continue;
        }
      return (int)c1 - (int)c2;
    }
  return 0;
}
#endif

#ifdef __GNUC__
__inline
#else
#ifdef __cplusplus
inline
#endif
#endif
static unsigned int
ankah_header_hash (register const char *str, register size_t len)
{
  static const unsigned char asso_values[] =
    {
      41, 41, 41, 41, 41, 41, 41, 41, 41, 41,
      41, 41, 41, 41, 41, 41, 41, 41, 41, 41,
      41, 41, 41, 41, 41, 41, 41, 41, 41, 41,
      41, 41, 41, 41, 41, 41, 41, 41, 41, 41,
      41, 41, 41, 41, 41, 15, 41, 41, 41, 41,
      41, 41, 41, 41, 41, 41, 41, 41, 41, 41,
      41, 41, 41, 41, 41, 23, 41,  5, 41, 13,
       5, 41, 41, 41, 41, 41, 41, 25, 41,  0,
      20, 41,  0, 30, 15, 25, 41, 41,  5, 41,
      41, 41, 41, 41, 41, 41, 41, 23, 41,  5,
      41, 13,  5, 41, 41, 41, 41, 41, 41, 25,
      41,  0, 20, 41,  0, 30, 15, 25, 41, 41,
       5, 41, 41, 41, 41, 41, 41, 41, 41, 41,
      41, 41, 41, 41, 41, 41, 41, 41, 41, 41,
      41, 41, 41, 41, 41, 41, 41, 41, 41, 41,
      41, 41, 41, 41, 41, 41, 41, 41, 41, 41,
      41, 41, 41, 41, 41, 41, 41, 41, 41, 41,
      41, 41, 41, 41, 41, 41, 41, 41, 41, 41,
      41, 41, 41, 41, 41, 41, 41, 41, 41, 41,
      41, 41, 41, 41, 41, 41, 41, 41, 41, 41,
      41, 41, 41, 41, 41, 41, 41, 41, 41, 41,
      41, 41, 41, 41, 41, 41, 41, 41, 41, 41,
      41, 41, 41, 41, 41, 41, 41, 41, 41, 41,
      41, 41, 41, 41, 41, 41, 41, 41, 41, 41,
      41, 41, 41, 41, 41, 41, 41, 41, 41, 41,
      41, 41, 41, 41, 41, 41
    };
  return len + asso_values[(unsigned char)str[1]];
}

static const unsigned char lengthtable[] =
  {
     0,  0,  0,  0,  4,  0,  6,  7,  0,  9, 10,  6, 12,  8,
    14,  2, 16, 17, 13, 19, 15,  0, 17, 10,  9,  5,  0,  7,
     5, 14, 15,  0,  7, 10,  0, 20, 21,  7, 13,  0, 10
  };

static const struct ankah_header_keyword ankah_header_words[] =
  {
    {"", ANKAH_HEADER_OTHER}, {"", ANKAH_HEADER_OTHER},
    {"", ANKAH_HEADER_OTHER}, {"", ANKAH_HEADER_OTHER},
#line 30 "src/header_names.gperf"
    {"host", ANKAH_HEADER_HOST},
    {"", ANKAH_HEADER_OTHER},
#line 27 "src/header_names.gperf"
    {"cookie", ANKAH_HEADER_COOKIE},
#line 40 "src/header_names.gperf"
    {"trailer", ANKAH_HEADER_TRAILER},
    {"", ANKAH_HEADER_OTHER},
#line 29 "src/header_names.gperf"
    {"forwarded", ANKAH_HEADER_FORWARDED},
#line 24 "src/header_names.gperf"
    {"connection", ANKAH_HEADER_CONNECTION},
#line 28 "src/header_names.gperf"
    {"expect", ANKAH_HEADER_EXPECT},
#line 26 "src/header_names.gperf"
    {"content-type", ANKAH_HEADER_CONTENT_TYPE},
#line 34 "src/header_names.gperf"
    {"if-range", ANKAH_HEADER_IF_RANGE},
#line 25 "src/header_names.gperf"
    {"content-length", ANKAH_HEADER_CONTENT_LENGTH},
#line 39 "src/header_names.gperf"
    {"te", ANKAH_HEADER_TE},
#line 37 "src/header_names.gperf"
    {"proxy-connection", ANKAH_HEADER_PROXY_CONNECTION},
#line 41 "src/header_names.gperf"
    {"transfer-encoding", ANKAH_HEADER_TRANSFER_ENCODING},
#line 33 "src/header_names.gperf"
    {"if-none-match", ANKAH_HEADER_IF_NONE_MATCH},
#line 36 "src/header_names.gperf"
    {"proxy-authorization", ANKAH_HEADER_PROXY_AUTHORIZATION},
#line 22 "src/header_names.gperf"
    {"accept-encoding", ANKAH_HEADER_ACCEPT_ENCODING},
    {"", ANKAH_HEADER_OTHER},
#line 32 "src/header_names.gperf"
    {"if-modified-since", ANKAH_HEADER_IF_MODIFIED_SINCE},
#line 35 "src/header_names.gperf"
    {"keep-alive", ANKAH_HEADER_KEEP_ALIVE},
#line 47 "src/header_names.gperf"
    {"x-real-ip", ANKAH_HEADER_X_REAL_IP},
#line 20 "src/header_names.gperf"
    {":path", ANKAH_HEADER_PSEUDO_PATH},
    {"", ANKAH_HEADER_OTHER},
#line 42 "src/header_names.gperf"
    {"upgrade", ANKAH_HEADER_UPGRADE},
#line 38 "src/header_names.gperf"
    {"range", ANKAH_HEADER_RANGE},
#line 31 "src/header_names.gperf"
    {"http2-settings", ANKAH_HEADER_HTTP2_SETTINGS},
#line 46 "src/header_names.gperf"
    {"x-forwarded-for", ANKAH_HEADER_X_FORWARDED_FOR},
    {"", ANKAH_HEADER_OTHER},
#line 19 "src/header_names.gperf"
    {":method", ANKAH_HEADER_PSEUDO_METHOD},
#line 18 "src/header_names.gperf"
    {":authority", ANKAH_HEADER_PSEUDO_AUTHORITY},
    {"", ANKAH_HEADER_OTHER},
#line 44 "src/header_names.gperf"
    {"x-ankah-internal-key", ANKAH_HEADER_X_ANKAH_INTERNAL_KEY},
#line 45 "src/header_names.gperf"
    {"x-ankah-internal-peer", ANKAH_HEADER_X_ANKAH_INTERNAL_PEER},
#line 21 "src/header_names.gperf"
    {":scheme", ANKAH_HEADER_PSEUDO_SCHEME},
#line 23 "src/header_names.gperf"
    {"authorization", ANKAH_HEADER_AUTHORIZATION},
    {"", ANKAH_HEADER_OTHER},
#line 43 "src/header_names.gperf"
    {"user-agent", ANKAH_HEADER_USER_AGENT}
  };

const struct ankah_header_keyword *
ankah_header_lookup (register const char *str, register size_t len)
{
  if (len <= MAX_WORD_LENGTH && len >= MIN_WORD_LENGTH)
    {
      register unsigned int key = ankah_header_hash (str, len);

      if (key <= MAX_HASH_VALUE)
        if (len == lengthtable[key])
          {
            register const char *s = ankah_header_words[key].name;

            if ((((unsigned char)*str ^ (unsigned char)*s) & ~32) == 0 && !gperf_case_memcmp (str, s, len))
              return &ankah_header_words[key];
          }
    }
  return 0;
}
#line 48 "src/header_names.gperf"

