#ifndef _HACK_AES_H_
#define _HACK_AES_H_

#ifdef __cplusplus
extern "C" {
#endif

// Users don't need to config this libary by MACROs.
// To make usage simpler, we don't define AES version associated macros.
// We set {key, round key} of the biggest size ({32, 240} for AES256)
// bits stands for the version of AES, maybe 128, 192, 256, defaulted to 256

// use C and unix style for it is a pure crypto project

typedef struct ha_ctx {
	int           bits;
	unsigned char key[32]; // enough for AES256
	// we often have only round_length (>= key length) bytes of the roundkey,
	// round_offset should be aligned by 16bits.
	unsigned char roundkey[240]; // enough for AES256
	int           roundkey_offset;
	int           roundkey_length;
	unsigned char sbox[256];
	unsigned char rsbox[256]; // for sbox validation
	unsigned char rcon[11]; // 11 bytes are enough, reference: https://github.com/kokke/tiny-AES-C
} ha_ctx, *p_ha_ctx;

// empty key, default sbox, default reverse sbox
// bits stands for the version of AES, maybe 128, 192, 256, defaulted to 256
p_ha_ctx ha_build_aes_ctx(int bits);

void ha_destroy_aes_ctx(p_ha_ctx ctx);

void ha_set_key(p_ha_ctx ctx, unsigned char* key);

void ha_set_sbox(p_ha_ctx ctx, unsigned char* sbox);

void ha_set_rcon(p_ha_ctx ctx, unsigned char* rcon);

// calculate reverse sbox
unsigned char* ha_calculate_rsbox(p_ha_ctx ctx);

// offset: round offset which should be aligned by 16bits.
// length: known round key length which should be greater than or equal to key length
void ha_set_roundkey(p_ha_ctx ctx, unsigned char* roundkey, int offset, int length);

// calculate the given partial roundkey's corresponding key
unsigned char* ha_calulate_key(p_ha_ctx ctx);

// calculate the full roundkey by key
unsigned char* ha_calulate_full_roundkey(p_ha_ctx ctx);

// test
void ha_test();

// show AES128 reverse key
void ha_show_rev_key_128();

#ifdef __cplusplus
}
#endif

#endif // _HACK_AES_H_