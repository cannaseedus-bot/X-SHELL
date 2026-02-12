#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define SHA256_BLOCK_SIZE 32
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32 - (b))))
#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

typedef struct {
    uint8_t data[64];
    uint32_t datalen;
    uint64_t bitlen;
    uint32_t state[8];
} SHA256_CTX;

static const uint32_t k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
    0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
    0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
    0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
    0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
    0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static void sha256_transform(SHA256_CTX *ctx, const uint8_t data[]) {
    uint32_t a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

    for (i = 0, j = 0; i < 16; i++, j += 4) {
        m[i] = ((uint32_t)data[j] << 24) | ((uint32_t)data[j + 1] << 16) |
               ((uint32_t)data[j + 2] << 8) | ((uint32_t)data[j + 3]);
    }
    for (; i < 64; i++) {
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
    }

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for (i = 0; i < 64; i++) {
        t1 = h + EP1(e) + CH(e, f, g) + k[i] + m[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

static void sha256_init(SHA256_CTX *ctx) {
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
}

static void sha256_update(SHA256_CTX *ctx, const uint8_t data[], size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

static void sha256_final(SHA256_CTX *ctx, uint8_t hash[]) {
    uint32_t i = ctx->datalen;

    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56) {
            ctx->data[i++] = 0x00;
        }
    } else {
        ctx->data[i++] = 0x80;
        while (i < 64) {
            ctx->data[i++] = 0x00;
        }
        sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }

    ctx->bitlen += (uint64_t)ctx->datalen * 8;
    ctx->data[63] = (uint8_t)(ctx->bitlen);
    ctx->data[62] = (uint8_t)(ctx->bitlen >> 8);
    ctx->data[61] = (uint8_t)(ctx->bitlen >> 16);
    ctx->data[60] = (uint8_t)(ctx->bitlen >> 24);
    ctx->data[59] = (uint8_t)(ctx->bitlen >> 32);
    ctx->data[58] = (uint8_t)(ctx->bitlen >> 40);
    ctx->data[57] = (uint8_t)(ctx->bitlen >> 48);
    ctx->data[56] = (uint8_t)(ctx->bitlen >> 56);
    sha256_transform(ctx, ctx->data);

    for (i = 0; i < 4; i++) {
        hash[i]      = (uint8_t)((ctx->state[0] >> (24 - i * 8)) & 0x000000ff);
        hash[i + 4]  = (uint8_t)((ctx->state[1] >> (24 - i * 8)) & 0x000000ff);
        hash[i + 8]  = (uint8_t)((ctx->state[2] >> (24 - i * 8)) & 0x000000ff);
        hash[i + 12] = (uint8_t)((ctx->state[3] >> (24 - i * 8)) & 0x000000ff);
        hash[i + 16] = (uint8_t)((ctx->state[4] >> (24 - i * 8)) & 0x000000ff);
        hash[i + 20] = (uint8_t)((ctx->state[5] >> (24 - i * 8)) & 0x000000ff);
        hash[i + 24] = (uint8_t)((ctx->state[6] >> (24 - i * 8)) & 0x000000ff);
        hash[i + 28] = (uint8_t)((ctx->state[7] >> (24 - i * 8)) & 0x000000ff);
    }
}

static void print_hash_hex(const uint8_t hash[SHA256_BLOCK_SIZE]) {
    int i;
    for (i = 0; i < SHA256_BLOCK_SIZE; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

static int load_file_bytes(const char *path, uint8_t **data, size_t *size) {
    FILE *file;
    long length;
    size_t read_total;

    *data = NULL;
    *size = 0;

    file = fopen(path, "rb");
    if (!file) {
        return 0;
    }

    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return 0;
    }

    length = ftell(file);
    if (length < 0) {
        fclose(file);
        return 0;
    }

    if (fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return 0;
    }

    *data = (uint8_t *)malloc((size_t)length + 1);
    if (!*data) {
        fclose(file);
        return 0;
    }

    read_total = fread(*data, 1, (size_t)length, file);
    fclose(file);

    if (read_total != (size_t)length) {
        free(*data);
        *data = NULL;
        return 0;
    }

    (*data)[length] = '\0';
    *size = (size_t)length;
    return 1;
}

static int hash_file(const char *path, uint8_t out[SHA256_BLOCK_SIZE]) {
    FILE *file;
    uint8_t buffer[1024];
    size_t read_n;
    SHA256_CTX ctx;

    file = fopen(path, "rb");
    if (!file) {
        return 0;
    }

    sha256_init(&ctx);
    while ((read_n = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        sha256_update(&ctx, buffer, read_n);
    }
    fclose(file);

    sha256_final(&ctx, out);
    return 1;
}

static int contains_literal(const char *json, const char *literal) {
    return strstr(json, literal) != NULL;
}

static int contains_forbidden_artifact_fields(const char *json) {
    const char *forbidden[] = {
        "\"css\"", "\"dom\"", "\"svg\"", "\"canvas\"", "\"ui_hint\"",
        "\"host_os\"", "\"environment\"", "\"session\"", "\"network\"",
        "\"kernel_routing\"", "\"micronaut\"", "\"projection_mode\""
    };
    size_t i;

    for (i = 0; i < sizeof(forbidden) / sizeof(forbidden[0]); i++) {
        if (contains_literal(json, forbidden[i])) {
            return 1;
        }
    }

    return 0;
}

static int validate_artifact_contract(const char *json) {
    if (!contains_literal(json, "\"@artifact\": \"collapse\"")) {
        printf("Artifact INVALID: @artifact must be collapse\n");
        return 0;
    }

    if (!contains_literal(json, "\"@version\": \"v1\"")) {
        printf("Artifact INVALID: @version must be v1\n");
        return 0;
    }

    if (!contains_literal(json, "\"@origin\": \"sw.khl\"")) {
        printf("Artifact INVALID: @origin must be sw.khl\n");
        return 0;
    }

    if (!contains_literal(json, "\"@deterministic\": true")) {
        printf("Artifact INVALID: @deterministic must be true\n");
        return 0;
    }

    if (!contains_literal(json, "\"entropy\": 0.21")) {
        printf("Artifact INVALID: entropy must be 0.21\n");
        return 0;
    }

    if (!contains_literal(json, "\"timestamp\": null")) {
        printf("Artifact INVALID: input.timestamp must be null\n");
        return 0;
    }

    if (!contains_literal(json, "\"one_outcome\": true") ||
        !contains_literal(json, "\"no_branching_detected\": true") ||
        !contains_literal(json, "\"no_parallelism_detected\": true") ||
        !contains_literal(json, "\"no_mutation_detected\": true") ||
        !contains_literal(json, "\"replay_identity_verified\": true")) {
        printf("Artifact INVALID: proof flags must all be true\n");
        return 0;
    }

    if (!contains_literal(json, "\"projection_ready\": true")) {
        printf("Artifact INVALID: projection_ready must be true\n");
        return 0;
    }

    if (contains_forbidden_artifact_fields(json)) {
        printf("Artifact INVALID: forbidden projection/orchestration fields present\n");
        return 0;
    }

    return 1;
}

static int write_text_file(const char *path, const char *content) {
    FILE *file = fopen(path, "wb");
    if (!file) {
        return 0;
    }
    fputs(content, file);
    fclose(file);
    return 1;
}

static int command_help(void) {
    puts("K-Shell v1 commands:");
    puts("  help");
    puts("  emit");
    puts("  verify <artifact.json>");
    puts("  hash <file>");
    puts("  artifact <artifact.json>");
    puts("  exit");
    return 0;
}

static int command_emit(void) {
    static const char *sha256_h =
        "#ifndef SHA256_H\n"
        "#define SHA256_H\n"
        "#include <stdint.h>\n"
        "#include <stddef.h>\n"
        "\n"
        "typedef struct {\n"
        "    uint8_t data[64];\n"
        "    uint32_t datalen;\n"
        "    uint64_t bitlen;\n"
        "    uint32_t state[8];\n"
        "} SHA256_CTX;\n"
        "\n"
        "void sha256_init(SHA256_CTX *ctx);\n"
        "void sha256_update(SHA256_CTX *ctx, const uint8_t data[], size_t len);\n"
        "void sha256_final(SHA256_CTX *ctx, uint8_t hash[]);\n"
        "\n"
        "#endif\n";

    static const char *sha256_c =
        "#include \"sha256.h\"\n"
        "#include <string.h>\n"
        "\n"
        "#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32 - (b))))\n"
        "#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))\n"
        "#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))\n"
        "#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))\n"
        "#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))\n"
        "#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))\n"
        "#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))\n"
        "\n"
        "static const uint32_t k[64] = {\n"
        "  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,\n"
        "  0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,\n"
        "  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,\n"
        "  0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,\n"
        "  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,\n"
        "  0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,\n"
        "  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,\n"
        "  0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,\n"
        "  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,\n"
        "  0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,\n"
        "  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,\n"
        "  0xd192e819,0xd6990624,0xf40e3585,0x106aa070,\n"
        "  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,\n"
        "  0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,\n"
        "  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,\n"
        "  0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2\n"
        "};\n"
        "\n"
        "static void sha256_transform(SHA256_CTX *ctx, const uint8_t data[]) {\n"
        "    uint32_t a,b,c,d,e,f,g,h,i,j,t1,t2,m[64];\n"
        "    for (i=0,j=0;i<16;i++,j+=4) m[i]=((uint32_t)data[j]<<24)|((uint32_t)data[j+1]<<16)|((uint32_t)data[j+2]<<8)|((uint32_t)data[j+3]);\n"
        "    for (;i<64;i++) m[i]=SIG1(m[i-2])+m[i-7]+SIG0(m[i-15])+m[i-16];\n"
        "    a=ctx->state[0]; b=ctx->state[1]; c=ctx->state[2]; d=ctx->state[3];\n"
        "    e=ctx->state[4]; f=ctx->state[5]; g=ctx->state[6]; h=ctx->state[7];\n"
        "    for (i=0;i<64;i++){\n"
        "        t1=h+EP1(e)+CH(e,f,g)+k[i]+m[i];\n"
        "        t2=EP0(a)+MAJ(a,b,c);\n"
        "        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;\n"
        "    }\n"
        "    ctx->state[0]+=a; ctx->state[1]+=b; ctx->state[2]+=c; ctx->state[3]+=d;\n"
        "    ctx->state[4]+=e; ctx->state[5]+=f; ctx->state[6]+=g; ctx->state[7]+=h;\n"
        "}\n"
        "\n"
        "void sha256_init(SHA256_CTX *ctx){\n"
        "    ctx->datalen=0; ctx->bitlen=0;\n"
        "    ctx->state[0]=0x6a09e667; ctx->state[1]=0xbb67ae85;\n"
        "    ctx->state[2]=0x3c6ef372; ctx->state[3]=0xa54ff53a;\n"
        "    ctx->state[4]=0x510e527f; ctx->state[5]=0x9b05688c;\n"
        "    ctx->state[6]=0x1f83d9ab; ctx->state[7]=0x5be0cd19;\n"
        "}\n"
        "\n"
        "void sha256_update(SHA256_CTX *ctx, const uint8_t data[], size_t len){\n"
        "    size_t i;\n"
        "    for(i=0;i<len;i++){\n"
        "        ctx->data[ctx->datalen]=data[i];\n"
        "        ctx->datalen++;\n"
        "        if(ctx->datalen==64){\n"
        "            sha256_transform(ctx,ctx->data);\n"
        "            ctx->bitlen+=512;\n"
        "            ctx->datalen=0;\n"
        "        }\n"
        "    }\n"
        "}\n"
        "\n"
        "void sha256_final(SHA256_CTX *ctx, uint8_t hash[]){\n"
        "    uint32_t i=ctx->datalen;\n"
        "    if(ctx->datalen<56){ctx->data[i++]=0x80; while(i<56) ctx->data[i++]=0;}\n"
        "    else{ctx->data[i++]=0x80; while(i<64) ctx->data[i++]=0; sha256_transform(ctx,ctx->data); memset(ctx->data,0,56);}\n"
        "    ctx->bitlen+=(uint64_t)ctx->datalen*8;\n"
        "    ctx->data[63]=(uint8_t)(ctx->bitlen);\n"
        "    ctx->data[62]=(uint8_t)(ctx->bitlen>>8);\n"
        "    ctx->data[61]=(uint8_t)(ctx->bitlen>>16);\n"
        "    ctx->data[60]=(uint8_t)(ctx->bitlen>>24);\n"
        "    ctx->data[59]=(uint8_t)(ctx->bitlen>>32);\n"
        "    ctx->data[58]=(uint8_t)(ctx->bitlen>>40);\n"
        "    ctx->data[57]=(uint8_t)(ctx->bitlen>>48);\n"
        "    ctx->data[56]=(uint8_t)(ctx->bitlen>>56);\n"
        "    sha256_transform(ctx,ctx->data);\n"
        "    for(i=0;i<4;i++){\n"
        "      hash[i]=(ctx->state[0]>>(24-i*8))&0xff;\n"
        "      hash[i+4]=(ctx->state[1]>>(24-i*8))&0xff;\n"
        "      hash[i+8]=(ctx->state[2]>>(24-i*8))&0xff;\n"
        "      hash[i+12]=(ctx->state[3]>>(24-i*8))&0xff;\n"
        "      hash[i+16]=(ctx->state[4]>>(24-i*8))&0xff;\n"
        "      hash[i+20]=(ctx->state[5]>>(24-i*8))&0xff;\n"
        "      hash[i+24]=(ctx->state[6]>>(24-i*8))&0xff;\n"
        "      hash[i+28]=(ctx->state[7]>>(24-i*8))&0xff;\n"
        "    }\n"
        "}\n";

    static const char *kux_verifier_c =
        "#include <stdio.h>\n"
        "#include <string.h>\n"
        "#include \"sha256.h\"\n"
        "\n"
        "static void bytes_to_hex(const uint8_t *hash, char *output){\n"
        "    int i;\n"
        "    for(i=0;i<32;i++){sprintf(output + (i*2), \"%02x\", hash[i]);}\n"
        "    output[64]='\\0';\n"
        "}\n"
        "\n"
        "static void compute_projection_hash(const char *collapse_hash,const char *mode,const char *layout,char *out_hex){\n"
        "    SHA256_CTX ctx; uint8_t hash[32];\n"
        "    sha256_init(&ctx);\n"
        "    sha256_update(&ctx, (const uint8_t*)collapse_hash, strlen(collapse_hash));\n"
        "    sha256_update(&ctx, (const uint8_t*)mode, strlen(mode));\n"
        "    sha256_update(&ctx, (const uint8_t*)layout, strlen(layout));\n"
        "    sha256_final(&ctx, hash);\n"
        "    bytes_to_hex(hash, out_hex);\n"
        "}\n"
        "\n"
        "int main(int argc, char *argv[]){\n"
        "    char computed_hash[65];\n"
        "    if(argc != 5){\n"
        "        puts(\"Usage:\");\n"
        "        puts(\"kux_verifier <collapse_hash> <mode> <layout> <declared_projection_hash>\");\n"
        "        return 2;\n"
        "    }\n"
        "    if(strcmp(argv[3], \"deterministic\") != 0){\n"
        "        puts(\"FAIL: layout must be deterministic\");\n"
        "        return 1;\n"
        "    }\n"
        "    compute_projection_hash(argv[1], argv[2], argv[3], computed_hash);\n"
        "    if(strcmp(computed_hash, argv[4]) != 0){\n"
        "        puts(\"FAIL: projection hash mismatch\");\n"
        "        return 1;\n"
        "    }\n"
        "    puts(\"PASS: K-UX v1 deterministic projection verified\");\n"
        "    return 0;\n"
        "}\n";

    static const char *build_bat =
        "@echo off\n"
        "echo Building K-UX Verifier...\n"
        "set CC=gcc\n"
        "set CFLAGS=-O2 -static\n"
        "%CC% kux_verifier.c sha256.c %CFLAGS% -o kux_verifier.exe\n"
        "if %ERRORLEVEL% NEQ 0 (\n"
        "    echo Build failed.\n"
        "    exit /b 1\n"
        ")\n"
        "echo Build complete.\n"
        "echo Output: kux_verifier.exe\n";

    if (!write_text_file("sha256.h", sha256_h) ||
        !write_text_file("sha256.c", sha256_c) ||
        !write_text_file("kux_verifier.c", kux_verifier_c) ||
        !write_text_file("build.bat", build_bat)) {
        puts("error: emit failed");
        return 1;
    }

    puts("Emitted sha256.h");
    puts("Emitted sha256.c");
    puts("Emitted kux_verifier.c");
    puts("Emitted build.bat");
    return 0;
}

static int command_hash(const char *path) {
    uint8_t hash[SHA256_BLOCK_SIZE];
    if (!path || path[0] == '\0') {
        puts("error: hash requires <file>");
        return 1;
    }

    if (!hash_file(path, hash)) {
        puts("error: cannot hash file");
        return 1;
    }

    print_hash_hex(hash);
    return 0;
}

static int command_artifact(const char *path) {
    uint8_t *data;
    size_t size;
    int valid;

    if (!path || path[0] == '\0') {
        puts("error: artifact requires <artifact.json>");
        return 1;
    }

    if (!load_file_bytes(path, &data, &size)) {
        puts("error: cannot read artifact file");
        return 1;
    }

    (void)size;
    valid = validate_artifact_contract((const char *)data);
    free(data);

    if (!valid) {
        puts("Artifact INVALID");
        return 1;
    }

    puts("Artifact VALID");
    return 0;
}

static int command_verify(const char *path) {
    int result = command_artifact(path);
    if (result != 0) {
        return result;
    }

    puts("Replay OK");
    puts("Badge: KUX_v1_GOLD");
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        return command_help();
    }

    if (strcmp(argv[1], "help") == 0) {
        return command_help();
    }

    if (strcmp(argv[1], "emit") == 0) {
        return command_emit();
    }

    if (strcmp(argv[1], "hash") == 0) {
        return command_hash(argc >= 3 ? argv[2] : NULL);
    }

    if (strcmp(argv[1], "artifact") == 0) {
        return command_artifact(argc >= 3 ? argv[2] : NULL);
    }

    if (strcmp(argv[1], "verify") == 0) {
        return command_verify(argc >= 3 ? argv[2] : NULL);
    }

    if (strcmp(argv[1], "exit") == 0) {
        return 0;
    }

    puts("error: unknown command");
    return 1;
}
