#ifndef ZONE_IMAGE_WALK_H
#define ZONE_IMAGE_WALK_H

/*
 * Reads everything a reader of a zone image (the query engine, AXFR, the ECS code, thaw) can reach, through the public
 * accessors and image_serialize_rr(): used by tests/test_zone_image.c and tests/fuzz/fuzz_zone_image_validate.c on images
 * that zone_image_validate() accepted.  Under ASan an exact-size block turns a read outside it into an error.  *bad counts
 * the consistency properties that a validated image must have (every name is found where the hash table says, in canonical
 * order, with its RRs and its NSEC3 entries); the return value is a checksum so the reads are not optimized away.
 * Include after dns_wire.h, dns_zone_parser.h and dns_zone_image.h.
 */
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

/* what a query, an AXFR and the ECS code do with an image: touch everything reachable */
static unsigned long zimg_walk(const zone_image_t *img, unsigned *bad) {
    unsigned long sink = 0;
    char b1[DNS_NAME_TEXT_SIZE], b2[DNS_NAME_TEXT_SIZE];
    uint8_t msg[4096];
    compress_ctx_t cc;
    for (uint32_t id = 0; id < img->n_names; id++) {
        const char *t = zone_image_name_text(img, id);
        sink += strlen(t) + zone_image_name_flags(img, id);
        if (!(zone_image_find_name(img, t) == id)) (*bad)++;
        bool ex = false;
        if (!(zone_image_canon_floor(img, t, &ex) == zone_image_names(img)[id].canon_rank && ex)) (*bad)++;
        sink += zone_image_nsec_floor(img, t);
        uint32_t first = zone_image_name_first_rr(img, id), cnt = zone_image_name_rr_count(img, id);
        for (uint32_t k = first; k < first + cnt; k++) {
            if (!(zone_image_rr_name(img, k) == id)) (*bad)++;
            sink += zone_image_rr_type(img, k) + zone_image_rr_class(img, k) + zone_image_rr_ttl(img, k);
            const uint8_t *rd = zone_image_rr_rdata(img, k);
            for (uint16_t i = 0; i < zone_image_rr_rdlen(img, k); i++) sink += rd[i];
            const zone_image_ext_t *e = zone_image_rr_ext(img, k);
            if (e) {
                const char *s;
                if ((s = zone_image_str(img, e->ecs_tag_off))) sink += strlen(s);
                if ((s = zone_image_str(img, e->loc_tag_off))) sink += strlen(s);
                if ((s = zone_image_str(img, e->alt_text_off))) sink += strlen(s);
                if (e->alt_wire_off) sink += zone_image_bytes(img, e->alt_wire_off)[0];
            }
        }
    }
    for (uint32_t k = 0; k < img->n_rrs; k++) {
        zone_image_soa_t n;
        zone_image_nsec3_t n3;
        uint16_t u = 0, v = 0, w = 0;
        uint32_t ttl;
        if (zone_image_rr_target(img, k, b1, sizeof(b1)) == 0) sink += (unsigned char)b1[0];
        if (zone_image_soa(img, k, b1, sizeof(b1), b2, sizeof(b2), &n) == 0) sink += n.serial;
        if (zone_image_mx_pref(img, k, &u) == 0) sink += u;
        if (zone_image_srv(img, k, &u, &v, &w) == 0) sink += u + v + w;
        if (zone_image_rrsig_covered(img, k, &u) == 0) sink += u;
        if (zone_image_nsec3(img, k, &n3) == 0) sink += n3.salt_len + n3.next_len;
        for (unsigned t = 0; t < 70; t++) if (zone_image_rr_bitmap_has(img, k, (uint16_t)(t * 3))) sink++;
        if (zone_image_soa_minimum(img, k, &ttl) == 0) sink += ttl;
        for (int mode = 0; mode < 3; mode++) {
            uint16_t off = 12;
            if (mode == 0) compress_ctx_init(&cc);
            if (image_serialize_rr(img, k, msg, sizeof(msg), &off, mode == 0 ? &cc : NULL, mode == 2 ? "Q.W.Test." : NULL, 300) == 0) sink += off;
        }
        (void)zone_image_rr_valid(img, k, 1700000000, "in", "t", "t", &ttl);
        sink += zone_image_seq_rr(img, k);
    }
    for (uint32_t i = 0; i < img->n_nsec; i++) sink += zone_image_nsec_rr(img, i);
    for (uint32_t c = 0; c < img->n_n3chains; c++) {
        const zone_image_n3chain_t *ch = zone_image_n3chain(img, c);
        sink += zone_image_n3chain_find(img, ch->algorithm, ch->iterations, ch->salt_len ? zone_image_bytes(img, ch->salt_off) : NULL, ch->salt_len);
        for (uint32_t e = 0; e < ch->count; e++) {
            size_t hl;
            const char *h = zone_image_n3chain_hash(img, c, e, &hl);
            uint32_t lb = zone_image_n3chain_lower_bound(img, c, h, hl);
            if (!(lb <= e)) (*bad)++;
            sink += lb;
        }
    }
    for (uint32_t i = 0; i < img->n_glue; i++) sink += zone_image_glue_name(img, i);
    if (img->n3_param_rr != ZONE_IMAGE_NONE) sink += zone_image_bytes(img, img->n3_salt_off) ? zone_image_bytes(img, img->n3_salt_off)[0] : 0;
    {
        zone_image_view_t view = { { 'i', 'n' }, "t", "t", 1700000000 };
        sink += zone_image_apex_soa(img) + zone_image_visible_soa(img, &view, NULL);
    }
    {
        int cnt = 0;
        const tinydns_location_entry_t *loc = zone_image_locations(img, &cnt);
        for (int i = 0; i < cnt; i++) sink += loc[i].prefix_bits + (unsigned char)loc[i].code[0];
        for (int kind = 0; kind < 2; kind++) {
            zone_image_tags_t it;
            zone_image_tag_t tg;
            zone_image_tags_open(img, kind, &it);
            while (zone_image_tags_next(&it, &tg)) {
                const char *cidr;
                cidr_entry_t parsed;
                if (tg.tag) sink += strlen(tg.tag);
                while (zone_image_tag_next_cidr(&tg, &cidr, &parsed)) {
                    if (cidr) sink += strlen(cidr);
                    sink += parsed.prefix + (parsed.valid ? 1u : 0u);
                }
            }
        }
        const acl_entry_t *acl = zone_image_ecs_trusted(img, &cnt);
        for (int i = 0; i < cnt; i++) sink += acl[i].cidr.prefix + (acl[i].is_deny ? 1u : 0u);
    }
    if (img->n_rrs <= 3000) {
        zone_arena_t b;
        zone_arena_init(&b);
        (void)zone_image_thaw(img, &b);
        sink += b.count;
        zone_arena_destroy(&b);
    }
    return sink;
}


#endif
