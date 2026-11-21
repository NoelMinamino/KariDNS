/* dnsqps: the counters, the latency histogram (16 steps per power of two, about 6 % wide), the text and JSON reports. */
#include "dnsqps.h"
#include <string.h>
#include <inttypes.h>

void dq_hist_init(dq_hist_t *h) {
    memset(h, 0, sizeof *h);
    h->min_ns = UINT64_MAX;
}

size_t dq_hist_bucket(uint64_t ns) {
    if (ns < 16) return (size_t)ns;
    unsigned msb = 63u - (unsigned)__builtin_clzll(ns);
    return (size_t)(msb - 3) * 16 + (size_t)((ns >> (msb - 4)) & 15);
}

uint64_t dq_hist_bucket_hi(size_t idx) {
    if (idx < 16) return idx;
    unsigned msb = (unsigned)(idx / 16) + 3, sub = (unsigned)(idx % 16);
    uint64_t lo = (uint64_t)(16 + sub) << (msb - 4);
    return lo + ((uint64_t)1 << (msb - 4)) - 1;
}

void dq_hist_add(dq_hist_t *h, uint64_t ns) {
    h->b[dq_hist_bucket(ns)]++;
    h->count++;
    h->sum_ns += ns;
    if (ns < h->min_ns) h->min_ns = ns;
    if (ns > h->max_ns) h->max_ns = ns;
}

void dq_hist_merge(dq_hist_t *d, const dq_hist_t *s) {
    for (size_t i = 0; i < DQ_HBUCKETS; i++) d->b[i] += s->b[i];
    d->count += s->count;
    d->sum_ns += s->sum_ns;
    if (s->min_ns < d->min_ns) d->min_ns = s->min_ns;
    if (s->max_ns > d->max_ns) d->max_ns = s->max_ns;
}

uint64_t dq_hist_pct(const dq_hist_t *h, double p) {
    if (h->count == 0) return 0;
    double want = (double)h->count * p / 100.0;
    uint64_t target = (uint64_t)want;
    if ((double)target < want) target++;
    if (target < 1) target = 1;
    uint64_t cum = 0;
    for (size_t i = 0; i < DQ_HBUCKETS; i++) {
        cum += h->b[i];
        if (cum >= target) {
            uint64_t hi = dq_hist_bucket_hi(i);
            if (hi > h->max_ns) hi = h->max_ns;
            if (hi < h->min_ns) hi = h->min_ns;
            return hi;
        }
    }
    return h->max_ns;
}

void dq_counts_add(dq_counts_t *d, const dq_counts_t *s) {
    d->sent += s->sent;
    d->completed += s->completed;
    d->lost += s->lost;
    d->malformed += s->malformed;
    d->unmatched += s->unmatched;
    d->foreign += s->foreign;
    d->send_errs += s->send_errs;
    d->recv_errs += s->recv_errs;
    d->sent_bytes += s->sent_bytes;
    d->recv_bytes += s->recv_bytes;
    for (int i = 0; i < DQ_NRCODE; i++) d->rcode[i] += s->rcode[i];
}

static const char *rcode_label(int i, char *buf, size_t n) {
    if (i == 16) return "EXTENDED";
    if (i <= 10) return dns_rcode_name((unsigned)i);
    snprintf(buf, n, "RCODE%d", i);
    return buf;
}

static double pct_of(uint64_t a, uint64_t b) { return b ? 100.0 * (double)a / (double)b : 0.0; }

void dq_print_text(FILE *f, const dq_report_t *r) {
    const dq_counts_t *c = &r->c;
    char lb[16];
    fprintf(f, "\nStatistics:\n\n");
    fprintf(f, "  Queries sent:         %" PRIu64 "\n", c->sent);
    if (r->sink) {
        fprintf(f, "  Queries completed:    n/a (null target: sink)\n");
    } else {
        fprintf(f, "  Queries completed:    %" PRIu64 " (%.2f%%)\n", c->completed, pct_of(c->completed, c->sent));
        fprintf(f, "  Queries lost:         %" PRIu64 " (%.2f%%)\n", c->lost, pct_of(c->lost, c->sent));
    }
    fprintf(f, "\n");
    if (c->completed) {
        fprintf(f, "  Response codes:      ");
        const char *sep = " ";
        for (int i = 0; i < DQ_NRCODE; i++) {
            if (!c->rcode[i]) continue;
            fprintf(f, "%s%s %" PRIu64 " (%.2f%%)", sep, rcode_label(i, lb, sizeof lb), c->rcode[i], pct_of(c->rcode[i], c->completed));
            sep = ", ";
        }
        fprintf(f, "\n");
    }
    if (c->malformed || c->unmatched || c->foreign || c->send_errs || c->recv_errs)
        fprintf(f, "  Malformed answers:    %" PRIu64 ", unmatched (late or duplicate): %" PRIu64 ", not ours: %" PRIu64 ", send errors: %" PRIu64
                   ", receive errors: %" PRIu64 "\n", c->malformed, c->unmatched, c->foreign, c->send_errs, c->recv_errs);
    fprintf(f, "  Average packet size:  request %" PRIu64 ", response %" PRIu64 "\n", c->sent ? c->sent_bytes / c->sent : 0,
            c->completed ? c->recv_bytes / c->completed : 0);
    fprintf(f, "  Run time (s):         %.3f\n", r->run_s);
    fprintf(f, "  Queries per second:   %.1f (sent %.1f)\n", r->run_s > 0 ? (double)c->completed / r->run_s : 0.0,
            r->run_s > 0 ? (double)c->sent / r->run_s : 0.0);
    if (r->h.count) {
        const dq_hist_t *h = &r->h;
        fprintf(f, "\n  Average Latency (s):  %.6f (min %.6f, max %.6f)\n", (double)h->sum_ns / (double)h->count / 1e9, (double)h->min_ns / 1e9,
                (double)h->max_ns / 1e9);
        fprintf(f, "  Latency percentiles (s): p50 %.6f, p90 %.6f, p99 %.6f, p99.9 %.6f\n", (double)dq_hist_pct(h, 50) / 1e9,
                (double)dq_hist_pct(h, 90) / 1e9, (double)dq_hist_pct(h, 99) / 1e9, (double)dq_hist_pct(h, 99.9) / 1e9);
    }
    fprintf(f, "\n  I/O path: %s, %u thread(s) x %u socket(s), server %s\n", r->io_name, r->threads, r->sockets, r->server);
}

static void json_str(FILE *f, const char *s) {
    fputc('"', f);
    for (; *s; s++) {
        unsigned char ch = (unsigned char)*s;
        if (ch == '"' || ch == '\\') fprintf(f, "\\%c", ch);
        else if (ch < 0x20) fprintf(f, "\\u%04x", ch);
        else fputc(ch, f);
    }
    fputc('"', f);
}

void dq_print_json(FILE *f, const dq_report_t *r) {
    const dq_counts_t *c = &r->c;
    const dq_hist_t *h = &r->h;
    char lb[16];
    fprintf(f, "{\"tool\":\"dnsqps\",\"io\":");
    json_str(f, r->io_name);
    fprintf(f, ",\"server\":");
    json_str(f, r->server);
    fprintf(f, ",\"threads\":%u,\"sockets\":%u,\"null_sink\":%s", r->threads, r->sockets, r->sink ? "true" : "false");
    fprintf(f, ",\"run_s\":%.6f,\"sent\":%" PRIu64 ",\"completed\":%" PRIu64 ",\"lost\":%" PRIu64, r->run_s, c->sent, c->completed, c->lost);
    fprintf(f, ",\"qps\":%.3f,\"sent_qps\":%.3f", r->run_s > 0 ? (double)c->completed / r->run_s : 0.0, r->run_s > 0 ? (double)c->sent / r->run_s : 0.0);
    fprintf(f, ",\"malformed\":%" PRIu64 ",\"unmatched\":%" PRIu64 ",\"foreign\":%" PRIu64 ",\"send_errors\":%" PRIu64 ",\"recv_errors\":%" PRIu64,
            c->malformed, c->unmatched, c->foreign, c->send_errs, c->recv_errs);
    fprintf(f, ",\"sent_bytes\":%" PRIu64 ",\"recv_bytes\":%" PRIu64, c->sent_bytes, c->recv_bytes);
    fprintf(f, ",\"latency_s\":{");
    if (h->count)
        fprintf(f, "\"avg\":%.9f,\"min\":%.9f,\"p50\":%.9f,\"p90\":%.9f,\"p99\":%.9f,\"p999\":%.9f,\"max\":%.9f", (double)h->sum_ns / (double)h->count / 1e9,
                (double)h->min_ns / 1e9, (double)dq_hist_pct(h, 50) / 1e9, (double)dq_hist_pct(h, 90) / 1e9, (double)dq_hist_pct(h, 99) / 1e9,
                (double)dq_hist_pct(h, 99.9) / 1e9, (double)h->max_ns / 1e9);
    fprintf(f, "},\"rcodes\":{");
    const char *sep = "";
    for (int i = 0; i < DQ_NRCODE; i++) {
        if (!c->rcode[i]) continue;
        fprintf(f, "%s\"%s\":%" PRIu64, sep, rcode_label(i, lb, sizeof lb), c->rcode[i]);
        sep = ",";
    }
    fprintf(f, "}}\n");
}

void dq_print_interval(FILE *f, double t, double dt, uint64_t sent, uint64_t done, uint64_t lost, uint64_t lat_sum, uint64_t lat_cnt) {
    fprintf(f, "[Interval] t=%.1fs sent=%" PRIu64 " completed=%" PRIu64 " lost=%" PRIu64 " qps=%.0f avg_latency=%.6fs\n", t, sent, done, lost,
            dt > 0 ? (double)done / dt : 0.0, lat_cnt ? (double)lat_sum / (double)lat_cnt / 1e9 : 0.0);
    fflush(f);
}

/* ---------------------------------------------------------------- the histogram as text (the result of an agent: dnsqps_agent.c) */
size_t dq_hist_encode(const dq_hist_t *h, char *out, size_t cap) {
    size_t n = 0;
    if (cap) out[0] = 0;
    for (size_t i = 0; i < DQ_HBUCKETS; i++) {
        if (!h->b[i]) continue;
        int w = snprintf(out + n, cap - n, "%s%zu:%" PRIu64, n ? "," : "", i, h->b[i]);
        if (w < 0 || (size_t)w >= cap - n) return (size_t)-1;
        n += (size_t)w;
    }
    return n;
}

static const char *num_u64(const char *s, uint64_t *v) {   /* decimal digits only; NULL on a bad number or an overflow */
    if (*s < '0' || *s > '9') return NULL;
    uint64_t x = 0;
    for (; *s >= '0' && *s <= '9'; s++) {
        if (x > (UINT64_MAX - (uint64_t)(*s - '0')) / 10) return NULL;
        x = x * 10 + (uint64_t)(*s - '0');
    }
    *v = x;
    return s;
}

/* the inverse; false on anything but "i:n,i:n" with i < DQ_HBUCKETS in rising order, or when the counts add up to more than a count of 2^62 */
bool dq_hist_decode(dq_hist_t *h, const char *s) {
    uint64_t total = 0;
    long last = -1;
    while (*s) {
        uint64_t i, n;
        s = num_u64(s, &i);
        if (!s || *s != ':' || i >= DQ_HBUCKETS || (long)i <= last) return false;
        s = num_u64(s + 1, &n);
        if (!s || n == 0 || n > ((uint64_t)1 << 62) || total + n > ((uint64_t)1 << 62)) return false;
        h->b[i] = n;
        total += n;
        last = (long)i;
        if (*s == ',') { s++; if (!*s) return false; }
        else if (*s) return false;
    }
    h->count = total;
    return true;
}
