/* Optional SCH search prefilter. Ruby owns decoding, CRC and stream state.
 * No fast-math: conservative thresholds keep borderline candidates in Ruby.
 * Buffers are doubles, training signs int32, offsets computed with round(). */
#include <math.h>
#include <stddef.h>
#include <stdint.h>

size_t pwn_gsm_search(const double *audio, size_t length, size_t start,
                      double spb, const int32_t *training)
{
    size_t span = (size_t)ceil(148.0 * spb);
    if (length <= span || start >= length - span) return start;
    size_t offsets[63];
    unsigned positives = 0;
    for (unsigned n = 0; n < 63; ++n) {
        offsets[n] = (size_t)round((43 + n) * spb);
        positives += training[n] > 0;
    }
    double nominal = 3.14159265358979323846 / (2.0 * spb);
    for (; start < length - span; ++start) {
        double high = 0.0, low = 0.0;
        for (unsigned n = 0; n < 63; ++n) {
            double value = audio[start + offsets[n]];
            if (training[n] > 0) high += value; else low += value;
        }
        high /= positives;
        low /= 63 - positives;
        double amplitude = (high - low) / 2.0;
        if (amplitude < nominal * 0.35 - 1e-12 || amplitude > nominal * 1.5 + 1e-12) continue;
        double bias = (high + low) / 2.0;
        unsigned errors = 0;
        for (unsigned n = 0; n < 63; ++n) {
            double value = audio[start + offsets[n]];
            if (fabs(value - bias) < 1e-12) continue;
            if ((value > bias ? 1 : -1) != training[n] && ++errors > 2) break;
        }
        if (errors <= 2) return start;
    }
    return start;
}
