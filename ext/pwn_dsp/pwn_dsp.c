/* Optional packed IQ kernels. No allocation, global state, or unaligned loads. */
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <math.h>

/* In-place radix-2 FFT followed by magnitudes; all storage caller-owned. */
int pwn_dsp_fft(double *x, size_t n, double *out) {
  if (!n || (n & (n - 1))) return -1;
  for (size_t i = 1, j = 0; i < n; i++) {
    size_t bit = n >> 1;
    for (; j & bit; bit >>= 1) j ^= bit;
    j ^= bit;
    if (i < j) {
      double re = x[2*i], im = x[2*i+1];
      x[2*i] = x[2*j]; x[2*i+1] = x[2*j+1];
      x[2*j] = re; x[2*j+1] = im;
    }
  }
  for (size_t len = 2; len <= n; len *= 2) {
    double angle = -2.0 * acos(-1.0) / len;
    double wr = cos(angle), wi = sin(angle);
    for (size_t start = 0; start < n; start += len) {
      double ur = 1.0, ui = 0.0;
      for (size_t offset = 0; offset < len/2; offset++) {
        size_t a = 2*(start+offset), b = a+len;
        double tr = x[b]*ur-x[b+1]*ui, ti = x[b]*ui+x[b+1]*ur;
        double ar = x[a], ai = x[a+1];
        x[a] = ar+tr; x[a+1] = ai+ti;
        x[b] = ar-tr; x[b+1] = ai-ti;
        double next = ur*wr-ui*wi;
        ui = ur*wi+ui*wr; ur = next;
      }
    }
    if (len == n) break;
  }
  for (size_t i = 0; i < n; i++) out[i] = sqrt(x[2*i]*x[2*i]+x[2*i+1]*x[2*i+1]);
  return 0;
}


static double scalar(const unsigned char *p, int format) {
  if (format == 0) return ((double)*p - 127.5) / 128.0;
  if (format == 1) {
    int value = (int)p[0] | ((int)p[1] << 8);
    if (value >= 32768) value -= 65536;
    return (double)value / 32768.0;
  }
  double value;
  memcpy(&value, p, sizeof(value));
  return value;
}

/* format: cu8=0, cs16le=1, native double=2; op: unpack=0, mag=1, fm=2.
 * Caller supplies output for 2*n doubles and previous[2]. */
size_t pwn_dsp_iq(const unsigned char *input, size_t n, int format, int op,
                  double kf, double *previous, int have_previous, double *out) {
  if (format < 0 || format > 2 || op < 0 || op > 2) return 0;
  size_t stride = format == 0 ? 1 : (format == 1 ? 2 : sizeof(double));
  size_t count = 0;
  double pr = previous[0], pi = previous[1];
  for (size_t i = 0; i < n; i++) {
    double re = scalar(input + 2*i*stride, format);
    double im = scalar(input + (2*i+1)*stride, format);
    if (op == 0) { out[count++] = re; out[count++] = im; }
    else if (op == 1) out[count++] = re*re + im*im;
    else if (have_previous) out[count++] = atan2(im*pr-re*pi, re*pr+im*pi)*kf;
    pr = re; pi = im; have_previous = 1;
  }
  previous[0] = pr; previous[1] = pi;
  return count;
}
