/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Optional srsRAN_4G bridge. Offline acquisition only; no RF device access.
 * Input: exactly one aligned FDD normal-CP subframe zero, 1.92 Msps.
 */
#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "srsran/srsran.h"

/* Search an offline window for FDD normal-CP PSS/SSS. Return corrected SF0
 * only when wholly present. This is acquisition, NOT a decoded MIB. */
int pwn_lte_acquire(const float *iq, unsigned samples, float *sf0,
                    unsigned *pci, unsigned *start, float *cfo_hz)
{
  if (!iq || !sf0 || !pci || !start || !cfo_hz || samples < 1920 || samples > 9600)
    return -1;
  for (unsigned i = 0; i < samples * 2; i++)
    if (!isfinite(iq[i])) return -1;
  for (unsigned nid2 = 0; nid2 < 3; nid2++) {
    srsran_sync_t sync = {0};
    if (srsran_sync_init(&sync, samples, samples, 128)) {
      srsran_sync_free(&sync);
      return -1;
    }
    srsran_sync_set_N_id_2(&sync, nid2);
    srsran_sync_set_threshold(&sync, 3.0f);
    srsran_sync_set_cp(&sync, SRSRAN_CP_NORM);
    srsran_sync_cp_en(&sync, false);
    srsran_sync_set_frame_type(&sync, SRSRAN_FDD);
    srsran_sync_set_cfo_pss_enable(&sync, true);
    unsigned peak = 0;
    int found = srsran_sync_find(&sync, (const cf_t *)iq, 0, &peak);
    if (found == SRSRAN_SYNC_FOUND && srsran_sync_sss_detected(&sync) &&
        srsran_sync_get_sf_idx(&sync) == 0 && peak >= 960 && peak + 960 <= samples) {
      *pci = srsran_sync_get_cell_id(&sync);
      *start = peak - 960;
      *cfo_hz = srsran_sync_get_cfo(&sync) * 15000.0f;
      cf_t *out = (cf_t *)sf0;
      const cf_t *in = (const cf_t *)iq;
      for (unsigned i = 0; i < 1920; i++) {
        float phase = -2.0f * 3.14159265358979323846f * (*cfo_hz) * i / 1920000.0f;
        out[i] = in[*start + i] * (cosf(phase) + I * sinf(phase));
      }
      srsran_sync_free(&sync);
      return 1;
    }
    srsran_sync_free(&sync);
  }
  return 0;
}

/* Return 1 only after native PBCH CRC passes, 0 for no MIB, -1 on error.
 * Output: 24 unpacked bits, ports, signed SFN offset (caller allocates).
 * No native structs or ownership cross the ABI boundary.
 */
int pwn_lte_pbch(const float *iq, unsigned samples, unsigned pci,
                 uint8_t *bits, unsigned *ports, int *sfn_offset)
{
  if (!iq || !bits || !ports || !sfn_offset || samples != 1920 || pci > 503)
    return -1;
  for (unsigned i = 0; i < samples * 2; i++)
    if (!isfinite(iq[i])) return -1;
  int result = -1;
  cf_t *input = srsran_vec_cf_malloc(samples);
  cf_t *symbols[SRSRAN_MAX_PORTS] = {0};
  symbols[0] = srsran_vec_cf_malloc(1008);
  srsran_ofdm_t fft = {0};
  srsran_chest_dl_t chest = {0};
  srsran_chest_dl_res_t estimates = {0};
  srsran_pbch_t pbch = {0};
  if (!input || !symbols[0]) goto cleanup;
  srsran_cell_t cell = {0};
  cell.nof_prb = 6;
  cell.nof_ports = 2;
  cell.id = pci;
  cell.cp = SRSRAN_CP_NORM;
  cell.phich_length = SRSRAN_PHICH_NORM;
  cell.phich_resources = SRSRAN_PHICH_R_1;
  cell.frame_type = SRSRAN_FDD;
  if (srsran_chest_dl_init(&chest, 6, 1) ||
      srsran_chest_dl_res_init(&estimates, 6) ||
      srsran_chest_dl_set_cell(&chest, cell) ||
      srsran_ofdm_rx_init(&fft, cell.cp, input, symbols[0], 6) ||
      srsran_pbch_init(&pbch) || srsran_pbch_set_cell(&pbch, cell)) goto cleanup;
  /* FFTW planning may overwrite its input; populate only after init. */
  memcpy(input, iq, samples * sizeof(cf_t));
  srsran_ofdm_rx_sf(&fft);
  srsran_dl_sf_cfg_t sf = {0};
  if (srsran_chest_dl_estimate(&chest, &sf, symbols, &estimates) < 0) goto cleanup;
  srsran_pbch_decode_reset(&pbch);
  result = srsran_pbch_decode(&pbch, &estimates, symbols, bits, ports, sfn_offset);
cleanup:
  srsran_pbch_free(&pbch);
  srsran_ofdm_rx_free(&fft);
  srsran_chest_dl_res_free(&estimates);
  srsran_chest_dl_free(&chest);
  free(symbols[0]);
  free(input);
  return result;
}
