#if 0
// for test .data
"rawaac.o",
#endif

#if 0
//"audio_dec_aac.o"
// fdk-aac
"aacdecoder.o",
"aacdecoder_lib.o",
"aacdec_drc.o",
"aacdec_hcr.o",
"aacdec_hcrs.o",
"aacdec_hcr_bit.o",
"aacdec_pns.o",
"aacdec_tns.o",
"aac_ram.o",
"aac_rom.o",
"block.o",
"channel.o",
"channelinfo.o",
"conceal.o",
"ldfiltbank.o",
"pulsedata.o",
"rvlc.o",
"rvlcbit.o",
"rvlcconceal.o",
"stereo.o",
"aacenc.o",
"aacenc_lib.o",
"aacenc_pns.o",
"aacEnc_ram.o",
"aacEnc_rom.o",
"aacenc_tns.o",
"adj_thr.o",
"bandwidth.o",
"band_nrg.o",
"bitenc.o",
"bit_cnt.o",
"block_switch.o",
"channel_map.o",
"chaosmeasure.o",
"dyn_bits.o",
"grp_data.o",
"intensity.o",
"line_pe.o",
"metadata_compressor.o",
"metadata_main.o",
"ms_stereo.o",
"noisedet.o",
"pnsparam.o",
"pre_echo_control.o",
"psy_configuration.o",
"psy_main.o",
"qc_main.o",
"quantize.o",
"sf_estim.o",
"spreading.o",
"tonality.o",
"transform.o",
"autocorr2nd.o",
"dct.o",
"FDK_bitbuffer.o",
"FDK_core.o",
"FDK_crc.o",
"FDK_hybrid.o",
"FDK_tools_rom.o",
"FDK_trigFcts.o",
"fft.o",
"fft_rad2.o",
"fixpoint_math.o",
"mdct.o",
"qmf.o",
"scale.o",
"tpdec_adif.o",
"tpdec_adts.o",
"tpdec_asc.o",
"tpdec_drm.o",
"tpdec_latm.o",
"tpdec_lib.o",
"tpenc_adif.o",
"tpenc_adts.o",
"tpenc_asc.o",
"tpenc_latm.o",
"tpenc_lib.o",
"limiter.o",
"pcmutils_lib.o",
"env_calc.o",
"env_dec.o",
"env_extr.o",
"huff_dec.o",
"lpp_tran.o",
"psbitdec.o",
"psdec.o",
"psdec_hybrid.o",
"sbrdecoder.o",
"sbrdec_drc.o",
"sbrdec_freq_sca.o",
"sbr_crc.o",
"sbr_deb.o",
"sbr_dec.o",
"sbr_ram.o",
"sbr_rom.o",
"bit_sbr.o",
"code_env.o",
"env_bit.o",
"env_est.o",
"fram_gen.o",
"invf_est.o",
"mh_det.o",
"nf_est.o",
"ps_bitenc.o",
"ps_encode.o",
"ps_main.o",
"resampler.o",
"sbrenc_freq_sca.o",
"sbr_encoder.o",
"sbr_misc.o",
"sbr_ram.o",
"sbr_rom.o",
"ton_corr.o",
"tran_det.o",
"cmdl_parser.o",
"conv_string.o",
"genericStds.o",
"wav_file.o",
#endif

#if 0
// minimp3
"audio_dec_mp3.o",
#endif

#if 0
// opus
"bands.o",
"celt.o",
"celt_decoder.o",
"celt_encoder.o",
"celt_lpc.o",
"cwrs.o",
"entcode.o",
"entdec.o",
"entenc.o",
"laplace.o",
"mathops.o",
"mdct.o",
"modes.o",
"opus_kiss_fft.o",
"pitch.o",
"quant_bands.o",
"rate.o",
"vq.o",
"A2NLSF.o",
"ana_filt_bank_1.o",
"biquad_alt.o",
"bwexpander.o",
"bwexpander_32.o",
"check_control_input.o",
"CNG.o",
"code_signs.o",
"control_audio_bandwidth.o",
"control_codec.o",
"control_SNR.o",
"debug.o",
"decoder_set_fs.o",
"decode_core.o",
"decode_frame.o",
"decode_indices.o",
"decode_parameters.o",
"decode_pitch.o",
"decode_pulses.o",
"dec_API.o",
"encode_indices.o",
"encode_pulses.o",
"enc_API.o",
"apply_sine_window_FIX.o",
"autocorr_FIX.o",
"burg_modified_FIX.o",
"corrMatrix_FIX.o",
"encode_frame_FIX.o",
"find_LPC_FIX.o",
"find_LTP_FIX.o",
"find_pitch_lags_FIX.o",
"find_pred_coefs_FIX.o",
"k2a_FIX.o",
"k2a_Q16_FIX.o",
"LTP_analysis_filter_FIX.o",
"LTP_scale_ctrl_FIX.o",
"noise_shape_analysis_FIX.o",
"pitch_analysis_core_FIX.o",
"process_gains_FIX.o",
"regularize_correlations_FIX.o",
"residual_energy16_FIX.o",
"residual_energy_FIX.o",
"schur64_FIX.o",
"schur_FIX.o",
"vector_ops_FIX.o",
"warped_autocorrelation_FIX.o",
"gain_quant.o",
"HP_variable_cutoff.o",
"init_decoder.o",
"init_encoder.o",
"inner_prod_aligned.o",
"interpolate.o",
"lin2log.o",
"log2lin.o",
"LPC_analysis_filter.o",
"LPC_fit.o",
"LPC_inv_pred_gain.o",
"LP_variable_cutoff.o",
"NLSF2A.o",
"NLSF_decode.o",
"NLSF_del_dec_quant.o",
"NLSF_encode.o",
"NLSF_stabilize.o",
"NLSF_unpack.o",
"NLSF_VQ.o",
"NLSF_VQ_weights_laroia.o",
"NSQ.o",
"NSQ_del_dec.o",
"pitch_est_tables.o",
"PLC.o",
"process_NLSFs.o",
"quant_LTP_gains.o",
"resampler.o",
"resampler_down2.o",
"resampler_down2_3.o",
"resampler_private_AR2.o",
"resampler_private_down_FIR.o",
"resampler_private_IIR_FIR.o",
"resampler_private_up2_HQ.o",
"resampler_rom.o",
"shell_coder.o",
"sigm_Q15.o",
"sort.o",
"stereo_decode_pred.o",
"stereo_encode_pred.o",
"stereo_find_predictor.o",
"stereo_LR_to_MS.o",
"stereo_MS_to_LR.o",
"stereo_quant_pred.o",
"sum_sqr_shift.o",
"tables_gain.o",
"tables_LTP.o",
"tables_NLSF_CB_NB_MB.o",
"tables_NLSF_CB_WB.o",
"tables_other.o",
"tables_pitch_lag.o",
"tables_pulses_per_block.o",
"table_LSF_cos.o",
"VAD.o",
"VQ_WMat_EC.o",
"analysis.o",
"mlp.o",
"mlp_data.o",
"opus.o",
"opus_decoder.o",
"opus_encoder.o",
"opus_memory.o",
"opus_multistream.o",
"opus_multistream_decoder.o",
"opus_multistream_encoder.o",
"repacketizer.o",
"voice_opus.o",
#endif

#if 1
// libspeex
"bits.o",
"cb_search.o",
"exc_10_16_table.o",
"exc_10_32_table.o",
"exc_20_32_table.o",
"exc_5_256_table.o",
"exc_5_64_table.o",
"exc_8_128_table.o",
"fftwrap.o",
"filterbank.o",
"filters.o",
"gain_table.o",
"gain_table_lbr.o",
"hexc_10_32_table.o",
"hexc_table.o",
"high_lsp_tables.o",
"jitter.o",
"kiss_fft.o",
"kiss_fftr.o",
"lbr_48k_tables.o",
"lpc.o",
"lsp.o",
"lsp_tables_nb.o",
"ltp.o",
"math_approx.o",
"mdf.o",
"misc.o",
"modes.o",
"nb_celp.o",
"preprocess.o",
"quant_lsp.o",
"sb_celp.o",
"smallft.o",
"speex.o",
"speex_callbacks.o",
"speex_header.o",
"stereo.o",
"vbr.o",
"vorbis_psy.o",
"vq.o",
"window.o",
#endif