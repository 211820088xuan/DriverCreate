# 2026-07-26 补实验：各 Driver 覆盖数明细

## c-blosc2

### new (LLM 生成)

| Driver | cov_edges | func_count | line_count |
|---|--:|--:|--:|
| generic_crfuzzer | 4013 | 200 | 200 |
| compress_v2_crfuzzer | 3784 | 205 | 205 |
| neon_crfuzzer | 3158 | 197 | 197 |
| cbuffer_crfuzzer | 2955 | 184 | 184 |
| prec_crfuzzer | 2757 | 191 | 191 |
| c_blosc2_crfuzzer | 2081 | 177 | 177 |

### origin (项目自带)

| Driver | cov_edges | func_count | line_count |
|---|--:|--:|--:|
| compress_chunk_fuzzer | 3754 | 177 | 177 |
| decompress_chunk_fuzzer | 2393 | 164 | 164 |
| compress_frame_fuzzer | 702 | 73 | 73 |
| decompress_frame_fuzzer | 508 | 55 | 55 |


---

## draco

### new (LLM 生成)

| Driver | cov_edges | func_count | line_count |
|---|--:|--:|--:|
| attributes_encoder_crfuzzer | 3358 | 260 | 260 |
| encode_v3_crfuzzer | 2647 | 223 | 223 |
| put_v4_crfuzzer | 2469 | 216 | 216 |
| draco_crfuzzer | 2054 | 145 | 145 |

### origin (项目自带)

| Driver | cov_edges | func_count | line_count |
|---|--:|--:|--:|
| draco_mesh_decoder_without_dequantization_fuzzer | 2678 | 201 | 201 |
| draco_mesh_decoder_fuzzer | 2647 | 208 | 208 |
| draco_pc_decoder_without_dequantization_fuzzer | 1974 | 211 | 211 |
| draco_pc_decoder_fuzzer | 1735 | 194 | 194 |

---



---

## flac

### new (LLM 生成)

| Driver | cov_edges | func_count | line_count |
|---|--:|--:|--:|
| options_crfuzzer | 2180 | 193 | 193 |
| compare_crfuzzer | 1985 | 158 | 158 |
| stream_crfuzzer | 1690 | 155 | 155 |
| field_crfuzzer | 1574 | 160 | 160 |
| channels_crfuzzer | 1537 | 150 | 150 |
| bits_crfuzzer | 1107 | 128 | 128 |

### origin (项目自带)

| Driver | cov_edges | func_count | line_count |
|---|--:|--:|--:|
| fuzzer_encoder_v2 | 3728 | 252 | 252 |
| fuzzer_tool_flac | 3574 | 283 | 283 |
| fuzzer_encoder | 2616 | 264 | 264 |
| fuzzer_reencoder | 2513 | 304 | 304 |
| fuzzer_metadata | 1560 | 214 | 214 |
| fuzzer_tool_metaflac | 1430 | 117 | 117 |
| fuzzer_seek | 1428 | 117 | 117 |
| fuzzer_decoder | 1346 | 157 | 157 |
| fuzzer_exo | 165 | 41 | 41 |

---

## glog

### new (LLM 生成)

| Driver | cov_edges | func_count | line_count |
|---|--:|--:|--:|
| wclosedir_v3_crfuzzer | 1128 | 26 | 26 |
| reg_v4_crfuzzer | 1081 | 25 | 25 |
| reg_v6_crfuzzer | 1081 | 25 | 25 |

### origin (项目自带)

| Driver | cov_edges | func_count | line_count |
|---|--:|--:|--:|
| fuzz_demangle | 1086 | 25 | 25 |

---

## json-c

### new (LLM 生成)

| Driver | cov_edges | func_count | line_count |
|---|--:|--:|--:|
| pointer_crfuzzer | 827 | 75 | 75 |
| pointer_v2_crfuzzer | 791 | 71 | 71 |
| debug_crfuzzer | 693 | 56 | 56 |
| tokener_crfuzzer | 686 | 54 | 54 |
| tokener_v3_crfuzzer | 674 | 54 | 54 |
| memset_crfuzzer | 593 | 52 | 52 |

### origin (项目自带)

| Driver | cov_edges | func_count | line_count |
|---|--:|--:|--:|
| json_object_fuzzer | 832 | 82 | 82 |
| json_pointer_fuzzer | 817 | 68 | 68 |
| tokener_parse_ex_fuzzer | 637 | 62 | 62 |
| json_array_fuzzer | 532 | 57 | 57 |

---

## libspng

### new (LLM 生成)

| Driver | cov_edges | func_count | line_count |
|---|--:|--:|--:|
| encode_crfuzzer | 1253 | 87 | 87 |
| decode_v3_crfuzzer | 1122 | 54 | 54 |
| ctx_v4_crfuzzer | 994 | 70 | 70 |
| time_crfuzzer | 796 | 46 | 46 |
| chunk_v2_crfuzzer | 791 | 45 | 45 |
| option_crfuzzer | 768 | 43 | 43 |
| ihdr_crfuzzer | 750 | 43 | 43 |
| decode_v2_crfuzzer | 739 | 40 | 40 |
| trns_crfuzzer | 723 | 41 | 41 |

### origin (项目自带)

| Driver | cov_edges | func_count | line_count |
|---|--:|--:|--:|
| spng_read_fuzzer | 948 | 64 | 64 |
| spng_write_fuzzer | 792 | 61 | 61 |
| spng_read_fuzzer_structure_aware | 92 | 16 | 16 |

---

## libtiff

### new (LLM 生成)

| Driver | cov_edges | func_count | line_count |
|---|--:|--:|--:|
| decode_v6_crfuzzer | 2183 | 185 | 185 |
| decode_v10_crfuzzer | 2150 | 189 | 189 |
| decode_v5_crfuzzer | 2141 | 178 | 178 |
| decode_v8_crfuzzer | 2136 | 174 | 174 |
| decode_crfuzzer | 2087 | 175 | 175 |
| tile_size_crfuzzer | 1987 | 177 | 177 |
| decode_v3_crfuzzer | 1962 | 173 | 173 |
| tiffsetdefaultcompressionstate_crfuzzer | 1898 | 164 | 164 |
| field_tag_crfuzzer | 1868 | 161 | 161 |
| tiffsetupfields_crfuzzer | 1830 | 160 | 160 |
| tiffmalloc_v2_crfuzzer | 1815 | 171 | 171 |
| decode_v4_crfuzzer | 1793 | 160 | 160 |
| tiffswab16bitdata_crfuzzer | 1716 | 161 | 161 |
| decode_v7_crfuzzer | 1659 | 163 | 163 |

### origin (项目自带)

| Driver | cov_edges | func_count | line_count |
|---|--:|--:|--:|
| tiff_read_rgba_fuzzer | 2047 | 172 | 172 |
| write_fuzzer | 409 | 79 | 79 |

---

## lua

### new (LLM 生成)

| Driver | cov_edges | func_count | line_count |
|---|--:|--:|--:|
| hook_crfuzzer | 3287 | 360 | 360 |
| alloc_crfuzzer | 3083 | 273 | 273 |
| integer_crfuzzer | 2972 | 267 | 267 |
| callk_crfuzzer | 2253 | 281 | 281 |
| cfunction_crfuzzer | 2238 | 229 | 229 |

### origin (项目自带)

| Driver | cov_edges | func_count | line_count |
|---|--:|--:|--:|
| luaL_loadstring_test | 3491 | 392 | 392 |
| luaL_loadbuffer_test | 3231 | 354 | 354 |
| luaL_dostring_test | 3191 | 360 | 360 |
| lua_load_test | 3068 | 356 | 356 |
| fuzz_lua | 3062 | 281 | 281 |
| torture_test | 2398 | 418 | 418 |
| lua_dump_test | 2328 | 223 | 223 |
| luaL_loadbufferx_test | 2124 | 215 | 215 |
| luaL_addgsub_test | 597 | 113 | 113 |
| luaL_gsub_test | 587 | 114 | 114 |
| luaL_buffsub_test | 534 | 112 | 112 |
| luaL_traceback_test | 508 | 111 | 111 |
| luaL_buffaddr_test | 497 | 111 | 111 |
| luaL_bufflen_test | 497 | 111 | 111 |
| lua_stringtonumber_test | 185 | 44 | 44 |

---

## md4c

### new (LLM 生成)

| Driver | cov_edges | func_count | line_count |
|---|--:|--:|--:|
| parse_v11_crfuzzer | 3430 | 59 | 59 |
| parse_v17_crfuzzer | 3346 | 59 | 59 |
| parse_v19_crfuzzer | 3341 | 56 | 56 |
| parse_v12_crfuzzer | 3319 | 59 | 59 |

### origin (项目自带)

| Driver | cov_edges | func_count | line_count |
|---|--:|--:|--:|
| fuzz-mdhtml | 3374 | 54 | 54 |

---

## simdjson

### new (LLM 生成)

| Driver | cov_edges | func_count | line_count |
|---|--:|--:|--:|
| member_v2_crfuzzer | 2186 | 55 | 55 |
| long_v4_crfuzzer | 1905 | 37 | 37 |
| long_v2_crfuzzer | 1758 | 44 | 44 |
| long_v3_crfuzzer | 1381 | 40 | 40 |
| logic_error_v2_crfuzzer | 1243 | 36 | 36 |
| comment_v2_crfuzzer | 1210 | 38 | 38 |
| reader_crfuzzer | 1205 | 27 | 27 |
| key_v2_crfuzzer | 1167 | 39 | 39 |
| defaults_crfuzzer | 1162 | 26 | 26 |
| key_crfuzzer | 1082 | 29 | 29 |
| index_crfuzzer | 1079 | 27 | 27 |
### origin (项目自带)

| Driver | cov_edges | func_count | line_count |
|---|--:|--:|--:|
| fuzz_implementations | 2392 | 36 | 36 |
| fuzz_element | 1337 | 69 | 69 |
| fuzz_print_json | 1212 | 27 | 27 |
| fuzz_minify | 1208 | 25 | 25 |
| fuzz_atpointer | 1020 | 30 | 30 |
| fuzz_ndjson | 999 | 28 | 28 |
| fuzz_dump_raw_tape | 905 | 24 | 24 |
| fuzz_dump | 901 | 23 | 23 |
| fuzz_parser | 833 | 19 | 19 |
| fuzz_ondemand | 622 | 21 | 21 |
| fuzz_minifyimpl | 80 | 11 | 11 |
| fuzz_padded | 59 | 3 | 3 |
| fuzz_utf8 | 59 | 4 | 4 |

---

## sql-parser

### new (LLM 生成)

| Driver | cov_edges | func_count | line_count |
|---|--:|--:|--:|
| sql_parser_v3_crfuzzer | 421 | 32 | 32 |
| sql_parser_v2_crfuzzer | 291 | 32 | 32 |

### origin (项目自带)

| Driver | cov_edges | func_count | line_count |
|---|--:|--:|--:|
| fuzz_sql_parse | 370 | 27 | 27 |

---


## 统计总览

| 项目 | new drivers | new 最高 | new 最低 | new 平均 | new 总和 | origin drivers | origin 最高 | origin 最低 | origin 平均 | origin 总和 |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| c-blosc2 | 6 | 4013 | 2081 | 3124.7 | 18748 | 4 | 3754 | 508 | 1839.2 | 7357 |
| draco | 4 | 3358 | 2054 | 2632.0 | 10528 | 4 | 2678 | 1735 | 2258.5 | 9034 |
| flac | 6 | 2180 | 1107 | 1678.8 | 10073 | 9 | 3728 | 165 | 2040.0 | 18360 |
| glog | 3 | 1128 | 1081 | 1096.7 | 3290 | 1 | 1086 | 1086 | 1086.0 | 1086 |
| json-c | 6 | 827 | 593 | 710.7 | 4264 | 4 | 832 | 532 | 704.5 | 2818 |
| libspng | 9 | 1253 | 723 | 881.8 | 7936 | 3 | 948 | 92 | 610.7 | 1832 |
| libtiff | 14 | 2183 | 1659 | 1944.6 | 27225 | 2 | 2047 | 409 | 1228.0 | 2456 |
| lua | 5 | 3287 | 2238 | 2766.6 | 13833 | 15 | 3491 | 185 | 1753.2 | 26298 |
| md4c | 4 | 3430 | 3319 | 3359.0 | 13436 | 1 | 3374 | 3374 | 3374.0 | 3374 |
| simdjson | 11 | 2186 | 1079 | 1398.0 | 15378 | 13 | 2392 | 59 | 894.4 | 11627 |
| sql-parser | 2 | 421 | 291 | 356.0 | 712 | 1 | 370 | 370 | 370.0 | 370 |

**全局合计**

| 组 | 二进制数 | 总覆盖边数 (sum_edges) | 平均覆盖 |
|---|--:|--:|--:|
| new | 70 | 125423 | 1791.8 |
| origin | 57 | 84612 | 1484.4 |
