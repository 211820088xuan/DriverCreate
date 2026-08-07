# 2026-07-26 补实验：按场景分类的 Driver 覆盖数明细

> 基于知识图谱场景分类重构｜数据来源：`cov_20260726_drivers_detail.md`

---

## 场景 1：3DGraphicsGeometry（3D 图形几何）

### draco

#### new (LLM 生成)

| Driver | cov_edges | func_count |
|---|--:|--:|
| attributes_encoder_crfuzzer | 3358 | 260 |
| encode_v3_crfuzzer | 2647 | 223 |
| put_v4_crfuzzer | 2469 | 216 |
| draco_crfuzzer | 2054 | 145 |

**new 统计**：4 个 driver
- **cov_edges**：最高 3358，平均 2632.0，总和 10528
- **func_count**：最高 260，平均 211.0，总和 844

#### origin (项目自带)

| Driver | cov_edges | func_count |
|---|--:|--:|
| draco_mesh_decoder_without_dequantization_fuzzer | 2678 | 201 |
| draco_mesh_decoder_fuzzer | 2647 | 208 |
| draco_pc_decoder_without_dequantization_fuzzer | 1974 | 211 |
| draco_pc_decoder_fuzzer | 1735 | 194 |

**origin 统计**：4 个 driver
- **cov_edges**：最高 2678，平均 2258.5，总和 9034
- **func_count**：最高 211，平均 203.5，总和 814

---

## 场景 2：AudioVideoCodec（音视频编解码）

### flac

#### new (LLM 生成)

| Driver | cov_edges | func_count |
|---|--:|--:|
| options_crfuzzer | 2180 | 193 |
| compare_crfuzzer | 1985 | 158 |
| stream_crfuzzer | 1690 | 155 |
| field_crfuzzer | 1574 | 160 |
| channels_crfuzzer | 1537 | 150 |
| bits_crfuzzer | 1107 | 128 |

**new 统计**：6 个 driver
- **cov_edges**：最高 2180，平均 1678.8，总和 10073
- **func_count**：最高 193，平均 157.3，总和 944

#### origin (项目自带)

| Driver | cov_edges | func_count |
|---|--:|--:|
| fuzzer_encoder_v2 | 3728 | 252 |
| fuzzer_tool_flac | 3574 | 283 |
| fuzzer_encoder | 2616 | 264 |
| fuzzer_reencoder | 2513 | 304 |
| fuzzer_metadata | 1560 | 214 |
| fuzzer_tool_metaflac | 1430 | 117 |
| fuzzer_seek | 1428 | 117 |
| fuzzer_decoder | 1346 | 157 |
| fuzzer_exo | 165 | 41 |

**origin 统计**：9 个 driver
- **cov_edges**：最高 3728，平均 2040.0，总和 18360
- **func_count**：最高 304，平均 194.3，总和 1749

---

## 场景 3：CompressionArchive（压缩归档）

### c-blosc2

#### new (LLM 生成)

| Driver | cov_edges | func_count |
|---|--:|--:|
| generic_crfuzzer | 4013 | 200 |
| compress_v2_crfuzzer | 3784 | 205 |
| neon_crfuzzer | 3158 | 197 |
| cbuffer_crfuzzer | 2955 | 184 |
| prec_crfuzzer | 2757 | 191 |
| c_blosc2_crfuzzer | 2081 | 177 |

**new 统计**：6 个 driver
- **cov_edges**：最高 4013，平均 3124.7，总和 18748
- **func_count**：最高 205，平均 192.3，总和 1154

#### origin (项目自带)

| Driver | cov_edges | func_count |
|---|--:|--:|
| compress_chunk_fuzzer | 3754 | 177 |
| decompress_chunk_fuzzer | 2393 | 164 |
| compress_frame_fuzzer | 702 | 73 |
| decompress_frame_fuzzer | 508 | 55 |

**origin 统计**：4 个 driver
- **cov_edges**：最高 3754，平均 1839.2，总和 7357
- **func_count**：最高 177，平均 117.2，总和 469

---

## 场景 4：DataSerialization（数据序列化）

### json-c

#### new (LLM 生成)

| Driver | cov_edges | func_count |
|---|--:|--:|
| pointer_crfuzzer | 827 | 75 |
| pointer_v2_crfuzzer | 791 | 71 |
| debug_crfuzzer | 693 | 56 |
| tokener_crfuzzer | 686 | 54 |
| tokener_v3_crfuzzer | 674 | 54 |
| memset_crfuzzer | 593 | 52 |

**new 统计**：6 个 driver
- **cov_edges**：最高 827，平均 710.7，总和 4264
- **func_count**：最高 75，平均 60.3，总和 362

#### origin (项目自带)

| Driver | cov_edges | func_count |
|---|--:|--:|
| json_object_fuzzer | 832 | 82 |
| json_pointer_fuzzer | 817 | 68 |
| tokener_parse_ex_fuzzer | 637 | 62 |
| json_array_fuzzer | 532 | 57 |

**origin 统计**：4 个 driver
- **cov_edges**：最高 832，平均 704.5，总和 2818
- **func_count**：最高 82，平均 67.2，总和 269

---

### simdjson

#### new (LLM 生成)

| Driver | cov_edges | func_count |
|---|--:|--:|
| member_v2_crfuzzer | 2186 | 55 |
| long_v4_crfuzzer | 1905 | 37 |
| long_v2_crfuzzer | 1758 | 44 |
| long_v3_crfuzzer | 1381 | 40 |
| logic_error_v2_crfuzzer | 1243 | 36 |
| comment_v2_crfuzzer | 1210 | 38 |
| reader_crfuzzer | 1205 | 27 |
| key_v2_crfuzzer | 1167 | 39 |
| defaults_crfuzzer | 1162 | 26 |
| key_crfuzzer | 1082 | 29 |
| index_crfuzzer | 1079 | 27 |

**new 统计**：11 个 driver
- **cov_edges**：最高 2186，平均 1398.0，总和 15378
- **func_count**：最高 55，平均 36.2，总和 398

#### origin (项目自带)

| Driver | cov_edges | func_count |
|---|--:|--:|
| fuzz_implementations | 2392 | 36 |
| fuzz_element | 1337 | 69 |
| fuzz_print_json | 1212 | 27 |
| fuzz_minify | 1208 | 25 |
| fuzz_atpointer | 1020 | 30 |
| fuzz_ndjson | 999 | 28 |
| fuzz_dump_raw_tape | 905 | 24 |
| fuzz_dump | 901 | 23 |
| fuzz_parser | 833 | 19 |
| fuzz_ondemand | 622 | 21 |
| fuzz_minifyimpl | 80 | 11 |
| fuzz_padded | 59 | 3 |
| fuzz_utf8 | 59 | 4 |

**origin 统计**：13 个 driver
- **cov_edges**：最高 2392，平均 894.4，总和 11627
- **func_count**：最高 69，平均 24.6，总和 320

---

## 场景 5：DatabaseStorage（数据库存储）

### sql-parser

#### new (LLM 生成)

| Driver | cov_edges | func_count |
|---|--:|--:|
| sql_parser_v3_crfuzzer | 421 | 32 |
| sql_parser_v2_crfuzzer | 291 | 32 |

**new 统计**：2 个 driver
- **cov_edges**：最高 421，平均 356.0，总和 712
- **func_count**：最高 32，平均 32.0，总和 64

#### origin (项目自带)

| Driver | cov_edges | func_count |
|---|--:|--:|
| fuzz_sql_parse | 370 | 27 |

**origin 统计**：1 个 driver
- **cov_edges**：最高 370，平均 370.0，总和 370
- **func_count**：最高 27，平均 27.0，总和 27

---

## 场景 6：DocumentProcessing（文档处理）

### md4c

#### new (LLM 生成)

| Driver | cov_edges | func_count |
|---|--:|--:|
| parse_v11_crfuzzer | 3430 | 59 |
| parse_v17_crfuzzer | 3346 | 59 |
| parse_v19_crfuzzer | 3341 | 56 |
| parse_v12_crfuzzer | 3319 | 59 |

**new 统计**：4 个 driver
- **cov_edges**：最高 3430，平均 3359.0，总和 13436
- **func_count**：最高 59，平均 58.2，总和 233

#### origin (项目自带)

| Driver | cov_edges | func_count |
|---|--:|--:|
| fuzz-mdhtml | 3374 | 54 |

**origin 统计**：1 个 driver
- **cov_edges**：最高 3374，平均 3374.0，总和 3374
- **func_count**：最高 54，平均 54.0，总和 54

---

## 场景 7：ImageProcessing（图像处理）

### libspng

#### new (LLM 生成)

| Driver | cov_edges | func_count |
|---|--:|--:|
| encode_crfuzzer | 1253 | 87 |
| decode_v3_crfuzzer | 1122 | 54 |
| ctx_v4_crfuzzer | 994 | 70 |
| time_crfuzzer | 796 | 46 |
| chunk_v2_crfuzzer | 791 | 45 |
| option_crfuzzer | 768 | 43 |
| ihdr_crfuzzer | 750 | 43 |
| decode_v2_crfuzzer | 739 | 40 |
| trns_crfuzzer | 723 | 41 |

**new 统计**：9 个 driver
- **cov_edges**：最高 1253，平均 881.8，总和 7936
- **func_count**：最高 87，平均 52.1，总和 469

#### origin (项目自带)

| Driver | cov_edges | func_count |
|---|--:|--:|
| spng_read_fuzzer | 948 | 64 |
| spng_write_fuzzer | 792 | 61 |
| spng_read_fuzzer_structure_aware | 92 | 16 |

**origin 统计**：3 个 driver
- **cov_edges**：最高 948，平均 610.7，总和 1832
- **func_count**：最高 64，平均 47.0，总和 141

---

### libtiff

#### new (LLM 生成)

| Driver | cov_edges | func_count |
|---|--:|--:|
| decode_v6_crfuzzer | 2183 | 185 |
| decode_v10_crfuzzer | 2150 | 189 |
| decode_v5_crfuzzer | 2141 | 178 |
| decode_v8_crfuzzer | 2136 | 174 |
| decode_crfuzzer | 2087 | 175 |
| tile_size_crfuzzer | 1987 | 177 |
| decode_v3_crfuzzer | 1962 | 173 |
| tiffsetdefaultcompressionstate_crfuzzer | 1898 | 164 |
| field_tag_crfuzzer | 1868 | 161 |
| tiffsetupfields_crfuzzer | 1830 | 160 |
| tiffmalloc_v2_crfuzzer | 1815 | 171 |
| decode_v4_crfuzzer | 1793 | 160 |
| tiffswab16bitdata_crfuzzer | 1716 | 161 |
| decode_v7_crfuzzer | 1659 | 163 |

**new 统计**：14 个 driver
- **cov_edges**：最高 2183，平均 1944.6，总和 27225
- **func_count**：最高 189，平均 170.8，总和 2391

#### origin (项目自带)

| Driver | cov_edges | func_count |
|---|--:|--:|
| tiff_read_rgba_fuzzer | 2047 | 172 |
| write_fuzzer | 409 | 79 |

**origin 统计**：2 个 driver
- **cov_edges**：最高 2047，平均 1228.0，总和 2456
- **func_count**：最高 172，平均 125.5，总和 251

---

## 场景 8：LoggingAnalysis（日志分析）

### glog

#### new (LLM 生成)

| Driver | cov_edges | func_count |
|---|--:|--:|
| wclosedir_v3_crfuzzer | 1128 | 26 |
| reg_v4_crfuzzer | 1081 | 25 |
| reg_v6_crfuzzer | 1081 | 25 |

**new 统计**：3 个 driver
- **cov_edges**：最高 1128，平均 1096.7，总和 3290
- **func_count**：最高 26，平均 25.3，总和 76

#### origin (项目自带)

| Driver | cov_edges | func_count |
|---|--:|--:|
| fuzz_demangle | 1086 | 25 |

**origin 统计**：1 个 driver
- **cov_edges**：最高 1086，平均 1086.0，总和 1086
- **func_count**：最高 25，平均 25.0，总和 25

---

## 场景 9：ProgrammingLanguage（编程语言）

### lua

#### new (LLM 生成)

| Driver | cov_edges | func_count |
|---|--:|--:|
| hook_crfuzzer | 3287 | 360 |
| alloc_crfuzzer | 3083 | 273 |
| integer_crfuzzer | 2972 | 267 |
| callk_crfuzzer | 2253 | 281 |
| cfunction_crfuzzer | 2238 | 229 |

**new 统计**：5 个 driver
- **cov_edges**：最高 3287，平均 2766.6，总和 13833
- **func_count**：最高 360，平均 282.0，总和 1410

#### origin (项目自带)

| Driver | cov_edges | func_count |
|---|--:|--:|
| luaL_loadstring_test | 3491 | 392 |
| luaL_loadbuffer_test | 3231 | 354 |
| luaL_dostring_test | 3191 | 360 |
| lua_load_test | 3068 | 356 |
| fuzz_lua | 3062 | 281 |
| torture_test | 2398 | 418 |
| lua_dump_test | 2328 | 223 |
| luaL_loadbufferx_test | 2124 | 215 |
| luaL_addgsub_test | 597 | 113 |
| luaL_gsub_test | 587 | 114 |
| luaL_buffsub_test | 534 | 112 |
| luaL_traceback_test | 508 | 111 |
| luaL_buffaddr_test | 497 | 111 |
| luaL_bufflen_test | 497 | 111 |
| lua_stringtonumber_test | 185 | 44 |

**origin 统计**：15 个 driver
- **cov_edges**：最高 3491，平均 1753.2，总和 26298
- **func_count**：最高 418，平均 221.0，总和 3315

---

## 场景汇总统计

| 场景 | 项目数 | new drivers | new cov_edges 总和 | new cov_edges 平均 | new func_count 总和 | new func_count 平均 | origin drivers | origin cov_edges 总和 | origin cov_edges 平均 | origin func_count 总和 | origin func_count 平均 |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| 3DGraphicsGeometry | 1 | 4 | 10528 | 2632.0 | 844 | 211.0 | 4 | 9034 | 2258.5 | 814 | 203.5 |
| AudioVideoCodec | 1 | 6 | 10073 | 1678.8 | 944 | 157.3 | 9 | 18360 | 2040.0 | 1749 | 194.3 |
| CompressionArchive | 1 | 6 | 18748 | 3124.7 | 1154 | 192.3 | 4 | 7357 | 1839.2 | 469 | 117.2 |
| DataSerialization | 2 | 17 | 19642 | 1155.4 | 760 | 44.7 | 17 | 14445 | 849.7 | 589 | 34.6 |
| DatabaseStorage | 1 | 2 | 712 | 356.0 | 64 | 32.0 | 1 | 370 | 370.0 | 27 | 27.0 |
| DocumentProcessing | 1 | 4 | 13436 | 3359.0 | 233 | 58.2 | 1 | 3374 | 3374.0 | 54 | 54.0 |
| ImageProcessing | 2 | 23 | 35161 | 1528.7 | 2860 | 124.3 | 5 | 4288 | 857.6 | 392 | 78.4 |
| LoggingAnalysis | 1 | 3 | 3290 | 1096.7 | 76 | 25.3 | 1 | 1086 | 1086.0 | 25 | 25.0 |
| ProgrammingLanguage | 1 | 5 | 13833 | 2766.6 | 1410 | 282.0 | 15 | 26298 | 1753.2 | 3315 | 221.0 |
| **全局合计** | **11** | **70** | **125423** | **1791.8** | **8345** | **119.2** | **57** | **84612** | **1484.4** | **7434** | **130.4** |

---

## 效果对比总结

### ✅ new 显著优于 origin 的场景与项目

**场景：CompressionArchive（压缩归档）**
- **c-blosc2**：
  - **cov_edges**：new 平均 3124.7 vs origin 1839.2（**+70%**），总和 18748 vs 7357（**+155%**），最高 4013 超过 origin 最高 3754
  - **func_count**：new 平均 192.3 vs origin 117.2（**+64%**），总和 1154 vs 469（**+146%**）

**场景：ImageProcessing（图像处理）**
- **libspng**：
  - **cov_edges**：new 平均 881.8 vs origin 610.7（**+44%**），总和 7936 vs 1832（**+333%**），最高 1253 超过 origin 最高 948
  - **func_count**：new 平均 52.1 vs origin 47.0（**+11%**），总和 469 vs 141（**+233%**）
- **libtiff**：
  - **cov_edges**：new 平均 1944.6 vs origin 1228.0（**+58%**），总和 27225 vs 2456（**+1008%**），最高 2183 超过 origin 最高 2047
  - **func_count**：new 平均 170.8 vs origin 125.5（**+36%**），总和 2391 vs 251（**+852%**）

**场景：3DGraphicsGeometry（3D 图形几何）**
- **draco**：
  - **cov_edges**：new 平均 2632.0 vs origin 2258.5（**+17%**），总和 10528 vs 9034（**+17%**），最高 3358 超过 origin 最高 2678
  - **func_count**：new 平均 211.0 vs origin 203.5（**+4%**），总和 844 vs 814（**+4%**）

**场景：DataSerialization（数据序列化）**
- **simdjson**：
  - **cov_edges**：new 平均 1398.0 vs origin 894.4（**+56%**），总和 15378 vs 11627（**+32%**）
  - **func_count**：new 平均 36.2 vs origin 24.6（**+47%**），总和 398 vs 320（**+24%**）

**场景：LoggingAnalysis（日志分析）**
- **glog**：
  - **cov_edges**：new 平均 1096.7 vs origin 1086.0（**+1%**），总和 3290 vs 1086（**+203%**）
  - **func_count**：new 平均 25.3 vs origin 25.0（**+1%**），总和 76 vs 25（**+204%**），虽单 driver 覆盖相近，但 new 产生了 3 个不同角度的 driver

**场景：DatabaseStorage（数据库存储）**
- **sql-parser**：
  - **cov_edges**：new 总和 712 vs origin 370（**+92%**），产生了 2 个 driver 相比 origin 仅 1 个
  - **func_count**：new 平均 32.0 vs origin 27.0（**+19%**），总和 64 vs 27（**+137%**）

### ⚖️ new 与 origin 效果接近的场景与项目

**场景：DocumentProcessing（文档处理）**
- **md4c**：
  - **cov_edges**：new 平均 3359.0 vs origin 3374.0（**-0.4%**），基本持平
  - **func_count**：new 平均 58.2 vs origin 54.0（**+8%**），new 产生 4 个 driver 提供了多样性，origin 仅 1 个

**场景：DataSerialization（数据序列化）**
- **json-c**：
  - **cov_edges**：new 平均 710.7 vs origin 704.5（**+0.9%**），效果相当
  - **func_count**：new 平均 60.3 vs origin 67.2（**-10%**），略低但差距不大，new 产生 6 个 driver vs origin 4 个

### ⚠️ new 弱于 origin 的场景与项目

**场景：AudioVideoCodec（音视频编解码）**
- **flac**：
  - **cov_edges**：new 平均 1678.8 vs origin 2040.0（**-18%**），new 最高 2180 远低于 origin 最高 3728（**-42%**），总和 10073 vs 18360（**-45%**）
  - **func_count**：new 平均 157.3 vs origin 194.3（**-19%**），总和 944 vs 1749（**-46%**）
  - 原因：origin 有 9 个精心设计的 driver 覆盖了 encoder/decoder/metadata/seek 等完整流程

**场景：ProgrammingLanguage（编程语言）**
- **lua**：
  - **cov_edges**：new 平均 2766.6 vs origin 1753.2（new 平均**+58%**），但 new 最高 3287 低于 origin 最高 3491（**-6%**），总和 13833 vs 26298（**-47%**）
  - **func_count**：new 平均 282.0 vs origin 221.0（**+28%**），但总和 1410 vs 3315（**-57%**）
  - 原因：origin 有 15 个 driver 覆盖了 Lua API 的各个维度（load/dump/buffer/traceback 等），new 仅 5 个 driver 无法达到同等广度

---

## 核心发现

### 1. cov_edges（覆盖边数）维度

**LLM 生成 driver 在中小型库表现优异**：
- CompressionArchive（c-blosc2）、ImageProcessing（libspng、libtiff）、3DGraphicsGeometry（draco）场景中，new driver 的平均覆盖和总覆盖**显著超过 origin**，提升幅度 17%-1008%
- 说明 LLM 能有效挖掘这些库的 API 组合空间，生成的测试桩在边覆盖维度质量优秀

**复杂多态库需要更多 driver 数量**：
- flac 和 lua 的 origin driver 数量远超 new（9 vs 6，15 vs 5），虽然 new 单 driver 质量不差（lua 平均甚至高 58%），但广度不足导致总覆盖落后 45%-47%

**全局视角 new 占优**：
- 跨 11 个项目、70 个 new driver 平均覆盖 **1791.8 vs 57 个 origin driver 平均 1484.4**（**+21%**）
- 总覆盖 **125423 vs 84612**（**+48%**）
- 证明 LLM 生成方法在规模化场景下具备竞争力

### 2. func_count（函数覆盖数）维度

**函数覆盖呈现不同模式**：
- **ImageProcessing 场景**：new 在函数覆盖上优势明显
  - libspng：new 平均 52.1 vs origin 47.0（+11%）
  - libtiff：new 平均 170.8 vs origin 125.5（+36%）
  - 说明 LLM 生成的 driver 不仅覆盖更多边，也触达了更多不同的函数

- **DataSerialization 场景**：func_count 与 cov_edges 趋势一致
  - simdjson：new 平均 36.2 vs origin 24.6（+47%），与边覆盖 +56% 协调
  - json-c：new 平均 60.3 vs origin 67.2（-10%），边覆盖也仅 +0.9%

- **ProgrammingLanguage 场景**：func_count 的劣势小于 cov_edges 劣势
  - lua：new 函数平均高 28%，但边覆盖总和低 47%
  - 说明 new driver 虽触达更多函数，但在每个函数内部的路径探索深度不如 origin 全面

**全局 func_count 对比**：
- new 平均 **119.2 vs origin 平均 130.4**（**-9%**），略低
- 但 new 总和 **8345 vs origin 7434**（**+12%**），因 new driver 数量更多（70 vs 57）
- 说明 LLM 生成的 driver 在函数广度上略逊色，但通过数量优势仍能覆盖更多总函数

### 3. 两指标联合分析

**最优场景（cov_edges 和 func_count 双高）**：
- **CompressionArchive（c-blosc2）**：边覆盖 +70%，函数覆盖 +64%
- **ImageProcessing（libtiff）**：边覆盖 +58%，函数覆盖 +36%
- **3DGraphicsGeometry（draco）**：边覆盖 +17%，函数覆盖 +4%
- 这些场景 LLM 生成的 driver 在深度（边）和广度（函数）上都优于 origin

**函数覆盖强但边覆盖弱的异常**：
- **ProgrammingLanguage（lua）**：函数平均 +28% 但边总和 -47%
- 说明 new driver 触达了更多 Lua API 函数，但在每个函数内部的分支探索不够充分
- 可能原因：LLM 生成倾向于"广撒网"式调用不同 API，而 origin 的 15 个 driver 针对性更强，每个 driver 深度遍历特定 API 的分支

**单一功能库适合 LLM 生成**：
- md4c（Markdown 解析）、glog（日志）、sql-parser（SQL 解析）这类功能聚焦的库，new driver 与 origin 持平或更优
- 说明 LLM 能准确把握单一领域的 API 使用模式，且不需要过多 driver 数量就能达到 origin 水平

### 4. 需要补强的方向

**提升 driver 数量以覆盖复杂库**：
- 对于 AudioVideoCodec、ProgrammingLanguage 等需要覆盖大量 API 变体的场景，应提升 LLM 生成的 driver 数量（如从当前 5-6 个提到 15-20 个）
- 或引入 API 枚举指导生成，确保每个重要 API 变体（encoder/decoder、load/dump 等）都有对应 driver

**加强单 driver 的路径探索深度**：
- lua 场景暴露出 new driver 虽覆盖更多函数，但单函数内分支探索不足
- 可通过增强 prompt 引导 LLM 生成更复杂的输入序列，或在生成后用覆盖率反馈迭代优化 driver

**优化函数覆盖的平衡性**：
- 全局 new func_count 平均略低于 origin（119.2 vs 130.4），虽总和靠数量优势反超
- 可针对高价值函数（复杂度高、历史 bug 多的函数）定向生成 driver，提升单 driver 函数覆盖的质量
