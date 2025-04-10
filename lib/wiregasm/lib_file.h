#pragma once



#include <glib.h>
#include <epan/timestamp.h>
#include <wiretap/wtap.h>
#include <epan/epan.h>
#include <wireshark/cfile.h>
#include <epan/addr_resolv.h>
#include <epan/secrets.h>
#include <epan/print.h>
#include <epan/column.h>
#include <wsutil/str_util.h>
#include <epan/color_filters.h>
#include <wsutil/filesystem.h>
#include <epan/tap.h>
#include <common/frame_tvbuff.h>
#include <epan/epan_dissect.h>
#include <epan/tvbuff.h>
#include <common/summary.h>
#include <epan/exceptions.h>
#include <epan/follow.h>
#include <epan/expert.h>
#include <epan/strutil.h>

// unmodified stuff
typedef struct {
    const char    *string;
    size_t         string_len;
    capture_file  *cf;
    field_info    *finfo;
    field_info    *prev_finfo;
    bool           frame_matched;
    bool           halt;
} match_data;

bool cf_find_packet_dfilter(capture_file *cf, dfilter_t *sfcode, search_direction dir);
bool cf_find_packet_summary_line(capture_file *cf, const char *string, search_direction dir);
bool cf_find_packet_data(capture_file *cf, const uint8_t *string, size_t string_size, search_direction dir, bool multiple);
bool cf_find_packet_protocol_tree(capture_file *cf, const char *string, search_direction dir, bool multiple);
field_info* cf_find_string_protocol_tree(capture_file *cf, proto_tree *tree);

// modified
bool cf_read_record(capture_file *cf, const frame_data *fdata, wtap_rec *rec, Buffer *buf);

// ui functions stubbed
bool packet_list_select_finfo(field_info *fi);
bool packet_list_select_row_from_data(frame_data *fdata_needle);

// global state
void wg_set_globals_for_find(capture_file *cf, uint8_t *const filtered_frames);