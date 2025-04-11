#include "lib_file.h"

/**
 * Functions from wireshark/file.c:v4.4.5
 * 
 * Code below is copied unmodified
 */

typedef enum {
    MR_NOTMATCHED,
    MR_MATCHED,
    MR_ERROR
} match_result;
typedef match_result (*ws_match_function)(capture_file *, frame_data *,
        wtap_rec *, Buffer *, void *);
static match_result match_protocol_tree(capture_file *cf, frame_data *fdata,
        wtap_rec *, Buffer *, void *criterion);
static void match_subtree_text(proto_node *node, void *data);
static void match_subtree_text_reverse(proto_node *node, void *data);
static match_result match_summary_line(capture_file *cf, frame_data *fdata,
        wtap_rec *, Buffer *, void *criterion);
static match_result match_narrow_and_wide(capture_file *cf, frame_data *fdata,
        wtap_rec *, Buffer *, void *criterion);
static match_result match_narrow_and_wide_reverse(capture_file *cf, frame_data *fdata,
        wtap_rec *, Buffer *, void *criterion);
static match_result match_narrow_and_wide_case(capture_file *cf, frame_data *fdata,
        wtap_rec *, Buffer *, void *criterion);
static match_result match_narrow_and_wide_case_reverse(capture_file *cf, frame_data *fdata,
        wtap_rec *, Buffer *, void *criterion);
static match_result match_narrow_case(capture_file *cf, frame_data *fdata,
        wtap_rec *, Buffer *, void *criterion);
static match_result match_narrow_case_reverse(capture_file *cf, frame_data *fdata,
        wtap_rec *, Buffer *, void *criterion);
static match_result match_wide(capture_file *cf, frame_data *fdata,
        wtap_rec *, Buffer *, void *criterion);
static match_result match_wide_reverse(capture_file *cf, frame_data *fdata,
        wtap_rec *, Buffer *, void *criterion);
static match_result match_wide_case(capture_file *cf, frame_data *fdata,
        wtap_rec *, Buffer *, void *criterion);
static match_result match_wide_case_reverse(capture_file *cf, frame_data *fdata,
        wtap_rec *, Buffer *, void *criterion);
static match_result match_binary(capture_file *cf, frame_data *fdata,
        wtap_rec *, Buffer *, void *criterion);
static match_result match_binary_reverse(capture_file *cf, frame_data *fdata,
        wtap_rec *, Buffer *, void *criterion);
static match_result match_regex(capture_file *cf, frame_data *fdata,
        wtap_rec *, Buffer *, void *criterion);
static match_result match_regex_reverse(capture_file *cf, frame_data *fdata,
        wtap_rec *, Buffer *, void *criterion);
static match_result match_dfilter(capture_file *cf, frame_data *fdata,
        wtap_rec *, Buffer *, void *criterion);
static match_result match_marked(capture_file *cf, frame_data *fdata,
        wtap_rec *, Buffer *, void *criterion);
static match_result match_time_reference(capture_file *cf, frame_data *fdata,
        wtap_rec *, Buffer *, void *criterion);
static bool find_packet(capture_file *cf, ws_match_function match_function,
        void *criterion, search_direction dir);


bool
cf_find_packet_protocol_tree(capture_file *cf, const char *string,
        search_direction dir, bool multiple)
{
    match_data mdata;

    mdata.frame_matched = false;
    mdata.halt = false;
    mdata.string = string;
    mdata.string_len = strlen(string);
    mdata.cf = cf;
    mdata.prev_finfo = cf->finfo_selected;
    if (multiple && cf->finfo_selected && cf->edt) {
        if (dir == SD_FORWARD) {
            proto_tree_children_foreach(cf->edt->tree, match_subtree_text, &mdata);
        } else {
            proto_tree_children_foreach(cf->edt->tree, match_subtree_text_reverse, &mdata);
        }
        if (mdata.frame_matched) {
            packet_list_select_finfo(mdata.finfo);
            return true;
        }
    }
    return find_packet(cf, match_protocol_tree, &mdata, dir);
}

field_info*
cf_find_string_protocol_tree(capture_file *cf, proto_tree *tree)
{
    match_data mdata;
    mdata.frame_matched = false;
    mdata.halt = false;
    mdata.string = convert_string_case(cf->sfilter, cf->case_type);
    mdata.string_len = strlen(mdata.string);
    mdata.cf = cf;
    mdata.prev_finfo = NULL;
    /* Iterate through all the nodes looking for matching text */
    if (cf->dir == SD_FORWARD) {
        proto_tree_children_foreach(tree, match_subtree_text, &mdata);
    } else {
        proto_tree_children_foreach(tree, match_subtree_text_reverse, &mdata);
    }
    g_free((char *)mdata.string);
    return mdata.frame_matched ? mdata.finfo : NULL;
}

static match_result
match_protocol_tree(capture_file *cf, frame_data *fdata,
        wtap_rec *rec, Buffer *buf, void *criterion)
{
    match_data     *mdata = (match_data *)criterion;
    epan_dissect_t  edt;

    /* Load the frame's data. */
    if (!cf_read_record(cf, fdata, rec, buf)) {
        /* Attempt to get the packet failed. */
        return MR_ERROR;
    }

    /* Construct the protocol tree, including the displayed text */
    epan_dissect_init(&edt, cf->epan, true, true);
    /* We don't need the column information */
    epan_dissect_run(&edt, cf->cd_t, rec,
            frame_tvbuff_new_buffer(&cf->provider, fdata, buf),
            fdata, NULL);

    /* Iterate through all the nodes, seeing if they have text that matches. */
    mdata->cf = cf;
    mdata->frame_matched = false;
    mdata->halt = false;
    mdata->prev_finfo = NULL;
    /* We don't care about the direction here, because we're just looking
     * for one match and we'll destroy this tree anyway. (We find the actual
     * field later in PacketList::selectionChanged().) Forwards is faster.
     */
    proto_tree_children_foreach(edt.tree, match_subtree_text, mdata);
    epan_dissect_cleanup(&edt);
    return mdata->frame_matched ? MR_MATCHED : MR_NOTMATCHED;
}

static void
match_subtree_text(proto_node *node, void *data)
{
    match_data   *mdata      = (match_data *) data;
    const char   *string     = mdata->string;
    size_t        string_len = mdata->string_len;
    capture_file *cf         = mdata->cf;
    field_info   *fi         = PNODE_FINFO(node);
    char          label_str[ITEM_LABEL_LENGTH];
    char         *label_ptr;
    size_t        label_len;
    uint32_t      i, i_restart;
    uint8_t       c_char;
    size_t        c_match    = 0;

    /* dissection with an invisible proto tree? */
    ws_assert(fi);

    if (mdata->frame_matched) {
        /* We already had a match; don't bother doing any more work. */
        return;
    }

    /* Don't match invisible entries. */
    if (proto_item_is_hidden(node))
        return;

    if (mdata->prev_finfo) {
        /* Haven't found the old match, so don't match this node. */
        if (fi == mdata->prev_finfo) {
            /* Found the old match, look for the next one after this. */
            mdata->prev_finfo = NULL;
        }
    } else {
        /* was a free format label produced? */
        if (fi->rep) {
            label_ptr = fi->rep->representation;
        } else {
            /* no, make a generic label */
            label_ptr = label_str;
            proto_item_fill_label(fi, label_str);
        }

        if (cf->regex) {
            if (ws_regex_matches(cf->regex, label_ptr)) {
                mdata->frame_matched = true;
                mdata->finfo = fi;
                return;
            }
        } else if (cf->case_type) {
            /* Case insensitive match */
            label_len = strlen(label_ptr);
            i_restart = 0;
            for (i = 0; i < label_len; i++) {
                if (i_restart == 0 && c_match == 0 && (label_len - i < string_len))
                    break;
                c_char = label_ptr[i];
                c_char = g_ascii_toupper(c_char);
                /* If c_match is non-zero, save candidate for retrying full match. */
                if (c_match > 0 && i_restart == 0 && c_char == string[0])
                    i_restart = i;
                if (c_char == string[c_match]) {
                    c_match++;
                    if (c_match == string_len) {
                        mdata->frame_matched = true;
                        mdata->finfo = fi;
                        /* No need to look further; we have a match */
                        return;
                    }
                } else if (i_restart) {
                    i = i_restart;
                    c_match = 1;
                    i_restart = 0;
                } else
                    c_match = 0;
            }
        } else if (strstr(label_ptr, string) != NULL) {
            /* Case sensitive match */
            mdata->frame_matched = true;
            mdata->finfo = fi;
            return;
        }
    }

    /* Recurse into the subtree, if it exists */
    if (node->first_child != NULL)
        proto_tree_children_foreach(node, match_subtree_text, mdata);
}

static void
match_subtree_text_reverse(proto_node *node, void *data)
{
    match_data   *mdata      = (match_data *) data;
    const char   *string     = mdata->string;
    size_t        string_len = mdata->string_len;
    capture_file *cf         = mdata->cf;
    field_info   *fi         = PNODE_FINFO(node);
    char          label_str[ITEM_LABEL_LENGTH];
    char         *label_ptr;
    size_t        label_len;
    uint32_t      i, i_restart;
    uint8_t       c_char;
    size_t        c_match    = 0;

    /* dissection with an invisible proto tree? */
    ws_assert(fi);

    /* We don't have an easy way to search backwards in the tree
     * (see also, proto_find_field_from_offset()) because we don't
     * have a previous node pointer, so we search backwards by
     * searching forwards, only stopping if we see the old match
     * (if we have one).
     */

    if (mdata->halt) {
        return;
    }

    /* Don't match invisible entries. */
    if (proto_item_is_hidden(node))
        return;

    if (mdata->prev_finfo && fi == mdata->prev_finfo) {
        /* Found the old match, use the previous match. */
        mdata->halt = true;
        return;
    }

    /* was a free format label produced? */
    if (fi->rep) {
        label_ptr = fi->rep->representation;
    } else {
        /* no, make a generic label */
        label_ptr = label_str;
        proto_item_fill_label(fi, label_str);
    }

    if (cf->regex) {
        if (ws_regex_matches(cf->regex, label_ptr)) {
            mdata->frame_matched = true;
            mdata->finfo = fi;
        }
    } else if (cf->case_type) {
        /* Case insensitive match */
        label_len = strlen(label_ptr);
        i_restart = 0;
        for (i = 0; i < label_len; i++) {
            if (i_restart == 0 && c_match == 0 && (label_len - i < string_len))
                break;
            c_char = label_ptr[i];
            c_char = g_ascii_toupper(c_char);
            /* If c_match is non-zero, save candidate for retrying full match. */
            if (c_match > 0 && i_restart == 0 && c_char == string[0])
                i_restart = i;
            if (c_char == string[c_match]) {
                c_match++;
                if (c_match == string_len) {
                    mdata->frame_matched = true;
                    mdata->finfo = fi;
                    break;
                }
            } else if (i_restart) {
                i = i_restart;
                c_match = 1;
                i_restart = 0;
            } else
                c_match = 0;
        }
    } else if (strstr(label_ptr, string) != NULL) {
        /* Case sensitive match */
        mdata->frame_matched = true;
        mdata->finfo = fi;
    }

    /* Recurse into the subtree, if it exists */
    if (node->first_child != NULL)
        proto_tree_children_foreach(node, match_subtree_text_reverse, mdata);
}

bool
cf_find_packet_summary_line(capture_file *cf, const char *string,
        search_direction dir)
{
    match_data mdata;

    mdata.string = string;
    mdata.string_len = strlen(string);
    return find_packet(cf, match_summary_line, &mdata, dir);
}

static match_result
match_summary_line(capture_file *cf, frame_data *fdata,
        wtap_rec *rec, Buffer *buf, void *criterion)
{
    match_data     *mdata      = (match_data *)criterion;
    const char     *string     = mdata->string;
    size_t          string_len = mdata->string_len;
    epan_dissect_t  edt;
    const char     *info_column;
    size_t          info_column_len;
    match_result    result     = MR_NOTMATCHED;
    int             colx;
    uint32_t        i, i_restart;
    uint8_t         c_char;
    size_t          c_match    = 0;

    /* Load the frame's data. */
    if (!cf_read_record(cf, fdata, rec, buf)) {
        /* Attempt to get the packet failed. */
        return MR_ERROR;
    }

    /* Don't bother constructing the protocol tree */
    epan_dissect_init(&edt, cf->epan, false, false);
    /* Get the column information */
    epan_dissect_run(&edt, cf->cd_t, rec,
            frame_tvbuff_new_buffer(&cf->provider, fdata, buf),
            fdata, &cf->cinfo);

    /* Find the Info column */
    for (colx = 0; colx < cf->cinfo.num_cols; colx++) {
        if (cf->cinfo.columns[colx].fmt_matx[COL_INFO]) {
            /* Found it.  See if we match. */
            info_column = get_column_text(edt.pi.cinfo, colx);
            info_column_len = strlen(info_column);
            if (cf->regex) {
                if (ws_regex_matches(cf->regex, info_column)) {
                    result = MR_MATCHED;
                    break;
                }
            } else if (cf->case_type) {
                /* Case insensitive match */
                i_restart = 0;
                for (i = 0; i < info_column_len; i++) {
                    if (i_restart == 0 && c_match == 0 && (info_column_len - i < string_len))
                        break;
                    c_char = info_column[i];
                    c_char = g_ascii_toupper(c_char);
                    /* If c_match is non-zero, save candidate for retrying full match. */
                    if (c_match > 0 && i_restart == 0 && c_char == string[0])
                        i_restart = i;
                    if (c_char == string[c_match]) {
                        c_match++;
                        if (c_match == string_len) {
                            result = MR_MATCHED;
                            break;
                        }
                    } else if (i_restart) {
                        i = i_restart;
                        c_match = 1;
                        i_restart = 0;
                    } else
                        c_match = 0;
                }
            } else if (strstr(info_column, string) != NULL) {
                /* Case sensitive match */
                result = MR_MATCHED;
            }
            break;
        }
    }
    epan_dissect_cleanup(&edt);
    return result;
}

typedef struct {
    const uint8_t *data;
    size_t        data_len;
    ws_mempbrk_pattern *pattern;
} cbs_t;    /* "Counted byte string" */


/*
 * The current match_* routines only support ASCII case insensitivity and don't
 * convert UTF-8 inputs to UTF-16 for matching.  The UTF-16 support just
 * interleaves with \0 bytes, which works for 7 bit ASCII.
 *
 * We could modify them to use the GLib Unicode routines or the International
 * Components for Unicode library but it's not apparent that we could do so
 * without consuming a lot more CPU and memory or that searching would be
 * significantly better.
 *
 * XXX: We could test the search string to see if it's all ASCII, and if not
 * use Unicode aware routines for case insensitive searches or any UTF-16
 * search.
 */

bool
cf_find_packet_data(capture_file *cf, const uint8_t *string, size_t string_size,
        search_direction dir, bool multiple)
{
    cbs_t  info;
    uint8_t needles[3];
    ws_mempbrk_pattern pattern = {0};
    ws_match_function match_function;

    info.data = string;
    info.data_len = string_size;

    /* Regex, String or hex search? */
    if (cf->regex) {
        /* Regular Expression search */
        match_function = (cf->dir == SD_FORWARD) ? match_regex : match_regex_reverse;
    } else if (cf->string) {
        /* String search - what type of string? */
        if (cf->case_type) {
            needles[0] = string[0];
            needles[1] = g_ascii_tolower(needles[0]);
            needles[2] = '\0';
            ws_mempbrk_compile(&pattern, needles);
            info.pattern = &pattern;
            switch (cf->scs_type) {

                case SCS_NARROW_AND_WIDE:
                    match_function = (cf->dir == SD_FORWARD) ? match_narrow_and_wide_case : match_narrow_and_wide_case_reverse;
                    break;

                case SCS_NARROW:
                    match_function = (cf->dir == SD_FORWARD) ? match_narrow_case : match_narrow_case_reverse;
                    break;

                case SCS_WIDE:
                    match_function = (cf->dir == SD_FORWARD) ? match_wide_case : match_wide_case_reverse;
                    break;

                default:
                    ws_assert_not_reached();
                    return false;
            }

        } else {
            switch (cf->scs_type) {

                case SCS_NARROW_AND_WIDE:
                    match_function = (cf->dir == SD_FORWARD) ? match_narrow_and_wide : match_narrow_and_wide_reverse;
                    break;

                case SCS_NARROW:
                    /* Narrow, case-sensitive match is the same as looking
                     * for a converted hexstring. */
                    match_function = (cf->dir == SD_FORWARD) ? match_binary : match_binary_reverse;
                    break;

                case SCS_WIDE:
                    match_function = (cf->dir == SD_FORWARD) ? match_wide : match_wide_reverse;
                    break;

                default:
                    ws_assert_not_reached();
                    return false;
            }
        }
    } else {
        match_function = (cf->dir == SD_FORWARD) ? match_binary : match_binary_reverse;
    }

    if (multiple && cf->current_frame && (cf->search_pos || cf->search_len)) {
        /* Use the current frame (this will perform the equivalent of
         * cf_read_current_record() in match_function).
         */
        if (match_function(cf, cf->current_frame, &cf->rec, &cf->buf, &info)) {
            cf->search_in_progress = true;
            if (cf->edt) {
                field_info *fi = NULL;
                /* The regex match can match an empty string. */
                if (cf->search_len) {
                    fi = proto_find_field_from_offset(cf->edt->tree, cf->search_pos + cf->search_len - 1, cf->edt->tvb);
                }
                packet_list_select_finfo(fi);
            } else {
                packet_list_select_row_from_data(cf->current_frame);
            }
            cf->search_in_progress = false;
            return true;
        }
    }
    cf->search_pos = 0; /* Reset the position */
    cf->search_len = 0; /* Reset length */
    return find_packet(cf, match_function, &info, dir);
}

static match_result
match_narrow_and_wide(capture_file *cf, frame_data *fdata,
        wtap_rec *rec, Buffer *buf, void *criterion)
{
    cbs_t        *info       = (cbs_t *)criterion;
    const uint8_t *ascii_text = info->data;
    size_t        textlen    = info->data_len;
    match_result  result;
    uint32_t      buf_len;
    uint8_t      *pd, *buf_start, *buf_end;
    uint32_t      i;
    uint8_t       c_char;
    size_t        c_match    = 0;

    /* Load the frame's data. */
    if (!cf_read_record(cf, fdata, rec, buf)) {
        /* Attempt to get the packet failed. */
        return MR_ERROR;
    }

    result = MR_NOTMATCHED;
    buf_len = fdata->cap_len;
    buf_start = ws_buffer_start_ptr(buf);
    buf_end = buf_start + buf_len;
    pd = buf_start;
    if (cf->search_len || cf->search_pos) {
        /* we want to start searching one byte past the previous match start */
        pd += cf->search_pos + 1;
    }
    for (; pd < buf_end; pd++) {
        pd = (uint8_t *)memchr(pd, ascii_text[0], buf_end - pd);
        if (pd == NULL) break;
        /* Try narrow match at this start location */
        c_match = 0;
        for (i = 0; pd + i < buf_end; i++) {
            c_char = pd[i];
            if (c_char == ascii_text[c_match]) {
                c_match++;
                if (c_match == textlen) {
                    result = MR_MATCHED;
                    /* Save position and length for highlighting the field. */
                    cf->search_pos = (uint32_t)(pd - buf_start);
                    cf->search_len = (uint32_t)(i + 1);
                    goto done;
                }
            } else {
                break;
            }
        }

        /* Now try wide match at the same start location. */
        c_match = 0;
        for (i = 0; pd + i < buf_end; i++) {
            c_char = pd[i];
            if (c_char == ascii_text[c_match]) {
                c_match++;
                if (c_match == textlen) {
                    result = MR_MATCHED;
                    /* Save position and length for highlighting the field. */
                    cf->search_pos = (uint32_t)(pd - buf_start);
                    cf->search_len = (uint32_t)(i + 1);
                    goto done;
                }
                i++;
                if (pd + i >= buf_end || pd[i] != '\0') break;
            } else {
                break;
            }
        }
    }

done:
    return result;
}

static match_result
match_narrow_and_wide_reverse(capture_file *cf, frame_data *fdata,
        wtap_rec *rec, Buffer *buf, void *criterion)
{
    cbs_t        *info       = (cbs_t *)criterion;
    const uint8_t *ascii_text = info->data;
    size_t        textlen    = info->data_len;
    match_result  result;
    uint32_t      buf_len;
    uint8_t      *pd, *buf_start, *buf_end;
    uint32_t      i;
    uint8_t       c_char;
    size_t        c_match    = 0;

    /* Load the frame's data. */
    if (!cf_read_record(cf, fdata, rec, buf)) {
        /* Attempt to get the packet failed. */
        return MR_ERROR;
    }

    result = MR_NOTMATCHED;
    /* Has to be room to hold the sought data. */
    if (textlen > fdata->cap_len) {
        return result;
    }
    buf_len = fdata->cap_len;
    buf_start = ws_buffer_start_ptr(buf);
    buf_end = buf_start + buf_len;
    pd = buf_end - textlen;
    if (cf->search_len || cf->search_pos) {
        /* we want to start searching one byte before the previous match start */
        pd = buf_start + cf->search_pos - 1;
    }
    for (; pd < buf_end; pd++) {
        pd = (uint8_t *)ws_memrchr(buf_start, ascii_text[0], pd - buf_start + 1);
        if (pd == NULL) break;
        /* Try narrow match at this start location */
        c_match = 0;
        for (i = 0; pd + i < buf_end; i++) {
            c_char = pd[i];
            if (c_char == ascii_text[c_match]) {
                c_match++;
                if (c_match == textlen) {
                    result = MR_MATCHED;
                    /* Save position and length for highlighting the field. */
                    cf->search_pos = (uint32_t)(pd - buf_start);
                    cf->search_len = (uint32_t)(i + 1);
                    goto done;
                }
            } else {
                break;
            }
        }

        /* Now try wide match at the same start location. */
        c_match = 0;
        for (i = 0; pd + i < buf_end; i++) {
            c_char = pd[i];
            if (c_char == ascii_text[c_match]) {
                c_match++;
                if (c_match == textlen) {
                    result = MR_MATCHED;
                    /* Save position and length for highlighting the field. */
                    cf->search_pos = (uint32_t)(pd - buf_start);
                    cf->search_len = (uint32_t)(i + 1);
                    goto done;
                }
                i++;
                if (pd + i >= buf_end || pd[i] != '\0') break;
            } else {
                break;
            }
        }
    }

done:
    return result;
}

/* Case insensitive match */
static match_result
match_narrow_and_wide_case(capture_file *cf, frame_data *fdata,
        wtap_rec *rec, Buffer *buf, void *criterion)
{
    cbs_t        *info       = (cbs_t *)criterion;
    const uint8_t *ascii_text = info->data;
    size_t        textlen    = info->data_len;
    ws_mempbrk_pattern *pattern = info->pattern;
    match_result  result;
    uint32_t      buf_len;
    uint8_t      *pd, *buf_start, *buf_end;
    uint32_t      i;
    uint8_t       c_char;
    size_t        c_match    = 0;

    /* Load the frame's data. */
    if (!cf_read_record(cf, fdata, rec, buf)) {
        /* Attempt to get the packet failed. */
        return MR_ERROR;
    }

    ws_assert(pattern != NULL);

    result = MR_NOTMATCHED;
    buf_len = fdata->cap_len;
    buf_start = ws_buffer_start_ptr(buf);
    buf_end = buf_start + buf_len;
    pd = buf_start;
    if (cf->search_len || cf->search_pos) {
        /* we want to start searching one byte past the previous match start */
        pd += cf->search_pos + 1;
    }
    for (; pd < buf_end; pd++) {
        pd = (uint8_t *)ws_mempbrk_exec(pd, buf_end - pd, pattern, &c_char);
        if (pd == NULL) break;
        /* Try narrow match at this start location */
        c_match = 0;
        for (i = 0; pd + i < buf_end; i++) {
            c_char = g_ascii_toupper(pd[i]);
            if (c_char == ascii_text[c_match]) {
                c_match++;
                if (c_match == textlen) {
                    result = MR_MATCHED;
                    /* Save position and length for highlighting the field. */
                    cf->search_pos = (uint32_t)(pd - buf_start);
                    cf->search_len = (uint32_t)(i + 1);
                    goto done;
                }
            } else {
                break;
            }
        }

        /* Now try wide match at the same start location. */
        c_match = 0;
        for (i = 0; pd + i < buf_end; i++) {
            c_char = g_ascii_toupper(pd[i]);
            if (c_char == ascii_text[c_match]) {
                c_match++;
                if (c_match == textlen) {
                    result = MR_MATCHED;
                    /* Save position and length for highlighting the field. */
                    cf->search_pos = (uint32_t)(pd - buf_start);
                    cf->search_len = (uint32_t)(i + 1);
                    goto done;
                }
                i++;
                if (pd + i >= buf_end || pd[i] != '\0') break;
            } else {
                break;
            }
        }
    }

done:
    return result;
}

static match_result
match_narrow_and_wide_case_reverse(capture_file *cf, frame_data *fdata,
        wtap_rec *rec, Buffer *buf, void *criterion)
{
    cbs_t        *info       = (cbs_t *)criterion;
    const uint8_t *ascii_text = info->data;
    size_t        textlen    = info->data_len;
    ws_mempbrk_pattern *pattern = info->pattern;
    match_result  result;
    uint32_t      buf_len;
    uint8_t      *pd, *buf_start, *buf_end;
    uint32_t      i;
    uint8_t       c_char;
    size_t        c_match    = 0;

    /* Load the frame's data. */
    if (!cf_read_record(cf, fdata, rec, buf)) {
        /* Attempt to get the packet failed. */
        return MR_ERROR;
    }

    ws_assert(pattern != NULL);

    result = MR_NOTMATCHED;
    /* Has to be room to hold the sought data. */
    if (textlen > fdata->cap_len) {
        return result;
    }
    buf_len = fdata->cap_len;
    buf_start = ws_buffer_start_ptr(buf);
    buf_end = buf_start + buf_len;
    pd = buf_end - textlen;
    if (cf->search_len || cf->search_pos) {
        /* we want to start searching one byte before the previous match start */
        pd = buf_start + cf->search_pos - 1;
    }
    for (; pd >= buf_start; pd--) {
        pd = (uint8_t *)ws_memrpbrk_exec(buf_start, pd - buf_start + 1, pattern, &c_char);
        if (pd == NULL) break;
        /* Try narrow match at this start location */
        c_match = 0;
        for (i = 0; pd + i < buf_end; i++) {
            c_char = g_ascii_toupper(pd[i]);
            if (c_char == ascii_text[c_match]) {
                c_match++;
                if (c_match == textlen) {
                    result = MR_MATCHED;
                    /* Save position and length for highlighting the field. */
                    cf->search_pos = (uint32_t)(pd - buf_start);
                    cf->search_len = (uint32_t)(i + 1);
                    goto done;
                }
            } else {
                break;
            }
        }

        /* Now try wide match at the same start location. */
        c_match = 0;
        for (i = 0; pd + i < buf_end; i++) {
            c_char = g_ascii_toupper(pd[i]);
            if (c_char == ascii_text[c_match]) {
                c_match++;
                if (c_match == textlen) {
                    result = MR_MATCHED;
                    /* Save position and length for highlighting the field. */
                    cf->search_pos = (uint32_t)(pd - buf_start);
                    cf->search_len = (uint32_t)(i + 1);
                    goto done;
                }
                i++;
                if (pd + i >= buf_end || pd[i] != '\0') break;
            } else {
                break;
            }
        }
    }

done:
    return result;
}

/* Case insensitive match */
static match_result
match_narrow_case(capture_file *cf, frame_data *fdata,
        wtap_rec *rec, Buffer *buf, void *criterion)
{
    cbs_t        *info       = (cbs_t *)criterion;
    const uint8_t *ascii_text = info->data;
    size_t        textlen    = info->data_len;
    ws_mempbrk_pattern *pattern = info->pattern;
    match_result  result;
    uint32_t      buf_len;
    uint8_t      *pd, *buf_start, *buf_end;
    uint32_t      i;
    uint8_t       c_char;
    size_t        c_match    = 0;

    /* Load the frame's data. */
    if (!cf_read_record(cf, fdata, rec, buf)) {
        /* Attempt to get the packet failed. */
        return MR_ERROR;
    }

    ws_assert(pattern != NULL);

    result = MR_NOTMATCHED;
    buf_len = fdata->cap_len;
    buf_start = ws_buffer_start_ptr(buf);
    buf_end = buf_start + buf_len;
    pd = buf_start;
    if (cf->search_len || cf->search_pos) {
        /* we want to start searching one byte past the previous match start */
        pd += cf->search_pos + 1;
    }
    for (; pd < buf_end; pd++) {
        pd = (uint8_t *)ws_mempbrk_exec(pd, buf_end - pd, pattern, &c_char);
        if (pd == NULL) break;
        c_match = 0;
        for (i = 0; pd + i < buf_end; i++) {
            c_char = g_ascii_toupper(pd[i]);
            if (c_char == ascii_text[c_match]) {
                c_match++;
                if (c_match == textlen) {
                    /* Save position and length for highlighting the field. */
                    result = MR_MATCHED;
                    cf->search_pos = (uint32_t)(pd - buf_start);
                    cf->search_len = (uint32_t)(i + 1);
                    goto done;
                }
            } else {
                break;
            }
        }
    }

done:
    return result;
}

static match_result
match_narrow_case_reverse(capture_file *cf, frame_data *fdata,
        wtap_rec *rec, Buffer *buf, void *criterion)
{
    cbs_t        *info       = (cbs_t *)criterion;
    const uint8_t *ascii_text = info->data;
    size_t        textlen    = info->data_len;
    ws_mempbrk_pattern *pattern = info->pattern;
    match_result  result;
    uint32_t      buf_len;
    uint8_t      *pd, *buf_start, *buf_end;
    uint32_t      i;
    uint8_t       c_char;
    size_t        c_match    = 0;

    /* Load the frame's data. */
    if (!cf_read_record(cf, fdata, rec, buf)) {
        /* Attempt to get the packet failed. */
        return MR_ERROR;
    }

    ws_assert(pattern != NULL);

    result = MR_NOTMATCHED;
    /* Has to be room to hold the sought data. */
    if (textlen > fdata->cap_len) {
        return result;
    }
    buf_len = fdata->cap_len;
    buf_start = ws_buffer_start_ptr(buf);
    buf_end = buf_start + buf_len;
    pd = buf_end - textlen;
    if (cf->search_len || cf->search_pos) {
        /* we want to start searching one byte before the previous match start */
        pd = buf_start + cf->search_pos - 1;
    }
    for (; pd >= buf_start; pd--) {
        pd = (uint8_t *)ws_memrpbrk_exec(buf_start, pd - buf_start + 1, pattern, &c_char);
        if (pd == NULL) break;
        c_match = 0;
        for (i = 0; pd + i < buf_end; i++) {
            c_char = g_ascii_toupper(pd[i]);
            if (c_char == ascii_text[c_match]) {
                c_match++;
                if (c_match == textlen) {
                    /* Save position and length for highlighting the field. */
                    result = MR_MATCHED;
                    cf->search_pos = (uint32_t)(pd - buf_start);
                    cf->search_len = (uint32_t)(i + 1);
                    goto done;
                }
            } else {
                break;
            }
        }
    }

done:
    return result;
}

static match_result
match_wide(capture_file *cf, frame_data *fdata,
        wtap_rec *rec, Buffer *buf, void *criterion)
{
    cbs_t        *info       = (cbs_t *)criterion;
    const uint8_t *ascii_text = info->data;
    size_t        textlen    = info->data_len;
    match_result  result;
    uint32_t      buf_len;
    uint8_t      *pd, *buf_start, *buf_end;
    uint32_t      i;
    uint8_t       c_char;
    size_t        c_match    = 0;

    /* Load the frame's data. */
    if (!cf_read_record(cf, fdata, rec, buf)) {
        /* Attempt to get the packet failed. */
        return MR_ERROR;
    }

    result = MR_NOTMATCHED;
    buf_len = fdata->cap_len;
    buf_start = ws_buffer_start_ptr(buf);
    buf_end = buf_start + buf_len;
    pd = buf_start;
    if (cf->search_len || cf->search_pos) {
        /* we want to start searching one byte past the previous match start */
        pd += cf->search_pos + 1;
    }
    for (; pd < buf_end; pd++) {
        pd = (uint8_t *)memchr(pd, ascii_text[0], buf_end - pd);
        if (pd == NULL) break;
        c_match = 0;
        for (i = 0; pd + i < buf_end; i++) {
            c_char = pd[i];
            if (c_char == ascii_text[c_match]) {
                c_match++;
                if (c_match == textlen) {
                    result = MR_MATCHED;
                    /* Save position and length for highlighting the field. */
                    cf->search_pos = (uint32_t)(pd - buf_start);
                    cf->search_len = (uint32_t)(i + 1);
                    goto done;
                }
                i++;
                if (pd + i >= buf_end || pd[i] != '\0') break;
            } else {
                break;
            }
        }
    }

done:
    return result;
}

static match_result
match_wide_reverse(capture_file *cf, frame_data *fdata,
        wtap_rec *rec, Buffer *buf, void *criterion)
{
    cbs_t        *info       = (cbs_t *)criterion;
    const uint8_t *ascii_text = info->data;
    size_t        textlen    = info->data_len;
    match_result  result;
    uint32_t      buf_len;
    uint8_t      *pd, *buf_start, *buf_end;
    uint32_t      i;
    uint8_t       c_char;
    size_t        c_match    = 0;

    /* Load the frame's data. */
    if (!cf_read_record(cf, fdata, rec, buf)) {
        /* Attempt to get the packet failed. */
        return MR_ERROR;
    }

    result = MR_NOTMATCHED;
    /* Has to be room to hold the sought data. */
    if (textlen > fdata->cap_len) {
        return result;
    }
    buf_len = fdata->cap_len;
    buf_start = ws_buffer_start_ptr(buf);
    buf_end = buf_start + buf_len;
    pd = buf_end - textlen;
    if (cf->search_len || cf->search_pos) {
        /* we want to start searching one byte before the previous match start */
        pd = buf_start + cf->search_pos - 1;
    }
    for (; pd < buf_end; pd++) {
        pd = (uint8_t *)ws_memrchr(buf_start, ascii_text[0], pd - buf_start + 1);
        if (pd == NULL) break;
        c_match = 0;
        for (i = 0; pd + i < buf_end; i++) {
            c_char = pd[i];
            if (c_char == ascii_text[c_match]) {
                c_match++;
                if (c_match == textlen) {
                    result = MR_MATCHED;
                    /* Save position and length for highlighting the field. */
                    cf->search_pos = (uint32_t)(pd - buf_start);
                    cf->search_len = (uint32_t)(i + 1);
                    goto done;
                }
                i++;
                if (pd + i >= buf_end || pd[i] != '\0') break;
            } else {
                break;
            }
        }
    }

done:
    return result;
}

/* Case insensitive match */
static match_result
match_wide_case(capture_file *cf, frame_data *fdata,
        wtap_rec *rec, Buffer *buf, void *criterion)
{
    cbs_t        *info       = (cbs_t *)criterion;
    const uint8_t *ascii_text = info->data;
    size_t        textlen    = info->data_len;
    ws_mempbrk_pattern *pattern = info->pattern;
    match_result  result;
    uint32_t      buf_len;
    uint8_t      *pd, *buf_start, *buf_end;
    uint32_t      i;
    uint8_t       c_char;
    size_t        c_match    = 0;

    /* Load the frame's data. */
    if (!cf_read_record(cf, fdata, rec, buf)) {
        /* Attempt to get the packet failed. */
        return MR_ERROR;
    }

    ws_assert(pattern != NULL);

    result = MR_NOTMATCHED;
    buf_len = fdata->cap_len;
    buf_start = ws_buffer_start_ptr(buf);
    buf_end = buf_start + buf_len;
    pd = buf_start;
    if (cf->search_len || cf->search_pos) {
        /* we want to start searching one byte past the previous match start */
        pd += cf->search_pos + 1;
    }
    for (; pd < buf_end; pd++) {
        pd = (uint8_t *)ws_mempbrk_exec(pd, buf_end - pd, pattern, &c_char);
        if (pd == NULL) break;
        c_match = 0;
        for (i = 0; pd + i < buf_end; i++) {
            c_char = g_ascii_toupper(pd[i]);
            if (c_char == ascii_text[c_match]) {
                c_match++;
                if (c_match == textlen) {
                    result = MR_MATCHED;
                    /* Save position and length for highlighting the field. */
                    cf->search_pos = (uint32_t)(pd - buf_start);
                    cf->search_len = (uint32_t)(i + 1);
                    goto done;
                }
                i++;
                if (pd + i >= buf_end || pd[i] != '\0') break;
            } else {
                break;
            }
        }
    }

done:
    return result;
}

/* Case insensitive match */
static match_result
match_wide_case_reverse(capture_file *cf, frame_data *fdata,
        wtap_rec *rec, Buffer *buf, void *criterion)
{
    cbs_t        *info       = (cbs_t *)criterion;
    const uint8_t *ascii_text = info->data;
    size_t        textlen    = info->data_len;
    ws_mempbrk_pattern *pattern = info->pattern;
    match_result  result;
    uint32_t      buf_len;
    uint8_t      *pd, *buf_start, *buf_end;
    uint32_t      i;
    uint8_t       c_char;
    size_t        c_match    = 0;

    /* Load the frame's data. */
    if (!cf_read_record(cf, fdata, rec, buf)) {
        /* Attempt to get the packet failed. */
        return MR_ERROR;
    }

    ws_assert(pattern != NULL);

    result = MR_NOTMATCHED;
    /* Has to be room to hold the sought data. */
    if (textlen > fdata->cap_len) {
        return result;
    }
    buf_len = fdata->cap_len;
    buf_start = ws_buffer_start_ptr(buf);
    buf_end = buf_start + buf_len;
    pd = buf_end - textlen;
    if (cf->search_len || cf->search_pos) {
        /* we want to start searching one byte before the previous match start */
        pd = buf_start + cf->search_pos - 1;
    }
    for (; pd >= buf_start; pd--) {
        pd = (uint8_t *)ws_memrpbrk_exec(buf_start, pd - buf_start + 1, pattern, &c_char);
        if (pd == NULL) break;
        c_match = 0;
        for (i = 0; pd + i < buf_end; i++) {
            c_char = g_ascii_toupper(pd[i]);
            if (c_char == ascii_text[c_match]) {
                c_match++;
                if (c_match == textlen) {
                    result = MR_MATCHED;
                    /* Save position and length for highlighting the field. */
                    cf->search_pos = (uint32_t)(pd - buf_start);
                    cf->search_len = (uint32_t)(i + 1);
                    goto done;
                }
                i++;
                if (pd + i >= buf_end || pd[i] != '\0') break;
            } else {
                break;
            }
        }
    }

done:
    return result;
}

static match_result
match_binary(capture_file *cf, frame_data *fdata,
        wtap_rec *rec, Buffer *buf, void *criterion)
{
    cbs_t        *info        = (cbs_t *)criterion;
    size_t        datalen     = info->data_len;
    match_result  result;
    const uint8_t *pd = NULL, *buf_start;

    /* Load the frame's data. */
    if (!cf_read_record(cf, fdata, rec, buf)) {
        /* Attempt to get the packet failed. */
        return MR_ERROR;
    }

    result = MR_NOTMATCHED;
    buf_start = ws_buffer_start_ptr(buf);
    size_t offset = 0;
    if (cf->search_len || cf->search_pos) {
        /* we want to start searching one byte past the previous match start */
        offset = cf->search_pos + 1;
    }
    if (offset < fdata->cap_len) {
        pd = ws_memmem(buf_start + offset, fdata->cap_len - offset, info->data, datalen);
    }
    if (pd != NULL) {
        result = MR_MATCHED;
        /* Save position and length for highlighting the field. */
        cf->search_pos = (uint32_t)(pd - buf_start);
        cf->search_len = (uint32_t)datalen;
    }

    return result;
}

static match_result
match_binary_reverse(capture_file *cf, frame_data *fdata,
        wtap_rec *rec, Buffer *buf, void *criterion)
{
    cbs_t        *info        = (cbs_t *)criterion;
    size_t        datalen     = info->data_len;
    match_result  result;
    const uint8_t *pd = NULL, *buf_start;

    /* Load the frame's data. */
    if (!cf_read_record(cf, fdata, rec, buf)) {
        /* Attempt to get the packet failed. */
        return MR_ERROR;
    }

    result = MR_NOTMATCHED;
    buf_start = ws_buffer_start_ptr(buf);
    /* Has to be room to hold the sought data. */
    if (datalen > fdata->cap_len) {
        return result;
    }
    pd = buf_start + fdata->cap_len - datalen;
    if (cf->search_len || cf->search_pos) {
        /* we want to start searching one byte before the previous match start */
        pd = buf_start + cf->search_pos - 1;
    }
    for (; pd >= buf_start; pd--) {
        pd = (uint8_t *)ws_memrchr(buf_start, info->data[0], pd - buf_start + 1);
        if (pd == NULL) break;
        if (memcmp(pd, info->data, datalen) == 0) {
            result = MR_MATCHED;
            /* Save position and length for highlighting the field. */
            cf->search_pos = (uint32_t)(pd - buf_start);
            cf->search_len = (uint32_t)datalen;
            break;
        }
    }

    return result;
}

static match_result
match_regex(capture_file *cf, frame_data *fdata,
        wtap_rec *rec, Buffer *buf, void *criterion _U_)
{
    match_result  result = MR_NOTMATCHED;
    size_t result_pos[2] = {0, 0};

    /* Load the frame's data. */
    if (!cf_read_record(cf, fdata, rec, buf)) {
        /* Attempt to get the packet failed. */
        return MR_ERROR;
    }

    size_t offset = 0;
    if (cf->search_len || cf->search_pos) {
        /* we want to start searching one byte past the previous match start */
        offset = cf->search_pos + 1;
    }
    if (offset < fdata->cap_len) {
        if (ws_regex_matches_pos(cf->regex,
                                    (const char *)ws_buffer_start_ptr(buf),
                                    fdata->cap_len, offset,
                                    result_pos)) {
            //TODO: A chosen regex can match the empty string (zero length)
            // which doesn't make a lot of sense for searching the packet bytes.
            // Should we search with the PCRE2_NOTEMPTY option?
            //TODO: Fix cast.
            /* Save position and length for highlighting the field. */
            cf->search_pos = (uint32_t)(result_pos[0]);
            cf->search_len = (uint32_t)(result_pos[1] - result_pos[0]);
            result = MR_MATCHED;
        }
    }
    return result;
}

static match_result
match_regex_reverse(capture_file *cf, frame_data *fdata,
        wtap_rec *rec, Buffer *buf, void *criterion _U_)
{
    match_result  result = MR_NOTMATCHED;
    size_t result_pos[2] = {0, 0};

    /* Load the frame's data. */
    if (!cf_read_record(cf, fdata, rec, buf)) {
        /* Attempt to get the packet failed. */
        return MR_ERROR;
    }

    size_t offset = fdata->cap_len - 1;
    if (cf->search_pos) {
        /* we want to start searching one byte before the previous match */
        offset = cf->search_pos - 1;
    }
    for (; offset > 0; offset--) {
        if (ws_regex_matches_pos(cf->regex,
                                    (const char *)ws_buffer_start_ptr(buf),
                                    fdata->cap_len, offset,
                                    result_pos)) {
            //TODO: A chosen regex can match the empty string (zero length)
            // which doesn't make a lot of sense for searching the packet bytes.
            // Should we search with the PCRE2_NOTEMPTY option?
            //TODO: Fix cast.
            /* Save position and length for highlighting the field. */
            cf->search_pos = (uint32_t)(result_pos[0]);
            cf->search_len = (uint32_t)(result_pos[1] - result_pos[0]);
            result = MR_MATCHED;
            break;
        }
    }
    return result;
}

bool
cf_find_packet_dfilter(capture_file *cf, dfilter_t *sfcode,
        search_direction dir)
{
    return find_packet(cf, match_dfilter, sfcode, dir);
}

bool
cf_find_packet_dfilter_string(capture_file *cf, const char *filter,
        search_direction dir)
{
    dfilter_t *sfcode;
    bool       result;

    if (!dfilter_compile(filter, &sfcode, NULL)) {
        /*
         * XXX - this shouldn't happen, as the filter string is machine
         * generated
         */
        return false;
    }
    if (sfcode == NULL) {
        /*
         * XXX - this shouldn't happen, as the filter string is machine
         * generated.
         */
        return false;
    }
    result = find_packet(cf, match_dfilter, sfcode, dir);
    dfilter_free(sfcode);
    return result;
}

static match_result
match_dfilter(capture_file *cf, frame_data *fdata,
        wtap_rec *rec, Buffer *buf, void *criterion)
{
    dfilter_t      *sfcode = (dfilter_t *)criterion;
    epan_dissect_t  edt;
    match_result    result;

    /* Load the frame's data. */
    if (!cf_read_record(cf, fdata, rec, buf)) {
        /* Attempt to get the packet failed. */
        return MR_ERROR;
    }

    epan_dissect_init(&edt, cf->epan, true, false);
    epan_dissect_prime_with_dfilter(&edt, sfcode);
    epan_dissect_run(&edt, cf->cd_t, rec,
            frame_tvbuff_new_buffer(&cf->provider, fdata, buf),
            fdata, NULL);
    result = dfilter_apply_edt(sfcode, &edt) ? MR_MATCHED : MR_NOTMATCHED;
    epan_dissect_cleanup(&edt);
    return result;
}


/**
 * To ease upgrading to newer versions of wireshark (which would basically
 * involve replacing copied functions with the newer versions), an overarching
 * theme is to minimize the number of patched/custom functions.
 * 
 * The disadvantages to this are:
 *   - unintuitive side effects. eg, when passing capture_file *cf, various 
 *     fields will be read and written
 *   - use of global variables to store additional state that is required
 *     NOT thread-safe
 * 
 * Find globals and modified/new functions below
 */

// this handles the state
static capture_file *active_capture_file;
static const uint8_t *filter_data;

void wg_set_globals_for_find(capture_file *cf, uint8_t *const filtered_frames) {
    active_capture_file = cf;
    filter_data = filtered_frames;
}

// ui functions stubbed
bool packet_list_select_finfo(field_info *fi) {
    if (active_capture_file == NULL) return false;
    // TODO:RECHECK THIS
    active_capture_file->finfo_selected = fi;
    return true;
}

bool packet_list_select_row_from_data(frame_data *fdata_needle) {
    if (active_capture_file == NULL) return false;
    if (fdata_needle == NULL) return false;
    active_capture_file->current_frame = fdata_needle;
    return true;
}

// Rewritten version of the original find_packet.
// Removes ui stuff like the progress bar
static bool
find_packet(capture_file *cf, ws_match_function match_function,
        void *criterion, search_direction dir)
{
    uint32_t     framenum;
    uint32_t     start_framenum;
    frame_data  *found_fdata = NULL;
    frame_data  *fdata;
    wtap_rec     rec;
    Buffer       buf;
    match_result result;

    wtap_rec_init(&rec);
    ws_buffer_init(&buf, 1514);

    start_framenum = cf->current_frame == NULL ? 0 : cf->current_frame->num;
    framenum = start_framenum;

    for (;;) {
        /* Go past the current frame. */
        if (dir == SD_BACKWARD) {
            /* Go on to the previous frame. */
            if (framenum <= 1)
                framenum = cf->count;
            else
                framenum--;
        } else {
            /* Go on to the next frame. */
            if (framenum == cf->count) 
                framenum = 1;
            else
                framenum++;
        }

        fdata = frame_data_sequence_find(cf->provider.frames, framenum);

        /* Is this packet in the display? */
        if (fdata && (!filter_data || (filter_data[framenum / 8] & (1 << (framenum % 8))))) {
            /* Yes.  Does it match the search criterion? */
            result = (*match_function)(cf, fdata, &rec, &buf, criterion);
            if (result == MR_ERROR) {
                /* Error; our caller has reported the error */
                break;
            } else if (result == MR_MATCHED) {
                /* Yes.  Go to the new frame. */
                found_fdata = fdata;
                break;
            }
            wtap_rec_reset(&rec);
        }

        if ((start_framenum == framenum) || 
            (start_framenum == 0 && ((dir == SD_BACKWARD && framenum == 1) || (dir == SD_FORWARD && framenum == cf->count)))
        ) {
            /* We're back to the frame we were on originally, and that frame
               doesn't match the search filter.  The search failed. */
            break;
        }
    }

    if (found_fdata != NULL) {
        /* We found a frame that's displayed and that matches. */
        cf->current_frame = found_fdata;

        // this is a hack because match_protocol_tree doesn't actually return
        // the found field info (ugh)
        if (match_function == match_protocol_tree)
            cf->finfo_selected = ((match_data*)criterion)->finfo;
    }

    wtap_rec_cleanup(&rec);
    ws_buffer_free(&buf);
    return found_fdata != NULL;
}

// this is cf_read_record_no_alert, renamed to cf_read_record
bool
cf_read_record(capture_file *cf, const frame_data *fdata,
        wtap_rec *rec, Buffer *buf)
{
    int    err;
    char *err_info;

    if (!wtap_seek_read(cf->provider.wth, fdata->file_off, rec, buf, &err, &err_info)) {
        g_free(err_info);
        return false;
    }
    return true;
}
