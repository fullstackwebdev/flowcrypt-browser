/* Business Source License 1.0 © 2016-2017 FlowCrypt Limited. Use limitations apply. Contact human@flowcrypt.com */

'use strict';

(function ( /* ALL TOOLS */ ) {

  // openpgp.initWorker({path: 'openpgp.worker.min.js'});

  var tool = window.tool = {
    str: {
      parse_email: str_parse_email,
      pretty_print: str_pretty_print,
      html_as_text: str_html_as_text,
      normalize_spaces: str_normalize_spaces,
      number_format: str_number_format,
      is_email_valid: str_is_email_valid,
      month_name: str_month_name,
      random: str_random,
      html_attribute_encode: str_html_attribute_encode,
      html_attribute_decode: str_html_attribute_decode,
      html_escape: str_html_escape,
      html_unescape: str_html_unescape,
      as_safe_html: str_untrusted_text_as_sanitized_html,
      base64url_encode: str_base64url_encode,
      base64url_decode: str_base64url_decode,
      from_uint8: str_from_uint8,
      to_uint8: str_to_uint8,
      from_equal_sign_notation_as_utf: str_from_equal_sign_notation_as_utf,
      uint8_as_utf: str_uint8_as_utf,
      to_hex: str_to_hex,
      from_hex: str_from_hex,
      extract_cryptup_attachments: str_extract_cryptup_attachments,
      extract_cryptup_reply_token: str_extract_cryptup_reply_token,
      strip_cryptup_reply_token: str_strip_cryptup_reply_token,
      strip_public_keys: str_strip_public_keys,
      int_to_hex: str_int_to_hex,
      message_difference: str_message_difference,
      capitalize: str_capitalize,
    },
    env: {
      browser: env_browser,
      runtime_id: env_extension_runtime_id,
      is_background_script: env_is_background_script,
      is_extension: env_is_extension,
      url_params: env_url_params,
      url_create: env_url_create,
      key_codes: env_key_codes,
      set_up_require: env_set_up_require,
      increment: env_increment,
      webmails: env_webmails,
      callback_placeholder: '!@#$%^&*():callback_placeholder_for_background_page',
    },
    arr: {
      unique: arr_unique,
      from_dome_node_list: arr_from_dome_node_list,
      without_key: arr_without_key,
      without_value: arr_without_value,
      select: arr_select,
      contains: arr_contains,
      sum: arr_sum,
      average: arr_average,
      zeroes: arr_zeroes,
      is: arr_is,
    },
    obj: {
      map: obj_map,
      key_by_value: obj_key_by_value,
    },
    int: {
      random: int_random,
    },
    time: {
      wait: time_wait,
      get_future_timestamp_in_months: time_get_future_timestamp_in_months,
      hours: time_hours,
      expiration_format: time_expiration_format,
      to_utc_timestamp: time_to_utc_timestamp,
    },
    file: {
      download_as_uint8: file_download_as_uint8,
      save_to_downloads: file_save_to_downloads,
      attachment: file_attachment,
      pgp_name_patterns: file_pgp_name_patterns,
      keyinfo_as_pubkey_attachment: file_keyinfo_as_pubkey_attachment,
      treat_as: file_treat_as,
    },
    mime: {
      process: mime_process,
      headers_to_from: mime_headers_to_from,
      reply_headers: mime_reply_headers,
      resembles_message: mime_resembles_message,
      format_content_to_display: mime_format_content_to_display, // todo - should be refactored into two
      decode: mime_decode,
      encode: mime_encode,
      signed: mime_parse_message_with_detached_signature,
    },
    ui: {
      spinner: ui_spinner,
      passphrase_toggle: ui_passphrase_toggle,
      enter: ui_enter,
      build_jquery_selectors: ui_build_jquery_selectors,
      scroll: ui_scroll,
      event: {
        stop: ui_event_stop,
        protect: ui_event_stop_propagation_to_parent_frame,
        double: ui_event_double,
        parallel: ui_event_parallel,
        spree: ui_event_spree,
        prevent: ui_event_prevent,
        release: ui_event_release, // todo - I may have forgot to use this somewhere, used only parallel() - if that's how it works
      },
    },
    browser: {
      message: {
        send: browser_message_send,
        tab_id: browser_message_tab_id,
        listen: browser_message_listen,
        listen_background: browser_message_listen_background,
      },
    },
    diagnose: {
      message_pubkeys: diagnose_message_pubkeys,
      keyserver_pubkeys: diagnose_keyserver_pubkeys,
    },
    crypto: {
      armor: {
        strip: crypto_armor_strip,
        clip: crypto_armor_clip,
        headers: crypto_armor_headers,
        detect_blocks: crypto_armor_detect_blocks,
        replace_blocks: crypto_armor_replace_blocks,
        normalize: crypto_armor_normalize,
      },
      hash: {
        sha1: crypto_hash_sha1,
        double_sha1_upper: crypto_hash_double_sha1_upper,
        sha256: crypto_hash_sha256,
        challenge_answer: crypto_hash_challenge_answer,
      },
      key: {
        create: crypto_key_create,
        read: crypto_key_read,
        decrypt: crypto_key_decrypt,
        expired_for_encryption: crypto_key_expired_for_encryption,
        normalize: crypto_key_normalize,
        fingerprint: crypto_key_fingerprint,
        longid: crypto_key_longid,
        test: crypto_key_test,
        usable: crypto_key_usable,
      },
      message: {
        sign: crypto_message_sign,
        verify: crypto_message_verify,
        verify_detached: crypto_message_verify_detached,
        decrypt: crypto_message_decrypt,
        encrypt: crypto_message_encrypt,
      },
      password: {
        estimate_strength: crypto_password_estimate_strength,
        weak_words: crypto_password_weak_words,
      }
    },
    api: {
    //   auth: {
    //     window: api_auth_window,
    //     parse_id_token: api_auth_parse_id_token,
    //   },
    //   error: {
    //     network: 'API_ERROR_NETWORK',
    //   },
    //   google: {
    //     user_info: api_google_user_info,
    //     auth: api_google_auth,
    //     auth_popup: google_auth_window_show_and_respond_to_auth_request,
    //   },
    //   common: {
    //     message: api_common_email_message_object,
    //     reply_correspondents: api_common_reply_correspondents,
    //   },
      gmail: {
    //     query: {
    //       or: api_gmail_query_or,
    //       backups: api_gmail_query_backups,
    //     },
        scope: api_gmail_scope,
        has_scope: api_gmail_has_scope,
    //     thread_get: api_gmail_thread_get,
    //     draft_create: api_gmail_draft_create,
    //     draft_delete: api_gmail_draft_delete,
    //     draft_update: api_gmail_draft_update,
    //     draft_get: api_gmail_draft_get,
    //     draft_send: api_gmail_draft_send, // todo - not used yet, and should be
    //     message_send: api_gmail_message_send,
    //     message_list: api_gmail_message_list,
    //     message_get: api_gmail_message_get,
    //     attachment_get: api_gmail_message_attachment_get,
    //     find_header: api_gmail_find_header,
    //     find_attachments: api_gmail_find_attachments,
    //     find_bodies: api_gmail_find_bodies,
    //     fetch_attachments: api_gmail_fetch_attachments,
    //     search_contacts: api_gmail_search_contacts,
    //     extract_armored_block: gmail_api_extract_armored_block,
    //     fetch_messages_based_on_query_and_extract_first_available_header: api_gmail_fetch_messages_based_on_query_and_extract_first_available_header,
    //     fetch_key_backups: api_gmail_fetch_key_backups,
      },
    //   attester: {
    //     lookup_email: api_attester_lookup_email,
    //     initial_legacy_submit: api_attester_initial_legacy_submit,
    //     initial_confirm: api_attester_initial_confirm,
    //     replace_request: api_attester_replace_request,
    //     replace_confirm: api_attester_replace_confirm,
    //     test_welcome: api_attester_test_welcome,
    //     packet: {
    //       create_sign: api_attester_packet_create_sign,
    //       parse: api_attester_packet_parse,
    //     },
    //   },
    //   cryptup: {
    //     auth_error: api_cryptup_auth_error,
    //     url: api_cryptup_url,
    //     help_feedback: api_cryptup_help_feedback,
    //     help_uninstall: api_cryptup_help_uninstall,
    //     account_login: api_cryptup_account_login,
    //     account_check: api_cryptup_account_check,
    //     account_check_sync: api_cryptup_account_check_sync,
    //     account_update: api_cryptup_account_update,
    //     account_subscribe: api_cryptup_account_subscribe,
    //     message_presign_files: api_cryptup_message_presign_files,
    //     message_confirm_files: api_cryptup_message_confirm_files,
    //     message_upload: api_cryptup_message_upload,  // todo - DEPRECATE THIS. Send as JSON to message/store
    //     message_token: api_cryptup_message_token,
    //     message_expiration: api_cryptup_message_expiration,
    //     message_reply: api_cryptup_message_reply,
    //     message_contact: api_cryptup_message_contact,
    //     link_message: api_cryptup_link_message,
    //     link_me: api_cryptup_link_me,
    //   },
    //   aws: {
    //     s3_upload: api_aws_s3_upload, // ([{base_url, fields, attachment}, ...], cb)
    //   }
    },
    value: function(v) {
      return {
        in: function(array_or_str) { return arr_contains(array_or_str, v); } // tool.value(v).in(array_or_string)
      };
    },
    e: function(name, attrs) {
      return $('<' + name + ' />', attrs)[0].outerHTML;
    },
    each: function(iterable, looper) {
      for (var k in iterable) {
        if(iterable.hasOwnProperty(k)){
          if(looper(k, iterable[k]) === false) {
            break;
          }
        }
      }
    },
    enums: {
      recovery_email_subjects: ['Your FlowCrypt Backup', 'Your CryptUp Backup', 'All you need to know about CryptUP (contains a backup)', 'CryptUP Account Backup'],
    },
  };

  var openpgp = window.openpgp;
  var storage = window.flowcrypt_storage;
  if(typeof exports === 'object') {
    exports.tool = tool;
    openpgp = require('openpgp');
    storage = require('js/storage').legacy;
  }

  /* tool.str */

  function str_parse_email(email_string) {
    if(tool.value('<').in(email_string) && tool.value('>').in(email_string)) {
      return {
        email: email_string.substr(email_string.indexOf('<') + 1, email_string.indexOf('>') - email_string.indexOf('<') - 1).replace(/["']/g, '').trim().toLowerCase(),
        name: email_string.substr(0, email_string.indexOf('<')).replace(/["']/g, '').trim(),
        full: email_string,
      };
    }
    return {
      email: email_string.replace(/["']/g, '').trim().toLowerCase(),
      name: null,
      full: email_string,
    };
  }

  function str_pretty_print(obj) {
    if(typeof obj === 'object') {
      return JSON.stringify(obj, null, 2).replace(/ /g, '&nbsp;').replace(/\n/g, '<br>');
    } else {
      return String(obj);
    }
  }

  function str_html_as_text(html_text, callback) {
    // extracts innerText from a html text in a safe way without executing any contained js
    // firefox does not preserve line breaks of iframe.contentDocument.body.innerText due to a bug - have to guess the newlines with regexes
    // this is still safe because Firefox does strip all other tags
    if(env_browser().name === 'firefox') {
      var br = 'CU_BR_' + str_random(5);
      var block_start = 'CU_BS_' + str_random(5);
      var block_end = 'CU_BE_' + str_random(5);
      html_text = html_text.replace(/<br[^>]*>/gi, br);
      html_text = html_text.replace(/<\/(p|h1|h2|h3|h4|h5|h6|ol|ul|pre|address|blockquote|dl|div|fieldset|form|hr|table)[^>]*>/gi, block_end);
      html_text = html_text.replace(/<(p|h1|h2|h3|h4|h5|h6|ol|ul|pre|address|blockquote|dl|div|fieldset|form|hr|table)[^>]*>/gi, block_start);
    }
    var e = document.createElement('iframe');
    e.sandbox = 'allow-same-origin';
    e.srcdoc = html_text;
    e.style['display'] = 'none';
    e.onload = function() {
      var text = e.contentDocument.body.innerText;
      if(env_browser().name === 'firefox') {
        text = text.replace(RegExp('(' + block_start + ')+', 'g'), block_start).replace(RegExp('(' + block_end + ')+', 'g'), block_end);
        text = text.split(block_end + block_start).join(br).split(br + block_end).join(br);
        text = text.split(br).join('\n').split(block_start).filter(function(v){return !!v}).join('\n').split(block_end).filter(function(v){return !!v}).join('\n');
        text = text.replace(/\n{2,}/g, '\n\n');
      }
      callback(text.trim());
      document.body.removeChild(e);
    };
    document.body.appendChild(e);
  }

  function str_normalize_spaces(str) {
    return str.replace(RegExp(String.fromCharCode(160), 'g'), String.fromCharCode(32)).replace(/\n /g, '\n');
  }

  function str_number_format(nStr) { // http://stackoverflow.com/questions/3753483/javascript-thousand-separator-string-format
    nStr += '';
    var x = nStr.split('.');
    var x1 = x[0];
    var x2 = x.length > 1 ? '.' + x[1] : '';
    var rgx = /(\d+)(\d{3})/;
    while(rgx.test(x1)) {
      x1 = x1.replace(rgx, '$1' + ',' + '$2');
    }
    return x1 + x2;
  }

  function str_is_email_valid(email) {
    return /[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?/i.test(email);
  }

  function str_month_name(month_index) {
    return ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'][month_index];
  }

  function str_random(length) {
    var id = '';
    var possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
    for(var i = 0; i < (length || 5); i++) {
      id += possible.charAt(Math.floor(Math.random() * possible.length));
    }
    return id;
  }

  function str_untrusted_text_as_sanitized_html(text_or_html, callback) {
    var nl = '_cryptup_newline_placeholder_' + str_random(3) + '_';
    str_html_as_text(text_or_html.replace(/<br ?\/?> ?\r?\n/gm, nl).replace(/\r?\n/gm, nl).replace(/</g, '&lt;').replace(RegExp(nl, 'g'), '<br>'), function(plain) {
      callback(plain.trim().replace(/</g, '&lt;').replace(/\n/g, '<br>').replace(/ {2,}/g, function (spaces) {
        return '&nbsp;'.repeat(spaces.length);
      }));
    });
  }

  function str_html_escape(str) { // http://stackoverflow.com/questions/1219860/html-encoding-lost-when-attribute-read-from-input-field
    return str.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/'/g, '&#39;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/\//g, '&#x2F;');
  }

  function str_html_unescape(str){
    return str.replace(/&#x2F;/g, '/').replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
  }

  function str_html_attribute_encode(values) {
    return str_base64url_encode(JSON.stringify(values));
  }

  function str_html_attribute_decode(encoded) {
    return JSON.parse(str_base64url_decode(encoded));
  }

  function str_base64url_encode(str) {
    if(typeof str === 'undefined') {
      return str;
    }
    return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function str_base64url_decode(str) {
    if(typeof str === 'undefined') {
      return str;
    }
    return atob(str.replace(/-/g, '+').replace(/_/g, '/'));
  }

  function str_from_uint8(u8a) {
    var CHUNK_SZ = 0x8000;
    var c = [];
    for(var i = 0; i < u8a.length; i += CHUNK_SZ) {
      c.push(String.fromCharCode.apply(null, u8a.subarray(i, i + CHUNK_SZ)));
    }
    return c.join('');
  }

  function str_to_uint8(raw) {
    var rawLength = raw.length;
    var uint8 = new Uint8Array(new ArrayBuffer(rawLength));
    for(var i = 0; i < rawLength; i++) {
      uint8[i] = raw.charCodeAt(i);
    }
    return uint8;
  }

  function str_from_equal_sign_notation_as_utf(str) {
    return str.replace(/(=[A-F0-9]{2})+/g, function (equal_sign_utf_part) {
      return str_uint8_as_utf(equal_sign_utf_part.replace(/^=/, '').split('=').map(function (two_hex_digits) { return parseInt(two_hex_digits, 16); }));
    });
  }

  function str_uint8_as_utf(a) { //tom
    var length = a.length;
    var bytes_left_in_char = 0;
    var utf8_string = '';
    var binary_char = '';
    for(var i = 0; i < length; i++) {
      if(a[i] < 128) {
        if(bytes_left_in_char) { // utf-8 continuation byte missing, assuming the last character was an 8-bit ASCII character
          utf8_string += String.fromCharCode(a[i-1]);
        }
        bytes_left_in_char = 0;
        binary_char = '';
        utf8_string += String.fromCharCode(a[i]);
      } else {
        if(!bytes_left_in_char) { // beginning of new multi-byte character
          if(a[i] >= 128 && a[i] < 192) { //10xx xxxx
            utf8_string += String.fromCharCode(a[i]); // extended 8-bit ASCII compatibility, european ASCII characters
          } else if(a[i] >= 192 && a[i] < 224) { //110x xxxx
            bytes_left_in_char = 1;
            binary_char = a[i].toString(2).substr(3);
          } else if(a[i] >= 224 && a[i] < 240) { //1110 xxxx
            bytes_left_in_char = 2;
            binary_char = a[i].toString(2).substr(4);
          } else if(a[i] >= 240 && a[i] < 248) { //1111 0xxx
            bytes_left_in_char = 3;
            binary_char = a[i].toString(2).substr(5);
          } else if(a[i] >= 248 && a[i] < 252) { //1111 10xx
            bytes_left_in_char = 4;
            binary_char = a[i].toString(2).substr(6);
          } else if(a[i] >= 252 && a[i] < 254) { //1111 110x
            bytes_left_in_char = 5;
            binary_char = a[i].toString(2).substr(7);
          } else {
            console.log('str_uint8_as_utf: invalid utf-8 character beginning byte: ' + a[i]);
          }
        } else { // continuation of a multi-byte character
          binary_char += a[i].toString(2).substr(2);
          bytes_left_in_char--;
        }
        if(binary_char && !bytes_left_in_char) {
          utf8_string += String.fromCharCode(parseInt(binary_char, 2));
          binary_char = '';
        }
      }
    }
    return utf8_string;
  }

  function str_to_hex(s) { // http://phpjs.org/functions/bin2hex/, Kevin van Zonneveld (http://kevin.vanzonneveld.net), Onno Marsman, Linuxworld, ntoniazzi
    var i, l, o = '', n;
    s += '';
    for(i = 0, l = s.length; i < l; i++) {
      n = s.charCodeAt(i).toString(16);
      o += n.length < 2 ? '0' + n : n;
    }
    return o;
  }

  function str_from_hex(hex) {
    var str = '';
    for (var i = 0; i < hex.length; i += 2) {
      var v = parseInt(hex.substr(i, 2), 16);
      if (v) str += String.fromCharCode(v);
    }
    return str;
  }

  function str_int_to_hex(int_as_string) { // http://stackoverflow.com/questions/18626844/convert-a-large-integer-to-a-hex-string-in-javascript (Collin Anderson)
    var dec = int_as_string.toString().split(''), sum = [], hex = [], i, s;
    while(dec.length){
      s = 1 * dec.shift();
      for(i = 0; s || i < sum.length; i++){
        s += (sum[i] || 0) * 10;
        sum[i] = s % 16;
        s = (s - sum[i]) / 16
      }
    }
    while(sum.length){
      hex.push(sum.pop().toString(16))
    }
    return hex.join('')
  }

  function str_strip_cryptup_reply_token(decrypted_content) {
    return decrypted_content.replace(/<div[^>]+class="cryptup_reply"[^>]+><\/div>/, '');
  }

  function str_strip_public_keys(decrypted_content, found_public_keys) {
    tool.each(crypto_armor_detect_blocks(decrypted_content), function(i, block) {
      if(block.type === 'public_key') {
        found_public_keys.push(block.content);
        decrypted_content = decrypted_content.replace(block.content, '');
      }
    });
    return decrypted_content;
  }

  function str_extract_cryptup_reply_token(decrypted_content) {
    var cryptup_token_element = $(tool.e('div', {html: decrypted_content})).find('.cryptup_reply');
    if(cryptup_token_element.length && cryptup_token_element.attr('cryptup-data')) {
      return str_html_attribute_decode(cryptup_token_element.attr('cryptup-data'));
    }
  }

  function str_extract_cryptup_attachments(decrypted_content, cryptup_attachments) {
    if(tool.value('cryptup_file').in(decrypted_content)) {
      decrypted_content = decrypted_content.replace(/<a[^>]+class="cryptup_file"[^>]+>[^<]+<\/a>/g, function (found_link) {
        var element = $(found_link);
        var attachment_data = str_html_attribute_decode(element.attr('cryptup-data'));
        cryptup_attachments.push(file_attachment(attachment_data.name, attachment_data.type, null, attachment_data.size, element.attr('href')));
        return '';
      });
    }
    return decrypted_content;
  }

  function message_to_comparable_format(encrypted_message) {
    return encrypted_message.substr(0, 5000).replace(/[^a-zA-Z0-9]+/g, ' ').trim().substr(0, 4000).trim().split(' ').reduce(function(arr, word) {
      if(word.length > 20) {
        arr.push(word);
      }
      return arr;
    }, []);
  }

  function str_message_difference(msg_1, msg_2) {
    var msg = [message_to_comparable_format(msg_1), message_to_comparable_format(msg_2)];
    var difference = [0, 0];
    tool.each(msg[0], function(i, word) {
      difference[0] += !tool.value(word).in(msg[1]);
    });
    if(!difference[0]) {
      return 0;
    }
    tool.each(msg[1], function(i, word) {
      difference[1] += !tool.value(word).in(msg[0]);
    });
    return Math.min(difference[0], difference[1]);
  }

  function str_capitalize(string) {
    return string.trim().split(' ').map(function(s) {
      return s.charAt(0).toUpperCase() + s.slice(1);
    }).join(' ');
  }

  /* tool.env */

  function env_browser() {  // http://stackoverflow.com/questions/4825498/how-can-i-find-out-which-browser-a-user-is-using
    if (/Firefox[\/\s](\d+\.\d+)/.test(navigator.userAgent)) {
      return {name: 'firefox', v: Number(RegExp.$1)};
    } else if (/MSIE (\d+\.\d+);/.test(navigator.userAgent)) {
      return {name: 'ie', v: Number(RegExp.$1)};
    } else if (/Chrome[\/\s](\d+\.\d+)/.test(navigator.userAgent)) {
      return {name: 'chrome', v: Number(RegExp.$1)};
    } else if (/Opera[\/\s](\d+\.\d+)/.test(navigator.userAgent)) {
      return {name: 'opera', v: Number(RegExp.$1)};
    } else if (/Safari[\/\s](\d+\.\d+)/.test(navigator.userAgent)) {
      return {name: 'safari', v: Number(RegExp.$1)};
    } else {
      return {name: 'unknown', v: null};
    }
  }

  function env_extension_runtime_id(original) {
    if(typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.id) {
      if(original === true) {
        return chrome.runtime.id;
      } else {
        return chrome.runtime.id.replace(/[^a-z0-9]/gi, '');
      }
    }
    return null;
  }

  function env_is_background_script() {
    return window.location && tool.value('_generated_background_page.html').in(window.location.href);
  }

  function env_is_extension() {
    return env_extension_runtime_id() !== null;
  }

  var env_url_param_decode_dict = {
    '___cu_true___': true,
    '___cu_false___': false,
    '___cu_null___': null,
  };

  function env_url_params(expected_keys, string) {
    var raw_url_data = (string || window.location.search.replace('?', '')).split('&');
    var url_data = {};
    tool.each(raw_url_data, function (i, pair_string) {
      var pair = pair_string.split('=');
      if(tool.value(pair[0]).in(expected_keys)) {
        url_data[pair[0]] = typeof env_url_param_decode_dict[pair[1]] !== 'undefined' ? env_url_param_decode_dict[pair[1]] : decodeURIComponent(pair[1]);
      }
    });
    return url_data;
  }

  function env_url_create(link, params) {
    tool.each(params, function(key, value) {
      if(typeof value !== 'undefined') {
        var transformed = obj_key_by_value(env_url_param_decode_dict, value);
        link += (!tool.value('?').in(link) ? '?' : '&') + key + '=' + encodeURIComponent(typeof transformed !== 'undefined' ? transformed : value);
      }
    });
    return link;
  }

  function env_key_codes() {
    return { a: 97, r: 114, A: 65, R: 82, f: 102, F: 70, backspace: 8, tab: 9, enter: 13, comma: 188, };
  }

  function env_set_up_require() {
    require.config({
      baseUrl: '/lib',
      paths: {
        'emailjs-addressparser': './emailjs/emailjs-addressparser',
        'emailjs-mime-builder': './emailjs/emailjs-mime-builder',
        'emailjs-mime-codec': './emailjs/emailjs-mime-codec',
        'emailjs-mime-parser': './emailjs/emailjs-mime-parser',
        'emailjs-mime-types': './emailjs/emailjs-mime-types',
        'emailjs-stringencoding': './emailjs/emailjs-stringencoding',
        'punycode': './emailjs/punycode',
      }
    });
  }

  var known_metric_types = {
    'compose': 'c',
    'view': 'w',
    'reply': 'r',
    'attach': 'a',
    'download': 'd',
    'setup': 's',
    'error': 'e',
    'upgrade_notify_attach_nonpgp': 'unan',
    'upgrade_notify_attach_size': 'unas',
    'upgrade_dialog_show': 'uds',
    'upgrade_dialog_register_click': 'udrc',
    'upgrade_verification_embedded_show': 'uves',
    'upgrade_done': 'ud',
  };

  function env_increment(type, callback) {
    if(typeof storage.get === 'function' && typeof chrome === 'object') {
      if(!known_metric_types[type]) {
        catcher.report('Unknown metric type "' + type + '"');
      }
      storage.get(null, ['metrics'], function (s) {
        var metrics_k = known_metric_types[type];
        if(!s.metrics) {
          s.metrics = {};
        }
        if(!s.metrics[metrics_k]) {
          s.metrics[metrics_k] = 1;
        } else {
          s.metrics[metrics_k] += 1;
        }
        storage.set(null, { metrics: s.metrics }, function () {
          browser_message_send(null, 'update_uninstall_url', null, callback);
        });
      });
    } else if (typeof callback === 'function') {
      callback();
    }
  }

  function env_webmails(cb) {
    cb(['gmail', 'inbox']);
  }

  /* tool.arr */

  function arr_unique(array) {
    var unique = [];
    tool.each(array, function (i, v) {
      if(!tool.value(v).in(unique)) {
        unique.push(v);
      }
    });
    return unique;
  }

  function arr_from_dome_node_list(obj) { // http://stackoverflow.com/questions/2735067/how-to-convert-a-dom-node-list-to-an-array-in-javascript
    var array = [];
    // iterate backwards ensuring that length is an UInt32
    for(var i = obj.length >>> 0; i--;) {
      array[i] = obj[i];
    }
    return array;
  }

  function arr_without_key(array, i) {
    return array.splice(0, i).concat(array.splice(i + 1, array.length));
  }

  function arr_without_value(array, without_value) {
    var result = [];
    tool.each(array, function (i, value) {
      if(value !== without_value) {
        result.push(value);
      }
    });
    return result;
  }

  function arr_select(array, mapped_object_key) {
    return array.map(function(obj) {
      return obj[mapped_object_key];
    });
  }

  function arr_contains(arr, value) {
    return arr && typeof arr.indexOf === 'function' && arr.indexOf(value) !== -1;
  }

  function arr_zeroes(length) {
    return new Array(length).map(function() { return 0 });
  }

  function arr_is(object_to_identify) { // http://stackoverflow.com/questions/4775722/check-if-object-is-array
    return Object.prototype.toString.call(object_to_identify) === '[object Array]';
  }

  function arr_sum(arr) {
    return arr.reduce(function(a, b) { return a + b; }, 0);
  }

  function arr_average(arr) {
    return arr_sum(arr) / arr.length;
  }

  /* tool.obj */

  function obj_map(original_obj, f) {
    var mapped = {};
    tool.each(original_obj, function(k, v) {
      mapped[k] = f(v);
    });
    return mapped;
  }

  function obj_key_by_value(obj, v) {
    for(var k in obj) {
      if(obj.hasOwnProperty(k) && obj[k] === v) {
        return k;
      }
    }
  }

  /* tool.int */

  function int_random(min_value, max_value) {
    return min_value + Math.round(Math.random() * (max_value - min_value))
  }

  /* tool.time */

  function time_wait(until_this_function_evaluates_true) {
    return catcher.Promise(function (success, error) {
      var interval = setInterval(function () {
        var result = until_this_function_evaluates_true();
        if(result === true) {
          clearInterval(interval);
          if(success) {
            success();
          }
        } else if(result === false) {
          clearInterval(interval);
          if(error) {
            error();
          }
        }
      }, 50);
    });
  }

  function time_get_future_timestamp_in_months(months_to_add) {
    return new Date().getTime() + 1000 * 3600 * 24 * 30 * months_to_add;
  }

  function time_hours(h) {
    return h * 1000 * 60 * 60; // hours in miliseconds
  }

  function time_expiration_format(date) {
    return str_html_escape(date.substr(0, 10));
  }

  function time_to_utc_timestamp(datetime_string, as_string) {
    if(!as_string) {
      return Date.parse(datetime_string);
    } else {
      return String(Date.parse(datetime_string));
    }
  }

  /* tools.file */

  function file_download_as_uint8(url, progress, callback) {
    var request = new XMLHttpRequest();
    request.open('GET', url, true);
    request.responseType = 'arraybuffer';
    if(typeof progress === 'function') {
      request.onprogress = function (evt) {
        progress(evt.lengthComputable ? Math.floor((evt.loaded / evt.total) * 100) : null, evt.loaded, evt.total);
      };
    }
    request.onerror = function (e) {
      callback(false, e);
    };
    request.onload = function (e) {
      callback(true, new Uint8Array(request.response));
    };
    request.send();
  }

  function file_save_to_downloads(name, type, content, render_in) {
    var blob = new Blob([content], { type: type });
    if(window.navigator && window.navigator.msSaveOrOpenBlob) {
      window.navigator.msSaveBlob(blob, name);
    } else {
      var a = window.document.createElement('a');
      a.href = window.URL.createObjectURL(blob);
      a.download = name;
      if(render_in) {
        a.textContent = 'DECRYPTED FILE';
        a.style = 'font-size: 16px; font-weight: bold;';
        render_in.html('<div style="font-size: 16px;padding: 17px 0;">File is ready.<br>Right-click the link and select <b>Save Link As</b></div>');
        render_in.append(a);
        render_in.find('a').click(function (e) {
          alert('Please use right-click and select Save Link As');
          e.preventDefault();
          e.stopPropagation();
          return false;
        });
      } else {
        if(typeof a.click === 'function') {
          a.click();
        } else { // safari
          var e = document.createEvent('MouseEvents');
          e.initMouseEvent('click', true, true, window);
          a.dispatchEvent(e);
        }
        if(env_browser().name === 'firefox') {
          try {
            document.body.removeChild(a);
          } catch(err) {
            if(err.message !== 'Node was not found') {
              throw err;
            }
          }
        }
        window.URL.revokeObjectURL(a.href);
      }
    }
  }

  function file_attachment(name, type, content, size, url) { // todo - refactor as (content, name, type, LENGTH, url), making all but content voluntary
    return { // todo: accept any type of content, then add getters for content(str, uint8, blob) and fetch(), also size('formatted')
      name: name || '',
      type: type || 'application/octet-stream',
      content: content,
      size: size || content.length,
      url: url || null,
    };
  }

  function file_pgp_name_patterns() {
    return ['*.pgp', '*.gpg', '*.asc', 'noname', 'message', 'PGPMIME version identification'];
  }

  function file_keyinfo_as_pubkey_attachment(keyinfo) {
    return file_attachment('0x' + keyinfo.longid + '.asc', 'application/pgp-keys', keyinfo.public);
  }

  function file_treat_as(attachment) {
    if(tool.value(attachment.name).in(['PGPexch.htm.pgp', 'PGPMIME version identification'])) {
      return 'hidden';  // PGPexch.htm.pgp is html alternative of textual body content produced by PGP Desktop and GPG4o
    } else if(attachment.name === 'signature.asc' || attachment.type === 'application/pgp-signature') {
      return  'signature';
    } else if(!attachment.name && !tool.value('image/').in(attachment.type)) { // attachment.name may be '' or undefined - catch either
      return attachment.size < 100 ? 'hidden' : 'message';
    } else if(tool.value(attachment.name).in(['message', 'message.asc', 'encrypted.asc', 'encrypted.eml.pgp'])) {
      return 'message';
    } else if(attachment.name.match(/(\.pgp$)|(\.gpg$)|(\.[a-zA-Z0-9]{3,4}\.asc$)/g)) { // ends with one of .gpg, .pgp, .???.asc, .????.asc
      return 'encrypted';
    } else if(attachment.name.match(/^(0|0x)?[A-F0-9]{8}([A-F0-9]{8})?\.asc$/g)) { // name starts with a key id
      return 'public_key';
    } else if(tool.value('public').in(attachment.name.toLowerCase()) && attachment.name.match(/[A-F0-9]{8}.*\.asc$/g)) { // name contains the word "public", any key id and ends with .asc
      return 'public_key';
    } else if(attachment.name.match(/\.asc$/) && attachment.size < 100000 && !attachment.inline) {
      return 'message';
    } else {
      return 'standard';
    }
  }

  /* tool.mime */

  function mime_node_type(node) {
    if(node.headers['content-type'] && node.headers['content-type'][0]) {
      return node.headers['content-type'][0].value;
    }
  }

  function mime_node_filename(node) {
    if(node.headers['content-disposition'] && node.headers['content-disposition'][0] && node.headers['content-disposition'][0].params && node.headers['content-disposition'][0].params.filename) {
      return node.headers['content-disposition'][0].params.filename;
    }
    if(node.headers['content-type'] && node.headers['content-type'][0] && node.headers['content-type'][0].params && node.headers['content-type'][0].params.name) {
      return node.headers['content-type'][0].params.name;
    }
  }

  function mime_content_node(MimeBuilder, type, content) {
    var node = new MimeBuilder(type).setContent(content);
    if(type === 'text/plain') {
      node.addHeader('Content-Transfer-Encoding', 'quoted-printable'); // gmail likes this
    }
    return node;
  }

  /*
   body: either string (plaintext) or a dict {'text/plain': ..., 'text/html': ...}
   headers: at least {To, From, Subject}
   attachments: [{name: 'some.txt', type: 'text/plain', content: uint8}]
   */
  function mime_encode(body, headers, attachments, mime_message_callback) {
    mime_require('builder', function (MimeBuilder) {
      var root_node = new MimeBuilder('multipart/mixed');
      tool.each(headers, function (key, header) {
        root_node.addHeader(key, header);
      });
      if(typeof body === 'string') {
        body = {'text/plain': body};
      }
      if(Object.keys(body).length === 1) {
        var content_node = mime_content_node(MimeBuilder, Object.keys(body)[0], body[Object.keys(body)[0]]);
      } else {
        var content_node = new MimeBuilder('multipart/alternative');
        tool.each(body, function (type, content) {
          content_node.appendChild(mime_content_node(MimeBuilder, type, content));
        });
      }
      root_node.appendChild(content_node);
      tool.each(attachments || [], function (i, attachment) {
        root_node.appendChild(new MimeBuilder(attachment.type + '; name="' + attachment.name + '"', { filename: attachment.name }).setHeader({
          'Content-Disposition': 'attachment',
          'X-Attachment-Id': 'f_' + tool.str.random(10),
          'Content-Transfer-Encoding': 'base64',
        }).setContent(attachment.content));
      });
      mime_message_callback(root_node.build());
    });
  }

  function mime_headers_to_from(parsed_mime_message) {
    var header_to = [];
    var header_from;
    if(parsed_mime_message.headers.from && parsed_mime_message.headers.from.length && parsed_mime_message.headers.from[0] && parsed_mime_message.headers.from[0].address) {
      header_from = parsed_mime_message.headers.from[0].address;
    }
    if(parsed_mime_message.headers.to && parsed_mime_message.headers.to.length) {
      tool.each(parsed_mime_message.headers.to, function (i, to) {
        if(to.address) {
          header_to.push(to.address);
        }
      });
    }
    return { from: header_from, to: header_to };
  }

  function mime_reply_headers(parsed_mime_message) {
    var message_id = parsed_mime_message.headers['message-id'] || '';
    var references = parsed_mime_message.headers['in-reply-to'] || '';
    return { 'in-reply-to': message_id, 'references': references + ' ' + message_id };
  }

  function mime_resembles_message(message) {
    var m = message.toLowerCase();
    var contentType = m.match(/content-type: +[0-9a-z\-\/]+/);
    if(contentType === null) {
      return false;
    }
    if(m.match(/content-transfer-encoding: +[0-9a-z\-\/]+/) || m.match(/content-disposition: +[0-9a-z\-\/]+/) || m.match(/; boundary=/) || m.match(/; charset=/)) {
      return true;
    }
    return Boolean(contentType.index === 0 && m.match(/boundary=/));
  }

  function mime_format_content_to_display(text, full_mime_message) {
    // todo - this function is very confusing, and should be split into two:
    // ---> format_mime_plaintext_to_display(text, charset)
    // ---> get_charset(full_mime_message)
    if(/<((br)|(div)|p) ?\/?>/.test(text)) {
      return text;
    }
    text = (text || '').replace(/\r?\n/g, '<br>\n');
    if(text && full_mime_message && full_mime_message.match(/^Charset: iso-8859-2/m) !== null) {
      return window.iso88592.decode(text);
    }
    return text;
  }

  function mime_require(group, callback) {
    if(group === 'parser') {
      if(typeof MimeParser !== 'undefined') { // browser
        callback(MimeParser);
      } else if (typeof exports === 'object') { // electron
        callback(require('emailjs-mime-parser'));
      } else { // RequireJS
        tool.env.set_up_require();
        require(['emailjs-mime-parser'], callback);
      }
    } else {
      if(typeof MimeBuilder !== 'undefined') { // browser
        callback(MimeBuilder);
      } else if (typeof exports === 'object') { // electron
        callback(require('emailjs-mime-builder'));
      } else { // RequireJS
        tool.env.set_up_require();
        require(['emailjs-mime-builder'], callback);
      }
    }
  }

  function mime_process(mime_message, callback) {
    mime_decode(mime_message, function (success, decoded) {
      if(typeof decoded.text === 'undefined' && typeof decoded.html !== 'undefined' && typeof $_HOST_html_to_text === 'function') { // android
        decoded.text = $_HOST_html_to_text(decoded.html); // temporary solution
      }
      var blocks = [];
      if(decoded.text) {  // may be undefined or empty
        blocks = blocks.concat(crypto_armor_detect_blocks(decoded.text));
      }
      tool.each(decoded.attachments, function(i, file) {
        var treat_as = file_treat_as(file);
        if(treat_as === 'message') {
          var armored = crypto_armor_clip(file.content);
          if(armored) {
            blocks.push(crypto_armor_block_object('message', armored));
          }
        } else if(treat_as === 'signature') {
          decoded.signature = decoded.signature || file.content;
        } else if(treat_as === 'public_key') {
          blocks = blocks.concat(crypto_armor_detect_blocks(file.content));
        }
      });
      if(decoded.signature) {
        tool.each(blocks, function(i, block) {
          if(block.type === 'text') {
            block.type = 'signed_message';
            block.signature = decoded.signature;
            return false;
          }
        });
      }
      callback({headers: decoded.headers, blocks: blocks});
    });
  }

  function mime_decode(mime_message, callback) {
    var mime_message_contents = {attachments: [], headers: {}, text: undefined, html: undefined, signature: undefined};
    mime_require('parser', function (emailjs_mime_parser) {
      try {
        var parser = new emailjs_mime_parser();
        var parsed = {};
        parser.onheader = function (node) {
          if(!String(node.path.join('.'))) { // root node headers
            tool.each(node.headers, function (name, header) {
              mime_message_contents.headers[name] = header[0].value;
            });
          }
        };
        parser.onbody = function (node, chunk) {
          var path = String(node.path.join('.'));
          if(typeof parsed[path] === 'undefined') {
            parsed[path] = node;
          }
        };
        parser.onend = function () {
          tool.each(parsed, function (path, node) {
            if(mime_node_type(node) === 'application/pgp-signature') {
              mime_message_contents.signature = tool.str.uint8_as_utf(node.content);
            } else if(mime_node_type(node) === 'text/html' && !mime_node_filename(node)) {
              mime_message_contents.html = tool.str.uint8_as_utf(node.content);
            } else if(mime_node_type(node) === 'text/plain' && !mime_node_filename(node)) {
              mime_message_contents.text = tool.str.uint8_as_utf(node.content);
            } else {
              var node_content = tool.str.from_uint8(node.content);
              mime_message_contents.attachments.push(file_attachment(mime_node_filename(node), mime_node_type(node), node_content));
            }
          });
          catcher.try(function () {
            callback(true, mime_message_contents);
          })();
        };
        parser.write(mime_message); //todo - better chunk it for very big messages containing attachments? research
        parser.end();
      } catch(e) {
        catcher.handle_exception(e);
        catcher.try(function () {
          callback(false, mime_message_contents);
        })();
      }
    });
  }

  function mime_parse_message_with_detached_signature(mime_message) {
    /*
     Trying to grab the full signed content that may look like this in its entirety (it's a signed mime message. May also be signed plain text)
     Unfortunately, emailjs-mime-parser was not able to do this, or I wasn't able to use it properly

     --eSmP07Gus5SkSc9vNmF4C0AutMibfplSQ
     Content-Type: multipart/mixed; boundary="XKKJ27hlkua53SDqH7d1IqvElFHJROQA1"
     From: Henry Electrum <henry.electrum@gmail.com>
     To: human@flowcrypt.com
     Message-ID: <abd68ba1-35c3-ee8a-0d60-0319c608d56b@gmail.com>
     Subject: compatibility - simples signed email

     --XKKJ27hlkua53SDqH7d1IqvElFHJROQA1
     Content-Type: text/plain; charset=utf-8
     Content-Transfer-Encoding: quoted-printable

     content

     --XKKJ27hlkua53SDqH7d1IqvElFHJROQA1--
     */
    var signed_header_index = mime_message.substr(0, 100000).toLowerCase().indexOf('content-type: multipart/signed');
    if(signed_header_index !== -1) {
      mime_message = mime_message.substr(signed_header_index);
      var first_boundary_index = mime_message.substr(0, 1000).toLowerCase().indexOf('boundary=');
      if(first_boundary_index) {
        var boundary = mime_message.substr(first_boundary_index, 100);
        boundary = (boundary.match(/boundary="[^"]{1,70}"/gi) || boundary.match(/boundary=[a-z0-9][a-z0-9 ]{0,68}[a-z0-9]/gi) || [])[0];
        if(boundary) {
          boundary = boundary.replace(/^boundary="?|"$/gi, '');
          var boundary_begin = '\r\n--' + boundary + '\r\n';
          var boundary_end = '--' + boundary + '--';
          var end_index = mime_message.indexOf(boundary_end);
          if(end_index !== -1) {
            mime_message = mime_message.substr(0, end_index + boundary_end.length);
            if(mime_message) {
              var result = { full: mime_message, signed: null, signature: null };
              var first_part_start_index = mime_message.indexOf(boundary_begin);
              if(first_part_start_index !== -1) {
                first_part_start_index += boundary_begin.length;
                var first_part_end_index = mime_message.indexOf(boundary_begin, first_part_start_index);
                var second_part_start_index = first_part_end_index + boundary_begin.length;
                var second_part_end_index = mime_message.indexOf(boundary_end, second_part_start_index);
                if(second_part_end_index !== -1) {
                  var first_part = mime_message.substr(first_part_start_index, first_part_end_index - first_part_start_index);
                  var second_part = mime_message.substr(second_part_start_index, second_part_end_index - second_part_start_index);
                  if(first_part.match(/^content-type: application\/pgp-signature/gi) !== null && tool.value('-----BEGIN PGP SIGNATURE-----').in(first_part) && tool.value('-----END PGP SIGNATURE-----').in(first_part)) {
                    result.signature = crypto_armor_clip(first_part);
                    result.signed = second_part;
                  } else {
                    result.signature = crypto_armor_clip(second_part);
                    result.signed = first_part;
                  }
                  return result;
                }
              }
            }
          }
        }
      }
    }
  }

  /* tool.ui */

  function  ui_event_stop_propagation_to_parent_frame() {
    // prevent events that could potentially leak information about sensitive info from bubbling above the frame
    $('body').on('keyup keypress keydown click drag drop dragover dragleave dragend submit', function(e) {
      // don't ask me how come Chrome allows it to bubble cross-domain
      // should be used in embedded frames where the parent cannot be trusted (eg parent is webmail)
      // should be further combined with iframe type=content + sandboxing, but these could potentially be changed by the parent frame
      // so this indeed seems like the only defense
      // happened on only one machine, but could potentially happen to other users as well
      // if you know more than I do about the hows and whys of events bubbling out of iframes on different domains, let me know
      e.stopPropagation();
    });
  }

  var events_fired = {};
  var DOUBLE_MS = 1000;
  var SPREE_MS = 50;
  var SLOW_SPREE_MS = 200;
  var VERY_SLOW_SPREE_MS = 500;

  function ui_event_double() {
    return { name: 'double', id: tool.str.random(10), };
  }

  function ui_event_parallel() {
    return { name: 'parallel', id: tool.str.random(10), };
  }

  function ui_event_spree(type) {
    return { name: (type || '') + 'spree', id: tool.str.random(10), };
  }

  function ui_event_prevent(meta, callback) { //todo: messy + needs refactoring
    return function () {
      if(meta.name === 'spree') {
        clearTimeout(events_fired[meta.id]);
        events_fired[meta.id] = setTimeout(callback, SPREE_MS);
      } else if(meta.name === 'slowspree') {
        clearTimeout(events_fired[meta.id]);
        events_fired[meta.id] = setTimeout(callback, SLOW_SPREE_MS);
      } else if(meta.name === 'veryslowspree') {
        clearTimeout(events_fired[meta.id]);
        events_fired[meta.id] = setTimeout(callback, VERY_SLOW_SPREE_MS);
      } else {
        if(meta.id in events_fired) {
          // if(meta.name === 'parallel') - id was found - means the event handling is still being processed. Do not call back
          if(meta.name === 'double') {
            if(Date.now() - events_fired[meta.id] > DOUBLE_MS) {
              events_fired[meta.id] = Date.now();
              callback(this, meta.id);
            }
          }
        } else {
          events_fired[meta.id] = Date.now();
          callback(this, meta.id);
        }
      }
    };
  }

  function ui_event_release(id) {
    if(id in events_fired) {
      var ms_to_release = DOUBLE_MS + events_fired[id] - Date.now();
      if(ms_to_release > 0) {
        setTimeout(function () {
          delete events_fired[id];
        }, ms_to_release);
      } else {
        delete events_fired[id];
      }
    }
  }

  function ui_event_stop() {
    return function(e) {
      e.preventDefault();
      e.stopPropagation();
      return false;
    };
  }

  function ui_spinner(color, placeholder_class) {
    var path = '/img/svgs/spinner-' + color + '-small.svg';
    var url = typeof chrome !== 'undefined' && chrome.extension && chrome.extension.getURL ? chrome.extension.getURL(path) : path;
    return '<i class="' + (placeholder_class || 'small_spinner') + '"><img src="' + url + '" /></i>';
  }

  function ui_scroll(selector, repeat) {
    var el = $(selector).first()[0];
    if(el) {
      el.scrollIntoView();
      tool.each(repeat, function(i, delay) { // useful if mobile keyboard is about to show up
        setTimeout(function() {
          el.scrollIntoView();
        }, delay);
      });
    }
  }

  function ui_passphrase_toggle(pass_phrase_input_ids, force_initial_show_or_hide) {
    var button_hide = '<img src="/img/svgs/eyeclosed-icon.svg" class="eye-closed"><br>hide';
    var button_show = '<img src="/img/svgs/eyeopen-icon.svg" class="eye-open"><br>show';
    storage.get(null, ['hide_pass_phrases'], function (s) {
      if(force_initial_show_or_hide === 'hide') {
        var show = false;
      } else if(force_initial_show_or_hide === 'show') {
        var show = true;
      } else {
        var show = !s.hide_pass_phrases;
      }
      tool.each(pass_phrase_input_ids, function (i, id) {
        $('#' + id).addClass('toggled_passphrase');
        if(show) {
          $('#' + id).after('<label href="#" id="toggle_' + id + '" class="toggle_show_hide_pass_phrase" for="' + id + '">' + button_hide + '</label>');
          $('#' + id).attr('type', 'text');
        } else {
          $('#' + id).after('<label href="#" id="toggle_' + id + '" class="toggle_show_hide_pass_phrase" for="' + id + '">' + button_show + '</label>');
          $('#' + id).attr('type', 'password');
        }
        $('#toggle_' + id).click(function () {
          if($('#' + id).attr('type') === 'password') {
            $('#' + id).attr('type', 'text');
            $(this).html(button_hide);
            storage.set(null, { hide_pass_phrases: false });
          } else {
            $('#' + id).attr('type', 'password');
            $(this).html(button_show);
            storage.set(null, { hide_pass_phrases: true });
          }
        });
      });
    });
  }

  function ui_enter(callback) {
    return function(e) {
      if (e.which == env_key_codes().enter) {
        callback();
      }
    };
  }

  function ui_build_jquery_selectors(selectors) {
    var cache = {};
    return {
      cached: function(name) {
        if(!cache[name]) {
          if(typeof selectors[name] === 'undefined') {
            catcher.report('unknown selector name: ' + name);
          }
          cache[name] = $(selectors[name]);
        }
        return cache[name];
      },
      now: function(name) {
        if(typeof selectors[name] === 'undefined') {
          catcher.report('unknown selector name: ' + name);
        }
        return $(selectors[name]);
      },
      selector: function (name) {
        if(typeof selectors[name] === 'undefined') {
          catcher.report('unknown selector name: ' + name);
        }
        return selectors[name];
      }
    };
  }

  /* tools.browser.message */

  var background_script_registered_handlers;
  var frame_registered_handlers = {};
  var standard_handlers = {
    set_css: function (data) {
      $(data.selector).css(data.css);
    },
  };

  function destination_parse(destination_string) {
    var parsed = { tab: null, frame: null };
    if(destination_string) {
      parsed.tab = Number(destination_string.split(':')[0]);
      parsed.frame = !isNaN(destination_string.split(':')[1]) ? Number(destination_string.split(':')[1]) : null;
    }
    return parsed;
  }

  function browser_message_send(destination_string, name, data, callback) {
    var msg = { name: name, data: data, to: destination_string || null, respondable: !!(callback), uid: tool.str.random(10), stack: typeof catcher !== 'undefined' ? catcher.stack_trace() : 'unknown' };
    var is_background_page = env_is_background_script();
    if(typeof  destination_string === 'undefined') { // don't know where to send the message
      catcher.report('browser_message_send to:undefined');
      if(typeof callback !== 'undefined') {
        callback();
      }
    } else if (is_background_page && background_script_registered_handlers && msg.to === null) {
      background_script_registered_handlers[msg.name](msg.data, 'background', callback); // calling from background script to background script: skip messaging completely
    } else if(is_background_page) {
      chrome.tabs.sendMessage(destination_parse(msg.to).tab, msg, undefined, function(r) {
        catcher.try(function() {
          if(typeof callback !== 'undefined') {
            callback(r);
          }
        })();
      });
    } else {
      chrome.runtime.sendMessage(msg, function(r) {
        catcher.try(function() {
          if(typeof callback !== 'undefined') {
            callback(r);
          }
        })();
      });
    }
  }

  function browser_message_tab_id(callback) {
    browser_message_send(null, '_tab_', null, callback);
  }

  function browser_message_listen_background(handlers) {
    if(!background_script_registered_handlers) {
      background_script_registered_handlers = handlers;
    } else {
      tool.each(handlers, function(name, handler) {
        background_script_registered_handlers[name] = handler;
      });
    }
    chrome.runtime.onMessage.addListener(function (msg, sender, respond) {
      var safe_respond = function (response) {
        try { // avoiding unnecessary errors when target tab gets closed
          respond(response);
        } catch(e) {
          if(e.message !== 'Attempting to use a disconnected port object') {
            catcher.handle_exception(e);
            throw e;
          }
        }
      };
      if(msg.to && msg.to !== 'broadcast') {
        msg.sender = sender;
        chrome.tabs.sendMessage(destination_parse(msg.to).tab, msg, undefined, safe_respond);
      } else if(tool.value(msg.name).in(Object.keys(background_script_registered_handlers))) {
        background_script_registered_handlers[msg.name](msg.data, sender, safe_respond);
      } else if(msg.to !== 'broadcast') {
        catcher.report('tool.browser.message.listen_background error: handler "' + msg.name + '" not set', 'Message sender stack:\n' + msg.stack);
      }
      return msg.respondable === true;
    });
  }

  function browser_message_listen(handlers, listen_for_tab_id) {
    tool.each(handlers, function(name, handler) {
      // newly registered handlers with the same name will overwrite the old ones if browser_message_listen is declared twice for the same frame
      // original handlers not mentioned in newly set handlers will continue to work
      frame_registered_handlers[name] = handler;
    });
    tool.each(standard_handlers, function(name, handler) {
      if(frame_registered_handlers[name] !== 'function') {
        frame_registered_handlers[name] = handler; // standard handlers are only added if not already set above
      }
    });
    var processed = [];
    chrome.runtime.onMessage.addListener(function (msg, sender, respond) {
      return catcher.try(function () {
        if(msg.to === listen_for_tab_id || msg.to === 'broadcast') {
          if(!tool.value(msg.uid).in(processed)) {
            processed.push(msg.uid);
            if(typeof frame_registered_handlers[msg.name] !== 'undefined') {
              frame_registered_handlers[msg.name](msg.data, sender, respond);
            } else if(msg.name !== '_tab_' && msg.to !== 'broadcast') {
              if(destination_parse(msg.to).frame !== null) { // only consider it an error if frameId was set because of firefox bug: https://bugzilla.mozilla.org/show_bug.cgi?id=1354337
                catcher.report('tool.browser.message.listen error: handler "' + msg.name + '" not set', 'Message sender stack:\n' + msg.stack);
              } else { // once firefox fixes the bug, it will behave the same as Chrome and the following will never happen.
                console.log('tool.browser.message.listen ignoring missing handler "' + msg.name + '" due to Firefox Bug');
              }
            }
          }
        }
        return msg.respondable === true;
      })();
    });
  }

  /* tool.diagnose */

  function diagnose_message_pubkeys(account_email, message) {
    return catcher.Promise(function(resolve, reject) {
      var message_key_ids = message.getEncryptionKeyIds();
      storage.keys_get(account_email).then(function(private_keys) {
        var local_key_ids = [].concat.apply([], private_keys.map(function(ki) {return ki.public}).map(crypto_key_ids));
        var diagnosis = { found_match: false, receivers: message_key_ids.length };
        tool.each(message_key_ids, function (i, msg_k_id) {
          tool.each(local_key_ids, function (j, local_k_id) {
            if(msg_k_id === local_k_id) {
              diagnosis.found_match = true;
              return false;
            }
          });
        });
        resolve(diagnosis);
      });
    });
  }

  function diagnose_keyserver_pubkeys(account_email, callback) {
    var diagnosis = { has_pubkey_missing: false, has_pubkey_mismatch: false, results: {} };
    storage.get(account_email, ['addresses'], function (s) {
      storage.keys_get(account_email).then(function(stored_keys) {
        var stored_keys_longids = stored_keys.map(function(ki) { return ki.longid; });
        api_attester_lookup_email(tool.arr.unique([account_email].concat(s.addresses || []))).then(function(pubkey_search_results) {
          tool.each(pubkey_search_results.results, function (i, pubkey_search_result) {
            if (!pubkey_search_result.pubkey) {
              diagnosis.has_pubkey_missing = true;
              diagnosis.results[pubkey_search_result.email] = {attested: false, pubkey: null, match: false};
            } else {
              var match = true;
              if (!tool.value(crypto_key_longid(pubkey_search_result.pubkey)).in(stored_keys_longids)) {
                diagnosis.has_pubkey_mismatch = true;
                match = false;
              }
              diagnosis.results[pubkey_search_result.email] = {
                pubkey: pubkey_search_result.pubkey,
                attested: pubkey_search_result.attested,
                match: match
              };
            }
          });
          callback(diagnosis);
        }, function(error) {
          callback();
        });
      });
    });
  }

  /* tool.crypto.armor */

  function crypto_armor_strip(pgp_block_text) {
    if(!pgp_block_text) {
      return pgp_block_text;
    }
    var debug = false;
    if(debug) {
      console.log('pgp_block_1');
      console.log(pgp_block_text);
    }
    var newlines = [/<div><br><\/div>/g, /<\/div><div>/g, /<[bB][rR]( [a-zA-Z]+="[^"]*")* ?\/? ?>/g, /<div ?\/?>/g];
    var spaces = [/&nbsp;/g];
    var removes = [/<wbr ?\/?>/g, /<\/?div>/g];
    tool.each(newlines, function (i, newline) {
      pgp_block_text = pgp_block_text.replace(newline, '\n');
    });
    if(debug) {
      console.log('pgp_block_2');
      console.log(pgp_block_text);
    }
    tool.each(removes, function (i, remove) {
      pgp_block_text = pgp_block_text.replace(remove, '');
    });
    if(debug) {
      console.log('pgp_block_3');
      console.log(pgp_block_text);
    }
    tool.each(spaces, function (i, space) {
      pgp_block_text = pgp_block_text.replace(space, ' ');
    });
    if(debug) {
      console.log('pgp_block_4');
      console.log(pgp_block_text);
    }
    pgp_block_text = pgp_block_text.replace(/\r\n/g, '\n');
    if(debug) {
      console.log('pgp_block_5');
      console.log(pgp_block_text);
    }
    pgp_block_text = $('<div>' + pgp_block_text + '</div>').text();
    if(debug) {
      console.log('pgp_block_6');
      console.log(pgp_block_text);
    }
    var double_newlines = pgp_block_text.match(/\n\n/g);
    if(double_newlines !== null && double_newlines.length > 2) { //a lot of newlines are doubled
      pgp_block_text = pgp_block_text.replace(/\n\n/g, '\n');
      if(debug) {
        console.log('pgp_block_removed_doubles');
      }
    }
    if(debug) {
      console.log('pgp_block_7');
      console.log(pgp_block_text);
    }
    pgp_block_text = pgp_block_text.replace(/^ +/gm, '');
    if(debug) {
      console.log('pgp_block_final');
      console.log(pgp_block_text);
    }
    return pgp_block_text;
  }

  var crypto_armor_header_max_length = 50;

  var crypto_armor_headers_dict = {
    null: { begin: '-----BEGIN', end: '-----END' },
    public_key: { begin: '-----BEGIN PGP PUBLIC KEY BLOCK-----', end: '-----END PGP PUBLIC KEY BLOCK-----', replace: true },
    private_key: { begin: '-----BEGIN PGP PRIVATE KEY BLOCK-----', end: '-----END PGP PRIVATE KEY BLOCK-----', replace: true },
    attest_packet: { begin: '-----BEGIN ATTEST PACKET-----', end: '-----END ATTEST PACKET-----', replace: true },
    cryptup_verification: { begin: '-----BEGIN CRYPTUP VERIFICATION-----', end: '-----END CRYPTUP VERIFICATION-----', replace: true },
    signed_message: { begin: '-----BEGIN PGP SIGNED MESSAGE-----', middle: '-----BEGIN PGP SIGNATURE-----', end: '-----END PGP SIGNATURE-----', replace: true },
    signature: { begin: '-----BEGIN PGP SIGNATURE-----', end: '-----END PGP SIGNATURE-----' },
    message: { begin: '-----BEGIN PGP MESSAGE-----', end: '-----END PGP MESSAGE-----', replace: true },
    password_message: { begin: 'This message is encrypted: Open Message', end: /https:(\/|&#x2F;){2}(cryptup\.org|flowcrypt\.com)(\/|&#x2F;)[a-zA-Z0-9]{10}(\n|$)/, replace: true},
  };

  function crypto_armor_headers(block_type, format) {
    if(format === 're') {
      var h = crypto_armor_headers_dict[block_type || null];
      if(typeof h.exec === 'function') {
        return h;
      }
      return obj_map(h, function (header_value) {
        if(typeof h === 'string') {
          return header_value.replace(/ /g, '\\\s'); // regexp match friendly
        } else {
          return header_value;
        }
      });
    } else {
      return crypto_armor_headers_dict[block_type || null];
    }
  }

  function crypto_armor_clip(text) {
    if(text && tool.value(crypto_armor_headers_dict[null].begin).in(text) && tool.value(crypto_armor_headers_dict[null].end).in(text)) {
      var match = text.match(/(-----BEGIN PGP (MESSAGE|SIGNED MESSAGE|SIGNATURE|PUBLIC KEY BLOCK)-----[^]+-----END PGP (MESSAGE|SIGNATURE|PUBLIC KEY BLOCK)-----)/gm);
      return(match !== null && match.length) ? match[0] : null;
    }
    return null;
  }

  var password_sentence_present_test = /https:\/\/(cryptup\.org|flowcrypt\.com)\/[a-zA-Z0-9]{10}/;
  var password_sentences = [
    /This\smessage\sis\sencrypted.+\n\n?/gm, // todo - should be in a common place as the code that generated it
    /.*https:\/\/(cryptup\.org|flowcrypt\.com)\/[a-zA-Z0-9]{10}.*\n\n?/gm,
  ];

  function crypto_armor_normalize(armored, type) {
    if(tool.value(type).in(['message', 'public_key', 'private_key', 'key'])) {
      armored = armored.replace(/\r?\n/g, '\n').trim();
      var nl_2 = armored.match(/\n\n/g);
      var nl_3 = armored.match(/\n\n\n/g);
      var nl_4 = armored.match(/\n\n\n\n/g);
      var nl_6 = armored.match(/\n\n\n\n\n\n/g);
      if (nl_3 && nl_6 && nl_3.length > 1 && nl_6.length === 1) {
        return armored.replace(/\n\n\n/g, '\n'); // newlines tripled: fix
      } else if(nl_2 && nl_4 && nl_2.length > 1 && nl_4.length === 1) {
        return armored.replace(/\n\n/g, '\n'); // newlines doubled.GPA on windows does this, and sometimes message can get extracted this way from html
      }
      return armored;
    } else {
      return armored;
    }
  }

  function crypto_armor_block_object(type, content, missing_end) {
    return {type: type, content: content, complete: !missing_end};
  }

  function crypto_armor_detect_block_next(original_text, start_at) {
    var result = {found: [], continue_at: null};
    var begin = original_text.indexOf(crypto_armor_headers(null).begin, start_at);
    if(begin !== -1) { // found
      var potential_begin_header = original_text.substr(begin, crypto_armor_header_max_length);
      tool.each(crypto_armor_headers_dict, function(type, block_header) {
        if(block_header.replace) {
          var index_of_confirmed_begin = potential_begin_header.indexOf(block_header.begin);
          if(index_of_confirmed_begin === 0 || (type === 'password_message' && index_of_confirmed_begin < 15)) { // identified beginning of a specific block
            if(begin > start_at) {
              var potential_text_before_block_begun = original_text.substring(start_at, begin).trim();
              if(potential_text_before_block_begun) {
                result.found.push(crypto_armor_block_object('text', potential_text_before_block_begun));
              }
            }
            if(typeof block_header.end === 'string') {
              var end = original_text.indexOf(block_header.end, begin + block_header.begin.length);
            } else { // regexp
              var end = original_text.match(block_header.end);
              end = end || -1; // useful below to mimic indexOf
              if(end !== -1) {
                block_header.end.length = end[0].length; // another hack to mimic results of indexOf
                end = end.index; // one more
              }
            }
            if(end !== -1) { // identified end of the same block
              if(type !== 'password_message') {
                result.found.push(crypto_armor_block_object(type, original_text.substring(begin, end + block_header.end.length).trim()));
              } else {
                var pm_full_text = original_text.substring(begin, end + block_header.end.length).trim();
                var pm_short_id_match = pm_full_text.match(/[a-zA-Z0-9]{10}$/);
                if(pm_short_id_match) {
                  result.found.push(crypto_armor_block_object(type, pm_short_id_match[0]));
                } else {
                  result.found.push(crypto_armor_block_object('text', pm_full_text));
                }
              }
              result.continue_at = end + block_header.end.length;
            } else { // corresponding end not found
              result.found.push(crypto_armor_block_object(type, original_text.substr(begin), true));
            }
            return false;
          }
        }
      });
    } else {
      var potential_text = original_text.substr(start_at).trim();
      if(potential_text) {
        result.found.push(crypto_armor_block_object('text', potential_text));
      }
    }
    return result;
  }

  function crypto_armor_detect_blocks(original_text) {
    var structure = [];
    original_text = str_normalize_spaces(original_text);
    var start_at = 0;
    while(true) {
      var r = crypto_armor_detect_block_next(original_text, start_at);
      if(r.found) {
        structure = structure.concat(r.found);
      }
      if(!r.continue_at) {
        return structure;
      } else {
        start_at = r.continue_at;
      }
    }
  }

  function crypto_armor_replace_blocks(factory, original_text, message_id, sender_email, is_outgoing) {
    var blocks = crypto_armor_detect_blocks(original_text);
    if(blocks.length === 1 && blocks[0].type === 'text') {
      return;
    }
    var r = '';
    tool.each(blocks, function(i, block) {
      if(block.type === 'text' || block.type === 'private_key') {
        r += (Number(i) ? '\n\n' : '') + str_html_escape(block.content) + '\n\n';
      } else if (block.type === 'message') {
        r += factory.embedded.message(block.complete ? crypto_armor_normalize(block.content, 'message') : '', message_id, is_outgoing, sender_email, false);
      } else if (block.type === 'signed_message') {
        r += factory.embedded.message(block.content, message_id, is_outgoing, sender_email, false);
      } else if (block.type === 'public_key') {
        r += factory.embedded.pubkey(crypto_armor_normalize(block.content, 'public_key'), is_outgoing);
      } else if (block.type === 'password_message') {
        r += factory.embedded.message('', message_id, is_outgoing, sender_email, true, null, block.content); // here block.content is message short id
      } else if (block.type === 'attest_packet') {
        r += factory.embedded.attest(block.content);
      } else if (block.type === 'cryptup_verification') {
        r += factory.embedded.verification(block.content);
      } else {
        catcher.report('dunno how to process block type: ' + block.type);
      }
    });
    return r;
  }

  /* tool.crypto.hash */

  function crypto_hash_sha1(string) {
    return tool.str.to_hex(tool.str.from_uint8(openpgp.crypto.hash.sha1(string)));
  }

  function crypto_hash_double_sha1_upper(string) {
    return crypto_hash_sha1(crypto_hash_sha1(string)).toUpperCase();
  }

  function crypto_hash_sha256(string) {
    return tool.str.to_hex(tool.str.from_uint8(openpgp.crypto.hash.sha256(string)));
  }

  function crypto_hash_sha256_loop(string, times) {
    for(var i = 0; i < (times || 100000); i++) {
      string = crypto_hash_sha256(string);
    }
    return string;
  }

  function crypto_hash_challenge_answer(answer) {
    return crypto_hash_sha256_loop(answer);
  }

  /* tool.crypto.key */

  function crypto_key_create(user_ids_as_pgp_contacts, num_bits, pass_phrase, callback) {
    openpgp.generateKey({
      numBits: num_bits,
      userIds: user_ids_as_pgp_contacts,
      passphrase: pass_phrase,
    }).then(function(key) {
      callback(key.privateKeyArmored);
    }).catch(function(error) {
      catcher.handle_exception(error);
    });
  }

  function crypto_key_read(armored_key) {
    return openpgp.key.readArmored(armored_key).keys[0];
  }

  function crypto_key_ids(armored_pubkey) {
    return openpgp.key.readArmored(armored_pubkey).keys[0].getKeyIds();
  }

  function crypto_key_decrypt(prv, passphrase) { // {success: true|false, error: undefined|str}
    try {
      return {success: prv.decrypt(passphrase)};
    } catch(primary_e) {
      if(!tool.value(primary_e.message).in(['Unknown s2k type.', 'Invalid enum value.'])) {
        return {success: false, error: 'primary decrypt error: "' + primary_e.message + '"'}; // unknown exception for master key
      } else if(prv.subKeys !== null && prv.subKeys.length) {
        var subkes_succeeded = 0;
        var subkeys_unusable = 0;
        var unknown_exception;
        tool.each(prv.subKeys, function(i, subkey) {
          try {
            subkes_succeeded += subkey.subKey.decrypt(passphrase);
          } catch(subkey_e) {
            subkeys_unusable++;
            if(!tool.value(subkey_e.message).in(['Key packet is required for this signature.', 'Unknown s2k type.', 'Invalid enum value.'])) {
              unknown_exception = subkey_e;
              return false;
            }
          }
        });
        if(unknown_exception) {
          return {success: false, error: 'subkey decrypt error: "' + unknown_exception.message + '"'};
        }
        return {success: subkes_succeeded > 0 && (subkes_succeeded + subkeys_unusable) === prv.subKeys.length};
      } else {
        return {success: false, error: 'primary decrypt error and no subkeys to try: "' + primary_e.message + '"'};
      }
    }
  }

  function crypto_key_expired_for_encryption(key) {
    if(key.getEncryptionKeyPacket() !== null) {
      return false;
    }
    if(key.verifyPrimaryKey() === openpgp.enums.keyStatus.expired) {
      return true;
    }
    var found_expired_subkey = false;
    tool.each(key.subKeys, function (i, sub_key) {
      if(sub_key.verify(key.primaryKey) === openpgp.enums.keyStatus.expired && sub_key.isValidEncryptionKey(key.primaryKey)) {
        found_expired_subkey = true;
        return false;
      }
    });
    return found_expired_subkey; // todo - shouldn't we be checking that ALL subkeys are either invalid or expired to declare a key expired?
  }

  function crypto_key_usable(armored) { // is pubkey usable for encrytion?
    if(!crypto_key_fingerprint(armored)) {
      return false;
    }
    var pubkey = openpgp.key.readArmored(armored).keys[0];
    if(!pubkey) {
      return false;
    }
    patch_public_keys_to_ignore_expiration([pubkey]);
    return pubkey.getEncryptionKeyPacket() !== null;
  }

  function crypto_key_normalize(armored) {
    try {
      armored = crypto_armor_normalize(armored, 'key');
      var key;
      if(RegExp(crypto_armor_headers('public_key', 're').begin).test(armored)) {
        key = openpgp.key.readArmored(armored).keys[0];
      } else if(RegExp(crypto_armor_headers('message', 're').begin).test(armored)) {
        key = openpgp.key.Key(openpgp.message.readArmored(armored).packets);
      }
      if(key) {
        return key.armor();
      } else {
        return armored;
      }
    } catch(error) {
      catcher.handle_exception(error);
    }
  }

  function crypto_key_fingerprint(key, formatting) {
    if(key === null || typeof key === 'undefined') {
      return null;
    } else if(typeof key.primaryKey !== 'undefined') {
      if(key.primaryKey.fingerprint === null) {
        return null;
      }
      try {
        var fp = key.primaryKey.fingerprint.toUpperCase();
        if(formatting === 'spaced') {
          return fp.replace(/(.{4})/g, '$1 ').trim();
        }
        return fp;
      } catch(error) {
        console.log(error);
        return null;
      }
    } else {
      try {
        return crypto_key_fingerprint(openpgp.key.readArmored(key).keys[0], formatting);
      } catch(error) {
        if(error.message === 'openpgp is not defined') {
          catcher.handle_exception(error);
        }
        console.log(error);
        return null;
      }
    }
  }

  function crypto_key_longid(key_or_fingerprint_or_bytes) {
    if(key_or_fingerprint_or_bytes === null || typeof key_or_fingerprint_or_bytes === 'undefined') {
      return null;
    } else if(key_or_fingerprint_or_bytes.length === 8) {
      return tool.str.to_hex(key_or_fingerprint_or_bytes).toUpperCase();
    } else if(key_or_fingerprint_or_bytes.length === 40) {
      return key_or_fingerprint_or_bytes.substr(-16);
    } else if(key_or_fingerprint_or_bytes.length === 49) {
      return key_or_fingerprint_or_bytes.replace(/ /g, '').substr(-16);
    } else {
      return crypto_key_longid(crypto_key_fingerprint(key_or_fingerprint_or_bytes));
    }
  }

  function crypto_key_test(armored, passphrase, callback) {
    try {
      openpgp.encrypt({ data: 'this is a test', armor: true, publicKeys: [openpgp.key.readArmored(armored).keys[0].toPublic()] }).then(function (result) {
        var prv = openpgp.key.readArmored(armored).keys[0];
        crypto_key_decrypt(prv, passphrase);
        openpgp.decrypt({ message: openpgp.message.readArmored(result.data), format: 'utf8', privateKey: prv }).then(function () {
          callback(true);
        }).catch(function (error) {
          callback(false, error.message);
        });
      }).catch(function (error) {
        callback(false, error.message);
      });
    } catch(error) {
      callback(false, error.message);
    }
  }

  /* tool.crypo.message */

  function crypto_message_sign(signing_prv, data, armor, callback) {
    var options = { data: data, armor: armor, privateKeys: signing_prv, };
    openpgp.sign(options).then(function(result) {callback(true, result.data)}, function (error) {callback(false, error.message)});
  }

  function get_sorted_keys_for_message(db, account_email, message, callback) {
    var keys = {};
    keys.verification_contacts = [];
    keys.for_verification = [];
    if(message.getEncryptionKeyIds) {
      keys.encrypted_for = (message.getEncryptionKeyIds() || []).map(function (id) {
        return crypto_key_longid(id.bytes);
      });
    } else {
      keys.encrypted_for = [];
    }
    keys.signed_by = (message.getSigningKeyIds() || []).filter(function(id) { return Boolean(id); }).map(function (id) {
      return crypto_key_longid(id.bytes);
    });
    storage.keys_get(account_email).then(function(private_keys_all) {
      keys.potentially_matching = private_keys_all.filter(function(ki) { return tool.value(ki.longid).in(keys.encrypted_for)});
      if(keys.potentially_matching.length === 0) { // not found any matching keys, or list of encrypted_for was not supplied in the message. Just try all keys.
        keys.potentially_matching = private_keys_all;
      }
      keys.with_passphrases = [];
      keys.without_passphrases = [];
      Promise.all(keys.potentially_matching.map(function(keyinfo) {return storage.passphrase_get(account_email, keyinfo.longid)})).then(function(passphrases) {
        tool.each(keys.potentially_matching, function (i, keyinfo) {
          if(passphrases[i] !== null) {
            var key = openpgp.key.readArmored(keyinfo.private).keys[0];
            if(crypto_key_decrypt(key, passphrases[i]).success) {
              keyinfo.decrypted = key;
              keys.with_passphrases.push(keyinfo);
            } else {
              keys.without_passphrases.push(keyinfo);
            }
          } else {
            keys.without_passphrases.push(keyinfo);
          }
        });
        if(keys.signed_by.length && typeof storage.db_contact_get === 'function') {
          storage.db_contact_get(db, keys.signed_by, function (verification_contacts) {
            keys.verification_contacts = verification_contacts.filter(function (contact) {
              return contact !== null;
            });
            keys.for_verification = [].concat.apply([], keys.verification_contacts.map(function (contact) {
              return openpgp.key.readArmored(contact.pubkey).keys;
            }));
            callback(keys);
          });
        } else {
          callback(keys);
        }
      });
    });
  }

  function zeroed_decrypt_error_counts(keys) {
    return {
      decrypted: 0,
      potentially_matching_keys: keys ? keys.potentially_matching.length : 0,
      rounds: keys ? keys.with_passphrases.length : 0,
      attempts: 0,
      key_mismatch: 0,
      wrong_password: 0,
      unsecure_mdc: 0,
      format_errors: 0,
    };
  }

  function increment_decrypt_error_counts(counts, other_errors, one_time_message_password, decrypt_error) {
    if(String(decrypt_error) === 'TypeError: Error decrypting message: Cannot read property \'isDecrypted\' of null' && !one_time_message_password) {
      counts.key_mismatch++; // wrong private key
    } else if(String(decrypt_error) === 'Error: Error decrypting message: Invalid session key for decryption.' && !one_time_message_password) {
      counts.key_mismatch++; // attempted opening password only message with key
    } else if(one_time_message_password && tool.value(String(decrypt_error)).in(['Error: Error decrypting message: Invalid enum value.', 'Error: Error decrypting message: CFB decrypt: invalid key'])) {
      counts.wrong_password++; // wrong password
    } else if(String(decrypt_error) === 'Error: Error decrypting message: Decryption failed due to missing MDC in combination with modern cipher.') {
      counts.unsecure_mdc++;
    } else if (String(decrypt_error) === 'Error: Error decrypting message: Decryption error') {
      counts.format_errors++; // typically
    } else {
      other_errors.push(String(decrypt_error));
    }
    counts.attempts++;
  }

  /**
   *
   * @param callback: callback function / listener
   * @param result: result to be called back
   * @returns {boolean}: continue to next attempt
   */
  function chained_decryption_result_collector(callback, result) {
    window.flowcrypt_profile.add('got result');
    if(result.success) {
      window.flowcrypt_profile.add('return result');
      window.flowcrypt_profile.print();
      callback(result); // callback the moment there is successful decrypt
      return false; // do not try again
    } else if(result.counts.attempts === result.counts.rounds && !result.counts.decrypted) {
      if(result.counts.format_errors > 0) {
        result.format_error = 'This message seems to be badly formatted.';
      }
      callback(result); // or callback if no success and this was the last attempt
      return false; // do not try again
    }
    return true; // next attempt
  }

  function get_decrypt_options(message, keyinfo, is_armored, one_time_message_password, force_output_format) {
    var options = { message: message, format: is_armored ? force_output_format || 'utf8' : force_output_format || 'binary' };
    if(!one_time_message_password) {
      options.privateKey = keyinfo.decrypted;
    } else {
      options.password = crypto_hash_challenge_answer(one_time_message_password);
    }
    return options;
  }

  function crypto_message_verify(message, keys_for_verification, optional_contact) {
    var signature = { signer: null, contact: optional_contact || null,  match: null, error: null };
    try {
      tool.each(message.verify(keys_for_verification), function (i, verify_result) {
        signature.match = tool.value(signature.match).in([true, null]) && verify_result.valid; // this will probably falsely show as not matching in some rare cases. Needs testing.
        if(!signature.signer) {
          signature.signer = crypto_key_longid(verify_result.keyid.bytes);
        }
      });
    } catch(verify_error) {
      signature.match = null;
      if(verify_error.message === 'Can only verify message with one literal data packet.') {
        signature.error = 'FlowCrypt is not equipped to verify this message (err 101)';
      } else {
        signature.error = 'FlowCrypt had trouble verifying this message (' + verify_error.message + ')';
        catcher.handle_exception(verify_error);
      }
    }
    return signature;
  }

  function crypto_message_verify_detached(db, account_email, plaintext, signature_text, callback) {
    var message = openpgp.message.readSignedContent(plaintext, signature_text);
    get_sorted_keys_for_message(db, account_email, message, function(keys) {
      callback(crypto_message_verify(message, keys.for_verification, keys.verification_contacts[0]));
    });
  }

  function crypto_message_decrypt(db, account_email, encrypted_data, message_password, callback, output_format) {
    window.flowcrypt_profile.add('decrypt_start');
    var armored_encrypted = tool.value(crypto_armor_headers('message').begin).in(encrypted_data);
    var armored_signed_only = tool.value(crypto_armor_headers('signed_message').begin).in(encrypted_data);
    var is_armored = armored_encrypted || armored_signed_only;
    var other_errors = [];
    try {
      if(armored_encrypted) {
        var message = openpgp.message.readArmored(encrypted_data);
      } else if(armored_signed_only) {
        var message = openpgp.cleartext.readArmored(encrypted_data);
      } else {
        var message = openpgp.message.read(typeof encrypted_data === 'string' ? tool.str.to_uint8(encrypted_data) : encrypted_data);
      }
    } catch(format_error) {
      callback({success: false, counts: zeroed_decrypt_error_counts(), format_error: format_error.message, errors: other_errors, encrypted: null, signature: null});
      return;
    }
    get_sorted_keys_for_message(db, account_email, message, function (keys) {
      window.flowcrypt_profile.add('get_sorted_keys_for_message');
      var counts = zeroed_decrypt_error_counts(keys);
      if(armored_signed_only) {
        if(!message.text) {
          var sm_headers = crypto_armor_headers('signed_message', 're');
          var text = encrypted_data.match(RegExp(sm_headers.begin + '\nHash:\s[A-Z0-9]+\n([^]+)\n' + sm_headers.middle + '[^]+' + sm_headers.end, 'm'));
          message.text = text && text.length === 2 ? text[1] : encrypted_data;
        }
        callback({success: true, content: { data: message.text }, encrypted: false, signature: crypto_message_verify(message, keys.for_verification, keys.verification_contacts[0])});
      } else {
        var missing_passphrases = keys.without_passphrases.map(function (keyinfo) { return keyinfo.longid; });
        if(!keys.with_passphrases.length && !message_password) {
          callback({success: false, signature: null, message: message, counts: counts, unsecure_mdc: !!counts.unsecure_mdc, encrypted_for: keys.encrypted_for, missing_passphrases: missing_passphrases, errors: other_errors});
        } else {
          var keyinfos_for_looper = keys.with_passphrases.slice(); // copy keyinfo array
          var keep_trying_until_decrypted_or_all_failed = function () {
            catcher.try(function () {
              window.flowcrypt_profile.add('beginning attempt');
              if(!counts.decrypted && keyinfos_for_looper.length) {
                try {
                  openpgp.decrypt(get_decrypt_options(message, keyinfos_for_looper.shift(), is_armored, message_password, output_format)).then(function (decrypted) {
                    catcher.try(function () {
                      if(!counts.decrypted++) { // don't call back twice if encrypted for two of my keys
                        // var signature_result = keys.signed_by.length ? crypto_message_verify(message, keys.for_verification, keys.verification_contacts[0]) : false;
                        var signature_result = null;
                        if(chained_decryption_result_collector(callback, {success: true, content: decrypted, encrypted: true, signature: signature_result})) {
                          keep_trying_until_decrypted_or_all_failed();
                        }
                      }
                    })();
                  }).catch(function (decrypt_error) {
                    catcher.try(function () {
                      increment_decrypt_error_counts(counts, other_errors, message_password, decrypt_error);
                      if(chained_decryption_result_collector(callback, {success: false, signature: null, message: message, counts: counts, unsecure_mdc: !!counts.unsecure_mdc, encrypted_for: keys.encrypted_for, missing_passphrases: missing_passphrases, errors: other_errors})) {
                        keep_trying_until_decrypted_or_all_failed();
                      }
                    })();
                  });
                } catch(decrypt_exception) {
                  other_errors.push(String(decrypt_exception));
                  counts.attempts++;
                  if(chained_decryption_result_collector(callback, {success: false, signature: null, message: message, counts: counts, unsecure_mdc: !!counts.unsecure_mdc, encrypted_for: keys.encrypted_for, missing_passphrases: missing_passphrases, errors: other_errors})) {
                    keep_trying_until_decrypted_or_all_failed();
                  }
                }
              }
            })();
          };
          window.flowcrypt_profile.add('before first attempt');
          keep_trying_until_decrypted_or_all_failed(); // first attempt
        }
      }
    });
  }

  function patch_public_keys_to_ignore_expiration(keys) {
    var openpgpjs_original_isValidEncryptionKeyPacket = function(keyPacket, signature) {
      return keyPacket.algorithm !== openpgp.enums.read(openpgp.enums.publicKey, openpgp.enums.publicKey.dsa) && keyPacket.algorithm !== openpgp.enums.read(openpgp.enums.publicKey, openpgp.enums.publicKey.rsa_sign) && (!signature.keyFlags || (signature.keyFlags[0] & openpgp.enums.keyFlags.encrypt_communication) !== 0 || (signature.keyFlags[0] & openpgp.enums.keyFlags.encrypt_storage) !== 0);
    };
    tool.each(keys, function (i, key) {
      tool.each(key.subKeys || [], function (i, sub_key) {
        sub_key.isValidEncryptionKey = function (primaryKey) {
          var verifyResult = this.verify(primaryKey);
          if (verifyResult !== openpgp.enums.keyStatus.valid && verifyResult !== openpgp.enums.keyStatus.expired) {
            return false;
          }
          for (var i = 0; i < this.bindingSignatures.length; i++) {
            if (openpgpjs_original_isValidEncryptionKeyPacket(this.subKey, this.bindingSignatures[i])) {
              return true;
            }
          }
          return false;
        };
      });
    });
  }

  function crypto_message_encrypt(armored_pubkeys, signing_prv, challenge, data, filename, armor, callback) {
    var options = { data: data, armor: armor };
    if(filename) {
      options.filename = filename;
    }
    var used_challange = false;
    if(armored_pubkeys) {
      options.publicKeys = [];
      tool.each(armored_pubkeys, function (i, armored_pubkey) {
        options.publicKeys = options.publicKeys.concat(openpgp.key.readArmored(armored_pubkey).keys);
      });
      patch_public_keys_to_ignore_expiration(options.publicKeys);
    }
    if(challenge && challenge.answer) {
      options.passwords = [crypto_hash_challenge_answer(challenge.answer)];
      used_challange = true;
    }
    if(!armored_pubkeys && !used_challange) {
      alert('Internal error: don\'t know how to encryt message. Please refresh the page and try again, or contact me at human@flowcrypt.com if this happens repeatedly.');
      throw new Error('no-pubkeys-no-challenge');
    }
    if(signing_prv && typeof signing_prv.isPrivate !== 'undefined' && signing_prv.isPrivate()) {
      options.privateKeys = [signing_prv];
    }
    openpgp.encrypt(options).then(function (result) {
      catcher.try(function () { // todo - this is very awkward, should create a Try wrapper with a better api
        callback(result);
      })();
    }, function (error) {
      console.log(error);
      alert('Error encrypting message, please try again. If you see this repeatedly, contact me at human@flowcrypt.com.');
      //todo: make the UI behave well on errors
    });
  }

  function readable_crack_time(total_seconds) { // http://stackoverflow.com/questions/8211744/convert-time-interval-given-in-seconds-into-more-human-readable-form
    function numberEnding(number) {
      return(number > 1) ? 's' : '';
    }
    total_seconds = Math.round(total_seconds);
    var millennia = Math.round(total_seconds / (86400 * 30 * 12 * 100 * 1000));
    if(millennia) {
      return millennia === 1 ? 'a millennium' : 'millennia';
    }
    var centuries = Math.round(total_seconds / (86400 * 30 * 12 * 100));
    if(centuries) {
      return centuries === 1 ? 'a century' : 'centuries';
    }
    var years = Math.round(total_seconds / (86400 * 30 * 12));
    if(years) {
      return years + ' year' + numberEnding(years);
    }
    var months = Math.round(total_seconds / (86400 * 30));
    if(months) {
      return months + ' month' + numberEnding(months);
    }
    var days = Math.round(total_seconds / 86400);
    if(days) {
      return days + ' day' + numberEnding(days);
    }
    var hours = Math.round(total_seconds / 3600);
    if(hours) {
      return hours + ' hour' + numberEnding(hours);
    }
    var minutes = Math.round(total_seconds / 60);
    if(minutes) {
      return minutes + ' minute' + numberEnding(minutes);
    }
    var seconds = total_seconds % 60;
    if(seconds) {
      return seconds + ' second' + numberEnding(seconds);
    }
    return 'less than a second';
  }

  // https://threatpost.com/how-much-does-botnet-cost-022813/77573/
  // https://www.abuse.ch/?p=3294
  var guesses_per_second = 10000 * 2 * 4000; //(10k ips) * (2 cores p/machine) * (4k guesses p/core)
  var crack_time_words = [
    ['millenni', 'perfect', 100, 'green', true],
    ['centu', 'great', 80, 'green', true],
    ['year', 'good', 60, 'orange', true],
    ['month', 'reasonable', 40, 'darkorange', true],
    ['day', 'poor', 20, 'darkred', false],
    ['', 'weak', 10, 'red', false],
  ]; // word search, word rating, bar percent, color, pass

  function crypto_password_estimate_strength(zxcvbn_result_guesses) {
    var time_to_crack = zxcvbn_result_guesses / guesses_per_second;
    for(var i = 0; i < crack_time_words.length; i++) {
      var readable_time = readable_crack_time(time_to_crack);
      if(tool.value(crack_time_words[i][0]).in(readable_time)) { // looks for a word match from readable_crack_time, defaults on "weak"
        return {
          word: crack_time_words[i][1],
          bar: crack_time_words[i][2],
          time: readable_time,
          seconds: Math.round(time_to_crack),
          pass: crack_time_words[i][4],
          color: crack_time_words[i][3],
          suggestions: [],
        };
      }
    }
  }

  function crypto_password_weak_words() {
    return [
      'crypt', 'up', 'cryptup', 'flow', 'flowcrypt', 'encryption', 'pgp', 'email', 'set', 'backup', 'passphrase', 'best', 'pass', 'phrases', 'are', 'long', 'and', 'have', 'several',
      'words', 'in', 'them', 'Best pass phrases are long', 'have several words', 'in them', 'bestpassphrasesarelong', 'haveseveralwords', 'inthem',
      'Loss of this pass phrase', 'cannot be recovered', 'Note it down', 'on a paper', 'lossofthispassphrase', 'cannotberecovered', 'noteitdown', 'onapaper',
      'setpassword', 'set password', 'set pass word', 'setpassphrase', 'set pass phrase', 'set passphrase'
    ];
  }


  /* tool.api.aws */

  var api_gmail_scope_dict = {
    read: 'https://www.googleapis.com/auth/gmail.readonly',
    compose: 'https://www.googleapis.com/auth/gmail.compose',
  };

  function api_gmail_scope(scope) {
    return (typeof scope === 'string') ? api_gmail_scope_dict[scope] : scope.map(api_gmail_scope);
  }

  function api_gmail_has_scope(scopes, scope) {
    return scopes && tool.value(api_gmail_scope_dict[scope]).in(scopes)
  }


})();


(function ( /* ERROR HANDLING */ ) {

  var tool = typeof tool === 'object' ? tool : window.tool;
  var storage = (typeof exports === 'object') ? require('js/storage').legacy : window.flowcrypt_storage;
  var RUNTIME = {};
  figure_out_flowcrypt_runtime();

  var original_on_error = window.onerror;
  window.onerror = handle_error;
  window.onunhandledrejection = handle_promise_error;

  function handle_promise_error(e) {
    if(e && typeof e === 'object' && typeof e.reason === 'object' && e.reason.message) {
      handle_exception(e.reason); // actual exception that happened in Promise, unhandled
    } else {
      log('unhandled_promise_reject_object', e); // some x that was called with reject(x) and later not handled
    }
  }

  function handle_error(error_message, url, line, col, error, is_manually_called, version, env) {
    if(typeof error === 'string') {
      error_message = error;
      error = { name: 'thrown_string', message: error_message, stack: error_message };
    }
    if(error_message && url && typeof line !== 'undefined' && !col && !error && !is_manually_called && !version && !env) { // safari has limited support
      error = { name: 'safari_error', message: error_message, stack: error_message };
    }
    if(typeof error_message === 'undefined' && line === 0 && col === 0 && is_manually_called && typeof error === 'object' && !(error instanceof Error)) {
      try { // this sometimes happen with unhandled Promise.then(_, reject)
        var stringified = JSON.stringify(error);
      } catch(cannot) {
        var stringified = 'typeof: ' + (typeof error) + '\n' + String(error);
      }
      error = { name: 'thrown_object', message: error.message || '(unknown)', stack: stringified};
      error_message = 'thrown_object'
    }
    var user_log_message = ' Please report errors above to human@flowcrypt.com. I fix errors VERY promptly.';
    var ignored_errors = [
      'Invocation of form get(, function) doesn\'t match definition get(optional string or array or object keys, function callback)', // happens in gmail window when reloaded extension + now reloading gmail
      'Invocation of form set(, function) doesn\'t match definition set(object items, optional function callback)', // happens in gmail window when reloaded extension + now reloading gmail
      'Invocation of form runtime.connect(null, ) doesn\'t match definition runtime.connect(optional string extensionId, optional object connectInfo)',
    ];
    if(!error) {
      return;
    }
    if(ignored_errors.indexOf(error.message) !== -1) {
      return true;
    }
    if(error.stack) {
      console.log('%c[' + error_message + ']\n' + error.stack, 'color: #F00; font-weight: bold;');
    } else {
      console.log('%c' + error_message, 'color: #F00; font-weight: bold;');
    }
    if(is_manually_called !== true && original_on_error && original_on_error !== handle_error) {
      original_on_error.apply(this, arguments); // Call any previously assigned handler
    }
    if((error.stack || '').indexOf('PRIVATE') !== -1) {
      return;
    }
    try {
      $.ajax({
        url: 'https://api.cryptup.io/help/error',
        method: 'POST',
        data: JSON.stringify({
          name: (error.name || '').substring(0, 50),
          message: (error_message || '').substring(0, 200),
          url: (url || '').substring(0, 100),
          line: line || 0,
          col: col || 0,
          trace: error.stack || '',
          version: version || cryptup_version() || 'unknown',
          environment: env || environment(),
        }),
        dataType: 'json',
        crossDomain: true,
        contentType: 'application/json; charset=UTF-8',
        async: true,
        success: function (response) {
          if(response.saved === true) {
            console.log('%cFlowCrypt ERROR:' + user_log_message, 'font-weight: bold;');
          } else {
            console.log('%cFlowCrypt EXCEPTION:' + user_log_message, 'font-weight: bold;');
          }
        },
        error: function (XMLHttpRequest, status, error) {
          console.log('%cFlowCrypt FAILED:' + user_log_message, 'font-weight: bold;');
        },
      });
    } catch(ajax_err) {
      console.log(ajax_err.message);
      console.log('%cFlowCrypt ISSUE:' + user_log_message, 'font-weight: bold;');
    }
    try {
      if(typeof storage.get === 'function' && typeof storage.set === 'function') {
        tool.env.increment('error');
        storage.get(null, ['errors'], function (s) {
          if(typeof s.errors === 'undefined') {
            s.errors = [];
          }
          s.errors.unshift(error.stack || error_message);
          storage.set(null, s);
        });
      }
    } catch (storage_err) {
      console.log('failed to locally log error "' + String(error_message) + '" because: ' + storage_err.message);
    }
    return true;
  }

  function try_wrapper(code) {
    return function () {
      try {
        return code();
      } catch(code_err) {
        handle_exception(code_err);
      }
    };
  }

  function handle_exception(exception) {
    try {
      var caller_line = exception.stack.split('\n')[1];
      var matched = caller_line.match(/\.js:([0-9]+):([0-9]+)\)?/);
      var line = Number(matched[1]);
      var col = Number(matched[2]);
    } catch(line_err) {
      var line = 0;
      var col = 0;
    }
    try {
      tool.browser.message.send(null, 'runtime', null, function (runtime) {
        handle_error(exception.message, window.location.href, line, col, exception, true, runtime.version, runtime.environment);
      });
    } catch(message_err) {
      handle_error(exception.message, window.location.href, line, col, exception, true);
    }
  }

  function report(name, details) {
    try {
      throw new Error(name);
    } catch(e) {
      if(typeof details !== 'string') {
        try {
          details = JSON.stringify(details);
        } catch(stringify_error) {
          details = '(could not stringify details "' + String(details) + '" in catcher.report because: ' + stringify_error.message + ')';
        }
      }
      e.stack = e.stack + '\n\n\ndetails: ' + details;
      handle_exception(e);
    }
  }

  function log(name, details) {
    name = 'catcher.log: ' + name;
    console.log(name);
    try {
      throw new Error(name);
    } catch(e) {
      if(typeof details !== 'string') {
        try {
          details = JSON.stringify(details);
        } catch(stringify_error) {
          details = '(could not stringify details "' + String(details) + '" in catcher.log because: ' + stringify_error.message + ')';
        }
      }
      e.stack = e.stack + '\n\n\ndetails: ' + details;
      try {
        storage.get(null, ['errors'], function (s) {
          if(typeof s.errors === 'undefined') {
            s.errors = [];
          }
          s.errors.unshift(e.stack || error_message);
          storage.set(null, s);
        });
      } catch (storage_err) {
        console.log('failed to locally log info "' + String(name) + '" because: ' + storage_err.message);
      }
    }
  }

  function promise_error_alert(note) {
    return function (error) {
      console.log(error);
      alert(note);
    };
  }

  function wrapped_Promise(f) {
    return new Promise(function(resolve, reject) {
      try {
        f(resolve, reject);
      } catch(e) {
        handle_exception(e);
        reject({code: null, message: 'Error happened, please write me at human@flowcrypt.com to fix this\n\nError: ' + e.message, internal: 'exception'});
      }
    })
  }

  function environment(url) {
    if(!url) {
      url = window.location.href;
    }
    var browser_name = tool.env.browser().name;
    var env = 'unknown';
    if(url.indexOf('bnjglocicd') !== -1) {
      env = 'ex:prod';
    } else if(url.indexOf('nmelpmhpel') !== -1 || url.indexOf('blfdgihad') !== -1) {
      env = 'ex:dev';
    } else if(url.indexOf('himcfccebk') !== -1) {
      env = 'ex:test';
    } else if (url.indexOf('l.flowcrypt.com') !== -1 || url.indexOf('127.0.0.1') !== -1) {
      env = 'web:local';
    } else if (url.indexOf('cryptup.org') !== -1 || url.indexOf('flowcrypt.com') !== -1) {
      env = 'web:prod';
    } else if (/chrome-extension:\/\/[a-z]{32}\/.+/.test(url)) {
      env = 'ex:fork';
    } else if (url.indexOf('mail.google.com') !== -1) {
      env = 'ex:script:gmail';
    } else if (url.indexOf('inbox.google.com') !== -1) {
      env = 'ex:script:inbox';
    } else if (/moz-extension:\/\/.+/.test(url)) {
      env = 'ex';
    }
    return browser_name + ':' + env;
  }

  function test() {
    this_will_fail();
  }

  function cryptup_version(format) {
    if(format === 'int') {
      return RUNTIME.version ? Number(RUNTIME.version.replace(/\./g, '')) : null;
    } else {
      return RUNTIME.version || null;
    }
  }

  function figure_out_flowcrypt_runtime() {
    if(window.is_bare_engine !== true) {
      try {
        RUNTIME.version = chrome.runtime.getManifest().version;
      } catch(err) {
      }
      RUNTIME.environment = environment();
      if(!tool.env.is_background_script() && tool.env.is_extension()) {
        tool.browser.message.send(null, 'runtime', null, function (extension_runtime) {
          if(typeof extension_runtime !== 'undefined') {
            RUNTIME = extension_runtime;
          } else {
            setTimeout(figure_out_flowcrypt_runtime, 200);
          }
        });
      }
    }
  }

  function produce_new_stack_trace() {
    try {
      test();
    } catch(e) {
      return e.stack.split('\n').splice(3).join('\n'); // return stack after removing first 3 lines
    }
  }

  var _c = { // web and extension code
    handle_error: handle_error,
    handle_exception: handle_exception,
    report: report,
    log: log,
    version: cryptup_version,
    try: try_wrapper,
    environment: environment,
    test: test,
    Promise: wrapped_Promise,
    promise_error_alert: promise_error_alert,
    stack_trace: produce_new_stack_trace,
  };

  if(window.is_bare_engine !== true) {
    window.catcher = _c;
  }

  if(typeof exports === 'object') {
    exports.catcher = _c;
  }

})();


(function ( /* EXTENSIONS AND CONFIG */ ) {

  if(typeof window.openpgp !== 'undefined' && typeof window.openpgp.config !== 'undefined' && typeof window.openpgp.config.versionstring !== 'undefined' && typeof window.openpgp.config.commentstring !== 'undefined') {
    window.openpgp.config.versionstring = 'FlowCrypt ' + (catcher.version() || '') + ' Gmail Encryption flowcrypt.com';
    window.openpgp.config.commentstring = 'Seamlessly send, receive and search encrypted email';
  }

  RegExp.escape = function (s) {
    return s.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&');
  };

  String.prototype.repeat = String.prototype.repeat || function(count) {
    if (this == null) {
      throw new TypeError('can\'t convert ' + this + ' to object');
    }
    var str = '' + this;
    count = +count;
    if (count != count) {
      count = 0;
    }
    if (count < 0) {
      throw new RangeError('repeat count must be non-negative');
    }
    if (count == Infinity) {
      throw new RangeError('repeat count must be less than infinity');
    }
    count = Math.floor(count);
    if (str.length == 0 || count == 0) {
      return '';
    }
    // Ensuring count is a 31-bit integer allows us to heavily optimize the
    // main part. But anyway, most current (August 2014) browsers can't handle
    // strings 1 << 28 chars or longer, so:
    if (str.length * count >= 1 << 28) {
      throw new RangeError('repeat count must not overflow maximum string size');
    }
    var rpt = '';
    for (;;) {
      if ((count & 1) == 1) {
        rpt += str;
      }
      count >>>= 1;
      if (count == 0) {
        break;
      }
      str += str;
    }
    // Could we try:
    // return Array(count + 1).join(this);
    return rpt;
  };

  Promise.prototype.validate = Promise.prototype.validate || function(validity_checker) {
    var original_promise = this;
    return catcher.Promise(function(resolve, reject) {
      original_promise.then(function(response) {
        if(typeof response === 'object') {
          if(validity_checker(response)) {
            resolve(response);
          } else {
            reject({code: null, message: 'Could not validate result', internal: 'validate'});
          }
        } else {
          reject({code: null, message: 'Could not validate result: not an object', internal: 'validate'});
        }
      }, reject);
    });
  };

  Promise.prototype.done = Promise.prototype.done || function(next) {
    return this.then(function(x) {
      next(true, x);
    }, function(x) {
      next(false, x);
    });
  };

  Promise.sequence = Promise.sequence || function (promise_factories) {
    return catcher.Promise(function (resolve, reject) {
      var all_results = [];
      return promise_factories.reduce(function(chained_promises, create_promise) {
        return chained_promises.then(function(promise_result) {
          all_results.push(promise_result);
          return create_promise();
        });
      }, Promise.resolve('remove+me')).then(function(last_promise_result) {
        all_results.push(last_promise_result);
        resolve(all_results.splice(1)); // remove first bogus promise result
      });
    });
  }

})();

if(window.flowcrypt_profile) {
  window.flowcrypt_profile.add('common');
}
