/*
 * Copyright (C) 2003-2005 Samuel Mimram
 *
 * This file is part of Ocaml-ssl.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

/**
 * Libssl bindings for OCaml.
 *
 * @author Samuel Mimram
 */

/*
 * WARNING: because of thread callbacks, all ssl functions should be in
 * blocking sections.
 */

#include <unistd.h>
#include <string.h>
#include <assert.h>

#include <caml/alloc.h>
#include <caml/callback.h>
#include <caml/custom.h>
#include <caml/fail.h>
#include <caml/memory.h>
#include <caml/mlvalues.h>
#include <caml/signals.h>
#include <caml/unixsupport.h>
#include <caml/bigarray.h>

#include <openssl/ssl.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/tls1.h>
#include <openssl/x509v3.h>

#include "ocaml_ssl.h"

#ifdef WIN32
#include <windows.h>
#else
#include <pthread.h>
#endif

static int client_verify_callback(int, X509_STORE_CTX *);
static DH *load_dh_param(const char *dhfile);

/*******************
 * Data structures *
 *******************/

/* Contexts */

#define Ctx_val(v) (*((SSL_CTX**)Data_custom_val(v)))

static void finalize_ctx(value block)
{
  SSL_CTX *ctx = Ctx_val(block);
  SSL_CTX_free(ctx);
}

static struct custom_operations ctx_ops =
{
  "ocaml_ssl_ctx",
  finalize_ctx,
  custom_compare_default,
  custom_hash_default,
  custom_serialize_default,
  custom_deserialize_default
};

/* Sockets */

#define SSL_val(v) (*((SSL**)Data_custom_val(v)))

static void finalize_ssl_socket(value block)
{
  SSL *ssl = SSL_val(block);
  SSL_free(ssl);
}

static struct custom_operations socket_ops =
{
  "ocaml_ssl_socket",
  finalize_ssl_socket,
  custom_compare_default,
  custom_hash_default,
  custom_serialize_default,
  custom_deserialize_default
};

/* Option types */

#define Val_none Val_int(0)

static value Val_some(value v)
{
  CAMLparam1(v);
  CAMLlocal1(some);
  some = caml_alloc(1, 0);
  Store_field(some, 0, v);
  CAMLreturn(some);
}


/******************
 * Initialization *
 ******************/

#ifdef WIN32
struct CRYPTO_dynlock_value
{
  HANDLE mutex;
};

static HANDLE *mutex_buf = NULL;

static void locking_function(int mode, int n, const char *file, int line)
{
  if (mode & CRYPTO_LOCK)
    WaitForSingleObject(mutex_buf[n], INFINITE);
  else
    ReleaseMutex(mutex_buf[n]);
}

static struct CRYPTO_dynlock_value *dyn_create_function(const char *file, int line)
{
  struct CRYPTO_dynlock_value *value;

  value = malloc(sizeof(struct CRYPTO_dynlock_value));
  if (!value)
    return NULL;
  if (!(value->mutex = CreateMutex(NULL, FALSE, NULL)))
    {
      free(value);
      return NULL;
    }

  return value;
}

static void dyn_lock_function(int mode, struct CRYPTO_dynlock_value *l, const char *file, int line)
{
  if (mode & CRYPTO_LOCK)
    WaitForSingleObject(l->mutex, INFINITE);
  else
    ReleaseMutex(l->mutex);
}

static void dyn_destroy_function(struct CRYPTO_dynlock_value *l, const char *file, int line)
{
  CloseHandle(l->mutex);
  free(l);
}
#else
struct CRYPTO_dynlock_value
{
  pthread_mutex_t mutex;
};

static pthread_mutex_t *mutex_buf = NULL;

static void locking_function(int mode, int n, const char *file, int line)
{
  if (mode & CRYPTO_LOCK)
      pthread_mutex_lock(&mutex_buf[n]);
  else
    pthread_mutex_unlock(&mutex_buf[n]);
}

static unsigned long id_function(void)
{
  return ((unsigned long) pthread_self());
}

static struct CRYPTO_dynlock_value *dyn_create_function(const char *file, int line)
{
  struct CRYPTO_dynlock_value *value;

  value = malloc(sizeof(struct CRYPTO_dynlock_value));
  if (!value)
    return NULL;
  pthread_mutex_init(&value->mutex, NULL);

  return value;
}

static void dyn_lock_function(int mode, struct CRYPTO_dynlock_value *l, const char *file, int line)
{
  if (mode & CRYPTO_LOCK)
    pthread_mutex_lock(&l->mutex);
  else
    pthread_mutex_unlock(&l->mutex);
}

static void dyn_destroy_function(struct CRYPTO_dynlock_value *l, const char *file, int line)
{
  pthread_mutex_destroy(&l->mutex);
  free(l);
}
#endif

CAMLprim value ocaml_ssl_init(value use_threads)
{
  int i;

  SSL_library_init();
  SSL_load_error_strings();

  if(Int_val(use_threads))
  {
#ifdef WIN32
    mutex_buf = malloc(CRYPTO_num_locks() * sizeof(HANDLE));
#else
    mutex_buf = malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
#endif
    assert(mutex_buf);
    for (i = 0; i < CRYPTO_num_locks(); i++)
#ifdef WIN32
      mutex_buf[i] = CreateMutex(NULL, FALSE, NULL);
#else
      pthread_mutex_init(&mutex_buf[i], NULL);
#endif
    CRYPTO_set_locking_callback(locking_function);
#ifndef WIN32
    /* Windows does not require id_function, see threads(3) */
    CRYPTO_set_id_callback(id_function);
#endif
    CRYPTO_set_dynlock_create_callback(dyn_create_function);
    CRYPTO_set_dynlock_lock_callback(dyn_lock_function);
    CRYPTO_set_dynlock_destroy_callback(dyn_destroy_function);
  }

  return Val_unit;
}

CAMLprim value ocaml_ssl_get_error_string(value unit)
{
  char buf[256];
  ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
  return caml_copy_string(buf);
}


/*****************************
 * Context-related functions *
 *****************************/

static int protocol_flags[] = {
    SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3,
    SSL_OP_NO_SSLv3,
    SSL_OP_NO_TLSv1,
#ifdef HAVE_TLS11
    SSL_OP_NO_TLSv1_1
#else
    0 /* not supported, nothing to disable */
#endif
    ,
#ifdef HAVE_TLS12
    SSL_OP_NO_TLSv1_2
#else
    0 /* not supported ,nothing to disable */
#endif
    ,
#ifdef HAVE_TLS13
    SSL_OP_NO_TLSv1_3
#else
    0 /* not supported, nothing to disable */
#endif
};

static const SSL_METHOD *get_method(int protocol, int type)
{
  const SSL_METHOD *method = NULL;

  caml_enter_blocking_section();
  switch (protocol)
  {
    case 0:
      switch (type)
      {
        case 0:
          method = SSLv23_client_method();
          break;

        case 1:
          method = SSLv23_server_method();
          break;

        case 2:
          method = SSLv23_method();
          break;
      }
      break;

#ifndef OPENSSL_NO_SSL3
    case 1:
      switch (type)
      {
        case 0:
          method = SSLv3_client_method();
          break;

        case 1:
          method = SSLv3_server_method();
          break;

        case 2:
          method = SSLv3_method();
          break;
      }
      break;
#endif

    case 2:
      switch (type)
      {
        case 0:
          method = TLSv1_client_method();
          break;

        case 1:
          method = TLSv1_server_method();
          break;

        case 2:
          method = TLSv1_method();
          break;
      }
      break;

    case 3:
#ifdef HAVE_TLS11
      switch (type)
      {
        case 0:
          method = TLSv1_1_client_method();
          break;

        case 1:
          method = TLSv1_1_server_method();
          break;

        case 2:
          method = TLSv1_1_method();
          break;
      }
#endif
      break;

    case 4:
#ifdef HAVE_TLS12
      switch (type)
      {
        case 0:
          method = TLSv1_2_client_method();
          break;

        case 1:
          method = TLSv1_2_server_method();
          break;

        case 2:
          method = TLSv1_2_method();
          break;
      }
#endif
      break;

    case 5:
#ifdef HAVE_TLS13
      switch (type)
      {
        case 0:
          method = TLS_client_method();
          break;

        case 1:
          method = TLS_server_method();
          break;

        case 2:
          method = TLS_method();
          break;
      }
#endif
      break;

    default:
      caml_leave_blocking_section();
      caml_invalid_argument("Unknown method (this should not have happened, please report).");
      break;
  }
  caml_leave_blocking_section();

  if (method == NULL)
    caml_raise_constant(*caml_named_value("ssl_exn_method_error"));

  return method;
}

CAMLprim value ocaml_ssl_create_context(value protocol, value type)
{
  value block;
  SSL_CTX *ctx;
  const SSL_METHOD *method = get_method(Int_val(protocol), Int_val(type));

  caml_enter_blocking_section();
  ctx = SSL_CTX_new(method);
  if (!ctx)
  {
    caml_leave_blocking_section();
    caml_raise_constant(*caml_named_value("ssl_exn_context_error"));
  }
  /* In non-blocking mode, accept a buffer with a different address on
     a write retry (since the GC may need to move it). In blocking
     mode, hide SSL_ERROR_WANT_(READ|WRITE) from us. */
  SSL_CTX_set_mode(ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_AUTO_RETRY);
  caml_leave_blocking_section();

  block = caml_alloc_custom(&ctx_ops, sizeof(SSL_CTX*), 0, 1);
  Ctx_val(block) = ctx;
  return block;
}

CAMLprim value ocaml_ssl_ctx_use_certificate(value context, value cert, value privkey)
{
  CAMLparam3(context, cert, privkey);
  SSL_CTX *ctx = Ctx_val(context);
  char *cert_name = String_val(cert);
  char *privkey_name = String_val(privkey);
  char buf[256];

  caml_enter_blocking_section();
  if (SSL_CTX_use_certificate_chain_file(ctx, cert_name) <= 0)
  {
    ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
    caml_leave_blocking_section();
    caml_raise_with_arg(*caml_named_value("ssl_exn_certificate_error"), caml_copy_string(buf));
  }
  if (SSL_CTX_use_PrivateKey_file(ctx, privkey_name, SSL_FILETYPE_PEM) <= 0)
  {
    ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
    caml_leave_blocking_section();
    caml_raise_with_arg(*caml_named_value("ssl_exn_private_key_error"), caml_copy_string(buf));
  }
  if (!SSL_CTX_check_private_key(ctx))
  {
    caml_leave_blocking_section();
    caml_raise_constant(*caml_named_value("ssl_exn_unmatching_keys"));
  }
  caml_leave_blocking_section();

  CAMLreturn(Val_unit);
}

CAMLprim value ocaml_ssl_get_verify_result(value socket)
{
  CAMLparam1(socket);
  int ans;
  SSL *ssl = SSL_val(socket);

  caml_enter_blocking_section();
  ans = SSL_get_verify_result(ssl);
  caml_leave_blocking_section();

  CAMLreturn(Val_int(ans));
}

CAMLprim value ocaml_ssl_get_client_verify_callback_ptr(value unit)
{
  return (value)client_verify_callback;
}

static int client_verify_callback_verbose = 1;

CAMLprim value ocaml_ssl_set_client_verify_callback_verbose(value verbose)
{
  CAMLparam1(verbose);

  client_verify_callback_verbose = Bool_val(verbose);

  CAMLreturn(Val_unit);
}

CAMLprim value ocaml_ssl_ctx_set_verify(value context, value vmode, value vcallback)
{
  CAMLparam3(context, vmode, vcallback);
  SSL_CTX *ctx = Ctx_val(context);
  int mode = 0;
  value mode_tl = vmode;
  int (*callback) (int, X509_STORE_CTX*) = NULL;

  if (Is_long(vmode))
    mode = SSL_VERIFY_NONE;

  while (Is_block(mode_tl))
  {
    switch(Int_val(Field(mode_tl, 0)))
    {
      case 0:
        mode |= SSL_VERIFY_PEER;
        break;

      case 1:
        mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT | SSL_VERIFY_PEER;
        break;

      case 2:
        mode |= SSL_VERIFY_CLIENT_ONCE | SSL_VERIFY_PEER;
        break;

      default:
        caml_invalid_argument("mode");
    }

    mode_tl = Field(mode_tl, 1);
  }

  if (Is_block(vcallback))
    callback = (int(*) (int, X509_STORE_CTX*))Field(vcallback, 0);

  caml_enter_blocking_section();
  SSL_CTX_set_verify(ctx, mode, callback);
  caml_leave_blocking_section();

  CAMLreturn(Val_unit);
}

CAMLprim value ocaml_ssl_ctx_set_verify_depth(value context, value vdepth)
{
  SSL_CTX *ctx = Ctx_val(context);
  int depth = Int_val(vdepth);

  if (depth < 0)
    caml_invalid_argument("depth");

  caml_enter_blocking_section();
  SSL_CTX_set_verify_depth(ctx, depth);
  caml_leave_blocking_section();

  return Val_unit;
}

CAMLprim value ocaml_ssl_ctx_set_client_CA_list_from_file(value context, value vfilename)
{
  CAMLparam2(context, vfilename);
  SSL_CTX *ctx = Ctx_val(context);
  char *filename = String_val(vfilename);
  STACK_OF(X509_NAME) *cert_names;
  char buf[256];

  caml_enter_blocking_section();
  cert_names = SSL_load_client_CA_file(filename);
  if (cert_names != 0)
    SSL_CTX_set_client_CA_list(ctx, cert_names);
  else
  {
    ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
    caml_leave_blocking_section();
    caml_raise_with_arg(*caml_named_value("ssl_exn_certificate_error"), caml_copy_string(buf));
  }
  caml_leave_blocking_section();

  CAMLreturn(Val_unit);
}

#ifdef HAVE_ALPN
static int get_alpn_buffer_length(value vprotos)
{
  value protos_tl = vprotos;
  int total_len = 0;
  while (protos_tl != Val_emptylist)
  {
    total_len += caml_string_length(Field(protos_tl, 0)) + 1;
    protos_tl = Field(protos_tl, 1);
  }
  return total_len;
}

static void build_alpn_protocol_buffer(value vprotos, unsigned char *protos)
{
  int proto_idx = 0;
  while (vprotos != Val_emptylist)
  {
    value head = Field(vprotos, 0);
    int len = caml_string_length(head);
    protos[proto_idx++] = len;

    int i;
    for (i = 0; i < len; i++)
      protos[proto_idx++] = Byte_u(head, i);
    vprotos = Field(vprotos, 1);
  }
}

CAMLprim value ocaml_ssl_ctx_set_alpn_protos(value context, value vprotos)
{
  CAMLparam2(context, vprotos);
  SSL_CTX *ctx = Ctx_val(context);

  int total_len = get_alpn_buffer_length(vprotos);
  unsigned char protos[total_len];
  build_alpn_protocol_buffer(vprotos, protos);

  caml_enter_blocking_section();
  SSL_CTX_set_alpn_protos(ctx, protos, sizeof(protos));
  caml_leave_blocking_section();

  CAMLreturn(Val_unit);
}

static value build_alpn_protocol_list(const unsigned char *protocol_buffer, unsigned int len)
{
  CAMLparam0();
  CAMLlocal3(protocol_list, current, tail);

  int idx = 0;
  protocol_list = Val_emptylist;

  while (idx < len)
  {
    int proto_len = (int) protocol_buffer[idx++];
    char proto[proto_len + 1];
    int i;
    for (i = 0; i < proto_len; i++)
      proto[i] = (char) protocol_buffer[idx++];
    proto[proto_len] = '\0';

    tail = caml_alloc(2, 0);
    Store_field(tail, 0, caml_copy_string(proto));
    Store_field(tail, 1, Val_emptylist);

    if (protocol_list == Val_emptylist)
      protocol_list = tail;
    else
      Store_field(current, 1, tail);

    current = tail;
  }

  CAMLreturn(protocol_list);
}

static int alpn_select_cb(SSL *ssl,
                          const unsigned char **out,
                          unsigned char *outlen,
                          const unsigned char *in,
                          unsigned int inlen,
                          void *arg)
{
  CAMLparam0();
  CAMLlocal3(protocol_list, selected_protocol, selected_protocol_opt);

  int len;

  caml_leave_blocking_section();
  protocol_list = build_alpn_protocol_list(in, inlen);
  selected_protocol_opt = caml_callback(*((value*)arg), protocol_list);

  if (selected_protocol_opt == Val_none)
    return SSL_TLSEXT_ERR_NOACK;

  selected_protocol = Field(selected_protocol_opt, 0);
  len = caml_string_length(selected_protocol);
  *out = String_val(selected_protocol);
  *outlen = len;
  caml_enter_blocking_section();

  return SSL_TLSEXT_ERR_OK;
}

CAMLprim value ocaml_ssl_ctx_set_alpn_select_callback(value context, value cb)
{
  CAMLparam2(context, cb);
  SSL_CTX *ctx = Ctx_val(context);

  value *select_cb;

  select_cb = malloc(sizeof(value));
  *select_cb = cb;
  caml_register_global_root(select_cb);

  caml_enter_blocking_section();
  SSL_CTX_set_alpn_select_cb(ctx, alpn_select_cb, select_cb);
  caml_leave_blocking_section();

  CAMLreturn(Val_unit);
}
#else
CAMLprim value ocaml_ssl_ctx_set_alpn_protos(value context, value vprotos)
{
  CAMLparam2(context, vprotos);
  caml_raise_constant(*caml_named_value("ssl_exn_method_error"));
  CAMLreturn(Val_unit);
}

CAMLprim value ocaml_ssl_ctx_set_alpn_select_callback(value context, value cb)
{
  CAMLparam2(context, cb);
  caml_raise_constant(*caml_named_value("ssl_exn_method_error"));
  CAMLreturn(Val_unit);
}
#endif

static int pem_passwd_cb(char *buf, int size, int rwflag, void *userdata)
{
  value s;
  int len;

  caml_leave_blocking_section();
  s = caml_callback(*((value*)userdata), Val_int(rwflag));
  len = caml_string_length(s);
  assert(len <= size);
  memcpy(buf, String_val(s), len);
  caml_enter_blocking_section();

  return len;
}

CAMLprim value ocaml_ssl_ctx_set_default_passwd_cb(value context, value cb)
{
  CAMLparam2(context, cb);
  SSL_CTX *ctx = Ctx_val(context);
  value *pcb;

  /* TODO: this never gets freed or even unregistered */
  pcb = malloc(sizeof(value));
  *pcb = cb;
  caml_register_global_root(pcb);

  caml_enter_blocking_section();
  SSL_CTX_set_default_passwd_cb(ctx, pem_passwd_cb);
  SSL_CTX_set_default_passwd_cb_userdata(ctx, pcb);
  caml_leave_blocking_section();

  CAMLreturn(Val_unit);
}

CAMLprim value ocaml_ssl_ctx_honor_cipher_order(value context)
{
 CAMLparam1(context);
 SSL_CTX *ctx = Ctx_val(context);

 SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
 CAMLreturn(Val_unit);
}

/****************************
 * Cipher-related functions *
 ****************************/

CAMLprim value ocaml_ssl_ctx_set_cipher_list(value context, value ciphers_string)
{
  CAMLparam2(context, ciphers_string);
  SSL_CTX *ctx = Ctx_val(context);
  char *ciphers = String_val(ciphers_string);

  if(*ciphers == 0)
    caml_raise_constant(*caml_named_value("ssl_exn_cipher_error"));

  caml_enter_blocking_section();
  if(SSL_CTX_set_cipher_list(ctx, ciphers) != 1)
  {
    caml_leave_blocking_section();
    caml_raise_constant(*caml_named_value("ssl_exn_cipher_error"));
  }
  caml_leave_blocking_section();

  CAMLreturn(Val_unit);
}

CAMLprim value ocaml_ssl_disable_protocols(value context, value protocol_list)
{
  CAMLparam2(context, protocol_list);
  SSL_CTX *ctx = Ctx_val(context);
  int flags = caml_convert_flag_list(protocol_list, protocol_flags);
  caml_enter_blocking_section();
  SSL_CTX_set_options(ctx, flags);
  caml_leave_blocking_section();

  CAMLreturn(Val_unit);
}

CAMLprim value ocaml_ssl_get_current_cipher(value socket)
{
  CAMLparam1(socket);
  SSL *ssl = SSL_val(socket);

  caml_enter_blocking_section();
  SSL_CIPHER *cipher = (SSL_CIPHER*)SSL_get_current_cipher(ssl);
  caml_leave_blocking_section();
  if (!cipher)
    caml_raise_constant(*caml_named_value("ssl_exn_cipher_error"));

  CAMLreturn((value)cipher);
}

CAMLprim value ocaml_ssl_get_cipher_description(value vcipher)
{
  char buf[1024];
  SSL_CIPHER *cipher = (SSL_CIPHER*)vcipher;

  caml_enter_blocking_section();
  SSL_CIPHER_description(cipher, buf, 1024);
  caml_leave_blocking_section();

  return caml_copy_string(buf);
}

CAMLprim value ocaml_ssl_get_cipher_name(value vcipher)
{
  const char *name;
  SSL_CIPHER *cipher = (SSL_CIPHER*)vcipher;

  caml_enter_blocking_section();
  name = SSL_CIPHER_get_name(cipher);
  caml_leave_blocking_section();

  return caml_copy_string(name);
}

CAMLprim value ocaml_ssl_get_cipher_version(value vcipher)
{
  const char *version;
  SSL_CIPHER *cipher = (SSL_CIPHER*)vcipher;

  caml_enter_blocking_section();
  version = SSL_CIPHER_get_version(cipher);
  caml_leave_blocking_section();

  return caml_copy_string(version);
}

CAMLprim value ocaml_ssl_ctx_init_dh_from_file(value context, value dh_file_path)
{
  CAMLparam2(context, dh_file_path);
  DH *dh = NULL;
  SSL_CTX *ctx = Ctx_val(context);
  char *dh_cfile_path = String_val(dh_file_path);

  if(*dh_cfile_path == 0)
    caml_raise_constant(*caml_named_value("ssl_exn_diffie_hellman_error"));

  dh = load_dh_param(dh_cfile_path);
  caml_enter_blocking_section();
  if (dh != NULL){
    if(SSL_CTX_set_tmp_dh(ctx,dh) != 1){
      caml_leave_blocking_section();
      caml_raise_constant(*caml_named_value("ssl_exn_diffie_hellman_error"));
    }
    SSL_CTX_set_options(ctx, SSL_OP_SINGLE_DH_USE);
    caml_leave_blocking_section();
    DH_free(dh);
  }
  else{
      caml_leave_blocking_section();
      caml_raise_constant(*caml_named_value("ssl_exn_diffie_hellman_error"));
  }
  CAMLreturn(Val_unit);
}

#ifdef HAVE_EC
CAMLprim value ocaml_ssl_ctx_init_ec_from_named_curve(value context, value curve_name)
{
  CAMLparam2(context, curve_name);
  EC_KEY *ecdh = NULL;
  int nid = 0;
  SSL_CTX *ctx = Ctx_val(context);
  char *ec_curve_name = String_val(curve_name);

  if(*ec_curve_name == 0)
    caml_raise_constant(*caml_named_value("ssl_exn_ec_curve_error"));

  nid = OBJ_sn2nid(ec_curve_name);
  if(nid == 0){
    caml_raise_constant(*caml_named_value("ssl_exn_ec_curve_error"));
  }

  caml_enter_blocking_section();
  ecdh = EC_KEY_new_by_curve_name(nid);
  if(ecdh != NULL){
    if(SSL_CTX_set_tmp_ecdh(ctx,ecdh) != 1){
      caml_leave_blocking_section();
      caml_raise_constant(*caml_named_value("ssl_exn_ec_curve_error"));
    }
    SSL_CTX_set_options(ctx, SSL_OP_SINGLE_ECDH_USE);
    caml_leave_blocking_section();
    EC_KEY_free(ecdh);
  }
  else{
    caml_leave_blocking_section();
    caml_raise_constant(*caml_named_value("ssl_exn_ec_curve_error"));
  }
  CAMLreturn(Val_unit);
}
#else
CAMLprim value ocaml_ssl_ctx_init_ec_from_named_curve(value context, value curve_name)
{
    CAMLparam2(context, curve_name);
    caml_raise_constant(*caml_named_value("ssl_exn_ec_curve_error"));
    CAMLreturn(Val_unit);
}
#endif
/*********************************
 * Certificate-related functions *
 *********************************/

#define Cert_val(v) (*((X509**)Data_custom_val(v)))

static void finalize_cert(value block)
{
  X509 *cert = Cert_val(block);
  X509_free(cert);
}

static struct custom_operations cert_ops =
{
  "ocaml_ssl_cert",
  finalize_cert,
  custom_compare_default,
  custom_hash_default,
  custom_serialize_default,
  custom_deserialize_default
};

CAMLprim value ocaml_ssl_read_certificate(value vfilename)
{
  value block;
  char *filename = String_val(vfilename);
  X509 *cert = NULL;
  FILE *fh = NULL;
  char buf[256];

  if((fh = fopen(filename, "r")) == NULL)
    caml_raise_with_arg(*caml_named_value("ssl_exn_certificate_error"), caml_copy_string("couldn't open certificate file"));

  caml_enter_blocking_section();
  if((PEM_read_X509(fh, &cert, 0, 0)) == NULL)
  {
    fclose(fh);
    ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
    caml_leave_blocking_section();
    caml_raise_with_arg(*caml_named_value("ssl_exn_certificate_error"), caml_copy_string(buf));
  }
  fclose(fh);
  caml_leave_blocking_section();

  block = caml_alloc_custom(&cert_ops, sizeof(X509*), 0, 1);
  Cert_val(block) = cert;
  return block;
}

CAMLprim value ocaml_ssl_write_certificate(value vfilename, value certificate)
{
  CAMLparam2(vfilename, certificate);
  char *filename = String_val(vfilename);
  X509 *cert = Cert_val(certificate);
  FILE *fh = NULL;
  char buf[256];

  if((fh = fopen(filename, "w")) == NULL)
    caml_raise_with_arg(*caml_named_value("ssl_exn_certificate_error"), caml_copy_string("couldn't open certificate file"));

  caml_enter_blocking_section();
  if(PEM_write_X509(fh, cert) == 0)
  {
    fclose(fh);
    ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
    caml_leave_blocking_section();
    caml_raise_with_arg(*caml_named_value("ssl_exn_certificate_error"), caml_copy_string(buf));
  }
  fclose(fh);
  caml_leave_blocking_section();

  CAMLreturn(Val_unit);
}

CAMLprim value ocaml_ssl_get_certificate(value socket)
{
  CAMLparam1(socket);
  SSL *ssl = SSL_val(socket);
  char buf[256];

  caml_enter_blocking_section();
  X509 *cert = SSL_get_peer_certificate(ssl);
  caml_leave_blocking_section();

  if (!cert) {
    ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
    caml_raise_with_arg(*caml_named_value("ssl_exn_certificate_error"), caml_copy_string(buf));
  }

  CAMLlocal1(block);
  block = caml_alloc_final(2, finalize_cert, 0, 1);
  (*((X509 **) Data_custom_val(block))) = cert;
  CAMLreturn(block);
}

CAMLprim value ocaml_ssl_get_issuer(value certificate)
{
  CAMLparam1(certificate);
  X509 *cert = Cert_val(certificate);

  caml_enter_blocking_section();
  char *issuer = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
  caml_leave_blocking_section();
  if (!issuer) caml_raise_not_found ();

  CAMLreturn(caml_copy_string(issuer));
}

CAMLprim value ocaml_ssl_get_subject(value certificate)
{
  CAMLparam1(certificate);
  X509 *cert = Cert_val(certificate);

  caml_enter_blocking_section();
  char *subject = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
  caml_leave_blocking_section();
  if (subject == NULL) caml_raise_not_found ();

  CAMLreturn(caml_copy_string(subject));
}

CAMLprim value ocaml_ssl_ctx_load_verify_locations(value context, value ca_file, value ca_path)
{
  CAMLparam3(context, ca_file, ca_path);
  SSL_CTX *ctx = Ctx_val(context);
  char *CAfile = String_val(ca_file);
  char *CApath = String_val(ca_path);

  if(*CAfile == 0)
    CAfile = NULL;
  if(*CApath == 0)
    CApath = NULL;

  caml_enter_blocking_section();
  if(SSL_CTX_load_verify_locations(ctx, CAfile, CApath) != 1)
  {
    caml_leave_blocking_section();
    caml_invalid_argument("cafile or capath");
  }
  caml_leave_blocking_section();

  CAMLreturn(Val_unit);
}

CAMLprim value ocaml_ssl_ctx_set_default_verify_paths(value context)
{
  CAMLparam1(context);
  int ret;
  SSL_CTX *ctx = Ctx_val(context);

  caml_enter_blocking_section();
  ret = SSL_CTX_set_default_verify_paths(ctx);
  caml_leave_blocking_section();

  CAMLreturn(Val_bool(ret));
}

/*************************
 * Operations on sockets *
 *************************/

CAMLprim value ocaml_ssl_get_file_descr(value socket)
{
  CAMLparam1(socket);
  SSL *ssl = SSL_val(socket);
  int fd;

  caml_enter_blocking_section();
  fd = SSL_get_fd(ssl);
  caml_leave_blocking_section();

  CAMLreturn(Val_int(fd));
}

CAMLprim value ocaml_ssl_embed_socket(value socket_, value context)
{
  CAMLparam1(context);
  CAMLlocal1(block);
#ifdef Socket_val
  SOCKET socket = Socket_val(socket_);
#else
  int socket = Int_val(socket_);
#endif
  SSL_CTX *ctx = Ctx_val(context);
  SSL *ssl;

  block = caml_alloc_custom(&socket_ops, sizeof(SSL*), 0, 1);

  if (socket < 0)
    caml_raise_constant(*caml_named_value("ssl_exn_invalid_socket"));
  caml_enter_blocking_section();
  ssl = SSL_new(ctx);
  if (!ssl)
  {
    caml_leave_blocking_section();
    caml_raise_constant(*caml_named_value("ssl_exn_handler_error"));
  }
  SSL_set_fd(ssl, socket);
  caml_leave_blocking_section();
  SSL_val(block) = ssl;

  CAMLreturn(block);
}

#ifdef HAVE_SNI
CAMLprim value ocaml_ssl_set_client_SNI_hostname(value socket, value vhostname)
{
  CAMLparam2(socket, vhostname);
  SSL *ssl       = SSL_val(socket);
  char *hostname = String_val(vhostname);

  caml_enter_blocking_section();
  SSL_set_tlsext_host_name(ssl, hostname);
  caml_leave_blocking_section();

  CAMLreturn(Val_unit);
}
#else
CAMLprim value ocaml_ssl_set_client_SNI_hostname(value socket, value vhostname)
{
    CAMLparam2(socket, vhostname);
    caml_raise_constant(*caml_named_value("ssl_exn_method_error"));
    CAMLreturn(Val_unit);
}
#endif

#ifdef HAVE_ALPN
CAMLprim value ocaml_ssl_set_alpn_protos(value socket, value vprotos)
{
  CAMLparam2(socket, vprotos);
  SSL *ssl = SSL_val(socket);

  int total_len = get_alpn_buffer_length(vprotos);
  unsigned char protos[total_len];
  build_alpn_protocol_buffer(vprotos, protos);

  caml_enter_blocking_section();
  SSL_set_alpn_protos(ssl, protos, sizeof(protos));
  caml_leave_blocking_section();

  CAMLreturn(Val_unit);
}

CAMLprim value ocaml_ssl_get_negotiated_alpn_protocol(value socket)
{
  CAMLparam1(socket);
  SSL *ssl = SSL_val(socket);

  const unsigned char *data;
  unsigned int len;
  SSL_get0_alpn_selected(ssl, &data, &len);

  if (len == 0) CAMLreturn(Val_none);

  /* Note: we use the implementation `caml_alloc_initialized_string` (which
   * unfortunately requires OCaml >= 4.06) instead of `copy_string` here
   * because the selected protocol in `data` is not NULL-terminated.
   *
   * From https://www.openssl.org/docs/man1.0.2/man3/SSL_get0_alpn_selected.html:
   *   SSL_get0_alpn_selected() returns a pointer to the selected protocol in
   *   data with length len. It is not NUL-terminated. data is set to NULL and
   *   len is set to 0 if no protocol has been selected. data must not be
   *   freed.
   */
  value proto = caml_alloc_string (len);
  memcpy((char *)String_val(proto), (const char*)data, len);

  CAMLreturn(Val_some(proto));
}
#else
CAMLprim value ocaml_ssl_set_alpn_protos(value socket, value vprotos)
{
  CAMLparam2(socket, vprotos);
  caml_raise_constant(*caml_named_value("ssl_exn_method_error"));
  CAMLreturn(Val_unit);
}

CAMLprim value ocaml_ssl_get_negotiated_alpn_protocol(value socket)
{
  CAMLparam1(socket);
  caml_raise_constant(*caml_named_value("ssl_exn_method_error"));
  CAMLreturn(Val_unit);
}
#endif

CAMLprim value ocaml_ssl_connect(value socket)
{
  CAMLparam1(socket);
  int ret, err;
  SSL *ssl = SSL_val(socket);

  caml_enter_blocking_section();
  ret = SSL_connect(ssl);
  err = SSL_get_error(ssl, ret);
  caml_leave_blocking_section();
  if (err != SSL_ERROR_NONE)
    caml_raise_with_arg(*caml_named_value("ssl_exn_connection_error"), Val_int(err));

  CAMLreturn(Val_unit);
}

CAMLprim value ocaml_ssl_verify(value socket)
{
  CAMLparam1(socket);
  SSL *ssl = SSL_val(socket);
  long ans;

  caml_enter_blocking_section();
  ans = SSL_get_verify_result(ssl);
  caml_leave_blocking_section();

  if (ans != 0)
  {
    if (2 <= ans && ans <= 32)
      caml_raise_with_arg(*caml_named_value("ssl_exn_verify_error"), Val_int(ans - 2)); /* Not very nice, but simple */
    else
      caml_raise_with_arg(*caml_named_value("ssl_exn_verify_error"), Val_int(31));
  }

  CAMLreturn(Val_unit);
}

CAMLprim value ocaml_ssl_set_hostflags(value socket, value flag_lst)
{
  CAMLparam2(socket, flag_lst);
  SSL *ssl = SSL_val(socket);
  unsigned int flags = 0;

  while (Is_block(flag_lst))
  {
    switch(Int_val(Field(flag_lst, 0)))
    {
      case 0:
        flags |= X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT;
        break;
      case 1:
        flags |= X509_CHECK_FLAG_NEVER_CHECK_SUBJECT;
        break;
      case 2:
        flags |= X509_CHECK_FLAG_NO_WILDCARDS;
        break;
      case 3:
        flags |= X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS;
        break;
      case 4:
        flags |= X509_CHECK_FLAG_MULTI_LABEL_WILDCARDS;
        break;
      case 5:
        flags |= X509_CHECK_FLAG_SINGLE_LABEL_SUBDOMAINS;
        break;
      default:
        caml_invalid_argument("flags");
    }
    flag_lst = Field(flag_lst, 1);
  }

  caml_enter_blocking_section();
  SSL_set_hostflags(ssl, flags);
  caml_leave_blocking_section();

  CAMLreturn(Val_unit);
}

CAMLprim value ocaml_ssl_set1_host(value socket, value host)
{
  CAMLparam2(socket, host);
  SSL *ssl = SSL_val(socket);
  const char *hostname = String_val (host);

  caml_enter_blocking_section();
  SSL_set1_host (ssl, hostname);
  caml_leave_blocking_section();

  CAMLreturn(Val_unit);
}

CAMLprim value ocaml_ssl_write(value socket, value buffer, value start, value length)
{
  CAMLparam2(socket, buffer);
  int ret, err;
  int buflen = Int_val(length);
  char *buf = malloc(buflen);
  SSL *ssl = SSL_val(socket);

  if (Int_val(start) + Int_val(length) > caml_string_length(buffer))
    caml_invalid_argument("Buffer too short.");

  memmove(buf, (char*)String_val(buffer) + Int_val(start), buflen);
  caml_enter_blocking_section();
  ERR_clear_error();
  ret = SSL_write(ssl, buf, buflen);
  err = SSL_get_error(ssl, ret);
  caml_leave_blocking_section();
  free(buf);

  if (err != SSL_ERROR_NONE)
    caml_raise_with_arg(*caml_named_value("ssl_exn_write_error"), Val_int(err));

  CAMLreturn(Val_int(ret));
}

CAMLprim value ocaml_ssl_write_bigarray(value socket, value buffer, value start, value length)
{
  CAMLparam2(socket, buffer);
  int ret, err;
  SSL *ssl = SSL_val(socket);
  struct caml_ba_array *ba = Caml_ba_array_val(buffer);
  char *buf = ((char *)ba->data) + Int_val(start);

  if(Int_val(start) < 0) caml_invalid_argument("Ssl.write_bigarray: negative offset");
  if(Int_val(length) < 0) caml_invalid_argument("Ssl.write_bigarray: negative length");

  if (Int_val(start) + Int_val(length) > ba->dim[0])
    caml_invalid_argument("Ssl.write_bigarray: buffer too short.");

  caml_enter_blocking_section();
  ERR_clear_error();
  ret = SSL_write(ssl, buf, Int_val(length));
  err = SSL_get_error(ssl, ret);
  caml_leave_blocking_section();

  if (err != SSL_ERROR_NONE)
    caml_raise_with_arg(*caml_named_value("ssl_exn_write_error"), Val_int(err));

  CAMLreturn(Val_int(ret));
}

CAMLprim value ocaml_ssl_write_bigarray_blocking(value socket, value buffer, value start, value length)
{
  CAMLparam2(socket, buffer);
  int ret, err;
  SSL *ssl = SSL_val(socket);
  struct caml_ba_array *ba = Caml_ba_array_val(buffer);
  char *buf = ((char *)ba->data) + Int_val(start);

  if(Int_val(start) < 0) caml_invalid_argument("Ssl.write_bigarray_blocking: negative offset");
  if(Int_val(length) < 0) caml_invalid_argument("Ssl.write_bigarray_blocking: negative length");

  if (Int_val(start) + Int_val(length) > ba->dim[0])
    caml_invalid_argument("Ssl.write_bigarray: buffer too short.");

  ERR_clear_error();
  ret = SSL_write(ssl, buf, Int_val(length));
  err = SSL_get_error(ssl, ret);

  if (err != SSL_ERROR_NONE)
    caml_raise_with_arg(*caml_named_value("ssl_exn_write_error"), Val_int(err));

  CAMLreturn(Val_int(ret));
}

CAMLprim value ocaml_ssl_read(value socket, value buffer, value start, value length)
{
  CAMLparam2(socket, buffer);
  int ret, err;
  int buflen = Int_val(length);
  char *buf = malloc(buflen);
  SSL *ssl = SSL_val(socket);

  if (Int_val(start) + Int_val(length) > caml_string_length(buffer))
    caml_invalid_argument("Buffer too short.");

  caml_enter_blocking_section();
  ERR_clear_error();
  ret = SSL_read(ssl, buf, buflen);
  err = SSL_get_error(ssl, ret);
  caml_leave_blocking_section();
  memmove(((char*)String_val(buffer)) + Int_val(start), buf, buflen);
  free(buf);

  if (err != SSL_ERROR_NONE)
    caml_raise_with_arg(*caml_named_value("ssl_exn_read_error"), Val_int(err));

  CAMLreturn(Val_int(ret));
}

CAMLprim value ocaml_ssl_read_into_bigarray(value socket, value buffer, value start, value length)
{
  CAMLparam2(socket, buffer);
  int ret, err;
  struct caml_ba_array *ba = Caml_ba_array_val(buffer);
  char *buf = ((char *)ba->data) + Int_val(start);
  SSL *ssl = SSL_val(socket);

  if(Int_val(start) < 0) caml_invalid_argument("Ssl.read_into_bigarray: negative offset");
  if(Int_val(length) < 0) caml_invalid_argument("Ssl.read_into_bigarray: negative length");

  if (Int_val(start) + Int_val(length) > ba->dim[0])
    caml_invalid_argument("Ssl.read_into_bigarray: buffer too short.");

  caml_enter_blocking_section();
  ERR_clear_error();
  ret = SSL_read(ssl, buf, Int_val(length));
  err = SSL_get_error(ssl, ret);
  caml_leave_blocking_section();

  if (err != SSL_ERROR_NONE)
    caml_raise_with_arg(*caml_named_value("ssl_exn_read_error"), Val_int(err));

  CAMLreturn(Val_int(ret));
}

CAMLprim value ocaml_ssl_read_into_bigarray_blocking(value socket, value buffer, value start, value length)
{
  CAMLparam2(socket, buffer);
  int ret, err;
  struct caml_ba_array *ba = Caml_ba_array_val(buffer);
  char *buf = ((char *)ba->data) + Int_val(start);
  SSL *ssl = SSL_val(socket);

  if(Int_val(start) < 0) caml_invalid_argument("Ssl.read_into_bigarray: negative offset");
  if(Int_val(length) < 0) caml_invalid_argument("Ssl.read_into_bigarray: negative length");

  if (Int_val(start) + Int_val(length) > ba->dim[0])
    caml_invalid_argument("Ssl.read_into_bigarray: buffer too short.");

  ERR_clear_error();
  ret = SSL_read(ssl, buf, Int_val(length));
  err = SSL_get_error(ssl, ret);

  if (err != SSL_ERROR_NONE)
    caml_raise_with_arg(*caml_named_value("ssl_exn_read_error"), Val_int(err));

  CAMLreturn(Val_int(ret));
}

CAMLprim value ocaml_ssl_accept(value socket)
{
  CAMLparam1(socket);
  SSL *ssl = SSL_val(socket);

  int ret, err;
  caml_enter_blocking_section();
  ERR_clear_error();
  ret = SSL_accept(ssl);
  err = SSL_get_error(ssl, ret);
  caml_leave_blocking_section();
  if (err != SSL_ERROR_NONE)
    caml_raise_with_arg(*caml_named_value("ssl_exn_accept_error"), Val_int(err));

  CAMLreturn(Val_unit);
}

CAMLprim value ocaml_ssl_flush(value socket)
{
  CAMLparam1(socket);
  SSL *ssl = SSL_val(socket);
  BIO *bio;

  caml_enter_blocking_section();
  bio = SSL_get_wbio(ssl);
  if(bio)
  {
    /* TODO: raise an error */
    assert(BIO_flush(bio) == 1);
  }
  caml_leave_blocking_section();

  CAMLreturn(Val_unit);
}

CAMLprim value ocaml_ssl_shutdown(value socket)
{
  CAMLparam1(socket);
  SSL *ssl = SSL_val(socket);
  int ret;

  caml_enter_blocking_section();
  ret = SSL_shutdown(ssl);
  if (!ret)
    SSL_shutdown(ssl);
  caml_leave_blocking_section();
  /* close(SSL_get_fd(SSL_val(socket))); */

  CAMLreturn(Val_unit);
}

/* ======================================================== */
/*
   T.F.:
   Here, we steal the client_verify_callback function from
   netkit-telnet-ssl-0.17.24+0.1/libtelnet/ssl.c

   From the original file header:

   The modifications to support SSLeay were done by Tim Hudson
   tjh@mincom.oz.au

   You can do whatever you like with these patches except pretend that
   you wrote them.

   Email ssl-users-request@mincom.oz.au to get instructions on how to
   join the mailing list that discusses SSLeay and also these patches.
   */

#define ONELINE_NAME(X) X509_NAME_oneline(X, 0, 0)

/* Quick translation ... */
#ifndef VERIFY_ERR_UNABLE_TO_GET_ISSUER
#define VERIFY_ERR_UNABLE_TO_GET_ISSUER X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT
#endif
#ifndef VERIFY_ERR_DEPTH_ZERO_SELF_SIGNED_CERT
#define VERIFY_ERR_DEPTH_ZERO_SELF_SIGNED_CERT X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT
#endif
#ifndef VERIFY_OK
#define VERIFY_OK X509_V_OK
#endif
#ifndef VERIFY_ERR_UNABLE_TO_GET_ISSUER
#define VERIFY_ERR_UNABLE_TO_GET_ISSUER X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT
#endif

/* Need to think about this mapping in terms of what the real
 * equivalent of this actually is.
 */
#ifndef VERIFY_ROOT_OK
#define VERIFY_ROOT_OK VERIFY_OK
#endif


static int client_verify_callback(int ok, X509_STORE_CTX *ctx)
{
  char *subject, *issuer;
  int depth, error;
  char *xs;

  depth = X509_STORE_CTX_get_error_depth(ctx);
  error = X509_STORE_CTX_get_error(ctx);
  xs = (char*)X509_STORE_CTX_get_current_cert(ctx);

  subject = issuer = NULL;

  /* First thing is to have a meaningful name for the current
   * certificate that is being verified ... and if we cannot
   * determine that then something is seriously wrong!
   */
  subject=(char*)ONELINE_NAME(X509_get_subject_name((X509*)xs));
  if (subject == NULL)
  {
    ERR_print_errors_fp(stderr);
    ok = 0;
    goto return_time;
  }
  issuer = (char*)ONELINE_NAME(X509_get_issuer_name((X509*)xs));
  if (issuer == NULL)
  {
    ERR_print_errors_fp(stderr);
    ok = 0;
    goto return_time;
  }

  /* If the user wants us to be chatty about things then this
   * is a good time to wizz the certificate chain past quickly :-)
   */
  if (client_verify_callback_verbose)
  {
    fprintf(stderr, "Certificate[%d] subject=%s\n", depth, subject);
    fprintf(stderr, "Certificate[%d] issuer =%s\n", depth, issuer);
    fflush(stderr);
  }

  /* If the server is using a self signed certificate then
   * we need to decide if that is good enough for us to
   * accept ...
   */
  if (error == VERIFY_ERR_DEPTH_ZERO_SELF_SIGNED_CERT)
  {
    if (1)
    {
      /* Make 100% sure that in secure more we drop the
       * connection if the server does not have a
       * real certificate!
       */
      if (client_verify_callback_verbose)
      {
        fprintf(stderr,"SSL: rejecting connection - server has a self-signed certificate\n");
        fflush(stderr);
      }

      /* Sometimes it is really handy to be able to debug things
       * and still get a connection!
       */
      ok = 0;
      goto return_time;
    }
    else
    {
      ok = 1;
      goto return_time;
    }
  }

  /* If we have any form of error in secure mode we reject the connection. */
  if (!((error == VERIFY_OK) || (error == VERIFY_ROOT_OK)))
  {
    if (1)
    {
      if (client_verify_callback_verbose)
      {
        fprintf(stderr, "SSL: rejecting connection - error=%d\n", error);
        if (error == VERIFY_ERR_UNABLE_TO_GET_ISSUER)
        {
          fprintf(stderr, "unknown issuer: %s\n", issuer);
        }
        else
        {
          ERR_print_errors_fp(stderr);
        }
        fflush(stderr);
      }
      ok = 0;
      goto return_time;
    }
    else
    {
      /* Be nice and display a lot more meaningful stuff
       * so that we know which issuer is unknown no matter
       * what the callers options are ...
       */
      if (error == VERIFY_ERR_UNABLE_TO_GET_ISSUER && client_verify_callback_verbose)
      {
        fprintf(stderr, "SSL: unknown issuer: %s\n", issuer);
        fflush(stderr);
      }
    }
  }

return_time:

  /* Clean up things. */
  if (subject)
    free(subject);
  if (issuer)
    free(issuer);

  return ok;
}

static DH *load_dh_param(const char *dhfile)
{
  DH *ret=NULL;
  BIO *bio;

  if ((bio=BIO_new_file(dhfile,"r")) == NULL)
  	goto err;
  ret=PEM_read_bio_DHparams(bio,NULL,NULL,NULL);
err:
  if (bio != NULL) BIO_free(bio);
  return(ret);
}
