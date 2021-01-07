type status =
    InputReq
  | Sensitive
  | Success
  | MovedTemp
  | MovedPerm
  | FailTemp
  | Unavailiable
  | CGI
  | ProxyError
  | Yamete
  | FailPerm
  | Notfound
  | Gone
  | ProxyRefused
  | BadReq
  | CertReq
  | Unauthorized
  | Invalid

type head = status * Text.t

type body = status * Text.t * in_channel

type answer = Head of head | Body of body

type handler = Uri.t -> answer

type config = {
  workdir  : Text.t;
  keypath  : Text.t;
  crtpath  : Text.t;
  port     : int;
  host     : Lwt_unix.inet_addr;
  sock     : Lwt_unix.file_descr;
  tlsver   : Tls.Core.tls_version * Tls.Core.tls_version;
  maxcon   : int;
}

val intcode : status -> int

val defconfig : config

(** string should be the result of Text.encode |> Uri.pct_encode **)
val register_handler : handler -> string -> unit

val get_handler : string -> handler

val init : config -> Tls.Config.server Lwt.t

val reinit : config -> Tls.Config.server Lwt.t

val recv : Tls.Config.server -> (Tls_lwt.Unix.t * Lwt_unix.sockaddr) Lwt.t

val read : Tls_lwt.Unix.t -> Uri.t Lwt.t

val handle : handler

val write : Tls_lwt.Unix.t -> answer -> unit Lwt.t
