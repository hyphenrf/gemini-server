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

type header = status * string

type bodied = status * string * Unix.file_descr

type answer = Header of header | Bodied of bodied

type handler = Uri.t -> answer

type config = {
  workdir  : string;
  keypath  : string;
  crtpath  : string;
  port     : int;
  host     : Lwt_unix.inet_addr;
  sock     : Lwt_unix.file_descr;
  tlsver   : Tls.Core.tls_version * Tls.Core.tls_version;
  nofcon   : int;
  handlers : (string, handler) Hashtbl.t;
  handldef : handler;
}

val intcode : status -> int

val defconfig : config

val register_handler : config -> handler -> string -> unit

val get_handler : config -> string -> handler

val init : config -> Tls.Config.server Lwt.t

val recv : Tls.Config.server -> config -> (Tls_lwt.Unix.t * Lwt_unix.sockaddr) Lwt.t

val read : Tls_lwt.Unix.t -> Uri.t Lwt.t

val write : Tls_lwt.Unix.t -> answer -> unit Lwt.t
