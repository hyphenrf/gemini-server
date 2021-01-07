open Lwt.Syntax
open Lwt.Infix


type config = {
    (* paths*)
    workdir  : string;
    keypath  : string;
    crtpath  : string;
    (* unix stuff *)
    port     : int;
    host     : Lwt_unix.inet_addr;
    sock     : Lwt_unix.file_descr;
    (* gemini stuff *)
    tlsver   : Tls.Core.tls_version * Tls.Core.tls_version;
    maxcon   : int;
}

let defconfig = {
    workdir  = Filename.concat (Sys.getcwd()) "gemini";
    keypath  = Filename.concat (Sys.getcwd()) "cert.key";
    crtpath  = Filename.concat (Sys.getcwd()) "cert.crt";
    port     = 1965;
    host     = Unix.inet_addr_any;
    sock     = Lwt_unix.(socket PF_INET SOCK_STREAM 0);
    tlsver   = Tls.Core.(`TLS_1_2, `TLS_1_3)[@warning "-33"]; (* WHY????? *)
    maxcon   = 15;
}

let cfg = ref defconfig

let setconfig c = cfg := c [@@inline]
let getconfig () = !cfg [@@inline]

(* init functions *)

let init_socket () = let open Lwt_unix in
    let cfg = getconfig () in
    let sock = cfg.sock in
    let addr = ADDR_INET(cfg.host, cfg.port) in
    setsockopt sock SO_REUSEADDR true;
    bind sock addr >|= fun () ->
    listen sock cfg.maxcon

let init_ssl () =
    let cfg = getconfig () in
    let+ cert = X509_lwt.private_of_pems
        ~priv_key:cfg.keypath
        ~cert:cfg.crtpath
    in
    let null_auth ~host:_ _ = Ok None in
    Tls.Config.server
        ~certificates:(`Single cert)
        ~authenticator:null_auth ()

