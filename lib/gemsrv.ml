(* TODO: clean opened resources *)
(*
 CODE:
     1x INPUT     -- essential 10, sensitive 11
     2x SUCCESS   -- essential 20
     3x REDIRECT  -- essential 30, moved permanently 31
     4x TEMP FAIL -- can be combined 40/50
     5x FAIL      _/
     6x CLIENT CERT REQUIRED -- optional

 CODE 20:
     META is mimetype. can be empty representing "text/gemini; charset=utf-8"
     BODY only accompanies this
     text should be linebreaked with crlf but lf alone is fine
     default charset is utf-8 unless otherwise encoded.

 CODE 40: server unavailable 1, cgi error 2, proxy error 3, slow down 4
 CODE 50: not found 1, gone 2, proxy refused 3, bad req 9
 CODE 60: not authorized 1, not valid 2
 *)

type status =
    | InputReq  | Sensitive
    | Success
    | MovedTemp | MovedPerm
    | FailTemp  | Unavailiable | CGI  | ProxyError   | Yamete
    | FailPerm  | Notfound     | Gone | ProxyRefused | BadReq
    | CertReq   | Unauthorized | Invalid

let intcode = function
    | InputReq  -> 10 | Sensitive    -> 11
    | Success   -> 20
    | MovedTemp -> 30 | MovedPerm    -> 31
    | FailTemp  -> 40 | Unavailiable -> 41 | CGI     -> 42 | ProxyError   -> 43 | Yamete -> 44
    | FailPerm  -> 50 | Notfound     -> 51 | Gone    -> 52 | ProxyRefused -> 53 | BadReq -> 59
    | CertReq   -> 60 | Unauthorized -> 61 | Invalid -> 62

(* Or How I Wish For Enums *)

(*
 PROTOCOL: Listen on 1965

 S: Accept      -- ssl
 C/S: handshake _/

 C: send req\r\n (req: UTF-8 PCT, absolute, incl. scheme, maxlen 1024b)
                 (uri: must not have userinfo)
 S: send (header\r\nbody) -> resp
    head: status␣meta(1024b, optional, status-dep)
    body: binary

 TLS SNI is mandatory >=v1.2 (1.3 pref)
*)
open Lwt.Syntax
open Lwt.Infix

module L = Lwt
module IO = Lwt_io
module Lu = Lwt_unix

(* UTF-8 aware Strings *)
module String = Text
type string = Text.t

type header = status * string
type bodied = status * string * Unix.file_descr
type answer = Header of header
            | Bodied of bodied
type handler = Uri.t -> answer

type config = {
    (* paths*)
    workdir  : string;
    keypath  : string;
    crtpath  : string;
    (* unix stuff *)
    port     : int;
    host     : Lu.inet_addr;
    sock     : Lu.file_descr;
    (* gemini stuff *)
    tlsver   : Tls.Core.tls_version * Tls.Core.tls_version;
    nofcon   : int;
    handlers : (string, handler) Hashtbl.t;
    handldef : handler;
}

let defconfig = {
    workdir  = Filename.concat (Sys.getcwd()) "gemini";
    keypath  = Filename.concat (Sys.getcwd()) "cert.key";
    crtpath  = Filename.concat (Sys.getcwd()) "cert.crt";
    port     = 1965;
    host     = Unix.inet_addr_any;
    sock     = Lu.(socket PF_INET SOCK_STREAM 0);
    tlsver   = Tls.Core.(`TLS_1_2, `TLS_1_3)[@warning "-33"]; (* WHY????? *)
    nofcon   = 15;
    handlers = Hashtbl.create 64 ~random:true;
    handldef = fun uri ->
     Uri.(path uri |> pct_decode)
      |> (function
         | "" -> "index.gmi"
         | p when String.ends_with p "/" -> Filename.(concat p "index.gmi")
         | p -> p)
      |> String.split ~sep:"/"
      |> List.filter ((<>) "..")
      |> String.concat "/"
      |> Filename.concat "."
      |> (fun path ->
           match Unix.(openfile path [O_RDONLY;O_NONBLOCK] 0) with
            | exception _-> Header(Notfound, "Page Requested Not Foud.")
            | file_descr -> Bodied(Success,  "text/gemini", file_descr)
         );
}

let cfg = ref defconfig

let setconfig c = cfg := c [@@inline]
let getconfig () = !cfg [@@inline]

(* init functions *)

let register_handler cfg callback uri =
    Hashtbl.replace cfg.handlers uri callback

let get_handler cfg uri =
    Hashtbl.find_opt cfg.handlers uri
    |> Option.value ~default:cfg.handldef

(* Using a hashtable is probably fragile. I can imagine things getting weird
 * with CGI params. But I'll leave parsing those as the job of a handler.
 * That in mind, a typical usage would be:
 *   register "[[scheme]host]/path",
 *   get ([[Uri.scheme req ^] Uri.host req ^] Uri.path req),
 *   handle req <-- here we start looking at cgi params.
 * An alternative would be to hash the uri directly but this is probably a bad
 * idea. URI requests are highly variable. Is URI slicing a thing?
 * Anyway, programmer doesn't even have to rely on these functions -- they can
 * define their own handling logic.  *)


let build_workspace () =
    let cfg = getconfig () in
    let rec descend dir =
        match Sys.readdir dir with
        | exception _-> ()
        | arr -> arr |> Array.iter (fun node ->
            let realpath = Filename.concat dir node in
            let regipath = "/"^String.lchop realpath in
            register_handler cfg cfg.handldef regipath;
            if Sys.is_directory realpath then
                descend realpath
            else ()
        )
    in
    Sys.chdir cfg.workdir;
    register_handler cfg cfg.handldef  "";
    register_handler cfg cfg.handldef "/";
    descend "."

let init_socket () = let open Lu in
    let cfg = getconfig () in
    let sock = cfg.sock in
    let addr = ADDR_INET(cfg.host, cfg.port) in
    setsockopt sock SO_REUSEADDR true;
    bind sock addr >|= fun () ->
    Lu.listen sock cfg.nofcon

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

let init cfg =
    setconfig cfg;
    let* _sock = init_socket() in
    let* state = init_ssl() in
    let _workd = build_workspace() in
        L.return state

let reinit cfg =
    let old = getconfig() in
        setconfig cfg;
    let* _sock = init_socket () in
    let* state = init_ssl () in
    let _workd = build_workspace () in
        Lu.close old.sock >>= fun () ->
        L.return state



(* loop functions *)
let recv server =
    let cfg = getconfig () in
    Tls_lwt.Unix.accept server cfg.sock

let read session =
    let  buf = Bytes.create (1024+2) |> Cstruct.of_bytes in
    let+ len = Tls_lwt.Unix.read session buf in
    let  msg = Cstruct.sub buf 0 len |> Cstruct.to_string in
    let  req = if String.ends_with msg "\r\n" then
        match msg |> Uri.pct_decode |> String.check with
        | None -> msg (* we good *)
        | Some _-> failwith "Bad Request Encoding"
    else
        failwith "Bad Request Length"
    in
    String.strip req |> Uri.of_string

let write_header session status meta =
    Printf.sprintf "%d %s\r\n" (intcode status) meta
    |> String.encode ~encoding:"utf-8"
    |> Cstruct.of_string
    |> Tls_lwt.Unix.write session

let pipe fdin fdout =
    let fdin = IO.(of_unix_fd fdin ~mode:Input) in
    let stream = IO.read_lines fdin in
    let output = IO.write_lines fdout stream in
        output

let write session resp =
    begin match resp with
    | Header(status, meta) ->
        write_header session status meta
    | Bodied(status, meta, fd) ->
        write_header session status meta
        >>= fun () -> pipe fd (snd @@ Tls_lwt.of_t session)
    end >>= fun () -> Tls_lwt.Unix.close_tls session

