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
    | FailTemp  | Unavailiable | CGI  | Proxy | Yamete
    | FailPerm  | Notfound     | Gone | ProxyRefused | Bad
    | CertReq   | Unauthorized | Invalid

let intcode = function
    | InputReq  | Sensitive                                -> 10
    | Success                                              -> 20
    | MovedTemp | MovedPerm                                -> 30
    | FailTemp  | Unavailiable | CGI  | Proxy | Yamete     -> 40
    | FailPerm  | Notfound     | Gone | ProxyRefused | Bad -> 50
    | CertReq   | Unauthorized | Invalid                   -> 60

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

let fmt = Printf.sprintf
let print = Printf.printf

(* UTF-8 aware Strings *)
module String = Text
type string = Text.t

type header = status * string
type bodied = status * string * Unix.file_descr

type answer = Header: header -> answer
            | Bodied: bodied -> answer

type state = {
    (* paths*)
    workdir  : string;
    keypath  : string;
    crtpath  : string;
    (* unix stuff *)
    port     : int;
    host     : Unix.inet_addr;
    sock     : Unix.file_descr;
    (* ssl stuff *)
    ctx      : Ssl.context option;
    ssldis   : Ssl.protocol list;
    (* gemini stuff *)
    hdrlen   : int;
    nofcon   : int;
    handlers : (string, Uri.t -> answer) Hashtbl.t;
    handldef : Uri.t -> answer;
}

let statedef = {
    workdir  = Filename.concat (Sys.getcwd()) "gemini";
    keypath  = Filename.concat (Sys.getcwd()) "cert.key";
    crtpath  = Filename.concat (Sys.getcwd()) "cert.crt";
    port     = 1965;
    host     = Unix.inet_addr_of_string "0.0.0.0";
    sock     = Unix.(socket PF_INET SOCK_STREAM 0);
    ctx      = None;
    ssldis   = Ssl.[SSLv23; TLSv1; TLSv1_1];
    hdrlen   = 1024+2;
    nofcon   = 15;
    handlers = Hashtbl.create 64 ~random:true;
    handldef = fun uri -> let module Path = Filename in
    Uri.(path uri |> pct_decode)
      |> (function
          | "" -> "index.gmi"
          | p when String.ends_with p "/" -> Path.(concat p "index.gmi")
          | p -> p)
      |> String.split ~sep:"/"
      |> List.filter ((<>) "..")
      |> String.concat "/"
      |> Path.concat "."
      |> (fun file ->
          let ans = match Unix.(openfile file [O_RDONLY] 0) with
            | exception _->
                    Header(Notfound, "Page Requested Not Foud.")
            | fd ->
                    Gc.(finalise(fun f->finalise_release();Unix.close f)) fd;
                    Bodied(Success,  "text/gemini", fd)
          in ans);
}

(* TODO: state monad instead of:
    - passing state manually
    - making state a global/internal variable
    ... or maybe I should go with the private variable route *)

let register_handler st callback path =
    Hashtbl.replace st.handlers path callback

let init st =
    let st = let open Ssl in
        init ~thread_safe:true ();

        let context = Option.value st.ctx
            ~default:(create_context SSLv23 Server_context)
        in
        disable_protocols context st.ssldis;
        use_certificate context st.crtpath st.keypath;
        {st with ctx = Some context}
    in
    let () = let open Unix in
        let addr = ADDR_INET(st.host, st.port) in
        setsockopt st.sock SO_REUSEADDR true;
        bind st.sock addr;
        listen st.sock st.nofcon;
    in
    let () =
        Sys.chdir st.workdir;
        register_handler st st.handldef  "";
        register_handler st st.handldef "/";
    in
    let rec descend dir =
        Sys.readdir dir |> Array.iter (
            fun node ->
                register_handler st st.handldef node;
                if Sys.is_directory node then
                    descend node
                else ()
        )
    in descend st.workdir;
    (* return new state: *) st

let ( let* ) = Option.bind
let recv st =
    let* context = st.ctx in
    let sock, ip = Unix.accept st.sock in
    let ssl_sock = Ssl.embed_socket sock context in
        Ssl.accept ssl_sock;
    Some(ssl_sock, ip)

let read st ssl_sock buf =
    let len = Ssl.read ssl_sock buf 0 st.hdrlen in
    let msg = Bytes.(sub buf 0 len |> to_string) in
    let open String in
    let* req = if ends_with msg "\r\n" then
        match msg |> Uri.pct_decode |> check with
        | None -> Some msg (* we good *)
        | Some _er -> None
    else
        None
    in
        Some(Uri.of_string (strip req))

let get_handler st uri =
    Hashtbl.find_opt st.handlers (Uri.path uri)
    |> Option.value ~default:st.handldef

let pipe fdin fdout =
    let bufl = 1024 in
    let buff = Bytes.create bufl in
    let rec writeb _n =
        let len = Unix.read fdin buff 0 bufl in
        if  len > 0 then Ssl.write fdout buff 0 len
                    |> writeb
    in writeb 0

let write_header ssl_sock status meta =
    fmt "%d %s\r\n" (intcode status) meta
    |> String.encode ~encoding:"utf-8"
    |> Ssl.output_string ssl_sock

let write_eof ssl_sock =
    Ssl.output_string ssl_sock "\xff\xff\xff\xff"

let write ssl_sock resp =
    begin match resp with
    | Header(status, meta) ->
        write_header ssl_sock status meta
    | Bodied(status, meta, fd) -> (
        write_header ssl_sock status meta;
        pipe fd ssl_sock
    ) end;
    write_eof ssl_sock;
    Ssl.flush ssl_sock;
    Ssl.shutdown ssl_sock;

