include Server
include Handle

open Lwt.Syntax
open Lwt.Infix

(* Full qualification for readability *)
module S = Server
module H = Handle


let init cfg =
    let  _ = S.setconfig cfg in
    let* _ = S.init_socket () in
    let* s = S.init_ssl () in
    let  _ = H.build_workspace cfg.workdir in
    let  _ = Sys.chdir cfg.workdir in
             Lwt.return s

let reinit cfg =
    let* _ = Lwt_unix.close (S.getconfig()).sock in
    let  _ = S.setconfig cfg in
    let* _ = S.init_socket () in
    let* s = S.init_ssl () in
    let  _ = H.build_workspace cfg.workdir in
    let  _ = Sys.chdir cfg.workdir in
             Lwt.return s

let recv server =
    let cfg = S.getconfig () in
    Tls_lwt.Unix.accept server cfg.sock

let read session =
    let  buf = Cstruct.create (1024+2) in
    let+ len = Tls_lwt.Unix.read session buf in
    let  msg = Cstruct.sub buf 0 len |> Cstruct.to_string in
    let  req = if Text.ends_with msg "\r\n" then
        match msg |> Uri.pct_decode |> Text.check with
        | None -> msg (* we good *)
        | Some _-> failwith "Bad Request Encoding"
    else
        failwith "Bad Request Length"
    in
    Text.strip req |> Uri.of_string

let handle = H.handldef

let write_header session status meta =
    Printf.sprintf "%d %s\r\n" (intcode status) meta
    |> Text.encode ~encoding:"utf-8"
    |> Cstruct.of_string
    |> Tls_lwt.Unix.write session

let pipe fdin fdout = let open Lwt_io in
    Unix.descr_of_in_channel fdin
    |> of_unix_fd ~mode:Input
    |> read_lines
    |> write_lines fdout

let write session resp =
    begin match resp with
    | Head(status, meta) ->
        write_header session status meta
    | Body(status, meta, fd) ->
        write_header session status meta
        >>= fun () -> pipe fd (snd @@ Tls_lwt.of_t session)
    end >>= fun () -> Tls_lwt.Unix.close_tls session

