type status =
    | InputReq  | Sensitive
    | Success
    | MovedTemp | MovedPerm
    | FailTemp  | Unavailiable | CGI  | ProxyError   | Yamete
    | FailPerm  | Notfound     | Gone | ProxyRefused | BadReq
    | CertReq   | Unauthorized | Invalid

let intcode = function (* Or How I Wish For Enums *)
    | InputReq  -> 10 | Sensitive    -> 11
    | Success   -> 20
    | MovedTemp -> 30 | MovedPerm    -> 31
    | FailTemp  -> 40 | Unavailiable -> 41 | CGI     -> 42 | ProxyError   -> 43 | Yamete -> 44
    | FailPerm  -> 50 | Notfound     -> 51 | Gone    -> 52 | ProxyRefused -> 53 | BadReq -> 59
    | CertReq   -> 60 | Unauthorized -> 61 | Invalid -> 62

(*------------------------------------------------*)
type text = Text.t

type head = status * text
type body = status * text * in_channel

type answer = Head of head
            | Body of body

type handler = Uri.t -> answer


let handlers : (text, handler) Hashtbl.t
  = Hashtbl.create 64 ~random:true

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

let handldef uri =
    Uri.(path uri |> pct_decode)
      |> (function
         | "" -> "index.gmi"
         | p when Text.ends_with p "/" -> Filename.(concat p "index.gmi")
         | p -> p
         )
      |> Text.split ~sep:"/"
      |> List.filter ((<>) "..")
      |> Text.concat "/"
      |> Filename.concat "."
      |> (fun path ->
           match Unix.(openfile path [O_RDONLY;O_NONBLOCK] 0
             |> in_channel_of_descr) with
             | exception _-> Head(Notfound, "Page Requested Not Foud.")
             | input_chan -> Body(Success,  "text/gemini", input_chan)
         )

let register_handler callback uri =
    Hashtbl.replace handlers uri callback

let get_handler uri =
    Hashtbl.find_opt handlers uri
    |> Option.value ~default:handldef

let build_workspace workdir =
    let rec descend root dir =
        let path = Filename.concat root dir in
        match Sys.readdir path with
        | exception _-> ()
        | arr -> arr |> Array.iter (fun node ->
            let realpath = Filename.concat path node in
            let regipath = Filename.concat dir node
                |> if Filename.dir_sep <> "/"
                   then Text.replace ~patt:Filename.dir_sep ~repl:"/"
                   else Fun.id
            in
            if Sys.is_directory realpath then (
                descend root realpath;
                register_handler handldef (regipath^"/")
            ) else
                register_handler handldef regipath
        )
    in
    register_handler handldef  "";
    register_handler handldef "/";
    descend workdir ""

