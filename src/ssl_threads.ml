(*
 Copyright (C) 2003-2005 Samuel Mimram

 This file is part of Ocaml-ssl.

 This library is free software; you can redistribute it and/or
 modify it under the terms of the GNU Lesser General Public
 License as published by the Free Software Foundation; either
 version 2.1 of the License, or (at your option) any later version.

 This library is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 Lesser General Public License for more details.

 You should have received a copy of the GNU Lesser General Public
 License along with this library; if not, write to the Free Software
 Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*)

let init () =
  Ssl.thread_id_function := Some (fun () -> Thread.id (Thread.self ()));
  let mtx = Array.init (Ssl.crypto_num_locks ()) (fun _ -> Mutex.create ()) in
    Ssl.thread_locking_function :=
    Some
      (fun n lock ->
         if lock then
           Mutex.lock mtx.(n)
         else
           Mutex.unlock mtx.(n)
      )
