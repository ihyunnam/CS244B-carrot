This folder contains files for Carrot with multiple intermediaires. Only the files that differ from the rest of the Carrot are included in this folder.
Carrot interposes on a GET request from the sender and forwards it to multiple machines.
Each of the machines then forward the request to 'intermediaries' that are presumably closer to the destination.
The sender either receives the fetched website from a machine (after which it closes socket) or times out.
