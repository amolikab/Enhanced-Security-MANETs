# Final-Thesis-Code

Folder Contents:
The folder contains the code for a group of nodes that a simulated to act like an adhoc network where different nodes enter the network at different times. The sub-folders contain the independent codes for each device. DCA1 (Delagated Certificate Authority) acts as a CA and the other nodes (1-6) depend on this node to perform administrative functions.
As the simulation proceeds, node 1 is elected as a new DCA (by DCA1 and DCA2) and can proceed to register its own nodes. Nodes 7 & 8 join the network after the election and register to node 1 as their DCA.
The node folders also contain their respective cryptographic files like RSA public/private key, OpenSSL certificate and their certificate chains leading upto their respective CA.
The folder named simulation contains the certificates of the same files after the simulation in order to observe the changes in the certificates of various nodes.

Assumptions:
The work assumes that the network can easily possess a routing mechanism and thus performs simulation using port numbers instead of IP addresses.
A reputation system is also assumed to be working to provide latest reputation updates. Thus pre-installed update tables are fed into the system to simulate a reputation mechanism.


Compiling the code:
The folder contains a bash script called script, which runs each node program on a different terminal to show how nodes enter the network at random intervals. The sleep command is used to simulate the nodes entering at various intervals.
Each node program is compiled by using 2 extra arguments, its own port number, and the port number of its DCA.


Understanding Certificate Chains:
The Root Certificate Authority (RCA) is represented by the root.pem and rootcert.pem files. Further, the certificates obtained Out of Band (OOB) by the new nodes entering the network is represented by OOB.pem and OOBcert.pem (which is signed by RCA). The DCAs present at the network configuration stage have their certificates signed directly by the RCA and all the other nodes of the network have their certificate chains leading back to the RCA. The elected DCAs have 2 certificate chains leading back to the RCA, one obtained from their own DCA and the other signed by the supporting DCA during election.


OpenSSL config file:
myopenssl.cnf is the config file used by OpenSSL to sign the certificates of the nodes. The file contains a custom field with oid 1.2.3.4 which is used to store the reputation group that the node belonged to before the CA signs the certificate. It also contains custom sections which are used to sign the certificate dfepending on the group change of the node or the CA status of the node.

The code:
Each node folder contains same code, whether it is a new node, TCA, or a DCA. However, the node can only use the functions pertaining to its current status depending upon its current certificate and reputation in the network. The code contains additional checks to verify the correct status of the peer before it accepts the identity (whether TCA or DCA) presented by the peer.
Inspite of containing the same code, each node code is segregated into its own folder to simulate the notion that the nodes represent different machines and more importantly, the codes differ slightly to accomodate the assumed routing mechanism and to feed different pre-installed reputation update values to different nodes.

The main function consists of 2 threads, a client thread that connects to other nodes and a server thread for listening to other nodes. 
When a TCA, the client thread is used to send certificate issuing and update requests to its DCA and the server thread is used to listen and accept certificates signed by the DCA.
When a DCA, the client thread is used to send signed certificates to the requested client and election requests to its peer DCAs. The server thread is used to listen to requests from new clients or reissue requests from current clients.It is also used to listen to election requests made by its peer DCAs.
The server thread is further branched out into multiple threads to be able to listen to multiple nodes at the same time. However, mutexes are used to avoid 2 or more clients to cause change in the DCA reputation table database at the same time.

The nodes in the network talk to each other using sockets at different ports and make secure connections to transfer data using SSL which is implemented using functions provided by OpenSSL.


Code Components:
Each node sub-folder contains one main program and includes functions written in other files. Each function has 2 codes, one that runs when a node is a TCA and an equivalent one when it runs as a DCA. The functions are:
check_tca.c         --- When TCA wants to make sure that its peer is a valid DCA before
                        it can register to it
check_dca.c         --- When DCA has to prove to a TCA that is a valid DCA
add_client_dca.c    --- When DCA gets request to add a new node
add_client_tca.c    --- When TCA requests a DCA to add itself as new client for that DCA
reissue_dca_peer.c  --- When DCA has to reissue a certificate for the client, whether on
                        the client's request, or if the client changes its reputation
                        group.
reissue_tca.c       --- When a TCA requests a DCA to reissue its expiring certificate
update_dca.c        --- When the TCA send a request to the DCA to send reputation table
update_tca.c        --- When the TCA wants to send its reputation table to the DCA
election_req.c      --- When a DCA wants to send/receive a request for election from its
                        peer DCA
accept_new_certfiles.c --- When the TCA needs to accept its new certificates after
                        election to start acting like a DCA.
common.c            --- The smaller list of functions shared by all the above functions.
common.h            --- Header file for the node







 


















