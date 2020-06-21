export config=`echo \{\"gui\":\"nogui\",\"netid\":9012,\"userhome\":\"${HOME}/\",\"passphrase\":\"${PASSPHRASE}\",\"rpcip\":\"0.0.0.0\",\"rpc_password\":\"RPC_PASSWORD\",\"rpc_local_only\":false,\"i_am_seed\":true\}`
/atomicDEX/mmbin/mm2 "${config}"
