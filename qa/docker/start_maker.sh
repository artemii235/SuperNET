snode=`dig +short mm_seed`
export config=`echo \{\"gui\":\"nogui\",\"netid\":9012,\"userhome\":\"${HOME}/\",\"passphrase\":\"${PASSPHRASE}\",\"rpcip\":\"0.0.0.0\",\"rpc_password\":\"RPC_PASSWORD\",\"rpc_local_only\":false,\"seednodes\":[\"$snode\"\]\}`
/atomicDEX/mmbin/mm2 "${config}"
