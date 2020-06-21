snodea=`dig +short mm_seed_a`
snodeb=`dig +short mm_seed_b`
export config=`echo \{\"gui\":\"nogui\",\"netid\":9012,\"userhome\":\"${HOME}/\",\"passphrase\":\"${PASSPHRASE}\",\"rpcip\":\"0.0.0.0\",\"rpc_password\":\"RPC_PASSWORD\",\"rpc_local_only\":false,\"seednodes\":[\"$snodea\", \"$snodeb\"]\}`
/atomicDEX/mmbin/mm2 "${config}"

