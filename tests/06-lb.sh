#!/bin/bash
#
# Test Topology:
#  2.2.2.2/32 via 3.3.3.3 src $(ip of cilium_host)
#  f00d::1:1/128 via fbfb::10:10
#        |
#        v
#  veth lbtest1    <-----> veth lbtest2
#  fbfb::10:10/128           |
#  3.3.3.3/32                +-> ingress bpf_lb (LB_REDIRECT=cilium_host)
#                                           |
#                                           +---> cilium_host

# Only run basic IPv4 tests if IPV4=1 has been set

source "./helpers.bash"

set -e

#cilium config ConntrackLocal=true

NETPERF_IMAGE="tgraf/netperf"

HOSTIP6="fd02:1:1:1:1:1:1:1"

logs_clear

function cleanup {
	gather_files 06-lb ${TEST_SUITE}
	docker rm -f server1 server2 server3 server4 server5 client misc 2> /dev/null || true
	rm netdev_config.h tmp_lb.o 2> /dev/null || true
	rm /sys/fs/bpf/tc/globals/lbtest 2> /dev/null || true
	ip link del lbtest1 2> /dev/null || true
	ip addr del $HOSTIP6 dev cilium_host 2> /dev/null || true
}

function mac2array()
{
	echo "{0x${1//:/,0x}}"
}

function host_ip4()
{
	ip -4 addr show scope global | grep inet | head -1 | awk '{print $2}' | sed -e 's/\/.*//'
}

function check_bpf_lb_maps_clean {
  if [ "$(cilium bpf lb list | wc -l)" -gt 2 ]; then
    abort "BPF LB maps should be clean"
  fi
}

function check_daemon_lb_maps_clean {
  local DATA=$(curl -s --unix-socket /var/run/cilium/cilium.sock http://localhost/v1beta/service/  | jq '.| length')
  # Check if everything was deleted
  if [ "$DATA" -gt 0 ]; then
        abort "Daemon's services map should be clean"
  fi
}

function check_no_services {
  # Daemon's map should be empty
  if [ -n "$(cilium service list | tail -n+2)" ]; then
    abort "Services map should be clean"
  fi
}
function check_num_services {
  local NUM_SERVICES=$1
  local DATA=$(curl -s --unix-socket /var/run/cilium/cilium.sock http://localhost/v1beta/service/  | jq '.| length')
  if [[ "$DATA" != "$NUM_SERVICES" ]]; then
    abort "expected $NUM_SERVICES services but there were $DATA"
  fi
}

function run_benchmark_tests {
  cilium service update --rev --frontend "[$SVC_IP6]:80" --id 2223 \
                        --backends "[$SERVER1_IP]:80" \
                        --backends "[$SERVER2_IP]:80" \
                        --backends "[$SERVER3_IP]:80" \
                        --backends "[$SERVER4_IP]:80" \
                        --backends "[$SERVER5_IP]:80"

  cilium service update --rev --frontend "$SVC_IP4:80" --id 2233 \
			--backends "$SERVER1_IP4:80" \
			--backends "$SERVER2_IP4:80" \
			--backends "$SERVER3_IP4:80" \
			--backends "$SERVER4_IP4:80" \
			--backends "$SERVER5_IP4:80"

  #cilium config Debug=false DropNotification=false TraceNotification=false
  #cilium endpoint config $SERVER1_ID Debug=false DropNotification=false TraceNotification=false
  #cilium endpoint config $SERVER2_ID Debug=false DropNotification=false TraceNotification=false

  docker exec -i misc wrk -t20 -c1000 -d60 "http://[$SVC_IP6]:80/" || {
    abort "Error: Unable to reach local IPv6 node via loadbalancer"
  }

  docker exec -i misc wrk -t20 -c1000 -d60 "http://$SVC_IP4:80/" || {
    abort "Error: Unable to reach local IPv4 node via loadbalancer"
  }

  docker exec -i misc ab -r -n 1000000 -c 200 -s 60 -v 1 "http://[$SVC_IP6]/" || {
    abort "Error: Unable to reach local IPv6 node via loadbalancer"
  }

  docker exec -i misc ab -r -n 1000000 -c 200 -s 60 -v 1 "http://$SVC_IP4/" || {
    abort "Error: Unable to reach local IPv4 node via loadbalancer"
  }

  #cilium config Debug=true DropNotification=true TraceNotification=true
}

function test_svc_restore_functionality {
  echo "----- checking restore functionality for services -----"
  local SVCS_BEFORE_RESTART=$(cilium service list | tail -n+2 | sort)
  local BPF_LB_LIST_BEFORE_RESTART=$(cilium bpf lb list | tail -n+3 | sort)

  echo "----- restarting Cilium -----"
  service cilium restart
  wait_for_cilium_status

  echo "----- checking services and BPF maps after restarting Cilium -----"
  local SVCS_AFTER_RESTART=$(cilium service list | tail -n+2 | sort)
  local BPF_LB_LIST_AFTER_RESTART=$(cilium bpf lb list | tail -n+3 | sort)

  if [[ "$SVCS_BEFORE_RESTART" != "$SVCS_AFTER_RESTART" ]]; then
    echo "Services before restart: $SVCS_BEFORE_RESTART"
    echo "Services after restart: $SVCS_AFTER_RESTART" 
    abort "Error: services before restart are not the same as services after restart"
  fi

  if [[ "$BPF_LB_LIST_BEFORE_RESTART" != "$BPF_LB_LIST_AFTER_RESTART" ]]; then
    echo "BPF LB maps before restart: $BPF_LB_LIST_BEFORE_RESTART"
    echo "BPF LB maps after restart: $BPF_LB_LIST_AFTER_RESTART"
    abort "Error: BPF lb maps before restart are not the same as after restart"
  fi
  
  local SVC_IDS=$(cilium service list | tail -n+2 | awk '{ print $1 }')
  for id in $SVC_IDS; do 
    check_cilium_bpf_maps_synced $id
  done
}


function check_cilium_bpf_maps_synced {
  local ID=$1
  echo "----- checking that BPF Maps are in sync with Cilium maps for service $ID -----"
  local SVC_FE=$(cilium service list | grep $ID | awk '{print $2}')
  local SVC_BE=$(cilium service list | grep $ID | awk '{print $5}') 
  local BPF_FE=$(cilium bpf lb list | grep $ID | awk '{print $1}')
  local BPF_BE=$(cilium bpf lb list | grep $ID | awk '{print $2}')

  echo "----- checking that service $ID frontends match in both maps -----"
  if [[ "${SVC_FE}" != "${BPF_FE}" ]]; then
    abort "Error: Service $ID has frontend ${SVC_FE} but BPF maps have frontend ${BPF_FE}"
  fi

  echo "----- checking that service $ID backends match in both maps -----"
  if [[ "${SVC_BE}" != "${BPF_BE}" ]]; then
    echo "Error: Service $ID has backend ${SVC_BE} but BPF maps have backend ${BPF_BE}"
    exit 1
  fi
}

trap cleanup EXIT

# Remove containers from a previously incomplete run
cleanup

set -x

ip addr add $HOSTIP6 dev cilium_host

#cilium config Debug=true DropNotification=true TraceNotification=true

# Test the addition and removal of services with and without daemon

# Clean everything first
cilium service delete --all
cilium service list


check_no_services
# Add a service with ID 1
cilium service update --frontend [::]:80 --backends '[::1]:90,[::2]:91' --id 1 --rev 2> /dev/null || {
	abort "Service should have been added"
}

LIST_FIXTURE=$(cat <<-EOF
{
  "backend-addresses": [
    {
      "ip": "::1",
      "port": 90
    },
    {
      "ip": "::2",
      "port": 91
    }
  ],
  "frontend-address": {
    "ip": "::",
    "port": 80,
    "protocol": "TCP"
  },
  "id": 1
}
EOF
)

DATA=$(curl -s --unix-socket /var/run/cilium/cilium.sock http://localhost/v1beta/service/ | jq '.[0]')
 
# Check if it's the only service present
if [[ "${LIST_FIXTURE}" != "$DATA" ]]; then
  abort "Service was not properly added"
fi

# Check if we can get the service by it's ID
if [[ "$(cilium service get 1)" != \
      "$(echo -e "[::]:80 =>\n\t\t1 => [::1]:90 (1)\n\t\t2 => [::2]:91 (1)")" ]]; then
     abort "Service was not properly added"
fi

# Add a service with ID 0 to the daemon, it should fail
cilium service update --frontend [::]:80 --backends [::1]:90,[::2]:91 --id 0 --rev 2> /dev/null && {
	abort "Unexpected success in creating a frontend with reverse ID 0"
}

DATA=$(curl -s --unix-socket /var/run/cilium/cilium.sock http://localhost/v1beta/service/ | jq '.[0]')
if [[ "${LIST_FIXTURE}" != "$DATA" ]]; then
     abort "Service with ID 0 should not have been added"
fi

# Add a service with ID 2 with a conflicting frontend address
cilium service update --frontend [::]:80 --backends [::1]:90,[::2]:91 --id 2 --rev 2> /dev/null && {
	abort "Conflicting service should not have been added"
}

check_num_services "1"

# Let's try delete the only service
if [[ "$(cilium service delete 1)" != \
      "$(echo -e "Service 1 deleted successfully")" ]]; then
     abort "Service ID 1 could not be deleted"
fi

check_daemon_lb_maps_clean
check_bpf_lb_maps_clean

# Test the same for IPv4 addresses
if [ -n "${IPV4}" ]; then

	# Clean everything first
	cilium service delete --all
	cilium service list

	check_no_services

	# Add a service with ID 0, it should fail
	cilium service update --frontend 127.0.0.1:80 --backends 127.0.0.2:90,127.0.0.3:90 --id 0 --rev 2> /dev/null && {
		abort "Unexpected success in creating a frontend with reverse nat ID 0"
	}

	check_no_services

	# Add a service with ID 10
	cilium service update --frontend 127.0.0.1:80 --backends 127.0.0.2:90 --backends 127.0.0.3:90 --id 10 --rev 2> /dev/null || {
		abort "Service should have been added"
	}


	check_num_services 1
	
	# Check if we can get the service by it's ID
	if [[ "$(cilium service get 10)" != \
	      "$(echo -e "127.0.0.1:80 =>\n\t\t1 => 127.0.0.2:90 (10)\n\t\t2 => 127.0.0.3:90 (10)")" ]]; then
	     abort "Service was not properly added"
	fi

	# Add a service with ID 20 with a conflicting frontend address
	cilium service update --frontend 127.0.0.1:80 --backends 127.0.0.2:90,127.0.0.3:90 --id 20 --rev 2> /dev/null && {
		abort "Conflicting service should not have been added"
	}

	check_num_services 1

#	# Check if we can get the service by it's ID
#	if [[ "$(cilium service get 20)" != \
#	      "$(echo -e "127.0.0.1:80 =>\n\t\t1 => 127.0.0.2:90 (20)\n\t\t2 => 127.0.0.3:90 (20)")" ]]; then
#	     abort "Service was not properly added"
#	fi

#	# BPF's map should contain service with a different RevNAT ID
#	if [[ "$(cilium service list)" != \
#	      "$(echo -e "127.0.0.1:80 =>\n\t\t1 => 127.0.0.2:90 (20)\n\t\t2 => 127.0.0.3:90 (20)\n")" ]]; then
#	     abort "Service was not properly added"
#	fi

	# Let's try delete the only service
	if [[ "$(cilium service delete 10)" != \
	      "$(echo -e "Service 10 deleted successfully")" ]]; then
	     abort "RevNAT's was not deleted"
	fi

	check_daemon_lb_maps_clean
	check_bpf_lb_maps_clean
fi
 
ip link add lbtest1 type veth peer name lbtest2
ip link set lbtest1 up

# Route f00d::1:1 IPv6 packets to a fantasy router ("fbfb::10:10") behind lbtest1
ip -6 route add fbfb::10:10/128 dev lbtest1
MAC=$(ip link show lbtest1 | grep ether | awk '{print $2}')
ip neigh add fbfb::10:10 lladdr $MAC dev lbtest1
ip -6 route add f00d::1:1/128 via fbfb::10:10

# Route 2.2.2.2 IPv4 packets to a fantasy router ("3.3.3.3") behind lbtest1
ip route add 3.3.3.3/32 dev lbtest1
MAC=$(ip link show lbtest1 | grep ether | awk '{print $2}')
ip neigh add 3.3.3.3 lladdr $MAC dev lbtest1
ip route add 2.2.2.2/32 via 3.3.3.3

ip link set lbtest2 up
LIB=/var/lib/cilium/bpf
RUN=/var/run/cilium/state
NH_IFINDEX=$(cat /sys/class/net/cilium_host/ifindex)
NH_MAC=$(ip link show cilium_host | grep ether | awk '{print $2}')
NH_MAC="{.addr=$(mac2array $NH_MAC)}"
CLANG_OPTS="-D__NR_CPUS__=$(nproc) -DLB_L3 -DLB_REDIRECT=$NH_IFINDEX -DLB_DSTMAC=$NH_MAC -DCALLS_MAP=lbtest -O2 -target bpf -I. -I$LIB/include -I$RUN/globals -DDEBUG -Wno-address-of-packed-member -Wno-unknown-warning-option"
touch netdev_config.h
clang $CLANG_OPTS -c $LIB/bpf_lb.c -o tmp_lb.o

tc qdisc del dev lbtest2 clsact 2> /dev/null || true
tc qdisc add dev lbtest2 clsact
tc filter add dev lbtest2 ingress bpf da obj tmp_lb.o sec from-netdev

create_cilium_docker_network

docker run -dt --net=$TEST_NET --name server1 -l id.server -l server1 httpd
docker run -dt --net=$TEST_NET --name server2 -l id.server -l server2 httpd
docker run -dt --net=$TEST_NET --name server3 -l id.server -l server3 httpd
docker run -dt --net=$TEST_NET --name server4 -l id.server -l server4 httpd
docker run -dt --net=$TEST_NET --name server5 -l id.server -l server5 httpd
docker run -dt --net=$TEST_NET --name client -l id.client tgraf/nettools
docker run -dt --net=$TEST_NET --name misc   -l id.client borkmann/misc

for i in server{1..5} client misc; do
    wait_for_docker_ipv6_addr ${i}
done

CLIENT_IP=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' client)
CLIENT_ID=$(cilium endpoint list | grep $CLIENT_IP | awk '{ print $1}')

SERVER1_IP=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' server1)
SERVER1_ID=$(cilium endpoint list | grep $SERVER1_IP | awk '{ print $1}')
SERVER1_IP4=$(cilium endpoint list | grep $SERVER1_IP | awk '{ print $6}')

SERVER2_IP=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' server2)
SERVER2_ID=$(cilium endpoint list | grep $SERVER2_IP | awk '{ print $1}')
SERVER2_IP4=$(cilium endpoint list | grep $SERVER2_IP | awk '{ print $6}')

SERVER3_IP=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' server3)
SERVER3_ID=$(cilium endpoint list | grep $SERVER3_IP | awk '{ print $1}')
SERVER3_IP4=$(cilium endpoint list | grep $SERVER3_IP | awk '{ print $6}')

SERVER4_IP=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' server4)
SERVER4_ID=$(cilium endpoint list | grep $SERVER4_IP | awk '{ print $1}')
SERVER4_IP4=$(cilium endpoint list | grep $SERVER4_IP | awk '{ print $6}')

SERVER5_IP=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' server5)
SERVER5_ID=$(cilium endpoint list | grep $SERVER5_IP | awk '{ print $1}')
SERVER5_IP4=$(cilium endpoint list | grep $SERVER5_IP | awk '{ print $6}')

cilium endpoint config $CLIENT_ID  | grep ConntrackLocal
cilium endpoint config $SERVER1_ID | grep ConntrackLocal
cilium endpoint config $SERVER2_ID | grep ConntrackLocal
cilium endpoint config $SERVER3_ID | grep ConntrackLocal
cilium endpoint config $SERVER4_ID | grep ConntrackLocal
cilium endpoint config $SERVER5_ID | grep ConntrackLocal

#IFACE=$(ip link | grep lxc | sed -e 's/.* \(lxc[^@]*\).*/\1/')
#for name in $IFACE; do
#	ethtool -k $name tso off gso off gro off
#done

cilium policy delete --all 2> /dev/null || true
cat <<EOF | policy_import_and_wait -
[{
    "endpointSelector": {"matchLabels":{"id.server":""}},
    "ingress": [{
        "fromEndpoints": [
	    {"matchLabels":{"reserved:host":""}},
	    {"matchLabels":{"id.client":""}},
	    {"matchLabels":{"id.server":""}}
	]
    }]
}]
EOF


# Clear eventual old entries, this may fail if the maps have not been created
cilium service delete --all || true
cilium service list

# Create IPv4 L3 service without reverse entry
cilium service update --frontend 4.4.4.4:0 --id 1 --backends 5.5.5.5:0 || {
	abort "Unable to add IPv4 service entry"
}

cilium service list

# Delete IPv4 L3 entry
cilium service delete 1 || {
	abort "Unable to delete IPv4 service entry"
}

# Mixing L3/L4 in frontend and backend is not allowed
cilium service update --frontend 4.4.4.4:0 --id 1 --backends 5.5.5.5:80 2> /dev/null && {
	abort "Unexpected success in creating mixed L3/L4 service"
}

# Add L4 IPv4 entry
cilium service update --frontend 4.4.4.4:40 --rev --id 5 --backends 5.5.5.5:80 || {
	abort "Unable to add IPv4 service entry"
}

cilium service list

# Try an L3 lookup for the created L4 entry, should fail
# FIXME: Add back when we add lookup by frontend in CLI
#cilium service delete 4.4.4.4:0 || {
#	abort "Unexpected success in looking up with L3 key of L4 entry"
#}

# Delete L4 entry
cilium service delete 5 || {
	abort "Unable to delete IPv4 service entry"
}

# We can also use multiple --backends that will get appended.
SVC_IP6="f00d::1:1"
cilium service update --rev --frontend "[$SVC_IP6]:0" --id 222 \
                        --backends "[$SERVER1_IP]:0" \
                        --backends "[$SERVER2_IP]:0"

SVC_IP4="2.2.2.2"
cilium service update --rev --frontend "$SVC_IP4:0"  --id 223 \
			--backends "$SERVER1_IP4:0" \
			--backends "$SERVER2_IP4:0"

LB_HOST_IP6="f00d::1:2"
cilium service update --rev --frontend "[$LB_HOST_IP6]:0" --id 224 \
			--backends "[$HOSTIP6]:0"

LB_HOST_IP4="3.3.3.3"
cilium service update --rev --frontend "$LB_HOST_IP4:0" --id 225 \
			--backends "$(host_ip4):0"

cilium service list

## Test 1: local host => bpf_lb => local container
# FIXME: investigate why ping6 doesn't work in this case.
#ping6 $SVC_IP6 -c 4 || {
#	abort "Error: Unable to ping"
#}

ping $SVC_IP4 -c 4 || {
	abort "Error: Unable to ping"
}

## Test 2: local container => bpf_lxc (LB) => local container
docker exec --privileged -i client ping6 -c 4 $SVC_IP6 || {
	abort "Error: Unable to reach netperf TCP IPv6 endpoint"
}

docker exec --privileged -i client ping -c 4 $SVC_IP4 || {
	abort "Error: Unable to reach netperf TCP IPv4 endpoint"
}

cilium endpoint config $CLIENT_ID Policy=false

## Test 3: local container => bpf_lxc (LB) => local host
docker exec --privileged -i client ping6 -c 4 $LB_HOST_IP6 || {
	abort "Error: Unable to reach local IPv6 node via loadbalancer"
}

docker exec --privileged -i client ping -c 4 $LB_HOST_IP4 || {
	abort "Error: Unable to reach local IPv4 node via loadbalancer"
}

#cilium bpf ct list global

## Test 4: Reachability of own service IP
cilium service update --rev --frontend "[$SVC_IP6]:0"  --id 222 \
		      --backends "[$SERVER1_IP]:0"

cilium service update --rev --frontend "$SVC_IP4:0"  --id 223 \
		      --backends "$SERVER1_IP4:0"

cilium service list

docker exec --privileged -i server1 ping6 -c 4 $SVC_IP6 || {
	abort "Error: Unable to reach own service IP"
}

docker exec --privileged -i server1 ping -c 4 $SVC_IP4 || {
	abort "Error: Unable to reach own service IP"
}

## Test 5: Run wrk & ab from container => bpf_lxc (LB) => local container
# Only run these tests if BENCHMARK=1 has been set
if [ -z $BENCHMARK ]; then
  echo "Skipping Test 5, not in benchmark mode."
  echo "Run with BENCHMARK=1 to enable this test"
else 
  run_benchmark_tests
fi

test_svc_restore_functionality
