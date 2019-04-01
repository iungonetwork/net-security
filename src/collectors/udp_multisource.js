/*
	UDP multisource collector

	Accepts netflows on single port from multiple sources
	Emits 'flow' events with '_observer' property set to source IP
*/

const Collector = require('node-netflowv9')
const {EventEmitter} = require('events')
const log = require('../log')('collector')

function create() {
	const collector = new EventEmitter()
	
	collector.nfcapd = Collector(function(packet) {

		// setup most popular protocols to be decoded
		const protocols = {
			'1': 'ICMP',
			'5': 'ST',
			'6': 'TCP',
			'17': 'UDP' 
		}

		// set observer to source of netflow packet
		const observer = packet.rinfo.address

		// emit event for each flow in the packet
		packet.flows.forEach(function (flow) {
			flow._timestamp = Date.now()
			flow._observer = observer

			// decode TCP flags for conveniences
			flow._tcp_flags = {
				'FIN': (flow.tcp_flags & 1) != 0,
				'SYN': (flow.tcp_flags & 2) != 0,
				'RST': (flow.tcp_flags & 4) != 0,
				'PSH': (flow.tcp_flags & 8) != 0,
				'ACK': (flow.tcp_flags & 16) != 0,
				'URG': (flow.tcp_flags & 32) != 0
			}
			flow._protocol = flow.protocol in protocols ? protocols[flow.protocol] : flow.protocol

			log.debug('[%s]\t%s\t%s%s%s%s%s%s\t%s:%d -> %s:%d\t\t%d pkts\t%d bytes', 
				flow._observer,
				flow._protocol,
				flow._tcp_flags.URG ? 'U': '-',
				flow._tcp_flags.ACK ? 'A': '-',
				flow._tcp_flags.RST ? 'R': '-',
				flow._tcp_flags.PSH ? 'P': '-',
				flow._tcp_flags.SYN ? 'S': '-',
				flow._tcp_flags.FIN ? 'F': '-',
				flow.ipv4_src_addr, 
				flow.ipv4_src_port, 
				flow.ipv4_dst_addr, 
				flow.ipv4_dst_port,
				flow.in_pkts,
				flow.in_bytes
			)

			collector.emit('flow', flow)
		})
	})

	collector.listen = function(port) {
		collector.nfcapd.listen(port)
		log.info(`Listening on port ${port}`)
		return collector
	}

	return collector
}

module.exports = {create}