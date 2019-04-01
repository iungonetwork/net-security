/*
	Portscan sensor
	Checks for portscan patterns. triggers threat notifications if there are more than 100 flows
	in 60 seconds for any single source on any single observer that match common port scanning flags.
*/

const {Sensor, filters, windows, keys, processors} = require('./Sensor')

module.exports = function() {
	return Sensor.createWindowed('portscan')
	.filterBy(
		filters.any([
			// TCP STEALTH SCAN
			filters.all([
				filters.bits_per_packet_lower_than(500),
				filters.any([
					filters.tcp_flags(2), // SYN
					filters.tcp_flags(6)  // SYN and RST
				])
			]),
			// TCP FULL SCAN
			filters.all([
				filters.bits_per_packet_lower_than(1000),
				filters.tcp_flags(2) // SYN only
			]),
			// UDP
			filters.all([
				filters.protocol_udp,
				filters.bits_per_packet_lower_than(224)
			])
		])
	)
	.keyBy(keys.ipv4_src_addr)
	.windowBy(windows.period(60))
	.processWith(processors.report_threat_if(flows => 
			flows
				.reduce(flow => flow.ipv4_dst_port != 8443) // remove flows that have dst port 8443 because Wunderlist chrome extension
				// add more exceptions here
				.length > 100
			, 'portscan'
		)
	)
}