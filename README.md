# Netflow collector, analyzer and reporter

This service collects netflows from multiple sources, analyzes them with predefined sensors and reports found threats to AMQP queue.

## Building sensors

A sensor should provide attachCollector(EventEmitter) method, listen on 'flow' events from attached collectors and emit 'threat' events when threat is detected. Structure of threat event:

```
{
	type: "portscan", // string that identifies type of threat
	observer: "10.8.2.3", // ip address of the netflow packet source which contained this flow,
	offender: "192.168.111.117", // source ip address of the flow(s) that triggered event,
	timestamp: 123456789, // unix timestamp of flow when it arrived,
	details: { // optional, used to pass additional data that could be useful for further action
		"attacked_hosts": ["host1.domain1.tld", "host2.domain2.tld"]
	}
}
```

Sensor building kit is provided with some common cases for flow processing. To create a sensor using this kit import Sensor.js, create instance of Sensor class and inject it with filters, key/group functions and processors.

```
// import building kit
const {Sensor, filters, windows, keys, processors} = require('./Sensor')

// export function that creates a sensor for some purpose
module.exports = function() {
	return Sensor.createWindowed('portscan') // name the sensor
	// filter flows to remove ones we are not interested in
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
	.keyBy(keys.ipv4_src_addr) // key by observer IP and source IP
	.windowBy(windows.period(60)) // track 60s history for this key
	.processWith(processors.report_threat_if(flows => 
			flows
				.reduce(flow => flow.ipv4_dst_port != 8443) // remove flows that have dst port 8443 because Wunderlist chrome extension
				// add more exceptions here
				.length > 100
			, 'portscan'
		)
	)
}
```