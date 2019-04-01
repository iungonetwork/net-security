/*
	Sensor building toolkit
	Sensors seek for threats in a stream of flows by filtering, grouping and analyzing them.
	This kit provides reusable sensor building blocks:
		- filters, to discard flows, that does not interest a particular sensor
		- windows and keys, to provide grouping of flows into time/count groups,
		- processors, to detect and report malicious patterns.
*/

const {EventEmitter} = require('events');
const createLogger = require('../log')

/*
	Common filters
*/
const filters = {
	// pass all flows (default)
	none: flow => true,

	// pass all flows, that pass all of the given filters
	all: filters => flow => filters.reduce((acc, filter) => acc && filter(flow), true),

	// pass all flows, that pass any of the given filters
	any: filters => flow => filters.reduce((acc, filter) => acc || filter(flow), false),
	
	// pass flows to given destination port
	dst_port: port => flow => flow.ipv4_dst_port == port,

	// pass flows to any of the given destination ports
	dst_ports: ports => filters.any(ports.map(filters.dst_port)),

	// pass flows to any of the ports in the given range
	dst_port_range: (fromPort, toPort) => flow => flow.ipv4_dst_port >= fromPort && flow.ipv4_dst_port <= toPort,
	
	// pass flows that have exact TCP flags
	tcp_flags: flags => flow => flow.tcp_flags == flags,

	// pass flows that have less bit per packet than given
	bits_per_packet_lower_than: bits => flow => (flow.in_bytes * 8) / flow.in_pkts <= bits,

	// pass flows for protocol code
	protocol: protocol => flow => flow.protocol == protocol,

	// pass udp flows
	protocol_udp: flow => flow.protocol == 17,

	// pass tcp flows
	protocol_tcp: flow => flow.protocol == 6
}

/*
	Common windows
*/
const windows = {
	// analyze every single flow one by one
	single: (flow, window) => [flow],

	// group into period of given seconds
	period: seconds => (flow, window) => window.filter(flow => flow._timestamp > Date.now() - seconds * 1000).concat([flow]),

	// group into portions of given size
	count: count => (flow, window) => {
		if (window.length == count) {
			window.shift()
		}
		window.push(flow)
		return window
	}
}

/*
	Common keys
*/
const keys = {
	// all flows from single observer
	observer: flow => flow._observer,

	// every single source from single observer
	ipv4_src_addr: flow => `${flow._observer}/${flow.ipv4_src_addr}`
}

/*
	Common processors
*/
const processors = {
	// report threat if filter/window conditions produce any flows
	report_threat: (type, details, offset) => processors.report_threat_if(flows => true, type, details, offset),

	// report threats if group of flows passed to condition function returns array of threats
	report_threat_if: (condition, type, details, offset) => flows => {
		return !condition(flows) ? null : {
			threats: [		
				{
					type: type,
					observer: flows[0]._observer,
					timestamp: flows[0]._timestamp,
					offender: flows[0].ipv4_src_addr,
					details: details || {}
				}
			],
			offset: offset || 600
		}
	}
}

/*
	Generic sensor
	Filters, keys, windows and processors are passed to it on setup to create a specific purpose sensor.
*/
class Sensor extends EventEmitter {

	constructor() {
		super()
		this.data = {}
	}

	static create(name, filter) {
		const sensor = new Sensor()
		sensor
			.setName(name)
			.filterBy(filter || filters.none)
			.keyBy(keys.ipv4_src_addr)
			.windowBy(windows.single)
			.processWith(flows => {
				return 0
			})

		return sensor
	}

	static createWindowed(name, period) {
		const sensor = new Sensor()
		sensor
			.setName(name)
			.filterBy(filters.none)
			.keyBy(keys.ipv4_src_addr)
			.windowBy(windows.period(period || 60))
			.processWith(flows => {
				return 0
			})

		return sensor
	}

	setName(name) {
		this.name = name
		return this
	}

	filterBy(filterFunction) {
		this.filterFunction = filterFunction
		return this
	}

	keyBy(keyFunction) {
		this.keyFunction = keyFunction
		return this
	}

	windowBy(windowFunction) {
		this.windowFunction = windowFunction
		return this
	}

	processWith(processFunction) {
		this.processFunction = processFunction
		return this
	}

	getKey(flow) {
		return this.keyFunction(flow)
	}

	initKeyData(key) {
		if (!(key in this.data)) {
			this.data[key] = {state: {processAt: 0}, window: []}
		}	
	}

	getWindow(key) {
		this.initKeyData(key)
		return this.data[key].window
	}

	setWindow(key, window) {
		this.initKeyData(key)
		this.data[key].window = window
	}

	updateWindow(key, flow) {
		this.setWindow(key, this.windowFunction(flow, this.getWindow(key)))
	}

	attachCollector(collector) {
		collector.on('flow', flow => {
			if (this.filterFunction(flow)) {
				const key = this.getKey(flow)
				this.updateWindow(key, flow)
				this.processWindow(key)
			}
		})
	}

	processWindow(key) {
		const now = Date.now()
		const flows = this.getWindow(key)
		if (this.data[key].state.processAt <= now && flows.length > 0) {
			const processingResult = this.processFunction(flows)

			if (processingResult) {
				if (processingResult.threats) {
					processingResult.threats.forEach(threat => {
						this.getLogger().info('threat detected by "%s": %o', this, threat)
						this.emit('threat', threat)
					})
				}

				this.data[key].state.processAt = processingResult.offset ? now + processingResult.offset * 1000 : now				
			}
		}
	}

	getLogger() {
		return this.logger || (this.logger = createLogger('sensors:' + this.getName()))
	}

	getName() {
		return this.name
	}

	toString() {
		return this.getName()
	}
}

module.exports = {Sensor, filters, keys, windows, processors}