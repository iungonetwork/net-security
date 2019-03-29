const {Sensor, filters, windows, keys, processors} = require('./Sensor')

module.exports = function() {
	return Sensor.create('winscan')
		.filterBy(
			filters.all([
				filters.dst_ports([445, 135, 137, 139, 1433, 3389]),
				filters.bits_per_packet_lower_than(512),
				filters.any([
					filters.tcp_flags(2), 
					filters.tcp_flags(6)
				])
			])
		)
		.processWith(processors.report_threat('winscan'))
}