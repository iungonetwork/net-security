const {Sensor, filters, windows, keys, processors} = require('./Sensor')

module.exports = function() {
	return Sensor.createWindowed('spam')
		.filterBy(filters.dst_ports([25, 465, 587, 993]))
		.windowBy(windows.period(60))
		.processWith(processors.report_threat_if(flows => flows.length > 20, 'spam'))
}