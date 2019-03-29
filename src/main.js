const ip_route = require('iproute').route
const collector = require('./collectors/udp_multisource').create()
const reporter = require('./reporters/amqp').create()
const log = require('./log')('main')
const net = require('net')
const repl = require('repl')

// add route to back to signaling network
ip_route.add({
	to: '10.8.0.0/16',
	via: '172.28.0.100'
}, error => {
	if (!error) return
	// code 2 means route alredy created by previuos run, ignore
	if (error.code != 2) {
		log.error('failed to create route: %s', error.message)
	}
});

// list enabled sensors here
const enabledSensors = [
	'spam', 
	'portscan', 
	'winscan',
]

// setup sensors
const sensors = {}

enabledSensors.forEach(sensorName => {
	const sensor = require(`./sensors/${sensorName}`)()
	sensor.attachCollector(collector)
	reporter.attachSensor(sensor)
	sensors[sensorName] = sensor
	log.info('added sensor "%s"', sensor)
})

// connect to reporting
reporter.connect(
	process.env.AMQP_REPORTING_URI || 'amqp://user:pass@rabbitmq:5672', 
	process.env.AMQP_REPORTING_QUEUE || 'security-threat'
)

// listen for incoming flows
collector.listen(process.env.COLLECTOR_LISTEN_PORT || 3000)

net.createServer((socket) => {
	const replServer = repl.start({
		prompt: '> ',
		input: socket,
		output: socket
	})
	.on('exit', () => {
		socket.end();
	});

	replServer.context.reporter = reporter
	replServer.context.sensors = sensors
	replServer.context.collector = collector

}).listen(process.env.REPL_PORT || 5000);
